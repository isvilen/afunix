#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <sys/un.h>
#include <assert.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <string.h>

#include <erl_nif.h>
#include <erl_driver.h>


#define MAX_FDS 28

static ErlNifResourceType* socket_type;
static ErlNifResourceType* fd_type;
static ERL_NIF_TERM atom_ok;
static ERL_NIF_TERM atom_error;
static ERL_NIF_TERM atom_closed;
static ERL_NIF_TERM atom_true;
static ERL_NIF_TERM atom_false;
static ERL_NIF_TERM atom_noerror;
static ERL_NIF_TERM atom_recbuf;
static ERL_NIF_TERM atom_sndbuf;
static ERL_NIF_TERM atom_afunix;
static ERL_NIF_TERM atom_read;
static ERL_NIF_TERM atom_write;


typedef struct monitor_data
{
    struct monitor_data* next;
    int socket;
    enum { MONITOR_NONE // socket is garbage collected, do not send notification
         , MONITOR_READ // send notification when socket is readable
         , MONITOR_WRITE // send notification when socket is writable
         , MONITOR_CLOSED // close is called, send notification and expect
                          // next API call to fail with {error, closed}
         } event;

    ErlNifEnv *env;
    ErlNifPid pid;
    ERL_NIF_TERM msg;

} monitor_data;


typedef struct {
    int pipefd[2];
    ErlNifMutex *lock;
    ErlNifCond *cond;

    ErlNifTid tid;
    bool running;

    monitor_data* monitors;

} afunix_data;


typedef struct {
    int fd;
    struct sockaddr_un addr;
    bool unlink;
} socket_data;


typedef struct {
    int nfds;
    int pipefd;
    fd_set rfds, wfds;
} select_data;


static afunix_data* priv_data(ErlNifEnv* env)
{
    return (afunix_data *) enif_priv_data(env);
}


// lock must be held
static void wakeup_select_thread(afunix_data* data)
{
    char buf = 0;
    write(data->pipefd[1], &buf, 1);
}


static void cancel_monitors(ErlNifEnv *env, socket_data *sd, bool notify)
{
    afunix_data* data = priv_data(env);

    enif_mutex_lock(data->lock);

    bool has_monitors = false;

    monitor_data* mon = data->monitors;
    while (mon != NULL) {
        if (mon->socket == sd->fd) {
            has_monitors = true;
            mon->event = notify ? MONITOR_CLOSED : MONITOR_NONE;
        }

        mon = mon->next;
    }

    while (has_monitors) {
        wakeup_select_thread(data);
        enif_cond_wait(data->cond, data->lock);

        has_monitors = false;
        mon = data->monitors;
        while (mon != NULL) {
            if (mon->socket == sd->fd) {
                has_monitors = true;
                break;
            }
            mon = mon->next;
        }
    }

    enif_mutex_unlock(data->lock);
}


static void socket_dtor(ErlNifEnv *env, void *obj)
{
    socket_data *sd = (socket_data *) obj;

    if (sd->fd == -1) return;

    cancel_monitors(env, sd, false);

    close(sd->fd);

    if (sd->unlink) unlink(sd->addr.sun_path);
}


static void fd_dtor(ErlNifEnv *env, void *obj)
{
    int *fd = (int *) obj;

    if (*fd != -1) close(*fd);
}


static bool make_fd_nonblock(int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1) return false;

    return fcntl(fd, F_SETFL, flags | O_NONBLOCK) != -1;
}


static bool init_resource_types(ErlNifEnv* env, ErlNifResourceFlags flags)
{
    socket_type = enif_open_resource_type(env, NULL, "socket", socket_dtor,
                                          flags, NULL);
    fd_type = enif_open_resource_type(env, NULL, "fd", fd_dtor, flags, NULL);

    return socket_type && fd_type;
}


static void init_atoms(ErlNifEnv* env)
{
    atom_ok = enif_make_atom(env, "ok");
    atom_error = enif_make_atom(env, "error");
    atom_closed = enif_make_atom(env, "closed");
    atom_true = enif_make_atom(env, "true");
    atom_false = enif_make_atom(env, "false");
    atom_recbuf = enif_make_atom(env, "recbuf");
    atom_sndbuf = enif_make_atom(env, "sndbuf");
    atom_noerror = enif_make_atom(env, "noerror");
    atom_afunix = enif_make_atom(env, "afunix");
    atom_read = enif_make_atom(env, "read");
    atom_write = enif_make_atom(env, "write");
}


static afunix_data* init_priv_data()
{
    int error;
    afunix_data *data = (afunix_data *) enif_alloc(sizeof(afunix_data));

    data->pipefd[0] = -1;
    data->pipefd[1] = -1;
    data->lock = NULL;
    data->cond = NULL;
    data->running = false;
    data->monitors = NULL;

    if (pipe(data->pipefd) != 0) goto ERROR;

    if (!make_fd_nonblock(data->pipefd[0]) ||
        !make_fd_nonblock(data->pipefd[1]))
        goto ERROR;

    data->lock = enif_mutex_create("afunix");
    if (data->lock == NULL) goto ERROR;

    data->cond = enif_cond_create("afunix");
    if (data->cond == NULL) goto ERROR;

    return data;

ERROR:
        error = errno;

        if (data->pipefd[0] != -1) close(data->pipefd[0]);
        if (data->pipefd[1] != -1) close(data->pipefd[1]);

        if (data->cond != NULL) enif_cond_destroy(data->cond);
        if (data->lock != NULL) enif_mutex_destroy(data->lock);

        enif_free(data);

        errno = error;

        return NULL;
}


static void upgrade_priv_data(afunix_data *old_data, afunix_data* new_data)
{
    enif_mutex_lock(old_data->lock);
    enif_mutex_lock(new_data->lock);


    enif_mutex_unlock(new_data->lock);
    enif_mutex_unlock(old_data->lock);
}


static void free_priv_data(afunix_data* data)
{
    close(data->pipefd[0]);
    close(data->pipefd[1]);

    enif_cond_destroy(data->cond);
    enif_mutex_destroy(data->lock);

    enif_free(data);
}


static monitor_data*
init_monitor_data(ErlNifEnv* env, socket_data* sd, int event, ERL_NIF_TERM ref)
{
    monitor_data* mon = enif_alloc(sizeof(monitor_data));

    if (mon != NULL) {
        mon->env = enif_alloc_env();
        if (mon->env == NULL) {
            enif_free(mon);
            return NULL;
        }

        mon->next = NULL;
        mon->socket = sd->fd;
        mon->event = event;

        ERL_NIF_TERM mon_afunix, mon_ref;

        mon_afunix = enif_make_copy(mon->env, atom_afunix);
        mon_ref = enif_make_copy(mon->env, ref);

        mon->msg = enif_make_tuple2(mon->env, mon_afunix, mon_ref);

        enif_self(env, &mon->pid);
    }

    return mon;
}


static void free_monitor_data(monitor_data* mon)
{
    enif_free_env(mon->env);
    enif_free(mon);
}


static void init_select(select_data* sdata, afunix_data* adata)
{
    enif_mutex_lock(adata->lock);

    sdata->pipefd = adata->pipefd[0];
    sdata->nfds = sdata->pipefd + 1;

    enif_mutex_unlock(adata->lock);

    FD_ZERO(&sdata->rfds);
    FD_SET(sdata->pipefd, &sdata->rfds);

    FD_ZERO(&sdata->wfds);
}


static void drain_wakeup_pipe(select_data* data)
{
    if (FD_ISSET(data->pipefd, &data->rfds)) {
        char buf;
        int rc;
        do {
            rc = read(data->pipefd, &buf, 1);
        } while(rc == 1 || (rc == -1 && errno == EINTR));
    }
}


static void send_notifications(select_data* sdata, afunix_data* adata)
{
    enif_mutex_lock(adata->lock);

    monitor_data** monptr = &adata->monitors;

    while (*monptr != NULL) {
        monitor_data* mon = *monptr;

        if (FD_ISSET(mon->socket, &sdata->rfds) ||
            FD_ISSET(mon->socket, &sdata->wfds)) {

            if (mon->event != MONITOR_NONE)
                enif_send(NULL, &mon->pid, mon->env, mon->msg);

            monitor_data* next = mon->next;
            free_monitor_data(mon);
            *monptr = next;

        } else {
            monptr = &(mon->next);
        }
    }

    enif_mutex_unlock(adata->lock);
}


static bool update_select(select_data* sdata, afunix_data* adata)
{
    enif_mutex_lock(adata->lock);

    if (!adata->running) {
        enif_mutex_unlock(adata->lock);
        return false;
    }

    FD_ZERO(&sdata->rfds);
    FD_SET(sdata->pipefd, &sdata->rfds);

    FD_ZERO(&sdata->wfds);

    sdata->nfds = sdata->pipefd;

    monitor_data** monptr = &adata->monitors;
    bool monitors_freed = false;

    while (*monptr != NULL) {
        monitor_data* mon = *monptr;

        switch (mon->event) {
        case MONITOR_READ:
            FD_SET(mon->socket, &sdata->rfds);
            break;
        case MONITOR_WRITE:
            FD_SET(mon->socket, &sdata->wfds);
            break;
        case MONITOR_CLOSED:
            enif_send(NULL, &mon->pid, mon->env, mon->msg);
            // fall-through to delete monitor data
        case MONITOR_NONE: { // socket destructor waiting
            monitors_freed = true;
            monitor_data* next = mon->next;
            free_monitor_data(mon);
            *monptr = next;
            continue;
        }
        }

        if (mon->socket > sdata->nfds) sdata->nfds = mon->socket;

        monptr = &(mon->next);
    }

    if (monitors_freed) enif_cond_broadcast(adata->cond);

    enif_mutex_unlock(adata->lock);

    sdata->nfds += 1;

    return true;
}


static void* select_thread(void* arg)
{
    select_data data;
    init_select(&data, (afunix_data*) arg);

    do {
        int rc = select(data.nfds, &data.rfds, &data.wfds, NULL, NULL);
        if (rc == -1 && errno == EINTR) continue;

        assert(rc != -1);

        drain_wakeup_pipe(&data);
        send_notifications(&data, (afunix_data*) arg);

    } while (update_select(&data, (afunix_data*) arg));

    return NULL;
}


static bool start_select_thread(afunix_data* data)
{
    enif_mutex_lock(data->lock);

    if (enif_thread_create("afunix", &data->tid, select_thread, data, 0) != 0) {
        enif_mutex_unlock(data->lock);
        return false;
    }

    data->running = true;
    enif_mutex_unlock(data->lock);

    return true;
}


static void stop_select_thread(afunix_data* data)
{
    enif_mutex_lock(data->lock);

    assert(data->running);

    data->running = false;

    wakeup_select_thread(data);

    enif_mutex_unlock(data->lock);

    enif_thread_join(data->tid, NULL);
}


static ERL_NIF_TERM alloc_socket(ErlNifEnv* env, int fd)
{
    socket_data *sd = enif_alloc_resource(socket_type,sizeof(socket_data));
    sd->fd = fd;
    sd->unlink = false;

    ERL_NIF_TERM socket = enif_make_resource(env, sd);

    enif_release_resource(sd);

    return socket;
}


static bool get_socket(ErlNifEnv* env, ERL_NIF_TERM term, socket_data** sdptr)
{
    void *res;
    if (!enif_get_resource(env, term, socket_type, &res)) return false;

    *sdptr = (socket_data *)res;

    return true;
}


static ERL_NIF_TERM alloc_fd(ErlNifEnv* env, int fd)
{
    int *res = enif_alloc_resource(fd_type, sizeof(int));
    *res = fd;

    ERL_NIF_TERM fd_term = enif_make_resource_binary(env, res, res, sizeof(int));
    enif_release_resource(res);

    return fd_term;
}


static bool get_fd(ErlNifEnv* env, ERL_NIF_TERM term, int* fd)
{
    ErlNifBinary bin;
    if (!enif_inspect_binary(env, term, &bin) || bin.size != sizeof(int))
        return false;

    *fd = *(int* )bin.data;

    return fcntl(*fd, F_GETFD) != -1;
}


static bool get_path(ErlNifEnv* env, ERL_NIF_TERM term, ErlNifBinary* path)
{
    return enif_inspect_binary(env, term, path);
}


static bool init_sockaddr(socket_data* sd, ErlNifBinary path)
{
    struct sockaddr_un* addr = &sd->addr;

    memset(addr, 0, sizeof *addr);
    addr->sun_family = AF_UNIX;

    if ((path.size + 1) > sizeof(addr->sun_path)) return false;

    memcpy(addr->sun_path, path.data, path.size);

    return true;
}


static bool unlink_sockpath(const char* path)
{
    struct stat sb;

    if (stat(path, &sb) != 0) return errno == ENOENT;

    if (S_ISREG(sb.st_mode) || S_ISDIR(sb.st_mode)) return false;

    return unlink(path) == 0;
}


static ERL_NIF_TERM errno_error(ErlNifEnv* env, int error) {
    ERL_NIF_TERM reason = enif_make_atom(env, erl_errno_id(error));

    return enif_make_tuple2(env, atom_error, reason);
}


static ERL_NIF_TERM closed_error(ErlNifEnv* env) {
    return enif_make_tuple2(env, atom_error, atom_closed);
}


static ERL_NIF_TERM errno_exception(ErlNifEnv* env, int error) {
    ERL_NIF_TERM reason = enif_make_atom(env, erl_errno_id(errno));

    return enif_raise_exception(env, reason);
}


static ERL_NIF_TERM
socket_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return errno_exception(env, errno);

    if (!make_fd_nonblock(fd)) {
        int error = errno;
        close(fd);
        return errno_error(env, error);
    }

    return alloc_socket(env, fd);
}


static ERL_NIF_TERM
bind_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data* sd;
    ErlNifBinary path;

    if (!get_socket(env, argv[0], &sd) || !get_path(env, argv[1], &path))
        return enif_make_badarg(env);

    if (sd->fd == -1) return closed_error(env);

    if (!init_sockaddr(sd, path)) return enif_make_badarg(env);

    if (enif_is_identical(argv[2], atom_true)) {
        if (!unlink_sockpath(sd->addr.sun_path))
            return enif_make_badarg(env);

        sd->unlink = true;

    } else if (!enif_is_identical(argv[2], atom_false)) {
        return enif_make_badarg(env);
    }

    socklen_t len = sizeof(sd->addr.sun_family) + strlen(sd->addr.sun_path);

    if (bind(sd->fd, (struct sockaddr *)&sd->addr, len) == -1) {
        sd->unlink = false;
        return errno_error(env, errno);
    }

    return atom_ok;
}


static ERL_NIF_TERM
listen_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data* sd;
    int backlog;

    if (!get_socket(env, argv[0], &sd) || !enif_get_int(env, argv[1], &backlog))
        return enif_make_badarg(env);

    if (sd->fd == -1) return closed_error(env);

    if (listen(sd->fd, backlog) == -1) return errno_error(env, errno);

    return atom_ok;
}


static ERL_NIF_TERM
accept_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data* sd;

    if (!get_socket(env, argv[0], &sd)) return enif_make_badarg(env);

    if (sd->fd == -1) return closed_error(env);

    int afd = accept(sd->fd, NULL, NULL);
    if (afd == -1) return errno_error(env, errno);

    if (!make_fd_nonblock(afd)) {
        int error = errno;
        close(afd);
        return errno_error(env, error);
    }

    ERL_NIF_TERM socket = alloc_socket(env, afd);
    return enif_make_tuple2(env, atom_ok, socket);
}


static ERL_NIF_TERM
connect_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data *sd;
    ErlNifBinary path;

    if (!get_socket(env, argv[0], &sd) || !get_path(env, argv[1], &path))
        return enif_make_badarg(env);

    if (sd->fd == -1) return closed_error(env);

    if (!init_sockaddr(sd, path)) return enif_make_badarg(env);

    socklen_t len = sizeof(sd->addr.sun_family) + strlen(sd->addr.sun_path);

    if (connect(sd->fd, (struct sockaddr *)&sd->addr, len) == -1)
        return errno_error(env, errno);

    return atom_ok;
}


static ERL_NIF_TERM
send_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data *sd;
    ErlNifBinary bin;

    if (!get_socket(env, argv[0], &sd) ||
        !enif_inspect_binary(env, argv[1], &bin) ||
        bin.size == 0)
        return enif_make_badarg(env);

    if (sd->fd == -1) return closed_error(env);

    struct iovec iov[1];
    iov[0].iov_base = bin.data;
    iov[0].iov_len = bin.size;

    struct msghdr msg = {0};
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    ssize_t len;
    do {
        len = sendmsg(sd->fd, &msg, MSG_NOSIGNAL);
    } while (len < 0 && errno == EINTR);

    if (len < 0)
        return errno_error(env, errno);

    if (len < bin.size)
        return enif_make_tuple2(env, atom_ok, enif_make_uint(env, len));

    return atom_ok;
}


static ERL_NIF_TERM
send_fd_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data *sd;
    unsigned num_fd;
    ErlNifBinary bin;

    if (!get_socket(env, argv[0], &sd) ||
        !enif_get_list_length(env, argv[1], &num_fd) ||
        num_fd > MAX_FDS ||
        !enif_inspect_binary(env, argv[2], &bin) ||
        bin.size == 0)
        return enif_make_badarg(env);

    if (sd->fd == -1) return closed_error(env);

    struct msghdr msg = {0};

    struct cmsghdr *cmsg;
    int fds[num_fd];

    ERL_NIF_TERM fd_list = argv[1];
    ERL_NIF_TERM fd_cell;
    int fd;
    unsigned fd_idx = 0;

    while (enif_get_list_cell(env, fd_list, &fd_cell, &fd_list)) {
        if (!get_fd(env, fd_cell, &fd))
            return enif_make_badarg(env);

        fds[fd_idx++] = fd;
    }

    union {
        char buf[CMSG_SPACE(sizeof fds)];
        struct cmsghdr align;
    } u;

    msg.msg_control = u.buf;
    msg.msg_controllen = sizeof u.buf;
    cmsg = CMSG_FIRSTHDR(&msg);
    cmsg->cmsg_level = SOL_SOCKET;
    cmsg->cmsg_type = SCM_RIGHTS;
    cmsg->cmsg_len = CMSG_LEN(sizeof(int) * num_fd);

    int* fdptr = (int *) CMSG_DATA(cmsg);
    memcpy(fdptr, fds, num_fd * sizeof(int));

    struct iovec iov[1];
    iov[0].iov_base = bin.data;
    iov[0].iov_len = bin.size;

    msg.msg_iov = iov;
    msg.msg_iovlen = 1;

    ssize_t len;
    do {
        len = sendmsg(sd->fd, &msg, MSG_NOSIGNAL);
    } while (len < 0 && errno == EINTR);

    if (len < 0)
        return errno_error(env, errno);

    if (len < bin.size)
        return enif_make_tuple2(env, atom_ok, enif_make_uint(env, len));

    return atom_ok;
}


static ERL_NIF_TERM
recv_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data *sd;
    unsigned size;
    if (!get_socket(env, argv[0], &sd) || !enif_get_uint(env, argv[1], &size))
        return enif_make_badarg(env);

    if (sd->fd == -1) return closed_error(env);

    ErlNifBinary buf;
    if (!enif_alloc_binary(size, &buf)) return enif_make_badarg(env);

    union {
        char ctrl_buf[CMSG_SPACE(sizeof(int) * MAX_FDS)];
        struct cmsghdr align;
    } u;

    struct iovec iov[1];
    iov[0].iov_base = buf.data;
    iov[0].iov_len = buf.size;

    struct msghdr msg = {0};

    msg.msg_name = NULL;
    msg.msg_namelen = 0;
    msg.msg_iov = iov;
    msg.msg_iovlen = 1;
    msg.msg_control = u.ctrl_buf;
    msg.msg_controllen = CMSG_LEN(sizeof(int) * MAX_FDS);
    msg.msg_flags = 0;

    ssize_t len;
    do {
        len = recvmsg(sd->fd, &msg, MSG_CMSG_CLOEXEC);
    } while (len < 0 && errno == EINTR);

    if (len < 0) {
        int err = errno;
        enif_release_binary(&buf);
        return errno_error(env, err);
    }

    ERL_NIF_TERM fd_list;
    unsigned fd_cnt = 0;

    for (struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg); cmsg != NULL;
         cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level != SOL_SOCKET || cmsg->cmsg_type != SCM_RIGHTS)
            continue;

        size_t len = (cmsg->cmsg_len - CMSG_LEN(0)) / sizeof(int);
        int *fd_ptr = (int *) CMSG_DATA(cmsg);

        if (fd_cnt == 0) fd_list = enif_make_list(env, 0);

        for (size_t i = 0; i < len; ++i) {
            ERL_NIF_TERM fd_cell = alloc_fd(env, fd_ptr[i]);
            fd_list = enif_make_list_cell(env, fd_cell, fd_list);
            ++fd_cnt;
        }
    }

    if (len == 0 && fd_cnt == 0) {
        enif_release_binary(&buf);
        return enif_make_tuple2(env, atom_error, atom_closed);
    }

    enif_realloc_binary(&buf, len);
    ERL_NIF_TERM recv_data = enif_make_binary(env, &buf);

    if (fd_cnt > 0)
        return enif_make_tuple3(env, atom_ok, fd_list, recv_data);

    return enif_make_tuple2(env, atom_ok, recv_data);
}


static ERL_NIF_TERM
close_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data *sd = NULL;
    int *fd;

    if (get_socket(env, argv[0], &sd))
        fd = &sd->fd;
    else
        return enif_make_badarg(env);

    if (*fd == -1)
        return enif_make_tuple2(env, atom_error, atom_closed);

    if (sd != NULL) cancel_monitors(env, sd, true);

    if (close(*fd) == -1)
        return errno_error(env, errno);

    *fd = -1;
    return atom_ok;
}


static ERL_NIF_TERM
getsockopt_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    size_t sopt;
    int iopt;
    int optname;
    void *optval;
    socklen_t optlen;

    socket_data *sd;
    if (!get_socket(env, argv[0], &sd)) return enif_make_badarg(env);

    if (enif_is_identical(argv[1], atom_error)) {
        optname = SO_ERROR;
        optval = &iopt;
        optlen = sizeof(int);
    } else if (enif_is_identical(argv[1], atom_recbuf)) {
        optname = SO_RCVBUF;
        optval = &sopt;
        optlen = sizeof(size_t);
    } else if (enif_is_identical(argv[1], atom_sndbuf)) {
        optname = SO_SNDBUF;
        optval = &sopt;
        optlen = sizeof(size_t);
    } else {
        return enif_make_badarg(env);
    }

    if (getsockopt(sd->fd, SOL_SOCKET, optname, optval, &optlen) == -1)
        return errno_exception(env, errno);

    if (enif_is_identical(argv[1], atom_error)) {
        return iopt == 0 ? atom_noerror
                         : enif_make_atom(env, erl_errno_id(iopt));

    } else if (enif_is_identical(argv[1], atom_recbuf)) {
        return enif_make_uint(env, sopt);

    } else if (enif_is_identical(argv[1], atom_sndbuf)) {
        return enif_make_uint(env, sopt);
    }

    return enif_make_badarg(env);
}


static ERL_NIF_TERM
setsockopt_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    unsigned int utmp;
    size_t sopt;
    int optname;
    void *optval;
    socklen_t optlen;

    socket_data *sd;
    if (!get_socket(env, argv[0], &sd)) return enif_make_badarg(env);

    if (enif_is_identical(argv[1], atom_recbuf)
        && enif_get_uint(env, argv[2], &utmp)) {
        sopt = utmp;
        optname = SO_RCVBUF;
        optval = &sopt;
        optlen = sizeof(size_t);

    } else if (enif_is_identical(argv[1], atom_sndbuf)
        && enif_get_uint(env, argv[2], &utmp)) {
        sopt = utmp;
        optname = SO_SNDBUF;
        optval = &sopt;
        optlen = sizeof(size_t);

    } else {
        return enif_make_badarg(env);
    }

    if (setsockopt(sd->fd, SOL_SOCKET, optname, optval, optlen) == -1)
        return errno_exception(env, errno);

    return atom_ok;
}


static ERL_NIF_TERM
monitor_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    afunix_data *data = priv_data(env);

    socket_data *sd;
    if (!get_socket(env, argv[0], &sd)) return enif_make_badarg(env);

    int event;
    if (enif_is_identical(argv[1], atom_read))
        event = MONITOR_READ;
    else if (enif_is_identical(argv[1], atom_write))
        event = MONITOR_WRITE;
    else
       return enif_make_badarg(env);

    ERL_NIF_TERM ref = enif_make_ref(env);

    enif_mutex_lock(data->lock);

    monitor_data* mon = init_monitor_data(env, sd, event, ref);

    if (mon == NULL) {
        enif_mutex_unlock(data->lock);
        return enif_make_badarg(env);
    }

    monitor_data** monptr = &data->monitors;

    while (*monptr != NULL) monptr = &((*monptr)->next);

    *monptr = mon;

    wakeup_select_thread(data);

    enif_mutex_unlock(data->lock);

    return ref;
}


static int onload(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    ErlNifSysInfo sys_info;
    enif_system_info(&sys_info, sizeof(ErlDrvSysInfo));

    if (!sys_info.smp_support) return -1;

    if (!init_resource_types(env, ERL_NIF_RT_CREATE))
        return -1;

    init_atoms(env);

    afunix_data* data = init_priv_data();

    if (data != NULL && !start_select_thread(data)) {
        free_priv_data(data);
        data = NULL;
    }

    *priv_data = data;
    return data != NULL ? 0 : -1;
}


static int upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data,
                   ERL_NIF_TERM load_info)
{
    if (!init_resource_types(env, ERL_NIF_RT_TAKEOVER))
        return -1;

    init_atoms(env);

    afunix_data* data = init_priv_data();

    if (data != NULL) {
        if (start_select_thread(data)) {
            upgrade_priv_data(*old_priv_data, data);
        } else {
            free_priv_data(data);
            data = NULL;
        }
    }

    *priv_data = data;
    return data != NULL ? 0 : -1;
}


static void unload(ErlNifEnv *env, void *priv_data)
{
    stop_select_thread((afunix_data *) priv_data);
    free_priv_data((afunix_data *) priv_data);
}


static ErlNifFunc nifs[] =
{
    {"socket",        0, socket_nif},
    {"bind",          3, bind_nif},
    {"listen",        2, listen_nif},
    {"accept",        1, accept_nif},
    {"connect",       2, connect_nif},
    {"send",          2, send_nif},
    {"send",          3, send_fd_nif},
    {"recv",          2, recv_nif},
    {"close",         1, close_nif},
    {"getsockopt",    2, getsockopt_nif},
    {"setsockopt",    3, setsockopt_nif},
    {"monitor",       2, monitor_nif},
};


ERL_NIF_INIT(afunix,nifs,onload,NULL,upgrade,unload)
