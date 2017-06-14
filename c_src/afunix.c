#define _GNU_SOURCE
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
#include <stdio.h>
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
static ERL_NIF_TERM atom_input;
static ERL_NIF_TERM atom_output;
static ERL_NIF_TERM atom_undefined;


typedef struct {
    ErlNifMutex* mtx;
    int fd;
    struct sockaddr_un addr;
    bool unlink;
} socket_data;


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


static int close_socket(ErlNifEnv *env, socket_data *sd)
{
    enif_mutex_lock(sd->mtx);

    if (sd->fd == -1) {
        enif_mutex_unlock(sd->mtx);
        return 0;
    }

    int rc = enif_select(env, sd->fd, ERL_NIF_SELECT_STOP, sd, NULL,
                         atom_undefined);

    if (rc > 0 && ((rc & ERL_NIF_SELECT_STOP_CALLED)
                   || (rc & ERL_NIF_SELECT_STOP_SCHEDULED))) {
        sd->fd = -1;
        enif_mutex_unlock(sd->mtx);
        return 0;
    }

    rc = 0;

    if (close(sd->fd) != 0) rc = errno;

    sd->fd = -1;

    enif_mutex_unlock(sd->mtx);

    return rc;
}


static void socket_dtor(ErlNifEnv *env, void *obj)
{
    socket_data *sd = (socket_data *) obj;

    int rc = close_socket(env, sd);
    if (rc != 0) {
        enif_fprintf(stderr, "afunix: close fd %d error %d", sd->fd, rc);
    }

    if (sd->unlink) unlink(sd->addr.sun_path);

    enif_mutex_destroy(sd->mtx);
}


static void socket_stop(ErlNifEnv* env, void* obj, ErlNifEvent event,
                        int is_direct_call)
{
    if (close(event) != 0) {
        enif_fprintf(stderr, "afunix: close fd %d error %d", event, errno);
    }
}


static void socket_down(ErlNifEnv* env, void* obj, ErlNifPid* pid,
                        ErlNifMonitor* mon)
{
    socket_data *sd = (socket_data *) obj;

    int rc = close_socket(env, sd);
    if (rc != 0) {
        enif_fprintf(stderr, "afunix: close fd %d error %d", sd->fd, rc);
    }
}


static void fd_dtor(ErlNifEnv *env, void *obj)
{
    int *fd = (int *) obj;

    if (close(*fd) != 0) {
        enif_fprintf(stderr, "afunix: close fd %d error %d", *fd, errno);
    }
}


static bool init_resource_types(ErlNifEnv* env, ErlNifResourceFlags flags)
{
    ErlNifResourceTypeInit init;
    init.dtor = socket_dtor;
    init.stop = socket_stop;
    init.down = socket_down;

    socket_type = enif_open_resource_type_x(env, "socket", &init, flags, NULL);
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
    atom_input = enif_make_atom(env, "input");
    atom_output = enif_make_atom(env, "output");
    atom_undefined = enif_make_atom(env, "undefined");
}


static ERL_NIF_TERM alloc_socket(ErlNifEnv* env, int fd)
{
    int flags = fcntl(fd, F_GETFL, 0);
    if (flags == -1 || fcntl(fd, F_SETFL, flags | O_NONBLOCK) == -1) {
        int error = errno;
        close(fd);
        return errno_error(env, error);
    }

    ErlNifPid pid;
    enif_self(env, &pid);

    socket_data *sd = enif_alloc_resource(socket_type,sizeof(socket_data));

    sd->mtx = enif_mutex_create("afunix_socket");
    if (sd->mtx == NULL) {
        enif_release_resource(sd);
        close(fd);
        return errno_error(env, ENOLCK);
    }

    if (enif_monitor_process(env, sd, &pid, NULL) != 0) {
        enif_mutex_destroy(sd->mtx);
        enif_release_resource(sd);
        close(fd);
        return enif_make_badarg(env);
    }

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


static ERL_NIF_TERM
socket_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) return errno_exception(env, errno);

    return alloc_socket(env, fd);
}


static ERL_NIF_TERM
bind_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data* sd;
    ErlNifBinary path;

    if (!get_socket(env, argv[0], &sd) || !get_path(env, argv[1], &path))
        return enif_make_badarg(env);

    enif_mutex_lock(sd->mtx);

    if (sd->fd == -1) {
        enif_mutex_unlock(sd->mtx);
        return closed_error(env);
    }

    if (!init_sockaddr(sd, path)) {
        enif_mutex_unlock(sd->mtx);
        return enif_make_badarg(env);
    }

    if (enif_is_identical(argv[2], atom_true)) {
        if (!unlink_sockpath(sd->addr.sun_path)) {
            enif_mutex_unlock(sd->mtx);
            return enif_make_badarg(env);
        }

        sd->unlink = true;

    } else if (!enif_is_identical(argv[2], atom_false)) {
        enif_mutex_unlock(sd->mtx);
        return enif_make_badarg(env);
    }

    socklen_t len = sizeof(sd->addr.sun_family) + strlen(sd->addr.sun_path);

    if (bind(sd->fd, (struct sockaddr *)&sd->addr, len) == -1) {
        int err = errno;
        sd->unlink = false;
        enif_mutex_unlock(sd->mtx);
        return errno_error(env, err);
    }

    enif_mutex_unlock(sd->mtx);
    return atom_ok;
}


static ERL_NIF_TERM
listen_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data* sd;
    int backlog;

    if (!get_socket(env, argv[0], &sd) || !enif_get_int(env, argv[1], &backlog))
        return enif_make_badarg(env);

    enif_mutex_lock(sd->mtx);

    if (sd->fd == -1) {
        enif_mutex_unlock(sd->mtx);
        return closed_error(env);
    }

    if (listen(sd->fd, backlog) == -1) {
        int err = errno;
        enif_mutex_unlock(sd->mtx);
        return errno_error(env, err);
    }

    enif_mutex_unlock(sd->mtx);
    return atom_ok;
}


static ERL_NIF_TERM
accept_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data* sd;

    if (!get_socket(env, argv[0], &sd)) return enif_make_badarg(env);

    enif_mutex_lock(sd->mtx);

    if (sd->fd == -1) {
        enif_mutex_unlock(sd->mtx);
        return closed_error(env);
    }

    int afd = accept(sd->fd, NULL, NULL);
    if (afd == -1) {
        int err = errno;
        enif_mutex_unlock(sd->mtx);
        return errno_error(env, err);
    }

    ERL_NIF_TERM socket = alloc_socket(env, afd);

    ERL_NIF_TERM reason;
    if (enif_has_pending_exception(env, &reason)) {
        enif_mutex_unlock(sd->mtx);
        return reason;
    }

    enif_mutex_unlock(sd->mtx);
    return enif_make_tuple2(env, atom_ok, socket);
}


static ERL_NIF_TERM
connect_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data *sd;
    ErlNifBinary path;

    if (!get_socket(env, argv[0], &sd) || !get_path(env, argv[1], &path))
        return enif_make_badarg(env);

    enif_mutex_lock(sd->mtx);

    if (sd->fd == -1) {
        enif_mutex_unlock(sd->mtx);
        return closed_error(env);
    }

    if (!init_sockaddr(sd, path)) {
        enif_mutex_unlock(sd->mtx);
        return enif_make_badarg(env);
    }

    socklen_t len = sizeof(sd->addr.sun_family) + strlen(sd->addr.sun_path);

    if (connect(sd->fd, (struct sockaddr *)&sd->addr, len) == -1) {
        int err = errno;
        enif_mutex_unlock(sd->mtx);
        return errno_error(env, err);
    }

    enif_mutex_unlock(sd->mtx);
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

    enif_mutex_lock(sd->mtx);

    if (sd->fd == -1) {
        enif_mutex_unlock(sd->mtx);
        return closed_error(env);
    }

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

    int err = errno;

    enif_mutex_unlock(sd->mtx);

    if (len < 0) {
        return errno_error(env, err);
    }

    if (len < bin.size) {
        return enif_make_tuple2(env, atom_ok, enif_make_uint(env, len));
    }

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

    enif_mutex_lock(sd->mtx);

    if (sd->fd == -1) {
        enif_mutex_unlock(sd->mtx);
        return closed_error(env);
    }

    struct msghdr msg = {0};

    struct cmsghdr *cmsg;
    int fds[num_fd];

    ERL_NIF_TERM fd_list = argv[1];
    ERL_NIF_TERM fd_cell;
    int fd;
    unsigned fd_idx = 0;

    while (enif_get_list_cell(env, fd_list, &fd_cell, &fd_list)) {
        if (!get_fd(env, fd_cell, &fd)) {
            enif_mutex_unlock(sd->mtx);
            return enif_make_badarg(env);
        }

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

    int err = errno;
    enif_mutex_unlock(sd->mtx);

    if (len < 0)
        return errno_error(env, err);

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

    enif_mutex_lock(sd->mtx);

    if (sd->fd == -1) {
        enif_mutex_unlock(sd->mtx);
        return closed_error(env);
    }

    ErlNifBinary buf;
    if (!enif_alloc_binary(size, &buf)) {
        enif_mutex_unlock(sd->mtx);
        return enif_make_badarg(env);
    }

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

    int err = errno;

    enif_mutex_unlock(sd->mtx);

    if (len < 0) {
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
    socket_data *sd;
    if (!get_socket(env, argv[0], &sd)) return enif_make_badarg(env);

    int rc = close_socket(env, sd);
    if (rc != 0) return errno_error(env, rc);

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

    enif_mutex_lock(sd->mtx);

    if (sd->fd == -1) {
        enif_mutex_unlock(sd->mtx);
        return closed_error(env);
    }

    if (getsockopt(sd->fd, SOL_SOCKET, optname, optval, &optlen) == -1) {
        int err = errno;
        enif_mutex_unlock(sd->mtx);
        return errno_exception(env, err);
    }

    enif_mutex_unlock(sd->mtx);

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

    enif_mutex_lock(sd->mtx);

    if (sd->fd == -1) {
        enif_mutex_unlock(sd->mtx);
        return closed_error(env);
    }

    if (setsockopt(sd->fd, SOL_SOCKET, optname, optval, optlen) == -1) {
        int err = errno;
        enif_mutex_unlock(sd->mtx);
        return errno_exception(env, err);
    }

    enif_mutex_unlock(sd->mtx);

    return atom_ok;
}


static ERL_NIF_TERM
select_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data *sd;
    if (!get_socket(env, argv[0], &sd)) return enif_make_badarg(env);

    enum ErlNifSelectFlags mode;
    if (enif_is_identical(argv[1], atom_input))
        mode = ERL_NIF_SELECT_READ;
    else if (enif_is_identical(argv[1], atom_output))
        mode = ERL_NIF_SELECT_WRITE;
    else
       return enif_make_badarg(env);

    enif_mutex_lock(sd->mtx);

    if (sd->fd == -1) {
        enif_mutex_unlock(sd->mtx);
        return closed_error(env);
    }

    int rc = enif_select(env, sd->fd, mode, sd, NULL, argv[2]);

    enif_mutex_unlock(sd->mtx);

    return rc >= 0 ? atom_ok : atom_error;
}


static ERL_NIF_TERM
credentials_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data *sd;
    if (!get_socket(env, argv[0], &sd)) return enif_make_badarg(env);

    enif_mutex_lock(sd->mtx);

    if (sd->fd == -1) {
        enif_mutex_unlock(sd->mtx);
        return closed_error(env);
    }

    struct ucred creds;
    socklen_t credslen = sizeof(struct ucred);

    if (getsockopt(sd->fd, SOL_SOCKET, SO_PEERCRED, &creds, &credslen) == -1) {
        int err = errno;
        enif_mutex_unlock(sd->mtx);
        return errno_exception(env, err);
    }

    enif_mutex_unlock(sd->mtx);

    if (creds.pid == 0) {
        return enif_make_tuple2(env, atom_ok, atom_undefined);
    }

    ERL_NIF_TERM pid = enif_make_long(env, creds.pid);
    ERL_NIF_TERM uid = enif_make_long(env, creds.uid);
    ERL_NIF_TERM gid = enif_make_long(env, creds.gid);
    ERL_NIF_TERM creds_term = enif_make_tuple3(env, pid, uid, gid);
    return enif_make_tuple2(env, atom_ok, creds_term);
}


static int onload(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    if (!init_resource_types(env, ERL_NIF_RT_CREATE))
        return -1;

    init_atoms(env);

    return 0;
}


static int upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data,
                   ERL_NIF_TERM load_info)
{
    if (!init_resource_types(env, ERL_NIF_RT_TAKEOVER))
        return -1;

    init_atoms(env);

    return 0;
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
    {"select",        3, select_nif},
    {"credentials",   1, credentials_nif},
};


ERL_NIF_INIT(afunix,nifs,onload,NULL,upgrade,NULL)
