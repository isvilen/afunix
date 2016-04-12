#include <sys/types.h>
#include <sys/stat.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <string.h>

#include <erl_nif.h>
#include <erl_driver.h>


#define MAX_FDS 28


typedef struct {
    ErlNifResourceType* socket_type;
    ErlNifResourceType* fd_type;
    ERL_NIF_TERM atom_ok;
    ERL_NIF_TERM atom_error;
    ERL_NIF_TERM atom_closed;
    ERL_NIF_TERM atom_true;
    ERL_NIF_TERM atom_false;
    ERL_NIF_TERM atom_noerror;
    ERL_NIF_TERM atom_recbuf;
    ERL_NIF_TERM atom_sndbuf;
} afunix_data;


typedef struct {
    int fd;
    struct sockaddr_un addr;
    bool unlink;
} socket_data;


static void socket_dtor(ErlNifEnv *env, void *obj)
{
    socket_data *sd = (socket_data *) obj;

    if (sd->fd != -1) close(sd->fd);

    if (sd->unlink) unlink(sd->addr.sun_path);
}


static void fd_dtor(ErlNifEnv *env, void *obj)
{
    int *fd = (int *) obj;

    if (*fd != -1) close(*fd);
}


static afunix_data* init_priv_data(ErlNifEnv* env, ErlNifResourceFlags flags)
{
    ErlNifResourceType *socket_type, *fd_type;

    socket_type = enif_open_resource_type(env, NULL, "socket", socket_dtor,
                                          flags, NULL);

    fd_type = enif_open_resource_type(env, NULL, "fd", fd_dtor, flags, NULL);

    if (!socket_type || !fd_type) return NULL;

    afunix_data *data = (afunix_data *) enif_alloc(sizeof(afunix_data));

    data->socket_type = socket_type;
    data->fd_type = fd_type;

    data->atom_ok = enif_make_atom(env, "ok");
    data->atom_error = enif_make_atom(env, "error");
    data->atom_closed = enif_make_atom(env, "closed");
    data->atom_true = enif_make_atom(env, "true");
    data->atom_false = enif_make_atom(env, "false");
    data->atom_recbuf = enif_make_atom(env, "recbuf");
    data->atom_sndbuf = enif_make_atom(env, "sndbuf");
    data->atom_noerror = enif_make_atom(env, "noerror");

    return data;
}


static afunix_data* priv_data(ErlNifEnv* env)
{
    return (afunix_data *) enif_priv_data(env);
}


static ERL_NIF_TERM alloc_socket(ErlNifEnv* env, int fd)
{
    afunix_data *data = priv_data(env);

    socket_data *sd = enif_alloc_resource(data->socket_type,sizeof(socket_data));
    sd->fd = fd;
    sd->unlink = false;

    ERL_NIF_TERM socket = enif_make_resource(env, sd);

    enif_release_resource(sd);

    return socket;
}


static bool get_socket(ErlNifEnv* env, ERL_NIF_TERM term, socket_data** sdptr)
{
    afunix_data *data = priv_data(env);

    void *res;
    if (!enif_get_resource(env, term, data->socket_type, &res)) return false;

    *sdptr = (socket_data *)res;

    return true;
}


static ERL_NIF_TERM alloc_fd(ErlNifEnv* env, int fd)
{
    int *res = enif_alloc_resource(priv_data(env)->fd_type, sizeof(int));
    *res = fd;

    ERL_NIF_TERM fd_term = enif_make_resource(env, res);
    enif_release_resource(res);

    return fd_term;
}


static bool get_fd(ErlNifEnv* env, ERL_NIF_TERM term, int** fd)
{
    afunix_data *data = priv_data(env);

    void *res;
    if (!enif_get_resource(env, term, data->fd_type, &res)) return false;

    *fd = (int *)res;

    return true;
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

    return enif_make_tuple2(env, priv_data(env)->atom_error, reason);
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

    return alloc_socket(env, fd);
}


static ERL_NIF_TERM
bind_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    afunix_data *data = (afunix_data *) enif_priv_data(env);

    socket_data* sd;
    ErlNifBinary path;

    if (!get_socket(env, argv[0], &sd) || !get_path(env, argv[1], &path))
        return enif_make_badarg(env);

    if (!init_sockaddr(sd, path)) return enif_make_badarg(env);

    if (enif_is_identical(argv[2], data->atom_true)) {
        if (!unlink_sockpath(sd->addr.sun_path))
            return enif_make_badarg(env);

        sd->unlink = true;

    } else if (!enif_is_identical(argv[2], data->atom_false)) {
        return enif_make_badarg(env);
    }

    socklen_t len = sizeof(sd->addr.sun_family) + strlen(sd->addr.sun_path);

    if (bind(sd->fd, (struct sockaddr *)&sd->addr, len) == -1) {
        sd->unlink = false;
        return errno_error(env, errno);
    }

    return data->atom_ok;
}


static ERL_NIF_TERM
listen_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data* sd;
    int backlog;

    if (!get_socket(env, argv[0], &sd) || !enif_get_int(env, argv[1], &backlog))
        return enif_make_badarg(env);

    if (listen(sd->fd, backlog) == -1) return errno_error(env, errno);

    return priv_data(env)->atom_ok;
}


static ERL_NIF_TERM
accept_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data* sd;

    if (!get_socket(env, argv[0], &sd)) return enif_make_badarg(env);

    int afd = accept(sd->fd, NULL, NULL);
    if (afd == -1) return errno_error(env, errno);

    ERL_NIF_TERM socket = alloc_socket(env, afd);
    return enif_make_tuple2(env, priv_data(env)->atom_ok, socket);
}


static ERL_NIF_TERM
connect_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data *sd;
    ErlNifBinary path;

    if (!get_socket(env, argv[0], &sd) || !get_path(env, argv[1], &path))
        return enif_make_badarg(env);

    if (!init_sockaddr(sd, path)) return enif_make_badarg(env);

    socklen_t len = sizeof(sd->addr.sun_family) + strlen(sd->addr.sun_path);

    if (connect(sd->fd, (struct sockaddr *)&sd->addr, len) == -1)
        return errno_error(env, errno);

    return priv_data(env)->atom_ok;
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

    afunix_data *data = priv_data(env);

    if (len < bin.size)
        return enif_make_tuple2(env, data->atom_ok, enif_make_uint(env, len));

    return data->atom_ok;
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

    struct msghdr msg = {0};

    struct cmsghdr *cmsg;
    int fds[num_fd];

    ERL_NIF_TERM fd_list = argv[1];
    ERL_NIF_TERM fd_cell;
    int *fdptr;
    unsigned fd_idx = 0;

    while (enif_get_list_cell(env, fd_list, &fd_cell, &fd_list)) {
        if (!get_fd(env, fd_cell, &fdptr) || *fdptr == -1)
            return enif_make_badarg(env);

        fds[fd_idx++] = *fdptr;
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

    fdptr = (int *) CMSG_DATA(cmsg);
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

    afunix_data *data = priv_data(env);

    if (len < bin.size)
        return enif_make_tuple2(env, data->atom_ok, enif_make_uint(env, len));

    return data->atom_ok;
}


static ERL_NIF_TERM
recv_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data *sd;
    unsigned size;
    if (!get_socket(env, argv[0], &sd) || !enif_get_uint(env, argv[1], &size))
        return enif_make_badarg(env);

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

    afunix_data *data = priv_data(env);

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
        return enif_make_tuple2(env, data->atom_error, data->atom_closed);
    }

    enif_realloc_binary(&buf, len);
    ERL_NIF_TERM recv_data = enif_make_binary(env, &buf);

    if (fd_cnt > 0)
        return enif_make_tuple3(env, data->atom_ok, fd_list, recv_data);

    return enif_make_tuple2(env, data->atom_ok, recv_data);
}


static ERL_NIF_TERM
close_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    socket_data *sd;
    int *fd;

    if (get_socket(env, argv[0], &sd))
        fd = &sd->fd;
    else if (!get_fd(env, argv[0], &fd))
        return enif_make_badarg(env);

    afunix_data *data = priv_data(env);

    if (*fd == -1)
        return enif_make_tuple2(env, data->atom_error, data->atom_closed);


    if (close(*fd) == -1)
        return errno_error(env, errno);

    *fd = -1;
    return data->atom_ok;
}


static ERL_NIF_TERM
fd_to_bin_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    int *fd;
    if (!get_fd(env, argv[0], &fd) || *fd == -1) return enif_make_badarg(env);

    return enif_make_resource_binary(env, fd, fd, sizeof(int));
}


static ERL_NIF_TERM
fd_from_bin_nif(ErlNifEnv* env, int argc, const ERL_NIF_TERM argv[])
{
    ErlNifBinary bin;
    if (!enif_inspect_binary(env, argv[0], &bin) || bin.size != sizeof(int))
        return enif_make_badarg(env);

    int old_fd = *(int* )bin.data;

    int new_fd = dup(old_fd);
    if (new_fd == -1) return enif_make_badarg(env);

    return alloc_fd(env, new_fd);
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

    afunix_data *data = priv_data(env);

    if (enif_is_identical(argv[1], data->atom_error)) {
        optname = SO_ERROR;
        optval = &iopt;
        optlen = sizeof(int);
    } else if (enif_is_identical(argv[1], data->atom_recbuf)) {
        optname = SO_RCVBUF;
        optval = &sopt;
        optlen = sizeof(size_t);
    } else if (enif_is_identical(argv[1], data->atom_sndbuf)) {
        optname = SO_SNDBUF;
        optval = &sopt;
        optlen = sizeof(size_t);
    } else {
        return enif_make_badarg(env);
    }

    if (getsockopt(sd->fd, SOL_SOCKET, optname, optval, &optlen) == -1)
        return errno_exception(env, errno);

    if (enif_is_identical(argv[1], data->atom_error)) {
        return iopt == 0 ? data->atom_noerror
                         : enif_make_atom(env, erl_errno_id(iopt));

    } else if (enif_is_identical(argv[1], data->atom_recbuf)) {
        return enif_make_uint(env, sopt);

    } else if (enif_is_identical(argv[1], data->atom_sndbuf)) {
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

    afunix_data *data = priv_data(env);

    if (enif_is_identical(argv[1], data->atom_recbuf)
        && enif_get_uint(env, argv[2], &utmp)) {
        sopt = utmp;
        optname = SO_RCVBUF;
        optval = &sopt;
        optlen = sizeof(size_t);

    } else if (enif_is_identical(argv[1], data->atom_sndbuf)
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

    return data->atom_ok;
}


static int onload(ErlNifEnv *env, void **priv_data, ERL_NIF_TERM load_info)
{
    ErlNifSysInfo sys_info;
    enif_system_info(&sys_info, sizeof(ErlDrvSysInfo));

    if (!sys_info.dirty_scheduler_support) return -1;

    *priv_data = init_priv_data(env, ERL_NIF_RT_CREATE);

    return *priv_data != NULL ? 0 : -1;
}


static int upgrade(ErlNifEnv* env, void** priv_data, void** old_priv_data,
                   ERL_NIF_TERM load_info)
{
    *priv_data = init_priv_data(env, ERL_NIF_RT_TAKEOVER);

    return *priv_data != NULL ? 0 : -1;
}


static void unload(ErlNifEnv *env, void *priv_data)
{
    enif_free(priv_data);
}


static ErlNifFunc nifs[] =
{
    {"socket",        0, socket_nif},
    {"bind",          3, bind_nif},
    {"listen",        2, listen_nif},
    {"accept",        1, accept_nif, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"connect",       2, connect_nif, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"send",          2, send_nif, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"send",          3, send_fd_nif, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"recv",          2, recv_nif, ERL_NIF_DIRTY_JOB_IO_BOUND},
    {"close",         1, close_nif},
    {"fd_to_binary",  1, fd_to_bin_nif},
    {"fd_from_binary",1, fd_from_bin_nif},
    {"getsockopt",    2, getsockopt_nif},
    {"setsockopt",    3, setsockopt_nif},
};


ERL_NIF_INIT(afunix,nifs,onload,NULL,upgrade,unload)
