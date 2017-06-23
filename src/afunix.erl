-module(afunix).

-export([ socket/0
        , socket/1
        , bind/2
        , bind/3
        , listen/1
        , listen/2
        , accept/1
        , connect/2
        , send/2
        , send/3
        , recv/2
        , close/1
        , getsockopt/2
        , setsockopt/3
        , select/3
        , credentials/1
        ]).

-on_load(init/0).

-define(DEFAULT_BACKLOG,5).


-type socket() :: identifier().
-type fd() :: binary().

-export_type([socket/0, fd/0]).


-spec socket() -> socket().
socket() ->
    socket(stream).


-spec socket(stream | datagram) -> socket().
socket(Type) ->
    erlang:nif_error(not_loaded, [Type]).


-spec bind(socket(), Path :: binary()) -> ok | {error, inet:posix() | closed}.
bind(Socket, Path) ->
    bind(Socket, Path, true).


-spec bind(socket(), Path :: binary(), Unlink :: boolean())
          -> ok | {error, inet:posix() | closed}.
bind(Socket, Path, Unlink) ->
    erlang:nif_error(not_loaded, [Socket, Path, Unlink]).


-spec listen(socket()) -> ok | {error, inet:posix() | closed}.
listen(Socket) ->
    listen(Socket, ?DEFAULT_BACKLOG).


-spec listen(socket(), Backlog :: pos_integer())
            -> ok | {error, inet:posix() | closed}.
listen(Socket, Backlog) ->
    erlang:nif_error(not_loaded, [Socket, Backlog]).


-spec accept(socket()) -> ok | {error, inet:posix() | closed}.
accept(Socket) ->
    erlang:nif_error(not_loaded, [Socket]).


-spec connect(socket(), Path :: binary()) -> ok | {error, inet:posix() | closed}.
connect(Socket, Path) ->
    erlang:nif_error(not_loaded, [Socket, Path]).


-spec send(socket(), Data :: iodata()) -> ok | {error, inet:posix() | closed}.
send(Socket, Data) ->
    erlang:nif_error(not_loaded, [Socket, Data]).


-spec send(socket(), Data :: iodata(), [fd()])
          -> ok | {error, inet:posix() | closed}.
send(Socket, Data, Fds) ->
    erlang:nif_error(not_loaded, [Socket, Data, Fds]).


-spec recv(socket(), Len :: pos_integer()) -> {ok, iodata()}
                                            | {ok, iodata(), [fd()]}
                                            | {error, inet:posix() | closed}.
recv(Socket, Len) ->
    erlang:nif_error(not_loaded, [Socket, Len]).


-spec close(socket()) -> ok | {error, inet:posix() | closed}.
close(Socket) ->
    erlang:nif_error(not_loaded, [Socket]).


-spec getsockopt(socket(), Option) -> {ok, Value} | {error, inet:posix() | closed}
      when Option :: sndbuf | recbuf | error,
           Value :: pos_integer() | noerror | inet:posix().
getsockopt(Socket, Option) ->
    erlang:nif_error(not_loaded, [Socket, Option]).


-spec setsockopt(socket(), Option, Value) -> ok | {error, inet:posix() | closed}
      when Option :: sndbuf | recbuf,
           Value :: pos_integer().
setsockopt(Socket, Option, Value) ->
    erlang:nif_error(not_loaded, [Socket, Option, Value]).


-spec select(socket(), What, Ref) -> ok | {error, inet:posix() | closed}
      when What :: input | output,
           Ref :: reference() | undefined.
select(Socket, What, Ref) ->
    erlang:nif_error(not_loaded, [Socket, What, Ref]).


-spec credentials(socket()) -> {ok, Result} | {error, inet:posix() | closed}
      when Result :: undefined | {Pid, Uid, Gid},
           Pid :: integer(),
           Uid :: integer(),
           Gid :: integer().
credentials(Socket) ->
    erlang:nif_error(not_loaded, [Socket]).


init() ->
    erlang:load_nif(filename:join(code:priv_dir(afunix), "afunix"), 0).
