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


socket() ->
    socket(stream).


socket(Type) ->
    erlang:nif_error(not_loaded, [Type]).


bind(Socket, Path) ->
    bind(Socket, Path, true).

bind(Socket, Path, Unlink) ->
    erlang:nif_error(not_loaded, [Socket, Path, Unlink]).


listen(Socket) ->
    listen(Socket, ?DEFAULT_BACKLOG).

listen(Socket, Backlog) ->
    erlang:nif_error(not_loaded, [Socket, Backlog]).


accept(Socket) ->
    erlang:nif_error(not_loaded, [Socket]).


connect(Socket, Path) ->
    erlang:nif_error(not_loaded, [Socket, Path]).


send(Socket, Data) ->
    erlang:nif_error(not_loaded, [Socket, Data]).

send(Socket, Fds, Data) ->
    erlang:nif_error(not_loaded, [Socket, Fds, Data]).


recv(Socket, Len) ->
    erlang:nif_error(not_loaded, [Socket, Len]).


close(Socket) ->
    erlang:nif_error(not_loaded, [Socket]).


getsockopt(Socket, Option) ->
    erlang:nif_error(not_loaded, [Socket, Option]).

setsockopt(Socket, Option, Value) ->
    erlang:nif_error(not_loaded, [Socket, Option, Value]).


select(Socket, What, Ref) ->
    erlang:nif_error(not_loaded, [Socket, What, Ref]).


credentials(Socket) ->
    erlang:nif_error(not_loaded, [Socket]).


init() ->
    erlang:load_nif(filename:join(code:priv_dir(afunix), "afunix"), 0).
