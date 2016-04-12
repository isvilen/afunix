-module(afunix_tests).

-include_lib("eunit/include/eunit.hrl").

-import(afunix,[ socket/0
               , bind/2
               , listen/1
               , connect/2
               , accept/1
               , send/2
               , send/3
               , recv/2
               ]).

-define(async(Expr),spawn_link(fun() -> Expr end)).


send_receive_test() ->
    Path = socket_path(),
    S = server(Path),
    ?async(begin C = client(Path), ok = send(C, <<"data">>) end),
    {ok, C} = accept(S),
    ?assertMatch({ok, <<"data">>}, recv(C, 100)).


send_receive_fd_test() ->
    Path = socket_path(),
    S = server(Path),
    ?async(begin C = client(Path),
                 Fd = memfd:create(),
                 ok = memfd:pwrite(Fd, bof, <<1,2,3,4>>),
                 FdBin = memfd:fd_to_binary(Fd),
                 ok = send(C, [afunix:fd_from_binary(FdBin)], <<"data">>)
           end),
    {ok, C} = accept(S),
    {ok, [Fd], <<"data">>} = recv(C, 100),
    FdBin = afunix:fd_to_binary(Fd),
    MemFd = memfd:fd_from_binary(FdBin),
    ?assertMatch({ok, <<1,2,3,4>>}, memfd:pread(MemFd, 0, 4)).


socket_path() ->
    list_to_binary(io_lib:format("./socket-~p", [self()])).


server(Path) ->
    S = socket(),
    ok = bind(S, Path),
    ok = listen(S),
    S.


client(Path) ->
    C = socket(),
    ok = connect(C, Path),
    C.
