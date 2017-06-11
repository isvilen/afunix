-module(afunix_tests).

-include_lib("eunit/include/eunit.hrl").

-import(afunix,[ socket/0
               , bind/2
               , listen/1
               , listen/2
               , connect/2
               , accept/1
               , send/2
               , send/3
               , recv/2
               ]).


send_receive_test() ->
    Path = socket_path(),

    S = socket(),
    ok = bind(S, Path),
    ok = listen(S),

    C = socket(),
    ok = connect(C, Path),

    {ok, C1} = accept(S),

    ok = send(C, <<"data">>),

    ?assertMatch({ok, <<"data">>}, recv(C1, 100)).


send_receive_fd_test() ->
    Path = socket_path(),

    S = socket(),
    ok = bind(S, Path),
    ok = listen(S),

    C = socket(),
    ok = connect(C, Path),

    Fd = memfd:new(),
    ok = memfd:pwrite(Fd, bof, <<1,2,3,4>>),
    ok = send(C, [afunix:fd_from_binary(memfd:fd(Fd))], <<"data">>),

    {ok, C1} = accept(S),
    {ok, [Fd1], <<"data">>} = recv(C1, 100),
    MemFd = memfd:new(afunix:fd_to_binary(Fd1)),
    ?assertMatch({ok, <<1,2,3,4>>}, memfd:pread(MemFd, 0, 4)).


accept_monitor_test() ->
    Path = socket_path(),

    S = socket(),
    ok = bind(S, Path),
    ok = listen(S),

    {error, eagain} = accept(S),
    Ref = afunix:monitor(S, read),

    C = socket(),
    ok = connect(C, Path),

    receive {afunix, Ref} -> {ok, _} = accept(S) end.


connect_monitor_test() ->
    Path = socket_path(),

    S = socket(),
    ok = bind(S, Path),
    ok = listen(S, 0),

    C1 = socket(),
    ok = connect(C1, Path),

    C2 = socket(),
    {error, eagain} = connect(C2, Path),

    Ref = afunix:monitor(C2, write),

    {ok, _} = accept(S),
    receive {afunix, Ref} -> ok = connect(C2, Path) end.


close_with_monitor_test() ->
    Path = socket_path(),

    S = socket(),
    ok = bind(S, Path),
    ok = listen(S),

    Ref = afunix:monitor(S, read),
    ok = afunix:close(S),

    receive {afunix, Ref} -> {error, closed} = accept(S) end.


socket_path() ->
    list_to_binary(io_lib:format("./socket-~p", [self()])).
