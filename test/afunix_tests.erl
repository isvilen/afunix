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
    ok = send(C, <<"data">>, [memfd:fd(Fd)]),

    {ok, C1} = accept(S),
    {ok, <<"data">>, [Fd1]} = recv(C1, 100),
    MemFd = memfd:new(Fd1),
    ?assertMatch({ok, <<1,2,3,4>>}, memfd:pread(MemFd, 0, 4)).


accept_select_test() ->
    Path = socket_path(),

    S = socket(),
    ok = bind(S, Path),
    ok = listen(S),

    {error, eagain} = accept(S),
    Ref = make_ref(),
    ok = afunix:select(S, input, Ref),

    C = socket(),
    ok = connect(C, Path),

    receive {select, S, Ref, ready_input} -> {ok, _} = accept(S) end.


connect_select_test() ->
    Path = socket_path(),

    S = socket(),
    ok = bind(S, Path),
    ok = listen(S, 0),

    C1 = socket(),
    ok = connect(C1, Path),

    C2 = socket(),
    {error, eagain} = connect(C2, Path),

    Ref = make_ref(),
    ok = afunix:select(C2, output, Ref),

    {ok, _} = accept(S),
    receive {select, C2, Ref, ready_output} -> ok = connect(C2, Path) end.


close_with_select_test() ->
    Path = socket_path(),

    S = socket(),
    ok = bind(S, Path),
    ok = listen(S),

    Ref = make_ref(),
    ok = afunix:select(S, input, Ref),
    ok = afunix:close(S),

    {error, _} = accept(S).


socket_path() ->
    list_to_binary(io_lib:format("./socket-~p", [self()])).
