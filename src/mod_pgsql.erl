-module(mod_pgsql).

-behaviour(gen_module).
-behaviour(gen_server).

%% API
-export([start_link/1,
         lookup_account/4,
         prepare_session/3,
         accounting_request/4,
         sync_session/1,
         handle_packet/2]).

%% gen_module callbacks
-export([start/1, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("netspire.hrl").
-include("netspire_radius.hrl").
-include("radius/radius.hrl").
-include("netflow/netflow_v5.hrl").
-include_lib("stdlib/include/qlc.hrl"). 

-record(state, {ref}).

-define(TIMEOUT, 50).
%% Acct-Status-Type attribute values
-define(ACCT_START, 1).
-define(ACCT_STOP, 2).
-define(INTERIM_UPDATE, 3).
-define(SESSION_SYNC_INTERVAL, 100 * 1000).

-record(data, {tariff, balance, octets_in, octets_out}).
-record(session, {id, ip, username, status, started_at, expires_at, finished_at, data}).

start(Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    ChildSpec = {?MODULE,
                 {?MODULE, start_link, [Options]},
                 permanent,
                 brutal_kill,
                 worker,
                 [?MODULE]
                },
    supervisor:start_child(netspire_sup, ChildSpec).

start_link(Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Options], []).

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    netspire_hooks:delete(radius_acct_lookup, ?MODULE, lookup_account),
    netspire_hooks:delete(radius_access_accept, ?MODULE, prepare_session),
    netspire_hooks:delete(radius_acct_request, ?MODULE, accounting_request),
    netspire_netflow:delete_packet_handler(?MODULE).

lookup_account(_Value, _Request, UserName, _Client) ->
    gen_server:call(?MODULE, {lookup_account, UserName}).

accounting_request(Response, Type, Request, Client) ->
    gen_server:call(?MODULE, {accounting_request, Response, Type, Request, Client}).

handle_packet(SrcIP, Pdu) ->
    gen_server:cast(?MODULE, {netflow, Pdu, SrcIP}).

sync_session(SID) ->
    gen_server:cast(?MODULE, {sync_session, SID}).


%%
%% Internal functions
%%

prepare_session(Response, Request, _Client) ->
    Username = radius:attribute_value(?USER_NAME, Request),
    IP = radius:attribute_value(?FRAMED_IP_ADDRESS, Response),
    case radius_sessions:is_exist(Username) of
        false ->
            radius_sessions:prepare(Username, IP, ?TIMEOUT),
            Response;
        true ->
            #radius_packet{code = ?ACCESS_REJECT}
    end.

connect(Server, Port, DB, UserName, Password) ->
    case pgsql:connect(Server, DB, UserName, Password, Port) of
        {ok, Ref} ->
            ?INFO_MSG("Database connection has been established~n", []),
            erlang:monitor(process, Ref),
            Ref;
        {error, Reason} ->
            ?ERROR_MSG("Connection to database failed: ~p~n", [Reason]),
            timer:sleep(3000), % 3 seconds
            connect(Server, Port, DB, UserName, Password)
    end.

init([Options]) ->
    case Options of
        [Server, Port, DB, Username, Password] ->
            Ref = connect(Server, Port, DB, Username, Password),
            netspire_hooks:add(radius_acct_lookup, ?MODULE, lookup_account),
            netspire_hooks:add(radius_access_accept, ?MODULE, prepare_session),
            netspire_hooks:add(radius_acct_request, ?MODULE, accounting_request),
            radius_sessions:init_mnesia(),
            netspire_netflow:add_packet_handler(?MODULE, []),
            {ok, _} = timer:send_interval(90000, self(), check_sessions),
            %{ok, _} = timer:send_interval(?SESSION_SYNC_INTERVAL, self(), sync_sessions),
            {ok, #state{ref = Ref}};
        _ ->
            ?ERROR_MSG("Invalid connection string for PostgreSQL driver~n", []),
            {stop, invalid_connection_string_pgsql}
    end.

handle_call({lookup_account, UserName}, _From, State) ->
    Query = "SELECT * FROM auth($1)",
    F = fun(List) ->
            [_, _, Name, Value] = List,
            {Name, Value}
    end,
    case pgsql:pquery(State#state.ref, Query, [UserName]) of
        {ok, _, _, _, Res} ->
            case Res of
                [] ->
                    {reply, {stop, undefined}, State};
                Result ->
                    [Password, IP, _, _]  = lists:nth(1, Result),
                    Attrs = case IP of
                        null ->
                            lists:map(F, Result);
                        Addr ->
                            [{?FRAMED_IP_ADDRESS, Addr}] ++ lists:map(F, Result)
                    end,
                    Response = {ok, {Password, Attrs}},
                    {reply, {stop, Response}, State}
            end;
        _ ->
            {reply, {stop, undefined}, State}
    end;

handle_call({accounting_request, _Response, ?ACCT_START, Request, _Client}, _From, State) ->
    UserName = radius:attribute_value(?USER_NAME, Request),
    SID = radius:attribute_value(?ACCT_SESSION_ID, Request),
    IP = radius:attribute_value(?FRAMED_IP_ADDRESS, Request),
    Now = calendar:now_to_local_time(now()),
    ExpiresAt = netspire_util:timestamp(),
    Query = "SELECT * FROM start_session($1, $2, $3, $4)",
    Result = pgsql:pquery(State#state.ref, Query,
        [UserName, SID, ip_to_string(IP), time_to_string(Now)]),
    case Result of
        {ok, _, _, _, Res} ->
            case Res of
                [] -> ok;
                [R] ->
                    [_, Tariff, Balance] = R,
                    F = fun(S) ->
                            Data = #data{tariff = Tariff,
                                         balance = Balance,
                                         octets_in = 0,
                                         octets_out = 0},
                            S#session{data = Data}

                    end,
                    radius_sessions:start(UserName, SID, ExpiresAt + ?TIMEOUT, F)
            end
    end,
    Reply = #radius_packet{code = ?ACCT_RESPONSE},
    {reply, Reply, State};

handle_call({accounting_request, _Response, ?ACCT_STOP, Request, _Client}, _From, State) ->
    SID = radius:attribute_value(?ACCT_SESSION_ID, Request),
    FinishedAt = netspire_util:timestamp(),
    Reply = #radius_packet{code = ?ACCT_RESPONSE},
    Username = radius:attribute_value(?USER_NAME, Request),
    Now = calendar:now_to_local_time(now()),
    case radius_sessions:is_exist(Username) of
        true ->
            sync_session(SID),
            radius_sessions:stop(SID, FinishedAt),
            Query = "SELECT * FROM stop_session($1, $2)",
            pgsql:pquery(State#state.ref, Query, [SID, time_to_string(Now)]);
        false -> ok
    end,
    {reply, Reply, State};
handle_call({accounting_request, _Response, ?INTERIM_UPDATE, Request, _Client}, _From, State) ->
    SID = radius:attribute_value(?ACCT_SESSION_ID, Request),
    ExpiresAt = netspire_util:timestamp() + ?TIMEOUT,
    Reply = #radius_packet{code = ?ACCT_RESPONSE},
    Username = radius:attribute_value(?USER_NAME, Request),
    case radius_sessions:is_exist(Username) of
        true ->
            sync_session(SID),
            radius_sessions:interim(SID, ExpiresAt);
        false -> ok
    end,
    {reply, Reply, State};

handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

decode_packet(Packet) ->
    {_H, Records} = Packet,
    F = fun(R) ->
            SrcIP = netspire_util:int_to_ip4(R#nfrec_v5.src_addr),
            DstIP = netspire_util:int_to_ip4(R#nfrec_v5.dst_addr),
            Octets = R#nfrec_v5.d_octets,
            {SrcIP, DstIP, Octets}
    end,
    lists:map(F, Records).

processing(Flows) when is_list(Flows) ->
    lists:foreach(fun(F) -> processing(F) end, Flows);

processing({SrcIP, DstIP, Octets}) ->
    case read_session(SrcIP, DstIP) of
        {error, not_found_ip} -> ok;
        {Type, Record} ->
            SID = Record#session.id,
            {data, Tariff, Balance, In, Out} = Record#session.data,
            case apply_tariff(Tariff, [Balance, Octets]) of
                error_exec_tariff -> ok;
                NewBalance ->
                    Data = case Type of
                        in ->
                            #data{tariff = Tariff,
                                  balance = NewBalance,
                                  octets_in = In + Octets,
                                  octets_out = Out};
                        out ->
                            #data{tariff = Tariff,
                                  balance = NewBalance,
                                  octets_in = In,
                                  octets_out = Out + Octets}
                    end,
                    radius_sessions:update(SID,
                        fun(S) -> S#session{data = Data} end),
                    if
                        NewBalance =< 0 ->
                            ?INFO_MSG("Client ~p need to be disconnected~n", [SID]);
                        true -> ok
                    end
            end
    end.

apply_tariff(TCode, Opts) ->
    Tariff = list_to_atom(TCode),
    try
        erlang:apply(Tariff, calculate, Opts)
    catch
        _:Reason ->
            ?ERROR_MSG("An error caused while trying starting tariff ~p: ~p~n", [Tariff, Reason]),
            error_exec_tariff
    end. 

read_session(SrcIP, DstIP) ->
    F = fun() ->
            Q = qlc:q([X || X <- mnesia:table(session),
                (X#session.ip == SrcIP orelse X#session.ip == DstIP) andalso 
                 X#session.status == active]),
            qlc:e(Q)
    end,
    case mnesia:transaction(F) of
        {atomic, [R]} when R#session.ip == SrcIP -> {out, R};
        {atomic, [R]} when R#session.ip == DstIP -> {in, R};
        {atomic, []} ->
            ?ERROR_MSG("Not registed IP addresses: ~p, ~p~n", [SrcIP, DstIP]),
            {error, not_found_ip};
        {aborted, Reason} ->
            ?WARNING_MSG("Abort: ~p~n", [Reason])
    end. 

handle_cast({netflow, Pdu, _SrcIP}, State) ->
    R = decode_packet(Pdu),
    processing(R),
    {noreply, State};

handle_cast({sync_session, SID}, State) ->
    Query = "select * from sync_accounting($1, $2, $3, $4)",
    [S] = radius_sessions:fetch(SID),
    case S#session.status of
        new -> ok;
        _ ->
            {data, _, Balance, In, Out} = S#session.data,
            pgsql:pquery(State#state.ref, Query, 
                        [SID, In, Out, float_to_list(Balance)]),
            ?INFO_MSG("Accounting info was synced for ~p~n", [SID])
    end,
    {noreply, State};

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({'DOWN', _MonitorRef, process, _Pid, _Info}, State) ->
    ?ERROR_MSG("Connection to database has been dropped~n", []),
    netspire_hooks:delete(radius_acct_lookup, ?MODULE, lookup_account),
    {stop, connection_dropped, State};

handle_info(check_sessions, State) ->
    case radius_sessions:expire() of
        {ok, []} -> ok;
        {ok, Result} ->
            lists:foreach(fun(S) -> radius_sessions:purge(S) end, Result)
    end,
    {noreply, State};

handle_info(sync_sessions, State) ->
    lists:foreach(fun(SID) -> sync_session(SID) end,
        mnesia:dirty_all_keys(session)),
    {noreply, State};

handle_info(_Request, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.

time_to_string({{Y, M, D}, {H, M1, S}}) ->
    io_lib:format("~p-~p-~p ~p:~p:~p", [Y, M, D, H, M1, S]). 

ip_to_string({A, B, C, D}) ->
    io_lib:format("~p.~p.~p.~p", [A, B, C, D]). 
