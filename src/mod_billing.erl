-module(mod_billing).
 
-behaviour(gen_module).
-behaviour(gen_server).
 
%% API
-export([start_link/1,
         lookup_account/4,
         prepare_session/4,
         accounting_request/4,
         sync_session/1,
         handle_packet/2]).
 
%% gen_module callbacks
-export([start/1, stop/0]).
 
%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).
 
-include("netspire.hrl").
-include("netspire_radius.hrl").
-include("radius/radius.hrl").
-include("netflow/netflow_v5.hrl").
-include_lib("stdlib/include/qlc.hrl").
 
-define(ACCT_START, 1).
-define(ACCT_STOP, 2).
-define(INTERIM_UPDATE, 3).
 
-define(SESSION_TIMEOUT, 120000).
-define(SESSION_SYNC_INTERVAL, 60000).
 
-record(data, {tariff, balance = 0, amount = 0, octets_in = 0, octets_out = 0}).
 
start(Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    ChildSpec = {?MODULE,
                 {?MODULE, start_link, [Options]},
                 transient,
                 brutal_kill,
                 worker,
                 [?MODULE]
                },
    supervisor:start_child(netspire_sup, ChildSpec).
 
start_link(Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Options], []).
 
stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    gen_server:call(?MODULE, stop),
    supervisor:terminate_child(netspire_sup, ?MODULE),
    supervisor:delete_child(netspire_sup, ?MODULE).
 
lookup_account(_Value, _Request, UserName, _Client) ->
    gen_server:call(?MODULE, {lookup_account, UserName}).
 
accounting_request(Response, Type, Request, Client) ->
    gen_server:call(?MODULE, {accounting_request, Response, Type, Request, Client}).
 
handle_packet(SrcIP, Pdu) ->
    gen_server:cast(?MODULE, {netflow, Pdu, SrcIP}).

sync_session(SID) ->
    gen_server:cast(?MODULE, {sync_session, SID}).
 
prepare_session(Response, Request, {Balance, Plan}, _Client) ->
    UserName = radius:attribute_value(?USER_NAME, Request),
    IP = radius:attribute_value(?FRAMED_IP_ADDRESS, Response),
    case radius_sessions:is_exist(UserName) of
        false ->
            Timeout = gen_module:get_option(?MODULE, session_timeout, ?SESSION_TIMEOUT),
            Data = #data{tariff = Plan, balance = Balance},
            radius_sessions:prepare(UserName, IP, Timeout, Data),
            Response;
        true ->
            #radius_packet{code = ?ACCESS_REJECT}
    end.
 
%%
%% Internal functions
%%
 
init([_Options]) ->
    netspire_hooks:add(radius_acct_lookup, ?MODULE, lookup_account),
    netspire_hooks:add(radius_access_accept, ?MODULE, prepare_session, 200),
    netspire_hooks:add(radius_acct_request, ?MODULE, accounting_request),
    radius_sessions:init_mnesia(),
    netspire_netflow:add_packet_handler(?MODULE, []),
    {ok, _} = timer:send_interval(90000, self(), sync_sessions),
    {ok, _} = timer:send_interval(90000, self(), expire_sessions),
    {ok, no_state}.
 
handle_call({lookup_account, UserName}, _From, State) ->
    case netspire_hooks:run_fold(backend_fetch_account, undefined, [UserName]) of
        {ok, Password, Replies, Extra} ->
            Response = {ok, {Password, Replies, Extra}},
            {reply, {stop, Response}, State};
        undefined ->
            {reply, {stop, undefined}, State}
    end;
 
handle_call({accounting_request, _Response, ?ACCT_START, Request, Client}, _From, State) ->
    UserName = radius:attribute_value(?USER_NAME, Request),
    SID = radius:attribute_value(?ACCT_SESSION_ID, Request),
    StartedAt = time_to_string(calendar:now_to_local_time(now())),
    ExpiredAt = netspire_util:timestamp(),
    Timeout = gen_module:get_option(?MODULE, session_timeout, ?SESSION_TIMEOUT),
    F = fun(S) ->
            S#session{nas_spec = Client}
    end,
    Reply = #radius_packet{code = ?ACCT_RESPONSE},
    radius_sessions:start(UserName, SID, ExpiredAt + Timeout, F),
    netspire_hooks:run(backend_start_session, [UserName, SID, StartedAt]),
    {reply, Reply, State};
handle_call({accounting_request, _Response, ?ACCT_STOP, Request, _Client}, _From, State) ->
    SID = radius:attribute_value(?ACCT_SESSION_ID, Request),
    FinishedAt = netspire_util:timestamp(),
    Reply = #radius_packet{code = ?ACCT_RESPONSE},
    UserName = radius:attribute_value(?USER_NAME, Request),
    Now = calendar:now_to_local_time(now()),
    case radius_sessions:is_exist(UserName) of
        true ->
            sync_session(SID),
            radius_sessions:stop(SID, FinishedAt),
            netspire_hooks:run_fold(backend_stop_session, undefined, [UserName, SID, time_to_string(Now)]);
        false -> ok
    end,
    {reply, Reply, State};
handle_call({accounting_request, _Response, ?INTERIM_UPDATE, Request, _Client}, _From, State) ->
    SID = radius:attribute_value(?ACCT_SESSION_ID, Request),
    Timeout = gen_module:get_option(?MODULE, session_timeout, ?SESSION_TIMEOUT),
    ExpiresAt = netspire_util:timestamp() + Timeout,
    Reply = #radius_packet{code = ?ACCT_RESPONSE},
    sync_session(SID),
    radius_sessions:interim(SID, ExpiresAt),
    {reply, Reply, State};
handle_call(stop, _From, State) ->
        {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.
 
extract_netflow_fields(Packet) ->
    {_H, Records} = Packet,
    F = fun(R) ->
            SrcIP = netspire_util:int_to_ip4(R#nfrec_v5.src_addr),
            DstIP = netspire_util:int_to_ip4(R#nfrec_v5.dst_addr),
            Octets = R#nfrec_v5.d_octets,
            {SrcIP, DstIP, Octets}
    end,
    lists:map(F, Records).
 
handle_netflow_records(Flows) when is_list(Flows) ->
    lists:foreach(fun(F) -> handle_netflow_records(F) end, Flows);
 
handle_netflow_records({SrcIP, DstIP, Octets}) ->
    case fetch_matching_session(SrcIP, DstIP) of
        {error, _Reason} -> ok;
        {ok, {Direction, Session}} ->
            case apply_tariff_plan(Session, Direction, Octets) of
                {ok, NewBalance, Amount} when NewBalance > 0 ->
                    update_session_data(Session, Octets, Direction, Amount);
                {ok, NewBalance, Amount} when NewBalance =< 0 ->
                    netspire_hooks:run(disconnect_client, [Session]),
                    update_session_data(Session, Octets, Direction, Amount);
                {error, Reason} ->
                    SID = Session#session.id,
                    ?ERROR_MSG("Can not calculate session ~s due ~p~n", [SID, Reason])
            end
    end.
 
update_session_data(Session, Octets, Direction, Amount) ->
    Fun = fun(S) ->
        Data = S#session.data,
        NewIn = Data#data.octets_in + Octets,
        NewOut = Data#data.octets_out + Octets,
        NewData = case Direction of
            in ->
                Data#data{amount = Amount, octets_in = NewIn};
            out ->
                Data#data{amount = Amount, octets_out = NewOut}
        end,
        S#session{data = NewData}
    end,
    radius_sessions:update(Session#session.id, Fun).
 
apply_tariff_plan(Session, Direction, Octets) ->
    Data = Session#session.data,
    Tariff = list_to_atom(Data#data.tariff),
    Opts = [Data#data.balance, Direction, Octets],
    try
        erlang:apply(Tariff, calculate, Opts)
    catch
        _:Reason ->
            ?ERROR_MSG("An error caused while trying starting tariff ~p: ~p~n", [Tariff, Reason])
    end.
 
fetch_matching_session(SrcIP, DstIP) ->
    F = fun() ->
            Q = qlc:q([X || X <- mnesia:table(session),
                (X#session.ip == SrcIP orelse X#session.ip == DstIP) andalso
                 X#session.status == active]),
            qlc:e(Q)
    end,
    case mnesia:activity(async_dirty, F) of
        [S] when S#session.ip == DstIP -> {ok, {in, S}};
        [S] when S#session.ip == SrcIP -> {ok, {out, S}};
        [] ->
            ?WARNING_MSG("No active sessions matching flow src/dst: ~p/~p~n", [SrcIP, DstIP]),
            {error, session_not_found};
        _ ->
            ?WARNING_MSG("Ambiguous session match for flow src/dst: ~p/~p~n", [SrcIP, DstIP])
    end.
 
handle_cast({netflow, Pdu, _SrcIP}, State) ->
    Result = extract_netflow_fields(Pdu),
    handle_netflow_records(Result),
    {noreply, State};
handle_cast({sync_session, SID}, State) ->
    [S] = radius_sessions:fetch(SID),
    case S#session.status of
        new -> ok;
        _ ->
            {data, _, _, Amount, In, Out} = S#session.data,
            netspire_hooks:run(backend_sync_session, [SID, In, Out, float_to_list(Amount)]),
            ?INFO_MSG("Netflow session data was synced for ~s~n", [SID])
    end,
    {noreply, State};
handle_cast(_Request, State) ->
    {noreply, State}.
 
handle_info(expire_sessions, State) ->
    case radius_sessions:expire() of
        {ok, []} -> ok;
        {ok, Result} ->
            lists:foreach(fun(S) -> radius_sessions:purge(S) end, Result)
    end,
    {noreply, State};
handle_info(_Request, State) ->
    {noreply, State}.
 
code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, _State) ->
    netspire_netflow:delete_packet_handler(?MODULE),
    netspire_hooks:delete(radius_acct_lookup, ?MODULE, lookup_account),
    netspire_hooks:delete(radius_access_accept, ?MODULE, prepare_session),
    netspire_hooks:delete(radius_acct_request, ?MODULE, accounting_request),
    ok.

time_to_string({{Y, M, D}, {H, M1, S}}) ->
    io_lib:format("~p-~p-~p ~p:~p:~p", [Y, M, D, H, M1, S]).
