-module(mod_iptraffic).

-behaviour(gen_module).
-behaviour(gen_server).

%% API
-export([start_link/1,
         lookup_account/4,
         prepare_session/4,
         accounting_request/4,
         handle_packet/2]).

%% gen_module callbacks
-export([start/1, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("netspire.hrl").
-include("netspire_radius.hrl").
-include("radius/radius.hrl").
-include("netflow/netflow_v5.hrl").
-include("netflow/netflow_v9.hrl").
-include("iptraffic.hrl").
-include_lib("stdlib/include/qlc.hrl").

-define(SESSION_TIMEOUT, 300).
-define(EXPIRE_SESSIONS_INTERVAL, 60000).

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

init([Options]) ->
    TariffsConfig = proplists:get_value(tariffs_config, Options, []),
    case iptraffic_tariffs:init(TariffsConfig) of
        ok ->
            radius_sessions:init_mnesia(),
            netspire_netflow:add_packet_handler(?MODULE, []),
            netspire_hooks:add(radius_acct_lookup, ?MODULE, lookup_account),
            netspire_hooks:add(radius_access_accept, ?MODULE, prepare_session, 200),
            netspire_hooks:add(radius_acct_request, ?MODULE, accounting_request),
            {ok, _TRef} = timer:send_interval(?EXPIRE_SESSIONS_INTERVAL, self(), expire_sessions),
            {ok, no_state};
        Error ->
            {stop, Error}
    end.

lookup_account(_Value, _Request, UserName, _Client) ->
    case radius_sessions:is_exist(UserName) of
        false ->
            case netspire_hooks:run_fold(backend_fetch_account, undefined, [UserName]) of
                {ok, Data} ->
                    Response = {ok, Data},
                    {stop, Response};
                undefined ->
                    {stop, undefined}
            end;
        true ->
            {stop, undefined}
    end.

accounting_request(_Response, ?ACCT_START, Request, Client) ->
    UserName = radius:attribute_value(?USER_NAME, Request),
    SID = radius:attribute_value(?ACCT_SESSION_ID, Request),
    Timeout = gen_module:get_option(?MODULE, session_timeout, ?SESSION_TIMEOUT),
    ExpiresAt = netspire_util:timestamp() + Timeout,
    F = fun(S) -> S#session{nas_spec = Client} end,
    radius_sessions:start(UserName, SID, ExpiresAt, F),
    netspire_hooks:run(backend_start_session, [UserName, SID, now()]),
    #radius_packet{code = ?ACCT_RESPONSE};

accounting_request(_Response, ?ACCT_STOP, Request, _Client) ->
    SID = radius:attribute_value(?ACCT_SESSION_ID, Request),
    UserName = radius:attribute_value(?USER_NAME, Request),
    case radius_sessions:is_exist(UserName) of
        true ->
            radius_sessions:stop(SID, netspire_util:timestamp()),
            case radius_sessions:fetch(SID) of
                [S] ->
                    Data = S#session.data,
                    netspire_hooks:run(backend_stop_session, [
                                        S#session.username,
                                        SID,
                                        now(),
                                        Data#data.octets_in,
                                        Data#data.octets_out,
                                        Data#data.amount,
                                        false]);
                _ -> ok
            end;
        false -> ok
    end,
    #radius_packet{code = ?ACCT_RESPONSE};

accounting_request(_Response, ?INTERIM_UPDATE, Request, _Client) ->
    SID = radius:attribute_value(?ACCT_SESSION_ID, Request),
    Timeout = gen_module:get_option(?MODULE, session_timeout, ?SESSION_TIMEOUT),
    ExpiresAt = netspire_util:timestamp() + Timeout,
    radius_sessions:interim(SID, ExpiresAt),
    case radius_sessions:fetch(SID) of
        [S] ->
            Data = S#session.data,
            netspire_hooks:run(backend_sync_session, [
                                S#session.username,
                                SID,
                                now(),
                                Data#data.octets_in,
                                Data#data.octets_out,
                                Data#data.amount]);
        _ -> ok
    end,
    #radius_packet{code = ?ACCT_RESPONSE}.

prepare_session(Response, Request, {Balance, Plan}, _Client) ->
    UserName = radius:attribute_value(?USER_NAME, Request),
    IP = case radius:attribute_value(?FRAMED_IP_ADDRESS, Response) of
        Term when is_tuple(Term) ->
            Term;
        Term ->
            {ok, Address} = inet_parse:address(Term),
            Address
    end,
    Timeout = gen_module:get_option(?MODULE, session_timeout, ?SESSION_TIMEOUT),
    Data = #data{plan = Plan, balance = Balance},
    radius_sessions:prepare(UserName, IP, Timeout, Data),
    Response.

handle_packet(SrcIP, Pdu) ->
    gen_server:cast(?MODULE, {netflow, Pdu, SrcIP}).

%%
%% Internal functions
%%

process_netflow_packet({H, Records}) ->
    Fun = fun(Rec) -> process_netflow_record(H, Rec) end,
    lists:foreach(Fun, Records).

process_netflow_record(H, Rec) ->
    Args = build_iptraffic_args(H, Rec),
    #ipt_args{src_ip = SrcIP, dst_ip = DstIP} = Args,
    case match_session(SrcIP, DstIP) of
        {ok, {Direction, Session}} ->
            NewArgs = Args#ipt_args{dir = Direction},
            do_accounting(Session, NewArgs);
        _ ->
            ok
    end.

build_iptraffic_args(H, Rec) when is_record(H, nfh_v5) ->
    {_, Time} = calendar:seconds_to_daystime(H#nfh_v5.unix_secs),
    #ipt_args{
        sec = calendar:time_to_seconds(Time),
        src_ip = netspire_util:int_to_ip4(Rec#nfrec_v5.src_addr),
        dst_ip = netspire_util:int_to_ip4(Rec#nfrec_v5.dst_addr),
        src_port = Rec#nfrec_v5.src_port,
        dst_port = Rec#nfrec_v5.dst_port,
        proto = Rec#nfrec_v5.prot,
        octets = Rec#nfrec_v5.d_octets
    };
build_iptraffic_args(H, _FlowSet) when is_record(H, nfh_v9) ->
    ?WARNING_MSG("NetFlow v9 is not supported yet~n", []).

do_accounting(Session, Args) ->
    Data = Session#session.data,
    Plan = Data#data.plan,  
    case iptraffic_tariffs:match(Plan, Session, Args) of
        {ok, {Plan, _Rule, Cost} = MatchResult} ->
            netspire_hooks:run(matched_session, [Session, Args, MatchResult]),
            Amount = Args#ipt_args.octets / 1024 / 1024 * Cost,
            NewBalance = Data#data.balance - (Data#data.amount + Amount),
            update_session_data(Session, Args, Amount),
            if
                NewBalance =< 0 ->
                    netspire_hooks:run(disconnect_client, [Session]);
                true -> false
            end;
        {error, Reason} ->
            SID = Session#session.id,
            ?ERROR_MSG("Cannot process accounting for session ~s due ~p~n", [SID, Reason])
    end.

match_session(SrcIP, DstIP) ->
    F = fun() ->
            Q = qlc:q([X || X <- mnesia:table(session),
                (X#session.ip == SrcIP orelse X#session.ip == DstIP) andalso
                 X#session.status == active]),
            qlc:e(Q)
    	end,
    case mnesia:activity(async_dirty, F) of
        [S] when S#session.ip == DstIP ->
            {ok, {in, S}};
        [S] when S#session.ip == SrcIP ->
            {ok, {out, S}};
        [] ->
            ?WARNING_MSG("No active sessions matching flow src/dst: ~p/~p~n", [SrcIP, DstIP]),
            {error, no_matches};
        _ ->
            ?WARNING_MSG("Ambiguous session match for flow src/dst: ~p/~p~n", [SrcIP, DstIP]),
            {error, ambiguous_match}
    end.

update_session_data(Session, Args, Amount) ->
    Fun = fun(S) ->
        Direction = Args#ipt_args.dir,
        Octets = Args#ipt_args.octets,
        Data = S#session.data,
        NewIn = Data#data.octets_in + Octets,
        NewOut = Data#data.octets_out + Octets,
        NewAmount = Data#data.amount + Amount,
        NewData =
			case Direction of
            	in ->
                	Data#data{amount = NewAmount, octets_in = NewIn};
            	out ->
                	Data#data{amount = NewAmount, octets_out = NewOut}
        	end,
        S#session{data = NewData}
    end,
    radius_sessions:update(Session#session.id, Fun).

handle_cast({netflow, Packet, _SrcIP}, State) ->
    process_netflow_packet(Packet),
    {noreply, State};
handle_cast(_Request, State) ->
    {noreply, State}.

handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_info(expire_sessions, State) ->
	Fun = fun(S) ->
                Data = S#session.data,
                SID = S#session.id,
                UserName = S#session.username,
                In = Data#data.octets_in,
                Out = Data#data.octets_out,
                Amount = Data#data.amount,
                netspire_hooks:run(backend_stop_session, [UserName, SID, now(), In, Out, Amount, true]),
                radius_sessions:purge(S)
			end,
    case radius_sessions:expire() of
        {ok, []} -> ok;
        {ok, Result} ->
            lists:foreach(Fun, Result)
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
    netspire_hooks:delete(radius_acct_request, ?MODULE, accounting_request).
