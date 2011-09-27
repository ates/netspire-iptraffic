-module(mod_iptraffic).

-behaviour(gen_module).
-behaviour(gen_server).

%% API
-export([start_link/1,
         access_request/3,
         init_session/4,
         accounting_request/4,
         get_option/2]).

%% gen_module callbacks
-export([start/1, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("netspire.hrl").
-include("iptraffic.hrl").
-include("radius/radius.hrl").

-record(state, {accounting_mode = netflow, backend}).

start(Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    iptraffic_sup:start(Options).

start_link(Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Options], []).

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    iptraffic_sup:stop().

accounting_request(Response, Type, Request, Client) ->
    gen_server:call(?MODULE, {accounting_request, Response, Type, Request, Client}).

init([Options]) ->
    process_flag(trap_exit, true),
    AccountingMode = proplists:get_value(accounting_mode, Options, netflow),
    case AccountingMode of
        netflow ->
            Plans = proplists:get_value(tariffs, Options),
            case iptraffic_tariffs:init(Plans) of
                ok ->
                    ?INFO_MSG("Selected netflow as traffic source~n", []),
                    netspire_netflow:add_packet_handler(iptraffic_session, []);
                _ -> ok
            end;
        radius ->
            ?INFO_MSG("Selected RADIUS as traffic source~n", [])
    end,
    case application:get_env(netspire, database_backend) of
        {ok, Name} ->
            Module = list_to_atom(lists:concat([?MODULE, "_", Name])),
            gen_module:start_module(Module, []),
            netspire_hooks:add(radius_access_request, ?MODULE, access_request),
            netspire_hooks:add(radius_access_accept, ?MODULE, init_session),
            netspire_hooks:add(radius_acct_request, ?MODULE, accounting_request),
            Timeout = proplists:get_value(session_timeout, Options, 60) * 1000,
            timer:send_interval(Timeout, expire_all),
            {ok, #state{accounting_mode = AccountingMode, backend = Module}};
        undefined ->
            ?ERROR_MSG("Cannot determine database backend~n", []),
            {stop, error}
    end.

access_request(_Value, Request, Client) ->
    case radius_util:verify_requirements(Request, ?MODULE) of
        false ->
            {stop, Request};
        true ->
            UserName = radius:attribute_value("User-Name", Request),
            case netspire_hooks:run_fold(iptraffic_fetch_account, undefined, [UserName]) of
                {ok, Data} ->
                    {_, Attrs, _} = Data,
                    Response = {auth, Data},
                    case proplists:get_all_values("Netspire-Allowed-NAS", Attrs) of
                        [] ->
                            {stop, Response};
                        NASes ->
                            case lists:member(atom_to_list(Client#nas_spec.name), NASes) of
                                true ->
                                    {stop, Response};
                                false ->
                                    ?INFO_MSG("User ~s is not allowed to connect to ~p NAS~n",
                                        [UserName, Client#nas_spec.name]),
                                    {stop, undefined}
                            end
                    end;
                _ ->
                    {stop, undefined}
            end
    end.

init_session(Response, Request, Extra, Client) ->
    UserName = radius:attribute_value("User-Name", Request),
    case netspire_hooks:run_fold(ippool_lease_ip, Response, []) of
        NewResponse when is_record(NewResponse, radius_packet) ->
            case iptraffic_sup:init_session(UserName) of
                {ok, Pid} ->
                    prepare_session(Pid, UserName, Extra, NewResponse, Client);
                {error, Reason} ->
                    ?ERROR_MSG("Can not initialize session for user ~s due to ~p~n", [UserName, Reason]),
                    netspire_hooks:run_fold(ippool_release_ip, NewResponse, []),
                    {reject, []}
            end;
        _ ->
            {reject, []}
    end.

prepare_session(Pid, UserName, Extra, Response, Client) ->
    case iptraffic_session:prepare(Pid, UserName, Extra, Client) of
        ok ->
            ?INFO_MSG("Session prepared for user ~s~n", [UserName]),
            Response;
        {error, Reason} ->
            ?ERROR_MSG("Can not prepare session for user ~s due to ~p~n", [UserName, Reason]),
            {reject, []}
    end.

handle_call({accounting_request, _Response, ?ACCT_START, Request, _Client}, _From, State) ->
    UserName = radius:attribute_value("User-Name", Request),
    IP = radius:attribute_value("Framed-IP-Address", Request),
    SID = radius:attribute_value("Acct-Session-Id", Request),
    case iptraffic_session:start(UserName, IP, SID) of
        ok ->
            {reply, #radius_packet{code = ?ACCT_RESPONSE}, State};
        _ ->
            {reply, noreply, State}
    end;
handle_call({accounting_request, _Response, ?INTERIM_UPDATE, Request, _Client}, _From, State) ->
    SID = radius:attribute_value("Acct-Session-Id", Request),
    case State#state.accounting_mode of
        radius ->
            OctetsIn = radius:attribute_value("Acct-Input-Gigawords", Request),
            OctetsOut = radius:attribute_value("Acct-Output-Gigawords", Request),
            iptraffic_session:update_octets_counters(SID, OctetsIn, OctetsOut);
        _ -> ok
    end,
    case iptraffic_session:interim(SID) of
        ok ->
            netspire_hooks:run(ippool_renew_ip, [Request]),
            {reply, #radius_packet{code = ?ACCT_RESPONSE}, State};
        _ ->
            {reply, noreply, State}
    end;
handle_call({accounting_request, _Response, ?ACCT_STOP, Request, _Client}, _From, State) ->
    SID = radius:attribute_value("Acct-Session-Id", Request),
    case State#state.accounting_mode of
        radius ->
            OctetsIn = radius:attribute_value("Acct-Input-Gigawords", Request),
            OctetsOut = radius:attribute_value("Acct-Output-Gigawords", Request),
            iptraffic_session:update_octets_counters(SID, OctetsIn, OctetsOut);
        _ -> ok
    end,
    case iptraffic_session:stop(SID) of
        {ok, Session} ->
            Timeout = gen_module:get_option(?MODULE, delay_stop, 5),
            timer:apply_after(Timeout * 1000, iptraffic_sup, delete_session, [Session, Request]),
            {reply, #radius_packet{code = ?ACCT_RESPONSE}, State};
        _ ->
            {reply, noreply, State}
    end;
handle_call({accounting_request, _Response, _, _, _}, _From, State) ->
    {reply, noreply, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(expire_all, State) ->
    Now = netspire_util:timestamp(),
    Guard = fun(S) -> S#ipt_session.expires_at =< Now end,
    Fun = fun(S) ->
        iptraffic_session:expire(S#ipt_session.sid),
        supervisor:delete_child(iptraffic_sup, {session, S#ipt_session.username})
    end,
    traverse_all(Guard, Fun),
    {noreply, State};
handle_info(_Request, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, State) ->
    case State#state.accounting_mode of
        netflow ->
            netspire_netflow:delete_packet_handler(iptraffic_session);
        _ -> ok
    end,
    gen_module:stop_module(State#state.backend),
    netspire_hooks:delete_all(?MODULE).

traverse_all(Guard, Fun) ->
    Key = mnesia:dirty_first(ipt_session),
    traverse_all(Key, Guard, Fun).
traverse_all('$end_of_table', _, _) ->
    ok;
traverse_all(Key, Guard, Fun) ->
    case mnesia:dirty_read(ipt_session, Key) of
        [State] ->
            Next = mnesia:dirty_next(ipt_session, Key),
            case Guard(State) of
                true ->
                    Fun(State),
                    traverse_all(Next, Guard, Fun);
                _ ->
                    traverse_all(Next, Guard, Fun)
            end;
        [] ->
            traverse_all(Guard, Fun)
    end.

get_option(Name, Default) ->
    gen_module:get_option(?MODULE, Name, Default).
