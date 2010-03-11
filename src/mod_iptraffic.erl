-module(mod_iptraffic).

-behaviour(gen_module).
-behaviour(gen_server).

%% API
-export([start_link/1,
         lookup_account/4,
         init_session/4,
         accounting_request/4,
         get_option/2]).

%% gen_module callbacks
-export([start/1, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("netspire.hrl").
-include("radius/radius.hrl").
-include("netflow/netflow_v5.hrl").
-include("netflow/netflow_v9.hrl").
-include("iptraffic.hrl").

start(Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    iptraffic_sup:start(Options).

start_link(Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Options], []).

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    iptraffic_sup:stop().

init([Options]) ->
    process_flag(trap_exit, true),
    Config = proplists:get_value(tariffs_config, Options, []),
    case iptraffic_tariffs:init(Config) of
        ok ->
            netspire_netflow:add_packet_handler(iptraffic_session, []),
            netspire_hooks:add(radius_acct_lookup, ?MODULE, lookup_account),
            netspire_hooks:add(radius_access_accept, ?MODULE, init_session, 10),
            netspire_hooks:add(radius_acct_request, ?MODULE, accounting_request),
            Timeout = proplists:get_value(session_timeout, Options, 60) * 1000,
            timer:send_interval(Timeout, expire_all),
            {ok, no_state};
        Error ->
            {stop, Error}
    end.

lookup_account(_Value, _Request, UserName, _Client) ->
    case netspire_hooks:run_fold(backend_fetch_account, undefined, [UserName]) of
        {ok, Data} ->
            Response = {ok, Data},
            {stop, Response};
        undefined ->
            {stop, undefined}
    end.

init_session(Response, Request, Extra, _Client) ->
    UserName = radius:attribute_value("User-Name", Request),
    case iptraffic_sup:init_session(UserName) of
        {ok, Pid} ->
            prepare_session(Pid, UserName, Extra, Response);
        {ok, Pid, _Info} ->
            prepare_session(Pid, UserName, Extra, Response);
        {error, Reason}->
            ?ERROR_MSG("Can not initialize session for user ~s due to ~p~n", [UserName, Reason]),
            {reject, []}
    end.

prepare_session(Pid, UserName, Extra, Response) ->
    case iptraffic_session:prepare(Pid, UserName, Extra) of
        ok ->
            ?INFO_MSG("Session prepared for user ~s~n", [UserName]),
            Response;
        {error, Reason} ->
            ?ERROR_MSG("Can not prepare session for user ~s due to ~p~n", [UserName, Reason]),
            {reject, []}
    end.

accounting_request(_Response, ?ACCT_START, Request, _Client) ->
    UserName = radius:attribute_value("User-Name", Request),
    IP = radius:attribute_value("Framed-IP-Address", Request),
    SID = radius:attribute_value("Acct-Session-Id", Request),
    case iptraffic_session:start(UserName, IP, SID) of
        ok ->
            #radius_packet{code = ?ACCT_RESPONSE};
        _Error ->
            noreply
    end;
accounting_request(_Response, ?INTERIM_UPDATE, Request, _Client) ->
    SID = radius:attribute_value("Acct-Session-Id", Request),
    case iptraffic_session:interim(SID) of
        ok ->
            #radius_packet{code = ?ACCT_RESPONSE};
        _Error ->
            noreply
    end;
accounting_request(_Response, ?ACCT_STOP, Request, _Client) ->
    SID = radius:attribute_value("Acct-Session-Id", Request),
    case iptraffic_session:stop(SID) of
        {ok, State} ->
            ok = supervisor:delete_child(iptraffic_sup, {session, State#ipt_session.username}),
            #radius_packet{code = ?ACCT_RESPONSE};
        _Error ->
            noreply
    end;
accounting_request(_Response, _, _, _) ->
    noreply.

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

terminate(_Reason, _State) ->
    netspire_netflow:delete_packet_handler(iptraffic_session),
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
