-module(mod_billing_pgsql).

-behaviour(gen_module).
-behaviour(gen_server).

-export([start_link/1,
         fetch_account/2,
         start_session/3,
         stop_session/5,
         sync_session_data/4]).

%% gen_module callbacks
-export([start/1, stop/0]).

-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("netspire.hrl").
-include("netspire_radius.hrl").

-record(state, {ref}).

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

fetch_account(_, Username) ->
    gen_server:call(?MODULE, {fetch_account, Username}).

start_session(UserName, StartedAt, ExpiredAt) ->
    gen_server:call(?MODULE, {start_session, UserName, StartedAt, ExpiredAt}).

stop_session(_, UserName, SID, FinishedAt, Expired) ->
    gen_server:call(?MODULE, {stop_session, UserName, SID, FinishedAt, Expired}).

sync_session_data(SID, In, Out, Balance) ->
    gen_server:call(?MODULE, {sync_session_data, SID, In, Out, Balance}).

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    gen_server:call(?MODULE, stop),
    supervisor:terminate_child(netspire_sup, ?MODULE),
    supervisor:delete_child(netspire_sup, ?MODULE).

init([Options]) ->
    Ref = connect(Options),
    erlang:monitor(process, Ref),
    netspire_hooks:add(backend_fetch_account, ?MODULE, fetch_account),
    netspire_hooks:add(backend_start_session, ?MODULE, start_session),
    netspire_hooks:add(backend_stop_session, ?MODULE, stop_session),
    netspire_hooks:add(backend_sync_session, ?MODULE, sync_session_data),
    {ok, #state{ref = Ref}}.

connect(Options) ->
    [Server, DB, Username, Password, Port] = Options,
    case pgsql:connect(Server, DB, Username, Password, Port) of
        {ok, Ref} ->
            ?INFO_MSG("Database connection has been established~n", []),
            Ref;
        {error, Reason} ->
            ?ERROR_MSG("Connection to database failed: ~p~n", [Reason]),
            timer:sleep(3000),
            connect([Server, DB, Username, Password, Port])
    end.

process_fetch_account_result(Result) ->
    F = fun(List) ->
            [_, _, _, Name, Value] = List,
            {Name, Value}
    end,
    case Result of
        {ok, _, _, _, Terms} ->
            case Terms of
                [] ->
                    undefined;
                Res ->
                    [Password, Balance, Plan, _, _] = lists:nth(1, Res),
                    Attrs = lists:map(F, Res),
                    {ok, {Password, Attrs, {Balance, Plan}}}
            end;
        _ -> undefined
    end.

handle_call({start_session, UserName, SID, StartedAt}, _From, State) ->
    pgsql:pquery(State#state.ref, "SELECT * FROM start_session($1, $2, $3)", [UserName, SID, StartedAt]),
    {reply, {stop, ok}, State};
handle_call({stop_session, UserName, SID, FinishedAt, Expired}, _From, State) ->
    pgsql:pquery(State#state.ref, "SELECT * FROM stop_session($1, $2, $3, $4)", [UserName, SID, FinishedAt, Expired]),
    {reply, {stop, ok}, State};
handle_call({sync_session_data, SID, In, Out, Balance}, _From, State) ->
    pgsql:pquery(State#state.ref, "SELECT * FROM sync_session_data($1, $2, $3, $4)", [SID, In, Out, Balance]),
    {reply, {stop, ok}, State};

handle_call({fetch_account, UserName}, _From, State) ->
    Result = pgsql:pquery(State#state.ref, "SELECT * FROM auth($1)", [UserName]),
    Result1 = process_fetch_account_result(Result),
    {reply, {stop, Result1}, State};
handle_call(stop, _From, State) ->
        {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({'DOWN', _MonitorRef, process, _Pid, _Info}, State) ->
    ?ERROR_MSG("Connection to database has been dropped~n", []),
    {stop, connection_dropped, State};
handle_info(_Request, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, State) ->
    pgsql:terminate(State#state.ref),
    netspire_hooks:delete(backend_fetch_account, ?MODULE, fetch_account),
    netspire_hooks:delete(backend_start_session, ?MODULE, start_session),
    netspire_hooks:delete(backend_stop_session, ?MODULE, stop_session),
    netspire_hooks:delete(backend_sync_session, ?MODULE, sync_session_data),
    ok.

