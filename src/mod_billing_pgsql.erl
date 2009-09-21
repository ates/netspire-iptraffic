-module(mod_billing_pgsql).

-behaviour(gen_module).
-behaviour(gen_server).

-export([start_link/1,
         fetch_account/2,
         start_session/3,
         sync_session/6,
         stop_session/7]).

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
                 3000,
                 worker,
                 [?MODULE]
                },
    supervisor:start_child(netspire_sup, ChildSpec).

start_link(Options) ->
    case gen_server:start_link({local, ?MODULE}, ?MODULE, [Options], []) of
        {ok, Pid} ->
            gen_server:call(Pid, {create_db_connection, Options}),
            {ok, Pid};
        Error -> Error
    end.

fetch_account(_, UserName) ->
    gen_server:call(?MODULE, {fetch_account, UserName}).

start_session(UserName, SID, StartedAt) ->
    gen_server:cast(?MODULE, {start_session, UserName, SID, calendar:now_to_local_time(StartedAt)}).

stop_session(UserName, SID, FinishedAt, In, Out, Amount, Expired) ->
    gen_server:cast(?MODULE, {stop_session, UserName, SID, calendar:now_to_local_time(FinishedAt), In, Out, Amount, Expired}).

sync_session(UserName, SID, TimeStamp, In, Out, Balance) ->
    gen_server:cast(?MODULE, {sync_session, UserName, SID, calendar:now_to_local_time(TimeStamp), In, Out, Balance}).

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    gen_server:call(?MODULE, stop),
    supervisor:terminate_child(netspire_sup, ?MODULE),
    supervisor:delete_child(netspire_sup, ?MODULE).

init([_Options]) ->
    process_flag(trap_exit, true),
    netspire_hooks:add(backend_fetch_account, ?MODULE, fetch_account),
    netspire_hooks:add(backend_start_session, ?MODULE, start_session),
    netspire_hooks:add(backend_sync_session, ?MODULE, sync_session),
    netspire_hooks:add(backend_stop_session, ?MODULE, stop_session),
    {ok, #state{}}.

process_fetch_account_result(Result) ->
    F = fun(List) ->
            {_, _, _, Name, Value} = List,
            {binary_to_list(Name), binary_to_list(Value)}
    end,
    case Result of
        {ok, _Columns, Rows} ->
            case Rows of
                [] ->
                    undefined;
                Res ->
                    {Password, Balance, Plan, _, _} = lists:nth(1, Res),
                    Attrs = lists:map(F, Res),
                    {ok, {binary_to_list(Password), Attrs, {Balance, binary_to_list(Plan)}}}
            end;
        _ -> undefined
    end.

handle_cast({start_session, UserName, SID, StartedAt}, State) ->
    pgsql:equery(State#state.ref, "SELECT * FROM start_session($1, $2, $3)",
        [UserName, SID, StartedAt]),
    {noreply, State};
handle_cast({stop_session, UserName, SID, FinishedAt, In, Out, Amount, Expired}, State) ->
    pgsql:equery(State#state.ref, "SELECT * FROM stop_session($1, $2, $3, $4, $5, $6, $7)",
        [UserName, SID, FinishedAt, In, Out, Amount, Expired]),
    {noreply, State};
handle_cast({sync_session, UserName, SID, TimeStamp, In, Out, Balance}, State) ->
    pgsql:equery(State#state.ref, "SELECT * FROM sync_session($1, $2, $3, $4, $5, $6)",
        [UserName, SID, TimeStamp, In, Out, Balance]),
    {noreply, State};
handle_cast(_Request, State) ->
    {noreply, State}.

handle_call({create_db_connection, Options}, _From, State) ->
    case erlang:apply(pgsql, connect, Options) of
        {ok, Ref} ->
            ?INFO_MSG("Database connection has been established~n", []),
            {reply, ok, State#state{ref = Ref}};
        {error, Reason} ->
            ?ERROR_MSG("Connection to database failed: ~p~n", [Reason]),
            {stop, conn_failed, ok, State}
    end;
handle_call({fetch_account, UserName}, _From, State) ->
    Result = pgsql:equery(State#state.ref, "SELECT * FROM auth($1)", [UserName]),
    Result1 = process_fetch_account_result(Result),
    {reply, {stop, Result1}, State};
handle_call(stop, _From, State) ->
    {stop, normal, ok, State};
handle_call(_Request, _From, State) ->
    Reply = ok,
    {reply, Reply, State}.

handle_info({'EXIT', From, Reason}, #state{ref = From} = State) ->
    ?WARNING_MSG("Lost connection to database backend ~p~n", [Reason]),
    % Otherwise it will exceed main sup's MaxR and cause application stop
    timer:sleep(3000),
    {stop, db_conn_died, State};
handle_info(_Request, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, State) ->
    pgsql:close(State#state.ref),
    netspire_hooks:delete(backend_fetch_account, ?MODULE, fetch_account),
    netspire_hooks:delete(backend_start_session, ?MODULE, start_session),
    netspire_hooks:delete(backend_sync_session, ?MODULE, sync_session),
    netspire_hooks:delete(backend_stop_session, ?MODULE, stop_session).
