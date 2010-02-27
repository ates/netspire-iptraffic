-module(mod_iptraffic_pgsql).

-behaviour(gen_module).

-export([fetch_account/2, start_session/5, sync_session/7, stop_session/8]).

%% gen_module callbacks
-export([start/1, stop/0]).

-include("netspire.hrl").

start(Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    PoolSize = proplists:get_value(pool_size, lists:last(Options), 5),
    case start_pool(PoolSize, proplists:delete(pool_size, Options)) of
        {ok, _Pid} ->
            netspire_hooks:add(backend_fetch_account, ?MODULE, fetch_account),
            netspire_hooks:add(backend_start_session, ?MODULE, start_session),
            netspire_hooks:add(backend_sync_session, ?MODULE, sync_session),
            netspire_hooks:add(backend_stop_session, ?MODULE, stop_session);
        _Any ->
            ok
    end.

start_pool(Size, Options) ->
    ChildSpec = {pgsql_pool,
                 {pgsql_pool, start_link, [Size, Options]},
                 transient,
                 3000,
                 worker,
                 [pgsql_pool]
                },
    supervisor:start_child(netspire_sup, ChildSpec).

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    netspire_hooks:delete_all(?MODULE),
    supervisor:terminate_child(netspire_sup, pgsql_pool),
    supervisor:delete_child(netspire_sup, pgsql_pool).

fetch_account(_, UserName) ->
    DbResult = execute("SELECT * FROM auth($1)", [UserName]),
    Result = process_fetch_account_result(DbResult),
    {stop, Result}.

start_session(_, UserName, IP, SID, StartedAt) ->
    Q = "SELECT * FROM iptraffic_start_session($1, $2, $3, $4)",
    case execute(Q, [UserName, inet_parse:ntoa(IP), SID, calendar:now_to_universal_time(StartedAt)]) of
        {ok, _, _} ->
            {stop, ok};
        {error, Reason} ->
            {stop, {error, Reason}}
    end.

sync_session(_, UserName, SID, UpdatedAt, In, Out, Amount) ->
    Q = "SELECT * FROM iptraffic_sync_session($1, $2, $3, $4, $5, $6)",
    case execute(Q, [UserName, SID, calendar:now_to_universal_time(UpdatedAt), In, Out, Amount]) of
        {ok, _, _} ->
            {stop, ok};
        {error, Reason} ->
            {stop, {error, Reason}}
    end.

stop_session(_, UserName, SID, FinishedAt, In, Out, Amount, Expired) ->
    Q = "SELECT * FROM iptraffic_stop_session($1, $2, $3, $4, $5, $6, $7)",
    case execute(Q, [UserName, SID, calendar:now_to_universal_time(FinishedAt), In, Out, Amount, Expired]) of
        {ok, _, _} ->
            {stop, ok};
        {error, Reason} ->
            {stop, {error, Reason}}
    end.

execute(Q, Params) ->
    case pgsql_pool:get_connection() of
        {ok, C} ->
            try
                pgsql:equery(C, Q, Params)
            after
                pgsql_pool:return_connection(C)
            end;
        {error, timeout} ->
            ?INFO_MSG("Unable to obtain database connection due to timeout~n", []),
            {error, timeout}
    end.

process_fetch_account_result(Result) ->
    F = fun({_, _, _, null, null}) ->
                undefined;
            ({_, _, _, Name, Value}) ->
                {binary_to_list(Name), binary_to_list(Value)}
    end,
    case Result of
        {ok, _Columns, Rows} ->
            case Rows of
                [] ->
                    undefined;
                Res ->
                    {Password, Balance, Plan, _, _} = lists:nth(1, Res),
                    Attrs = lists:filter(fun(E) -> E /= undefined end, lists:map(F, Res)),
                    {ok, {binary_to_list(Password), Attrs, {Balance, binary_to_list(Plan)}}}
            end;
        _ -> undefined
    end.
