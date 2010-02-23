-module(mod_iptraffic_pgsql).

-behaviour(gen_module).

-export([pgsql_connect/1, fetch_account/2, start_session/5, sync_session/7, stop_session/8]).

%% gen_module callbacks
-export([start/1, stop/0]).

-include("netspire.hrl").

start(Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    case create_connection(Options) of
        {ok, _} ->
            netspire_hooks:add(backend_fetch_account, ?MODULE, fetch_account),
            netspire_hooks:add(backend_start_session, ?MODULE, start_session),
            netspire_hooks:add(backend_sync_session, ?MODULE, sync_session),
            netspire_hooks:add(backend_stop_session, ?MODULE, stop_session);
        _ ->
            ok
    end.

create_connection(Options) ->
    ChildSpec = {?MODULE,
                 {?MODULE, pgsql_connect, [Options]},
                 transient,
                 3000,
                 worker,
                 [?MODULE]
                },
    supervisor:start_child(netspire_sup, ChildSpec).

pgsql_connect(Options) ->
    pgsql_connect(Options, undefined, 1000).

pgsql_connect(_Options, Error, 0) ->
    ?ERROR_MSG("Cannot create database connection due to ~p~n", [Error]),
    Error;
pgsql_connect(Options, _LastError, I) ->
    case erlang:apply(pgsql, connect, Options) of
        {ok, Pid} ->
            erlang:register(pgsql_connection, Pid),
            ?INFO_MSG("Database connection created successfully~n", []),
            {ok, Pid};
        Error ->
            timer:sleep(300),
            pgsql_connect(Options, Error, I - 1)
    end.

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    netspire_hooks:delete(backend_fetch_account, ?MODULE, fetch_account),
    netspire_hooks:delete(backend_start_session, ?MODULE, start_session),
    netspire_hooks:delete(backend_sync_session, ?MODULE, sync_session),
    netspire_hooks:delete(backend_stop_session, ?MODULE, stop_session),
    pgsql:close(erlang:whereis(pgsql_connection)),
    supervisor:terminate_child(netspire_sup, ?MODULE),
    supervisor:delete_child(netspire_sup, ?MODULE).

fetch_account(_, UserName) ->
    Ref = erlang:whereis(pgsql_connection),
    DbResult = pgsql:equery(Ref, "SELECT * FROM auth($1)", [UserName]),
    Result = process_fetch_account_result(DbResult),
    {stop, Result}.

start_session(_, UserName, IP, SID, StartedAt) ->
    Ref = erlang:whereis(pgsql_connection),
    Q = "SELECT * FROM iptraffic_start_session($1, $2, $3, $4)",
    case pgsql:equery(Ref, Q, [UserName, inet_parse:ntoa(IP), SID, calendar:now_to_universal_time(StartedAt)]) of
        {ok, _, _} ->
            {stop, ok};
        Error ->
            {stop, {error, Error}}
    end.

sync_session(_, UserName, SID, UpdatedAt, In, Out, Amount) ->
    Ref = erlang:whereis(pgsql_connection),
    Q = "SELECT * FROM iptraffic_sync_session($1, $2, $3, $4, $5, $6)",
    case pgsql:equery(Ref, Q, [UserName, SID, calendar:now_to_universal_time(UpdatedAt), In, Out, Amount]) of
        {ok, _, _} ->
            {stop, ok};
        Error ->
            {stop, {error, Error}}
    end.

stop_session(_, UserName, SID, FinishedAt, In, Out, Amount, Expired) ->
    Ref = erlang:whereis(pgsql_connection),
    Q = "SELECT * FROM iptraffic_stop_session($1, $2, $3, $4, $5, $6, $7)",
    case pgsql:equery(Ref, Q, [UserName, SID, calendar:now_to_universal_time(FinishedAt), In, Out, Amount, Expired]) of
        {ok, _, _} ->
            {stop, ok};
        Error ->
            {stop, {error, Error}}
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
