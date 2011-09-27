-module(mod_iptraffic_pgsql).

-behaviour(gen_module).

-export([fetch_account/2, start_session/5, sync_session/7, stop_session/8]).

%% gen_module callbacks
-export([start/1, stop/0]).

-include("netspire.hrl").

-define(NOW2UTC(Date), calendar:now_to_universal_time(Date)).

start(_Options) ->
    ?INFO_MSG("Starting dynamic module ~p~n", [?MODULE]),
    netspire_hooks:add(iptraffic_fetch_account, ?MODULE, fetch_account),
    netspire_hooks:add(iptraffic_start_session, ?MODULE, start_session),
    netspire_hooks:add(iptraffic_sync_session, ?MODULE, sync_session),
    netspire_hooks:add(iptraffic_stop_session, ?MODULE, stop_session).

stop() ->
    ?INFO_MSG("Stopping dynamic module ~p~n", [?MODULE]),
    netspire_hooks:delete_all(?MODULE).

fetch_account(_, UserName) ->
    try
        {ok, _, [{ServiceLinkID, Password, Balance}]} = execute(
            "SELECT service_link_id, password, balance::FLOAT FROM iptraffic_access_links WHERE login = $1 AND balance > 0 LIMIT 1", [UserName]),
        {ok, _, [{AssignedServiceID}]} = execute(
            "SELECT assigned_service_id FROM service_links WHERE id = $1 AND active = TRUE LIMIT 1", [ServiceLinkID]),
        {ok, _, [{PlanID}]} = execute(
            "SELECT plan_id FROM assigned_services WHERE id = $1 LIMIT 1", [AssignedServiceID]),
        {ok, _, [{Code}]} = execute("SELECT code FROM plans WHERE id = $1 AND active = TRUE LIMIT 1", [PlanID]),
        {stop, {ok, {binary_to_list(Password), [], {Balance, binary_to_list(Code)}}}}
    catch
        _:Reason ->
            {stop, {error, Reason}}
    end.

start_session(_, UserName, IP, SID, StartedAt) ->
    Q = "SELECT * FROM iptraffic_start_session($1, $2, $3, $4)",
    case execute(Q, [UserName, inet_parse:ntoa(IP), SID, ?NOW2UTC(StartedAt)]) of
        {ok, _, _} ->
            {stop, ok};
        {error, Reason} ->
            ?ERROR_MSG("Cannot start session ~s due to ~p~n", [SID, Reason]),
            {stop, {error, Reason}}
    end.

sync_session(_, UserName, SID, UpdatedAt, In, Out, Amount) ->
    Q = "SELECT * FROM iptraffic_sync_session($1, $2, $3, $4, $5, $6)",
    case execute(Q, [UserName, SID, ?NOW2UTC(UpdatedAt), In, Out, Amount]) of
        {ok, _, _} ->
            {stop, ok};
        {error, Reason} ->
            ?ERROR_MSG("Cannot update session ~s due to ~p~n", [SID, Reason]),
            {stop, {error, Reason}}
    end.

stop_session(_, UserName, SID, FinishedAt, In, Out, Amount, Expired) ->
    Q = "SELECT * FROM iptraffic_stop_session($1, $2, $3, $4, $5, $6, $7)",
    case execute(Q, [UserName, SID, ?NOW2UTC(FinishedAt), In, Out, Amount, Expired]) of
        {ok, _, _} ->
            {stop, ok};
        {error, Reason} ->
            ?ERROR_MSG("Cannot update session ~s due to ~p~n", [SID, Reason]),
            {stop, {error, Reason}}
    end.

%%
%% Internal functions
%%
execute(Q, Params) ->
    mod_postgresql:execute(Q, Params).
