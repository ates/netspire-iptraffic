-module(mod_pgsql).

-behaviour(gen_module).
-behaviour(gen_server).

%% API
-export([start_link/1, lookup_account/4]).

%% gen_module callbacks
-export([start/1, stop/0]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2,
         terminate/2, code_change/3]).

-include("netspire.hrl").

-record(state, {ref}).

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
    netspire_hooks:delete(radius_acct_lookup, ?MODULE, lookup_account).

lookup_account(_Value, _Request, UserName, _Client) ->
    gen_server:call(?MODULE, {lookup_account, UserName}).

%%
%% Internal functions
%%

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
            {ok, #state{ref = Ref}};
        _ ->
            ?ERROR_MSG("Invalid connection string for PostgreSQL driver~n", []),
            {stop, invalid_connection_string_pgsql}
    end.

handle_call({lookup_account, UserName}, _From, State) ->
    Query = "SELECT * FROM auth($1)",
    Result = pgsql:pquery(State#state.ref, Query, [UserName]),
    case Result of
        {ok, _, _, _, [Res]} ->
            case Res of
                [] ->
                    {reply, {stop, undefined}, State};
                [Password, _, _, _, _,_] ->
                    Response = {ok, {Password, []}},
                    {reply, {stop, Response}, State}
            end;
        _ ->
            {reply, {stop, undefined}, State}
    end;

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

terminate(_Reason, _State) ->
    ok.

