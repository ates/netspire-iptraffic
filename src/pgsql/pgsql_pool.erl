%% This module is originally from Zotonic CMS. Look at LICENSE for copyright holders.
-module(pgsql_pool).

-behaviour(gen_server).

%% API
-export([start_link/2, get_connection/0, get_connection/1, return_connection/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-record(state, {size, connections, monitors, waiting, options}).

start_link(Size, Options) ->
    gen_server:start_link({local, ?MODULE}, ?MODULE, [Size, Options], []).

get_connection() ->
    get_connection(5000).

get_connection(Timeout) ->
    try
        gen_server:call(?MODULE, get_connection, Timeout)
    catch
        _:_ ->
            gen_server:cast(?MODULE, {cancel_wait, self()}),
            {error, timeout}
    end.

return_connection(C) ->
    gen_server:cast(?MODULE, {return_connection, C}).

init([Size, Options]) ->
    process_flag(trap_exit, true),
    {ok, C} = connect(Options),
    State = #state{size = Size, connections = [C], monitors = [], waiting = queue:new(), options = Options},
    {ok, State}.

handle_call(get_connection, From, #state{connections = Connections, waiting = Waiting} = State) ->
    case Connections of
        [C | T] ->
            {noreply, deliver(From, C, State#state{connections = T})};
        [] ->
            case length(State#state.monitors) < State#state.size of
                true ->
                    {ok, C} = connect(State#state.options),
                    {noreply, deliver(From, C, State)};
                false ->
                    {noreply, State#state{waiting = queue:in(From, Waiting)}}
            end
    end;
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({return_connection, C}, #state{monitors = Monitors} = State) ->
    case lists:keytake(C, 1, Monitors) of
        {value, {C, M}, NewMonitors} ->
            erlang:demonitor(M),
            NewState = return(C, State#state{monitors = NewMonitors}),
            {noreply, NewState};
        false ->
            {noreply, State}
    end;
handle_cast({cancel_wait, Pid}, #state{waiting = Waiting} = State) ->
    NewWaiting = queue:filter(fun({QPid, _Tag}) -> QPid =/= Pid end, Waiting),
    {noreply, State#state{waiting = NewWaiting}};
handle_cast(_Request, State) ->
    {noreply, State}.

handle_info({'DOWN', M, process, _Pid, _Info}, #state{monitors = Monitors} = State) ->
    case lists:keytake(M, 2, Monitors) of
        {value, {C, M}, NewMonitors} ->
            pgsql:close(C),
            {noreply, State#state{monitors = NewMonitors}};
        false ->
            {noreply, State}
    end;

handle_info({'EXIT', Pid, _Reason}, State) ->
    #state{connections = Connections, monitors = Monitors} = State,
    NewConnections = proplists:delete(Pid, Connections),
    F = fun({C, M}) when C == Pid -> erlang:demonitor(M), false;
            (_) -> true
        end,
    NewMonitors = lists:filter(F, Monitors),
    {noreply, State#state{connections = NewConnections, monitors = NewMonitors}};
handle_info(_Request, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(_Reason, _State) ->
    ok.

connect(Options) ->
    erlang:apply(pgsql, connect, Options).

deliver({Pid, _Tag} = From, C, #state{monitors = Monitors} = State) ->
    M = erlang:monitor(process, Pid),
	gen_server:reply(From, {ok, C}),
	State#state{monitors = [{C, M} | Monitors]}.

return(C, #state{connections = Connections, waiting = Waiting} = State) ->
    case queue:out(Waiting) of
        {{value, From}, Q} ->
            NewState = deliver(From, C, State),
            NewState#state{waiting = Q};
        {empty, _Q} ->
            State#state{connections = [C | Connections]}
    end.
