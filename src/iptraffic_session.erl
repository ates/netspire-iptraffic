-module(iptraffic_session).

-behaviour(gen_server).

%% API
-export([start_link/1, prepare/4, start/3, interim/1, stop/1, expire/1, handle_packet/2, list/0, list/1]).

%% gen_server callbacks
-export([init/1, handle_call/3, handle_cast/2, handle_info/2, terminate/2, code_change/3]).

-include("netspire.hrl").
-include("netflow/netflow_v5.hrl").
-include("netflow/netflow_v9.hrl").
-include("iptraffic.hrl").
-include_lib("stdlib/include/qlc.hrl").

start_link(UUID) ->
    gen_server:start_link(?MODULE, [UUID], []).

prepare(Pid, UserName, Extra, Client) ->
    gen_server:call(Pid, {prepare, UserName, Extra, Client}).

start(UserName, IP, SID) ->
    case fetch({new, UserName}) of
        {ok, State} ->
            gen_server:call(State#ipt_session.pid, {start, IP, SID});
        Error ->
            Error
    end.

interim(SID) ->
    case fetch(SID) of
        {ok, State} ->
            gen_server:call(State#ipt_session.pid, interim);
        Error ->
            Error
    end.

stop(Pid) when is_pid(Pid) ->
    gen_server:call(Pid, stop);
stop(SID) ->
    case fetch(SID) of
        {ok, State} ->
            stop(State#ipt_session.pid);
        Error ->
            Error
    end.

expire(Pid) when is_pid(Pid) ->
    gen_server:call(Pid, expire);
expire(SID) ->
    case fetch(SID) of
        {ok, State} ->
            expire(State#ipt_session.pid);
        Error ->
            Error
    end.

handle_packet(_SrcIP, Pdu) ->
    process_netflow_packet(Pdu).

%% Shows all registered sessions
list() ->
    lists:map(fun(SID) -> list(SID) end, mnesia:dirty_all_keys(ipt_session)).

%% Shows the session by SID
list(SID) ->
    [Session] = mnesia:dirty_read({ipt_session, SID}), Session.

init([UUID]) ->
    process_flag(trap_exit, true),
    case mnesia:dirty_index_read(ipt_session, UUID, uuid) of
        [] ->
            State = #ipt_session{uuid = UUID, pid = self(), node = node()},
            {ok, State};
        [State] ->
            NewState = State#ipt_session{pid = self(), node = node()},
            mnesia:dirty_write(NewState),
            {ok, NewState};
        _ ->
            {stop, ambiguous_match}
    end.

handle_call({prepare, UserName, {Balance, Plan}, Client}, _From, State) ->
    SID = {new, UserName},
    Now = netspire_util:timestamp(),
    Timeout = mod_iptraffic:get_option(session_timeout, 60),
    ExpiresAt = Now + Timeout,
    Data = #ipt_data{balance = Balance, plan = Plan},
    NewState = State#ipt_session{sid = SID, status = new, username = UserName, nas_spec = Client, disc_req_sent = false,
        data = Data, started_at = Now, expires_at = ExpiresAt},
    mnesia:dirty_write(NewState),
    {reply, ok, NewState};
handle_call({start, IP, SID}, _From, State) ->
    F = fun() ->
            mnesia:delete_object(State),
            NewState = State#ipt_session{sid = SID, ip = IP, status = active},
            mnesia:write(NewState),
            NewState
        end,
    case mnesia:transaction(F) of
        {atomic, NewState} ->
            UserName = State#ipt_session.username,
            case netspire_hooks:run_fold(iptraffic_start_session, undef, [UserName, IP, SID, now()]) of
                ok ->
                    {reply, ok, NewState};
                _Error ->
                    {reply, {error, backend_failure}, NewState}
            end;
        Aborted ->
            Reply = {error, Aborted},
            {reply, Reply, State}
    end;
handle_call(interim, _From, State) ->
    Timeout = mod_iptraffic:get_option(session_timeout, 60),
    ExpiresAt = netspire_util:timestamp() + Timeout,
    F = fun() ->
            mnesia:delete_object(State),
            NewState = State#ipt_session{expires_at = ExpiresAt},
            mnesia:write(NewState),
            NewState
        end,
    case mnesia:transaction(F) of
        {atomic, NewState} ->
            #ipt_session{sid = SID, username = UserName, data = Data} = State,
            #ipt_data{octets_in = In, octets_out = Out, amount = Amount} = Data,
            case netspire_hooks:run_fold(iptraffic_sync_session, undef, [UserName, SID, now(), In, Out, Amount]) of
                ok ->
                    {reply, ok, NewState};
                _Error ->
                    {reply, {error, backend_failure}, NewState}
            end;
        Aborted ->
            {reply, {error, Aborted}, State}
    end;
handle_call(stop, _From, State) ->
    case stop_session(State, false) of
        {ok, NewState} ->
            Reply = {ok, NewState},
            {stop, normal, Reply, State};
        {preclosed, NewState} ->
            {reply, {ok, NewState}, NewState};
        _Error ->
            {reply, {error, backend_failure}, State}
    end;
handle_call(expire, _From, State) ->
    case stop_session(State, true) of
        {ok, _} ->
            {stop, normal, ok, State};
        _Error ->
            {reply, {error, backend_failure}, State}
    end;
handle_call(_Request, _From, State) ->
    {reply, ok, State}.

handle_cast({netflow, Direction, {H, Rec}}, State) ->
    {ok, Args} = build_iptraffic_args(H, Rec, Direction),
    case do_accounting(State, Args) of
        {ok, NewState} ->
            mnesia:dirty_write(NewState),
            {noreply, NewState};
        _Error ->
            {noreply, State}
    end;
handle_cast(_Request, State) ->
    {noreply, State}.

handle_info(_Request, State) ->
    {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
    {ok, State}.

terminate(normal, State) ->
    ?INFO_MSG("Session ~s finished successfully~n", [to_string(State)]);
terminate(shutdown, State) ->
    case gen_module:get_option(mod_iptraffic, disconnect_on_shutdown, yes) of
        yes ->
            disconnect_client(State);
        _ -> ok
    end,
    stop_session(State, false),
    ?INFO_MSG("Session ~s shutted down successfully~n", [to_string(State)]);
terminate(Reason, State) ->
    ?ERROR_MSG("Session ~s abnormally terminated due to ~p~n", [to_string(State), Reason]).

stop_session(#ipt_session{status = new} = Session, _Expired) ->
    ?INFO_MSG("Discarding session: ~s~n", [to_string(Session)]),
    mnesia:dirty_delete_object(Session);
stop_session(#ipt_session{status = preclosed} = Session, Expired) ->
    #ipt_session{sid = SID, username = UserName, finished_at = FinishedAt, data = Data} = Session,
    #ipt_data{octets_in = In, octets_out = Out, amount = Amount} = Data,
    case netspire_hooks:run_fold(iptraffic_stop_session, undef, [UserName, SID, FinishedAt, In, Out, Amount, Expired]) of
        ok ->
            mnesia:dirty_delete_object(Session),
            {ok, Session};
        Error ->
            {error, Error}
    end;
stop_session(Session, Expired) ->
    NewState = Session#ipt_session{status = preclosed, finished_at = now()},
    case mnesia:transaction(fun() -> mnesia:write(NewState) end) of
        {atomic, ok} ->
            case Expired of
                true ->
                    stop_session(NewState, Expired);
                false ->
                    ?INFO_MSG("Session ~s changed to preclosed~n", [to_string(NewState)]),
                    {preclosed, NewState}
            end;
        Error ->
            ?INFO_MSG("Cannot change status of session ~s due to ~p~n", [to_string(NewState), Error])
    end.

process_netflow_packet({H, Records}) when is_record(H, nfh_v5) ->
    Fun = fun(Rec) -> match_record(H, Rec) end,
    lists:foreach(Fun, Records);
process_netflow_packet(_Pdu) ->
    ?WARNING_MSG("Unsupported NetFlow version~n", []).

match_record(H, Rec) ->
    SrcIP = ip:long2ip(Rec#nfrec_v5.src_addr),
    DstIP = ip:long2ip(Rec#nfrec_v5.dst_addr),
    case match_session(SrcIP, DstIP) of
        {ok, Matches} ->
            Fun = fun({Dir, Session}) ->
                Message = {netflow, Dir, {H, Rec}},
                gen_server:cast(Session#ipt_session.pid, Message)
            end,
            lists:foreach(Fun, Matches);
        _ ->
            ok
    end.

match_session(SrcIP, DstIP) ->
    F = fun() ->
            Q = qlc:q([X || X <- mnesia:table(ipt_session),
                    (X#ipt_session.ip == SrcIP orelse X#ipt_session.ip == DstIP) andalso
                    (X#ipt_session.status == active orelse X#ipt_session.status == preclosed)]),
            qlc:e(Q)
    end,
    case mnesia:ets(F) of
        [] ->
            ?WARNING_MSG("No active sessions matching flow src/dst: ~s/~s~n",
                [inet_parse:ntoa(SrcIP), inet_parse:ntoa(DstIP)]),
            {error, no_matches};
        Res when is_list(Res) ->
            tag_with_direction(Res, SrcIP, DstIP, [])
    end.

tag_with_direction([], _, _, Acc) ->
    {ok, Acc};
tag_with_direction([S | Tail], SrcIP, DstIP, Acc) ->
    S1 = tag_with_direction(S, SrcIP, DstIP),
    tag_with_direction(Tail, SrcIP, DstIP, [S1 | Acc]).
tag_with_direction(S, _, DstIP) when S#ipt_session.ip == DstIP ->
    {in, S};
tag_with_direction(S, SrcIP, _) when S#ipt_session.ip == SrcIP ->
    {out, S}.

build_iptraffic_args(H, Rec, Direction) when is_record(H, nfh_v5) ->
    {_Days, Time} = calendar:seconds_to_daystime(H#nfh_v5.unix_secs),
    Args = #ipt_args{
        sec = calendar:time_to_seconds(Time),
        src_ip = ip:long2ip(Rec#nfrec_v5.src_addr),
        dst_ip = ip:long2ip(Rec#nfrec_v5.dst_addr),
        src_port = Rec#nfrec_v5.src_port,
        dst_port = Rec#nfrec_v5.dst_port,
        proto = Rec#nfrec_v5.prot,
        octets = Rec#nfrec_v5.d_octets,
        dir = Direction
    },
    {ok, Args}.

do_accounting(Session, Args) ->
    Data = Session#ipt_session.data,
    Plan = Data#ipt_data.plan,
    case iptraffic_tariffs:match(Plan, Session, Args) of
        {ok, {Plan, _Rule, Cost} = MatchResult} when Cost > 0 ->
            Amount = Args#ipt_args.octets / 1024 / 1024 * Cost,
            NewBalance = Data#ipt_data.balance - (Data#ipt_data.amount + Amount),
            NewSession = if
                NewBalance =< 0 andalso Session#ipt_session.disc_req_sent == false ->
                    spawn(fun() -> disconnect_client(Session) end),
                    Session#ipt_session{disc_req_sent = true};
                true -> Session
            end,
            NewState = update_session_state(NewSession, Args, Amount),
            netspire_hooks:run(matched_session, [Session, Args, MatchResult, Amount]),
            {ok, NewState};
        {ok, MatchResult} ->
            NewState = update_session_state(Session, Args, 0),
            netspire_hooks:run(matched_session, [Session, Args, MatchResult, 0]),
            {ok, NewState};
        {error, Reason} ->
            ?ERROR_MSG("Cannot process accounting for session ~s due to ~p~n",
                [Session#ipt_session.sid, Reason]),
            {error, Reason}
    end.

disconnect_client(Session) ->
    UserName = Session#ipt_session.username,
    SID = Session#ipt_session.sid,
    IP = Session#ipt_session.ip,
    NasSpec = Session#ipt_session.nas_spec,
    ?INFO_MSG("Disconnecting ~s | SID: ~p~n", [UserName, SID]),
    case netspire_hooks:run_fold(disconnect_client, undef, [UserName, SID, IP, NasSpec]) of
        {ok, _} ->
            ?INFO_MSG("User ~s | SID: ~p successful disconnected~n", [UserName, SID]);
        {error, Reason} ->
            ?ERROR_MSG("Failed to disconnect ~s | SID: ~p due to ~w~n", [UserName, SID, Reason])
    end.

update_session_state(Session, Args, Amount) ->
    Data = Session#ipt_session.data,
    #ipt_args{dir = Direction, octets = Octets} = Args,
    NewAmount = Amount + Data#ipt_data.amount,
    NewData =
        case Direction of
            in ->
                Data#ipt_data{amount = NewAmount, octets_in = Data#ipt_data.octets_in + Octets};
            out ->
                Data#ipt_data{amount = NewAmount, octets_out = Data#ipt_data.octets_out + Octets}
        end,
    Session#ipt_session{data = NewData}.

fetch(SID) ->
    case mnesia:dirty_read(ipt_session, SID) of
        [State] ->
            {ok, State};
        [] ->
            {error, not_found}
    end.

to_string(Session) ->
    #ipt_session{username = UserName, sid = SID} = Session,
    io_lib:format("UserName: ~s | SID: ~p", [UserName, SID]).
