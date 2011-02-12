-module(iptraffic_tariffs).

-export([init/1, match/3, reload/1]).

-include("netspire.hrl").
-include("iptraffic.hrl").
-include_lib("stdlib/include/qlc.hrl").

-record(netflow_rule, {
    idx,
    class,
    time,
    dir,
    src_net,
    src_mask,
    src_port,
    dst_net,
    dst_mask,
    dst_port,
    proto
}).

init(File) ->
    ets:new(iptraffic_tariffs, [named_table, public]),
    ets:new(iptraffic_rules, [named_table, public, ordered_set, {keypos, 2}]),
    load_file(File).

match(Plan, Session, Args) ->
    case match_class(Args) of
        {ok, Rule} -> get_cost(Plan, Session, Rule);
        Error -> Error
    end.

reload(File) when is_list(File) ->
    ets:delete_all_objects(iptraffic_tariffs),
    ets:delete_all_objects(iptraffic_rules),
    load_file(File).

get_cost(Plan, _Session, Rule) ->
    Key = {Plan, Rule#netflow_rule.class},
    case ets:lookup(iptraffic_tariffs, Key) of
        [{{Plan, _Class}, Cost}] -> {ok, {Plan, Rule, Cost}};
        _ -> {error, no_matching_plans}
    end.

match_class(Args) ->
    QH = qlc:q([Rule || Rule <- ets:table(iptraffic_rules), match_rule(Rule, Args)]),
    QC = qlc:cursor(QH),
    Result = case qlc:next_answers(QC, 1) of
        [Rule] -> {ok, Rule};
        _ -> {error, no_matching_rules}
    end,
    qlc:delete_cursor(QC),
    Result.

match_rule(any, _) ->
    true;
match_rule(Rule, Args) ->
    match_time(Rule#netflow_rule.time, Args#ipt_args.sec) andalso
    (Rule#netflow_rule.dir == Args#ipt_args.dir orelse Rule#netflow_rule.dir == any) andalso
    match_net(Rule#netflow_rule.src_net, Rule#netflow_rule.src_mask, Args#ipt_args.src_ip) andalso
    match_net(Rule#netflow_rule.dst_net, Rule#netflow_rule.dst_mask, Args#ipt_args.dst_ip) andalso
    (Rule#netflow_rule.src_port == Args#ipt_args.src_port orelse Rule#netflow_rule.src_port == any) andalso
    (Rule#netflow_rule.src_port == Args#ipt_args.dst_port orelse Rule#netflow_rule.dst_port == any) andalso
    (Rule#netflow_rule.proto == Args#ipt_args.proto orelse Rule#netflow_rule.proto == any).

match_time(any, _) ->
    true;
match_time({0, 0}, _Time) ->
    true;
match_time({Start, End}, Time) when End >= Start ->
    Time >= Start andalso Time =< End;
match_time({Start, End}, Time) when End < Start ->
    Time >= Start orelse Time =< End.


%% TODO: Use ip:in_range instead of this match_net functions
match_net(Network, NetworkMask, IP) when is_integer(NetworkMask) ->
    IPInt = ip:ip2long(IP),
    NetworkInt = ip:ip2long(Network),
    Mask = 16#ffffffff bsl (32 - NetworkMask),
    if
        (IPInt band Mask) == (NetworkInt band Mask) ->
            true;
        true -> false
    end;
match_net(Network, NetworkMask, IP) when is_tuple(NetworkMask) ->
    IPInt = ip:ip2long(IP),
    NetworkInt = ip:ip2long(Network),
    MaskInt = ip:ip2long(NetworkMask),
    if
        (IPInt band MaskInt) == NetworkInt ->
            true;
        true -> false
    end.

load_file(File) ->
    ?INFO_MSG("Loading tariff plans from ~s~n", [File]),
    case file:consult(File) of
        {ok, Terms} ->
            process_terms(Terms);
        {error, Reason} ->
            Msg = file:format_error(Reason),
            ?ERROR_MSG("Can't load file with tariffs ~s: ~s~n", [File, Msg]),
            {error, Reason}
    end.

process_terms(Terms) ->
    Periods = proplists:get_value(periods, Terms, []),
    Classes = proplists:get_value(classes, Terms, []),
    Plans = proplists:get_value(plans, Terms, []),
    read_class(Classes, 0, read_time(Periods, [])),
    read_plan(Plans).

read_plan([]) ->
    ok;
read_plan([{Name, ClassLinks} | Tail]) ->
    Fun = fun({ClassName, Cost}) ->
        {{Name, ClassName}, Cost}
    end,
    Records = lists:map(Fun, ClassLinks),
    ets:insert(iptraffic_tariffs, Records),
    read_plan(Tail).

read_class([], _, _) ->
    ok;
read_class([{Name, PeriodName, Rules} | Tail], Idx, Periods) ->
    read_class([{Name, PeriodName, any, Rules} | Tail], Idx, Periods);
read_class([{Name, PeriodName, Direction, Rules} | Tail], Idx, Periods) ->
    Period = proplists:get_value(PeriodName, Periods, any),
    Fun = fun(Rule) -> write_rule(Name, Period, Direction, Rule, Idx) end,
    lists:foreach(Fun, Rules),
    read_class(Tail, Idx + 1, Periods).

write_rule(Class, Period, Direction, Rule, Idx) ->
    SrcRule = proplists:get_value(src, Rule),
    DstRule = proplists:get_value(dst, Rule),
    {SrcNet, SrcMask, SrcPort} = expand_net(SrcRule),
    {DstNet, DstMask, DstPort} = expand_net(DstRule),
    Proto = proplists:get_value(proto, Rule, any),
    Rec = #netflow_rule{
        idx = Idx,
        class = Class,
        time = Period,
        dir = Direction,
        src_net = SrcNet,
        src_mask = SrcMask,
        src_port = SrcPort,
        dst_net = DstNet,
        dst_mask = DstMask,
        dst_port = DstPort,
        proto = proto(Proto)
    },
    ets:insert(iptraffic_rules, Rec).

expand_net(Rule) ->
    {Addr, Mask} =
        case proplists:get_value(net, Rule) of
            {A, M} ->
                {ok, A1} = inet_parse:address(A),
                {ok, M1} = inet_parse:address(M),
                {A1, M1};
            Net when is_list(Net) ->
                [A, M] = string:tokens(Net, "/"),
                {ok, A1} = inet_parse:address(A),
                {A1, list_to_integer(M)}
        end,
    Port = proplists:get_value(port, Rule, any),
    {Addr, Mask, Port}.

read_time([], Acc) ->
    lists:reverse(Acc);
read_time([{Name, Frame} | Tail], Acc) ->
    [Start, End] = string:tokens(Frame, "-"),
    Acc1 = [{Name, {list_to_seconds(Start), list_to_seconds(End)}} | Acc],
    read_time(Tail, Acc1).

list_to_time(L) ->
    [H, M, S] = string:tokens(L, ":"),
    {list_to_integer(H), list_to_integer(M), list_to_integer(S)}.

list_to_seconds(L) ->
    calendar:time_to_seconds(list_to_time(L)).

proto(icmp) ->
    1;
proto(tcp) ->
    6;
proto(udp) ->
    17;
proto(Proto) ->
    Proto.
