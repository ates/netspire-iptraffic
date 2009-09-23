-module(iptraffic_tariffs).

-export([init/1, match/7]).

-include("netspire.hrl").
-include_lib("stdlib/include/qlc.hrl").

-record(iptraffic_class, {name, time, rules = []}).
-record(netflow_rule, {src_net, src_mask, src_port, dst_net, dst_mask, dst_port, proto}).

init(File) ->
    ets:new(tariffs, [named_table, bag]),
    load_file(File).

match(Plan, Time, SrcIP, DstIP, SrcPort, DstPort, Proto) ->
    QH = qlc:q([T || T <- ets:table(tariffs),
        match_plan(T, Plan, Time, SrcIP, DstIP, SrcPort, DstPort, Proto)]),
    QC = qlc:cursor(QH),
    Result = case qlc:next_answers(QC, 1) of
        [Match] ->
            {ok, Match};
        _ ->
            {error, no_matches}
    end,
    qlc:delete_cursor(QC),
    Result.
match_plan({Name, Class, _}, Plan, Time, SrcIP, DstIP, SrcPort, DstPort, Proto) ->
    case Name == Plan of
        true ->
            match_class(Class, Time, SrcIP, DstIP, SrcPort, DstPort, Proto);
        _ ->
            false
    end.

match_class(any, _, _, _, _, _, _) ->
    true;
match_class(Class, Time, SrcIP, DstIP, SrcPort, DstPort, Proto) ->
    Fun = fun(Rule) ->
        match_rule(Rule, SrcIP, DstIP, SrcPort, DstPort, Proto)
    end,
    match_time(Class#iptraffic_class.time, Time) andalso
    lists:any(Fun, Class#iptraffic_class.rules).

match_rule(Rule, SrcIP, DstIP, SrcPort, DstPort, Proto) ->
    net_match(Rule#netflow_rule.src_net, Rule#netflow_rule.src_mask, SrcIP) andalso
    net_match(Rule#netflow_rule.dst_net, Rule#netflow_rule.dst_mask, DstIP) andalso
    (Rule#netflow_rule.src_port == SrcPort orelse Rule#netflow_rule.src_port == any) andalso
    (Rule#netflow_rule.src_port == DstPort orelse Rule#netflow_rule.dst_port == any) andalso
    (Rule#netflow_rule.proto == Proto orelse Rule#netflow_rule.proto == any).

match_time({Start, End}, Time) ->
    Time >= Start andalso Time =< End.

load_file(File) ->
    ?INFO_MSG("Reading tariffs ~s~n", [File]),
    case file:consult(File) of
        {ok, Terms} ->
            process_term(lists:reverse(Terms), [], [], []);
        {error, Reason} ->
            Msg = file:format_error(Reason),
            ?ERROR_MSG("Can't load file with tariffs ~s: ~s~n", [File, Msg]),
            {error, Reason}
    end.

process_term([Term | Tail], Periods, Classes, Plans) ->
    case Term of
        {periods, Val} ->
            Acc = read_period(Val, []),
            process_term(Tail, Acc, Classes, Plans);
        {classes, Val} ->
            Acc = read_class(Val, Periods, []),
            process_term(Tail, Periods, Acc, Plans);
        {plans, Val} ->
            read_plan(Val, Classes)
    end.

read_plan([], _Classes) ->
    ok;
read_plan([{Name, ClassLinks} | Tail], Classes) ->
    Fun = fun({ClassName, Cost}) ->
        Class = proplists:get_value(ClassName, Classes, any),
        {Name, Class, Cost}
    end,
    Records = lists:map(Fun, ClassLinks),
    ets:insert(tariffs, Records),
    read_plan(Tail, Classes).

read_class([], _Periods, Acc) ->
    Acc;
read_class([{Name, PeriodName, Rules} | Tail], Periods, Acc) ->
    ExpandedRules = lists:map(fun expand_rule/1, Rules),
    Period = proplists:get_value(PeriodName, Periods, any),
    ClassRec = #iptraffic_class{name = Name, time = Period, rules = ExpandedRules},
    read_class(Tail, Periods, [{Name, ClassRec} | Acc]).

expand_rule(Rule) ->
    SrcRule = proplists:get_value(src, Rule),
    DstRule = proplists:get_value(dst, Rule),
    {SrcNet, SrcMask, SrcPort} = expand_net_rule(SrcRule),
    {DstNet, DstMask, DstPort} = expand_net_rule(DstRule),
    Proto = proplists:get_value(proto, Rule, tcp),
    #netflow_rule{
        src_net = SrcNet,
        src_mask = SrcMask,
        src_port = SrcPort,
        dst_net = DstNet,
        dst_mask = DstMask,
        dst_port = DstPort,
        proto = proto(Proto)
    }.

expand_net_rule(Rule) ->
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

read_period([], Acc) ->
    lists:reverse(Acc);
read_period([{Name, Frame} | Tail], Acc) ->
    [Start, End] = string:tokens(Frame, "-"),
    Acc1 = [{Name, {list_to_seconds(Start), list_to_seconds(End)}} | Acc],
    read_period(Tail, Acc1).

list_to_time(L) ->
    [H, M, S] = string:tokens(L, ":"),
    {list_to_integer(H), list_to_integer(M), list_to_integer(S)}.

list_to_seconds(L) ->
    calendar:time_to_seconds(list_to_time(L)).

proto(tcp) ->
    6;
proto(udp) ->
    17.

net_match(Network, NetworkMask, IP) when is_integer(NetworkMask) ->
    IPInt = netspire_util:ip4_to_int(IP),
    NetworkInt = netspire_util:ip4_to_int(Network),
    Mask = 16#ffffffff bsl (32 - NetworkMask),
    if
        (IPInt band Mask) == (NetworkInt band Mask) ->
            true;
        true -> false
    end;

net_match(Network, NetworkMask, IP) when is_tuple(NetworkMask) ->
    IPInt = netspire_util:ip4_to_int(IP),
    NetworkInt = netspire_util:ip4_to_int(Network),
    MaskInt = netspire_util:ip4_to_int(NetworkMask),
    Res = (IPInt band MaskInt),
    if
        Res == NetworkInt ->
            true;
        true -> false
    end.
