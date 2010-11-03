-module(iptraffic_tariffs).

-export([init/0, match/3, reload/0]).

-include("netspire.hrl").
-include("iptraffic.hrl").
-include_lib("stdlib/include/qlc.hrl").

-record(netflow_rule, {
    class,
    time,
    days,
    dir,
    src_net,
    src_mask,
    src_port,
    dst_net,
    dst_mask,
    dst_port,
    proto
}).

init() ->
    ets:new(iptraffic_tariffs, [named_table, public]),
    ets:new(iptraffic_rules, [named_table, public, ordered_set, {keypos, 2}]),
    load_plans().

match(Plan, Session, Args) ->
    case match_class(Args) of
        {ok, Rule} -> get_cost(Plan, Session, Rule);
        Error -> Error
    end.

reload() ->
    ets:delete_all_objects(iptraffic_tariffs),
    ets:delete_all_objects(iptraffic_rules),
    load_plans().

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
    match_days(Rule#netflow_rule.days) andalso
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

match_days(Days) ->
    {Today, _} = erlang:localtime(),
    DayOfWeek = calendar:day_of_the_week(Today),
    lists:member(DayOfWeek, Days).

match_net(Network, NetworkMask, IP) when is_integer(NetworkMask) ->
    IPInt = netspire_util:ipconv(IP),
    NetworkInt = netspire_util:ipconv(Network),
    Mask = 16#ffffffff bsl (32 - NetworkMask),
    if
        (IPInt band Mask) == (NetworkInt band Mask) ->
            true;
        true -> false
    end;
match_net(Network, NetworkMask, IP) when is_tuple(NetworkMask) ->
    IPInt = netspire_util:ipconv(IP),
    NetworkInt = netspire_util:ipconv(Network),
    MaskInt = netspire_util:ipconv(NetworkMask),
    if
        (IPInt band MaskInt) == NetworkInt ->
            true;
        true -> false
    end.

load_plans() ->
    case netspire_hooks:run_fold(iptraffic_load_tariffs, undef, []) of
        Tariffs when is_list(Tariffs) ->
            process_terms(Tariffs);
        Error -> ?ERROR_MSG("Cannot load tariff plans due to ~p~n", [Error])
    end.

process_terms([]) -> ok;
process_terms([Term|T]) ->
     [Name, Dir, Src, Dst, SrcPort, DstPort, Proto, Hours, Days, Cost] = Term,
     ets:insert(iptraffic_tariffs, {{Name, Dir}, Cost}),
     {A1, M1} = expand_net(Src),
     {A2, M2} = expand_net(Dst),

     Rec = #netflow_rule{
         class = Dir,
         time = read_time(Hours),
         days = read_days(Days),
         dir = any,
         src_net = A1,
         src_mask = M1,
         src_port = SrcPort,
         dst_net = A2,
         dst_mask = M2,
         dst_port = DstPort,
         proto = proto(Proto)
     },
     ets:insert(iptraffic_rules, Rec),
     process_terms(T).

expand_net(Net) ->
    [A, M] = string:tokens(Net, "/"),
    {ok, A1} = inet_parse:address(A),
    {A1, list_to_integer(M)}.

read_days(Days) ->
    lists:map(fun(D) -> list_to_integer(D) end, string:tokens(Days, ",")).

read_time(Frame) ->
    [Start, End] = string:tokens(Frame, "-"),
    {list_to_seconds(Start), list_to_seconds(End)}.

list_to_time(L) ->
    [H, M, S] = string:tokens(L, ":"),
    {list_to_integer(H), list_to_integer(M), list_to_integer(S)}.

list_to_seconds(L) ->
    calendar:time_to_seconds(list_to_time(L)).

proto("icmp") ->
    1;
proto("tcp") ->
    6;
proto("udp") ->
    17;
proto(Proto) ->
    Proto.
