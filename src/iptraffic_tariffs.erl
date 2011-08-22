-module(iptraffic_tariffs).

-export([init/1, match/2, reload/1]).

-include("netspire.hrl").
-include("iptraffic.hrl").
-include_lib("stdlib/include/qlc.hrl").

-record(plan, {idx, name, class, period, cost}).
-record(class, {name, src_net, src_port, dst_net, dst_port, proto}).

init(File) ->
    ets:new(iptraffic_rules, [named_table, public, ordered_set, {keypos, 2}]),
    ets:new(iptraffic_networks, [named_table, public, ordered_set, {keypos, 2}]),
    load_file(File).

match(Plan, Args) ->
    case match_class(Plan, Args) of
        {ok, Rule} ->
            {ok, {Plan, Rule#plan.cost}};
        Error -> Error
    end.

reload(File) ->
    ets:delete_all_objects(iptraffic_rules),
    ets:delete_all_objects(iptraffic_networks),
    load_file(File).

%%
%% Internal functions
%%
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
    Plans = proplists:get_value(plans, Terms, []),
    Periods = proplists:get_value(periods, Terms, []),
    Classes = proplists:get_value(classes, Terms, []),
    Networks = proplists:get_value(networks, Terms, []),
    read_networks(Networks),
    read_plan(Plans, read_class(Classes), read_time(Periods)).

read_plan([], _, _) ->
    ok;
read_plan([{Name, ClassLinks} | Tail], Classes, Periods) ->
    F = fun({ClassName, PeriodName, Cost}) ->
            P = proplists:get_value(PeriodName, Periods),
            C = lists:keyfind(ClassName, 2, Classes),
            #plan{idx = make_ref(), name = Name, class = C, period = P, cost = Cost}
    end,
    Records = [F(X) || X <- ClassLinks],
    ets:insert(iptraffic_rules, Records),
    read_plan(Tail, Classes, Periods).

%% read and parse 'periods' section
read_time(Periods) ->
    read_time(Periods, []).

read_time([], Acc) ->
    lists:reverse(Acc);
read_time([{Name, Frame} | Tail], Acc) ->
    read_time([{Name, [], Frame} | Tail], Acc);
read_time([{Name, Days, Frame} | Tail], Acc) ->
    [Start, End] = string:tokens(Frame, "-"),
    Acc1 = [{Name, {Days, list_to_seconds(Start), list_to_seconds(End)}} | Acc],
    read_time(Tail, Acc1).

%% read and parse 'classes' section
read_class(Classes) ->
    read_class(Classes, []).

read_class([], Acc) ->
    lists:reverse(Acc);
read_class([{Name, Rules} | Tail], Acc) ->
  read_class(Tail, [prepare_rule(Name, Rules) | Acc]).

prepare_rule(Name, Rule) ->
    SrcRule = proplists:get_value(src, Rule),
    DstRule = proplists:get_value(dst, Rule),
    Proto = proplists:get_value(proto, Rule, any),
    #class{
        name = Name,
        src_net = proplists:get_value(net, SrcRule),
        src_port = proplists:get_value(port, SrcRule, any),
        dst_net = proplists:get_value(net, DstRule),
        dst_port = proplists:get_value(port, DstRule, any),
        proto = proto(Proto)
    }.

read_networks([]) ->
    ok;
read_networks([{Name, list, List} | Tail]) ->
    lists:foreach(fun(N) -> ets:insert(iptraffic_networks, {Name, N}) end, List),
    read_networks(Tail).

match_class(Plan, Args) ->
    QH = qlc:q([Rule || Rule <- ets:table(iptraffic_rules),
                Rule#plan.name =:= Plan, match_rule(Rule, Args)]),
    QC = qlc:cursor(QH),
    Result = case qlc:next_answers(QC, 1) of
        [Rule] -> {ok, Rule};
        _ ->
            {error, no_matching_rules}
    end,
    qlc:delete_cursor(QC),
    Result.

match_network(_, []) -> false;
match_network(IP, [H|T]) ->
    case iplib:in_range(IP, H) of
        true -> true;
        _ -> match_network(IP, T)
    end.

%% returns the list of all addresses which attached to network Name
get_network(Name) ->
    [N || [N] <- ets:match(iptraffic_networks, {Name, '$1'})].

match_rule(any, _) -> true;
match_rule(Rule, Args) ->
    match_time(Rule#plan.period, Args#ipt_args.sec) andalso
    match_network(Args#ipt_args.src_ip, get_network(Rule#plan.class#class.src_net)) andalso
    match_network(Args#ipt_args.dst_ip, get_network(Rule#plan.class#class.dst_net)) andalso
    (Rule#plan.class#class.src_port == Args#ipt_args.src_port orelse Rule#plan.class#class.src_port == any) andalso
    (Rule#plan.class#class.dst_port == Args#ipt_args.dst_port orelse Rule#plan.class#class.dst_port == any) andalso
    (Rule#plan.class#class.proto == Args#ipt_args.proto orelse Rule#plan.class#class.proto == any).

match_time(any, _) -> true;
match_time({[], 0, 0}, _Time) -> true;
match_time({Days, Start, End}, Time) when End >= Start ->
    Time >= Start andalso Time =< End andalso is_today(Days);
match_time({Days, Start, End}, Time) when End < Start ->
    Time >= Start orelse Time =< End andalso is_today(Days).

is_today(Days) when Days =:= [] -> true;
is_today(Days) ->
    DayOfTheWeek = calendar:day_of_the_week(erlang:date()),
    lists:member(DayOfTheWeek, Days).

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
