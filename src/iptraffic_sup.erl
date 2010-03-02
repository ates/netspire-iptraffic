-module(iptraffic_sup).
-behaviour(supervisor).

%% API
-export([start/1, start_link/1, stop/0, init_session/1, resume_all/0]).

%% supervisor callbacks
-export([init/1]).

-include("netspire.hrl").
-include("iptraffic.hrl").

start(Options) ->
    init_mnesia(),
    ChildSpec = {?MODULE,
                 {?MODULE, start_link, [Options]},
                 transient,
                 infinity,
                 supervisor,
                 [iptraffic_sup]
                },
    supervisor:start_child(netspire_sup, ChildSpec),
    {ok, Count} = iptraffic_sup:resume_all(),
    ?INFO_MSG("~p previously started session(s) has been resumed~n", [Count]).

stop() ->
    supervisor:terminate_child(netspire_sup, iptraffic_sup),
    supervisor:delete_child(netspire_sup, iptraffic_sup).

init_mnesia() ->
    mnesia:create_table(ipt_session, [{disc_copies, [node()]}, {index, [uuid]},
        {attributes, record_info(fields, ipt_session)}]),
    mnesia:add_table_copy(ipt_session, node(), disc_copies).

start_link(Options) ->
    supervisor:start_link({local, ?MODULE}, ?MODULE, [Options]).

init([Options]) ->
    ChildSpec = {mod_iptraffic,
                 {mod_iptraffic, start_link, [Options]},
                 transient,
                 30000,
                 worker,
                 [mod_iptraffic]
                },
    {ok, {{one_for_one, 100, 1}, [ChildSpec]}}.

init_session(UserName) ->
    init_session(UserName, uuid_to_string(uuid_v4())).

init_session(UserName, UUID) ->
    ChildSpec = {{session, UserName},
                 {iptraffic_session, start_link, [UUID]},
                 transient,
                 3000,
                 worker,
                 [iptraffic_session]
                },
    supervisor:start_child(?MODULE, ChildSpec).

resume_all() ->
    Key = mnesia:dirty_first(ipt_session),
    resume_session(Key, 0).

resume_session('$end_of_table', Count) ->
    {ok, Count};
resume_session(Key, Count) ->
    [State] = mnesia:dirty_read(ipt_session, Key),
    case is_process_alive(State#ipt_session.pid) of
        false ->
            #ipt_session{username = UserName, uuid = UUID} = State,
            init_session(UserName, UUID),
            Next = mnesia:dirty_next(ipt_session, Key),
            resume_session(Next, Count + 1);
        true ->
            Next = mnesia:dirty_next(ipt_session, Key),
            resume_session(Next, Count)
    end.

uuid_v4() ->
    % round(math:pow(2, N)) where N = 48, 12, 32, 30
    R1 = random:uniform(281474976710656) - 1,
    R2 = random:uniform(4096) - 1,
    R3 = random:uniform(4294967296) - 1,
    R4 = random:uniform(1073741824) - 1,
    <<R1:48, 4:4, R2:12, 2:2, R3:32, R4: 30>>.

uuid_to_string(U) ->
    Parts = uuid_get_parts(U),
    lists:flatten(io_lib:format("~8.16.0b-~4.16.0b-~4.16.0b-~2.16.0b~2.16.0b-~12.16.0b", Parts)).

uuid_get_parts(<<TL:32, TM:16, THV:16, CSR:8, CSL:8, N:48>>) ->
    [TL, TM, THV, CSR, CSL, N].
