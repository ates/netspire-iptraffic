-module(ultimate).

-export([calculate/3]).

-define(SUM_FOR_MB, 0.05).

calculate(Balance, _Direction, Octets) ->
    OctetsInMB= Octets / 1024 / 1024,
    Amount = OctetsInMB * ?SUM_FOR_MB,
    NewBalance = Balance - Amount,
    {ok, NewBalance, Amount}.

