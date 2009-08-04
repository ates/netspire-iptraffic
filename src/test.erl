-module(test).

-export([calculate/2]).

-define(SUM_PER_MB, 0.05).

calculate(Balance, Octets) ->
    OctetsInMB= Octets / 1024 / 1024,
    Balance - OctetsInMB * ?SUM_PER_MB.

