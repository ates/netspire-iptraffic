-module(ultimate).

-export([calculate/2]).

-define(SUM_FOR_MB, 0.05).

calculate(_Direction, Octets) ->
    OctetsInMB= Octets / 1024 / 1024,
    OctetsInMB * ?SUM_FOR_MB.

