The iptraffic module provides the abilities to serve the VPM customers.

Features:

* Realtime traffic calculation using [Netflow](http://en.wikipedia.org/wiki/Netflow) v5 as a traffic source
* Supporting the tariff plans
* Restoring sessions after Netspire crash
* Using PostgreSQL database for the storing users, tariff plans, radius attributes and sessions

Configuration:

The following options should be added to the netspire.conf file for integrating the mod_iptraffic with the Netspire system:

{mod_iptraffic, [{tariffs_config, "tariffs.conf"}, {session_timeout, 60}]}
{mod_iptraffic_pgsql, ["hostname", "username", [{database, "databasename"}]]}

The default value of the session_timeout option is 60 seconds and may be ommited.

