The IPTraffic module for serving VPN customers
==============================================

Features:

* RADIUS authentication
* Realtime traffic calculation using [Netflow](http://en.wikipedia.org/wiki/Netflow) v5 as a traffic source
* Flexible tariffs (subnet rules, time rules)
* Using PostgreSQL database for the storing users, tariff plans, RADIUS attributes and sessions
* It's easy to add your own backends

Configuration
-------------

The following modules should be added to the netspire.conf file:

    {mod_iptraffic, [{tariffs_config, "tariffs.conf"}, {session_timeout, 60}]}
    {mod_iptraffic_pgsql, ["hostname", "username", "password", [{database, "dbname"}, {pool_size, 5}]]}

The default value of the **session_timeout** option is 60 seconds and may be ommited.

You MUST set **Acct-Interim-Interval** RADIUS attribute for client. This attribute is required to prolong session and it's value MUST be significantly less than **session_timeout**.
Note that if Netspire does not receiving interim updates from NAS via RADIUS, sessions will be marked as *expired* and closed, regardless of real state on NAS.
