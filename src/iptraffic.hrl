-record(ipt_args, {sec, src_ip, dst_ip, src_port, dst_port, proto, octets, dir}).

-record(ipt_session, {
        sid,
        uuid,
        ip,
        username,
        status,
        started_at,
        expires_at,
        finished_at,
        pid,
        node,
        nas_spec,
        disc_req_sent,
        data
    }).

-record(ipt_data, {
        plan,
        amount = 0.0,
        balance = 0.0,
        octets_in = 0,
        octets_out = 0
    }).
