CREATE OR REPLACE FUNCTION auth(VARCHAR) RETURNS SETOF auth_result AS $$
DECLARE
    result RECORD;
BEGIN
    FOR result IN
        SELECT t0.password, t0.ip_addr, t2.vendor_id, t2.attr_id, t2.name, t1.value FROM accounts t0
            -- Retrieve all personal RADIUS attributes
            LEFT OUTER JOIN assigned_radius_replies t1
                ON ((t1.account_id = t0.id AND t1.attached_type = 'Account') OR
                -- Retrieve all personal RADIUS attributes from assigned groups
                (t1.account_id IN
                    (SELECT t0.radius_reply_group_id FROM assigned_radius_reply_groups t0
                        JOIN accounts t1 ON t1.id = t0.account_id)
                            AND t1.attached_type = 'RadiusReplyGroup') OR
                -- Retrieve all tariff related RADIUS attributes
                (t1.account_id = t0.tariff_id AND t1.attached_type = 'Tariff'))
            LEFT OUTER JOIN radius_attributes t2 on t2.id = t1.radius_attribute_id
        WHERE t0.login ILIKE $1 AND t0.tariff_id IS NOT NULL AND t0.active = TRUE
    LOOP
        RETURN NEXT result;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION start_session(VARCHAR, VARCHAR, INET, TIMESTAMP) RETURNS start_session_result AS $$
DECLARE
    result start_session_result;
BEGIN
    SELECT a.id, t.code, a.balance INTO result  FROM tariffs t, accounts a
        WHERE a.tariff_id = t.id AND a.login ILIKE $1;
    INSERT INTO sessions(account_id, sid, ip_addr, started_at) VALUES (result.account_id, $2, $3, $4);

    RETURN result;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION stop_session(VARCHAR, BIGINT, BIGINT, VARCHAR, INTEGER, TIMESTAMP) RETURNS INTEGER AS $$
DECLARE
    result INTEGER;
BEGIN
    UPDATE sessions SET octets_in = $2, octets_out = $3, finished_at = $6 WHERE sid = $1 AND finished_at IS NULL;
    UPDATE accounts SET balance = $4::FLOAT WHERE id = $5;
    UPDATE accounts SET active = 'false', inactive_reason = 'Negative balance' WHERE id = $5 and $4::FLOAT <= 0;
    GET DIAGNOSTICS result = ROW_COUNT;
    RETURN result;
END;
$$ LANGUAGE plpgsql;

