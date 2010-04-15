CREATE LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION auth(VARCHAR) RETURNS TABLE(
	password VARCHAR,
	balance FLOAT,
	plan_code VARCHAR,
	name VARCHAR,
	value VARCHAR) AS $$
BEGIN
    RETURN QUERY SELECT t0.password, t0.balance::FLOAT, t1.code, t3.name, t2.value FROM accounts t0
        LEFT OUTER JOIN plans t1 ON (t0.plan_id = t1.id)
        LEFT OUTER JOIN assigned_radius_replies t2
            ON (t2.target_id = t0.id AND t2.target_type = 'Account')
        LEFT OUTER JOIN radius_replies t3 ON t3.id = t2.radius_reply_id
    WHERE t0.login = $1 AND (t0.balance IS NOT NULL AND t0.balance > 0) AND t0.plan_id IS NOT NULL AND t0.active = TRUE;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION iptraffic_start_session(VARCHAR, VARCHAR, VARCHAR, TIMESTAMP) RETURNS VOID AS $$
DECLARE
    acct_id INTEGER;
BEGIN
    SELECT id INTO acct_id FROM accounts WHERE login = $1;
    INSERT INTO iptraffic_sessions(account_id, ip, sid, started_at) VALUES (acct_id, $2, $3, $4);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION iptraffic_stop_session(VARCHAR, VARCHAR, TIMESTAMP, BIGINT, BIGINT, FLOAT, BOOLEAN) RETURNS INTEGER AS $$
DECLARE
    acct_id INTEGER;
    session_id INTEGER;
BEGIN
    SELECT id INTO acct_id FROM accounts WHERE login = $1;
    SELECT id INTO session_id FROM iptraffic_sessions WHERE sid = $2 AND finished_at IS NULL AND account_id = acct_id LIMIT 1;
    -- Don't update balance when session already closed
    IF FOUND THEN
        UPDATE accounts SET balance = balance - $6 WHERE id = acct_id;
        UPDATE iptraffic_sessions SET octets_in = $4, octets_out = $5, amount = $6, finished_at = $3, expired = $7
            WHERE id = session_id;
        RETURN 1;
    ELSE
        RETURN 0;
    END IF;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION iptraffic_sync_session(VARCHAR, VARCHAR, TIMESTAMP, BIGINT, BIGINT, FLOAT) RETURNS INTEGER AS $$
BEGIN
    UPDATE iptraffic_sessions SET octets_in = $4, octets_out = $5, updated_at = $3, amount = $6
        WHERE sid = $2 AND account_id = (SELECT id FROM accounts WHERE login = $1);
    IF FOUND THEN
        RETURN 1;
    ELSE
        RETURN 0;
    END IF;
END;
$$ LANGUAGE plpgsql;
