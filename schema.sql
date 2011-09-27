DROP FUNCTION IF EXISTS iptraffic_start_session(VARCHAR, VARCHAR, VARCHAR, TIMESTAMP);
DROP FUNCTION IF EXISTS iptraffic_stop_session(VARCHAR, VARCHAR, TIMESTAMP, BIGINT, BIGINT, FLOAT, BOOLEAN);
DROP FUNCTION IF EXISTS iptraffic_sync_session(VARCHAR, VARCHAR, TIMESTAMP, BIGINT, BIGINT, FLOAT);

CREATE OR REPLACE FUNCTION iptraffic_start_session(VARCHAR, VARCHAR, VARCHAR, TIMESTAMP) RETURNS VOID AS $$
DECLARE
    acct_id INTEGER;
BEGIN
    SELECT account_id INTO acct_id FROM iptraffic_access_links WHERE login = $1;
    INSERT INTO iptraffic_sessions(account_id, ip, sid, started_at) VALUES (acct_id, $2, $3, $4);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION iptraffic_stop_session(VARCHAR, VARCHAR, TIMESTAMP, BIGINT, BIGINT, FLOAT, BOOLEAN) RETURNS VOID AS $$
DECLARE
    acct_id INTEGER;
    session_id INTEGER;
BEGIN
    SELECT id INTO acct_id FROM accounts WHERE login = $1;
    SELECT id INTO session_id FROM iptraffic_sessions WHERE sid = $2 AND finished_at IS NULL AND account_id = acct_id LIMIT 1;
    UPDATE iptraffic_sessions SET octets_in = $4, octets_out = $5, amount = $6, finished_at = $3, expired = $7 WHERE id = session_id;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION iptraffic_sync_session(VARCHAR, VARCHAR, TIMESTAMP, BIGINT, BIGINT, FLOAT) RETURNS VOID AS $$
BEGIN
    UPDATE iptraffic_sessions SET octets_in = $4, octets_out = $5, updated_at = $3, amount = $6
        WHERE sid = $2 AND account_id = (SELECT account_id FROM iptraffic_access_links WHERE login = $1);
END;
$$ LANGUAGE plpgsql;
