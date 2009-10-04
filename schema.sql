CREATE LANGUAGE plpgsql;

CREATE TYPE auth_result AS (
    password VARCHAR,
    balance FLOAT,
    plan_code VARCHAR,
    name VARCHAR,
    value VARCHAR
);

CREATE SEQUENCE iptraffic_sessions_id_seq START 1;

CREATE TABLE iptraffic_sessions(
    id INTEGER NOT NULL DEFAULT NEXTVAL('iptraffic_sessions_id_seq'::text),
    account_id INTEGER NOT NULL,
    sid VARCHAR(255),
    octets_in BIGINT DEFAULT 0,
    octets_out BIGINT DEFAULT 0,
    amount NUMERIC(20, 10) DEFAULT 0,
    started_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE,
    finished_at TIMESTAMP WITHOUT TIME ZONE,
    expired BOOLEAN

);

CREATE OR REPLACE FUNCTION auth(VARCHAR) RETURNS SETOF auth_result AS $$
DECLARE
    result RECORD;
BEGIN
    FOR result IN
        SELECT t0.password, t0.balance::FLOAT, t1.code, t3.name, t2.value FROM accounts t0
            LEFT OUTER JOIN plans t1 ON (t0.plan_id = t1.id)
            -- Retrieve all personal RADIUS attributes
            LEFT OUTER JOIN assigned_radius_replies t2
                ON (t2.target_id = t0.id AND t2.target_type = 'Account')
            LEFT OUTER JOIN radius_replies t3 on t3.id = t2.radius_reply_id
        WHERE t0.login ILIKE $1 AND (t0.balance IS NOT NULL AND t0.balance > 0) AND t0.plan_id IS NOT NULL AND t0.active = TRUE
    LOOP
        RETURN NEXT result;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION iptraffic_start_session(VARCHAR, VARCHAR, TIMESTAMP) RETURNS VOID AS $$
DECLARE
    acct_id integer;
BEGIN
    SELECT id INTO acct_id FROM accounts WHERE login ILIKE $1;
    INSERT INTO iptraffic_sessions(account_id, sid, started_at) VALUES (acct_id, $2, $3);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION iptraffic_stop_session(VARCHAR, VARCHAR, TIMESTAMP, BIGINT, BIGINT, FLOAT, BOOLEAN) RETURNS VOID AS $$
DECLARE
    _acct_id INTEGER;
BEGIN
    SELECT account_id INTO _acct_id FROM iptraffic_sessions WHERE sid = $2;
    PERFORM iptraffic_sync_session($1, $2, $3, $4, $5, $6);
    UPDATE accounts SET balance = balance - $6 WHERE id = _acct_id;
    UPDATE iptraffic_sessions SET finished_at = $3, expired = $7 WHERE sid = $2 AND finished_at IS NULL AND account_id = (SELECT id FROM accounts WHERE login ILIKE $1);
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION iptraffic_sync_session(VARCHAR, VARCHAR, TIMESTAMP, BIGINT, BIGINT, FLOAT) RETURNS INTEGER AS $$
DECLARE
    _id INTEGER;
BEGIN
    SELECT id INTO _id FROM iptraffic_sessions WHERE sid = $2;
    UPDATE iptraffic_sessions SET updated_at = $3 WHERE sid = $2 AND account_id = (SELECT id FROM accounts WHERE login ILIKE $1);
    LOOP
        UPDATE iptraffic_sessions SET octets_in = $4, octets_out = $5, updated_at = $3, amount = $6 WHERE sid = $2 AND account_id = _id;
        if found THEN
            RETURN 1;
        END IF;
        BEGIN
            INSERT INTO iptraffic_sessions(sid, octets_in, octets_out, amount, created_at, updated_at) VALUES($2, $4, $5, $6, $3, $3);
            RETURN 0;
        END;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

