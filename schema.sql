CREATE LANGUAGE plpgsql;

CREATE TYPE auth_result AS (
    password VARCHAR,
    balance FLOAT,
    plan_code VARCHAR,
    name VARCHAR,
    value VARCHAR
);

CREATE SEQUENCE netflow_session_data_id_seq START 1;

CREATE TABLE netflow_session_data(
    id INTEGER NOT NULL DEFAULT NEXTVAL('netflow_session_data_id_seq'::text),
    sid_id INTEGER NOT NULL,
    octets_in BIGINT DEFAULT 0,
    octets_out BIGINT DEFAULT 0,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
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
        WHERE t0.login ILIKE $1 AND t0.balance IS NOT NULL AND t0.plan_id IS NOT NULL AND t0.active = TRUE
    LOOP
        RETURN NEXT result;
    END LOOP;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION start_session(VARCHAR, VARCHAR, TIMESTAMP) RETURNS  BOOLEAN AS $$
DECLARE
    acct_id integer;
BEGIN
    SELECT id INTO acct_id  FROM accounts WHERE login ILIKE $1;
    INSERT INTO radius_sessions(account_id, sid, started_at) VALUES (acct_id, $2, $3);

    RETURN TRUE;
END;
$$ LANGUAGE plpgsql;

CREATE OR REPLACE FUNCTION stop_session(VARCHAR, VARCHAR, TIMESTAMP) RETURNS INTEGER AS $$
DECLARE
    result INTEGER;
BEGIN
    UPDATE radius_sessions SET finished_at = $3, updated_at = $3 WHERE sid = $2 AND finished_at IS NULL AND account_id = (SELECT id FROM accounts WHERE login ILIKE $1);
    GET DIAGNOSTICS result = ROW_COUNT;
    RETURN result;
END;
$$ LANGUAGE plpgsql; 

CREATE OR REPLACE FUNCTION sync_session_data(VARCHAR, BIGINT, BIGINT, VARCHAR) RETURNS INTEGER AS $$
DECLARE
    _sid_id INTEGER;
    _acct_id INTEGER;
BEGIN
    SELECT id INTO _sid_id FROM radius_sessions WHERE sid = $1;
    SELECT account_id INTO _acct_id FROM radius_sessions WHERE sid = $1;
    UPDATE accounts SET balance = balance - $4::FLOAT WHERE id = _acct_id;
    UPDATE radius_sessions SET updated_at = LOCALTIMESTAMP;
    LOOP 
        UPDATE netflow_session_data SET octets_in = $2, octets_out = $3, updated_at = LOCALTIMESTAMP WHERE sid_id = _sid_id;
        IF found THEN
            RETURN 1;
        END IF;
        BEGIN
            INSERT INTO netflow_session_data(sid_id, octets_in, octets_out, created_at, updated_at) VALUES(_sid_id, $2, $3, LOCALTIMESTAMP, LOCALTIMESTAMP);
            RETURN 0;
        END;
    END LOOP;
END;
$$ LANGUAGE plpgsql;
