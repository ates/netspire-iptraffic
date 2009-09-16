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
        SELECT t0.password, t0.balance::FLOAT, t3.code, t2.name, t1.value FROM accounts t0
            -- Retrieve all personal RADIUS attributes
            LEFT OUTER JOIN plans t3 ON (t0.plan_id = t3.id)
            LEFT OUTER JOIN assigned_radius_replies t1
                ON ((t1.target_id = t0.id AND t1.target_type = 'Account') OR
                -- Retrieve all personal RADIUS attributes from assigned groups
                --(t1.account_id IN
                --    (SELECT t0.radius_reply_group_id FROM assigned_radius_reply_groups t0
                --        JOIN accounts t1 ON t1.id = t0.account_id)
                ---            AND t1.attached_type = 'RadiusReplyGroup') OR
              -- Retrieve all tariff related RADIUS attributes
                (t1.target_id = t0.plan_id AND t1.target_type = 'Tariff'))
            LEFT OUTER JOIN radius_replies t2 on t2.id = t1.radius_reply_id
        WHERE t0.login ILIKE $1 AND t0.plan_id IS NOT NULL AND t0.active = TRUE
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
    UPDATE radius_sessions SET finished_at = $3 WHERE sid = $2 AND finished_at IS NULL AND account_id = (SELECT id FROM accounts WHERE login ILIKE $1);
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
    UPDATE accounts SET balance = $4::FLOAT WHERE id = _acct_id;
    LOOP 
        UPDATE netflow_session_data SET octets_in = $2, octets_out = $3 WHERE sid_id = _sid_id;
        IF found THEN
            RETURN 1;
        END IF;
        BEGIN
            INSERT INTO netflow_session_data(sid_id, octets_in, octets_out) VALUES(_sid_id, $2, $3);
            RETURN 0;
        END;
    END LOOP;
END;
$$ LANGUAGE plpgsql;
