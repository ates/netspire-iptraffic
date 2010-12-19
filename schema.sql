-- Drop schema objects

DROP FUNCTION IF EXISTS auth(VARCHAR);
DROP FUNCTION IF EXISTS iptraffic_start_session(VARCHAR, VARCHAR, VARCHAR, TIMESTAMP);
DROP FUNCTION IF EXISTS iptraffic_stop_session(VARCHAR, VARCHAR, TIMESTAMP, BIGINT, BIGINT, FLOAT, BOOLEAN);
DROP FUNCTION IF EXISTS iptraffic_sync_session(VARCHAR, VARCHAR, TIMESTAMP, BIGINT, BIGINT, FLOAT);

DROP TABLE IF EXISTS iptraffic_sessions;
DROP TABLE IF EXISTS assigned_radius_replies;
DROP TABLE IF EXISTS radius_replies;
DROP TABLE IF EXISTS accounts;
DROP TABLE IF EXISTS plans;
DROP TABLE IF EXISTS users;

DROP SEQUENCE IF EXISTS iptraffic_sessions_id_seq CASCADE;
DROP SEQUENCE IF EXISTS assigned_radius_replies_id_seq CASCADE;
DROP SEQUENCE IF EXISTS radius_replies_id_seq CASCADE;
DROP SEQUENCE IF EXISTS accounts_id_seq CASCADE;
DROP SEQUENCE IF EXISTS plans_id_seq CASCADE;
DROP SEQUENCE IF EXISTS users_id_seq CASCADE;

DROP LANGUAGE IF EXISTS plpgsql;

-- Create schema objects
CREATE LANGUAGE plpgsql;

CREATE SEQUENCE users_id_seq;
CREATE SEQUENCE accounts_id_seq;
CREATE SEQUENCE plans_id_seq;
CREATE SEQUENCE radius_replies_id_seq;
CREATE SEQUENCE assigned_radius_replies_id_seq;
CREATE SEQUENCE iptraffic_sessions_id_seq;

CREATE TABLE users(
    id INTEGER NOT NULL DEFAULT NEXTVAL('users_id_seq') PRIMARY KEY,
    login VARCHAR(128) NOT NULL,
    password VARCHAR(128) NOT NULL,
    email VARCHAR(128),
    balance NUMERIC(20,10) DEFAULT 0.0,
    active BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE plans(
    id INTEGER NOT NULL DEFAULT NEXTVAL('plans_id_seq') PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    code VARCHAR(128) NOT NULL,
    fee NUMERIC(20, 10) DEFAULT 0,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE accounts(
    id INTEGER NOT NULL DEFAULT NEXTVAL('accounts_id_seq') PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES users(id),
    plan_id INTEGER NOT NULL REFERENCES plans(id),
    login VARCHAR(128) NOT NULL,
    password VARCHAR(128) NOT NULL,
    balance NUMERIC(20,10) DEFAULT 0.0,
    active BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE radius_replies(
    id INTEGER NOT NULL DEFAULT NEXTVAL('radius_replies_id_seq') PRIMARY KEY,
    name VARCHAR(128) NOT NULL,
    description TEXT,
    active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE assigned_radius_replies(
    id INTEGER NOT NULL DEFAULT NEXTVAL('assigned_radius_replies_id_seq') PRIMARY KEY,
    target_id INTEGER NOT NULL,
    target_type VARCHAR(128) NOT NULL,
    radius_reply_id INTEGER NOT NULL REFERENCES radius_replies(id),
    value VARCHAR(128) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE TABLE iptraffic_sessions(
    id INTEGER NOT NULL DEFAULT NEXTVAL('iptraffic_sessions_id_seq') PRIMARY KEY,
    account_id INTEGER NOT NULL REFERENCES accounts(id),
    sid VARCHAR(128) NOT NULL,
    ip VARCHAR(128) NOT NULL,
    octets_in BIGINT DEFAULT 0,
    octets_out BIGINT DEFAULT 0,
    amount NUMERIC(20,10) DEFAULT 0.0,
    started_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE,
    finished_at TIMESTAMP WITHOUT TIME ZONE,
    expired BOOLEAN
);

CREATE OR REPLACE FUNCTION auth(VARCHAR) RETURNS TABLE(
    password VARCHAR,
    balance FLOAT,
    plan_code VARCHAR,
    name VARCHAR,
    value VARCHAR) AS $$
BEGIN
    RETURN QUERY SELECT t0.password, t0.balance::FLOAT, t1.code, t3.name, t2.value FROM accounts t0
        LEFT OUTER JOIN plans t1 ON t0.plan_id = t1.id
        LEFT OUTER JOIN assigned_radius_replies t2
            ON (t2.target_id = t0.id AND t2.target_type = 'Account') OR (t2.target_id = t0.plan_id AND t2.target_type = 'Plan')
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

-- Fill up schema for testing purpose

INSERT INTO users(login, password, email, balance, active) VALUES('joel', 'secret', 'joel@example.com', 100, TRUE);

INSERT INTO plans(name, code) VALUES('Standard traffic plan', 'Standard');
INSERT INTO plans(name, code) VALUES('Unlimited 512 Kbit', 'Unlimited 512');
INSERT INTO plans(name, code) VALUES('Unlimited 1024 kbit ', 'Unlimited 1024');

INSERT INTO accounts(user_id, plan_id, login, password, balance, active) VALUES(1, 1, 'joel', 'secret', 100, TRUE);

INSERT INTO radius_replies(name, description) VALUES('Acct-Interim-Interval', 'This attribute indicates the number of seconds between each interim update in seconds for this specific session.');
INSERT INTO radius_replies(name, description) VALUES('Framed-IP-Address', 'This Attribute indicates the address to be configured for the user.');
INSERT INTO radius_replies(name, description) VALUES('Service-Type', 'This Attribute indicates the type of service the user has requested, or the type of service to be provided.');
INSERT INTO radius_replies(name, description) VALUES('Framed-Protocol', 'This Attribute indicates the framing to be used for framed access.');
INSERT INTO radius_replies(name, description) VALUES('Netspire-Framed-Pool', 'This Attribute indicates the pool of IP addresses that need to use.');
INSERT INTO radius_replies(name, description) VALUES('Netspire-Upstream-Speed-Limit', 'This Attribute indicates the UpStream speed limit.');
INSERT INTO radius_replies(name, description) VALUES('Netspire-Downstream-Speed-Limit', 'This Attribute indicates the DownStream speed limit.');

INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(1, 'Account', 1, '65');
INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(1, 'Account', 3, '2'); -- value is Framed-User
INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(1, 'Account', 4, '1'); -- value is PPP

-- Tariff's radius replies
INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(2, 'Plan', 7, '512');
INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(2, 'Plan', 6, '64');
INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(3, 'Plan', 7, '1024');
INSERT INTO assigned_radius_replies(target_id, target_type, radius_reply_id, value) VALUES(3, 'Plan', 6, '128');
