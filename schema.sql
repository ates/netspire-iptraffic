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


-- SQL based tariff plans

DROP TABLE iptraffic_directions;
DROP TABLE iptraffic_classes;
DROP TABLE iptraffic_periods;
DROP TABLE iptraffic_plans;

DROP SEQUENCE iptraffic_plans_id_seq CASCADE;
DROP SEQUENCE iptraffic_directions_id_seq CASCADE;
DROP SEQUENCE iptraffic_classes_id_seq CASCADE;
DROP SEQUENCE iptraffic_periods_id_seq CASCADE;

CREATE SEQUENCE iptraffic_plans_id_seq;
CREATE SEQUENCE iptraffic_directions_id_seq;
CREATE SEQUENCE iptraffic_classes_id_seq;
CREATE SEQUENCE iptraffic_periods_id_seq;

CREATE TABLE iptraffic_plans(
    id INTEGER NOT NULL DEFAULT NEXTVAL('iptraffic_plans_id_seq'::regclass) PRIMARY KEY,
    name VARCHAR NOT NULL);

CREATE TABLE iptraffic_periods(
    id INTEGER NOT NULL DEFAULT NEXTVAL('iptraffic_periods_id_seq'::regclass) PRIMARY KEY,
    name VARCHAR NOT NULL,
    hours VARCHAR DEFAULT '00:00:00-23:59:59',
    days VARCHAR DEFAULT '1,2,3,4,5,6,7');

CREATE TABLE iptraffic_classes(
    id INTEGER NOT NULL DEFAULT NEXTVAL('iptraffic_classes_id_seq'::regclass) PRIMARY KEY,
    period_id INTEGER NOT NULL REFERENCES iptraffic_periods(id),
    name VARCHAR NOT NULL,
    src INET NOT NULL,
    dst INET NOT NULL,
    src_port INTEGER,
    dst_port INTEGER,
    proto VARCHAR);

CREATE TABLE iptraffic_directions(
    id INTEGER NOT NULL DEFAULT NEXTVAL('iptraffic_directions_id_seq'::regclass) PRIMARY KEY,
    plan_id INTEGER NOT NULL REFERENCES iptraffic_plans(id),
    class_id INTEGER NOT NULL REFERENCES iptraffic_classes(id),
    cost NUMERIC(20,10) NOT NULL);

CREATE OR REPLACE FUNCTION iptraffic_load_tariffs() RETURNS TABLE(
    plan_name VARCHAR,
    name VARCHAR,
    src INET,
    dst INET,
    src_port INTEGER,
    dst_port INTEGER,
    proto VARCHAR,
    hours VARCHAR,
    days VARCHAR,
    cost FLOAT) AS $$
BEGIN
    RETURN QUERY SELECT DISTINCT plan.name, class.name, class.src, class.dst, class.src_port, class.dst_port, class.proto, period.hours, period.days, dir.cost::FLOAT
    FROM iptraffic_directions dir 
    LEFT OUTER JOIN iptraffic_classes class ON dir.class_id = class.id
    LEFT OUTER JOIN iptraffic_periods period ON class.period_id = period.id
    LEFT OUTER JOIN iptraffic_plans plan ON dir.plan_id = plan.id ORDER BY 1;
END;
$$ LANGUAGE plpgsql;

-- Fill up tariffs plans for testing purpose

-- Plans
INSERT INTO iptraffic_plans(name) VALUES('Ultimate');
INSERT INTO iptraffic_plans(name) VALUES('Daylight');
INSERT INTO iptraffic_plans(name) VALUES('Unlimited'); -- 0 cost to all directions

-- Periods
INSERT INTO iptraffic_periods(name) VALUES('All Day');
INSERT INTO iptraffic_periods(name, hours) VALUES('Night', '22:00:00-08:00:00');
INSERT INTO iptraffic_periods(name, hours) VALUES('Day', '08:00:00-21:59:59');

-- Classes
INSERT INTO iptraffic_classes(period_id, name, src, dst) VALUES(
    1, 'Local', '10.10.0.0/16', '10.10.0.0/16');

INSERT INTO iptraffic_classes(period_id, name, src, dst, src_port, proto) VALUES(
    3, 'Incoming HTTP Day', '0.0.0.0/0', '10.10.0.0/16', 80, 'tcp');

INSERT INTO iptraffic_classes(period_id, name, src, dst, src_port, proto) VALUES(
    2, 'Incoming HTTP Night', '0.0.0.0/0', '10.10.0.0/16', 80, 'tcp');

INSERT INTO iptraffic_classes(period_id, name, src, dst) VALUES(
    3, 'Incoming Day', '0.0.0.0/0', '10.10.0.0/16');

INSERT INTO iptraffic_classes(period_id, name, src, dst) VALUES(
    2, 'Incoming Night', '0.0.0.0/0', '10.10.0.0/16');

INSERT INTO iptraffic_classes(period_id, name, src, dst) VALUES(
    3, 'Outgoing Day', '10.10.0.0/16', '0.0.0.0/0');

INSERT INTO iptraffic_classes(period_id, name, src, dst) VALUES(
    1, 'Outgoing', '10.10.0.0/16', '0.0.0.0/0');

INSERT INTO iptraffic_classes(period_id, name, src, dst) VALUES(
    1, 'FREE', '0.0.0.0/0', '0.0.0.0/0');

-- Directions
-- For Ultimate tariff
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(1, 2, 1);
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(1, 3, 1);
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(1, 4, 1);
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(1, 4, 1);
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(1, 6, 5);
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(1, 7, 0);
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(1, 2, 1);
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(1, 1, 0);

-- For Daylight tariff
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(2, 2, 0.5);
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(2, 3, 0.7);
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(2, 4, 0.5);
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(2, 4, 2);
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(2, 7, 0);
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(2, 1, 0);

-- For Unlimited tariff
INSERT INTO iptraffic_directions(plan_id, class_id, cost) VALUES(3, 8, 0);

