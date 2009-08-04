CREATE LANGUAGE plpgsql;

CREATE TYPE auth_result AS (
    password VARCHAR,
    ip_addr INET,
    name VARCHAR,
    value VARCHAR
);

CREATE TYPE start_session_result AS (
    account_id INTEGER,
    tariff_code VARCHAR,
    balance FLOAT
);
