CREATE SEQUENCE users_id_seq START 1;

CREATE TABLE users(
    id INTEGER NOT NULL DEFAULT NEXTVAL('users_id_seq'::text),
    login VARCHAR(64) NOT NULL,
    password VARCHAR(64) NOT NULL,
    full_name VARCHAR(128) NOT NULL,
    passport TEXT,
    address TEXT,
    inn VARCHAR(32),
    phones TEXT,
    balance NUMERIC(12,2) NOT NULL DEFAULT 0,
    contract_id VARCHAR(32) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE SEQUENCE accounts_id_seq START 1;

CREATE TABLE accounts(
    id INTEGER NOT NULL DEFAULT NEXTVAL('accounts_id_seq'::text),
    user_id INTEGER NOT NULL,
    login VARCHAR(64) NOT NULL,
    password VARCHAR(64) NOT NULL,
    ip_addr INET,
    mac_addr MACADDR,
    tariff_id INTEGER NOT NULL,
    active BOOLEAN DEFAULT FALSE,
    inactive_reason TEXT,
    balance NUMERIC(20,10) NOT NULL DEFAULT 0,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE SEQUENCE tariffs_id_seq START 1;

CREATE TABLE tariffs(
    id INTEGER NOT NULL DEFAULT NEXTVAL('tariffs_id_seq'::text),
    code VARCHAR(32) NOT NULL,
    name VARCHAR(128) NOT NULL,
    active BOOLEAN DEFAULT TRUE,
    description TEXT,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE SEQUENCE sessions_id_seq START 1;

CREATE TABLE sessions(
    id INTEGER NOT NULL DEFAULT NEXTVAL('sessions_id_seq'::text),
    sid VARCHAR(128) NOT NULL,
    account_id INTEGER NOT NULL,
    ip_addr INET NOT NULL,
    started_at TIMESTAMP WITHOUT TIME ZONE,
    finished_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE SEQUENCE radius_attributes_id_seq START 1;

CREATE TABLE radius_attributes(
    id INTEGER NOT NULL DEFAULT NEXTVAL('radius_attributes_id_seq'::text),
    name VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

CREATE SEQUENCE assigned_radius_replies_id_seq START 1;

CREATE TABLE assigned_radius_replies(
    id INTEGER NOT NULL DEFAULT NEXTVAL('assigned_radius_replies_id_seq'::text),
    attachee_id INTEGER NOT NULL,
    attachee_type VARCHAR NOT NULL,
    radius_attribute_id INTEGER NOT NULL,
    value VARCHAR(128) NOT NULL,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

--CREATE SEQUENCE assigned_radius_reply_groups_id_seq START 1;

--CREATE TABLE assigned_radius_reply_groups(
--    id INTEGER NOT NULL DEFAULT NEXTVAL('assigned_radius_reply_groups_id_seq'::text),
--    account_id INTEGER NOT NULL,
--    radius_reply_group_id INTEGER NOT NULL,
--    created_at TIMESTAMP WITHOUT TIME ZONE,
--    updated_at TIMESTAMP WITHOUT TIME ZONE
--);

--CREATE SEQUENCE radius_reply_groups_id_seq START 1;

--CREATE TABLE radius_reply_groups(
--    id INTEGER NOT NULL DEFAULT NEXTVAL('radius_reply_groups_id_seq'::text),
--    name VARCHAR(64) NOT NULL,
--    created_at TIMESTAMP WITHOUT TIME ZONE,
--    updated_at TIMESTAMP WITHOUT TIME ZONE
--);

