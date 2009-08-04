CREATE SEQUENCE accounting_id_seq START 1;

CREATE TABLE accounting(
    id INTEGER NOT NULL DEFAULT NEXTVAL('accounting_id_seq'::text),
    sid_id INTEGER NOT NULL,
    octets_in BIGINT DEFAULT 0,
    octets_out BIGINT DEFAULT 0,
    created_at TIMESTAMP WITHOUT TIME ZONE,
    updated_at TIMESTAMP WITHOUT TIME ZONE
);

create or replace function sync_accounting(VARCHAR, BIGINT, BIGINT, VARCHAR) RETURNS INTEGER AS $$
declare
    _sid_id integer;
    _acct_id integer;
begin
    select id into _sid_id from sessions where sid = $1;
    select account_id into _acct_id from sessions where sid = $1;
    update accounts set balance = $4::FLOAT where id = _acct_id;
    loop
        update accounting set octets_in = $2, octets_out = $3, where sid_id = _sid_id;
        if found then
            return 1;
        end if;
        begin
            insert into accounting(sid_id, octets_in, octets_out) values(_sid_id, $2, $3);
            return 0;
        end;
    end loop;
end;
$$ LANGUAGE plpgsql;
