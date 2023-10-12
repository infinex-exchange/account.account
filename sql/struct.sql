CREATE ROLE "account.account" LOGIN PASSWORD 'password';

create table users(
    uid bigserial not null primary key,
    email varchar(255) not null,
    password varchar(255) not null,
    verified boolean not null default false,
    register_time timestamptz not null default current_timestamp
);

GRANT SELECT, UPDATE, INSERT ON users TO "account.account";
GRANT SELECT, USAGE ON SEQUENCE users_uid_seq TO "account.account";

create table sessions(
    sid bigserial not null primary key,
    uid bigint not null,
    api_key varchar(64) not null,
    origin varchar(32) not null,
    wa_remember boolean null,
    wa_lastact timestamptz null,
    wa_browser varchar(255) null,
    wa_os varchar(255) null,
    wa_device varchar(32) null,
    ak_description varchar(255) null,
    
    foreign key(uid) references users(uid)
);

GRANT SELECT, UPDATE, INSERT, DELETE ON sessions TO "account.account";
GRANT SELECT, USAGE ON SEQUENCE sessions_sid_seq TO "account.account";

create table email_codes(
    codeid bigserial not null primary key,
    uid bigint not null,
    context varchar(32) not null,
    code varchar(6) not null,
    context_data text default null,
    
    foreign key(uid) references users(uid)
);

GRANT SELECT, INSERT, DELETE ON email_codes TO "account.account";
GRANT SELECT, USAGE ON SEQUENCE email_codes_codeid_seq TO "account.account";
