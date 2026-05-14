create extension if not exists pgcrypto;

create table if not exists admin_users (
    id uuid primary key default gen_random_uuid(),
    email text not null unique,
    password_hash text not null,
    totp_secret text,
    roles jsonb not null default '[]'::jsonb,
    created_at timestamptz not null default now()
);

create table if not exists audit_events (
    id bigserial primary key,
    happened_at timestamptz not null default now(),
    actor text not null,
    domain text not null,
    action text not null,
    detail text not null
);

create table if not exists service_state (
    service_id text primary key,
    state text not null,
    summary text not null,
    updated_at timestamptz not null default now()
);

create table if not exists feature_flags (
    service_id text primary key,
    enabled boolean not null,
    updated_at timestamptz not null default now()
);

create table if not exists identity_objects (
    dn text primary key,
    parent_dn text,
    kind text not null,
    object_classes jsonb not null default '[]'::jsonb,
    attributes jsonb not null default '{}'::jsonb,
    updated_at timestamptz not null default now()
);

create table if not exists dns_zones (
    name text primary key,
    serial bigint not null,
    updated_at timestamptz not null default now()
);

create table if not exists dns_records (
    id bigserial primary key,
    zone_name text not null references dns_zones(name) on delete cascade,
    name text not null,
    type text not null,
    value text not null,
    ttl integer not null,
    priority integer not null default 0
);

create table if not exists dhcp_pools (
    name text primary key,
    subnet cidr not null,
    range_start inet not null,
    range_end inet not null,
    options jsonb not null default '{}'::jsonb
);

create table if not exists dhcp_leases (
    ip_address inet primary key,
    pool_name text not null references dhcp_pools(name) on delete cascade,
    client_id text not null,
    hostname text,
    state text not null,
    expires_at timestamptz not null
);

create table if not exists pki_authorities (
    id bigserial primary key,
    name text not null unique,
    certificate_pem text not null,
    private_key_pem text not null,
    created_at timestamptz not null default now()
);

create table if not exists pki_certificates (
    serial text primary key,
    authority_id bigint not null references pki_authorities(id) on delete cascade,
    common_name text not null,
    certificate_pem text not null,
    revoked boolean not null default false,
    created_at timestamptz not null default now()
);

create table if not exists pki_revocations (
    serial text primary key references pki_certificates(serial) on delete cascade,
    reason text not null,
    revoked_at timestamptz not null default now()
);

create table if not exists repo_repositories (
    distribution text not null,
    component text not null,
    primary key (distribution, component)
);

create table if not exists repo_packages (
    id bigserial primary key,
    distribution text not null,
    component text not null,
    name text not null,
    version text not null,
    architecture text not null,
    filename text not null,
    sha256 text not null,
    size bigint not null
);

create table if not exists job_queue (
    id text primary key,
    domain text not null,
    status text not null,
    description text not null,
    submitted_at timestamptz not null default now()
);
