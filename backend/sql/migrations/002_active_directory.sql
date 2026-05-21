create table if not exists ad_domains (
    dns_name text primary key,
    netbios_name text not null unique,
    realm text not null,
    base_dn text not null,
    domain_sid text not null,
    domain_guid uuid not null default gen_random_uuid(),
    invocation_id uuid not null default gen_random_uuid(),
    site_name text not null default 'Default-First-Site-Name',
    dc_host text not null default 'dc1',
    dc_address inet,
    next_rid bigint not null default 1000,
    created_at timestamptz not null default now()
);

alter table ad_domains add column if not exists domain_guid uuid not null default gen_random_uuid();
alter table ad_domains add column if not exists invocation_id uuid not null default gen_random_uuid();
alter table ad_domains add column if not exists site_name text not null default 'Default-First-Site-Name';
alter table ad_domains add column if not exists dc_host text not null default 'dc1';
alter table ad_domains add column if not exists dc_address inet;
alter table ad_domains add column if not exists next_rid bigint not null default 1000;

alter table dns_records add column if not exists dns_class text not null default 'IN';
alter table dns_records add column if not exists weight integer not null default 0;
alter table dns_records add column if not exists port integer not null default 0;
alter table dns_records add column if not exists flags text not null default '';

create sequence if not exists ad_usn_sequence as bigint start with 1 increment by 1;

create table if not exists ad_objects (
    object_guid uuid primary key default gen_random_uuid(),
    domain_dns_name text not null references ad_domains(dns_name) on delete cascade,
    dn text not null unique,
    parent_dn text,
    rdn text not null,
    kind text not null,
    object_sid text unique,
    rid bigint,
    object_classes jsonb not null default '[]'::jsonb,
    attributes jsonb not null default '{}'::jsonb,
    when_created timestamptz not null default now(),
    when_changed timestamptz not null default now(),
    uSNCreated bigint not null default nextval('ad_usn_sequence'),
    uSNChanged bigint not null default nextval('ad_usn_sequence')
);

create table if not exists ad_memberships (
    group_dn text not null,
    member_dn text not null,
    primary key (group_dn, member_dn)
);

create table if not exists ad_service_principals (
    principal text primary key,
    object_dn text not null,
    created_at timestamptz not null default now()
);

create table if not exists ad_account_secrets (
    object_dn text primary key,
    encryption_version integer not null default 1,
    wrapped_nt_hash text not null,
    wrapped_kerberos_keys jsonb not null default '{}'::jsonb,
    updated_at timestamptz not null default now()
);

create table if not exists ad_protocol_status (
    protocol text primary key,
    implemented boolean not null default false,
    detail text not null,
    updated_at timestamptz not null default now()
);

insert into ad_protocol_status(protocol, implemented, detail) values
    ('dns-ad-locator', true, 'DNS UDP/TCP AD locator answers A and SRV records for the configured domain controller'),
    ('ldap-rootdse', true, 'LDAP bind and RootDSE discovery are implemented for early AD client probes'),
    ('cldap-netlogon', true, 'LDAP ping netlogon returns a NETLOGON_SAM_LOGON_RESPONSE_EX locator response'),
    ('ldap-search', true, 'LDAP AD object subtree/base search is implemented for stored Nexus directory objects'),
    ('kerberos-probe', true, 'KDC TCP/UDP listeners return structured Kerberos errors for AS/TGS probes'),
    ('kerberos-preauth', true, 'PA-ENC-TIMESTAMP is parsed and validated with AES-CTS-HMAC-SHA1 Kerberos keys'),
    ('ad-secrets', true, 'AD-compatible NT hash and Kerberos key material is wrapped at rest for password-bearing accounts'),
    ('ldap-ad', false, 'LDAP AD-compatible add/modify/delete is not complete yet'),
    ('kerberos-kdc', false, 'Native Kerberos KDC is not implemented yet'),
    ('netlogon-rpc', false, 'MS-RPC Netlogon/SAMR/LSA are not implemented yet'),
    ('smb-sysvol', false, 'SMB SYSVOL/NETLOGON shares are not implemented yet')
on conflict (protocol) do update set
    implemented = excluded.implemented,
    detail = excluded.detail,
    updated_at = now();
