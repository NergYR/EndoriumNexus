create extension if not exists pgcrypto;

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

update ad_domains set site_name = 'Default-First-Site-Name' where site_name is null or site_name = '';
update ad_domains set dc_host = 'dc1' where dc_host is null or dc_host = '';
update ad_domains set next_rid = 1000 where next_rid is null or next_rid < 1000;

alter table dns_records add column if not exists dns_class text not null default 'IN';
alter table dns_records add column if not exists weight integer not null default 0;
alter table dns_records add column if not exists port integer not null default 0;
alter table dns_records add column if not exists flags text not null default '';
