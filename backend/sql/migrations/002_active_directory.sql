create table if not exists ad_domains (
    dns_name text primary key,
    netbios_name text not null unique,
    realm text not null,
    base_dn text not null,
    domain_sid text not null,
    created_at timestamptz not null default now()
);

create table if not exists ad_protocol_status (
    protocol text primary key,
    implemented boolean not null default false,
    detail text not null,
    updated_at timestamptz not null default now()
);

insert into ad_protocol_status(protocol, implemented, detail) values
    ('ldap-ad', false, 'LDAP AD-compatible wire protocol is not implemented yet'),
    ('kerberos-kdc', false, 'Native Kerberos KDC is not implemented yet'),
    ('netlogon-rpc', false, 'MS-RPC Netlogon/SAMR/LSA are not implemented yet'),
    ('smb-sysvol', false, 'SMB SYSVOL/NETLOGON shares are not implemented yet')
on conflict (protocol) do nothing;
