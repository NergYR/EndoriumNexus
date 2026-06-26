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

alter table dns_records add column if not exists dns_class text not null default 'IN';
alter table dns_records add column if not exists weight integer not null default 0;
alter table dns_records add column if not exists port integer not null default 0;
alter table dns_records add column if not exists flags text not null default '';

create sequence if not exists ad_usn_sequence as bigint start with 1 increment by 1;

create table if not exists ad_objects (
    object_guid uuid default gen_random_uuid(),
    domain_dns_name text not null references ad_domains(dns_name) on delete cascade,
    dn text not null,
    parent_dn text,
    rdn text not null,
    kind text not null,
    object_sid text,
    rid bigint,
    object_classes jsonb not null default '[]'::jsonb,
    attributes jsonb not null default '{}'::jsonb,
    when_created timestamptz not null default now(),
    when_changed timestamptz not null default now(),
    uSNCreated bigint not null default nextval('ad_usn_sequence'),
    uSNChanged bigint not null default nextval('ad_usn_sequence')
);

alter table ad_objects add column if not exists object_guid uuid default gen_random_uuid();
alter table ad_objects add column if not exists domain_dns_name text;
alter table ad_objects add column if not exists dn text;
alter table ad_objects add column if not exists parent_dn text;
alter table ad_objects add column if not exists rdn text;
alter table ad_objects add column if not exists kind text;
alter table ad_objects add column if not exists object_sid text;
alter table ad_objects add column if not exists rid bigint;
alter table ad_objects add column if not exists object_classes jsonb not null default '[]'::jsonb;
alter table ad_objects add column if not exists attributes jsonb not null default '{}'::jsonb;
alter table ad_objects add column if not exists when_created timestamptz not null default now();
alter table ad_objects add column if not exists when_changed timestamptz not null default now();
alter table ad_objects add column if not exists uSNCreated bigint not null default nextval('ad_usn_sequence');
alter table ad_objects add column if not exists uSNChanged bigint not null default nextval('ad_usn_sequence');

update ad_objects set object_guid = gen_random_uuid() where object_guid is null;

create unique index if not exists ad_objects_dn_key on ad_objects(dn);
create unique index if not exists ad_objects_object_sid_key on ad_objects(object_sid);

create table if not exists ad_memberships (
    group_dn text not null,
    member_dn text not null,
    primary key (group_dn, member_dn)
);
create unique index if not exists ad_memberships_group_member_key on ad_memberships(group_dn, member_dn);

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
    ('ad-secrets', true, 'AD-compatible NT hash and Kerberos key material is wrapped at rest for password-bearing accounts'),
    ('ad-system-secrets', false, 'krbtgt and DC service account secrets have not been bootstrapped yet'),
    ('ad-objects-canonical', true, 'API and directory protocols persist AD objects into canonical ad_objects and maintain identity_objects as the compatibility projection'),
    ('ad-account-password-metadata', true, 'AD user and computer accounts expose accountExpires, pwdLastSet, badPwdCount, logonCount and msDS-SupportedEncryptionTypes; password resets advance pwdLastSet'),
    ('ad-default-seed', true, 'Default AD containers, users, groups, Builtin aliases and DC computer account are seeded idempotently'),
    ('dns-ad-locator', true, 'DNS UDP/TCP AD locator answers and merges A/SRV records for the configured domain controller'),
    ('dns-dynamic-update', true, 'DNS UPDATE packets for authorized AD zones are parsed, applied in-memory and persisted to dns_records for machine A/SRV registrations'),
    ('ldap-rootdse', true, 'LDAP bind and RootDSE discovery are implemented for early AD client probes'),
    ('ldap-simple-bind-verifier', true, 'LDAP simple binds on the directory daemon validate supplied passwords against wrapped AD account secrets before authorizing the session'),
    ('ldap-search', true, 'LDAP AD object subtree/base search is implemented for stored Nexus directory objects'),
    ('ldap-write-minimal', true, 'LDAP Add/Modify/Delete/ModifyDN requests are decoded and persisted to canonical ad_objects with AD account defaults and UI projection sync'),
    ('ldap-membership-sync', true, 'LDAP group member add/delete/replace updates canonical ad_memberships and member groupRids for join-time group changes'),
    ('ldap-machine-spn-merge', true, 'LDAP machine account adds/modifies preserve client-provided SPNs and merge required HOST/RestrictedKrbHost/LDAP/CIFS aliases'),
    ('ldap-constructed-membership', true, 'LDAP search/compare responses synthesize memberOf, primaryGroupToken, sAMAccountType and binary tokenGroups from canonical group memberships'),
    ('ldap-transitive-membership', true, 'LDAP matching rule 1.2.840.113556.1.4.1941 evaluates nested member/memberOf group chains for AD clients'),
    ('ldap-attribute-options', true, 'LDAP requested attributes with options such as member;range=0-* resolve against their base AD attribute names'),
    ('ldap-object-guid', true, 'LDAP search/filter responses expose objectGUID as a binary AD GUID backed by canonical ad_objects.object_guid when available'),
    ('ldap-operational-metadata', true, 'LDAP search responses expose AD-style whenCreated, whenChanged, uSNCreated and uSNChanged metadata for stored and virtual objects'),
    ('ldap-ad-controls', true, 'LDAP accepts common Windows AD controls including SD flags, domain-scope, show-deleted, server sort and VLV, with paged/sort/VLV response controls where required'),
    ('ldap-ad', false, 'LDAP AD write support is minimal; schema enforcement, controls and full SASL authorization are not complete yet'),
    ('kerberos-as-rep', true, 'KDC can issue a minimal encrypted AS-REP/TGT after successful pre-authentication'),
    ('kerberos-asrep-etype-negotiation', true, 'KDC selects a requested AS-REP enctype shared by the client and krbtgt, independently from the pre-auth timestamp enctype'),
    ('kerberos-tgs-rep', true, 'KDC can validate PA-TGS-REQ and issue a minimal encrypted TGS-REP for known service principals'),
    ('kerberos-pac-logon-info', true, 'Kerberos PAC includes a first LOGON_INFO buffer populated from SID/RID/group attributes'),
    ('kerberos-pac-signature-buffers', true, 'Kerberos PAC UPN_DNS_INFO, server checksum and KDC checksum buffers are emitted in their Windows PAC buffer slots'),
    ('kerberos-enterprise-upn-asreq', true, 'KDC accepts Windows enterprise UPN AS-REQ client names and emits the canonical account principal in the TGT and AS-REP'),
    ('kerberos-account-state', true, 'KDC and AP-REQ validation refuse disabled or expired AD principals instead of issuing or accepting tickets for blocked accounts'),
    ('kerberos-apreq-client-account-state', true, 'LDAP/SMB Kerberos AP-REQ validation refuses tickets whose client principal is disabled or expired in Nexus AD'),
    ('kerberos-kdc', false, 'Native Kerberos AS/TGS issuance has started; PAC and Windows logon are not complete yet'),
    ('kpasswd-password-change', true, 'kpasswd validates AP-REQ, decrypts KRB-PRIV ChangePasswdData and persists wrapped AD account secrets'),
    ('rpc-endpoint-mapper', true, 'DCE/RPC endpoint mapper accepts binds and returns lookup/map/server-alive hints for Nexus AD RPC interfaces'),
    ('rpc-epmapper-named-pipe', true, 'DCE/RPC endpoint mapper is also exposed over SMB IPC$ named pipe epmapper for Windows transport probes'),
    ('netlogon-authenticate', true, 'NetrServerAuthenticate validates the legacy machine secure-channel credential and returns a server credential'),
    ('netlogon-authenticate-account-state', true, 'Netlogon Authenticate refuses disabled or expired machine accounts after validating the client credential and before creating a secure-channel session'),
    ('netlogon-authenticator', true, 'Netlogon secure-channel authenticators are verified after Authenticate3 and return authenticators are generated'),
    ('netlogon-authenticate2', true, 'NetrServerAuthenticate2 negotiates AES secure-channel flags and stores the same session state as Authenticate3 for older Windows join paths'),
    ('netlogon-password-set2', true, 'NetrServerPasswordSet2 decrypts the machine password blob and persists updated wrapped AD secrets'),
    ('netlogon-dc-locator-rpc', true, 'Netlogon DsrGetDcName/DsrGetDcNameEx/DsrGetDcNameEx2, DsrGetSiteName and DsrAddressToSiteNamesW return LPWSTR-encoded Nexus DC/site metadata'),
    ('netlogon-capabilities', true, 'NetrLogonGetCapabilities returns negotiated and requested secure-channel flags after machine authentication'),
    ('netlogon-address-to-site', true, 'DsrAddressToSiteNamesW maps client socket-address probes to the configured Nexus AD site name'),
    ('netlogon-site-coverage', true, 'DsrAddressToSiteNamesExW and DsrGetDcSiteCoverageW return configured Nexus AD site coverage metadata'),
    ('netlogon-control', true, 'NetrLogonControl/Control2/Control2Ex answer query, TC verify and DNS registration status probes with coherent DC metadata'),
    ('netlogon-dns-host-records', true, 'DsrDeregisterDnsHostRecords accepts Windows DNS cleanup probes with STATUS_SUCCESS for the single Nexus DC'),
    ('netlogon-domain-trusts', true, 'NetrEnumerateTrustedDomains, NetrEnumerateTrustedDomainsEx and DsrEnumerateDomainTrusts expose the current Nexus domain as the primary native AD trust'),
    ('netlogon-forest-trust-info', true, 'DsrGetForestTrustInformation and NetrGetForestTrustInformation return minimal single-forest trust records for the Nexus domain DNS name, NetBIOS name and SID'),
    ('netlogon-sam-logon', true, 'NetrLogonSamLogonEx/WithFlags validates NTLMv2 proofs against wrapped NT hashes and returns minimal SAM validation data'),
    ('netlogon-samlogon-account-state', true, 'Netlogon SamLogon refuses disabled AD accounts with STATUS_ACCOUNT_DISABLED even when the NTLMv2 proof is valid'),
    ('netlogon-rpc', false, 'MS-RPC Netlogon secure-channel authenticators and full SAMR/LSA operations are not complete yet'),
    ('samr-domain-core', true, 'SAMR exposes minimal domain SID lookup, domain open, user open/create and lookup-name responses'),
    ('samr-domain-info2', true, 'SAMR QueryInformationDomain2 returns structured domain NetBIOS/DNS/SID/count metadata and SetInformationDomain accepts join-time probes'),
    ('samr-create-user-legacy', true, 'SAMR CreateUserInDomain legacy fallback can create/open machine accounts when Windows does not use CreateUser2InDomain'),
    ('samr-domain-enumeration', true, 'SAMR domain enumerate and display-information calls list built-in and stored user, computer and group accounts'),
    ('samr-domain-groups', true, 'SAMR domain group open/query/member/set-info probes return minimal v1 responses from canonical AD accounts'),
    ('samr-security-descriptor', true, 'SAMR QuerySecurityObject returns a minimal self-relative security descriptor and SetSecurityObject accepts join-time probes'),
    ('samr-compat-cleanup-ops', true, 'SAMR EnumerateDomains and cleanup/set/delete probes return coherent success responses instead of unsupported opnum errors'),
    ('lsa-lookup', true, 'LSA lookup-name and lookup-SID calls translate Nexus domain accounts for Windows join probes'),
    ('lsa-policy-privileges', true, 'LSA policy, privilege lookup/enumeration and account-right assignment probes return minimal v1 responses'),
    ('lsa-security-descriptor', true, 'LSA QuerySecurityObject returns a minimal self-relative security descriptor and SetSecurityObject accepts policy security probes'),
    ('lsa-trusted-domains', true, 'LSA trusted-domain enumerate/open/query calls expose the current Nexus domain as the primary single-forest trust'),
    ('lsa-account-management-ops', true, 'LSA account create/open privilege, quota, delete-object and GetUserName probes return minimal Windows-compatible responses'),
    ('smb2-session-kerberos-apreq', true, 'SMB2 SESSION_SETUP can validate Kerberos AP-REQ CIFS service tickets when Kerberos key material is loaded'),
    ('smb2-pipe-read-write', true, 'SMB2 named pipes accept WRITE requests and return queued DCE/RPC responses through READ'),
    ('smb2-pipe-fragmentation', true, 'SMB2 named-pipe RPC input fragments are reassembled and oversized IOCTL responses are drained through READ'),
    ('smb2-signing', true, 'SMB2 responses after Kerberos session setup are signed with a session HMAC-SHA256 signature for domain join/login clients'),
    ('smb2-transport-commands', true, 'SMB2 ECHO, FLUSH and SET_INFO return minimal success responses for Windows IPC$/SYSVOL transport probes'),
    ('smb2-lock', true, 'SMB2 LOCK requests on valid IPC$/SYSVOL/NETLOGON handles return minimal success responses for Windows file access probes'),
    ('smb2-file-info-classes', true, 'SMB2 QUERY_INFO answers common Windows file metadata classes including All, NetworkOpen, Name, Internal and AttributeTag'),
    ('smb2-security-info', true, 'SMB2 QUERY_INFO security requests return a minimal self-relative security descriptor for IPC$/SYSVOL/NETLOGON handles'),
    ('smb2-change-notify-cancel', true, 'SMB2 CHANGE_NOTIFY on SYSVOL/NETLOGON directory handles and CANCEL transport requests are handled for Windows clients'),
    ('smb2-sysvol-gpo-skeleton', true, 'SMB2 SYSVOL exposes default GPO folders with gpt.ini, empty Registry.pol and minimal SecEdit templates'),
    ('smb2-sysvol-path-validation', true, 'SMB2 SYSVOL/NETLOGON CREATE validates known GPO/script paths and returns OBJECT_NAME_NOT_FOUND for unknown files'),
    ('smb-sysvol', false, 'SMB SYSVOL/NETLOGON shares are minimal and read-only; policy replication, authoring and Windows acceptance are not complete yet'),
    ('windows-join-acceptance', false, 'Windows nltest/domain-join/reboot/login/klist/sc_verify acceptance has not passed yet')
on conflict (protocol) do nothing;
