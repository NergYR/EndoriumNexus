#include "platform_state.hpp"

#include "nexus/apt/repository.hpp"
#include "nexus/core/time.hpp"
#include "nexus/protocol/dns.hpp"
#include "nexus/protocol/kerberos.hpp"
#include "nexus/protocol/ldap.hpp"
#include "nexus/protocol/repo.hpp"
#include "nexus/protocol/rpc.hpp"
#include "nexus/protocol/smb.hpp"
#include "nexus/security/ad_crypto.hpp"

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <libpq-fe.h>

#include <algorithm>
#include <cctype>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <iostream>
#include <iterator>
#include <chrono>
#include <numeric>
#include <set>
#include <sstream>
#include <stdexcept>
#include <system_error>

namespace nexus::api {

namespace {

std::string lowercase_ascii(std::string value);
std::string uppercase_ascii(std::string value);
std::string sql_literal(PGconn* connection, const std::string& value);
std::string synthetic_domain_sid(const std::string& domain);

PGconn* connect_database(const std::string& connection_string) {
    if (connection_string.empty()) {
        return nullptr;
    }

    PGconn* connection = PQconnectdb(connection_string.c_str());
    if (PQstatus(connection) != CONNECTION_OK) {
        PQfinish(connection);
        return nullptr;
    }
    return connection;
}

bool ensure_feature_flags_table(PGconn* connection) {
    const char* sql = R"SQL(
        create table if not exists feature_flags (
            service_id text primary key,
            enabled boolean not null,
            updated_at timestamptz not null default now()
        )
    )SQL";
    PGresult* result = PQexec(connection, sql);
    const bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    PQclear(result);
    return ok;
}

std::map<std::string, bool> feature_flag_defaults(const nexus::core::Config& config) {
    std::map<std::string, bool> flags;
    for (const auto& service : nexus::core::service_definitions()) {
        if (service.feature_flag.empty()) {
            continue;
        }
        const auto it = config.features.find(service.feature_flag);
        flags[service.feature_flag] = it != config.features.end() && it->second;
    }
    return flags;
}

struct AdProtocolStatus {
    bool implemented{false};
    std::string detail;
};

std::map<std::string, AdProtocolStatus> load_ad_protocol_status(const std::string& database_url) {
    std::map<std::string, AdProtocolStatus> statuses;
    PGconn* connection = connect_database(database_url);
    if (connection == nullptr) {
        return statuses;
    }

    PGresult* result = PQexec(
        connection,
        "select protocol, implemented, detail from ad_protocol_status order by protocol");
    if (PQresultStatus(result) == PGRES_TUPLES_OK) {
        for (int row = 0; row < PQntuples(result); ++row) {
            const std::string protocol = PQgetvalue(result, row, 0);
            const bool implemented = std::string(PQgetvalue(result, row, 1)) == "t";
            const std::string detail = PQgetisnull(result, row, 2) ? "" : PQgetvalue(result, row, 2);
            statuses[protocol] = {implemented, detail};
        }
    }
    PQclear(result);
    PQfinish(connection);
    return statuses;
}

void set_ad_protocol_status(
    const std::string& database_url,
    const std::string& protocol,
    bool implemented,
    const std::string& detail) {
    PGconn* connection = connect_database(database_url);
    if (connection == nullptr) {
        return;
    }
    const std::string sql =
        "INSERT INTO ad_protocol_status(protocol,implemented,detail,updated_at) VALUES (" +
        sql_literal(connection, protocol) + "," +
        (implemented ? std::string{"true"} : std::string{"false"}) + "," +
        sql_literal(connection, detail) + ",now()) "
        "ON CONFLICT (protocol) DO UPDATE SET "
        "implemented=excluded.implemented, detail=excluded.detail, updated_at=now();";
    PGresult* result = PQexec(connection, sql.c_str());
    PQclear(result);
    PQfinish(connection);
}

void seed_ad_protocol_status_baseline(const std::string& database_url) {
    PGconn* connection = connect_database(database_url);
    if (connection == nullptr) {
        return;
    }

    const char* sql = R"SQL(
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
            ('ldap-ad', true, 'LDAP AD writes enforce minimal AD schema (objectClass, computer sAMAccountName and userAccountControl) and require an authenticated SASL/simple bind before Add/Modify/Delete'),
            ('kerberos-as-rep', true, 'KDC can issue a minimal encrypted AS-REP/TGT after successful pre-authentication'),
            ('kerberos-asrep-etype-negotiation', true, 'KDC selects a requested AS-REP enctype shared by the client and krbtgt, independently from the pre-auth timestamp enctype'),
            ('kerberos-tgs-rep', true, 'KDC can validate PA-TGS-REQ and issue a minimal encrypted TGS-REP for known service principals'),
            ('kerberos-pac-logon-info', true, 'Kerberos PAC includes a first LOGON_INFO buffer populated from SID/RID/group attributes'),
            ('kerberos-pac-signature-buffers', true, 'Kerberos PAC UPN_DNS_INFO, server checksum and KDC checksum buffers are emitted in their Windows PAC buffer slots'),
            ('kerberos-enterprise-upn-asreq', true, 'KDC accepts Windows enterprise UPN AS-REQ client names and emits the canonical account principal in the TGT and AS-REP'),
            ('kerberos-account-state', true, 'KDC and AP-REQ validation refuse disabled or expired AD principals instead of issuing or accepting tickets for blocked accounts'),
            ('kerberos-apreq-client-account-state', true, 'LDAP/SMB Kerberos AP-REQ validation refuses tickets whose client principal is disabled or expired in Nexus AD'),
            ('kerberos-kdc', true, 'Native Kerberos KDC issues AS-REP TGTs and TGS-REP service tickets (ldap/cifs) with PAC, exercised end-to-end by the domain-join acceptance test'),
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
            ('netlogon-rpc', true, 'MS-RPC Netlogon establishes the machine secure channel (ReqChallenge/Authenticate3), rotates the trust password (PasswordSet2) and validates SamLogon, exercised end-to-end by the domain-join acceptance test'),
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
            ('smb-sysvol', true, 'SMB SYSVOL/NETLOGON shares accept Group Policy authoring: writes to gpt.ini, Registry.pol and GptTmpl.inf persist through a writable overlay and are returned on subsequent reads'),
            ('windows-join-acceptance', true, 'The native domain-join sequence (DNS locator, LDAP RootDSE, Kerberos AS/TGS, SMB2 Kerberos session, LDAP machine-account creation, Netlogon secure channel, PasswordSet2 and SamLogon) passes end-to-end in the C++ acceptance test')
        on conflict (protocol) do nothing;
    )SQL";
    PGresult* result = PQexec(connection, sql);
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to seed AD protocol status baseline: "
                  << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(connection);
}

std::string trim_trailing_dot(std::string value) {
    while (!value.empty() && value.back() == '.') {
        value.pop_back();
    }
    return value;
}

bool service_ready(const std::vector<nexus::core::ServiceStatus>& services, const std::string& id) {
    const auto match = std::find_if(services.begin(), services.end(), [&](const auto& service) {
        return service.id == id;
    });
    return match != services.end() && match->enabled && match->blocking_reason.empty();
}

std::optional<nexus::core::DnsZone> find_dns_zone(
    const std::vector<nexus::core::DnsZone>& zones,
    const std::string& zone_name) {
    const auto normalized = lowercase_ascii(zone_name);
    const auto match = std::find_if(zones.begin(), zones.end(), [&](const auto& zone) {
        return lowercase_ascii(zone.name) == normalized;
    });
    if (match == zones.end()) {
        return std::nullopt;
    }
    return *match;
}

bool has_dns_record(
    const nexus::core::DnsZone& zone,
    const std::string& name,
    const std::string& type,
    std::uint16_t port = 0) {
    const auto expected_name = lowercase_ascii(name);
    const auto expected_type = uppercase_ascii(type);
    return std::any_of(zone.records.begin(), zone.records.end(), [&](const auto& record) {
        return lowercase_ascii(record.name) == expected_name &&
               uppercase_ascii(record.type) == expected_type &&
               (port == 0 || record.port == port);
    });
}

bool has_dc_a_record(
    const nexus::core::DnsZone& zone,
    const nexus::core::Config& config) {
    const auto expected_host = lowercase_ascii(config.directory.domain_controller_host);
    const auto expected_fqdn = expected_host + "." + lowercase_ascii(config.domain);
    return std::any_of(zone.records.begin(), zone.records.end(), [&](const auto& record) {
        const auto name = trim_trailing_dot(lowercase_ascii(record.name));
        const auto value = trim_trailing_dot(lowercase_ascii(record.value));
        return uppercase_ascii(record.type) == "A" &&
               (name == expected_host || name == expected_fqdn) &&
               (record.value.empty() || value == config.directory.domain_controller_address);
    });
}

bool has_directory_seed_account(
    const std::vector<nexus::core::DirectoryObject>& directory,
    const std::string& sam_account_name) {
    const auto expected = lowercase_ascii(sam_account_name);
    return std::any_of(directory.begin(), directory.end(), [&](const auto& object) {
        const auto it = object.attributes.find("sAMAccountName");
        return it != object.attributes.end() && lowercase_ascii(it->second) == expected;
    });
}

void append_readiness_item(
    PlatformState::ActiveDirectoryReadinessSnapshot& snapshot,
    std::string id,
    std::string label,
    std::string category,
    std::string detail,
    bool ready,
    bool blocking = true) {
    snapshot.items.push_back({
        std::move(id),
        std::move(label),
        std::move(category),
        std::move(detail),
        ready,
        blocking,
    });
}

void append_protocol_status_item(
    PlatformState::ActiveDirectoryReadinessSnapshot& snapshot,
    const std::map<std::string, AdProtocolStatus>& statuses,
    const std::string& protocol,
    const std::string& label,
    const std::string& category) {
    const auto match = statuses.find(protocol);
    if (match == statuses.end()) {
        append_readiness_item(
            snapshot,
            protocol,
            label,
            category,
            "missing ad_protocol_status row",
            false);
        return;
    }
    append_readiness_item(
        snapshot,
        protocol,
        label,
        category,
        match->second.detail,
        match->second.implemented);
}

using ProbeBytes = std::vector<std::uint8_t>;

void probe_append_length(ProbeBytes& output, std::size_t length) {
    if (length < 0x80) {
        output.push_back(static_cast<std::uint8_t>(length));
        return;
    }
    if (length <= 0xff) {
        output.push_back(0x81);
        output.push_back(static_cast<std::uint8_t>(length));
        return;
    }
    output.push_back(0x82);
    output.push_back(static_cast<std::uint8_t>((length >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(length & 0xffU));
}

ProbeBytes probe_tlv(std::uint8_t tag, const ProbeBytes& payload) {
    ProbeBytes output{tag};
    probe_append_length(output, payload.size());
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

ProbeBytes probe_concat(std::initializer_list<ProbeBytes> chunks) {
    ProbeBytes output;
    for (const auto& chunk : chunks) {
        output.insert(output.end(), chunk.begin(), chunk.end());
    }
    return output;
}

ProbeBytes probe_int(int value) {
    ProbeBytes encoded;
    bool started = false;
    for (int shift = 24; shift >= 0; shift -= 8) {
        const auto byte = static_cast<std::uint8_t>((value >> shift) & 0xff);
        if (byte != 0 || started || shift == 0) {
            encoded.push_back(byte);
            started = true;
        }
    }
    if (!encoded.empty() && (encoded.front() & 0x80U) != 0) {
        encoded.insert(encoded.begin(), 0);
    }
    return probe_tlv(0x02, encoded);
}

ProbeBytes probe_seq(const ProbeBytes& payload) {
    return probe_tlv(0x30, payload);
}

ProbeBytes probe_ctx(std::uint8_t index, const ProbeBytes& payload) {
    return probe_tlv(static_cast<std::uint8_t>(0xa0U + index), payload);
}

ProbeBytes probe_ldap_string(const std::string& value) {
    return probe_tlv(0x04, ProbeBytes(value.begin(), value.end()));
}

ProbeBytes probe_ldap_enum(int value) {
    return probe_tlv(0x0a, {static_cast<std::uint8_t>(value)});
}

ProbeBytes probe_ldap_message(int message_id, std::uint8_t operation_tag, const ProbeBytes& operation_payload) {
    return probe_seq(probe_concat({
        probe_int(message_id),
        probe_tlv(operation_tag, operation_payload),
    }));
}

ProbeBytes probe_ldap_search_request(
    int message_id,
    const std::string& base_dn,
    int scope,
    const std::vector<std::string>& attributes,
    const std::vector<ProbeBytes>& controls = {}) {
    ProbeBytes attribute_list;
    for (const auto& attribute : attributes) {
        const auto encoded = probe_ldap_string(attribute);
        attribute_list.insert(attribute_list.end(), encoded.begin(), encoded.end());
    }
    const auto operation_payload = probe_concat({
        probe_ldap_string(base_dn),
        probe_ldap_enum(scope),
        probe_ldap_enum(0),
        probe_int(0),
        probe_int(0),
        probe_tlv(0x01, {0}),
        probe_tlv(0x87, ProbeBytes{'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's'}),
        probe_seq(attribute_list),
    });
    if (controls.empty()) {
        return probe_ldap_message(message_id, 0x63, operation_payload);
    }

    ProbeBytes controls_payload;
    for (const auto& control : controls) {
        controls_payload.insert(controls_payload.end(), control.begin(), control.end());
    }
    return probe_seq(probe_concat({
        probe_int(message_id),
        probe_tlv(0x63, operation_payload),
        probe_tlv(0xa0, controls_payload),
    }));
}

ProbeBytes probe_ldap_control(const std::string& oid, bool critical = true) {
    const auto value = probe_seq(probe_concat({probe_int(1000), probe_tlv(0x04, {})}));
    return probe_seq(probe_concat({
        probe_ldap_string(oid),
        critical ? probe_tlv(0x01, {0xff}) : ProbeBytes{},
        probe_tlv(0x04, value),
    }));
}

ProbeBytes probe_kerberos_string(const std::string& value) {
    return probe_tlv(0x1b, ProbeBytes(value.begin(), value.end()));
}

ProbeBytes probe_kerberos_as_req_without_preauth(const std::string& realm) {
    const auto request_body = probe_seq(probe_concat({
        probe_ctx(2, probe_kerberos_string(realm)),
        probe_ctx(7, probe_int(42)),
        probe_ctx(8, probe_seq(probe_concat({probe_int(18), probe_int(17)}))),
    }));
    return probe_tlv(0x6a, probe_seq(probe_concat({
        probe_ctx(1, probe_int(5)),
        probe_ctx(2, probe_int(10)),
        probe_ctx(4, request_body),
    })));
}

ProbeBytes probe_kpasswd_missing_payload_request() {
    return {0x00, 0x06, 0xff, 0x80, 0x00, 0x00};
}

void probe_write_u16_le(ProbeBytes& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

void probe_write_u32_le(ProbeBytes& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
}

void probe_write_u64_le(ProbeBytes& output, std::uint64_t value) {
    probe_write_u32_le(output, static_cast<std::uint32_t>(value & 0xffffffffU));
    probe_write_u32_le(output, static_cast<std::uint32_t>((value >> 32U) & 0xffffffffU));
}

ProbeBytes probe_rpc_header(std::uint8_t ptype, std::uint32_t call_id, const ProbeBytes& body) {
    ProbeBytes output{5, 0, ptype, 0x03, 0x10, 0, 0, 0};
    probe_write_u16_le(output, static_cast<std::uint16_t>(16 + body.size()));
    probe_write_u16_le(output, 0);
    probe_write_u32_le(output, call_id);
    output.insert(output.end(), body.begin(), body.end());
    return output;
}

ProbeBytes probe_rpc_ndr_syntax() {
    return {
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00,
    };
}

ProbeBytes probe_rpc_epm_bind() {
    ProbeBytes body;
    probe_write_u16_le(body, 4280);
    probe_write_u16_le(body, 4280);
    probe_write_u32_le(body, 0);
    body.insert(body.end(), {1, 0, 0, 0});
    probe_write_u16_le(body, 0);
    body.push_back(1);
    body.push_back(0);
    body.insert(body.end(), {
        0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
        0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
    });
    probe_write_u32_le(body, 3);
    const auto transfer = probe_rpc_ndr_syntax();
    body.insert(body.end(), transfer.begin(), transfer.end());
    return probe_rpc_header(0x0b, 7001, body);
}

ProbeBytes probe_smb2_netbios_frame(const ProbeBytes& payload) {
    ProbeBytes output{
        0x00,
        static_cast<std::uint8_t>((payload.size() >> 16U) & 0xffU),
        static_cast<std::uint8_t>((payload.size() >> 8U) & 0xffU),
        static_cast<std::uint8_t>(payload.size() & 0xffU),
    };
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

ProbeBytes probe_smb2_header(std::uint16_t command, std::uint64_t message_id, const ProbeBytes& body) {
    ProbeBytes output{0xfe, 'S', 'M', 'B'};
    probe_write_u16_le(output, 64);
    probe_write_u16_le(output, 0);
    probe_write_u32_le(output, 0);
    probe_write_u16_le(output, command);
    probe_write_u16_le(output, 1);
    probe_write_u32_le(output, 0);
    probe_write_u32_le(output, 0);
    probe_write_u64_le(output, message_id);
    probe_write_u32_le(output, 0);
    probe_write_u32_le(output, 0);
    probe_write_u64_le(output, 0);
    output.insert(output.end(), 16, 0);
    output.insert(output.end(), body.begin(), body.end());
    return output;
}

ProbeBytes probe_smb2_negotiate_request() {
    ProbeBytes body;
    probe_write_u16_le(body, 36);
    probe_write_u16_le(body, 5);
    probe_write_u16_le(body, 1);
    probe_write_u16_le(body, 0);
    probe_write_u32_le(body, 0);
    body.insert(body.end(), 16, 0x42);
    probe_write_u32_le(body, 0);
    probe_write_u16_le(body, 0);
    probe_write_u16_le(body, 0);
    for (const auto dialect : {0x0202, 0x0210, 0x0300, 0x0302, 0x0311}) {
        probe_write_u16_le(body, static_cast<std::uint16_t>(dialect));
    }
    return probe_smb2_netbios_frame(probe_smb2_header(0, 9001, body));
}

bool bytes_contain(const ProbeBytes& haystack, const std::string& needle) {
    const ProbeBytes needle_bytes(needle.begin(), needle.end());
    return std::search(haystack.begin(), haystack.end(), needle_bytes.begin(), needle_bytes.end()) != haystack.end();
}

bool ldap_rootdse_internal_probe(const nexus::core::Config& config) {
    const nexus::protocol::LdapDirectoryInfo directory{
        config.domain,
        config.directory.base_dn,
        config.directory.realm,
        config.directory.site_name.empty() ? std::string{"Default-First-Site-Name"} : config.directory.site_name,
        config.directory.domain_controller_host,
        config.directory.domain_controller_address,
        synthetic_domain_sid(config.domain),
    };
    const auto response = nexus::protocol::ldap_ad_response(
        probe_ldap_search_request(8101, "", 0, {"dsServiceName", "supportedControl"}),
        directory);
    return !response.empty() &&
        bytes_contain(response, "cn=NTDS Settings") &&
        bytes_contain(response, "1.2.840.113556.1.4.319") &&
        bytes_contain(response, "1.2.840.113556.1.4.417") &&
        bytes_contain(response, "2.16.840.1.113730.3.4.9");
}

bool ldap_windows_controls_internal_probe(const nexus::core::Config& config) {
    const nexus::protocol::LdapDirectoryInfo directory{
        config.domain,
        config.directory.base_dn,
        config.directory.realm,
        config.directory.site_name.empty() ? std::string{"Default-First-Site-Name"} : config.directory.site_name,
        config.directory.domain_controller_host,
        config.directory.domain_controller_address,
        synthetic_domain_sid(config.domain),
    };
    const auto response = nexus::protocol::ldap_ad_response(
        probe_ldap_search_request(
            8102,
            config.directory.base_dn,
            2,
            {"cn", "nTSecurityDescriptor"},
            {
                probe_ldap_control("1.2.840.113556.1.4.473"),
                probe_ldap_control("1.2.840.113556.1.4.801"),
                probe_ldap_control("1.2.840.113556.1.4.1339"),
                probe_ldap_control("1.2.840.113556.1.4.417"),
                probe_ldap_control("2.16.840.1.113730.3.4.9"),
            }),
        directory);
    return !response.empty() &&
        !bytes_contain(response, "unsupported critical LDAP control") &&
        bytes_contain(response, "1.2.840.113556.1.4.474") &&
        bytes_contain(response, "2.16.840.1.113730.3.4.10") &&
        bytes_contain(response, "nTSecurityDescriptor");
}

bool kerberos_internal_probe(const nexus::core::Config& config) {
    const nexus::protocol::KerberosRealmInfo realm{config.directory.realm, "krbtgt", {}};
    const auto response = nexus::protocol::kerberos_error_response(
        probe_kerberos_as_req_without_preauth(config.directory.realm),
        realm);
    return !response.empty() && response.front() == 0x7e && bytes_contain(response, "pre-authentication required");
}

bool kpasswd_internal_probe(const nexus::core::Config& config) {
    const nexus::protocol::KerberosRealmInfo realm{config.directory.realm, "krbtgt", {}};
    const auto response = nexus::protocol::kerberos_kpasswd_response(
        probe_kpasswd_missing_payload_request(),
        realm);
    return response.size() > 6 && response[6] == 0x7e && bytes_contain(response, "AP-REQ");
}

bool rpc_epm_internal_probe(const nexus::core::Config& config) {
    const auto response = nexus::protocol::rpc_endpoint_mapper_response(
        probe_rpc_epm_bind(),
        static_cast<std::uint16_t>(config.rpc.port));
    return response.size() > 16 && response[2] == 0x0c;
}

bool smb2_internal_probe() {
    const auto response = nexus::protocol::smb2_response(probe_smb2_negotiate_request());
    return response.size() > 132 &&
        response.front() == 0x00 &&
        response[4] == 0xfe &&
        response[5] == 'S' &&
        response[6] == 'M' &&
        response[7] == 'B';
}

std::string get_service_blocking_reason(const std::string& service_id, const std::string& database_url) {
    if (database_url.empty()) {
        return "database not configured";
    }

    PGconn* conn = PQconnectdb(database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        PQfinish(conn);
        return "database connection failed";
    }

    std::string reason;

    if (service_id == "network") {
        // Network service needs at least one DNS zone and one DHCP pool
        PGresult* zones_result = PQexec(conn, "SELECT COUNT(*) FROM dns_zones");
        PGresult* pools_result = PQexec(conn, "SELECT COUNT(*) FROM dhcp_pools");

        if (PQresultStatus(zones_result) == PGRES_TUPLES_OK && PQresultStatus(pools_result) == PGRES_TUPLES_OK) {
            try {
                const int zone_count = std::stoi(PQgetvalue(zones_result, 0, 0));
                const int pool_count = std::stoi(PQgetvalue(pools_result, 0, 0));

                if (zone_count == 0 || pool_count == 0) {
                    reason = "Requires ≥1 DNS zone (" + std::to_string(zone_count) + " found) and ≥1 DHCP pool (" + std::to_string(pool_count) + " found)";
                }
            } catch (...) {
                reason = "Cannot verify prerequisites";
            }
        }

        PQclear(zones_result);
        PQclear(pools_result);
    } else if (service_id == "pki-repo") {
        // PKI repository needs at least one certificate authority
        PGresult* authorities_result = PQexec(conn, "SELECT COUNT(*) FROM pki_authorities");

        if (PQresultStatus(authorities_result) == PGRES_TUPLES_OK) {
            try {
                const int authority_count = std::stoi(PQgetvalue(authorities_result, 0, 0));

                if (authority_count == 0) {
                    reason = "Requires ≥1 PKI authority (0 found)";
                }
            } catch (...) {
                reason = "Cannot verify prerequisites";
            }
        }

        PQclear(authorities_result);
    }
    // directory and other services have no special prerequisites

    PQfinish(conn);
    return reason;  // Empty string means no blocking reason
}

bool persist_dhcp_pool_to_database(const nexus::core::DhcpPool& pool, const std::string& database_url, std::string* out_err) {
    if (database_url.empty()) {
        if (out_err) *out_err = "database not configured";
        return false;
    }

    PGconn* conn = PQconnectdb(database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        if (out_err) *out_err = "database connection failed";
        PQfinish(conn);
        return false;
    }

    // Build options JSON
    std::string options_json = "{";
    bool first = true;
    for (const auto& [k, v] : pool.options) {
        if (!first) options_json += ",";
        first = false;
        // naive JSON escaping for keys/values (quotes/backslashes)
        auto escape = [](const std::string& s){
            std::string out;
            for (char c : s) {
                if (c == '\\' || c == '"') {
                    out.push_back('\\');
                    out.push_back(c);
                } else if (c == '\n') {
                    out += "\\n";
                } else {
                    out.push_back(c);
                }
            }
            return out;
        };
        options_json += "\"" + escape(k) + "\":\"" + escape(v) + "\"";
    }
    options_json += "}";

    // Escape literals using libpq
    char* name_esc = PQescapeLiteral(conn, pool.name.c_str(), static_cast<unsigned long>(pool.name.size()));
    char* subnet_esc = PQescapeLiteral(conn, pool.subnet.c_str(), static_cast<unsigned long>(pool.subnet.size()));
    char* start_esc = PQescapeLiteral(conn, pool.range_start.c_str(), static_cast<unsigned long>(pool.range_start.size()));
    char* end_esc = PQescapeLiteral(conn, pool.range_end.c_str(), static_cast<unsigned long>(pool.range_end.size()));
    char* opts_esc = PQescapeLiteral(conn, options_json.c_str(), static_cast<unsigned long>(options_json.size()));

    if (!name_esc || !subnet_esc || !start_esc || !end_esc || !opts_esc) {
        if (out_err) *out_err = "failed to escape SQL literals";
        if (name_esc) PQfreemem(name_esc);
        if (subnet_esc) PQfreemem(subnet_esc);
        if (start_esc) PQfreemem(start_esc);
        if (end_esc) PQfreemem(end_esc);
        if (opts_esc) PQfreemem(opts_esc);
        PQfinish(conn);
        return false;
    }

    std::string sql = "INSERT INTO dhcp_pools(name, subnet, range_start, range_end, options) VALUES (" +
                      std::string(name_esc) + "," + std::string(subnet_esc) + "," + std::string(start_esc) + "," + std::string(end_esc) + "," + std::string(opts_esc) + "::jsonb) ON CONFLICT (name) DO UPDATE SET subnet=excluded.subnet, range_start=excluded.range_start, range_end=excluded.range_end, options=excluded.options;";

    PGresult* res = PQexec(conn, sql.c_str());
    bool ok = PQresultStatus(res) == PGRES_COMMAND_OK;
    if (!ok && out_err) {
        *out_err = PQresultErrorMessage(res);
    }
    PQclear(res);

    PQfreemem(name_esc);
    PQfreemem(subnet_esc);
    PQfreemem(start_esc);
    PQfreemem(end_esc);
    PQfreemem(opts_esc);
    PQfinish(conn);
    return ok;
}

std::string sql_literal(PGconn* connection, const std::string& value) {
    char* escaped = PQescapeLiteral(connection, value.c_str(), static_cast<unsigned long>(value.size()));
    if (escaped == nullptr) {
        return "''";
    }
    std::string result(escaped);
    PQfreemem(escaped);
    return result;
}

std::string json_string_array(const std::vector<std::string>& values) {
    Json::Value array(Json::arrayValue);
    for (const auto& value : values) {
        array.append(value);
    }
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    return Json::writeString(builder, array);
}

std::string json_string_object(const std::map<std::string, std::string>& values) {
    Json::Value object(Json::objectValue);
    for (const auto& [key, value] : values) {
        object[key] = value;
    }
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    return Json::writeString(builder, object);
}

std::vector<std::string> json_array_from_string(const std::string& payload) {
    Json::CharReaderBuilder builder;
    Json::Value value;
    std::string errors;
    std::istringstream input(payload.empty() ? "[]" : payload);
    std::vector<std::string> result;
    if (!Json::parseFromStream(builder, input, &value, &errors) || !value.isArray()) {
        return result;
    }
    for (const auto& entry : value) {
        result.push_back(entry.asString());
    }
    return result;
}

std::map<std::string, std::string> json_object_from_string(const std::string& payload) {
    Json::CharReaderBuilder builder;
    Json::Value value;
    std::string errors;
    std::istringstream input(payload.empty() ? "{}" : payload);
    std::map<std::string, std::string> result;
    if (!Json::parseFromStream(builder, input, &value, &errors) || !value.isObject()) {
        return result;
    }
    for (const auto& key : value.getMemberNames()) {
        result[key] = value[key].asString();
    }
    return result;
}

std::string trim_copy(const std::string& value) {
    const auto first = value.find_first_not_of(" \t\r\n");
    if (first == std::string::npos) {
        return "";
    }
    const auto last = value.find_last_not_of(" \t\r\n");
    return value.substr(first, last - first + 1);
}

std::vector<std::string> split_multi_value_attribute(const std::string& value) {
    std::vector<std::string> result;
    std::string current;
    for (const auto ch : value) {
        if (ch == ',' || ch == ';' || ch == '\n' || ch == '\r' || ch == '\t') {
            auto trimmed = trim_copy(current);
            if (!trimmed.empty()) {
                result.push_back(std::move(trimmed));
            }
            current.clear();
            continue;
        }
        current.push_back(ch);
    }
    auto trimmed = trim_copy(current);
    if (!trimmed.empty()) {
        result.push_back(std::move(trimmed));
    }
    return result;
}

std::string sha256_hex(const std::string& payload) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), digest);
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned char byte : digest) {
        output << std::setw(2) << static_cast<int>(byte);
    }
    return output.str();
}

std::string lowercase_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string uppercase_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

std::string machine_spn_attribute(const std::string& host, const std::string& dns_host) {
    std::vector<std::string> spns;
    const auto add_spn = [&](const std::string& value) {
        if (value.empty()) {
            return;
        }
        const auto normalized = lowercase_ascii(value);
        const auto exists = std::any_of(spns.begin(), spns.end(), [&](const auto& current) {
            return lowercase_ascii(current) == normalized;
        });
        if (!exists) {
            spns.push_back(value);
        }
    };
    for (const auto& service : {"HOST", "RestrictedKrbHost", "LDAP", "CIFS"}) {
        if (!host.empty()) {
            add_spn(std::string(service) + "/" + host);
        }
        if (!dns_host.empty()) {
            add_spn(std::string(service) + "/" + dns_host);
        }
    }

    std::string joined;
    for (const auto& spn : spns) {
        if (!joined.empty()) {
            joined.push_back(',');
        }
        joined += spn;
    }
    return joined;
}

std::string merge_machine_spn_attribute(
    const std::string& existing,
    const std::string& host,
    const std::string& dns_host) {
    std::vector<std::string> spns;
    const auto add_spn = [&](const std::string& value) {
        const auto trimmed = trim_copy(value);
        if (trimmed.empty()) {
            return;
        }
        const auto normalized = lowercase_ascii(trimmed);
        const auto exists = std::any_of(spns.begin(), spns.end(), [&](const auto& current) {
            return lowercase_ascii(current) == normalized;
        });
        if (!exists) {
            spns.push_back(trimmed);
        }
    };
    for (const auto& spn : split_multi_value_attribute(existing)) {
        add_spn(spn);
    }
    for (const auto& spn : split_multi_value_attribute(machine_spn_attribute(host, dns_host))) {
        add_spn(spn);
    }

    std::string joined;
    for (const auto& spn : spns) {
        if (!joined.empty()) {
            joined.push_back(',');
        }
        joined += spn;
    }
    return joined;
}

std::string current_ad_filetime_string() {
    constexpr std::int64_t windows_epoch_offset_ticks = 116444736000000000LL;
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto ticks_since_unix_epoch = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count() / 100LL;
    return std::to_string(windows_epoch_offset_ticks + ticks_since_unix_epoch);
}

void set_attribute_if_missing(
    std::map<std::string, std::string>& attributes,
    const std::string& name,
    const std::string& value) {
    const auto existing = std::find_if(attributes.begin(), attributes.end(), [&](const auto& entry) {
        return lowercase_ascii(entry.first) == lowercase_ascii(name);
    });
    if (existing == attributes.end() || existing->second.empty()) {
        attributes[name] = value;
    }
}

void stamp_ad_password_metadata(
    std::map<std::string, std::string>& attributes,
    const std::string& sam_account_name) {
    attributes["pwdLastSet"] = current_ad_filetime_string();
    attributes["badPwdCount"] = "0";
    const auto normalized_sam = lowercase_ascii(sam_account_name);
    if (!normalized_sam.empty() && normalized_sam.back() == '$') {
        const auto uac_it = attributes.find("userAccountControl");
        if (uac_it == attributes.end()) {
            return;
        }
        try {
            constexpr std::uint32_t user_account_control_passwd_notreqd = 0x00000020U;
            constexpr std::uint32_t user_account_control_workstation_trust = 0x00001000U;
            const auto uac = static_cast<std::uint32_t>(std::stoul(uac_it->second));
            if ((uac & user_account_control_workstation_trust) != 0 &&
                (uac & user_account_control_passwd_notreqd) != 0) {
                uac_it->second = std::to_string(uac & ~user_account_control_passwd_notreqd);
            }
        } catch (...) {
        }
    }
}

bool stamp_ad_password_metadata_to_database(PGconn* conn, const std::string& object_dn) {
    if (object_dn.empty()) {
        return true;
    }
    const auto pwd_last_set = sql_literal(conn, current_ad_filetime_string());
    const std::string attributes_expression =
        "jsonb_set(jsonb_set(attributes, '{pwdLastSet}', to_jsonb(" + pwd_last_set +
        "::text), true), '{badPwdCount}', to_jsonb('0'::text), true)";

    const std::string identity_sql =
        "update identity_objects set attributes = " + attributes_expression +
        ", updated_at = now() where dn = " + sql_literal(conn, object_dn) + ";";
    PGresult* identity_result = PQexec(conn, identity_sql.c_str());
    const bool identity_ok = PQresultStatus(identity_result) == PGRES_COMMAND_OK;
    PQclear(identity_result);

    const std::string ad_sql =
        "update ad_objects set attributes = " + attributes_expression +
        ", when_changed = now(), uSNChanged = nextval('ad_usn_sequence') where dn = " +
        sql_literal(conn, object_dn) + ";";
    PGresult* ad_result = PQexec(conn, ad_sql.c_str());
    const bool ad_ok = PQresultStatus(ad_result) == PGRES_COMMAND_OK;
    PQclear(ad_result);
    return identity_ok && ad_ok;
}

std::uint32_t stable_hash32(const std::string& value) {
    std::uint32_t hash = 2166136261U;
    for (const unsigned char ch : value) {
        hash ^= ch;
        hash *= 16777619U;
    }
    return hash;
}

std::string synthetic_domain_sid(const std::string& domain) {
    const auto lower = lowercase_ascii(domain);
    const auto a = 1000U + (stable_hash32(lower + ":a") % 1000000000U);
    const auto b = 1000U + (stable_hash32(lower + ":b") % 1000000000U);
    const auto c = 1000U + (stable_hash32(lower + ":c") % 1000000000U);
    return "S-1-5-21-" + std::to_string(a) + "-" + std::to_string(b) + "-" + std::to_string(c);
}

std::uint32_t synthetic_rid(const std::string& sam_account_name) {
    const auto normalized = lowercase_ascii(sam_account_name);
    if (normalized == "administrator") {
        return 500;
    }
    if (normalized == "guest") {
        return 501;
    }
    if (normalized == "krbtgt") {
        return 502;
    }
    return 1000U + (stable_hash32(normalized) % 900000U);
}

std::string netbios_name_from_domain(const std::string& domain) {
    const auto dot = domain.find('.');
    auto name = dot == std::string::npos ? domain : domain.substr(0, dot);
    std::string sanitized;
    for (const auto ch : name) {
        if (std::isalnum(static_cast<unsigned char>(ch))) {
            sanitized.push_back(static_cast<char>(std::toupper(static_cast<unsigned char>(ch))));
        }
    }
    if (sanitized.empty()) {
        return "ENDORIUM";
    }
    if (sanitized.size() > 15) {
        sanitized.resize(15);
    }
    return sanitized;
}

std::string attribute_or_empty(const nexus::core::DirectoryObject& object, const std::string& name) {
    const auto it = object.attributes.find(name);
    if (it == object.attributes.end()) {
        return "";
    }
    return it->second;
}

bool equals_ascii_case(const std::string& left, const std::string& right) {
    return lowercase_ascii(left) == lowercase_ascii(right);
}

std::uint64_t parse_u64_or_zero(const std::string& value) {
    if (value.empty()) {
        return 0;
    }
    try {
        return static_cast<std::uint64_t>(std::stoull(value));
    } catch (...) {
        return 0;
    }
}

std::string stable_guid_from_key(const std::string& key) {
    const auto hash = sha256_hex(key);
    return hash.substr(0, 8) + "-" +
        hash.substr(8, 4) + "-" +
        hash.substr(12, 4) + "-" +
        hash.substr(16, 4) + "-" +
        hash.substr(20, 12);
}

bool is_sensitive_ad_attribute(const std::string& name) {
    const auto lower = lowercase_ascii(name);
    return lower == "userpasswordhash" ||
        lower == "nthash" ||
        lower == "unicodepwd" ||
        lower == "supplementalcredentials" ||
        lower == "kerberoskeys" ||
        lower == "wrappedkerberoskeys";
}

bool is_multivalued_ad_attribute(const std::string& name) {
    const auto lower = lowercase_ascii(name);
    return lower == "objectclass" ||
        lower == "serviceprincipalname" ||
        lower == "member" ||
        lower == "memberof" ||
        lower == "grouprids" ||
        lower == "dnshostnamealiases";
}

std::string ad_attribute_type(const std::string& name) {
    const auto lower = lowercase_ascii(name);
    if (lower == "objectguid") {
        return "guid";
    }
    if (lower == "objectsid") {
        return "sid";
    }
    if (lower == "ntsecuritydescriptor") {
        return "security-descriptor";
    }
    if (lower == "rid" ||
        lower == "primarygroupid" ||
        lower == "useraccountcontrol" ||
        lower == "usncreated" ||
        lower == "usnchanged" ||
        lower == "samaccounttype" ||
        lower == "accountexpires" ||
        lower == "pwdlastset" ||
        lower == "badpwdcount" ||
        lower == "logoncount" ||
        lower == "msds-supportedencryptiontypes") {
        return "integer";
    }
    return "string";
}

std::string ad_attribute_encoding(const std::string& type) {
    if (type == "guid") {
        return "uuid";
    }
    if (type == "sid") {
        return "sddl";
    }
    if (type == "integer") {
        return "decimal";
    }
    if (type == "security-descriptor") {
        return "base64";
    }
    return "utf8";
}

PlatformState::ActiveDirectoryAttribute make_ad_attribute(
    const std::string& name,
    const std::vector<std::string>& raw_values) {
    PlatformState::ActiveDirectoryAttribute attribute;
    attribute.name = name;
    attribute.type = ad_attribute_type(name);
    attribute.multi_valued = raw_values.size() > 1 || is_multivalued_ad_attribute(name);
    const auto encoding = ad_attribute_encoding(attribute.type);
    for (const auto& value : raw_values) {
        if (!value.empty()) {
            attribute.values.push_back({value, encoding});
        }
    }
    return attribute;
}

std::vector<std::string> ad_attribute_values(const std::string& name, const std::string& raw_value) {
    if (is_multivalued_ad_attribute(name)) {
        auto values = split_multi_value_attribute(raw_value);
        if (!values.empty()) {
            return values;
        }
    }
    return raw_value.empty() ? std::vector<std::string>{} : std::vector<std::string>{raw_value};
}

bool has_object_class(const nexus::core::DirectoryObject& object, const std::string& object_class) {
    const auto expected = lowercase_ascii(object_class);
    return std::any_of(object.object_classes.begin(), object.object_classes.end(), [&](const auto& current) {
        return lowercase_ascii(current) == expected;
    });
}

std::string first_rdn_value(const std::string& dn) {
    const auto equals = dn.find('=');
    if (equals == std::string::npos) {
        return "";
    }
    const auto comma = dn.find(',', equals + 1);
    return dn.substr(equals + 1, comma == std::string::npos ? std::string::npos : comma - equals - 1);
}

std::string parent_dn_from_dn(const std::string& dn) {
    const auto comma = dn.find(',');
    if (comma == std::string::npos || comma + 1 >= dn.size()) {
        return "";
    }
    return dn.substr(comma + 1);
}

bool should_have_ad_account_material(const nexus::core::DirectoryObject& object) {
    const auto kind = lowercase_ascii(object.kind);
    return kind == "user" ||
           kind == "computer" ||
           has_object_class(object, "user") ||
           has_object_class(object, "computer") ||
           object.attributes.find("sAMAccountName") != object.attributes.end();
}

void ensure_ad_account_attributes(nexus::core::DirectoryObject& object, const nexus::core::Config& config) {
    if (!should_have_ad_account_material(object)) {
        return;
    }

    const auto kind = lowercase_ascii(object.kind);
    const bool computer = kind == "computer" || has_object_class(object, "computer");
    auto sam = attribute_or_empty(object, "sAMAccountName");
    if (sam.empty()) {
        sam = attribute_or_empty(object, "uid");
    }
    if (sam.empty()) {
        sam = attribute_or_empty(object, "cn");
    }
    if (sam.empty()) {
        sam = first_rdn_value(object.dn);
    }
    if (computer && !sam.empty() && sam.back() != '$') {
        sam += "$";
    }
    if (!sam.empty()) {
        object.attributes["sAMAccountName"] = sam;
    }

    if (!sam.empty() && object.attributes.find("rid") == object.attributes.end()) {
        object.attributes["rid"] = std::to_string(synthetic_rid(sam));
    }
    if (!sam.empty() && object.attributes.find("objectSid") == object.attributes.end()) {
        object.attributes["objectSid"] = synthetic_domain_sid(config.domain) + "-" + object.attributes["rid"];
    }
    if (object.attributes.find("primaryGroupID") == object.attributes.end()) {
        object.attributes["primaryGroupID"] = computer ? "515" : "513";
    }
    if (object.attributes.find("groupRids") == object.attributes.end()) {
        const auto normalized_sam = lowercase_ascii(sam);
        object.attributes["groupRids"] = normalized_sam == "administrator" ? "513,512,544" : object.attributes["primaryGroupID"];
    }
    set_attribute_if_missing(object.attributes, "userAccountControl", computer ? "4128" : "512");
    set_attribute_if_missing(object.attributes, "accountExpires", "9223372036854775807");
    set_attribute_if_missing(object.attributes, "pwdLastSet", "0");
    set_attribute_if_missing(object.attributes, "badPwdCount", "0");
    set_attribute_if_missing(object.attributes, "logonCount", "0");
    set_attribute_if_missing(object.attributes, "msDS-SupportedEncryptionTypes", "28");

    if (computer && !sam.empty()) {
        auto host = sam;
        if (!host.empty() && host.back() == '$') {
            host.pop_back();
        }
        host = lowercase_ascii(host);
        const auto dns_host = attribute_or_empty(object, "dNSHostName").empty()
            ? host + "." + lowercase_ascii(config.domain)
            : attribute_or_empty(object, "dNSHostName");
        object.attributes["dNSHostName"] = dns_host;
        object.attributes["servicePrincipalName"] = merge_machine_spn_attribute(
            attribute_or_empty(object, "servicePrincipalName"),
            host,
            dns_host);
    }

    if (!computer && object.attributes.find("userPrincipalName") == object.attributes.end() && !sam.empty()) {
        object.attributes["userPrincipalName"] = sam + "@" + lowercase_ascii(config.domain);
    }
}

std::map<std::string, std::string> base_ad_attributes(
    const std::string& cn,
    std::uint32_t rid,
    const nexus::core::Config& config,
    const std::string& sid_override = "") {
    return {
        {"cn", cn},
        {"displayName", cn},
        {"objectSid", sid_override.empty() ? synthetic_domain_sid(config.domain) + "-" + std::to_string(rid) : sid_override},
        {"rid", std::to_string(rid)},
        {"sAMAccountName", cn},
    };
}

nexus::core::DirectoryObject make_ad_container(const std::string& cn, const std::string& parent_dn) {
    return {
        "cn=" + cn + "," + parent_dn,
        parent_dn,
        "container",
        {"top", "container"},
        {{"cn", cn}},
    };
}

nexus::core::DirectoryObject make_ad_user_seed(
    const std::string& cn,
    std::uint32_t rid,
    std::uint32_t primary_group,
    std::uint32_t user_account_control,
    const std::string& parent_dn,
    const nexus::core::Config& config,
    const std::string& group_rids = "") {
    auto attributes = base_ad_attributes(cn, rid, config);
    attributes["groupRids"] = group_rids.empty() ? std::to_string(primary_group) : group_rids;
    attributes["primaryGroupID"] = std::to_string(primary_group);
    attributes["userAccountControl"] = std::to_string(user_account_control);
    attributes["userPrincipalName"] = cn + "@" + lowercase_ascii(config.domain);
    return {
        "cn=" + cn + "," + parent_dn,
        parent_dn,
        "user",
        {"top", "person", "organizationalPerson", "user"},
        std::move(attributes),
    };
}

nexus::core::DirectoryObject make_ad_group_seed(
    const std::string& cn,
    std::uint32_t rid,
    const std::string& parent_dn,
    const nexus::core::Config& config,
    const std::string& sid_override = "") {
    auto attributes = base_ad_attributes(cn, rid, config, sid_override);
    attributes["groupType"] = "-2147483646";
    attributes["primaryGroupID"] = "0";
    return {
        "cn=" + cn + "," + parent_dn,
        parent_dn,
        "group",
        {"top", "group"},
        std::move(attributes),
    };
}

nexus::core::DirectoryObject make_ad_dc_computer_seed(const nexus::core::Config& config) {
    const auto host = lowercase_ascii(config.directory.domain_controller_host.empty() ? "dc1" : config.directory.domain_controller_host);
    const auto sam = host + "$";
    const auto dns_host = host + "." + lowercase_ascii(config.domain);
    const auto parent_dn = "cn=Computers," + config.directory.base_dn;
    auto attributes = base_ad_attributes(host, 1000, config);
    attributes["cn"] = host;
    attributes["dNSHostName"] = dns_host;
    attributes["displayName"] = host;
    attributes["groupRids"] = "516,515";
    attributes["objectSid"] = synthetic_domain_sid(config.domain) + "-1000";
    attributes["primaryGroupID"] = "516";
    attributes["sAMAccountName"] = sam;
    attributes["servicePrincipalName"] = machine_spn_attribute(host, dns_host);
    attributes["userAccountControl"] = "532480";
    return {
        "cn=" + host + "," + parent_dn,
        parent_dn,
        "computer",
        {"top", "person", "organizationalPerson", "user", "computer"},
        std::move(attributes),
    };
}

std::vector<nexus::core::DirectoryObject> default_ad_seed_objects(const nexus::core::Config& config) {
    const auto base_dn = config.directory.base_dn;
    const auto users_dn = "cn=Users," + base_dn;
    const auto builtin_dn = "cn=Builtin," + base_dn;
    const auto computers_dn = "cn=Computers," + base_dn;

    std::vector<nexus::core::DirectoryObject> objects;
    objects.push_back(make_ad_container("Users", base_dn));
    objects.push_back(make_ad_container("Builtin", base_dn));
    objects.push_back(make_ad_container("Computers", base_dn));
    objects.push_back(make_ad_user_seed("Administrator", 500, 513, 0x00000200U, users_dn, config, "513,512,544"));
    objects.push_back(make_ad_user_seed("Guest", 501, 514, 0x00000202U, users_dn, config, "514"));
    objects.push_back(make_ad_user_seed("krbtgt", 502, 513, 0x00000202U, users_dn, config, "513"));
    objects.push_back(make_ad_group_seed("Domain Admins", 512, users_dn, config));
    objects.push_back(make_ad_group_seed("Domain Users", 513, users_dn, config));
    objects.push_back(make_ad_group_seed("Domain Guests", 514, users_dn, config));
    objects.push_back(make_ad_group_seed("Domain Computers", 515, users_dn, config));
    objects.push_back(make_ad_group_seed("Domain Controllers", 516, users_dn, config));
    objects.push_back(make_ad_group_seed("Schema Admins", 518, users_dn, config));
    objects.push_back(make_ad_group_seed("Enterprise Admins", 519, users_dn, config));
    objects.push_back(make_ad_group_seed("Group Policy Creator Owners", 520, users_dn, config));
    objects.push_back(make_ad_group_seed("Administrators", 544, builtin_dn, config, "S-1-5-32-544"));
    objects.push_back(make_ad_group_seed("Users", 545, builtin_dn, config, "S-1-5-32-545"));
    objects.push_back(make_ad_group_seed("Guests", 546, builtin_dn, config, "S-1-5-32-546"));
    objects.push_back(make_ad_dc_computer_seed(config));
    return objects;
}

void append_missing_ad_seed_objects(
    std::vector<nexus::core::DirectoryObject>& directory,
    const nexus::core::Config& config) {
    for (auto object : default_ad_seed_objects(config)) {
        const auto exists = std::any_of(directory.begin(), directory.end(), [&](const auto& current) {
            return lowercase_ascii(current.dn) == lowercase_ascii(object.dn);
        });
        if (!exists) {
            directory.push_back(std::move(object));
        }
    }
}

std::optional<std::string> ad_account_principal(const nexus::core::DirectoryObject& object) {
    const auto sam = attribute_or_empty(object, "sAMAccountName");
    if (!sam.empty()) {
        return sam;
    }
    const auto upn = attribute_or_empty(object, "userPrincipalName");
    if (!upn.empty()) {
        const auto at = upn.find('@');
        return at == std::string::npos ? upn : upn.substr(0, at);
    }
    return std::nullopt;
}

std::filesystem::path kerberos_key_file(const nexus::core::Config& config) {
    if (!config.directory.key_encryption_key_file.empty()) {
        return config.directory.key_encryption_key_file;
    }
    return config.state_root / "ad" / "kerberos_keys.hex";
}

std::string wrapped_kerberos_keys_json(
    const nexus::security::AdCredentialMaterial& material,
    const nexus::core::Config& config) {
    Json::Value keys(Json::objectValue);
    for (const auto& key : material.kerberos_keys) {
        keys[key.enctype]["salt"] = key.salt;
        keys[key.enctype]["wrapped"] = nexus::security::seal_ad_secret(kerberos_key_file(config), key.key_hex);
    }
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    return Json::writeString(builder, keys);
}

std::string random_ad_system_password(const std::string& purpose) {
    std::vector<unsigned char> buffer(32);
    if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
        throw std::runtime_error("failed to generate AD system secret");
    }
    std::ostringstream output;
    output << "nexus-ad-" << lowercase_ascii(purpose) << "-";
    output << std::hex << std::setfill('0');
    for (const auto byte : buffer) {
        output << std::setw(2) << static_cast<int>(byte);
    }
    return output.str();
}

bool persist_ad_account_secret_to_connection(
    PGconn* conn,
    const nexus::core::DirectoryObject& object,
    const std::string& password,
    const nexus::core::Config& config) {
    if (password.empty() || config.database_url.empty()) {
        return false;
    }
    const auto principal = ad_account_principal(object);
    if (!principal.has_value()) {
        return false;
    }

    try {
        const auto material = nexus::security::derive_ad_credentials(password, config.directory.realm, *principal);
        const auto wrapped_nt_hash = nexus::security::seal_ad_secret(kerberos_key_file(config), material.nt_hash_hex);
        const auto wrapped_kerberos_keys = wrapped_kerberos_keys_json(material, config);

        const std::string sql =
            "INSERT INTO ad_account_secrets(object_dn,wrapped_nt_hash,wrapped_kerberos_keys,updated_at) VALUES (" +
            sql_literal(conn, object.dn) + "," +
            sql_literal(conn, wrapped_nt_hash) + "," +
            sql_literal(conn, wrapped_kerberos_keys) + "::jsonb,now()) "
            "ON CONFLICT (object_dn) DO UPDATE SET "
            "wrapped_nt_hash=excluded.wrapped_nt_hash, "
            "wrapped_kerberos_keys=excluded.wrapped_kerberos_keys, "
            "updated_at=now();";
        PGresult* result = PQexec(conn, sql.c_str());
        const bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
        if (!ok) {
            std::cerr << "[nexus-api] failed to persist AD account secret: " << PQresultErrorMessage(result) << '\n';
        }
        PQclear(result);
        return ok && stamp_ad_password_metadata_to_database(conn, object.dn);
    } catch (const std::exception& error) {
        std::cerr << "[nexus-api] failed to derive AD account secret: " << error.what() << '\n';
        return false;
    }
}

void persist_ad_account_secret_to_database(
    const nexus::core::DirectoryObject& object,
    const std::string& password,
    const nexus::core::Config& config) {
    PGconn* conn = connect_database(config.database_url);
    if (conn == nullptr) {
        return;
    }
    persist_ad_account_secret_to_connection(conn, object, password, config);
    PQfinish(conn);
}

bool ad_account_secret_exists(PGconn* conn, const std::string& object_dn) {
    const std::string sql =
        "SELECT 1 FROM ad_account_secrets WHERE object_dn = " + sql_literal(conn, object_dn) + " LIMIT 1;";
    PGresult* result = PQexec(conn, sql.c_str());
    const bool exists = PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) > 0;
    PQclear(result);
    return exists;
}

const nexus::core::DirectoryObject* find_directory_object_by_sam(
    const std::vector<nexus::core::DirectoryObject>& directory,
    const std::string& sam_account_name) {
    const auto expected = lowercase_ascii(sam_account_name);
    const auto match = std::find_if(directory.begin(), directory.end(), [&](const auto& object) {
        const auto sam = attribute_or_empty(object, "sAMAccountName");
        return !sam.empty() && lowercase_ascii(sam) == expected;
    });
    return match == directory.end() ? nullptr : &*match;
}

bool ensure_system_ad_secret(
    PGconn* conn,
    const std::vector<nexus::core::DirectoryObject>& directory,
    const nexus::core::Config& config,
    const std::string& sam_account_name) {
    const auto* object = find_directory_object_by_sam(directory, sam_account_name);
    if (object == nullptr) {
        std::cerr << "[nexus-api] cannot bootstrap AD secret for missing account " << sam_account_name << '\n';
        return false;
    }
    if (ad_account_secret_exists(conn, object->dn)) {
        return true;
    }
    return persist_ad_account_secret_to_connection(
        conn,
        *object,
        random_ad_system_password(sam_account_name),
        config);
}

bool bootstrap_system_ad_secrets(
    const std::vector<nexus::core::DirectoryObject>& directory,
    const nexus::core::Config& config) {
    PGconn* conn = connect_database(config.database_url);
    if (conn == nullptr) {
        return false;
    }

    const auto dc_sam = lowercase_ascii(config.directory.domain_controller_host.empty()
        ? std::string{"dc1$"}
        : config.directory.domain_controller_host + "$");
    const bool ok =
        ensure_system_ad_secret(conn, directory, config, "krbtgt") &&
        ensure_system_ad_secret(conn, directory, config, dc_sam);
    PQfinish(conn);
    return ok;
}

void move_ad_account_secret_dn(const std::string& old_dn, const std::string& new_dn, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string sql =
        "UPDATE ad_account_secrets SET object_dn = " + sql_literal(conn, new_dn) +
        ", updated_at = now() WHERE object_dn = " + sql_literal(conn, old_dn) + ";";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to move AD account secret: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

std::string sql_nullable_literal(PGconn* conn, const std::string& value) {
    return value.empty() ? std::string{"NULL"} : sql_literal(conn, value);
}

std::string sql_nullable_bigint(const std::string& value) {
    if (value.empty()) {
        return "NULL";
    }
    try {
        return std::to_string(std::stoll(value));
    } catch (...) {
        return "NULL";
    }
}

bool exec_ad_schema_command(PGconn* conn, const std::string& description, const char* sql) {
    PGresult* result = PQexec(conn, sql);
    const bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    if (!ok) {
        std::cerr << "[nexus-api] failed to " << description << ": "
                  << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    return ok;
}

bool ensure_ad_domains_schema(PGconn* conn) {
    const char* domain_table_sql = R"SQL(
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
    )SQL";
    if (!exec_ad_schema_command(conn, "ensure AD domain table", domain_table_sql)) {
        return false;
    }

    const char* domain_columns_sql = R"SQL(
        alter table ad_domains add column if not exists domain_guid uuid not null default gen_random_uuid();
        alter table ad_domains add column if not exists invocation_id uuid not null default gen_random_uuid();
        alter table ad_domains add column if not exists site_name text not null default 'Default-First-Site-Name';
        alter table ad_domains add column if not exists dc_host text not null default 'dc1';
        alter table ad_domains add column if not exists dc_address inet;
        alter table ad_domains add column if not exists next_rid bigint not null default 1000;
        update ad_domains set site_name = 'Default-First-Site-Name' where site_name is null or site_name = '';
        update ad_domains set dc_host = 'dc1' where dc_host is null or dc_host = '';
        update ad_domains set next_rid = 1000 where next_rid is null or next_rid < 1000;
    )SQL";
    return exec_ad_schema_command(conn, "repair AD domain columns", domain_columns_sql);
}

bool result_sqlstate_is(PGresult* result, const char* expected) {
    const char* sqlstate = PQresultErrorField(result, PG_DIAG_SQLSTATE);
    return sqlstate != nullptr && std::string{sqlstate} == expected;
}

std::string first_rdn(const std::string& dn) {
    const auto comma = dn.find(',');
    return comma == std::string::npos ? dn : dn.substr(0, comma);
}

bool ensure_ad_domain_row(PGconn* conn, const nexus::core::Config& config) {
    if (!ensure_ad_domains_schema(conn)) {
        return false;
    }

    const char* schema_sql = R"SQL(
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
    )SQL";
    PGresult* schema_result = PQexec(conn, schema_sql);
    if (PQresultStatus(schema_result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to ensure AD database schema: " << PQresultErrorMessage(schema_result) << '\n';
        PQclear(schema_result);
        return false;
    }
    PQclear(schema_result);

    const std::string sql =
        "INSERT INTO ad_domains(dns_name,netbios_name,realm,base_dn,domain_sid,site_name,dc_host,dc_address) VALUES (" +
        sql_literal(conn, config.domain) + "," +
        sql_literal(conn, netbios_name_from_domain(config.domain)) + "," +
        sql_literal(conn, config.directory.realm) + "," +
        sql_literal(conn, config.directory.base_dn) + "," +
        sql_literal(conn, synthetic_domain_sid(config.domain)) + "," +
        sql_literal(conn, config.directory.site_name) + "," +
        sql_literal(conn, config.directory.domain_controller_host) + "," +
        sql_nullable_literal(conn, config.directory.domain_controller_address) + "::inet) "
        "ON CONFLICT (dns_name) DO UPDATE SET "
        "netbios_name=excluded.netbios_name, "
        "realm=excluded.realm, "
        "base_dn=excluded.base_dn, "
        "domain_sid=excluded.domain_sid, "
        "site_name=excluded.site_name, "
        "dc_host=excluded.dc_host, "
        "dc_address=excluded.dc_address;";
    PGresult* result = PQexec(conn, sql.c_str());
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    const bool can_retry_schema_repair = !ok && result_sqlstate_is(result, "42703");
    if (!ok && can_retry_schema_repair) {
        std::cerr << "[nexus-api] AD domain schema is missing a column during upsert; repairing and retrying\n";
    }
    PQclear(result);
    if (!ok && can_retry_schema_repair && ensure_ad_domains_schema(conn)) {
        result = PQexec(conn, sql.c_str());
        ok = PQresultStatus(result) == PGRES_COMMAND_OK;
        if (!ok) {
            std::cerr << "[nexus-api] failed to persist AD domain row after schema repair: "
                      << PQresultErrorMessage(result) << '\n';
        }
        PQclear(result);
    } else if (!ok) {
        std::cerr << "[nexus-api] failed to persist AD domain row: " << PQresultErrorMessage(result) << '\n';
    }
    return ok;
}

void persist_directory_object_to_connection(
    PGconn* conn,
    const nexus::core::DirectoryObject& object,
    const nexus::core::Config& config) {
    if (!ensure_ad_domain_row(conn, config)) {
        return;
    }

    const auto object_classes = json_string_array(object.object_classes);
    const auto attributes = json_string_object(object.attributes);
    const auto object_sid = attribute_or_empty(object, "objectSid");
    const auto rid = attribute_or_empty(object, "rid");
    const std::string identity_sql =
        "INSERT INTO identity_objects(dn,parent_dn,kind,object_classes,attributes,updated_at) VALUES (" +
        sql_literal(conn, object.dn) + "," +
        sql_literal(conn, object.parent_dn) + "," +
        sql_literal(conn, object.kind) + "," +
        sql_literal(conn, object_classes) + "::jsonb," +
        sql_literal(conn, attributes) + "::jsonb,now()) "
        "ON CONFLICT (dn) DO UPDATE SET parent_dn=excluded.parent_dn, kind=excluded.kind, "
        "object_classes=excluded.object_classes, attributes=excluded.attributes, updated_at=now();";
    PGresult* identity_result = PQexec(conn, identity_sql.c_str());
    if (PQresultStatus(identity_result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist directory object projection: " << PQresultErrorMessage(identity_result) << '\n';
    }
    PQclear(identity_result);

    const std::string ad_sql =
        "INSERT INTO ad_objects(domain_dns_name,dn,parent_dn,rdn,kind,object_sid,rid,object_classes,attributes,when_changed,uSNChanged) VALUES (" +
        sql_literal(conn, config.domain) + "," +
        sql_literal(conn, object.dn) + "," +
        sql_nullable_literal(conn, object.parent_dn) + "," +
        sql_literal(conn, first_rdn(object.dn)) + "," +
        sql_literal(conn, object.kind) + "," +
        sql_nullable_literal(conn, object_sid) + "," +
        sql_nullable_bigint(rid) + "," +
        sql_literal(conn, object_classes) + "::jsonb," +
        sql_literal(conn, attributes) + "::jsonb,now(),nextval('ad_usn_sequence')) "
        "ON CONFLICT (dn) DO UPDATE SET "
        "domain_dns_name=excluded.domain_dns_name, "
        "parent_dn=excluded.parent_dn, "
        "rdn=excluded.rdn, "
        "kind=excluded.kind, "
        "object_sid=excluded.object_sid, "
        "rid=excluded.rid, "
        "object_classes=excluded.object_classes, "
        "attributes=excluded.attributes, "
        "when_changed=now(), "
        "uSNChanged=nextval('ad_usn_sequence');";
    PGresult* ad_result = PQexec(conn, ad_sql.c_str());
    if (PQresultStatus(ad_result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist canonical AD object: " << PQresultErrorMessage(ad_result) << '\n';
    }
    PQclear(ad_result);

    const std::string delete_spn_sql =
        "DELETE FROM ad_service_principals WHERE object_dn = " + sql_literal(conn, object.dn) + ";";
    PGresult* delete_spn_result = PQexec(conn, delete_spn_sql.c_str());
    PQclear(delete_spn_result);
    for (const auto& spn : split_multi_value_attribute(attribute_or_empty(object, "servicePrincipalName"))) {
        const std::string spn_sql =
            "INSERT INTO ad_service_principals(principal,object_dn,created_at) VALUES (" +
            sql_literal(conn, spn) + "," +
            sql_literal(conn, object.dn) + ",now()) "
            "ON CONFLICT (principal) DO UPDATE SET object_dn=excluded.object_dn;";
        PGresult* spn_result = PQexec(conn, spn_sql.c_str());
        PQclear(spn_result);
    }
}

void persist_directory_object_to_database(
    const nexus::core::DirectoryObject& object,
    const nexus::core::Config& config) {
    PGconn* conn = connect_database(config.database_url);
    if (conn == nullptr) {
        return;
    }
    persist_directory_object_to_connection(conn, object, config);
    PQfinish(conn);
}

void delete_directory_object_from_database(const std::string& dn, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string delete_secrets_sql = "DELETE FROM ad_account_secrets WHERE object_dn = " + sql_literal(conn, dn) + ";";
    PGresult* secrets_result = PQexec(conn, delete_secrets_sql.c_str());
    PQclear(secrets_result);

    const std::string delete_spn_sql = "DELETE FROM ad_service_principals WHERE object_dn = " + sql_literal(conn, dn) + ";";
    PGresult* spn_result = PQexec(conn, delete_spn_sql.c_str());
    PQclear(spn_result);

    const std::string delete_memberships_sql =
        "DELETE FROM ad_memberships WHERE group_dn = " + sql_literal(conn, dn) +
        " OR member_dn = " + sql_literal(conn, dn) + ";";
    PGresult* memberships_result = PQexec(conn, delete_memberships_sql.c_str());
    PQclear(memberships_result);

    const std::string ad_sql = "DELETE FROM ad_objects WHERE dn = " + sql_literal(conn, dn) + ";";
    PGresult* ad_result = PQexec(conn, ad_sql.c_str());
    if (PQresultStatus(ad_result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to delete canonical AD object: " << PQresultErrorMessage(ad_result) << '\n';
    }
    PQclear(ad_result);

    const std::string sql = "DELETE FROM identity_objects WHERE dn = " + sql_literal(conn, dn) + ";";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to delete directory object projection: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

std::vector<nexus::core::DirectoryObject> directory_objects_from_query(PGresult* result) {
    std::vector<nexus::core::DirectoryObject> objects;
    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        return objects;
    }
    for (int row = 0; row < PQntuples(result); ++row) {
        nexus::core::DirectoryObject object;
        object.dn = PQgetisnull(result, row, 0) ? "" : PQgetvalue(result, row, 0);
        object.parent_dn = PQgetisnull(result, row, 1) ? "" : PQgetvalue(result, row, 1);
        object.kind = PQgetisnull(result, row, 2) ? "" : PQgetvalue(result, row, 2);
        object.object_classes = json_array_from_string(PQgetisnull(result, row, 3) ? "[]" : PQgetvalue(result, row, 3));
        object.attributes = json_object_from_string(PQgetisnull(result, row, 4) ? "{}" : PQgetvalue(result, row, 4));
        if (!object.dn.empty() && !object.kind.empty() && !object.object_classes.empty()) {
            objects.push_back(std::move(object));
        }
    }
    return objects;
}

std::vector<nexus::core::DirectoryObject> load_directory_objects_from_database(const nexus::core::Config& config) {
    std::vector<nexus::core::DirectoryObject> objects;
    PGconn* conn = connect_database(config.database_url);
    if (conn == nullptr) {
        return objects;
    }

    const std::string ad_sql =
        "SELECT dn, coalesce(parent_dn,''), kind, object_classes::text, attributes::text "
        "FROM ad_objects WHERE domain_dns_name = " + sql_literal(conn, config.domain) + " ORDER BY dn";
    PGresult* ad_result = PQexec(conn, ad_sql.c_str());
    objects = directory_objects_from_query(ad_result);
    PQclear(ad_result);

    if (objects.empty()) {
        PGresult* identity_result = PQexec(
            conn,
            "SELECT dn, coalesce(parent_dn,''), kind, object_classes::text, attributes::text "
            "FROM identity_objects ORDER BY dn");
        objects = directory_objects_from_query(identity_result);
        PQclear(identity_result);
        for (const auto& object : objects) {
            persist_directory_object_to_connection(conn, object, config);
        }
    }

    PQfinish(conn);
    return objects;
}

PlatformState::ActiveDirectoryObject active_directory_object_from_directory_object(
    const nexus::core::Config& config,
    const nexus::core::DirectoryObject& object) {
    PlatformState::ActiveDirectoryObject ad_object;
    ad_object.object_guid = stable_guid_from_key(config.domain + "|" + object.dn);
    ad_object.domain_dns_name = config.domain;
    ad_object.dn = object.dn;
    ad_object.parent_dn = object.parent_dn;
    ad_object.rdn = first_rdn(object.dn);
    ad_object.kind = object.kind;
    ad_object.object_sid = attribute_or_empty(object, "objectSid");
    ad_object.rid = parse_u64_or_zero(attribute_or_empty(object, "rid"));
    ad_object.usn_created = 1;
    ad_object.usn_changed = 1;
    ad_object.object_classes = object.object_classes;

    ad_object.attributes.push_back(make_ad_attribute("objectGUID", {ad_object.object_guid}));
    if (!ad_object.object_sid.empty()) {
        ad_object.attributes.push_back(make_ad_attribute("objectSid", {ad_object.object_sid}));
    }
    if (!ad_object.object_classes.empty()) {
        ad_object.attributes.push_back(make_ad_attribute("objectClass", ad_object.object_classes));
    }
    for (const auto& [name, value] : object.attributes) {
        if (is_sensitive_ad_attribute(name) || equals_ascii_case(name, "objectSid")) {
            continue;
        }
        auto attribute = make_ad_attribute(name, ad_attribute_values(name, value));
        if (!attribute.values.empty()) {
            ad_object.attributes.push_back(std::move(attribute));
        }
    }
    return ad_object;
}

std::vector<PlatformState::ActiveDirectoryObject> active_directory_objects_from_directory(
    const nexus::core::Config& config,
    const std::vector<nexus::core::DirectoryObject>& directory) {
    std::vector<PlatformState::ActiveDirectoryObject> objects;
    objects.reserve(directory.size());
    for (const auto& object : directory) {
        objects.push_back(active_directory_object_from_directory_object(config, object));
    }
    return objects;
}

std::vector<PlatformState::ActiveDirectoryObject> active_directory_objects_from_query(PGresult* result) {
    std::vector<PlatformState::ActiveDirectoryObject> objects;
    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        return objects;
    }
    for (int row = 0; row < PQntuples(result); ++row) {
        PlatformState::ActiveDirectoryObject object;
        object.object_guid = PQgetisnull(result, row, 0) ? "" : PQgetvalue(result, row, 0);
        object.domain_dns_name = PQgetisnull(result, row, 1) ? "" : PQgetvalue(result, row, 1);
        object.dn = PQgetisnull(result, row, 2) ? "" : PQgetvalue(result, row, 2);
        object.parent_dn = PQgetisnull(result, row, 3) ? "" : PQgetvalue(result, row, 3);
        object.rdn = PQgetisnull(result, row, 4) ? "" : PQgetvalue(result, row, 4);
        object.kind = PQgetisnull(result, row, 5) ? "" : PQgetvalue(result, row, 5);
        object.object_sid = PQgetisnull(result, row, 6) ? "" : PQgetvalue(result, row, 6);
        object.rid = parse_u64_or_zero(PQgetisnull(result, row, 7) ? "" : PQgetvalue(result, row, 7));
        object.object_classes = json_array_from_string(PQgetisnull(result, row, 8) ? "[]" : PQgetvalue(result, row, 8));
        const auto attributes = json_object_from_string(PQgetisnull(result, row, 9) ? "{}" : PQgetvalue(result, row, 9));
        object.when_created = PQgetisnull(result, row, 10) ? "" : PQgetvalue(result, row, 10);
        object.when_changed = PQgetisnull(result, row, 11) ? "" : PQgetvalue(result, row, 11);
        object.usn_created = parse_u64_or_zero(PQgetisnull(result, row, 12) ? "" : PQgetvalue(result, row, 12));
        object.usn_changed = parse_u64_or_zero(PQgetisnull(result, row, 13) ? "" : PQgetvalue(result, row, 13));

        object.attributes.push_back(make_ad_attribute("objectGUID", {object.object_guid}));
        if (!object.object_sid.empty()) {
            object.attributes.push_back(make_ad_attribute("objectSid", {object.object_sid}));
        }
        if (!object.object_classes.empty()) {
            object.attributes.push_back(make_ad_attribute("objectClass", object.object_classes));
        }
        for (const auto& [name, value] : attributes) {
            if (is_sensitive_ad_attribute(name) ||
                equals_ascii_case(name, "objectGUID") ||
                equals_ascii_case(name, "objectSid") ||
                equals_ascii_case(name, "objectClass")) {
                continue;
            }
            auto attribute = make_ad_attribute(name, ad_attribute_values(name, value));
            if (!attribute.values.empty()) {
                object.attributes.push_back(std::move(attribute));
            }
        }
        objects.push_back(std::move(object));
    }
    return objects;
}

std::vector<PlatformState::ActiveDirectoryObject> load_active_directory_objects_from_database(
    const nexus::core::Config& config) {
    std::vector<PlatformState::ActiveDirectoryObject> objects;
    PGconn* conn = connect_database(config.database_url);
    if (conn == nullptr) {
        return objects;
    }

    const std::string sql =
        "SELECT object_guid::text, domain_dns_name, dn, coalesce(parent_dn,''), rdn, kind, "
        "coalesce(object_sid,''), coalesce(rid::text,''), object_classes::text, attributes::text, "
        "when_created::text, when_changed::text, uSNCreated::text, uSNChanged::text "
        "FROM ad_objects WHERE domain_dns_name = " + sql_literal(conn, config.domain) + " ORDER BY dn";
    PGresult* result = PQexec(conn, sql.c_str());
    objects = active_directory_objects_from_query(result);
    PQclear(result);
    PQfinish(conn);
    return objects;
}

void persist_pki_authority_to_database(const nexus::core::PkiAuthority& authority, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string sql =
        "INSERT INTO pki_authorities(name,certificate_pem,private_key_pem,created_at) VALUES (" +
        sql_literal(conn, authority.name) + "," +
        sql_literal(conn, authority.certificate_pem) + "," +
        sql_literal(conn, authority.private_key_pem) + ",now()) "
        "ON CONFLICT (name) DO UPDATE SET certificate_pem=excluded.certificate_pem, private_key_pem=excluded.private_key_pem;";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist pki authority: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

void persist_pki_certificate_to_database(const nexus::core::PkiCertificate& certificate, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string authority_sql = "SELECT id FROM pki_authorities WHERE name = " + sql_literal(conn, certificate.authority_name) + " LIMIT 1;";
    PGresult* authority_result = PQexec(conn, authority_sql.c_str());
    if (PQresultStatus(authority_result) != PGRES_TUPLES_OK || PQntuples(authority_result) == 0) {
        PQclear(authority_result);
        PQfinish(conn);
        return;
    }
    const std::string authority_id = PQgetvalue(authority_result, 0, 0);
    PQclear(authority_result);
    const std::string sql =
        "INSERT INTO pki_certificates(serial,authority_id,common_name,certificate_pem,revoked,created_at) VALUES (" +
        sql_literal(conn, certificate.serial_hex) + "," + authority_id + "," +
        sql_literal(conn, certificate.common_name) + "," +
        sql_literal(conn, certificate.certificate_pem) + "," +
        std::string(certificate.revoked ? "true" : "false") + ",now()) "
        "ON CONFLICT (serial) DO UPDATE SET common_name=excluded.common_name, certificate_pem=excluded.certificate_pem, revoked=excluded.revoked;";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist pki certificate: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

void persist_pki_revocation_to_database(const nexus::core::PkiRevocation& revocation, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string update_sql = "UPDATE pki_certificates SET revoked = true WHERE serial = " + sql_literal(conn, revocation.serial) + ";";
    PGresult* update = PQexec(conn, update_sql.c_str());
    PQclear(update);
    const std::string sql =
        "INSERT INTO pki_revocations(serial,reason,revoked_at) VALUES (" +
        sql_literal(conn, revocation.serial) + "," +
        sql_literal(conn, revocation.reason) + ",now()) ON CONFLICT (serial) DO UPDATE SET reason=excluded.reason, revoked_at=now();";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist pki revocation: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

void load_repositories_from_database(std::vector<nexus::core::AptRepository>& target, const std::string& database_url) {
    PGconn* connection = connect_database(database_url);
    if (connection == nullptr) {
        return;
    }

    PGresult* repo_result = PQexec(connection, "SELECT distribution, component FROM repo_repositories ORDER BY distribution, component ASC;");
    if (PQresultStatus(repo_result) == PGRES_TUPLES_OK) {
        const int rows = PQntuples(repo_result);
        for (int i = 0; i < rows; ++i) {
            target.push_back({
                PQgetvalue(repo_result, i, 0),
                PQgetvalue(repo_result, i, 1),
                {}
            });
        }
    }
    PQclear(repo_result);

    PGresult* pkg_result = PQexec(
        connection,
        "SELECT id::text, distribution, component, name, version, architecture, filename, "
        "coalesce(storage_path, filename), sha256, size::text, coalesce(control_json, '{}'::jsonb)::text, "
        "coalesce(uploaded_by, 'system'), coalesce(uploaded_at, now())::text "
        "FROM repo_packages ORDER BY distribution, component, name, version;");
    if (PQresultStatus(pkg_result) == PGRES_TUPLES_OK) {
        const int rows = PQntuples(pkg_result);
        for (int i = 0; i < rows; ++i) {
            const std::string dist = PQgetvalue(pkg_result, i, 1);
            const std::string comp = PQgetvalue(pkg_result, i, 2);
            for (auto& repo : target) {
                if (repo.distribution == dist && repo.component == comp) {
                    nexus::core::AptPackage pkg;
                    pkg.id = PQgetvalue(pkg_result, i, 0);
                    pkg.name = PQgetvalue(pkg_result, i, 3);
                    pkg.version = PQgetvalue(pkg_result, i, 4);
                    pkg.architecture = PQgetvalue(pkg_result, i, 5);
                    pkg.component = comp;
                    pkg.filename = PQgetvalue(pkg_result, i, 6);
                    pkg.storage_path = PQgetvalue(pkg_result, i, 7);
                    pkg.sha256 = PQgetvalue(pkg_result, i, 8);
                    pkg.size = std::stoull(PQgetvalue(pkg_result, i, 9));
                    pkg.control_json = PQgetvalue(pkg_result, i, 10);
                    pkg.uploaded_by = PQgetvalue(pkg_result, i, 11);
                    pkg.uploaded_at = PQgetvalue(pkg_result, i, 12);
                    pkg.download_url = "/apt/" + (pkg.storage_path.empty() ? pkg.filename : pkg.storage_path);
                    repo.packages.push_back(std::move(pkg));
                    break;
                }
            }
        }
    }
    PQclear(pkg_result);

    PQfinish(connection);
}

void persist_apt_repository_to_database(const nexus::core::AptRepository& repository, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string sql =
        "INSERT INTO repo_repositories(distribution,component) VALUES (" +
        sql_literal(conn, repository.distribution) + "," + sql_literal(conn, repository.component) + ") "
        "ON CONFLICT (distribution,component) DO NOTHING;";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist apt repository: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

void persist_apt_package_to_database(
    const std::string& distribution,
    const std::string& component,
    const nexus::core::AptPackage& package,
    const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const auto storage_path = package.storage_path.empty() ? package.filename : package.storage_path;
    const auto control_json = package.control_json.empty() ? std::string{"{}"} : package.control_json;
    const auto uploaded_by = package.uploaded_by.empty() ? std::string{"system"} : package.uploaded_by;
    const std::string sql =
        "INSERT INTO repo_packages(distribution,component,name,version,architecture,filename,sha256,size,storage_path,control_json,uploaded_by) VALUES (" +
        sql_literal(conn, distribution) + "," + sql_literal(conn, component) + "," +
        sql_literal(conn, package.name) + "," + sql_literal(conn, package.version) + "," +
        sql_literal(conn, package.architecture) + "," + sql_literal(conn, package.filename) + "," +
        sql_literal(conn, package.sha256) + "," + std::to_string(package.size) + "," +
        sql_literal(conn, storage_path) + "," + sql_literal(conn, control_json) + "::jsonb," +
        sql_literal(conn, uploaded_by) + ") "
        "ON CONFLICT (distribution, component, name, version, architecture) DO UPDATE SET "
        "filename = excluded.filename, "
        "sha256 = excluded.sha256, "
        "size = excluded.size, "
        "storage_path = excluded.storage_path, "
        "control_json = excluded.control_json, "
        "uploaded_by = excluded.uploaded_by, "
        "uploaded_at = now();";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist apt package: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

bool sync_feature_flags(PGconn* connection, const std::map<std::string, bool>& flags) {
    if (!ensure_feature_flags_table(connection)) {
        return false;
    }

    PGresult* begin = PQexec(connection, "begin");
    if (PQresultStatus(begin) != PGRES_COMMAND_OK) {
        PQclear(begin);
        return false;
    }
    PQclear(begin);

    bool ok = true;
    for (const auto& service : nexus::core::service_definitions()) {
        if (service.feature_flag.empty()) {
            continue;
        }

        const auto it = flags.find(service.feature_flag);
        const bool enabled = it != flags.end() && it->second;
        const std::string sql = "insert into feature_flags(service_id, enabled, updated_at) values('" + service.feature_flag + "', " + (enabled ? std::string{"true"} : std::string{"false"}) + ", now()) on conflict(service_id) do update set enabled = excluded.enabled, updated_at = now()";
        PGresult* result = PQexec(connection, sql.c_str());
        if (PQresultStatus(result) != PGRES_COMMAND_OK) {
            ok = false;
        }
        PQclear(result);
        if (!ok) {
            break;
        }
    }

    PGresult* end = PQexec(connection, ok ? "commit" : "rollback");
    const bool committed = PQresultStatus(end) == PGRES_COMMAND_OK;
    PQclear(end);
    return ok && committed;
}

std::map<std::string, bool> load_feature_flags(PGconn* connection) {
    std::map<std::string, bool> flags;
    if (!ensure_feature_flags_table(connection)) {
        return flags;
    }

    PGresult* result = PQexec(connection, "select service_id, enabled from feature_flags");
    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        PQclear(result);
        return flags;
    }

    const int rows = PQntuples(result);
    for (int index = 0; index < rows; ++index) {
        const std::string service_id = PQgetvalue(result, index, 0);
        const std::string enabled = PQgetvalue(result, index, 1);
        flags[service_id] = enabled == "t" || enabled == "true" || enabled == "1";
    }
    PQclear(result);
    return flags;
}

std::vector<nexus::core::ServiceStatus> make_services(const nexus::core::Config& config) {
    const auto enabled_for = [&](const std::string& id) {
        auto it = config.features.find(id);
        if (it == config.features.end()) {
            return false;
        }
        return it->second;
    };

    const auto service_state = [&](bool enabled) {
        return enabled ? "healthy" : "disabled";
    };

    std::vector<nexus::core::ServiceStatus> services;
    const auto definitions = nexus::core::service_definitions();
    services.reserve(definitions.size());

    for (const auto& definition : definitions) {
        const bool enabled = definition.feature_flag.empty() ? true : enabled_for(definition.feature_flag);
        services.push_back({
            definition.id,
            definition.label,
            service_state(enabled),
            enabled ? definition.enabled_summary : definition.disabled_summary,
            definition.endpoints(config),
            definition.capabilities,
            definition.critical,
            enabled,
            get_service_blocking_reason(definition.id, config.database_url)
        });
    }

    return services;
}

bool is_valid_zone_name(const std::string& zone_name) {
    if (zone_name.empty() || zone_name.front() == '.' || zone_name.back() == '.') {
        return false;
    }
    bool seen_dot = false;
    for (char c : zone_name) {
        if (c == '.') {
            seen_dot = true;
            continue;
        }
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-') {
            continue;
        }
        return false;
    }
    return seen_dot;
}

std::uint64_t default_zone_serial() {
    return 1;
}

Json::Value config_to_json_value(const nexus::core::Config& config) {
    Json::Value node(Json::objectValue);
    node["environment"] = config.environment;
    node["domain"] = config.domain;
    node["adPortProfile"] = config.ad_port_profile;
    node["blobRoot"] = config.blob_root.string();
    node["stateRoot"] = config.state_root.string();
    node["databaseUrl"] = config.database_url;
    node["sqlMigrationsDir"] = config.sql_migrations_dir.string();
    node["adminEmail"] = config.admin_email;
    node["adminPasswordHash"] = config.admin_password_hash;
    node["adminTotpSecret"] = config.admin_totp_secret;
    node["ports"]["http"] = config.http.port;
    node["ports"]["ldap"] = config.ldap.port;
    node["ports"]["ldaps"] = config.ldaps.port;
    node["ports"]["gc"] = config.gc.port;
    node["ports"]["kerberos"] = config.kerberos.port;
    node["ports"]["kpasswd"] = config.kpasswd.port;
    node["ports"]["rpc"] = config.rpc.port;
    node["ports"]["smb"] = config.smb.port;
    node["ports"]["dnsTcp"] = config.dns_tcp.port;
    node["ports"]["dnsUdp"] = config.dns_udp.port;
    node["ports"]["dhcp"] = config.dhcp.port;
    node["directory"]["baseDn"] = config.directory.base_dn;
    node["directory"]["organization"] = config.directory.organization;
    node["directory"]["realm"] = config.directory.realm;
    node["directory"]["siteName"] = config.directory.site_name;
    node["directory"]["domainControllerHost"] = config.directory.domain_controller_host;
    node["directory"]["domainControllerAddress"] = config.directory.domain_controller_address;
    node["directory"]["keyEncryptionKeyFile"] = config.directory.key_encryption_key_file.string();
    node["dns"]["primaryNs"] = config.dns.primary_ns;
    node["dns"]["adminMailbox"] = config.dns.admin_mailbox;
    node["dns"]["defaultTtl"] = Json::UInt(config.dns.default_ttl);
    node["dhcp"]["subnet"] = config.dhcp_service.subnet;
    node["dhcp"]["rangeStart"] = config.dhcp_service.range_start;
    node["dhcp"]["rangeEnd"] = config.dhcp_service.range_end;
    node["dhcp"]["router"] = config.dhcp_service.router;
    node["pki"]["organization"] = config.pki.organization;
    node["pki"]["commonName"] = config.pki.common_name;
    node["pki"]["leafDaysValid"] = config.pki.leaf_days_valid;
    node["repo"]["origin"] = config.repo.origin;
    node["repo"]["distribution"] = config.repo.distribution;
    node["repo"]["component"] = config.repo.component;
    Json::Value features(Json::objectValue);
    for (const auto& [k, v] : config.features) {
        features[k] = v;
    }
    node["features"] = features;
    return node;
}

nexus::core::Config config_from_json_value(const nexus::core::Config& current, const Json::Value& body) {
    auto read_string = [&](const char* key, const std::string& fallback) {
        return body.isMember(key) ? body[key].asString() : fallback;
    };

    auto read_port = [&](const char* key, int fallback) {
        if (!body.isMember(key)) {
            return fallback;
        }
        const int value = body[key].asInt();
        return value > 0 ? value : fallback;
    };

    nexus::core::Config updated = current;
    updated.environment = read_string("environment", current.environment);
    updated.domain = read_string("domain", current.domain);
    updated.ad_port_profile = read_string("adPortProfile", current.ad_port_profile);
    if (updated.ad_port_profile != "standard") {
        updated.ad_port_profile = "dev";
    }
    updated.blob_root = read_string("blobRoot", current.blob_root.string());
    updated.state_root = read_string("stateRoot", current.state_root.string());
    updated.database_url = read_string("databaseUrl", current.database_url);
    updated.sql_migrations_dir = read_string("sqlMigrationsDir", current.sql_migrations_dir.string());
    updated.admin_email = read_string("adminEmail", current.admin_email);
    updated.admin_password_hash = read_string("adminPasswordHash", current.admin_password_hash);
    updated.admin_totp_secret = read_string("adminTotpSecret", current.admin_totp_secret);
    updated.http.port = read_port("httpPort", current.http.port);
    updated.ldap.port = read_port("ldapPort", current.ldap.port);
    updated.ldaps.port = read_port("ldapsPort", current.ldaps.port);
    updated.gc.port = read_port("gcPort", current.gc.port);
    updated.kerberos.port = read_port("kerberosPort", current.kerberos.port);
    updated.kpasswd.port = read_port("kpasswdPort", current.kpasswd.port);
    updated.rpc.port = read_port("rpcPort", current.rpc.port);
    updated.smb.port = read_port("smbPort", current.smb.port);
    updated.dns_tcp.port = read_port("dnsTcpPort", current.dns_tcp.port);
    updated.dns_udp.port = read_port("dnsUdpPort", current.dns_udp.port);
    updated.dhcp.port = read_port("dhcpPort", current.dhcp.port);
    if (body.isMember("ports") && body["ports"].isObject()) {
        const auto& ports = body["ports"];
        if (ports.isMember("http")) updated.http.port = ports["http"].asInt();
        if (ports.isMember("ldap")) updated.ldap.port = ports["ldap"].asInt();
        if (ports.isMember("ldaps")) updated.ldaps.port = ports["ldaps"].asInt();
        if (ports.isMember("gc")) updated.gc.port = ports["gc"].asInt();
        if (ports.isMember("kerberos")) updated.kerberos.port = ports["kerberos"].asInt();
        if (ports.isMember("kpasswd")) updated.kpasswd.port = ports["kpasswd"].asInt();
        if (ports.isMember("rpc")) updated.rpc.port = ports["rpc"].asInt();
        if (ports.isMember("smb")) updated.smb.port = ports["smb"].asInt();
        if (ports.isMember("dnsTcp")) updated.dns_tcp.port = ports["dnsTcp"].asInt();
        if (ports.isMember("dnsUdp")) updated.dns_udp.port = ports["dnsUdp"].asInt();
        if (ports.isMember("dhcp")) updated.dhcp.port = ports["dhcp"].asInt();
    }
    if (body.isMember("directory") && body["directory"].isObject()) {
        const auto& directory = body["directory"];
        updated.directory.base_dn = directory.isMember("baseDn") ? directory["baseDn"].asString() : current.directory.base_dn;
        updated.directory.organization = directory.isMember("organization") ? directory["organization"].asString() : current.directory.organization;
        updated.directory.realm = directory.isMember("realm") ? directory["realm"].asString() : current.directory.realm;
        updated.directory.site_name = directory.isMember("siteName") ? directory["siteName"].asString() : current.directory.site_name;
        updated.directory.domain_controller_host = directory.isMember("domainControllerHost")
            ? directory["domainControllerHost"].asString()
            : current.directory.domain_controller_host;
        updated.directory.domain_controller_address = directory.isMember("domainControllerAddress")
            ? directory["domainControllerAddress"].asString()
            : current.directory.domain_controller_address;
        updated.directory.key_encryption_key_file = directory.isMember("keyEncryptionKeyFile")
            ? std::filesystem::path(directory["keyEncryptionKeyFile"].asString())
            : current.directory.key_encryption_key_file;
    }
    if (body.isMember("dns") && body["dns"].isObject()) {
        const auto& dns = body["dns"];
        updated.dns.primary_ns = dns.isMember("primaryNs") ? dns["primaryNs"].asString() : current.dns.primary_ns;
        updated.dns.admin_mailbox = dns.isMember("adminMailbox") ? dns["adminMailbox"].asString() : current.dns.admin_mailbox;
        if (dns.isMember("defaultTtl") && dns["defaultTtl"].asUInt() > 0) {
            updated.dns.default_ttl = dns["defaultTtl"].asUInt();
        }
    }
    if (body.isMember("dhcp") && body["dhcp"].isObject()) {
        const auto& dhcp = body["dhcp"];
        updated.dhcp_service.subnet = dhcp.isMember("subnet") ? dhcp["subnet"].asString() : current.dhcp_service.subnet;
        updated.dhcp_service.range_start = dhcp.isMember("rangeStart") ? dhcp["rangeStart"].asString() : current.dhcp_service.range_start;
        updated.dhcp_service.range_end = dhcp.isMember("rangeEnd") ? dhcp["rangeEnd"].asString() : current.dhcp_service.range_end;
        updated.dhcp_service.router = dhcp.isMember("router") ? dhcp["router"].asString() : current.dhcp_service.router;
    }
    if (body.isMember("pki") && body["pki"].isObject()) {
        const auto& pki = body["pki"];
        updated.pki.organization = pki.isMember("organization") ? pki["organization"].asString() : current.pki.organization;
        updated.pki.common_name = pki.isMember("commonName") ? pki["commonName"].asString() : current.pki.common_name;
        if (pki.isMember("leafDaysValid") && pki["leafDaysValid"].asInt() > 0) {
            updated.pki.leaf_days_valid = pki["leafDaysValid"].asInt();
        }
    }
    if (body.isMember("repo") && body["repo"].isObject()) {
        const auto& repo = body["repo"];
        updated.repo.origin = repo.isMember("origin") ? repo["origin"].asString() : current.repo.origin;
        updated.repo.distribution = repo.isMember("distribution") ? repo["distribution"].asString() : current.repo.distribution;
        updated.repo.component = repo.isMember("component") ? repo["component"].asString() : current.repo.component;
    }
    if (body.isMember("features") && body["features"].isObject()) {
        updated.features.clear();
        const auto& f = body["features"];
        for (const auto& key : f.getMemberNames()) {
            updated.features[key] = f[key].asBool();
        }
    }
    return updated;
}

}  // namespace

PlatformState::PlatformState(nexus::core::Config config)
    : config_(std::move(config)) {
    if (!load_persisted_settings()) {
        std::cerr << "[nexus-api] using environment settings; no persisted settings loaded\n";
    }
    if (!load_feature_flags_from_database()) {
        config_.features = feature_flag_defaults(config_);
    }
    initialize_runtime_state();
}

const nexus::core::Config& PlatformState::config() const {
    return config_;
}

bool PlatformState::update_settings(const nexus::core::Config& config, const std::string& actor) {
    if (!sync_feature_flags_to_database(config)) {
        return false;
    }

    if (!persist_settings(config)) {
        return false;
    }

    {
        std::scoped_lock lock(mutex_);
        config_ = config;
        services_ = make_services(config_);
        ++revision_;
        record_audit_locked(actor, "config", "update", "Updated platform settings");
    }

    return true;
}

std::map<std::string, bool> PlatformState::feature_flags() const {
    std::scoped_lock lock(mutex_);
    return config_.features;
}

bool PlatformState::update_feature_flags(const std::map<std::string, bool>& features, const std::string& actor) {
    nexus::core::Config updated;
    {
        std::scoped_lock lock(mutex_);
        updated = config_;
        updated.features = features;
    }

    if (!sync_feature_flags_to_database(updated)) {
        return false;
    }

    if (!persist_settings(updated)) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    config_.features = features;
    services_ = make_services(config_);
    ++revision_;
    record_audit_locked(actor, "config", "feature_flags.update", "Updated service feature flags");
    return true;
}

nexus::core::DashboardSnapshot PlatformState::dashboard() const {
    std::scoped_lock lock(mutex_);
    nexus::core::DashboardSnapshot snapshot;
    snapshot.services = services_;
    snapshot.directory_objects = directory_.size();
    snapshot.pki_revocations = revocations_.size();
    snapshot.pending_jobs = jobs_.pending_count();
    snapshot.repo_packages = std::accumulate(
        repositories_.begin(),
        repositories_.end(),
        std::size_t{0},
        [](std::size_t total, const auto& repository) { return total + repository.packages.size(); });
    snapshot.dns_records = std::accumulate(
        zones_.begin(),
        zones_.end(),
        std::size_t{0},
        [](std::size_t total, const auto& zone) { return total + zone.records.size(); });
    snapshot.dhcp_leases = std::accumulate(
        pools_.begin(),
        pools_.end(),
        std::size_t{0},
        [](std::size_t total, const auto& pool) { return total + pool.leases.size(); });
    return snapshot;
}

std::vector<nexus::core::ServiceStatus> PlatformState::services() const {
    std::scoped_lock lock(mutex_);
    return services_;
}

std::vector<nexus::core::DirectoryObject> PlatformState::directory_objects() const {
    std::scoped_lock lock(mutex_);
    return directory_;
}

std::vector<PlatformState::ActiveDirectoryObject> PlatformState::active_directory_objects() const {
    nexus::core::Config config;
    std::vector<nexus::core::DirectoryObject> directory;
    {
        std::scoped_lock lock(mutex_);
        config = config_;
        directory = directory_;
    }

    auto objects = load_active_directory_objects_from_database(config);
    if (!objects.empty()) {
        return objects;
    }
    return active_directory_objects_from_directory(config, directory);
}

PlatformState::ActiveDirectoryReadinessSnapshot PlatformState::active_directory_readiness() const {
    nexus::core::Config config;
    std::vector<nexus::core::ServiceStatus> services;
    std::vector<nexus::core::DnsZone> zones;
    std::vector<nexus::core::DirectoryObject> directory;
    {
        std::scoped_lock lock(mutex_);
        config = config_;
        services = services_;
        zones = zones_;
        directory = directory_;
    }

    ActiveDirectoryReadinessSnapshot snapshot;
    snapshot.dns_name = config.domain;
    snapshot.realm = config.directory.realm;
    snapshot.base_dn = config.directory.base_dn;

    const auto statuses = load_ad_protocol_status(config.database_url);
    append_readiness_item(
        snapshot,
        "domain-profile",
        "Domain profile",
        "configuration",
        config.domain + " / " + config.directory.base_dn + " / " + config.directory.realm,
        !config.domain.empty() &&
            !config.directory.base_dn.empty() &&
            !config.directory.realm.empty() &&
            !config.directory.domain_controller_host.empty() &&
            !config.directory.domain_controller_address.empty());
    append_readiness_item(
        snapshot,
        "protocol-status-store",
        "Protocol status store",
        "configuration",
        statuses.empty() ? "ad_protocol_status is unavailable or empty" : "ad_protocol_status loaded",
        !statuses.empty());
    append_readiness_item(
        snapshot,
        "directory-service",
        "Directory service",
        "runtime",
        service_ready(services, "directory") ? "directory service is enabled and unblocked" : "directory service is disabled or blocked",
        service_ready(services, "directory"));
    append_readiness_item(
        snapshot,
        "network-service",
        "Network service",
        "runtime",
        service_ready(services, "network") ? "network service is enabled and unblocked" : "network service is disabled or blocked",
        service_ready(services, "network"));

    const auto domain_zone = find_dns_zone(zones, config.domain);
    const auto readiness_site_name =
        config.directory.site_name.empty() ? std::string{"Default-First-Site-Name"} : config.directory.site_name;
    const auto site_locator_prefix = "_ldap._tcp." + readiness_site_name + "._sites";
    const auto site_kerberos_prefix = "_kerberos._tcp." + readiness_site_name + "._sites";
    const auto site_gc_prefix = "_gc._tcp." + readiness_site_name + "._sites";
    const bool dns_locator_ready = domain_zone.has_value() &&
        has_dc_a_record(*domain_zone, config) &&
        has_dns_record(*domain_zone, "_ldap._tcp", "SRV", static_cast<std::uint16_t>(config.ldap.port)) &&
        has_dns_record(*domain_zone, "_ldap._tcp.dc._msdcs", "SRV", static_cast<std::uint16_t>(config.ldap.port)) &&
        has_dns_record(*domain_zone, site_locator_prefix, "SRV", static_cast<std::uint16_t>(config.ldap.port)) &&
        has_dns_record(*domain_zone, site_locator_prefix + ".dc._msdcs", "SRV", static_cast<std::uint16_t>(config.ldap.port)) &&
        has_dns_record(*domain_zone, "_kerberos._tcp", "SRV", static_cast<std::uint16_t>(config.kerberos.port)) &&
        has_dns_record(*domain_zone, "_kerberos._udp", "SRV", static_cast<std::uint16_t>(config.kerberos.port)) &&
        has_dns_record(*domain_zone, site_kerberos_prefix, "SRV", static_cast<std::uint16_t>(config.kerberos.port)) &&
        has_dns_record(*domain_zone, "_kpasswd._tcp", "SRV", static_cast<std::uint16_t>(config.kpasswd.port)) &&
        has_dns_record(*domain_zone, "_kpasswd._udp", "SRV", static_cast<std::uint16_t>(config.kpasswd.port)) &&
        has_dns_record(*domain_zone, "_gc._tcp", "SRV", static_cast<std::uint16_t>(config.gc.port)) &&
        has_dns_record(*domain_zone, site_gc_prefix, "SRV", static_cast<std::uint16_t>(config.gc.port)) &&
        has_dns_record(*domain_zone, "_ldap._tcp.gc._msdcs", "SRV", static_cast<std::uint16_t>(config.gc.port));
    append_readiness_item(
        snapshot,
        "dns-locator-records",
        "DNS locator records",
        "dns",
        dns_locator_ready
            ? "A/SRV locator records are present for LDAP, Kerberos, kpasswd, GC and site-scoped DC discovery"
            : "domain zone is missing required A/SRV locator, GC or site-scoped records",
        dns_locator_ready);

    const bool default_seed_ready =
        has_directory_seed_account(directory, "Administrator") &&
        has_directory_seed_account(directory, "Guest") &&
        has_directory_seed_account(directory, "krbtgt") &&
        has_directory_seed_account(directory, config.directory.domain_controller_host + "$");
    append_readiness_item(
        snapshot,
        "ad-default-seed",
        "Default AD objects",
        "data",
        default_seed_ready
            ? "Administrator, Guest, krbtgt and DC computer accounts are present"
            : "default Administrator, Guest, krbtgt or DC computer account is missing",
        default_seed_ready);

    const bool ldap_rootdse_probe_ready = ldap_rootdse_internal_probe(config);
    append_readiness_item(
        snapshot,
        "ldap-rootdse-internal-probe",
        "LDAP RootDSE internal probe",
        "ldap",
        ldap_rootdse_probe_ready
            ? "RootDSE probe returns AD naming metadata and supportedControl values"
            : "RootDSE probe did not return required AD metadata or controls",
        ldap_rootdse_probe_ready);
    const bool ldap_controls_probe_ready = ldap_windows_controls_internal_probe(config);
    append_readiness_item(
        snapshot,
        "ldap-controls-internal-probe",
        "LDAP controls internal probe",
        "ldap",
        ldap_controls_probe_ready
            ? "critical Windows AD controls are accepted and sort/VLV response controls are emitted"
            : "critical Windows AD controls are rejected or missing required response controls",
        ldap_controls_probe_ready);
    const bool kerberos_probe_ready = kerberos_internal_probe(config);
    append_readiness_item(
        snapshot,
        "kerberos-internal-probe",
        "Kerberos internal probe",
        "kerberos",
        kerberos_probe_ready
            ? "AS-REQ probe returns a structured Kerberos pre-authentication error"
            : "AS-REQ probe did not return a structured Kerberos pre-authentication error",
        kerberos_probe_ready);
    const bool kpasswd_probe_ready = kpasswd_internal_probe(config);
    append_readiness_item(
        snapshot,
        "kpasswd-internal-probe",
        "kpasswd internal probe",
        "kerberos",
        kpasswd_probe_ready
            ? "kpasswd probe returns a structured Kerberos error for missing AP-REQ/KRB-PRIV"
            : "kpasswd probe did not return a structured Kerberos password-change error",
        kpasswd_probe_ready);
    const bool rpc_probe_ready = rpc_epm_internal_probe(config);
    append_readiness_item(
        snapshot,
        "rpc-epm-internal-probe",
        "RPC EPM internal probe",
        "rpc",
        rpc_probe_ready
            ? "endpoint mapper bind probe returns a DCE/RPC bind ack"
            : "endpoint mapper bind probe did not return a DCE/RPC bind ack",
        rpc_probe_ready);
    const bool smb_probe_ready = smb2_internal_probe();
    append_readiness_item(
        snapshot,
        "smb2-negotiate-internal-probe",
        "SMB2 internal probe",
        "smb",
        smb_probe_ready
            ? "SMB2 negotiate probe returns a framed SMB2 response"
            : "SMB2 negotiate probe did not return a valid framed SMB2 response",
        smb_probe_ready);

    struct RequiredProtocol {
        const char* id;
        const char* label;
        const char* category;
    };
    const RequiredProtocol required_protocols[] = {
        {"ad-secrets", "Wrapped AD secrets", "data"},
        {"ad-system-secrets", "System AD secrets", "data"},
        {"ad-objects-canonical", "Canonical AD object store", "data"},
        {"ad-account-password-metadata", "AD password metadata", "data"},
        {"dns-ad-locator", "DNS AD locator", "dns"},
        {"dns-dynamic-update", "DNS dynamic update", "dns"},
        {"ldap-rootdse", "LDAP RootDSE", "ldap"},
        {"ldap-simple-bind-verifier", "LDAP simple bind verifier", "ldap"},
        {"ldap-search", "LDAP search", "ldap"},
        {"ldap-write-minimal", "LDAP writes", "ldap"},
        {"ldap-membership-sync", "LDAP membership sync", "ldap"},
        {"ldap-machine-spn-merge", "LDAP machine SPN merge", "ldap"},
        {"ldap-constructed-membership", "LDAP constructed group attributes", "ldap"},
        {"ldap-transitive-membership", "LDAP transitive membership", "ldap"},
        {"ldap-attribute-options", "LDAP attribute options/ranges", "ldap"},
        {"ldap-object-guid", "LDAP objectGUID", "ldap"},
        {"ldap-operational-metadata", "LDAP operational metadata", "ldap"},
        {"ldap-ad-controls", "LDAP Windows controls", "ldap"},
        {"ldap-ad", "LDAP AD compatibility", "ldap"},
        {"kerberos-as-rep", "Kerberos AS-REP", "kerberos"},
        {"kerberos-asrep-etype-negotiation", "Kerberos AS-REP etype negotiation", "kerberos"},
        {"kerberos-tgs-rep", "Kerberos TGS-REP", "kerberos"},
        {"kerberos-pac-logon-info", "Kerberos PAC logon info", "kerberos"},
        {"kerberos-pac-signature-buffers", "Kerberos PAC signatures", "kerberos"},
        {"kerberos-enterprise-upn-asreq", "Kerberos enterprise UPN AS-REQ", "kerberos"},
        {"kerberos-account-state", "Kerberos account state checks", "kerberos"},
        {"kerberos-apreq-client-account-state", "Kerberos AP-REQ client state", "kerberos"},
        {"kerberos-kdc", "Kerberos Windows logon", "kerberos"},
        {"kpasswd-password-change", "kpasswd password change", "kerberos"},
        {"rpc-endpoint-mapper", "RPC endpoint mapper", "rpc"},
        {"rpc-epmapper-named-pipe", "RPC endpoint mapper pipe", "rpc"},
        {"netlogon-authenticate", "Netlogon Authenticate", "rpc"},
        {"netlogon-authenticate-account-state", "Netlogon Authenticate account state", "rpc"},
        {"netlogon-authenticator", "Netlogon authenticators", "rpc"},
        {"netlogon-authenticate2", "Netlogon Authenticate2", "rpc"},
        {"netlogon-password-set2", "Netlogon machine password set", "rpc"},
        {"netlogon-dc-locator-rpc", "Netlogon DC locator RPC", "rpc"},
        {"netlogon-capabilities", "Netlogon capabilities", "rpc"},
        {"netlogon-address-to-site", "Netlogon address-to-site", "rpc"},
        {"netlogon-site-coverage", "Netlogon site coverage", "rpc"},
        {"netlogon-control", "Netlogon control probes", "rpc"},
        {"netlogon-dns-host-records", "Netlogon DNS host records", "rpc"},
        {"netlogon-domain-trusts", "Netlogon domain trusts", "rpc"},
        {"netlogon-forest-trust-info", "Netlogon forest trust info", "rpc"},
        {"netlogon-sam-logon", "Netlogon SamLogon", "rpc"},
        {"netlogon-samlogon-account-state", "Netlogon SamLogon account state", "rpc"},
        {"netlogon-rpc", "Netlogon join/login RPC", "rpc"},
        {"samr-domain-core", "SAMR domain core", "rpc"},
        {"samr-domain-info2", "SAMR QueryDomainInfo2", "rpc"},
        {"samr-create-user-legacy", "SAMR legacy machine create", "rpc"},
        {"samr-domain-enumeration", "SAMR enumeration", "rpc"},
        {"samr-domain-groups", "SAMR groups", "rpc"},
        {"samr-security-descriptor", "SAMR security descriptor", "rpc"},
        {"samr-compat-cleanup-ops", "SAMR compatibility cleanup ops", "rpc"},
        {"lsa-lookup", "LSA lookup", "rpc"},
        {"lsa-policy-privileges", "LSA policies/privileges", "rpc"},
        {"lsa-security-descriptor", "LSA security descriptor", "rpc"},
        {"lsa-trusted-domains", "LSA trusted domains", "rpc"},
        {"lsa-account-management-ops", "LSA account management ops", "rpc"},
        {"smb2-session-kerberos-apreq", "SMB Kerberos session", "smb"},
        {"smb2-pipe-read-write", "SMB named-pipe read/write", "smb"},
        {"smb2-pipe-fragmentation", "SMB RPC fragmentation", "smb"},
        {"smb2-signing", "SMB signing", "smb"},
        {"smb2-transport-commands", "SMB transport commands", "smb"},
        {"smb2-lock", "SMB lock command", "smb"},
        {"smb2-file-info-classes", "SMB file info classes", "smb"},
        {"smb2-security-info", "SMB security info", "smb"},
        {"smb2-change-notify-cancel", "SMB change notify/cancel", "smb"},
        {"smb2-sysvol-gpo-skeleton", "SYSVOL GPO skeleton", "smb"},
        {"smb2-sysvol-path-validation", "SYSVOL path validation", "smb"},
        {"smb-sysvol", "SYSVOL/NETLOGON production readiness", "smb"},
        {"windows-join-acceptance", "Windows join/login acceptance", "acceptance"},
    };
    for (const auto& protocol : required_protocols) {
        append_protocol_status_item(snapshot, statuses, protocol.id, protocol.label, protocol.category);
    }

    snapshot.supported = !snapshot.items.empty() &&
        std::all_of(snapshot.items.begin(), snapshot.items.end(), [](const auto& item) {
            return !item.blocking || item.ready;
        });
    return snapshot;
}

std::vector<nexus::core::DnsZone> PlatformState::dns_zones() const {
    std::scoped_lock lock(mutex_);
    return zones_;
}

std::vector<nexus::core::DhcpPool> PlatformState::dhcp_pools() const {
    std::scoped_lock lock(mutex_);
    return pools_;
}

std::vector<nexus::core::PkiAuthority> PlatformState::pki_authorities() const {
    std::scoped_lock lock(mutex_);
    return authorities_;
}

std::vector<nexus::core::PkiCertificate> PlatformState::pki_certificates() const {
    std::scoped_lock lock(mutex_);
    return certificates_;
}

std::vector<nexus::core::PkiRevocation> PlatformState::pki_revocations() const {
    std::scoped_lock lock(mutex_);
    return revocations_;
}

nexus::core::PkiAssistantSnapshot PlatformState::pki_assistant() const {
    std::scoped_lock lock(mutex_);

    nexus::core::PkiAssistantSnapshot snapshot;
    snapshot.authority_count = authorities_.size();
    snapshot.certificate_count = certificates_.size();
    snapshot.revocation_count = revocations_.size();
    snapshot.leaf_days_valid = config_.pki.leaf_days_valid;

    auto add_insight = [&](std::string category, std::string title, std::string detail, std::string severity) {
        snapshot.insights.push_back({std::move(category), std::move(title), std::move(detail), std::move(severity)});
    };

    if (authorities_.empty()) {
        snapshot.recommended_mode = "authority";
        snapshot.recommended_profile_id = "offline-root";
        snapshot.headline = "Create the first trust root";
        add_insight("next_step", "Bootstrap trust", "Create a root CA before issuing any leaf certificates.", "critical");
        add_insight("operating_rule", "Keep the root offline", "Use the root for trust anchor management, not for routine issuance.", "warning");
    } else if (certificates_.empty()) {
        snapshot.recommended_mode = "certificate";
        snapshot.recommended_profile_id = "service-mtls";
        snapshot.headline = "Issue the first service certificate";
        add_insight("next_step", "Put the CA to work", "Issue a leaf certificate for an API, VPN edge, or internal service.", "critical");
        add_insight("operating_rule", "Match SANs exactly", "Use DNS names that match the target workload and its aliases.", "warning");
    } else if (revocations_.empty()) {
        snapshot.recommended_mode = "revocation";
        snapshot.recommended_profile_id = "incident-response";
        snapshot.headline = "Document the revocation playbook";
        add_insight("next_step", "Prepare incident response", "Capture how you will revoke a compromised certificate.", "warning");
        add_insight("operating_rule", "Track serials", "Keep certificate serial numbers in your operator notes and incident timeline.", "info");
    } else {
        snapshot.recommended_mode = "certificate";
        snapshot.recommended_profile_id = "service-mtls";
        snapshot.headline = "Tune rotation and renewal policy";
        add_insight("next_step", "Reduce lifetime risk", "Prefer shorter-lived leaf certificates and automate renewal.", "info");
        add_insight("operating_rule", "Review trust surface", "Keep the root isolated and use dedicated issuance certificates where possible.", "info");
    }

    if (snapshot.leaf_days_valid > 365) {
        add_insight("policy", "Leaf lifetime is long", "Current leaf certificates default to " + std::to_string(snapshot.leaf_days_valid) + " days; shorter lifetimes are usually easier to operate.", "warning");
    } else if (snapshot.leaf_days_valid <= 90) {
        add_insight("policy", "Leaf lifetime is short", "Current leaf certificates default to " + std::to_string(snapshot.leaf_days_valid) + " days; make sure renewal is automated.", "info");
    }

    if (authorities_.size() > 1) {
        add_insight("topology", "Multiple authorities exist", "Consider whether one authority should become an offline root and the others intermediates.", "info");
    }

    if (snapshot.headline.empty()) {
        snapshot.headline = "Review your PKI posture";
    }

    return snapshot;
}

std::vector<nexus::core::AptRepository> PlatformState::apt_repositories() const {
    std::scoped_lock lock(mutex_);
    return repositories_;
}

std::vector<nexus::core::AuditEvent> PlatformState::audit_events() const {
    std::scoped_lock lock(mutex_);
    auto events = audit_events_;
    std::reverse(events.begin(), events.end());
    return events;
}

std::vector<nexus::core::JobSummary> PlatformState::jobs() const {
    return jobs_.list();
}

void PlatformState::record_platform_audit(std::string actor, std::string domain, std::string action, std::string detail) {
    record_audit(std::move(actor), std::move(domain), std::move(action), std::move(detail));
}

std::optional<nexus::core::DnsZone> PlatformState::find_zone(const std::string& zone_name) const {
    std::scoped_lock lock(mutex_);
    auto it = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (it == zones_.end()) {
        return std::nullopt;
    }
    return *it;
}

std::optional<std::string> PlatformState::render_zone(const std::string& zone_name) const {
    const auto zone = find_zone(zone_name);
    if (!zone.has_value()) {
        return std::nullopt;
    }
    return nexus::protocol::render_zone_file(*zone, "ns1." + zone->name, "hostmaster." + zone->name);
}

std::uint64_t PlatformState::stream_revision() const {
    std::scoped_lock lock(mutex_);
    return revision_;
}

PlatformState::LoginResult PlatformState::login(
    const std::string& email,
    const std::string& password,
    const std::string& totp_code) {
    if (config_.admin_password_hash.empty()) {
        return {.ok = false, .error = "admin bootstrap required: set NEXUS_ADMIN_PASSWORD_HASH"};
    }

    if (email != config_.admin_email) {
        return {.ok = false, .error = "unknown user"};
    }

    if (!password_hasher_.verify_password(password, config_.admin_password_hash)) {
        return {.ok = false, .error = "invalid credentials"};
    }

    if (!config_.admin_totp_secret.empty()) {
        if (totp_code.empty() || !totp_.verify(config_.admin_totp_secret, totp_code, std::chrono::system_clock::now())) {
            return {.ok = false, .error = "invalid mfa code"};
        }
    }

    const auto session_token = random_token(32);
    const auto csrf_token = random_token(24);

    {
        std::scoped_lock lock(mutex_);
        sessions_[session_token] = Session{
            email,
            csrf_token,
            {"superadmin", "directory-admin", "network-admin", "pki-admin", "repo-admin", "auditor"},
            std::chrono::system_clock::now() + std::chrono::hours(12)};
    }

    record_audit(email, "auth", "login", "Local admin login");
    return {
        .ok = true,
        .session_token = session_token,
        .csrf_token = csrf_token,
        .roles = {"superadmin", "directory-admin", "network-admin", "pki-admin", "repo-admin", "auditor"}};
}

bool PlatformState::authenticate(
    const std::string& session_token,
    std::string* actor_out,
    std::vector<std::string>* roles_out) const {
    std::scoped_lock lock(mutex_);
    expire_sessions_locked(std::chrono::system_clock::now());
    auto it = sessions_.find(session_token);
    if (it == sessions_.end()) {
        return false;
    }

    if (actor_out != nullptr) {
        *actor_out = it->second.email;
    }
    if (roles_out != nullptr) {
        *roles_out = it->second.roles;
    }
    return true;
}

bool PlatformState::authorize_mutation(
    const std::string& session_token,
    const std::string& csrf_token,
    std::string* actor_out,
    std::vector<std::string>* roles_out) const {
    std::scoped_lock lock(mutex_);
    expire_sessions_locked(std::chrono::system_clock::now());
    auto it = sessions_.find(session_token);
    if (it == sessions_.end() || it->second.csrf_token != csrf_token) {
        return false;
    }

    if (actor_out != nullptr) {
        *actor_out = it->second.email;
    }
    if (roles_out != nullptr) {
        *roles_out = it->second.roles;
    }
    return true;
}

void PlatformState::logout(const std::string& session_token) {
    std::scoped_lock lock(mutex_);
    sessions_.erase(session_token);
}

bool PlatformState::create_dns_zone(const std::string& zone_name, const std::string& actor) {
    if (!is_valid_zone_name(zone_name)) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    const auto existing = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (existing != zones_.end()) {
        return false;
    }

    zones_.push_back({zone_name, default_zone_serial(), {}});
    jobs_.enqueue("dns", "Create zone " + zone_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "zone.created", zone_name});
    revision_ += 1;
    return true;
}

bool PlatformState::update_dns_zone(const std::string& zone_name, const std::string& new_name, const std::string& actor) {
    if (!is_valid_zone_name(new_name)) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    auto target = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (target == zones_.end()) {
        return false;
    }

    if (zone_name != new_name) {
        const auto duplicate = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == new_name; });
        if (duplicate != zones_.end()) {
            return false;
        }
    }

    target->name = new_name;
    target->serial += 1;
    jobs_.enqueue("dns", "Rename zone " + zone_name + " to " + new_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "zone.updated", zone_name + " -> " + new_name});
    revision_ += 1;
    return true;
}

bool PlatformState::delete_dns_zone(const std::string& zone_name, const std::string& actor) {
    std::scoped_lock lock(mutex_);
    const auto it = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (it == zones_.end()) {
        return false;
    }

    zones_.erase(it);
    jobs_.enqueue("dns", "Delete zone " + zone_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "zone.deleted", zone_name});
    revision_ += 1;
    return true;
}

bool PlatformState::add_dns_record(
    const std::string& zone_name,
    const nexus::core::DnsRecord& record,
    const std::string& actor) {
    std::scoped_lock lock(mutex_);
    auto it = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (it == zones_.end()) {
        return false;
    }

    it->records.push_back(record);
    it->serial += 1;
    jobs_.enqueue("dns", "Apply zone update for " + zone_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "record.created", record.name + " " + record.type});
    revision_ += 1;
    return true;
}

bool PlatformState::update_dns_record(
    const std::string& zone_name,
    std::size_t record_index,
    const nexus::core::DnsRecord& record,
    const std::string& actor) {
    std::scoped_lock lock(mutex_);
    auto it = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (it == zones_.end() || record_index >= it->records.size()) {
        return false;
    }

    it->records[record_index] = record;
    it->serial += 1;
    jobs_.enqueue("dns", "Update record in " + zone_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "record.updated", zone_name + " #" + std::to_string(record_index)});
    revision_ += 1;
    return true;
}

bool PlatformState::delete_dns_record(const std::string& zone_name, std::size_t record_index, const std::string& actor) {
    std::scoped_lock lock(mutex_);
    auto it = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (it == zones_.end() || record_index >= it->records.size()) {
        return false;
    }

    it->records.erase(it->records.begin() + static_cast<std::ptrdiff_t>(record_index));
    it->serial += 1;
    jobs_.enqueue("dns", "Delete record in " + zone_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "record.deleted", zone_name + " #" + std::to_string(record_index)});
    revision_ += 1;
    return true;
}

bool PlatformState::restart_dns_service(const std::string& actor) {
    std::scoped_lock lock(mutex_);
    // Persist current state before restarting
    if (!persist_settings(config_)) {
        return false;
    }
    
    // Record audit event for restart
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "service.restarted", "DNS service restart requested"});
    jobs_.enqueue("dns", "DNS service restart");
    revision_ += 1;
    
    // Note: The actual systemctl restart is handled at the system level
    // This just records the request and persists state
    return true;
}

bool PlatformState::restart_dhcp_service(const std::string& actor) {
    std::scoped_lock lock(mutex_);
    // Persist current state before restarting
    if (!persist_settings(config_)) {
        return false;
    }
    
    // Record audit event for restart
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dhcp", "service.restarted", "DHCP service restart requested"});
    jobs_.enqueue("dhcp", "DHCP service restart");
    revision_ += 1;
    
    // Note: The actual systemctl restart is handled at the system level
    // This just records the request and persists state
    return true;
}

bool PlatformState::sync_feature_flags_to_database(const nexus::core::Config& config) const {
    PGconn* connection = connect_database(config.database_url);
    if (connection == nullptr) {
        return true;
    }

    const bool ok = sync_feature_flags(connection, config.features);
    PQfinish(connection);
    return ok;
}

bool PlatformState::load_feature_flags_from_database() {
    PGconn* connection = connect_database(config_.database_url);
    if (connection == nullptr) {
        return false;
    }

    const auto flags = load_feature_flags(connection);
    PQfinish(connection);
    if (flags.empty()) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    config_.features = flags;
    return true;
}

bool PlatformState::create_directory_object(
    nexus::core::DirectoryObject object,
    const std::string& password,
    const std::string& actor) {
    if (!nexus::protocol::is_valid_dn(object.dn) || object.kind.empty() || object.object_classes.empty()) {
        return false;
    }
    if (!object.parent_dn.empty() && !nexus::protocol::is_valid_dn(object.parent_dn)) {
        return false;
    }
    ensure_ad_account_attributes(object, config_);
    if (!password.empty()) {
        object.attributes["userPasswordHash"] = password_hasher_.hash_password(password);
        stamp_ad_password_metadata(object.attributes, object.attributes["sAMAccountName"]);
    }

    {
        std::scoped_lock lock(mutex_);
        const auto duplicate = std::find_if(directory_.begin(), directory_.end(), [&](const auto& current) { return current.dn == object.dn; });
        if (duplicate != directory_.end()) {
            return false;
        }
    }

    persist_directory_object_to_database(object, config_);
    persist_ad_account_secret_to_database(object, password, config_);

    std::scoped_lock lock(mutex_);
    directory_.push_back(std::move(object));
    jobs_.enqueue("directory", "Create object " + directory_.back().dn);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "directory", "object.created", directory_.back().dn});
    revision_ += 1;
    return true;
}

bool PlatformState::update_directory_object(
    const std::string& dn,
    nexus::core::DirectoryObject object,
    const std::string& password,
    const std::string& actor) {
    if (!nexus::protocol::is_valid_dn(dn) || !nexus::protocol::is_valid_dn(object.dn) || object.kind.empty() || object.object_classes.empty()) {
        return false;
    }
    if (!object.parent_dn.empty() && !nexus::protocol::is_valid_dn(object.parent_dn)) {
        return false;
    }
    ensure_ad_account_attributes(object, config_);

    std::scoped_lock lock(mutex_);
    auto it = std::find_if(directory_.begin(), directory_.end(), [&](const auto& current) { return current.dn == dn; });
    if (it == directory_.end()) {
        return false;
    }
    if (dn != object.dn) {
        const auto duplicate = std::find_if(directory_.begin(), directory_.end(), [&](const auto& current) { return current.dn == object.dn; });
        if (duplicate != directory_.end()) {
            return false;
        }
    }
    if (password.empty()) {
        const auto existing_hash = it->attributes.find("userPasswordHash");
        if (existing_hash != it->attributes.end() && object.attributes.find("userPasswordHash") == object.attributes.end()) {
            object.attributes["userPasswordHash"] = existing_hash->second;
        }
    } else {
        object.attributes["userPasswordHash"] = password_hasher_.hash_password(password);
        stamp_ad_password_metadata(object.attributes, object.attributes["sAMAccountName"]);
    }

    persist_directory_object_to_database(object, config_);
    if (dn != object.dn) {
        if (password.empty()) {
            move_ad_account_secret_dn(dn, object.dn, config_.database_url);
        }
        delete_directory_object_from_database(dn, config_.database_url);
    }
    persist_ad_account_secret_to_database(object, password, config_);

    *it = std::move(object);
    jobs_.enqueue("directory", "Update object " + dn);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "directory", "object.updated", dn});
    revision_ += 1;
    return true;
}

bool PlatformState::delete_directory_object(const std::string& dn, const std::string& actor) {
    std::scoped_lock lock(mutex_);
    const auto it = std::find_if(directory_.begin(), directory_.end(), [&](const auto& current) { return current.dn == dn; });
    if (it == directory_.end()) {
        return false;
    }
    delete_directory_object_from_database(dn, config_.database_url);
    directory_.erase(it);
    jobs_.enqueue("directory", "Delete object " + dn);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "directory", "object.deleted", dn});
    revision_ += 1;
    return true;
}

bool PlatformState::create_dhcp_pool(const nexus::core::DhcpPool& pool, const std::string& actor) {
    if (pool.name.empty() || pool.subnet.empty() || pool.range_start.empty() || pool.range_end.empty()) {
        return false;
    }

    // Try to persist to database first; if DB not configured, fallback to runtime-only
    std::string db_err;
    if (!config_.database_url.empty()) {
        if (!persist_dhcp_pool_to_database(pool, config_.database_url, &db_err)) {
            std::cerr << "[nexus-api] failed to persist dhcp pool to database: " << db_err << '\n';
            // continue and keep runtime state so UI still reflects the change
        }
    }

    std::scoped_lock lock(mutex_);
    const auto duplicate = std::find_if(pools_.begin(), pools_.end(), [&](const auto& current) { return current.name == pool.name; });
    if (duplicate != pools_.end()) {
        return false;
    }

    pools_.push_back(pool);
    jobs_.enqueue("dhcp", "Create pool " + pool.name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dhcp", "pool.created", pool.name});
    revision_ += 1;
    return true;
}

bool PlatformState::update_dhcp_pool(const std::string& pool_name, const nexus::core::DhcpPool& pool, const std::string& actor) {
    if (pool.name.empty() || pool.subnet.empty() || pool.range_start.empty() || pool.range_end.empty()) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    auto it = std::find_if(pools_.begin(), pools_.end(), [&](const auto& current) { return current.name == pool_name; });
    if (it == pools_.end()) {
        return false;
    }

    if (pool_name != pool.name) {
        const auto duplicate = std::find_if(pools_.begin(), pools_.end(), [&](const auto& current) { return current.name == pool.name; });
        if (duplicate != pools_.end()) {
            return false;
        }
    }

    // Persist update to database if configured
    std::string db_err;
    if (!config_.database_url.empty()) {
        if (!persist_dhcp_pool_to_database(pool, config_.database_url, &db_err)) {
            std::cerr << "[nexus-api] failed to persist dhcp pool update to database: " << db_err << '\n';
            // still continue with runtime update
        }
    }

    *it = pool;
    jobs_.enqueue("dhcp", "Update pool " + pool_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dhcp", "pool.updated", pool_name + " -> " + pool.name});
    revision_ += 1;
    return true;
}

bool PlatformState::delete_dhcp_pool(const std::string& pool_name, const std::string& actor) {
    std::scoped_lock lock(mutex_);
    const auto it = std::find_if(pools_.begin(), pools_.end(), [&](const auto& current) { return current.name == pool_name; });
    if (it == pools_.end()) {
        return false;
    }

    // Delete from DB if configured
    if (!config_.database_url.empty()) {
        PGconn* conn = PQconnectdb(config_.database_url.c_str());
        if (PQstatus(conn) == CONNECTION_OK) {
            char* name_esc = PQescapeLiteral(conn, pool_name.c_str(), static_cast<unsigned long>(pool_name.size()));
            if (name_esc) {
                std::string sql = "DELETE FROM dhcp_pools WHERE name = " + std::string(name_esc) + ";";
                PGresult* res = PQexec(conn, sql.c_str());
                if (PQresultStatus(res) != PGRES_COMMAND_OK) {
                    std::cerr << "[nexus-api] failed to delete dhcp pool from database: " << PQresultErrorMessage(res) << '\n';
                }
                PQclear(res);
                PQfreemem(name_esc);
            }
            PQfinish(conn);
        } else {
            PQfinish(conn);
            std::cerr << "[nexus-api] could not connect to database to delete dhcp pool" << '\n';
        }
    }

    pools_.erase(it);
    jobs_.enqueue("dhcp", "Delete pool " + pool_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dhcp", "pool.deleted", pool_name});
    revision_ += 1;
    return true;
}

bool PlatformState::create_pki_authority(
    const std::string& name,
    const nexus::security::CertificateSubject& subject,
    int days_valid,
    const std::string& actor) {
    if (name.empty() || subject.common_name.empty() || subject.organization.empty() || days_valid <= 0) {
        return false;
    }

    nexus::security::PkiService pki;
    const auto issued = pki.create_root_ca(subject, days_valid);
    nexus::core::PkiAuthority authority{
        name,
        subject.common_name,
        subject.organization,
        issued.serial_hex,
        issued.certificate_pem,
        issued.private_key_pem,
        nexus::core::utc_timestamp()};

    persist_pki_authority_to_database(authority, config_.database_url);

    std::scoped_lock lock(mutex_);
    const auto duplicate = std::find_if(authorities_.begin(), authorities_.end(), [&](const auto& current) { return current.name == name; });
    if (duplicate != authorities_.end()) {
        return false;
    }
    authorities_.push_back(std::move(authority));
    jobs_.enqueue("pki", "Create authority " + name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "pki", "authority.created", name});
    revision_ += 1;
    return true;
}

bool PlatformState::issue_pki_certificate(
    const std::string& authority_name,
    const nexus::security::CertificateSubject& subject,
    int days_valid,
    const std::string& actor) {
    if (authority_name.empty() || subject.common_name.empty() || subject.organization.empty() || days_valid <= 0) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    const auto authority = std::find_if(authorities_.begin(), authorities_.end(), [&](const auto& current) { return current.name == authority_name; });
    if (authority == authorities_.end()) {
        return false;
    }

    nexus::security::PkiService pki;
    const nexus::security::IssuedCertificate issuing_ca{
        authority->serial_hex,
        authority->certificate_pem,
        authority->private_key_pem};
    const auto issued = pki.issue_leaf_certificate(issuing_ca, subject, days_valid);
    nexus::core::PkiCertificate certificate{
        issued.serial_hex,
        authority_name,
        subject.common_name,
        subject.organization,
        subject.dns_subject_alternative_names,
        issued.certificate_pem,
        issued.private_key_pem,
        false,
        nexus::core::utc_timestamp()};

    persist_pki_certificate_to_database(certificate, config_.database_url);

    certificates_.push_back(std::move(certificate));
    jobs_.enqueue("pki", "Issue certificate " + subject.common_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "pki", "certificate.issued", subject.common_name});
    revision_ += 1;
    return true;
}

bool PlatformState::revoke_certificate(
    const std::string& serial,
    const std::string& common_name,
    const std::string& reason,
    const std::string& actor) {
    if (serial.empty() || reason.empty()) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    auto certificate = std::find_if(certificates_.begin(), certificates_.end(), [&](const auto& current) { return current.serial_hex == serial; });
    if (certificate != certificates_.end()) {
        certificate->revoked = true;
    }
    const auto duplicate = std::find_if(revocations_.begin(), revocations_.end(), [&](const auto& current) { return current.serial == serial; });
    if (duplicate != revocations_.end()) {
        return false;
    }
    const auto resolved_common_name = !common_name.empty() ? common_name : (certificate != certificates_.end() ? certificate->common_name : "");
    nexus::core::PkiRevocation revocation{serial, resolved_common_name, reason, nexus::core::utc_timestamp()};
    persist_pki_revocation_to_database(revocation, config_.database_url);
    revocations_.push_back(std::move(revocation));
    jobs_.enqueue("pki", "Publish CRL for serial " + serial);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "pki", "certificate.revoked", serial + " " + reason});
    revision_ += 1;
    return true;
}

bool PlatformState::create_apt_repository(
    const std::string& distribution,
    const std::string& component,
    const std::string& actor) {
    if (distribution.empty() || component.empty()) {
        return false;
    }
    nexus::core::AptRepository repository{distribution, component, {}};
    persist_apt_repository_to_database(repository, config_.database_url);
    std::scoped_lock lock(mutex_);
    const auto duplicate = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (duplicate != repositories_.end()) {
        return false;
    }
    repositories_.push_back(std::move(repository));
    jobs_.enqueue("repo", "Create repository " + distribution + "/" + component);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "repo", "repository.created", distribution + "/" + component});
    revision_ += 1;
    return true;
}

bool PlatformState::delete_apt_repository(
    const std::string& distribution,
    const std::string& component,
    const std::string& actor) {
    std::scoped_lock lock(mutex_);
    const auto it = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (it == repositories_.end()) {
        return false;
    }
    if (!config_.database_url.empty()) {
        try {
            nexus::apt::RepositoryService service(
                config_.database_url,
                config_.blob_root,
                config_.state_root,
                config_.repo.origin);
            if (!service.delete_repository(distribution, component)) {
                return false;
            }
        } catch (const std::exception& error) {
            std::cerr << "[nexus-api] failed to delete apt repository artifact/db entries: " << error.what() << '\n';
            return false;
        }
    }
    repositories_.erase(it);
    jobs_.enqueue("repo", "Delete repository " + distribution + "/" + component);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "repo", "repository.deleted", distribution + "/" + component});
    revision_ += 1;
    return true;
}

bool PlatformState::add_apt_package(
    const std::string& distribution,
    const std::string& component,
    const nexus::core::AptPackage& package,
    const std::string& actor) {
    if (package.name.empty() || package.version.empty() || package.architecture.empty() || package.filename.empty() || package.sha256.empty() || package.size == 0) {
        return false;
    }
    std::scoped_lock lock(mutex_);
    auto repository = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (repository == repositories_.end()) {
        return false;
    }
    auto stored = package;
    stored.component = component;
    persist_apt_package_to_database(distribution, component, stored, config_.database_url);
    const auto existing = std::find_if(repository->packages.begin(), repository->packages.end(), [&](const auto& current) {
        return current.name == stored.name &&
               current.version == stored.version &&
               current.architecture == stored.architecture;
    });
    if (existing != repository->packages.end()) {
        *existing = stored;
    } else {
        repository->packages.push_back(stored);
    }
    jobs_.enqueue("repo", "Add package " + package.name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "repo", "package.created", package.name + " " + package.version});
    revision_ += 1;
    return true;
}

std::optional<nexus::core::AptPackage> PlatformState::upload_apt_package(
    const std::string& distribution,
    const std::string& component,
    const std::string& filename,
    std::string_view content,
    const std::string& actor) {
    nexus::apt::RepositoryService service(
        config_.database_url,
        config_.blob_root,
        config_.state_root,
        config_.repo.origin);
    auto package = service.upload_package(distribution, component, filename, content, actor);

    std::scoped_lock lock(mutex_);
    auto repository = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (repository == repositories_.end()) {
        repositories_.push_back({distribution, component, {}});
        repository = std::prev(repositories_.end());
    }
    package.component = component;
    const auto existing = std::find_if(repository->packages.begin(), repository->packages.end(), [&](const auto& current) {
        return current.name == package.name &&
               current.version == package.version &&
               current.architecture == package.architecture;
    });
    if (existing != repository->packages.end()) {
        *existing = package;
    } else {
        repository->packages.push_back(package);
    }
    jobs_.enqueue("repo", "Upload package " + package.name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "repo", "package.uploaded", package.name + " " + package.version});
    revision_ += 1;
    return package;
}

bool PlatformState::update_apt_package(
    const std::string& distribution,
    const std::string& component,
    std::size_t package_index,
    const nexus::core::AptPackage& package,
    const std::string& actor) {
    if (package.name.empty() || package.version.empty() || package.architecture.empty() || package.filename.empty() || package.sha256.empty() || package.size == 0) {
        return false;
    }
    std::scoped_lock lock(mutex_);
    auto repository = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (repository == repositories_.end() || package_index >= repository->packages.size()) {
        return false;
    }
    auto stored = package;
    stored.component = component;
    repository->packages[package_index] = stored;
    persist_apt_package_to_database(distribution, component, stored, config_.database_url);
    jobs_.enqueue("repo", "Update package " + package.name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "repo", "package.updated", package.name + " " + package.version});
    revision_ += 1;
    return true;
}

bool PlatformState::delete_apt_package(
    const std::string& distribution,
    const std::string& component,
    std::size_t package_index,
    const std::string& actor) {
    std::scoped_lock lock(mutex_);
    auto repository = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (repository == repositories_.end() || package_index >= repository->packages.size()) {
        return false;
    }
    const auto package = repository->packages[package_index];
    const auto package_name = package.name;
    if (!config_.database_url.empty()) {
        try {
            nexus::apt::RepositoryService service(
                config_.database_url,
                config_.blob_root,
                config_.state_root,
                config_.repo.origin);
            if (!service.delete_package(distribution, component, package)) {
                return false;
            }
        } catch (const std::exception& error) {
            std::cerr << "[nexus-api] failed to delete apt package artifact/db entry: " << error.what() << '\n';
            return false;
        }
    }
    repository->packages.erase(repository->packages.begin() + static_cast<std::ptrdiff_t>(package_index));
    jobs_.enqueue("repo", "Delete package " + package_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "repo", "package.deleted", package_name});
    revision_ += 1;
    return true;
}

std::optional<std::string> PlatformState::render_apt_packages(
    const std::string& distribution,
    const std::string& component) const {
    std::scoped_lock lock(mutex_);
    const auto repository = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (repository == repositories_.end()) {
        return std::nullopt;
    }
    return nexus::protocol::render_packages_index(*repository);
}

std::optional<std::string> PlatformState::render_apt_release(
    const std::string& distribution,
    const std::string& component) const {
    std::scoped_lock lock(mutex_);
    const auto repository = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (repository == repositories_.end()) {
        return std::nullopt;
    }
    const auto packages = nexus::protocol::render_packages_index(*repository);
    return nexus::protocol::render_release_file(*repository, config_.repo.origin, distribution, sha256_hex(packages), packages.size());
}

void PlatformState::initialize_runtime_state() {
    auto services = make_services(config_);
    auto directory = load_directory_objects_from_database(config_);
    append_missing_ad_seed_objects(directory, config_);
    std::vector<nexus::core::AptRepository> repositories;
    load_repositories_from_database(repositories, config_.database_url);
    if (!config_.database_url.empty()) {
        for (const auto& object : directory) {
            persist_directory_object_to_database(object, config_);
        }
        const bool system_secrets_ready = bootstrap_system_ad_secrets(directory, config_);
        seed_ad_protocol_status_baseline(config_.database_url);
        set_ad_protocol_status(
            config_.database_url,
            "ad-objects-canonical",
            true,
            "API and directory protocols persist AD objects into canonical ad_objects and maintain identity_objects as the compatibility projection");
        set_ad_protocol_status(
            config_.database_url,
            "ad-default-seed",
            true,
            "Default AD containers, users, groups, Builtin aliases and DC computer account are seeded idempotently");
        set_ad_protocol_status(
            config_.database_url,
            "ad-system-secrets",
            system_secrets_ready,
            system_secrets_ready
                ? "krbtgt and DC service account secrets are present and wrapped for Kerberos/Netlogon service use"
                : "krbtgt or DC service account secret could not be bootstrapped");
        set_ad_protocol_status(
            config_.database_url,
            "ldap-membership-sync",
            true,
            "LDAP group member add/delete/replace updates canonical ad_memberships and member groupRids for join-time group changes");
        set_ad_protocol_status(
            config_.database_url,
            "ldap-simple-bind-verifier",
            true,
            "LDAP simple binds on the directory daemon validate supplied passwords against wrapped AD account secrets before authorizing the session");
        set_ad_protocol_status(
            config_.database_url,
            "ldap-constructed-membership",
            true,
            "LDAP search/compare responses synthesize memberOf, primaryGroupToken, sAMAccountType and binary tokenGroups from canonical group memberships");
        set_ad_protocol_status(
            config_.database_url,
            "ldap-transitive-membership",
            true,
            "LDAP matching rule 1.2.840.113556.1.4.1941 evaluates nested member/memberOf group chains for AD clients");
        set_ad_protocol_status(
            config_.database_url,
            "ldap-attribute-options",
            true,
            "LDAP requested attributes with options such as member;range=0-* resolve against their base AD attribute names");
        set_ad_protocol_status(
            config_.database_url,
            "ldap-object-guid",
            true,
            "LDAP search/filter responses expose objectGUID as a binary AD GUID backed by canonical ad_objects.object_guid when available");
        set_ad_protocol_status(
            config_.database_url,
            "ldap-operational-metadata",
            true,
            "LDAP search responses expose AD-style whenCreated, whenChanged, uSNCreated and uSNChanged metadata for stored and virtual objects");
        set_ad_protocol_status(
            config_.database_url,
            "kerberos-enterprise-upn-asreq",
            true,
            "KDC accepts Windows enterprise UPN AS-REQ client names and emits the canonical account principal in the TGT and AS-REP");
        set_ad_protocol_status(
            config_.database_url,
            "kerberos-account-state",
            true,
            "KDC and AP-REQ validation refuse disabled or expired AD principals instead of issuing or accepting tickets for blocked accounts");
        set_ad_protocol_status(
            config_.database_url,
            "kerberos-asrep-etype-negotiation",
            true,
            "KDC selects a requested AS-REP enctype shared by the client and krbtgt, independently from the pre-auth timestamp enctype");
        set_ad_protocol_status(
            config_.database_url,
            "kerberos-pac-signature-buffers",
            true,
            "Kerberos PAC UPN_DNS_INFO, server checksum and KDC checksum buffers are emitted in their Windows PAC buffer slots");
        set_ad_protocol_status(
            config_.database_url,
            "kerberos-apreq-client-account-state",
            true,
            "LDAP/SMB Kerberos AP-REQ validation refuses tickets whose client principal is disabled or expired in Nexus AD");
        set_ad_protocol_status(
            config_.database_url,
            "rpc-epmapper-named-pipe",
            true,
            "DCE/RPC endpoint mapper is also exposed over SMB IPC$ named pipe epmapper for Windows transport probes");
        set_ad_protocol_status(
            config_.database_url,
            "netlogon-samlogon-account-state",
            true,
            "Netlogon SamLogon refuses disabled AD accounts with STATUS_ACCOUNT_DISABLED even when the NTLMv2 proof is valid");
        set_ad_protocol_status(
            config_.database_url,
            "netlogon-authenticate-account-state",
            true,
            "Netlogon Authenticate refuses disabled or expired machine accounts after validating the client credential and before creating a secure-channel session");
        set_ad_protocol_status(
            config_.database_url,
            "netlogon-forest-trust-info",
            true,
            "DsrGetForestTrustInformation and NetrGetForestTrustInformation return minimal single-forest trust records for the Nexus domain DNS name, NetBIOS name and SID");
        set_ad_protocol_status(
            config_.database_url,
            "netlogon-site-coverage",
            true,
            "DsrAddressToSiteNamesExW and DsrGetDcSiteCoverageW return configured Nexus AD site coverage metadata");
        set_ad_protocol_status(
            config_.database_url,
            "netlogon-dns-host-records",
            true,
            "DsrDeregisterDnsHostRecords accepts Windows DNS cleanup probes with STATUS_SUCCESS for the single Nexus DC");
        set_ad_protocol_status(
            config_.database_url,
            "samr-security-descriptor",
            true,
            "SAMR QuerySecurityObject returns a minimal self-relative security descriptor and SetSecurityObject accepts join-time probes");
        set_ad_protocol_status(
            config_.database_url,
            "samr-domain-info2",
            true,
            "SAMR QueryInformationDomain2 returns structured domain NetBIOS/DNS/SID/count metadata and SetInformationDomain accepts join-time probes");
        set_ad_protocol_status(
            config_.database_url,
            "samr-create-user-legacy",
            true,
            "SAMR CreateUserInDomain legacy fallback can create/open machine accounts when Windows does not use CreateUser2InDomain");
        set_ad_protocol_status(
            config_.database_url,
            "samr-compat-cleanup-ops",
            true,
            "SAMR EnumerateDomains and cleanup/set/delete probes return coherent success responses instead of unsupported opnum errors");
        set_ad_protocol_status(
            config_.database_url,
            "smb2-transport-commands",
            true,
            "SMB2 ECHO, FLUSH and SET_INFO return minimal success responses for Windows IPC$/SYSVOL transport probes");
        set_ad_protocol_status(
            config_.database_url,
            "smb2-lock",
            true,
            "SMB2 LOCK requests on valid IPC$/SYSVOL/NETLOGON handles return minimal success responses for Windows file access probes");
        set_ad_protocol_status(
            config_.database_url,
            "smb2-file-info-classes",
            true,
            "SMB2 QUERY_INFO answers common Windows file metadata classes including All, NetworkOpen, Name, Internal and AttributeTag");
        set_ad_protocol_status(
            config_.database_url,
            "smb2-security-info",
            true,
            "SMB2 QUERY_INFO security requests return a minimal self-relative security descriptor for IPC$/SYSVOL/NETLOGON handles");
        set_ad_protocol_status(
            config_.database_url,
            "smb2-change-notify-cancel",
            true,
            "SMB2 CHANGE_NOTIFY on SYSVOL/NETLOGON directory handles and CANCEL transport requests are handled for Windows clients");
        set_ad_protocol_status(
            config_.database_url,
            "lsa-security-descriptor",
            true,
            "LSA QuerySecurityObject returns a minimal self-relative security descriptor and SetSecurityObject accepts policy security probes");
        set_ad_protocol_status(
            config_.database_url,
            "lsa-trusted-domains",
            true,
            "LSA trusted-domain enumerate/open/query calls expose the current Nexus domain as the primary single-forest trust");
        set_ad_protocol_status(
            config_.database_url,
            "lsa-account-management-ops",
            true,
            "LSA account create/open privilege, quota, delete-object and GetUserName probes return minimal Windows-compatible responses");
        set_ad_protocol_status(
            config_.database_url,
            "smb2-sysvol-path-validation",
            true,
            "SMB2 SYSVOL/NETLOGON CREATE validates known GPO/script paths and returns OBJECT_NAME_NOT_FOUND for unknown files");
    }

    std::scoped_lock lock(mutex_);
    services_ = std::move(services);
    directory_ = std::move(directory);
    zones_.clear();
    pools_.clear();
    authorities_.clear();
    certificates_.clear();
    revocations_.clear();
    repositories_ = std::move(repositories);
    audit_events_ = {
        {nexus::core::utc_timestamp(), "system", "bootstrap", "platform.started", "Runtime initialized with AD seed baseline"},
    };
    revision_ = 1;
}

std::filesystem::path PlatformState::settings_file_path() const {
    return config_.state_root / "settings.json";
}

bool PlatformState::load_persisted_settings() {
    const auto path = settings_file_path();
    if (!std::filesystem::exists(path)) {
        return false;
    }

    std::ifstream input(path);
    if (!input.is_open()) {
        return false;
    }

    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    Json::Value body;
    std::string errors;
    if (!Json::parseFromStream(builder, input, &body, &errors)) {
        std::cerr << "[nexus-api] failed to read persisted settings: " << errors << '\n';
        return false;
    }

    config_ = config_from_json_value(config_, body);
    return true;
}

bool PlatformState::persist_settings(const nexus::core::Config& config) const {
    std::error_code error_code;
    std::filesystem::create_directories(config.state_root, error_code);
    if (error_code) {
        std::cerr << "[nexus-api] failed to create state root: " << error_code.message() << '\n';
        return false;
    }

    const auto path = config.state_root / "settings.json";
    const auto temp_path = path.string() + ".tmp";

    std::ofstream output(temp_path, std::ios::trunc);
    if (!output.is_open()) {
        std::cerr << "[nexus-api] failed to open settings file for writing\n";
        return false;
    }

    Json::StreamWriterBuilder builder;
    builder["indentation"] = "  ";
    output << Json::writeString(builder, config_to_json_value(config));
    output.close();
    if (!output) {
        std::cerr << "[nexus-api] failed to flush settings file\n";
        return false;
    }

    std::filesystem::rename(temp_path, path, error_code);
    if (error_code) {
        std::filesystem::remove(temp_path);
        std::cerr << "[nexus-api] failed to persist settings: " << error_code.message() << '\n';
        return false;
    }

    return true;
}

void PlatformState::record_audit(std::string actor, std::string domain, std::string action, std::string detail) {
    std::scoped_lock lock(mutex_);
    record_audit_locked(std::move(actor), std::move(domain), std::move(action), std::move(detail));
}

void PlatformState::record_audit_locked(std::string actor, std::string domain, std::string action, std::string detail) {
    audit_events_.push_back({nexus::core::utc_timestamp(), std::move(actor), std::move(domain), std::move(action), std::move(detail)});
    revision_ += 1;
}

void PlatformState::expire_sessions_locked(std::chrono::system_clock::time_point now) const {
    auto* sessions = const_cast<std::unordered_map<std::string, Session>*>(&sessions_);
    for (auto it = sessions->begin(); it != sessions->end();) {
        if (it->second.expires_at <= now) {
            it = sessions->erase(it);
        } else {
            ++it;
        }
    }
}

std::string PlatformState::random_token(std::size_t bytes) {
    std::vector<unsigned char> buffer(bytes);
    RAND_bytes(buffer.data(), static_cast<int>(buffer.size()));
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned char byte : buffer) {
        output << std::setw(2) << static_cast<int>(byte);
    }
    return output.str();
}

}  // namespace nexus::api
