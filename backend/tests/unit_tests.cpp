#include "nexus/core/models.hpp"
#include "nexus/jobs/queue.hpp"
#include "nexus/protocol/dhcp.hpp"
#include "nexus/protocol/dns.hpp"
#include "nexus/protocol/kerberos.hpp"
#include "nexus/protocol/ldap.hpp"
#include "nexus/protocol/repo.hpp"
#include "nexus/security/ad_crypto.hpp"
#include "nexus/security/password_hasher.hpp"
#include "nexus/security/pki.hpp"
#include "nexus/security/totp.hpp"

#include "apps/api/platform_state.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <initializer_list>
#include <string>
#include <vector>

namespace {

using TestBytes = std::vector<std::uint8_t>;

void append_test_length(TestBytes& output, std::size_t length) {
    if (length < 0x80) {
        output.push_back(static_cast<std::uint8_t>(length));
        return;
    }
    if (length > 0xff) {
        output.push_back(0x82);
        output.push_back(static_cast<std::uint8_t>((length >> 8U) & 0xffU));
        output.push_back(static_cast<std::uint8_t>(length & 0xffU));
        return;
    }
    output.push_back(0x81);
    output.push_back(static_cast<std::uint8_t>(length));
}

TestBytes test_tlv(std::uint8_t tag, const TestBytes& payload) {
    TestBytes output{tag};
    append_test_length(output, payload.size());
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

TestBytes test_int(int value) {
    return test_tlv(0x02, {static_cast<std::uint8_t>(value)});
}

TestBytes test_enum(int value) {
    return test_tlv(0x0a, {static_cast<std::uint8_t>(value)});
}

TestBytes test_bool(bool value) {
    return test_tlv(0x01, {static_cast<std::uint8_t>(value ? 0xff : 0x00)});
}

TestBytes test_string(const std::string& value) {
    return test_tlv(0x1b, TestBytes(value.begin(), value.end()));
}

TestBytes test_generalized_time(const std::string& value) {
    return test_tlv(0x18, TestBytes(value.begin(), value.end()));
}

TestBytes test_ldap_string(const std::string& value) {
    return test_tlv(0x04, TestBytes(value.begin(), value.end()));
}

TestBytes test_octet_string(const TestBytes& value) {
    return test_tlv(0x04, value);
}

TestBytes test_concat(std::initializer_list<TestBytes> parts) {
    TestBytes output;
    for (const auto& part : parts) {
        output.insert(output.end(), part.begin(), part.end());
    }
    return output;
}

TestBytes test_seq(const TestBytes& payload) {
    return test_tlv(0x30, payload);
}

TestBytes test_ctx(std::uint8_t index, const TestBytes& payload) {
    return test_tlv(static_cast<std::uint8_t>(0xa0U + index), payload);
}

TestBytes test_pa_data(int type, const TestBytes& value) {
    return test_seq(test_concat({
        test_ctx(1, test_int(type)),
        test_ctx(2, test_octet_string(value)),
    }));
}

TestBytes test_ldap_present_filter(const std::string& attribute) {
    return test_tlv(0x87, TestBytes(attribute.begin(), attribute.end()));
}

TestBytes test_ldap_equality_filter(const std::string& attribute, const std::string& value) {
    return test_tlv(0xa3, test_concat({test_ldap_string(attribute), test_ldap_string(value)}));
}

TestBytes test_ldap_search_request(
    int message_id,
    const std::string& base_dn,
    int scope,
    const TestBytes& filter,
    const std::vector<std::string>& attributes) {
    TestBytes attribute_list;
    for (const auto& attribute : attributes) {
        const auto encoded = test_ldap_string(attribute);
        attribute_list.insert(attribute_list.end(), encoded.begin(), encoded.end());
    }
    const auto search = test_tlv(0x63, test_concat({
        test_ldap_string(base_dn),
        test_enum(scope),
        test_enum(0),
        test_int(0),
        test_int(0),
        test_bool(false),
        filter,
        test_seq(attribute_list),
    }));
    return test_seq(test_concat({test_int(message_id), search}));
}

TestBytes test_encrypted_data(int enctype, const TestBytes& cipher = {0x00, 0x01, 0x02}) {
    return test_seq(test_concat({
        test_ctx(0, test_int(enctype)),
        test_ctx(2, test_octet_string(cipher)),
    }));
}

TestBytes test_as_req(
    const std::string& principal,
    const std::string& realm,
    bool include_enc_timestamp = false,
    const TestBytes& encrypted_timestamp_cipher = {}) {
    const auto principal_name = test_seq(test_concat({
        test_ctx(0, test_int(1)),
        test_ctx(1, test_seq(test_string(principal))),
    }));
    const auto req_body = test_seq(test_concat({
        test_ctx(1, principal_name),
        test_ctx(2, test_string(realm)),
        test_ctx(8, test_seq(test_concat({test_int(18), test_int(17)}))),
    }));
    TestBytes padata;
    if (include_enc_timestamp) {
        padata = test_ctx(3, test_seq(test_pa_data(2, test_encrypted_data(18, encrypted_timestamp_cipher.empty() ? TestBytes{0x00, 0x01, 0x02} : encrypted_timestamp_cipher))));
    }
    TestBytes kdc_payload = test_concat({
        test_ctx(1, test_int(5)),
        test_ctx(2, test_int(10)),
    });
    if (!padata.empty()) {
        kdc_payload.insert(kdc_payload.end(), padata.begin(), padata.end());
    }
    const auto body_context = test_ctx(4, req_body);
    kdc_payload.insert(kdc_payload.end(), body_context.begin(), body_context.end());
    const auto kdc_req = test_seq(kdc_payload);
    return test_tlv(0x6a, kdc_req);
}

nexus::protocol::KerberosPrincipal test_kerberos_principal(
    const std::string& principal,
    std::vector<nexus::protocol::KerberosKey> keys = {
        {18, "aes256-cts-hmac-sha1-96", "ENDORIUM.LOCALadministrator", "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"},
        {17, "aes128-cts-hmac-sha1-96", "ENDORIUM.LOCALadministrator", "00112233445566778899aabbccddeeff"},
    }) {
    return {principal, "ENDORIUM.LOCAL", !keys.empty(), keys};
}

}  // namespace

int main() {
    using namespace nexus;

    assert(protocol::is_valid_dn("cn=alice,ou=People,dc=endorium,dc=local"));
    assert(!protocol::is_valid_dn("this-is-not-a-dn"));

    const core::DnsZone zone{
        "endorium.local",
        2026042401,
        {
            {"@", "NS", "ns1.endorium.local.", "IN", 3600, 0, 0, 0, ""},
            {"api", "A", "10.10.10.10", "IN", 300, 0, 0, 0, ""},
            {"_ldap._tcp", "SRV", "directory.endorium.local.", "IN", 300, 10, 20, 389, ""},
            {"@", "CAA", "letsencrypt.org", "IN", 300, 0, 0, 0, "issue"},
        }};
    const auto zone_text = protocol::render_zone_file(zone, "ns1.endorium.local", "hostmaster.endorium.local");
    assert(zone_text.find("SOA") != std::string::npos);
    assert(zone_text.find("2026042401") != std::string::npos);
    assert(zone_text.find("_ldap._tcp 300 IN SRV 10 20 389 directory.endorium.local.") != std::string::npos);
    assert(zone_text.find("@ 300 IN CAA 0 issue \"letsencrypt.org\"") != std::string::npos);

    const auto ad_zone = protocol::make_active_directory_dns_zone({
        "endorium.local",
        "Default-First-Site-Name",
        "dc1",
        "10.10.10.10",
        389,
        88,
        464,
        3268,
    });
    std::vector<std::uint8_t> dns_query{
        0x12, 0x34, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x05, '_', 'l', 'd', 'a', 'p',
        0x04, '_', 't', 'c', 'p',
        0x02, 'd', 'c',
        0x06, '_', 'm', 's', 'd', 'c', 's',
        0x08, 'e', 'n', 'd', 'o', 'r', 'i', 'u', 'm',
        0x05, 'l', 'o', 'c', 'a', 'l',
        0x00, 0x00, 0x21, 0x00, 0x01};
    const auto dns_response = protocol::resolve_dns_query(dns_query, {ad_zone});
    assert(dns_response.size() > dns_query.size());
    assert(dns_response[0] == 0x12 && dns_response[1] == 0x34);
    assert(dns_response[6] == 0x00 && dns_response[7] >= 0x01);

    const std::vector<std::uint8_t> ldap_bind{0x30, 0x0c, 0x02, 0x01, 0x01, 0x60, 0x07, 0x02, 0x01, 0x03, 0x04, 0x00, 0x80, 0x00};
    const auto bind_response = protocol::ldap_ad_response(ldap_bind, {"endorium.local", "dc=endorium,dc=local", "ENDORIUM.LOCAL", "Default-First-Site-Name", "dc1"});
    assert(!bind_response.empty());
    assert(std::find(bind_response.begin(), bind_response.end(), 0x61) != bind_response.end());

    const auto ldap_root_dse_search = test_ldap_search_request(2, "", 0, test_ldap_present_filter("objectClass"), {"*"});
    const auto root_dse_response = protocol::ldap_ad_response(ldap_root_dse_search, {"endorium.local", "dc=endorium,dc=local", "ENDORIUM.LOCAL", "Default-First-Site-Name", "dc1"});
    const std::string root_dse_text(root_dse_response.begin(), root_dse_response.end());
    assert(root_dse_text.find("defaultNamingContext") != std::string::npos);

    const auto ldap_netlogon_search = test_ldap_search_request(3, "", 0, test_ldap_present_filter("objectClass"), {"NetLogon"});
    const auto netlogon_response = protocol::ldap_ad_response(
        ldap_netlogon_search,
        {"endorium.local", "dc=endorium,dc=local", "ENDORIUM.LOCAL", "Default-First-Site-Name", "dc1", "10.10.10.10"});
    const std::string netlogon_text(netlogon_response.begin(), netlogon_response.end());
    assert(netlogon_text.find("NetLogon") != std::string::npos);
    const std::vector<std::uint8_t> netlogon_opcode{0x17, 0x00, 0x00, 0x00};
    assert(std::search(netlogon_response.begin(), netlogon_response.end(), netlogon_opcode.begin(), netlogon_opcode.end()) != netlogon_response.end());
    assert(netlogon_text.find("dc1") != std::string::npos);

    const std::vector<protocol::LdapObject> ldap_objects{
        {"dc=endorium,dc=local", "", "domainDNS", {"top", "domain", "domainDNS"}, {{"dc", "endorium"}, {"objectSid", "S-1-5-21-1"}}},
        {"cn=Administrator,ou=Users,dc=endorium,dc=local", "ou=Users,dc=endorium,dc=local", "user", {"top", "person", "user"}, {{"cn", "Administrator"}, {"sAMAccountName", "Administrator"}, {"userPasswordHash", "hidden"}}},
        {"cn=dc1,ou=Domain Controllers,dc=endorium,dc=local", "ou=Domain Controllers,dc=endorium,dc=local", "computer", {"top", "computer"}, {{"cn", "dc1"}, {"sAMAccountName", "DC1$"}, {"servicePrincipalName", "HOST/dc1.endorium.local;LDAP/dc1.endorium.local"}}},
    };
    const auto ldap_user_search = test_ldap_search_request(
        4,
        "dc=endorium,dc=local",
        2,
        test_ldap_equality_filter("sAMAccountName", "Administrator"),
        {"cn", "sAMAccountName", "objectClass", "userPasswordHash"});
    const auto user_search_response = protocol::ldap_ad_response(
        ldap_user_search,
        {"endorium.local", "dc=endorium,dc=local", "ENDORIUM.LOCAL", "Default-First-Site-Name", "dc1"},
        ldap_objects);
    const std::string user_search_text(user_search_response.begin(), user_search_response.end());
    assert(user_search_text.find("cn=Administrator,ou=Users,dc=endorium,dc=local") != std::string::npos);
    assert(user_search_text.find("sAMAccountName") != std::string::npos);
    assert(user_search_text.find("hidden") == std::string::npos);

    const auto ldap_spn_search = test_ldap_search_request(
        5,
        "dc=endorium,dc=local",
        2,
        test_ldap_equality_filter("servicePrincipalName", "LDAP/dc1.endorium.local"),
        {"servicePrincipalName"});
    const auto spn_search_response = protocol::ldap_ad_response(
        ldap_spn_search,
        {"endorium.local", "dc=endorium,dc=local", "ENDORIUM.LOCAL", "Default-First-Site-Name", "dc1"},
        ldap_objects);
    const std::string spn_search_text(spn_search_response.begin(), spn_search_response.end());
    assert(spn_search_text.find("cn=dc1,ou=Domain Controllers,dc=endorium,dc=local") != std::string::npos);
    assert(spn_search_text.find("HOST/dc1.endorium.local") != std::string::npos);

    const auto as_req_probe = test_as_req("Administrator", "ENDORIUM.LOCAL");
    const auto parsed_as_req = protocol::parse_kerberos_request(as_req_probe);
    assert(parsed_as_req.valid);
    assert(parsed_as_req.message_type == 10);
    assert(parsed_as_req.realm == "ENDORIUM.LOCAL");
    assert(parsed_as_req.client_principal == "Administrator");
    assert(parsed_as_req.requested_etypes.size() == 2);
    assert(!parsed_as_req.has_padata);
    const auto krb_error = protocol::kerberos_error_response(as_req_probe, {"ENDORIUM.LOCAL", "krbtgt", {test_kerberos_principal("Administrator")}});
    assert(!krb_error.empty());
    assert(krb_error.front() == 0x7e);
    const std::string krb_error_text(krb_error.begin(), krb_error.end());
    assert(krb_error_text.find("pre-authentication required") != std::string::npos);
    assert(std::find(krb_error.begin(), krb_error.end(), 0xac) != krb_error.end());
    const std::vector<std::uint8_t> pa_etype_info2_pattern{0x02, 0x01, 0x13};
    assert(std::search(krb_error.begin(), krb_error.end(), pa_etype_info2_pattern.begin(), pa_etype_info2_pattern.end()) != krb_error.end());
    const auto unknown_krb_error = protocol::kerberos_error_response(as_req_probe, {"ENDORIUM.LOCAL", "krbtgt", {}});
    const std::string unknown_krb_error_text(unknown_krb_error.begin(), unknown_krb_error.end());
    assert(unknown_krb_error_text.find("client principal unknown") != std::string::npos);
    const auto preauthed_as_req = test_as_req("Administrator", "ENDORIUM.LOCAL", true);
    const auto parsed_preauthed_as_req = protocol::parse_kerberos_request(preauthed_as_req);
    assert(parsed_preauthed_as_req.has_padata);
    assert(parsed_preauthed_as_req.padata_types.size() == 1);
    assert(parsed_preauthed_as_req.padata_types[0] == 2);
    assert(parsed_preauthed_as_req.encrypted_timestamp_etypes.size() == 1);
    assert(parsed_preauthed_as_req.encrypted_timestamp_etypes[0] == 18);
    assert(parsed_preauthed_as_req.encrypted_timestamps.size() == 1);
    const auto preauth_failed = protocol::kerberos_error_response(preauthed_as_req, {"ENDORIUM.LOCAL", "krbtgt", {test_kerberos_principal("Administrator")}});
    const std::string preauth_failed_text(preauth_failed.begin(), preauth_failed.end());
    assert(preauth_failed_text.find("encrypted timestamp validation failed") != std::string::npos);
    const auto unsupported_etype = protocol::kerberos_error_response(
        preauthed_as_req,
        {"ENDORIUM.LOCAL", "krbtgt", {test_kerberos_principal("Administrator", {{17, "aes128-cts-hmac-sha1-96", "ENDORIUM.LOCALadministrator", "00112233445566778899aabbccddeeff"}})}});
    const std::string unsupported_etype_text(unsupported_etype.begin(), unsupported_etype.end());
    assert(unsupported_etype_text.find("etype is not available") != std::string::npos);
    const auto real_admin_key = security::derive_ad_kerberos_aes_key("ChangeMe-AD-1", "ENDORIUM.LOCALadministrator", 32);
    const auto encrypted_timestamp_plaintext = test_seq(test_ctx(0, test_generalized_time("20260521120000Z")));
    const TestBytes deterministic_confounder{
        0x00, 0x01, 0x02, 0x03,
        0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b,
        0x0c, 0x0d, 0x0e, 0x0f};
    const auto real_encrypted_timestamp = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        encrypted_timestamp_plaintext,
        real_admin_key,
        1,
        deterministic_confounder);
    const auto valid_preauthed_as_req = test_as_req("Administrator", "ENDORIUM.LOCAL", true, real_encrypted_timestamp);
    const auto valid_preauth_response = protocol::kerberos_error_response(
        valid_preauthed_as_req,
        {"ENDORIUM.LOCAL", "krbtgt", {test_kerberos_principal("Administrator", {{18, "aes256-cts-hmac-sha1-96", "ENDORIUM.LOCALadministrator", real_admin_key}})}});
    const std::string valid_preauth_text(valid_preauth_response.begin(), valid_preauth_response.end());
    assert(valid_preauth_text.find("AS-REP/TGT issuance") != std::string::npos);
    std::vector<std::uint8_t> tcp_as_req_probe{
        0x00,
        0x00,
        static_cast<std::uint8_t>((as_req_probe.size() >> 8U) & 0xffU),
        static_cast<std::uint8_t>(as_req_probe.size() & 0xffU)};
    tcp_as_req_probe.insert(tcp_as_req_probe.end(), as_req_probe.begin(), as_req_probe.end());
    const auto tcp_krb_error = protocol::kerberos_tcp_error_response(tcp_as_req_probe, {"ENDORIUM.LOCAL", "krbtgt", {test_kerberos_principal("Administrator")}});
    assert(tcp_krb_error.size() > krb_error.size());
    assert(tcp_krb_error[4] == 0x7e);

    const core::DhcpPool pool{
        "office",
        "10.10.10.0/24",
        "10.10.10.100",
        "10.10.10.102",
        {{"router", "10.10.10.1"}},
        {
            {"10.10.10.100", "client-01", "ws-01", "active", "2026-04-24T12:00:00Z"},
        }};
    const auto lease = protocol::allocate_next_lease(pool, pool.leases, "client-02", "ws-02");
    assert(lease.has_value());
    assert(lease->ip_address == "10.10.10.101");

    security::PasswordHasher hasher;
    const auto hash = hasher.hash_password("endorium-admin");
    assert(hasher.verify_password("endorium-admin", hash));
    assert(!hasher.verify_password("wrong-password", hash));

    const auto ad_credentials = security::derive_ad_credentials("password", "ENDORIUM.LOCAL", "Administrator");
    assert(ad_credentials.nt_hash_hex == "8846f7eaee8fb117ad06bdd830b7586c");
    assert(ad_credentials.kerberos_keys.size() == 2);
    assert(ad_credentials.kerberos_keys[0].salt == "ENDORIUM.LOCALadministrator");
    assert(security::derive_ad_kerberos_aes_key("password", "ATHENA.MIT.EDUraeburn", 16, 1) == "42263c6e89f4fc28b8df68ee09799f15");
    assert(security::derive_ad_kerberos_aes_key("password", "ATHENA.MIT.EDUraeburn", 32, 1) == "fe697b52bc0d3ce14432ba036a92e65bbb52280990a2fa27883998d72af30161");
    assert(security::derive_ad_kerberos_aes_key("password", "ATHENA.MIT.EDUraeburn", 16, 1200) == "4c01cd46d632d01e6dbe230a01ed642a");
    assert(security::derive_ad_kerberos_aes_key("password", "ATHENA.MIT.EDUraeburn", 32, 1200) == "55a6ac740ad17b4846941051e1e8b0a7548d93b0ab30a8bc3ff16280382b8c2a");
    const auto secret_test_root = std::filesystem::temp_directory_path() / "endorium-nexus-ad-secret-test";
    std::filesystem::remove_all(secret_test_root);
    std::filesystem::create_directories(secret_test_root);
    const auto secret_key_file = secret_test_root / "ad-kek.key";
    const auto sealed_secret = security::seal_ad_secret(secret_key_file, "kerberos-key-material");
    const auto opened_secret = security::open_ad_secret(secret_key_file, sealed_secret);
    assert(opened_secret.has_value());
    assert(*opened_secret == "kerberos-key-material");
    std::filesystem::remove(secret_key_file);
    assert(!security::open_ad_secret(secret_key_file, sealed_secret).has_value());
    std::filesystem::remove_all(secret_test_root);

    security::Totp totp;
    const auto secret = totp.generate_secret();
    const auto now = std::chrono::system_clock::now();
    const auto code = totp.code_at(secret, now);
    assert(totp.verify(secret, code, now));

    security::PkiService pki;
    const auto root = pki.create_root_ca({"Endorium Root", "Endorium", {"endorium.local"}}, 3650);
    const auto leaf = pki.issue_leaf_certificate(root, {"api.endorium.local", "Endorium", {"api.endorium.local"}}, 365);
    assert(root.certificate_pem.find("BEGIN CERTIFICATE") != std::string::npos);
    assert(leaf.private_key_pem.find("BEGIN PRIVATE KEY") != std::string::npos);

    const core::AptRepository repository{
        "bookworm",
        "main",
        {
            {"endorium-agent", "0.1.0", "amd64", "main", "pool/main/e/endorium-agent_0.1.0_amd64.deb", "abc123", 12345},
        }};
    const auto packages = protocol::render_packages_index(repository);
    const auto release = protocol::render_release_file(repository, "Endorium", "stable", "abc123", packages.size());
    const auto gzip = protocol::gzip_bytes(packages);
    assert(packages.find("Package: endorium-agent") != std::string::npos);
    assert(release.find("Codename: bookworm") != std::string::npos);
    assert(!gzip.empty());

    jobs::JobQueue queue;
    assert(queue.pending_count() >= 1);
    const auto job = queue.enqueue("dns", "Reload zone");
    assert(job.domain == "dns");

    const auto state_root = std::filesystem::temp_directory_path() / "endorium-nexus-settings-test";
    std::filesystem::remove_all(state_root);

    core::Config config;
    config.environment = "development";
    config.domain = "endorium.local";
    config.http = {"127.0.0.1", 8080};
    config.dns_udp = {"127.0.0.1", 8053};
    config.dns_tcp = {"127.0.0.1", 8053};
    config.dhcp = {"127.0.0.1", 8067};
    config.ldap = {"127.0.0.1", 8389};
    config.ldaps = {"127.0.0.1", 8636};
    config.kerberos = {"127.0.0.1", 8088};
    config.kpasswd = {"127.0.0.1", 8464};
    config.global_catalog = {"127.0.0.1", 8326};
    config.rpc_endpoint_mapper = {"127.0.0.1", 8135};
    config.smb = {"127.0.0.1", 8445};
    config.database_url = "";
    config.admin_email = "admin@endorium.local";
    config.admin_password_hash = hash;
    config.state_root = state_root;

    nexus::api::PlatformState first_state(config);
    assert(!first_state.active_directory_domain().has_value());
    assert(first_state.create_active_directory_domain(
        {"endorium.local", "ENDORIUM", "", "", "", ""},
        "Administrator",
        "Administrator",
        "ChangeMe-AD-1",
        "dc1",
        "10.10.10.10",
        "tester"));
    const auto ad_domain = first_state.active_directory_domain();
    assert(ad_domain.has_value());
    assert(ad_domain->dns_name == "endorium.local");
    assert(ad_domain->realm == "ENDORIUM.LOCAL");
    assert(ad_domain->base_dn == "dc=endorium,dc=local");
    const auto ad_readiness = first_state.active_directory_readiness();
    assert(std::any_of(ad_readiness.begin(), ad_readiness.end(), [](const auto& item) {
        return item.id == "domain" && item.ready;
    }));
    assert(std::any_of(ad_readiness.begin(), ad_readiness.end(), [](const auto& item) {
        return item.id == "kerberos" && !item.ready;
    }));
    const auto ad_objects = first_state.directory_objects();
    assert(std::any_of(ad_objects.begin(), ad_objects.end(), [](const auto& object) {
        return object.kind == "user" && object.attributes.contains("sAMAccountName") && object.attributes.at("sAMAccountName") == "Administrator";
    }));
    assert(std::any_of(ad_objects.begin(), ad_objects.end(), [](const auto& object) {
        return object.attributes.contains("sAMAccountName") &&
               object.attributes.at("sAMAccountName") == "krbtgt" &&
               object.attributes.contains("adSecretState") &&
               object.attributes.at("adSecretState") == "wrapped";
    }));
    assert(std::any_of(ad_objects.begin(), ad_objects.end(), [](const auto& object) {
        return object.kind == "computer" &&
               object.attributes.contains("servicePrincipalName") &&
               object.attributes.contains("adSecretState");
    }));
    assert(first_state.find_zone("endorium.local").has_value());
    assert(!first_state.create_active_directory_domain(
        {"other.local", "OTHER", "", "", "", ""},
        "Administrator",
        "Administrator",
        "ChangeMe-AD-1",
        "dc1",
        "10.10.10.10",
        "tester"));

    core::DirectoryObject user{
        "uid=alice,ou=People,dc=endorium,dc=local",
        "ou=People,dc=endorium,dc=local",
        "user",
        {"inetOrgPerson", "person"},
        {{"cn", "Alice Admin"}, {"sn", "Admin"}, {"uid", "alice"}}};
    assert(first_state.create_directory_object(user, "alice-secret", "tester"));
    auto directory = first_state.directory_objects();
    const auto alice = std::find_if(directory.begin(), directory.end(), [](const auto& object) {
        return object.dn == "uid=alice,ou=People,dc=endorium,dc=local";
    });
    assert(alice != directory.end());
    assert(alice->attributes.count("userPasswordHash") == 1);
    assert(alice->attributes.at("userPasswordHash") != "alice-secret");
    assert(alice->attributes.at("adSecretState") == "wrapped");
    assert(!first_state.create_directory_object({"not-a-dn", "", "user", {"person"}, {}}, "", "tester"));
    user.attributes["mail"] = "alice@endorium.local";
    assert(first_state.update_directory_object("uid=alice,ou=People,dc=endorium,dc=local", user, "", "tester"));
    assert(first_state.delete_directory_object("uid=alice,ou=People,dc=endorium,dc=local", "tester"));
    assert(!first_state.delete_directory_object("uid=missing,dc=endorium,dc=local", "tester"));

    assert(first_state.create_pki_authority("root-ca", {"Endorium Root CA", "Endorium", {"ca.endorium.local"}}, 3650, "tester"));
    assert(first_state.pki_authorities().size() == 1);
    assert(first_state.issue_pki_certificate("root-ca", {"api.endorium.local", "Endorium", {"api.endorium.local"}}, 365, "tester"));
    auto issued_certs = first_state.pki_certificates();
    assert(issued_certs.size() == 1);
    assert(issued_certs[0].certificate_pem.find("BEGIN CERTIFICATE") != std::string::npos);
    assert(first_state.revoke_certificate(issued_certs[0].serial_hex, issued_certs[0].common_name, "cessationOfOperation", "tester"));
    assert(first_state.pki_revocations().size() == 1);
    assert(!first_state.revoke_certificate(issued_certs[0].serial_hex, issued_certs[0].common_name, "cessationOfOperation", "tester"));

    assert(first_state.create_apt_repository("bookworm", "main", "tester"));
    assert(first_state.add_apt_package(
        "bookworm",
        "main",
        {"endorium-agent", "0.1.0", "amd64", "main", "pool/main/e/endorium-agent_0.1.0_amd64.deb", "abc123", 12345},
        "tester"));
    const auto rendered_packages = first_state.render_apt_packages("bookworm", "main");
    const auto rendered_release = first_state.render_apt_release("bookworm", "main");
    assert(rendered_packages.has_value());
    assert(rendered_packages->find("Package: endorium-agent") != std::string::npos);
    assert(rendered_release.has_value());
    assert(rendered_release->find("Codename: bookworm") != std::string::npos);
    assert(first_state.delete_apt_package("bookworm", "main", 0, "tester"));
    assert(first_state.delete_apt_repository("bookworm", "main", "tester"));

    auto updated = config;
    updated.domain = "control.endorium.local";
    updated.http.port = 18080;
    updated.directory.base_dn = "dc=control,dc=endorium,dc=local";
    updated.pki.common_name = "Control Root CA";
    updated.repo.distribution = "trixie";
    assert(first_state.update_settings(updated, "tester"));

    const auto settings_file = state_root / "settings.json";
    assert(std::filesystem::exists(settings_file));

    nexus::api::PlatformState second_state(config);
    assert(second_state.config().domain == "control.endorium.local");
    assert(second_state.config().http.port == 18080);
    assert(second_state.config().state_root == state_root);
    assert(second_state.config().directory.base_dn == "dc=control,dc=endorium,dc=local");
    assert(second_state.config().pki.common_name == "Control Root CA");
    assert(second_state.config().repo.distribution == "trixie");

    std::filesystem::remove_all(state_root);
    return 0;
}
