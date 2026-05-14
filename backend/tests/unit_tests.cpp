#include "nexus/core/models.hpp"
#include "nexus/jobs/queue.hpp"
#include "nexus/protocol/dhcp.hpp"
#include "nexus/protocol/dns.hpp"
#include "nexus/protocol/ldap.hpp"
#include "nexus/protocol/repo.hpp"
#include "nexus/security/password_hasher.hpp"
#include "nexus/security/pki.hpp"
#include "nexus/security/totp.hpp"

#include "apps/api/platform_state.hpp"

#include <algorithm>
#include <cassert>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <string>

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
