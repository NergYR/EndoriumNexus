#include "nexus/core/config.hpp"

#include <cstdlib>

namespace nexus::core {

namespace {

std::string read_env(const char* key, const std::string& fallback) {
    if (const char* value = std::getenv(key); value != nullptr) {
        return value;
    }
    return fallback;
}

int read_env_int(const char* key, int fallback) {
    if (const char* value = std::getenv(key); value != nullptr) {
        try {
            return std::stoi(value);
        } catch (...) {
            return fallback;
        }
    }
    return fallback;
}

}  // namespace

std::vector<ServiceDefinition> service_definitions() {
    return {
        {
            "api",
            "Control API",
            0,
            true,
            "",
            "nexus-api",
            {"https", "rest", "sse"},
            [](const Config& config) {
                return std::vector<std::string>{config.http.host + ":" + std::to_string(config.http.port)};
            },
            "REST API, session auth, SSE dashboard",
            "Control API is always online",
        },
        {
            "directory",
            "Directory + KDC",
            10,
            true,
            "directory",
            "nexus-directory",
            {"ldap", "ldaps", "kerberos"},
            [](const Config& config) {
                return std::vector<std::string>{
                    config.ldap.host + ":" + std::to_string(config.ldap.port),
                    config.ldaps.host + ":" + std::to_string(config.ldaps.port),
                    config.kerberos.host + ":" + std::to_string(config.kerberos.port),
                };
            },
            "Directory listeners are online and ready for provisioning",
            "Directory is disabled until the shared configuration is completed",
        },
        {
            "network",
            "DNS + DHCP",
            20,
            true,
            "network",
            "nexus-network",
            {"dns", "dhcpv4"},
            [](const Config& config) {
                return std::vector<std::string>{
                    config.dns_udp.host + ":" + std::to_string(config.dns_udp.port),
                    config.dhcp.host + ":" + std::to_string(config.dhcp.port),
                };
            },
            "DNS and DHCP listeners are online",
            "Network services are disabled until zones and pools are configured",
        },
        {
            "pki-repo",
            "PKI + APT",
            30,
            true,
            "pki-repo",
            "nexus-pki-repo",
            {"x509", "crl", "apt"},
            [](const Config&) {
                return std::vector<std::string>{"internal"};
            },
            "PKI and repository services are online",
            "PKI and repository services are disabled until trust and packaging parameters are configured",
        },
    };
}

bool Config::is_development() const {
    return environment == "development";
}

Config Config::from_env() {
    Config config;
    config.environment = read_env("NEXUS_ENV", "development");
    config.domain = read_env("NEXUS_DOMAIN", "endorium.local");
    config.http = {read_env("NEXUS_HTTP_HOST", "127.0.0.1"), read_env_int("NEXUS_HTTP_PORT", 8080)};
    config.dns_udp = {read_env("NEXUS_HTTP_HOST", "127.0.0.1"), read_env_int("NEXUS_DNS_UDP_PORT", 8053)};
    config.dns_tcp = {read_env("NEXUS_HTTP_HOST", "127.0.0.1"), read_env_int("NEXUS_DNS_TCP_PORT", 8053)};
    config.dhcp = {read_env("NEXUS_HTTP_HOST", "127.0.0.1"), read_env_int("NEXUS_DHCP_PORT", 8067)};
    config.ldap = {read_env("NEXUS_HTTP_HOST", "127.0.0.1"), read_env_int("NEXUS_LDAP_PORT", 8389)};
    config.ldaps = {read_env("NEXUS_HTTP_HOST", "127.0.0.1"), read_env_int("NEXUS_LDAPS_PORT", 8636)};
    config.kerberos = {read_env("NEXUS_HTTP_HOST", "127.0.0.1"), read_env_int("NEXUS_KRB_PORT", 8088)};
    config.database_url = read_env("NEXUS_DATABASE_URL", "");
    config.admin_email = read_env("NEXUS_ADMIN_EMAIL", "admin@endorium.local");
    config.admin_password_hash = read_env("NEXUS_ADMIN_PASSWORD_HASH", "");
    config.admin_totp_secret = read_env("NEXUS_ADMIN_TOTP_SECRET", "");
    config.ui_dist_dir = read_env("NEXUS_UI_DIST_DIR", "frontend/dist");
    config.blob_root = read_env("NEXUS_BLOB_ROOT", "var/blob");
    config.state_root = read_env("NEXUS_STATE_ROOT", "var/state");
    config.directory.base_dn = read_env("NEXUS_DIRECTORY_BASE_DN", config.directory.base_dn);
    config.directory.organization = read_env("NEXUS_DIRECTORY_ORG", config.directory.organization);
    config.directory.realm = read_env("NEXUS_DIRECTORY_REALM", config.directory.realm);
    config.dns.primary_ns = read_env("NEXUS_DNS_PRIMARY_NS", config.dns.primary_ns);
    config.dns.admin_mailbox = read_env("NEXUS_DNS_ADMIN_MAILBOX", config.dns.admin_mailbox);
    config.dns.default_ttl = static_cast<std::uint32_t>(read_env_int("NEXUS_DNS_DEFAULT_TTL", static_cast<int>(config.dns.default_ttl)));
    config.dhcp_service.subnet = read_env("NEXUS_DHCP_SUBNET", config.dhcp_service.subnet);
    config.dhcp_service.range_start = read_env("NEXUS_DHCP_RANGE_START", config.dhcp_service.range_start);
    config.dhcp_service.range_end = read_env("NEXUS_DHCP_RANGE_END", config.dhcp_service.range_end);
    config.dhcp_service.router = read_env("NEXUS_DHCP_ROUTER", config.dhcp_service.router);
    config.pki.organization = read_env("NEXUS_PKI_ORG", config.pki.organization);
    config.pki.common_name = read_env("NEXUS_PKI_COMMON_NAME", config.pki.common_name);
    config.pki.leaf_days_valid = read_env_int("NEXUS_PKI_LEAF_DAYS", config.pki.leaf_days_valid);
    config.repo.origin = read_env("NEXUS_REPO_ORIGIN", config.repo.origin);
    config.repo.distribution = read_env("NEXUS_REPO_DISTRIBUTION", config.repo.distribution);
    config.repo.component = read_env("NEXUS_REPO_COMPONENT", config.repo.component);
    return config;
}

}  // namespace nexus::core
