#pragma once

#include <filesystem>
#include <functional>
#include <map>
#include <string>
#include <vector>


namespace nexus::core {

struct Config;

struct ServiceDefinition {
    std::string id;
    std::string label;
    int priority{0};
    bool critical{true};
    std::string feature_flag;
    std::string binary_name;
    std::vector<std::string> capabilities;
    std::function<std::vector<std::string>(const Config&)> endpoints;
    std::string enabled_summary;
    std::string disabled_summary;
};

struct ListenerConfig {
    std::string host;
    int port;
};

struct DirectoryConfig {
    std::string base_dn{"dc=endorium,dc=local"};
    std::string organization{"Endorium"};
    std::string realm{"ENDORIUM.LOCAL"};
    std::string site_name{"Default-First-Site-Name"};
    std::string domain_controller_host{"dc1"};
    std::string domain_controller_address{"127.0.0.1"};
    std::filesystem::path key_encryption_key_file;
};

struct DnsConfig {
    std::string primary_ns{"ns1.endorium.local"};
    std::string admin_mailbox{"hostmaster.endorium.local"};
    std::uint32_t default_ttl{3600};
};

struct DhcpConfig {
    std::string subnet{"10.10.10.0/24"};
    std::string range_start{"10.10.10.100"};
    std::string range_end{"10.10.10.200"};
    std::string router{"10.10.10.1"};
};

struct PkiConfig {
    std::string organization{"Endorium"};
    std::string common_name{"Endorium Root CA"};
    int leaf_days_valid{365};
};

struct RepoConfig {
    std::string origin{"Endorium"};
    std::string distribution{"bookworm"};
    std::string component{"main"};
};

struct Config {
    std::string environment;
    std::string domain;
    std::string ad_port_profile{"dev"};
    ListenerConfig http;
    ListenerConfig dns_udp;
    ListenerConfig dns_tcp;
    ListenerConfig dhcp;
    ListenerConfig ldap;
    ListenerConfig ldaps;
    ListenerConfig gc;
    ListenerConfig kerberos;
    ListenerConfig kpasswd;
    ListenerConfig rpc;
    ListenerConfig smb;
    std::string database_url;
    std::filesystem::path sql_migrations_dir;
    std::string admin_email;
    std::string admin_password_hash;
    std::string admin_totp_secret;
    std::filesystem::path ui_dist_dir;
    std::filesystem::path blob_root;
    std::filesystem::path state_root;
    DirectoryConfig directory;
    DnsConfig dns;
    DhcpConfig dhcp_service;
    PkiConfig pki;
    RepoConfig repo;
    std::map<std::string, bool> features;

    [[nodiscard]] bool is_development() const;
    static Config from_env();
};

[[nodiscard]] std::vector<ServiceDefinition> service_definitions();

}  // namespace nexus::core
