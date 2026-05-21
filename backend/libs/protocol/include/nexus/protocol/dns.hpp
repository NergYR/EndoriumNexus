#pragma once

#include "nexus/core/models.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace nexus::protocol {

struct ActiveDirectoryDnsConfig {
    std::string dns_name;
    std::string site_name;
    std::string domain_controller_host;
    std::string domain_controller_address;
    std::uint16_t ldap_port{389};
    std::uint16_t kerberos_port{88};
    std::uint16_t kpasswd_port{464};
    std::uint16_t global_catalog_port{3268};
};

[[nodiscard]] std::string render_zone_file(const nexus::core::DnsZone& zone, const std::string& primary_ns, const std::string& admin_mailbox);
[[nodiscard]] nexus::core::DnsZone make_active_directory_dns_zone(const ActiveDirectoryDnsConfig& config);
[[nodiscard]] std::vector<std::uint8_t> resolve_dns_query(
    const std::vector<std::uint8_t>& query,
    const std::vector<nexus::core::DnsZone>& zones);
[[nodiscard]] std::vector<std::uint8_t> resolve_dns_tcp_query(
    const std::vector<std::uint8_t>& frame,
    const std::vector<nexus::core::DnsZone>& zones);

}  // namespace nexus::protocol
