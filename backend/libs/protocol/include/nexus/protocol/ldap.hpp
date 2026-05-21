#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace nexus::protocol {

struct LdapDirectoryInfo {
    std::string dns_name;
    std::string base_dn;
    std::string realm;
    std::string site_name;
    std::string domain_controller_host;
};

[[nodiscard]] std::vector<std::string> split_dn(const std::string& distinguished_name);
[[nodiscard]] bool is_valid_dn(const std::string& distinguished_name);
[[nodiscard]] std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory);

}  // namespace nexus::protocol
