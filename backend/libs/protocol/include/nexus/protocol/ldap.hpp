#pragma once

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace nexus::protocol {

struct LdapDirectoryInfo {
    std::string dns_name;
    std::string base_dn;
    std::string realm;
    std::string site_name;
    std::string domain_controller_host;
    std::string domain_controller_address{"127.0.0.1"};
};

struct LdapObject {
    std::string dn;
    std::string parent_dn;
    std::string kind;
    std::vector<std::string> object_classes;
    std::map<std::string, std::string> attributes;
};

[[nodiscard]] std::vector<std::string> split_dn(const std::string& distinguished_name);
[[nodiscard]] bool is_valid_dn(const std::string& distinguished_name);
[[nodiscard]] std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory);
[[nodiscard]] std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects);

}  // namespace nexus::protocol
