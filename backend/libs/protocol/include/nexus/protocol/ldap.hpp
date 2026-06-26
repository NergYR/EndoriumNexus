#pragma once

#include <cstdint>
#include <functional>
#include <map>
#include <optional>
#include <string>
#include <vector>

#include "nexus/protocol/kerberos.hpp"

namespace nexus::protocol {

struct LdapDirectoryInfo {
    std::string dns_name;
    std::string base_dn;
    std::string realm;
    std::string site_name;
    std::string domain_controller_host;
    std::string domain_controller_address{"127.0.0.1"};
    std::string domain_sid;
};

struct LdapObject {
    std::string dn;
    std::string parent_dn;
    std::string kind;
    std::vector<std::string> object_classes;
    std::map<std::string, std::string> attributes;
};

enum class LdapMutationType {
    add,
    modify,
    rename,
    remove,
};

struct LdapMutation {
    LdapMutationType type{LdapMutationType::add};
    std::string previous_dn;
    LdapObject object;
    std::map<std::string, std::string> attributes;
    std::map<std::string, int> attribute_operations;
};

struct LdapMutationResult {
    bool ok{false};
    int result_code{0};
    std::string diagnostic;
};

struct LdapSessionInfo {
    bool authenticated{false};
    std::string bind_dn;
    std::string principal;
    std::string sasl_mechanism;
};

using LdapMutationHandler = std::function<LdapMutationResult(const LdapMutation&)>;
using LdapSimpleBindVerifier = std::function<std::optional<std::string>(
    const std::string& bind_name,
    const std::string& password)>;

[[nodiscard]] std::vector<std::string> split_dn(const std::string& distinguished_name);
[[nodiscard]] bool is_valid_dn(const std::string& distinguished_name);
[[nodiscard]] std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory);
[[nodiscard]] std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects);
[[nodiscard]] std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects,
    const LdapMutationHandler& mutation_handler);
[[nodiscard]] std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects,
    const LdapMutationHandler& mutation_handler,
    const KerberosRealmInfo& kerberos_realm);
[[nodiscard]] std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects,
    const LdapMutationHandler& mutation_handler,
    const KerberosRealmInfo& kerberos_realm,
    LdapSessionInfo* session);
[[nodiscard]] std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects,
    const LdapMutationHandler& mutation_handler,
    const KerberosRealmInfo& kerberos_realm,
    LdapSessionInfo* session,
    const LdapSimpleBindVerifier& simple_bind_verifier);

}  // namespace nexus::protocol
