#include "nexus/protocol/rpc.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cctype>
#include <cstring>
#include <iomanip>
#include <mutex>
#include <optional>
#include <sstream>
#include <string_view>
#include <unordered_map>
#include <utility>

namespace nexus::protocol {

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr std::uint8_t ptype_request = 0x00;
constexpr std::uint8_t ptype_response = 0x02;
constexpr std::uint8_t ptype_fault = 0x03;
constexpr std::uint8_t ptype_bind = 0x0b;
constexpr std::uint8_t ptype_bind_ack = 0x0c;
constexpr std::uint32_t nca_s_op_rng_error = 0x1c010002U;
constexpr std::uint32_t nt_status_success = 0x00000000U;
constexpr std::uint32_t nt_status_access_denied = 0xc0000022U;
constexpr std::uint32_t nt_status_no_such_user = 0xc0000064U;
constexpr std::uint32_t nt_status_account_disabled = 0xc0000072U;
constexpr std::uint32_t nt_status_invalid_level = 0xc0000148U;
constexpr std::uint32_t nt_status_no_trust_sam_account = 0xc000018bU;
constexpr std::uint32_t nt_status_account_expired = 0xc0000193U;
constexpr std::uint32_t win32_error_invalid_parameter = 0x00000057U;
constexpr std::uint32_t win32_error_invalid_level = 0x0000007cU;
constexpr std::uint32_t rpc_status_not_supported = 0x00000032U;
constexpr std::uint32_t netlogon_flag_strong_keys = 0x00004000U;
constexpr std::uint32_t netlogon_flag_aes = 0x01000000U;
constexpr std::uint32_t netlogon_server_capabilities =
    0x000fffffU | netlogon_flag_strong_keys | netlogon_flag_aes;
constexpr std::uint32_t samr_user_handle_marker = 0x55535253U;
constexpr std::uint32_t samr_group_handle_marker = 0x50524753U;
constexpr std::uint32_t samr_alias_handle_marker = 0x53494c41U;
constexpr std::uint32_t lsa_account_handle_marker = 0x54434341U;
constexpr std::uint32_t lsa_trusted_domain_handle_marker = 0x5453444dU;
constexpr std::uint32_t sid_name_use_user = 1;
constexpr std::uint32_t sid_name_use_group = 2;
constexpr std::uint32_t sid_name_use_alias = 4;
constexpr std::uint32_t sid_name_use_computer = 9;
constexpr std::uint32_t user_account_control_normal = 0x00000200U;
constexpr std::uint32_t user_account_control_workstation_trust = 0x00001000U;
constexpr std::uint32_t user_account_control_passwd_notreqd = 0x00000020U;

constexpr const char* uuid_epmapper = "e1af8308-5d1f-11c9-91a4-08002b14a0fa";
constexpr const char* uuid_netlogon = "12345678-1234-abcd-ef00-01234567cffb";
constexpr const char* uuid_samr = "12345778-1234-abcd-ef00-0123456789ac";
constexpr const char* uuid_lsarpc = "12345778-1234-abcd-ef00-0123456789ab";
constexpr const char* uuid_srvsvc = "4b324fc8-1670-01d3-1278-5a47bf6ee188";
constexpr const char* uuid_wkssvc = "6bffd098-a112-3610-9833-46c3f87e345a";

struct RpcEndpointHint {
    std::string uuid;
    std::string annotation;
    std::string protocol_sequence;
    std::string endpoint;
};

struct SamrAliasRecord {
    std::uint32_t rid{0};
    std::string name;
    std::string description;
    std::vector<std::uint32_t> member_rids;
};

struct LsaPrivilegeRecord {
    std::string name;
    std::string display_name;
    std::uint32_t luid_low{0};
    std::uint32_t luid_high{0};
};

struct NetlogonChallengeEntry {
    std::string computer_name;
    Bytes client_challenge;
    Bytes server_challenge;
    std::chrono::steady_clock::time_point updated_at;
};

struct NetlogonSecureChannelSession {
    std::string account_name;
    std::string computer_name;
    Bytes session_key;
    Bytes stored_credential;
    std::uint32_t negotiated_flags{0};
    std::uint32_t requested_flags{0};
    std::uint32_t rid{0};
    std::chrono::steady_clock::time_point updated_at;
};

struct VerifiedNetlogonAuthenticator {
    Bytes return_authenticator;
    std::string session_cache_key;
    std::string account_name;
    std::string computer_name;
    Bytes session_key;
    std::uint32_t negotiated_flags{0};
    std::uint32_t requested_flags{0};
};

struct NetlogonControlCall {
    std::uint32_t function_code{1};
    std::uint32_t query_level{1};
};

std::mutex netlogon_challenge_mutex;
std::unordered_map<std::string, NetlogonChallengeEntry> netlogon_challenges;
std::mutex netlogon_session_mutex;
std::unordered_map<std::string, NetlogonSecureChannelSession> netlogon_sessions;

std::optional<SamrAccountRecord> resolve_samr_account(
    const RpcRuntimeInfo& runtime,
    const SamrAccountRequest& request);
Bytes fault_response(const RpcRequestInfo& request);
Bytes endpoint_mapper_lookup_response(const RpcRequestInfo& request, std::uint16_t endpoint_port);
Bytes endpoint_mapper_map_response(const RpcRequestInfo& request, std::uint16_t endpoint_port);
Bytes endpoint_mapper_alive_response(const RpcRequestInfo& request, std::uint16_t endpoint_port);

std::uint16_t read_u16_le(const Bytes& input, std::size_t offset) {
    return static_cast<std::uint16_t>(input[offset]) |
           static_cast<std::uint16_t>(input[offset + 1] << 8U);
}

std::uint32_t read_u32_le(const Bytes& input, std::size_t offset) {
    return static_cast<std::uint32_t>(input[offset]) |
           (static_cast<std::uint32_t>(input[offset + 1]) << 8U) |
           (static_cast<std::uint32_t>(input[offset + 2]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 3]) << 24U);
}

void write_u16_le(Bytes& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

void write_u32_le(Bytes& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
}

void write_u64_le(Bytes& output, std::uint64_t value) {
    for (int index = 0; index < 8; ++index) {
        output.push_back(static_cast<std::uint8_t>((value >> (index * 8U)) & 0xffU));
    }
}

void put_u32_le(Bytes& output, std::size_t offset, std::uint32_t value) {
    if (offset + 4 > output.size()) {
        return;
    }
    output[offset] = static_cast<std::uint8_t>(value & 0xffU);
    output[offset + 1] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
    output[offset + 2] = static_cast<std::uint8_t>((value >> 16U) & 0xffU);
    output[offset + 3] = static_cast<std::uint8_t>((value >> 24U) & 0xffU);
}

void append_bytes(Bytes& output, const Bytes& chunk) {
    output.insert(output.end(), chunk.begin(), chunk.end());
}

std::string lower_ascii(std::string value) {
    for (auto& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

std::string upper_ascii(std::string value) {
    for (auto& ch : value) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    return value;
}

std::string trim_pipe_prefix(std::string value) {
    while (!value.empty() && (value.front() == '\\' || value.front() == '/')) {
        value.erase(value.begin());
    }
    return lower_ascii(value);
}

std::string normalize_netlogon_name(std::string value) {
    while (!value.empty() && (value.front() == '\\' || value.front() == '/')) {
        value.erase(value.begin());
    }
    const auto slash = value.find_last_of("\\/");
    if (slash != std::string::npos) {
        value = value.substr(slash + 1);
    }
    const auto at = value.find('@');
    if (at != std::string::npos) {
        value = value.substr(0, at);
    }
    while (!value.empty() && (value.back() == '\0' || value.back() == '.' || value.back() == ' ')) {
        value.pop_back();
    }
    return lower_ascii(value);
}

bool account_name_matches(const std::string& requested, const std::string& stored) {
    const auto left = normalize_netlogon_name(requested);
    const auto right = normalize_netlogon_name(stored);
    if (left.empty() || right.empty()) {
        return true;
    }
    if (left == right) {
        return true;
    }
    return left + "$" == right || left == right + "$";
}

std::uint32_t stable_hash32(const std::string& value) {
    std::uint32_t hash = 2166136261U;
    for (const auto ch : value) {
        hash ^= static_cast<std::uint8_t>(ch);
        hash *= 16777619U;
    }
    return hash;
}

std::string default_domain_sid(const std::string& domain_name) {
    const auto domain = domain_name.empty() ? std::string{"endorium.local"} : lower_ascii(domain_name);
    const auto a = 1000U + (stable_hash32(domain + ":a") % 1000000000U);
    const auto b = 1000U + (stable_hash32(domain + ":b") % 1000000000U);
    const auto c = 1000U + (stable_hash32(domain + ":c") % 1000000000U);
    return "S-1-5-21-" + std::to_string(a) + "-" + std::to_string(b) + "-" + std::to_string(c);
}

std::string runtime_domain_sid(const RpcRuntimeInfo& runtime) {
    if (!runtime.domain_sid.empty()) {
        return runtime.domain_sid;
    }
    return default_domain_sid(runtime.domain_dns_name);
}

std::string runtime_domain_netbios_name(const RpcRuntimeInfo& runtime) {
    if (!runtime.domain_netbios_name.empty()) {
        return runtime.domain_netbios_name;
    }
    return "ENDORIUM";
}

std::string runtime_domain_dns_name(const RpcRuntimeInfo& runtime) {
    if (!runtime.domain_dns_name.empty()) {
        return lower_ascii(runtime.domain_dns_name);
    }
    return "endorium.local";
}

std::string runtime_dc_host_name(const RpcRuntimeInfo& runtime) {
    auto host = runtime.domain_controller_host.empty() ? std::string{"dc1"} : lower_ascii(runtime.domain_controller_host);
    const auto dot = host.find('.');
    if (dot != std::string::npos) {
        host = host.substr(0, dot);
    }
    return host.empty() ? std::string{"dc1"} : host;
}

std::string runtime_dc_dns_name(const RpcRuntimeInfo& runtime) {
    if (!runtime.domain_controller_host.empty() && runtime.domain_controller_host.find('.') != std::string::npos) {
        return lower_ascii(runtime.domain_controller_host);
    }
    return runtime_dc_host_name(runtime) + "." + runtime_domain_dns_name(runtime);
}

std::string runtime_dc_netbios_name(const RpcRuntimeInfo& runtime) {
    return upper_ascii(runtime_dc_host_name(runtime));
}

std::string runtime_dc_address(const RpcRuntimeInfo& runtime) {
    if (!runtime.domain_controller_address.empty()) {
        return runtime.domain_controller_address;
    }
    return "127.0.0.1";
}

std::string runtime_site_name(const RpcRuntimeInfo& runtime) {
    if (!runtime.site_name.empty()) {
        return runtime.site_name;
    }
    return "Default-First-Site-Name";
}

std::uint32_t synthetic_rid_for_name(const std::string& name) {
    const auto normalized = normalize_netlogon_name(name);
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

std::vector<SamrAliasRecord> well_known_samr_aliases() {
    return {
        {544, "Administrators", "Administrators have complete and unrestricted access to the domain", {500, 512}},
        {545, "Users", "Users are prevented from making accidental or intentional system-wide changes", {513}},
        {546, "Guests", "Guests have the same access as members of the Users group by default", {514}},
        {548, "Account Operators", "Members can administer domain user and group accounts", {}},
        {549, "Server Operators", "Members can administer domain servers", {}},
        {550, "Print Operators", "Members can administer printers", {}},
        {551, "Backup Operators", "Members can bypass file security to back up and restore files", {}},
        {552, "Replicator", "Supports file replication in a domain", {}},
    };
}

std::vector<LsaPrivilegeRecord> well_known_lsa_privileges() {
    return {
        {"SeMachineAccountPrivilege", "Add workstations to domain", 6, 0},
        {"SeTcbPrivilege", "Act as part of the operating system", 7, 0},
        {"SeSecurityPrivilege", "Manage auditing and security log", 8, 0},
        {"SeBackupPrivilege", "Back up files and directories", 17, 0},
        {"SeRestorePrivilege", "Restore files and directories", 18, 0},
        {"SeDebugPrivilege", "Debug programs", 20, 0},
        {"SeChangeNotifyPrivilege", "Bypass traverse checking", 23, 0},
        {"SeImpersonatePrivilege", "Impersonate a client after authentication", 29, 0},
        {"SeCreateGlobalPrivilege", "Create global objects", 30, 0},
    };
}

std::optional<LsaPrivilegeRecord> well_known_lsa_privilege_by_name(const std::string& name) {
    const auto normalized = lower_ascii(name);
    for (const auto& privilege : well_known_lsa_privileges()) {
        if (lower_ascii(privilege.name) == normalized) {
            return privilege;
        }
    }
    return std::nullopt;
}

std::optional<LsaPrivilegeRecord> well_known_lsa_privilege_by_luid(
    std::uint32_t low,
    std::uint32_t high) {
    for (const auto& privilege : well_known_lsa_privileges()) {
        if (privilege.luid_low == low && privilege.luid_high == high) {
            return privilege;
        }
    }
    return std::nullopt;
}

std::optional<SamrAliasRecord> well_known_samr_alias(std::uint32_t rid) {
    const auto aliases = well_known_samr_aliases();
    const auto match = std::find_if(aliases.begin(), aliases.end(), [&](const auto& alias) {
        return alias.rid == rid;
    });
    if (match == aliases.end()) {
        return std::nullopt;
    }
    return *match;
}

std::optional<SamrAccountRecord> well_known_samr_account(const SamrAccountRequest& request) {
    const auto normalized_name = lower_ascii(request.sam_account_name);
    const auto matches = [&](const std::string& name, std::uint32_t rid) {
        return (!normalized_name.empty() && normalized_name == lower_ascii(name)) ||
               (request.rid != 0 && request.rid == rid);
    };
    const auto user = [&](const std::string& name,
                          std::uint32_t rid,
                          const std::vector<std::uint32_t>& groups,
                          std::uint32_t control = user_account_control_normal) {
        return SamrAccountRecord{name, rid, name, groups.empty() ? 513U : groups.front(), control, false, groups, sid_name_use_user};
    };
    const auto group = [&](const std::string& name, std::uint32_t rid) {
        return SamrAccountRecord{name, rid, name, 0, 0, false, {}, sid_name_use_group};
    };

    if (matches("Administrator", 500)) {
        return user("Administrator", 500, {513, 512, 544});
    }
    if (matches("Guest", 501)) {
        return user("Guest", 501, {514}, user_account_control_normal | 0x00000002U);
    }
    if (matches("krbtgt", 502)) {
        return user("krbtgt", 502, {513}, user_account_control_normal | 0x00000002U);
    }
    if (matches("Domain Admins", 512)) {
        return group("Domain Admins", 512);
    }
    if (matches("Domain Users", 513)) {
        return group("Domain Users", 513);
    }
    if (matches("Domain Guests", 514)) {
        return group("Domain Guests", 514);
    }
    if (matches("Domain Computers", 515)) {
        return group("Domain Computers", 515);
    }
    if (matches("Domain Controllers", 516)) {
        return group("Domain Controllers", 516);
    }
    if (matches("Cert Publishers", 517)) {
        return group("Cert Publishers", 517);
    }
    if (matches("Schema Admins", 518)) {
        return group("Schema Admins", 518);
    }
    if (matches("Enterprise Admins", 519)) {
        return group("Enterprise Admins", 519);
    }
    if (matches("Group Policy Creator Owners", 520)) {
        return group("Group Policy Creator Owners", 520);
    }
    if (matches("Read-only Domain Controllers", 521)) {
        return group("Read-only Domain Controllers", 521);
    }

    const auto aliases = well_known_samr_aliases();
    const auto alias = std::find_if(aliases.begin(), aliases.end(), [&](const auto& candidate) {
        return matches(candidate.name, candidate.rid);
    });
    if (alias != aliases.end()) {
        return SamrAccountRecord{alias->name, alias->rid, alias->name, 0, 0, false, {}, sid_name_use_alias};
    }

    return std::nullopt;
}

SamrAccountRecord normalized_samr_record(SamrAccountRecord record) {
    if (record.display_name.empty()) {
        record.display_name = record.sam_account_name;
        if (!record.display_name.empty() && record.display_name.back() == '$') {
            record.display_name.pop_back();
        }
    }
    record.machine_account = record.machine_account || record.sam_account_name.ends_with('$');
    if (record.machine_account) {
        record.sid_name_use = sid_name_use_computer;
    }
    if (record.sid_name_use == 0) {
        record.sid_name_use = record.machine_account ? sid_name_use_computer : sid_name_use_user;
    }
    if (record.primary_group_rid == 0 &&
        (record.sid_name_use == sid_name_use_user || record.sid_name_use == sid_name_use_computer)) {
        record.primary_group_rid = record.machine_account ? 515 : 513;
    }
    if (record.user_account_control == 0 &&
        (record.sid_name_use == sid_name_use_user || record.sid_name_use == sid_name_use_computer)) {
        record.user_account_control = record.machine_account
            ? user_account_control_workstation_trust | user_account_control_passwd_notreqd
            : user_account_control_normal;
    }
    if (record.group_rids.empty() && record.primary_group_rid != 0 &&
        (record.sid_name_use == sid_name_use_user || record.sid_name_use == sid_name_use_computer)) {
        record.group_rids.push_back(record.primary_group_rid);
    }
    return record;
}

std::string uuid_to_string(const Bytes& input, std::size_t offset) {
    if (offset + 16 > input.size()) {
        return "";
    }
    std::ostringstream out;
    out << std::hex << std::setfill('0');
    const auto byte = [&](std::size_t index) {
        return static_cast<int>(input[offset + index]);
    };
    out << std::setw(2) << byte(3) << std::setw(2) << byte(2) << std::setw(2) << byte(1) << std::setw(2) << byte(0) << '-';
    out << std::setw(2) << byte(5) << std::setw(2) << byte(4) << '-';
    out << std::setw(2) << byte(7) << std::setw(2) << byte(6) << '-';
    out << std::setw(2) << byte(8) << std::setw(2) << byte(9) << '-';
    for (std::size_t index = 10; index < 16; ++index) {
        out << std::setw(2) << byte(index);
    }
    return out.str();
}

std::optional<Bytes> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        return std::nullopt;
    }

    Bytes output;
    output.reserve(hex.size() / 2);
    for (std::size_t index = 0; index < hex.size(); index += 2) {
        const auto high = static_cast<unsigned char>(hex[index]);
        const auto low = static_cast<unsigned char>(hex[index + 1]);
        if (!std::isxdigit(high) || !std::isxdigit(low)) {
            return std::nullopt;
        }
        output.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(index, 2), nullptr, 16)));
    }
    return output;
}

std::optional<Bytes> hmac_sha256(const Bytes& key, const Bytes& message) {
    Bytes digest(EVP_MAX_MD_SIZE);
    unsigned int digest_len = 0;
    if (HMAC(
            EVP_sha256(),
            key.data(),
            static_cast<int>(key.size()),
            message.data(),
            message.size(),
            digest.data(),
            &digest_len) == nullptr) {
        return std::nullopt;
    }
    digest.resize(digest_len);
    return digest;
}

std::optional<Bytes> hmac_md5(const Bytes& key, const Bytes& message) {
    Bytes digest(EVP_MAX_MD_SIZE);
    unsigned int digest_len = 0;
    if (HMAC(
            EVP_md5(),
            key.data(),
            static_cast<int>(key.size()),
            message.data(),
            message.size(),
            digest.data(),
            &digest_len) == nullptr) {
        return std::nullopt;
    }
    digest.resize(digest_len);
    return digest;
}

std::optional<Bytes> aes_128_cfb8_encrypt(const Bytes& key, const Bytes& input) {
    if (key.size() != 16) {
        return std::nullopt;
    }

    std::array<unsigned char, 16> iv{};
    Bytes output(input.size() + 16);
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        return std::nullopt;
    }

    int out_len = 0;
    int total = 0;
    const bool ok =
        EVP_EncryptInit_ex(context, EVP_aes_128_cfb8(), nullptr, key.data(), iv.data()) == 1 &&
        EVP_CIPHER_CTX_set_padding(context, 0) == 1 &&
        EVP_EncryptUpdate(context, output.data(), &out_len, input.data(), static_cast<int>(input.size())) == 1;
    if (!ok) {
        EVP_CIPHER_CTX_free(context);
        return std::nullopt;
    }
    total = out_len;
    if (EVP_EncryptFinal_ex(context, output.data() + total, &out_len) != 1) {
        EVP_CIPHER_CTX_free(context);
        return std::nullopt;
    }
    total += out_len;
    EVP_CIPHER_CTX_free(context);
    output.resize(static_cast<std::size_t>(total));
    return output;
}

std::optional<Bytes> aes_128_cfb8_decrypt(const Bytes& key, const Bytes& input) {
    if (key.size() != 16) {
        return std::nullopt;
    }

    std::array<unsigned char, 16> iv{};
    Bytes output(input.size() + 16);
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        return std::nullopt;
    }

    int out_len = 0;
    int total = 0;
    const bool ok =
        EVP_DecryptInit_ex(context, EVP_aes_128_cfb8(), nullptr, key.data(), iv.data()) == 1 &&
        EVP_CIPHER_CTX_set_padding(context, 0) == 1 &&
        EVP_DecryptUpdate(context, output.data(), &out_len, input.data(), static_cast<int>(input.size())) == 1;
    if (!ok) {
        EVP_CIPHER_CTX_free(context);
        return std::nullopt;
    }
    total = out_len;
    if (EVP_DecryptFinal_ex(context, output.data() + total, &out_len) != 1) {
        EVP_CIPHER_CTX_free(context);
        return std::nullopt;
    }
    total += out_len;
    EVP_CIPHER_CTX_free(context);
    output.resize(static_cast<std::size_t>(total));
    return output;
}

void append_utf16le_codepoint(Bytes& output, std::uint32_t codepoint) {
    if (codepoint <= 0xffff) {
        output.push_back(static_cast<std::uint8_t>(codepoint & 0xffU));
        output.push_back(static_cast<std::uint8_t>((codepoint >> 8U) & 0xffU));
        return;
    }
    codepoint -= 0x10000U;
    const auto high = static_cast<std::uint16_t>(0xd800U + ((codepoint >> 10U) & 0x3ffU));
    const auto low = static_cast<std::uint16_t>(0xdc00U + (codepoint & 0x3ffU));
    output.push_back(static_cast<std::uint8_t>(high & 0xffU));
    output.push_back(static_cast<std::uint8_t>((high >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(low & 0xffU));
    output.push_back(static_cast<std::uint8_t>((low >> 8U) & 0xffU));
}

Bytes utf16le_from_utf8(const std::string& value) {
    Bytes output;
    output.reserve(value.size() * 2);
    for (std::size_t offset = 0; offset < value.size();) {
        const auto first = static_cast<std::uint8_t>(value[offset]);
        std::uint32_t codepoint = 0xfffdU;
        std::size_t consumed = 1;
        if (first < 0x80U) {
            codepoint = first;
        } else if ((first & 0xe0U) == 0xc0U && offset + 1 < value.size()) {
            const auto second = static_cast<std::uint8_t>(value[offset + 1]);
            if ((second & 0xc0U) == 0x80U) {
                codepoint = ((first & 0x1fU) << 6U) | (second & 0x3fU);
                consumed = 2;
            }
        } else if ((first & 0xf0U) == 0xe0U && offset + 2 < value.size()) {
            const auto second = static_cast<std::uint8_t>(value[offset + 1]);
            const auto third = static_cast<std::uint8_t>(value[offset + 2]);
            if ((second & 0xc0U) == 0x80U && (third & 0xc0U) == 0x80U) {
                codepoint = ((first & 0x0fU) << 12U) | ((second & 0x3fU) << 6U) | (third & 0x3fU);
                consumed = 3;
            }
        } else if ((first & 0xf8U) == 0xf0U && offset + 3 < value.size()) {
            const auto second = static_cast<std::uint8_t>(value[offset + 1]);
            const auto third = static_cast<std::uint8_t>(value[offset + 2]);
            const auto fourth = static_cast<std::uint8_t>(value[offset + 3]);
            if ((second & 0xc0U) == 0x80U && (third & 0xc0U) == 0x80U && (fourth & 0xc0U) == 0x80U) {
                codepoint = ((first & 0x07U) << 18U) |
                            ((second & 0x3fU) << 12U) |
                            ((third & 0x3fU) << 6U) |
                            (fourth & 0x3fU);
                consumed = 4;
            }
        }
        if (codepoint > 0x10ffffU || (codepoint >= 0xd800U && codepoint <= 0xdfffU)) {
            codepoint = 0xfffdU;
        }
        append_utf16le_codepoint(output, codepoint);
        offset += consumed;
    }
    return output;
}

void append_utf8_codepoint(std::string& output, std::uint32_t codepoint) {
    if (codepoint <= 0x7fU) {
        output.push_back(static_cast<char>(codepoint));
    } else if (codepoint <= 0x7ffU) {
        output.push_back(static_cast<char>(0xc0U | ((codepoint >> 6U) & 0x1fU)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    } else if (codepoint <= 0xffffU) {
        output.push_back(static_cast<char>(0xe0U | ((codepoint >> 12U) & 0x0fU)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    } else {
        output.push_back(static_cast<char>(0xf0U | ((codepoint >> 18U) & 0x07U)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 12U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | ((codepoint >> 6U) & 0x3fU)));
        output.push_back(static_cast<char>(0x80U | (codepoint & 0x3fU)));
    }
}

std::optional<std::string> decode_utf16le_password(const Bytes& buffer, std::size_t offset, std::size_t byte_count) {
    if (offset + byte_count > buffer.size() || byte_count % 2 != 0) {
        return std::nullopt;
    }
    std::string output;
    for (std::size_t index = 0; index < byte_count; index += 2) {
        const auto current = static_cast<std::uint16_t>(buffer[offset + index]) |
                             (static_cast<std::uint16_t>(buffer[offset + index + 1]) << 8U);
        std::uint32_t codepoint = current;
        if (current >= 0xd800U && current <= 0xdbffU) {
            if (index + 4 > byte_count) {
                return std::nullopt;
            }
            const auto next = static_cast<std::uint16_t>(buffer[offset + index + 2]) |
                              (static_cast<std::uint16_t>(buffer[offset + index + 3]) << 8U);
            if (next < 0xdc00U || next > 0xdfffU) {
                return std::nullopt;
            }
            codepoint = 0x10000U + (((current - 0xd800U) << 10U) | (next - 0xdc00U));
            index += 2;
        } else if (current >= 0xdc00U && current <= 0xdfffU) {
            return std::nullopt;
        }
        append_utf8_codepoint(output, codepoint);
    }
    return output;
}

Bytes encode_netlogon_authenticator(const Bytes& credential, std::uint32_t timestamp) {
    Bytes output;
    output.insert(output.end(), credential.begin(), credential.end());
    write_u32_le(output, timestamp);
    return output;
}

std::vector<std::uint32_t> sid_sub_authorities(const std::string& sid) {
    constexpr std::string_view prefix = "S-1-5-";
    if (!sid.starts_with(prefix)) {
        return {21, 1000, 1001, 1002};
    }
    std::vector<std::uint32_t> output;
    std::size_t start = prefix.size();
    while (start < sid.size()) {
        const auto next = sid.find('-', start);
        const auto part = sid.substr(start, next == std::string::npos ? std::string::npos : next - start);
        try {
            output.push_back(static_cast<std::uint32_t>(std::stoul(part)));
        } catch (...) {
            return {21, 1000, 1001, 1002};
        }
        if (next == std::string::npos) {
            break;
        }
        start = next + 1;
    }
    if (output.empty() || output.size() > 15) {
        return {21, 1000, 1001, 1002};
    }
    return output;
}

Bytes sid_bytes(const std::string& sid) {
    const auto sub_authorities = sid_sub_authorities(sid);
    Bytes output;
    output.reserve(8 + sub_authorities.size() * 4U);
    output.push_back(1);
    output.push_back(static_cast<std::uint8_t>(sub_authorities.size()));
    output.insert(output.end(), {0, 0, 0, 0, 0, 5});
    for (const auto value : sub_authorities) {
        write_u32_le(output, value);
    }
    return output;
}

Bytes sid_pointer_stub(const std::string& sid, std::uint32_t referent_id = 0x00020000U) {
    Bytes output;
    write_u32_le(output, referent_id);
    const auto encoded = sid_bytes(sid);
    output.insert(output.end(), encoded.begin(), encoded.end());
    return output;
}

Bytes security_descriptor_ace(const std::string& sid, std::uint32_t access_mask) {
    const auto encoded_sid = sid_bytes(sid);
    Bytes output;
    output.push_back(0);
    output.push_back(0);
    write_u16_le(output, static_cast<std::uint16_t>(8U + encoded_sid.size()));
    write_u32_le(output, access_mask);
    output.insert(output.end(), encoded_sid.begin(), encoded_sid.end());
    return output;
}

Bytes security_descriptor_dacl(const std::vector<std::string>& allowed_sids) {
    Bytes aces;
    std::uint16_t ace_count = 0;
    for (const auto& sid : allowed_sids) {
        const auto ace = security_descriptor_ace(sid, 0x000f01ffU);
        aces.insert(aces.end(), ace.begin(), ace.end());
        ++ace_count;
    }

    Bytes output;
    output.push_back(2);
    output.push_back(0);
    write_u16_le(output, static_cast<std::uint16_t>(8U + aces.size()));
    write_u16_le(output, ace_count);
    write_u16_le(output, 0);
    output.insert(output.end(), aces.begin(), aces.end());
    return output;
}

Bytes rpc_security_descriptor(const RpcRuntimeInfo& runtime) {
    const auto domain_sid = runtime_domain_sid(runtime);
    const auto owner = sid_bytes("S-1-5-32-544");
    const auto group = sid_bytes(domain_sid + "-512");
    const auto dacl = security_descriptor_dacl({"S-1-5-18", "S-1-5-32-544", domain_sid + "-512"});

    constexpr std::uint32_t header_size = 20;
    const auto owner_offset = header_size;
    const auto group_offset = owner_offset + owner.size();
    const auto dacl_offset = group_offset + group.size();

    Bytes output;
    output.push_back(1);
    output.push_back(0);
    write_u16_le(output, 0x8004U);
    write_u32_le(output, static_cast<std::uint32_t>(owner_offset));
    write_u32_le(output, static_cast<std::uint32_t>(group_offset));
    write_u32_le(output, 0);
    write_u32_le(output, static_cast<std::uint32_t>(dacl_offset));
    append_bytes(output, owner);
    append_bytes(output, group);
    append_bytes(output, dacl);
    return output;
}

Bytes rpc_security_descriptor_payload(const RpcRuntimeInfo& runtime, std::uint32_t referent_base) {
    const auto descriptor = rpc_security_descriptor(runtime);
    Bytes output;
    write_u32_le(output, referent_base);
    write_u32_le(output, static_cast<std::uint32_t>(descriptor.size()));
    write_u32_le(output, referent_base + 4U);
    write_u32_le(output, static_cast<std::uint32_t>(descriptor.size()));
    write_u32_le(output, 0);
    write_u32_le(output, static_cast<std::uint32_t>(descriptor.size()));
    append_bytes(output, descriptor);
    while (output.size() % 4 != 0) {
        output.push_back(0);
    }
    write_u32_le(output, nt_status_success);
    return output;
}

Bytes unicode_string_stub(const std::string& value, std::uint32_t referent_id = 0x00020004U) {
    const auto bytes = utf16le_from_utf8(value);
    Bytes output;
    write_u16_le(output, static_cast<std::uint16_t>(bytes.size()));
    write_u16_le(output, static_cast<std::uint16_t>(bytes.size() + 2));
    write_u32_le(output, referent_id);
    write_u32_le(output, static_cast<std::uint32_t>((bytes.size() / 2U) + 1U));
    write_u32_le(output, 0);
    write_u32_le(output, static_cast<std::uint32_t>((bytes.size() / 2U) + 1U));
    output.insert(output.end(), bytes.begin(), bytes.end());
    output.push_back(0);
    output.push_back(0);
    while (output.size() % 4 != 0) {
        output.push_back(0);
    }
    return output;
}

std::size_t align_4(std::size_t value) {
    return (value + 3U) & ~std::size_t{3U};
}

Bytes ndr_wide_string_value_stub(const std::string& value) {
    const auto bytes = utf16le_from_utf8(value);
    Bytes output;
    const auto characters = static_cast<std::uint32_t>((bytes.size() / 2U) + 1U);
    write_u32_le(output, characters);
    write_u32_le(output, 0);
    write_u32_le(output, characters);
    output.insert(output.end(), bytes.begin(), bytes.end());
    output.push_back(0);
    output.push_back(0);
    while (output.size() % 4 != 0) {
        output.push_back(0);
    }
    return output;
}

Bytes ndr_wide_string_pointer_stub(const std::string& value, std::uint32_t referent_id = 0x00020004U) {
    Bytes output;
    write_u32_le(output, referent_id);
    append_bytes(output, ndr_wide_string_value_stub(value));
    return output;
}

std::optional<std::size_t> ndr_utf16_string_end_offset(const Bytes& stub, std::size_t offset) {
    if (offset + 12 > stub.size()) {
        return std::nullopt;
    }
    const auto max_count = read_u32_le(stub, offset);
    const auto first_index = read_u32_le(stub, offset + 4);
    const auto actual_count = read_u32_le(stub, offset + 8);
    if (max_count == 0 || max_count > 512 || actual_count == 0 || actual_count > max_count ||
        first_index > max_count) {
        return std::nullopt;
    }
    const auto byte_count = static_cast<std::size_t>(actual_count) * 2U;
    const auto end = offset + 12U + byte_count;
    if (end > stub.size()) {
        return std::nullopt;
    }
    return align_4(end);
}

Bytes ndr_transfer_syntax() {
    return {
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00,
    };
}

Bytes rpc_header(std::uint8_t ptype, std::uint32_t call_id, std::size_t body_size) {
    Bytes output;
    output.reserve(16 + body_size);
    output.push_back(5);
    output.push_back(0);
    output.push_back(ptype);
    output.push_back(0x03);
    output.insert(output.end(), {0x10, 0x00, 0x00, 0x00});
    write_u16_le(output, static_cast<std::uint16_t>(16 + body_size));
    write_u16_le(output, 0);
    write_u32_le(output, call_id);
    return output;
}

Bytes bind_ack(const RpcRequestInfo& request, std::uint16_t endpoint_port) {
    Bytes body;
    write_u16_le(body, 4280);
    write_u16_le(body, 4280);
    write_u32_le(body, 1);

    const auto endpoint = std::to_string(endpoint_port);
    write_u16_le(body, static_cast<std::uint16_t>(endpoint.size() + 1));
    body.insert(body.end(), endpoint.begin(), endpoint.end());
    body.push_back(0);
    while (body.size() % 4 != 0) {
        body.push_back(0);
    }

    const auto context_count = static_cast<std::uint8_t>(std::max<std::size_t>(request.bind_context_ids.size(), 1));
    body.push_back(context_count);
    body.push_back(0);
    write_u16_le(body, 0);
    for (std::uint8_t index = 0; index < context_count; ++index) {
        const auto context_id = index < request.bind_context_ids.size() ? request.bind_context_ids[index] : 0;
        write_u16_le(body, context_id);
        write_u16_le(body, 0);
        const auto transfer = ndr_transfer_syntax();
        body.insert(body.end(), transfer.begin(), transfer.end());
    }

    auto output = rpc_header(ptype_bind_ack, request.call_id, body.size());
    output.insert(output.end(), body.begin(), body.end());
    return output;
}

Bytes response_with_stub(const RpcRequestInfo& request, const Bytes& stub) {
    Bytes body;
    write_u32_le(body, static_cast<std::uint32_t>(stub.size()));
    write_u16_le(body, request.context_id);
    body.push_back(0);
    body.push_back(0);
    body.insert(body.end(), stub.begin(), stub.end());

    auto output = rpc_header(ptype_response, request.call_id, body.size());
    output.insert(output.end(), body.begin(), body.end());
    return output;
}

Bytes dword_stub(std::uint32_t value) {
    Bytes output;
    write_u32_le(output, value);
    return output;
}

Bytes context_handle_bytes(std::uint32_t rid = 0, std::uint32_t marker = 0) {
    Bytes output(20, 0);
    output[0] = 1;
    output[4] = 0x45;
    output[5] = 0x4e;
    output[6] = 0x58;
    output[7] = 0x53;
    put_u32_le(output, 8, rid);
    put_u32_le(output, 12, marker);
    return output;
}

Bytes context_handle_stub(std::uint32_t status, std::uint32_t rid = 0, std::uint32_t marker = 0) {
    auto output = context_handle_bytes(rid, marker);
    write_u32_le(output, status);
    return output;
}

Bytes random_challenge() {
    Bytes challenge(8);
    if (RAND_bytes(challenge.data(), static_cast<int>(challenge.size())) == 1) {
        return challenge;
    }
    const auto fallback = static_cast<std::uint64_t>(
        std::chrono::steady_clock::now().time_since_epoch().count());
    for (std::size_t index = 0; index < challenge.size(); ++index) {
        challenge[index] = static_cast<std::uint8_t>((fallback >> (index * 8U)) & 0xffU);
    }
    return challenge;
}

Bytes last_eight_or_zero(const Bytes& input) {
    Bytes output(8, 0);
    if (input.size() >= output.size()) {
        std::copy(input.end() - static_cast<std::ptrdiff_t>(output.size()), input.end(), output.begin());
    }
    return output;
}

std::string decode_utf16le_ascii(const Bytes& input, std::size_t offset, std::uint32_t count) {
    std::string value;
    value.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        const auto current = offset + static_cast<std::size_t>(index) * 2U;
        if (current + 2 > input.size()) {
            return "";
        }
        const auto low = input[current];
        const auto high = input[current + 1];
        if (low == 0 && high == 0) {
            break;
        }
        if (high != 0 || (low < 0x20 && low != '\t') || low > 0x7e) {
            return "";
        }
        value.push_back(static_cast<char>(low));
    }
    return value;
}

std::vector<std::string> extract_ndr_utf16_strings(const Bytes& stub) {
    std::vector<std::string> strings;
    for (std::size_t offset = 0; offset + 12 <= stub.size(); offset += 4) {
        const auto max_count = read_u32_le(stub, offset);
        const auto first_index = read_u32_le(stub, offset + 4);
        const auto actual_count = read_u32_le(stub, offset + 8);
        if (max_count == 0 || max_count > 512 || actual_count == 0 || actual_count > 512 ||
            actual_count > max_count || first_index > max_count) {
            continue;
        }
        const auto chars_offset = offset + 12;
        const auto byte_count = static_cast<std::size_t>(actual_count) * 2U;
        if (chars_offset + byte_count > stub.size()) {
            continue;
        }
        auto value = decode_utf16le_ascii(stub, chars_offset, actual_count);
        if (value.empty()) {
            continue;
        }
        const auto normalized = normalize_netlogon_name(value);
        if (normalized.empty()) {
            continue;
        }
        if (std::find(strings.begin(), strings.end(), value) == strings.end()) {
            strings.push_back(std::move(value));
        }
    }
    return strings;
}

void prune_netlogon_challenges_locked(std::chrono::steady_clock::time_point now) {
    for (auto iterator = netlogon_challenges.begin(); iterator != netlogon_challenges.end();) {
        if (now - iterator->second.updated_at > std::chrono::minutes(5)) {
            iterator = netlogon_challenges.erase(iterator);
        } else {
            ++iterator;
        }
    }
}

void prune_netlogon_sessions_locked(std::chrono::steady_clock::time_point now) {
    for (auto iterator = netlogon_sessions.begin(); iterator != netlogon_sessions.end();) {
        if (now - iterator->second.updated_at > std::chrono::hours(8)) {
            iterator = netlogon_sessions.erase(iterator);
        } else {
            ++iterator;
        }
    }
}

void store_netlogon_challenge(
    const std::string& computer_name,
    const Bytes& client_challenge,
    const Bytes& server_challenge) {
    const auto key = normalize_netlogon_name(computer_name);
    std::lock_guard lock(netlogon_challenge_mutex);
    const auto now = std::chrono::steady_clock::now();
    prune_netlogon_challenges_locked(now);
    netlogon_challenges[key] = {key, client_challenge, server_challenge, now};
}

std::string netlogon_session_key(const std::string& account_name, const std::string& computer_name) {
    const auto computer = normalize_netlogon_name(computer_name);
    if (!computer.empty()) {
        return computer;
    }
    return normalize_netlogon_name(account_name);
}

void store_netlogon_session(
    const std::string& account_name,
    const std::string& computer_name,
    const Bytes& session_key,
    const Bytes& stored_credential,
    std::uint32_t negotiated_flags,
    std::uint32_t requested_flags,
    std::uint32_t rid) {
    if (session_key.size() != 16 || stored_credential.size() != 8) {
        return;
    }
    const auto key = netlogon_session_key(account_name, computer_name);
    if (key.empty()) {
        return;
    }

    std::lock_guard lock(netlogon_session_mutex);
    const auto now = std::chrono::steady_clock::now();
    prune_netlogon_sessions_locked(now);
    netlogon_sessions[key] = {
        normalize_netlogon_name(account_name),
        normalize_netlogon_name(computer_name),
        session_key,
        stored_credential,
        negotiated_flags,
        requested_flags,
        rid,
        now,
    };
}

std::vector<NetlogonChallengeEntry> matching_netlogon_challenges(const std::string& computer_name) {
    std::lock_guard lock(netlogon_challenge_mutex);
    const auto now = std::chrono::steady_clock::now();
    prune_netlogon_challenges_locked(now);

    std::vector<NetlogonChallengeEntry> entries;
    const auto key = normalize_netlogon_name(computer_name);
    if (const auto found = netlogon_challenges.find(key); found != netlogon_challenges.end()) {
        entries.push_back(found->second);
        return entries;
    }
    entries.reserve(netlogon_challenges.size());
    for (const auto& [_, entry] : netlogon_challenges) {
        entries.push_back(entry);
    }
    return entries;
}

std::vector<std::string> matching_netlogon_session_keys(
    const std::string& account_name,
    const std::string& computer_name) {
    std::lock_guard lock(netlogon_session_mutex);
    const auto now = std::chrono::steady_clock::now();
    prune_netlogon_sessions_locked(now);

    std::vector<std::string> keys;
    const auto exact = netlogon_session_key(account_name, computer_name);
    if (!exact.empty() && netlogon_sessions.find(exact) != netlogon_sessions.end()) {
        keys.push_back(exact);
        return keys;
    }
    const auto account = normalize_netlogon_name(account_name);
    for (const auto& [key, session] : netlogon_sessions) {
        if (!account.empty() && !account_name_matches(account, session.account_name)) {
            continue;
        }
        keys.push_back(key);
    }
    if (!keys.empty()) {
        return keys;
    }
    for (const auto& [key, _] : netlogon_sessions) {
        keys.push_back(key);
    }
    return keys;
}

bool contains_bytes(const Bytes& haystack, const Bytes& needle) {
    if (needle.empty() || haystack.size() < needle.size()) {
        return false;
    }
    return std::search(haystack.begin(), haystack.end(), needle.begin(), needle.end()) != haystack.end();
}

std::uint32_t extract_requested_netlogon_flags(const Bytes& stub) {
    if (stub.size() >= 4) {
        const auto trailing = read_u32_le(stub, stub.size() - 4);
        if ((trailing & netlogon_flag_aes) != 0 || (trailing & netlogon_flag_strong_keys) != 0) {
            return trailing;
        }
    }

    std::uint32_t fallback = 0;
    for (std::size_t offset = 0; offset + 4 <= stub.size(); offset += 4) {
        const auto value = read_u32_le(stub, offset);
        if ((value & netlogon_flag_aes) != 0) {
            return value;
        }
        if ((value & netlogon_flag_strong_keys) != 0) {
            fallback = value;
        }
    }
    return fallback;
}

std::uint32_t negotiate_netlogon_flags(std::uint32_t requested) {
    if (requested == 0) {
        return netlogon_server_capabilities;
    }
    return requested & netlogon_server_capabilities;
}

Bytes netlogon_challenge_response(const RpcRequestInfo& request) {
    const auto strings = extract_ndr_utf16_strings(request.stub_data);
    const auto computer_name = strings.empty() ? std::string{} : strings.back();
    const auto client_challenge = last_eight_or_zero(request.stub_data);
    const auto server_challenge = random_challenge();
    store_netlogon_challenge(computer_name, client_challenge, server_challenge);

    Bytes output;
    output.insert(output.end(), server_challenge.begin(), server_challenge.end());
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

struct NetlogonAuthenticateResult {
    bool matched{false};
    std::uint32_t status{nt_status_access_denied};
    std::uint32_t rid{0};
    std::uint32_t negotiated_flags{netlogon_server_capabilities};
    std::uint32_t requested_flags{0};
    Bytes server_credential{Bytes(8, 0)};
};

NetlogonAuthenticateResult authenticate_netlogon_client(
    const RpcRequestInfo& request,
    const RpcRuntimeInfo& runtime) {
    NetlogonAuthenticateResult result;
    const auto requested_flags = request.opnum == 5 ? 0 : extract_requested_netlogon_flags(request.stub_data);
    result.requested_flags = requested_flags == 0 ? netlogon_server_capabilities : requested_flags;
    result.negotiated_flags = negotiate_netlogon_flags(requested_flags);
    if ((result.negotiated_flags & netlogon_flag_aes) == 0) {
        result.status = nt_status_access_denied;
        return result;
    }
    if (runtime.netlogon_accounts.empty()) {
        result.status = nt_status_no_trust_sam_account;
        return result;
    }

    const auto strings = extract_ndr_utf16_strings(request.stub_data);
    std::string account_name;
    std::string computer_name;
    for (const auto& value : strings) {
        if (account_name.empty() && normalize_netlogon_name(value).find('$') != std::string::npos) {
            account_name = value;
        }
        computer_name = value;
    }
    if (account_name.empty() && strings.size() >= 2) {
        account_name = strings[strings.size() - 2];
    }

    const auto challenges = matching_netlogon_challenges(computer_name);
    if (challenges.empty()) {
        result.status = nt_status_access_denied;
        return result;
    }

    for (const auto& challenge : challenges) {
        for (const auto& account : runtime.netlogon_accounts) {
            if (!account_name_matches(account_name, account.sam_account_name)) {
                continue;
            }
            auto material = compute_netlogon_aes_credentials(
                account.nt_hash_hex,
                challenge.client_challenge,
                challenge.server_challenge);
            if (!material.has_value()) {
                continue;
            }
            if (!contains_bytes(request.stub_data, material->client_credential)) {
                continue;
            }
            if ((account.user_account_control & 0x00000002U) != 0) {
                result.status = nt_status_account_disabled;
                return result;
            }
            if (account.account_expired) {
                result.status = nt_status_account_expired;
                return result;
            }
            result.matched = true;
            result.status = nt_status_success;
            result.rid = account.rid;
            result.server_credential = material->server_credential;
            store_netlogon_session(
                account.sam_account_name,
                computer_name,
                material->session_key,
                material->client_credential,
                result.negotiated_flags,
                result.requested_flags,
                result.rid);
            return result;
        }
    }

    result.status = nt_status_access_denied;
    return result;
}

std::optional<VerifiedNetlogonAuthenticator> verify_netlogon_authenticator(const RpcRequestInfo& request) {
    const auto strings = extract_ndr_utf16_strings(request.stub_data);
    std::string account_name;
    std::string computer_name;
    for (const auto& value : strings) {
        if (account_name.empty() && normalize_netlogon_name(value).find('$') != std::string::npos) {
            account_name = value;
        }
        computer_name = value;
    }
    if (account_name.empty() && strings.size() >= 2) {
        account_name = strings[strings.size() - 2];
    }

    const auto candidate_keys = matching_netlogon_session_keys(account_name, computer_name);
    for (const auto& key : candidate_keys) {
        std::lock_guard lock(netlogon_session_mutex);
        auto session = netlogon_sessions.find(key);
        if (session == netlogon_sessions.end()) {
            continue;
        }
        for (std::size_t offset = 0; offset + 12 <= request.stub_data.size(); ++offset) {
            const Bytes received_credential(
                request.stub_data.begin() + static_cast<std::ptrdiff_t>(offset),
                request.stub_data.begin() + static_cast<std::ptrdiff_t>(offset + 8));
            const auto timestamp = read_u32_le(request.stub_data, offset + 8);
            const auto credential_seed = advance_netlogon_credential_seed(session->second.stored_credential, timestamp);
            auto expected = compute_netlogon_aes_credential(session->second.session_key, credential_seed);
            if (!expected.has_value() || *expected != received_credential) {
                continue;
            }

            const auto return_seed = advance_netlogon_credential_seed(credential_seed, 1);
            auto return_credential = compute_netlogon_aes_credential(session->second.session_key, return_seed);
            if (!return_credential.has_value()) {
                return std::nullopt;
            }

            session->second.stored_credential = *return_credential;
            session->second.updated_at = std::chrono::steady_clock::now();
            return VerifiedNetlogonAuthenticator{
                encode_netlogon_authenticator(*return_credential, 0),
                key,
                session->second.account_name,
                session->second.computer_name,
                session->second.session_key,
                session->second.negotiated_flags,
                session->second.requested_flags,
            };
        }
    }
    return std::nullopt;
}

std::optional<std::string> decrypt_password_set2_payload(
    const RpcRequestInfo& request,
    const Bytes& session_key) {
    constexpr std::size_t password_blob_size = 516;
    if (request.stub_data.size() < password_blob_size) {
        return std::nullopt;
    }
    Bytes encrypted(
        request.stub_data.end() - static_cast<std::ptrdiff_t>(password_blob_size),
        request.stub_data.end());
    return decrypt_netlogon_trust_password(session_key, encrypted);
}

bool apply_password_set2_update(
    const RpcRequestInfo& request,
    const VerifiedNetlogonAuthenticator& auth,
    const RpcRuntimeInfo& runtime) {
    if (!runtime.netlogon_password_update_handler) {
        return true;
    }
    auto password = decrypt_password_set2_payload(request, auth.session_key);
    if (!password.has_value()) {
        return false;
    }
    return runtime.netlogon_password_update_handler({
        auth.account_name,
        auth.computer_name,
        *password,
    });
}

Bytes netlogon_empty_unicode() {
    return unicode_string_stub("");
}

Bytes netlogon_one_domain_info_payload(const RpcRuntimeInfo& runtime) {
    Bytes output;
    append_bytes(output, unicode_string_stub(runtime_domain_netbios_name(runtime)));
    append_bytes(output, unicode_string_stub(runtime_domain_dns_name(runtime)));
    append_bytes(output, unicode_string_stub(runtime_domain_dns_name(runtime)));
    output.insert(output.end(), 16, 0);
    append_bytes(output, sid_pointer_stub(runtime_domain_sid(runtime)));
    append_bytes(output, netlogon_empty_unicode());
    append_bytes(output, netlogon_empty_unicode());
    append_bytes(output, netlogon_empty_unicode());
    append_bytes(output, netlogon_empty_unicode());
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    return output;
}

Bytes netlogon_lsa_policy_payload(const RpcRuntimeInfo& runtime) {
    Bytes output;
    append_bytes(output, unicode_string_stub(runtime_domain_netbios_name(runtime)));
    append_bytes(output, unicode_string_stub(runtime_domain_dns_name(runtime)));
    append_bytes(output, sid_pointer_stub(runtime_domain_sid(runtime)));
    output.insert(output.end(), 16, 0);
    return output;
}

Bytes netlogon_domain_info_payload(const RpcRuntimeInfo& runtime) {
    Bytes output;
    append_bytes(output, netlogon_one_domain_info_payload(runtime));
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    append_bytes(output, netlogon_lsa_policy_payload(runtime));
    append_bytes(output, unicode_string_stub(runtime_dc_dns_name(runtime)));
    append_bytes(output, netlogon_empty_unicode());
    append_bytes(output, netlogon_empty_unicode());
    append_bytes(output, netlogon_empty_unicode());
    write_u32_le(output, 0);
    write_u32_le(output, 0x0000001cU);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    return output;
}

Bytes netlogon_get_domain_info_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto auth = verify_netlogon_authenticator(request);
    Bytes output;
    if (!auth.has_value()) {
        output.insert(output.end(), 12, 0);
        write_u32_le(output, nt_status_access_denied);
        return response_with_stub(request, output);
    }

    output.insert(output.end(), auth->return_authenticator.begin(), auth->return_authenticator.end());
    write_u32_le(output, 1);
    write_u32_le(output, 0x00020100U);
    append_bytes(output, netlogon_domain_info_payload(runtime));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

std::uint32_t trailing_dword_or_zero(const Bytes& stub) {
    if (stub.size() < 4) {
        return 0;
    }
    return read_u32_le(stub, stub.size() - 4);
}

Bytes netlogon_capabilities_response(const RpcRequestInfo& request) {
    const auto query_level = trailing_dword_or_zero(request.stub_data);
    Bytes output;
    if (query_level != 1 && query_level != 2) {
        output.insert(output.end(), 12, 0);
        write_u32_le(output, nt_status_invalid_level);
        return response_with_stub(request, output);
    }

    const auto auth = verify_netlogon_authenticator(request);
    if (!auth.has_value()) {
        output.insert(output.end(), 12, 0);
        write_u32_le(output, nt_status_access_denied);
        return response_with_stub(request, output);
    }

    output.insert(output.end(), auth->return_authenticator.begin(), auth->return_authenticator.end());
    write_u32_le(output, query_level);
    write_u32_le(output, query_level == 2 ? auth->requested_flags : auth->negotiated_flags);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

std::uint32_t netlogon_dc_locator_flags() {
    return 0x00000001U |  // PDC
           0x00000004U |  // GC
           0x00000008U |  // LDAP
           0x00000010U |  // DS
           0x00000020U |  // KDC
           0x00000040U |  // time server
           0x00000080U |  // closest site
           0x00000100U |  // writable
           0x00000200U |  // good time server
           0x00001000U |  // full secret domain
           0x00002000U |  // AD web service capable
           0x20000000U |  // DNS controller
           0x40000000U |  // DNS domain
           0x80000000U;   // DNS forest
}

Bytes netlogon_dc_info_payload(const RpcRuntimeInfo& runtime) {
    const std::array<std::string, 6> strings{
        "\\\\" + runtime_dc_dns_name(runtime),
        "\\\\" + runtime_dc_address(runtime),
        runtime_domain_dns_name(runtime),
        runtime_domain_dns_name(runtime),
        runtime_site_name(runtime),
        runtime_site_name(runtime),
    };

    Bytes output;
    write_u32_le(output, 0x00020300U);
    for (std::uint32_t index = 0; index < 2; ++index) {
        write_u32_le(output, 0x00020310U + index * 4U);
    }
    write_u32_le(output, 2);
    output.insert(output.end(), 16, 0);
    for (std::uint32_t index = 2; index < 4; ++index) {
        write_u32_le(output, 0x00020310U + index * 4U);
    }
    write_u32_le(output, netlogon_dc_locator_flags());
    for (std::uint32_t index = 4; index < strings.size(); ++index) {
        write_u32_le(output, 0x00020310U + index * 4U);
    }
    for (const auto& value : strings) {
        append_bytes(output, ndr_wide_string_value_stub(value));
    }
    return output;
}

Bytes netlogon_dsr_get_dc_name_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    Bytes output = netlogon_dc_info_payload(runtime);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes netlogon_dsr_get_site_name_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    Bytes output = ndr_wide_string_pointer_stub(runtime_site_name(runtime));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

std::uint32_t netlogon_address_to_site_count(const Bytes& stub) {
    for (const auto string_offset : {std::size_t{0}, std::size_t{4}}) {
        const auto end = ndr_utf16_string_end_offset(stub, string_offset);
        if (!end.has_value() || *end + 4 > stub.size()) {
            continue;
        }
        const auto count = read_u32_le(stub, *end);
        if (count > 0 && count <= 64) {
            return count;
        }
    }

    std::uint32_t fallback = 0;
    const auto scan_limit = std::min<std::size_t>(stub.size(), 160);
    for (std::size_t offset = 0; offset + 4 <= scan_limit; offset += 4) {
        const auto value = read_u32_le(stub, offset);
        if (value > 0 && value <= 64) {
            fallback = value;
        }
    }
    return fallback == 0 ? 1U : fallback;
}

Bytes netlogon_address_to_site_names_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto count = netlogon_address_to_site_count(request.stub_data);
    const auto site_name = runtime_site_name(runtime);

    Bytes output;
    write_u32_le(output, 0x00020700U);
    write_u32_le(output, count);
    write_u32_le(output, 0x00020704U);
    write_u32_le(output, count);
    for (std::uint32_t index = 0; index < count; ++index) {
        write_u32_le(output, 0x00020710U + index * 4U);
    }
    for (std::uint32_t index = 0; index < count; ++index) {
        append_bytes(output, ndr_wide_string_value_stub(site_name));
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

void append_netlogon_string_array(Bytes& output, const std::vector<std::string>& values, std::uint32_t referent_base) {
    write_u32_le(output, referent_base);
    write_u32_le(output, static_cast<std::uint32_t>(values.size()));
    write_u32_le(output, referent_base + 4U);
    write_u32_le(output, static_cast<std::uint32_t>(values.size()));
    for (std::uint32_t index = 0; index < values.size(); ++index) {
        write_u32_le(output, referent_base + 0x10U + index * 4U);
    }
    for (const auto& value : values) {
        append_bytes(output, ndr_wide_string_value_stub(value));
    }
}

Bytes netlogon_address_to_site_names_ex_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto count = netlogon_address_to_site_count(request.stub_data);
    std::vector<std::string> sites;
    std::vector<std::string> subnets;
    sites.reserve(count);
    subnets.reserve(count);
    for (std::uint32_t index = 0; index < count; ++index) {
        sites.push_back(runtime_site_name(runtime));
        subnets.push_back("");
    }

    Bytes output;
    append_netlogon_string_array(output, sites, 0x00020740U);
    append_netlogon_string_array(output, subnets, 0x00020780U);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes netlogon_site_coverage_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    Bytes output;
    append_netlogon_string_array(output, {runtime_site_name(runtime)}, 0x000207c0U);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes netlogon_dc_name_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    Bytes output = ndr_wide_string_pointer_stub("\\\\" + runtime_dc_netbios_name(runtime));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes netlogon_trusted_domains_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    constexpr std::uint32_t ds_domain_in_forest = 0x00000001U;
    constexpr std::uint32_t ds_domain_tree_root = 0x00000004U;
    constexpr std::uint32_t ds_domain_primary = 0x00000008U;
    constexpr std::uint32_t ds_domain_native_mode = 0x00000010U;
    constexpr std::uint32_t trust_type_up_level = 0x00000002U;

    Bytes output;
    write_u32_le(output, 1);
    write_u32_le(output, 0x00020400U);
    write_u32_le(output, 1);
    append_bytes(output, unicode_string_stub(runtime_domain_netbios_name(runtime)));
    append_bytes(output, unicode_string_stub(runtime_domain_dns_name(runtime)));
    write_u32_le(output, ds_domain_in_forest | ds_domain_tree_root | ds_domain_primary | ds_domain_native_mode);
    write_u32_le(output, 0);
    write_u32_le(output, trust_type_up_level);
    write_u32_le(output, 0);
    append_bytes(output, sid_pointer_stub(runtime_domain_sid(runtime)));
    output.insert(output.end(), 16, 0);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes netlogon_trusted_domain_names_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    auto domain_names = utf16le_from_utf8(runtime_domain_netbios_name(runtime));
    domain_names.insert(domain_names.end(), {0, 0, 0, 0});

    Bytes output;
    write_u32_le(output, 0x00020420U);
    write_u32_le(output, static_cast<std::uint32_t>(domain_names.size()));
    write_u32_le(output, 0x00020424U);
    write_u32_le(output, static_cast<std::uint32_t>(domain_names.size()));
    append_bytes(output, domain_names);
    while (output.size() % 4 != 0) {
        output.push_back(0);
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes netlogon_forest_trust_record_top_level_name(const RpcRuntimeInfo& runtime) {
    constexpr std::uint32_t forest_trust_top_level_name = 0;

    Bytes output;
    write_u32_le(output, 0);
    write_u32_le(output, forest_trust_top_level_name);
    output.insert(output.end(), 8, 0);
    append_bytes(output, unicode_string_stub(runtime_domain_dns_name(runtime), 0x00020520U));
    return output;
}

Bytes netlogon_forest_trust_record_domain_info(const RpcRuntimeInfo& runtime) {
    constexpr std::uint32_t forest_trust_domain_info = 2;

    Bytes output;
    write_u32_le(output, 0);
    write_u32_le(output, forest_trust_domain_info);
    output.insert(output.end(), 8, 0);
    append_bytes(output, sid_pointer_stub(runtime_domain_sid(runtime), 0x00020530U));
    append_bytes(output, unicode_string_stub(runtime_domain_dns_name(runtime), 0x00020534U));
    append_bytes(output, unicode_string_stub(runtime_domain_netbios_name(runtime), 0x00020538U));
    return output;
}

Bytes netlogon_forest_trust_information_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    constexpr std::uint32_t record_count = 2;

    Bytes output;
    write_u32_le(output, 0x00020500U);
    write_u32_le(output, record_count);
    write_u32_le(output, 0x00020504U);
    write_u32_le(output, record_count);
    write_u32_le(output, 0x00020510U);
    write_u32_le(output, 0x00020514U);
    append_bytes(output, netlogon_forest_trust_record_top_level_name(runtime));
    append_bytes(output, netlogon_forest_trust_record_domain_info(runtime));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

bool is_netlogon_control_function(std::uint32_t value) {
    return (value >= 1 && value <= 12) ||
           (value >= 0x0000fffcU && value <= 0x0000ffffU);
}

NetlogonControlCall parse_netlogon_control_call(const Bytes& stub) {
    NetlogonControlCall fallback;
    std::optional<NetlogonControlCall> invalid_candidate;
    if (stub.size() < 8) {
        return fallback;
    }

    std::size_t offset = ((stub.size() - 8U) / 4U) * 4U;
    while (true) {
        const auto function_code = read_u32_le(stub, offset);
        const auto query_level = read_u32_le(stub, offset + 4U);
        if (is_netlogon_control_function(function_code)) {
            NetlogonControlCall call{function_code, query_level};
            if (query_level >= 1 && query_level <= 4) {
                return call;
            }
            if (!invalid_candidate.has_value()) {
                invalid_candidate = call;
            }
        }
        if (offset == 0) {
            break;
        }
        offset -= 4U;
    }

    return invalid_candidate.value_or(fallback);
}

std::uint32_t netlogon_control_status(const NetlogonControlCall& call) {
    if (call.query_level < 1 || call.query_level > 4) {
        return win32_error_invalid_level;
    }
    if (call.query_level == 4 && call.function_code != 8) {
        return win32_error_invalid_parameter;
    }
    if (call.query_level == 2 &&
        call.function_code != 5 &&
        call.function_code != 6 &&
        call.function_code != 10) {
        return win32_error_invalid_parameter;
    }
    if (call.function_code == 8 && call.query_level != 4) {
        return win32_error_invalid_parameter;
    }
    if (call.function_code == 10 && call.query_level != 2) {
        return win32_error_invalid_parameter;
    }
    if (call.function_code == 12 && call.query_level != 1) {
        return win32_error_invalid_level;
    }
    if (call.function_code == 2 ||
        call.function_code == 3 ||
        call.function_code == 4 ||
        call.function_code == 9) {
        return rpc_status_not_supported;
    }
    return nt_status_success;
}

Bytes netlogon_control_info_payload(
    const NetlogonControlCall& call,
    const RpcRuntimeInfo& runtime) {
    Bytes output;
    switch (call.query_level) {
        case 1:
            write_u32_le(output, 0);
            write_u32_le(output, nt_status_success);
            break;
        case 2:
            write_u32_le(output, 0);
            write_u32_le(output, nt_status_success);
            append_bytes(output, unicode_string_stub("\\\\" + runtime_dc_dns_name(runtime)));
            write_u32_le(output, nt_status_success);
            break;
        case 3:
            write_u32_le(output, 0);
            write_u32_le(output, 0);
            output.insert(output.end(), 20, 0);
            break;
        case 4:
            append_bytes(output, unicode_string_stub(runtime_domain_dns_name(runtime)));
            append_bytes(output, unicode_string_stub("\\\\" + runtime_dc_dns_name(runtime)));
            break;
        default:
            break;
    }
    return output;
}

Bytes netlogon_control_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto call = parse_netlogon_control_call(request.stub_data);
    const auto status = netlogon_control_status(call);
    Bytes output;
    if (status != nt_status_success) {
        write_u32_le(output, 0);
        write_u32_le(output, status);
        return response_with_stub(request, output);
    }

    write_u32_le(output, 0x00020320U);
    append_bytes(output, netlogon_control_info_payload(call, runtime));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

bool is_netlogon_logon_level(std::uint32_t value) {
    return value >= 1 && value <= 8;
}

bool is_netlogon_validation_level(std::uint32_t value) {
    return value == 2 || value == 3 || value == 6;
}

std::uint32_t default_netlogon_validation_level(std::uint32_t opnum) {
    return opnum == 39 ? 6U : 3U;
}

std::string netlogon_account_name_from_strings(
    const std::vector<std::string>& strings,
    const std::string& computer_name,
    const RpcRuntimeInfo& runtime) {
    const auto domain_netbios = lower_ascii(runtime_domain_netbios_name(runtime));
    const auto domain_dns = lower_ascii(runtime_domain_dns_name(runtime));
    const auto computer = normalize_netlogon_name(computer_name);
    std::string fallback;
    for (std::size_t index = 0; index < strings.size(); ++index) {
        auto value = strings[index];
        const auto normalized = normalize_netlogon_name(value);
        if (normalized.empty() || normalized == domain_netbios || normalized == domain_dns ||
            normalized == computer || normalized.starts_with("\\\\") || normalized.ends_with('$')) {
            continue;
        }
        if (index < 2) {
            continue;
        }
        fallback = std::move(value);
    }
    if (!fallback.empty()) {
        return fallback;
    }
    if (strings.size() >= 3) {
        return strings[strings.size() - 2];
    }
    return "administrator";
}

NetlogonSamLogonRequest parse_netlogon_sam_logon_request(
    const RpcRequestInfo& request,
    const RpcRuntimeInfo& runtime) {
    const auto strings = extract_ndr_utf16_strings(request.stub_data);
    NetlogonSamLogonRequest call;
    call.raw_stub = request.stub_data;
    call.domain_name = runtime_domain_netbios_name(runtime);
    for (std::size_t index = 1; index < strings.size(); ++index) {
        const auto normalized = normalize_netlogon_name(strings[index]);
        if (normalized.empty() || normalized.ends_with('$') ||
            lower_ascii(normalized) == lower_ascii(runtime_domain_netbios_name(runtime)) ||
            lower_ascii(normalized) == lower_ascii(runtime_domain_dns_name(runtime))) {
            continue;
        }
        call.computer_name = strings[index];
        break;
    }
    if (call.computer_name.empty() && !strings.empty()) {
        call.computer_name = strings.back();
    }
    call.sam_account_name = netlogon_account_name_from_strings(strings, call.computer_name, runtime);
    call.validation_level = default_netlogon_validation_level(request.opnum);
    call.logon_level = 2;
    call.extra_flags = request.opnum == 39 || request.opnum == 45 ? trailing_dword_or_zero(request.stub_data) : 0;

    for (const auto& value : strings) {
        const auto normalized = lower_ascii(normalize_netlogon_name(value));
        if (normalized == lower_ascii(runtime_domain_netbios_name(runtime)) ||
            normalized == lower_ascii(runtime_domain_dns_name(runtime))) {
            call.domain_name = value;
            break;
        }
    }

    if (request.stub_data.size() >= 12) {
        const auto maybe_logon_level = read_u32_le(request.stub_data, request.stub_data.size() - 12);
        const auto maybe_validation_level = read_u32_le(request.stub_data, request.stub_data.size() - 8);
        if (is_netlogon_logon_level(maybe_logon_level) &&
            is_netlogon_validation_level(maybe_validation_level)) {
            call.logon_level = maybe_logon_level;
            call.validation_level = maybe_validation_level;
        }
    }
    return call;
}

bool has_established_netlogon_session(const NetlogonSamLogonRequest& call) {
    return !matching_netlogon_session_keys(call.sam_account_name, call.computer_name).empty();
}

std::optional<Bytes> ntlmv2_response_key(
    const std::string& nt_hash_hex,
    const std::string& sam_account_name,
    const std::string& domain_name) {
    auto nt_hash = hex_to_bytes(nt_hash_hex);
    if (!nt_hash.has_value() || nt_hash->size() != 16) {
        return std::nullopt;
    }
    const auto identity = utf16le_from_utf8(upper_ascii(normalize_netlogon_name(sam_account_name)) + upper_ascii(domain_name));
    return hmac_md5(*nt_hash, identity);
}

Bytes ntlmv2_blob(const Bytes& client_challenge, const Bytes& target_info) {
    Bytes blob{
        0x01, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00,
    };
    Bytes challenge = client_challenge;
    challenge.resize(8, 0);
    append_bytes(blob, challenge);
    blob.insert(blob.end(), {0x00, 0x00, 0x00, 0x00});
    append_bytes(blob, target_info);
    if (target_info.size() < 4 ||
        target_info[target_info.size() - 4] != 0x00 ||
        target_info[target_info.size() - 3] != 0x00 ||
        target_info[target_info.size() - 2] != 0x00 ||
        target_info[target_info.size() - 1] != 0x00) {
        blob.insert(blob.end(), {0x00, 0x00, 0x00, 0x00});
    }
    return blob;
}

std::optional<Bytes> ntlmv2_proof(
    const Bytes& response_key,
    const Bytes& server_challenge,
    const Bytes& blob) {
    if (response_key.size() != 16 || server_challenge.size() != 8 || blob.size() < 32) {
        return std::nullopt;
    }
    Bytes proof_input;
    proof_input.reserve(server_challenge.size() + blob.size());
    append_bytes(proof_input, server_challenge);
    append_bytes(proof_input, blob);
    return hmac_md5(response_key, proof_input);
}

std::optional<Bytes> ntlmv2_user_session_key(const Bytes& response_key, const Bytes& proof) {
    if (response_key.size() != 16 || proof.size() != 16) {
        return std::nullopt;
    }
    return hmac_md5(response_key, proof);
}

std::optional<std::size_t> ntlmv2_response_size_at(const Bytes& stub, std::size_t offset) {
    const auto blob = offset + 16;
    if (blob + 32 > stub.size() ||
        stub[blob] != 0x01 ||
        stub[blob + 1] != 0x01 ||
        stub[blob + 2] != 0x00 ||
        stub[blob + 3] != 0x00) {
        return std::nullopt;
    }

    std::size_t cursor = blob + 28;
    while (cursor + 4 <= stub.size()) {
        const auto avid = read_u16_le(stub, cursor);
        const auto avlen = read_u16_le(stub, cursor + 2);
        cursor += 4;
        if (cursor + avlen > stub.size()) {
            return std::nullopt;
        }
        cursor += avlen;
        if (avid == 0 && avlen == 0) {
            return cursor - offset;
        }
    }
    return std::nullopt;
}

std::optional<Bytes> find_netlogon_ntlmv2_session_key(
    const NetlogonSamLogonRequest& call,
    const std::string& nt_hash_hex) {
    auto response_key = ntlmv2_response_key(nt_hash_hex, call.sam_account_name, call.domain_name);
    if (!response_key.has_value()) {
        return std::nullopt;
    }

    for (std::size_t response_offset = 0; response_offset + 48 <= call.raw_stub.size(); ++response_offset) {
        const auto response_size = ntlmv2_response_size_at(call.raw_stub, response_offset);
        if (!response_size.has_value() || *response_size < 48 ||
            response_offset + *response_size > call.raw_stub.size()) {
            continue;
        }
        const Bytes proof(
            call.raw_stub.begin() + static_cast<std::ptrdiff_t>(response_offset),
            call.raw_stub.begin() + static_cast<std::ptrdiff_t>(response_offset + 16));
        const Bytes blob(
            call.raw_stub.begin() + static_cast<std::ptrdiff_t>(response_offset + 16),
            call.raw_stub.begin() + static_cast<std::ptrdiff_t>(response_offset + *response_size));

        for (std::size_t challenge_offset = 0; challenge_offset + 8 <= call.raw_stub.size(); ++challenge_offset) {
            if (challenge_offset >= response_offset &&
                challenge_offset < response_offset + *response_size) {
                continue;
            }
            const Bytes challenge(
                call.raw_stub.begin() + static_cast<std::ptrdiff_t>(challenge_offset),
                call.raw_stub.begin() + static_cast<std::ptrdiff_t>(challenge_offset + 8));
            auto expected = ntlmv2_proof(*response_key, challenge, blob);
            if (!expected.has_value() || *expected != proof) {
                continue;
            }
            return ntlmv2_user_session_key(*response_key, proof);
        }
    }
    return std::nullopt;
}

std::optional<NetlogonSamLogonResult> validate_netlogon_sam_logon_with_ntlmv2(
    const NetlogonSamLogonRequest& call,
    const RpcRuntimeInfo& runtime) {
    auto record = resolve_samr_account(runtime, {call.sam_account_name, 0, false});
    if (!record.has_value() || record->rid == 0 || record->machine_account) {
        return std::nullopt;
    }
    if ((record->user_account_control & 0x00000002U) != 0) {
        return NetlogonSamLogonResult{
            false,
            nt_status_account_disabled,
            *record,
            {},
        };
    }

    for (const auto& secret : runtime.netlogon_accounts) {
        if (!account_name_matches(call.sam_account_name, secret.sam_account_name)) {
            continue;
        }
        auto session_key = find_netlogon_ntlmv2_session_key(call, secret.nt_hash_hex);
        if (!session_key.has_value()) {
            continue;
        }
        return NetlogonSamLogonResult{
            true,
            nt_status_success,
            *record,
            *session_key,
        };
    }

    return NetlogonSamLogonResult{
        false,
        nt_status_access_denied,
        *record,
        {},
    };
}

void append_filetime_zero(Bytes& output) {
    output.insert(output.end(), 8, 0);
}

void append_netlogon_user_session_key(Bytes& output, const Bytes& session_key) {
    output.insert(output.end(), 16, 0);
    const auto copy = std::min<std::size_t>(session_key.size(), 16);
    std::copy(session_key.begin(), session_key.begin() + static_cast<std::ptrdiff_t>(copy), output.end() - 16);
}

Bytes netlogon_validation_payload(
    const NetlogonSamLogonRequest& call,
    const NetlogonSamLogonResult& result,
    const RpcRuntimeInfo& runtime) {
    auto record = result.account;
    if (record.sam_account_name.empty()) {
        record.sam_account_name = call.sam_account_name;
    }
    if (record.display_name.empty()) {
        record.display_name = record.sam_account_name;
    }
    if (record.rid == 0) {
        record.rid = synthetic_rid_for_name(record.sam_account_name);
    }
    if (record.primary_group_rid == 0) {
        record.primary_group_rid = record.machine_account ? 515 : 513;
    }
    if (record.user_account_control == 0) {
        record.user_account_control = record.machine_account
            ? user_account_control_workstation_trust | user_account_control_passwd_notreqd
            : user_account_control_normal;
    }

    std::vector<std::uint32_t> groups;
    const auto add_group = [&](std::uint32_t rid) {
        if (rid != 0 && std::find(groups.begin(), groups.end(), rid) == groups.end()) {
            groups.push_back(rid);
        }
    };
    add_group(record.primary_group_rid);
    for (const auto rid : record.group_rids) {
        add_group(rid);
    }
    if (groups.empty()) {
        add_group(record.machine_account ? 515U : 513U);
    }
    const auto account_name = unicode_string_stub(record.sam_account_name);
    const auto full_name = unicode_string_stub(record.display_name);
    const auto empty = unicode_string_stub("");
    const auto domain_netbios = runtime_domain_netbios_name(runtime);
    const auto domain_dns = runtime_domain_dns_name(runtime);
    const auto upn = record.sam_account_name + "@" + domain_dns;

    Bytes output;
    write_u32_le(output, call.validation_level);
    append_filetime_zero(output);
    append_filetime_zero(output);
    append_filetime_zero(output);
    append_filetime_zero(output);
    append_filetime_zero(output);
    append_filetime_zero(output);
    append_bytes(output, account_name);
    append_bytes(output, full_name);
    append_bytes(output, empty);
    append_bytes(output, empty);
    append_bytes(output, empty);
    append_bytes(output, empty);
    write_u16_le(output, 0);
    write_u16_le(output, 0);
    write_u32_le(output, record.rid);
    write_u32_le(output, record.primary_group_rid);
    write_u32_le(output, static_cast<std::uint32_t>(groups.size()));
    write_u32_le(output, 0x00020200U);
    write_u32_le(output, static_cast<std::uint32_t>(groups.size()));
    write_u32_le(output, static_cast<std::uint32_t>(groups.size()));
    for (const auto group_rid : groups) {
        write_u32_le(output, group_rid);
        write_u32_le(output, 0x00000007U);
    }
    write_u32_le(output, 0x00000020U);
    append_netlogon_user_session_key(output, result.user_session_key);
    append_bytes(output, unicode_string_stub(runtime_dc_dns_name(runtime)));
    append_bytes(output, unicode_string_stub(domain_netbios));
    append_bytes(output, sid_pointer_stub(runtime_domain_sid(runtime)));
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);

    if (call.validation_level >= 3) {
        write_u32_le(output, record.user_account_control);
        write_u32_le(output, 0);
        append_filetime_zero(output);
        append_filetime_zero(output);
        append_filetime_zero(output);
        append_filetime_zero(output);
        write_u32_le(output, 0);
        write_u32_le(output, 0);
        write_u32_le(output, 0);
    }
    if (call.validation_level >= 6) {
        append_bytes(output, unicode_string_stub(domain_dns));
        append_bytes(output, unicode_string_stub(upn));
        append_bytes(output, empty);
        append_bytes(output, empty);
    }
    return output;
}

Bytes netlogon_sam_logon_failure_response(
    const RpcRequestInfo& request,
    const std::optional<VerifiedNetlogonAuthenticator>& auth,
    bool include_extra_flags,
    std::uint32_t status) {
    Bytes output;
    if (auth.has_value()) {
        output.insert(output.end(), auth->return_authenticator.begin(), auth->return_authenticator.end());
    }
    write_u32_le(output, 0);
    write_u32_le(output, 1);
    if (include_extra_flags) {
        write_u32_le(output, 0);
    }
    write_u32_le(output, status);
    return response_with_stub(request, output);
}

Bytes netlogon_sam_logon_response(
    const RpcRequestInfo& request,
    const RpcRuntimeInfo& runtime,
    bool requires_authenticator,
    bool include_extra_flags) {
    const auto call = parse_netlogon_sam_logon_request(request, runtime);
    std::optional<VerifiedNetlogonAuthenticator> auth;
    if (requires_authenticator) {
        auth = verify_netlogon_authenticator(request);
        if (!auth.has_value()) {
            return netlogon_sam_logon_failure_response(
                request,
                std::nullopt,
                include_extra_flags,
                nt_status_access_denied);
        }
    } else if (!has_established_netlogon_session(call)) {
        return netlogon_sam_logon_failure_response(
            request,
            std::nullopt,
            include_extra_flags,
            nt_status_access_denied);
    }

    auto result = runtime.netlogon_logon_handler
        ? runtime.netlogon_logon_handler(call)
        : validate_netlogon_sam_logon_with_ntlmv2(call, runtime);
    if (!result.has_value()) {
        return netlogon_sam_logon_failure_response(
            request,
            auth,
            include_extra_flags,
            nt_status_no_such_user);
    }
    const auto status = result->status != 0 ? result->status : (result->authenticated ? nt_status_success : nt_status_access_denied);
    if (!result->authenticated || status != nt_status_success) {
        return netlogon_sam_logon_failure_response(request, auth, include_extra_flags, status);
    }

    Bytes output;
    if (auth.has_value()) {
        output.insert(output.end(), auth->return_authenticator.begin(), auth->return_authenticator.end());
    }
    write_u32_le(output, 0x00020300U);
    append_bytes(output, netlogon_validation_payload(call, *result, runtime));
    write_u32_le(output, 1);
    if (include_extra_flags) {
        write_u32_le(output, call.extra_flags);
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes netlogon_secure_channel_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto auth = verify_netlogon_authenticator(request);
    Bytes output;
    if (!auth.has_value()) {
        output.insert(output.end(), 12, 0);
        write_u32_le(output, nt_status_access_denied);
        return response_with_stub(request, output);
    }
    if (request.opnum == 30 && !apply_password_set2_update(request, *auth, runtime)) {
        output.insert(output.end(), auth->return_authenticator.begin(), auth->return_authenticator.end());
        write_u32_le(output, nt_status_access_denied);
        return response_with_stub(request, output);
    }
    output.insert(output.end(), auth->return_authenticator.begin(), auth->return_authenticator.end());
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes netlogon_authenticate3_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto auth = authenticate_netlogon_client(request, runtime);
    Bytes output;
    output.insert(output.end(), auth.server_credential.begin(), auth.server_credential.end());
    write_u32_le(output, auth.negotiated_flags);
    write_u32_le(output, auth.rid);
    write_u32_le(output, auth.status);
    return response_with_stub(request, output);
}

Bytes netlogon_authenticate2_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto auth = authenticate_netlogon_client(request, runtime);
    Bytes output;
    output.insert(output.end(), auth.server_credential.begin(), auth.server_credential.end());
    write_u32_le(output, auth.negotiated_flags);
    write_u32_le(output, auth.status);
    return response_with_stub(request, output);
}

Bytes netlogon_authenticate_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto auth = authenticate_netlogon_client(request, runtime);
    Bytes output;
    output.insert(output.end(), auth.server_credential.begin(), auth.server_credential.end());
    write_u32_le(output, auth.status);
    return response_with_stub(request, output);
}

Bytes netlogon_stub_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    if (request.opnum == 2) {
        return netlogon_sam_logon_response(request, runtime, true, false);
    }
    if (request.opnum == 4) {
        return netlogon_challenge_response(request);
    }
    if (request.opnum == 5) {
        return netlogon_authenticate_response(request, runtime);
    }
    if (request.opnum == 11 || request.opnum == 13) {
        return netlogon_dc_name_response(request, runtime);
    }
    if (request.opnum == 12 || request.opnum == 14 || request.opnum == 18) {
        return netlogon_control_response(request, runtime);
    }
    if (request.opnum == 19) {
        return netlogon_trusted_domain_names_response(request, runtime);
    }
    if (request.opnum == 20 || request.opnum == 27 || request.opnum == 34) {
        return netlogon_dsr_get_dc_name_response(request, runtime);
    }
    if (request.opnum == 21) {
        return netlogon_capabilities_response(request);
    }
    if (request.opnum == 15) {
        return netlogon_authenticate2_response(request, runtime);
    }
    if (request.opnum == 26) {
        return netlogon_authenticate3_response(request, runtime);
    }
    if (request.opnum == 28) {
        return netlogon_dsr_get_site_name_response(request, runtime);
    }
    if (request.opnum == 33) {
        return netlogon_address_to_site_names_response(request, runtime);
    }
    if (request.opnum == 37) {
        return netlogon_address_to_site_names_ex_response(request, runtime);
    }
    if (request.opnum == 38) {
        return netlogon_site_coverage_response(request, runtime);
    }
    if (request.opnum == 29) {
        return netlogon_get_domain_info_response(request, runtime);
    }
    if (request.opnum == 30 || request.opnum == 42) {
        return netlogon_secure_channel_response(request, runtime);
    }
    if (request.opnum == 36 || request.opnum == 40) {
        return netlogon_trusted_domains_response(request, runtime);
    }
    if (request.opnum == 43) {
        return netlogon_forest_trust_information_response(request, runtime);
    }
    if (request.opnum == 41) {
        return response_with_stub(request, dword_stub(nt_status_success));
    }
    if (request.opnum == 44) {
        return netlogon_forest_trust_information_response(request, runtime);
    }
    if (request.opnum == 39) {
        return netlogon_sam_logon_response(request, runtime, false, true);
    }
    if (request.opnum == 45) {
        return netlogon_sam_logon_response(request, runtime, true, true);
    }
    return response_with_stub(request, dword_stub(rpc_status_not_supported));
}

Bytes samr_lookup_domain_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    Bytes output = sid_pointer_stub(runtime_domain_sid(runtime));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

std::optional<SamrAccountRecord> resolve_samr_account(
    const RpcRuntimeInfo& runtime,
    const SamrAccountRequest& request) {
    if (runtime.samr_account_handler) {
        if (auto record = runtime.samr_account_handler(request)) {
            return normalized_samr_record(*record);
        }
    }
    if (auto record = well_known_samr_account(request)) {
        return normalized_samr_record(*record);
    }
    if (!request.create_if_missing && request.sam_account_name.empty() && request.rid == 0) {
        return std::nullopt;
    }
    auto sam = request.sam_account_name;
    const bool machine = sam.ends_with('$');
    auto display = sam;
    if (!display.empty() && display.back() == '$') {
        display.pop_back();
    }
    return SamrAccountRecord{
        sam,
        request.rid != 0 ? request.rid : synthetic_rid_for_name(sam),
        display,
        machine ? 515U : 513U,
        machine ? user_account_control_workstation_trust | user_account_control_passwd_notreqd : user_account_control_normal,
        machine,
        {machine ? 515U : 513U},
        machine ? sid_name_use_computer : sid_name_use_user,
    };
}

std::vector<SamrAccountRecord> default_samr_domain_records() {
    std::vector<SamrAccountRecord> records;
    const auto add = [&](const std::string& name, std::uint32_t rid) {
        if (auto record = well_known_samr_account({name, rid, false})) {
            records.push_back(normalized_samr_record(*record));
        }
    };
    add("Administrator", 500);
    add("Guest", 501);
    add("krbtgt", 502);
    add("Domain Admins", 512);
    add("Domain Users", 513);
    add("Domain Guests", 514);
    add("Domain Computers", 515);
    add("Domain Controllers", 516);
    add("Cert Publishers", 517);
    add("Schema Admins", 518);
    add("Enterprise Admins", 519);
    add("Group Policy Creator Owners", 520);
    add("Read-only Domain Controllers", 521);
    return records;
}

std::vector<SamrAccountRecord> samr_domain_records(const RpcRuntimeInfo& runtime) {
    auto records = default_samr_domain_records();
    if (runtime.samr_account_enumerator) {
        for (auto record : runtime.samr_account_enumerator()) {
            record = normalized_samr_record(std::move(record));
            if (record.rid == 0 || record.sam_account_name.empty()) {
                continue;
            }
            records.push_back(std::move(record));
        }
    }

    std::vector<SamrAccountRecord> deduped;
    for (auto& record : records) {
        const auto normalized_name = lower_ascii(record.sam_account_name);
        const auto exists = std::find_if(deduped.begin(), deduped.end(), [&](const auto& candidate) {
            return candidate.rid == record.rid ||
                   lower_ascii(candidate.sam_account_name) == normalized_name;
        });
        if (exists == deduped.end()) {
            deduped.push_back(std::move(record));
        }
    }
    std::sort(deduped.begin(), deduped.end(), [](const auto& left, const auto& right) {
        if (left.rid != right.rid) {
            return left.rid < right.rid;
        }
        return lower_ascii(left.sam_account_name) < lower_ascii(right.sam_account_name);
    });
    return deduped;
}

bool samr_record_is_user_or_machine(const SamrAccountRecord& record) {
    return record.sid_name_use == sid_name_use_user ||
           record.sid_name_use == sid_name_use_computer ||
           record.machine_account;
}

bool samr_record_is_group(const SamrAccountRecord& record) {
    return record.sid_name_use == sid_name_use_group;
}

std::vector<SamrAccountRecord> samr_domain_users(const RpcRuntimeInfo& runtime) {
    std::vector<SamrAccountRecord> users;
    for (const auto& record : samr_domain_records(runtime)) {
        if (samr_record_is_user_or_machine(record)) {
            users.push_back(record);
        }
    }
    return users;
}

std::vector<SamrAccountRecord> samr_domain_groups(const RpcRuntimeInfo& runtime) {
    std::vector<SamrAccountRecord> groups;
    for (const auto& record : samr_domain_records(runtime)) {
        if (samr_record_is_group(record)) {
            groups.push_back(record);
        }
    }
    return groups;
}

std::uint32_t samr_domain_information_class(const Bytes& stub) {
    if (stub.size() >= 24) {
        return read_u32_le(stub, 20);
    }
    if (stub.size() >= 4) {
        return read_u32_le(stub, stub.size() - 4);
    }
    return 2;
}

Bytes samr_query_domain_info_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto info_class = samr_domain_information_class(request.stub_data);
    const auto users = samr_domain_users(runtime);
    const auto groups = samr_domain_groups(runtime);
    const auto aliases = well_known_samr_aliases();

    Bytes output;
    write_u32_le(output, 0x00020018U);
    write_u32_le(output, info_class);
    append_bytes(output, unicode_string_stub(runtime_domain_netbios_name(runtime)));
    append_bytes(output, unicode_string_stub(runtime_domain_dns_name(runtime)));
    append_bytes(output, sid_pointer_stub(runtime_domain_sid(runtime)));
    write_u32_le(output, static_cast<std::uint32_t>(users.size()));
    write_u32_le(output, static_cast<std::uint32_t>(groups.size()));
    write_u32_le(output, static_cast<std::uint32_t>(aliases.size()));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_enumerate_domains_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    Bytes output;
    write_u32_le(output, 0);
    write_u32_le(output, 0x00020014U);
    write_u32_le(output, 1);
    write_u32_le(output, 0x00020018U);
    write_u32_le(output, 1);
    write_u32_le(output, 0);
    append_bytes(output, unicode_string_stub(runtime_domain_netbios_name(runtime)));
    write_u32_le(output, 1);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

std::uint32_t trailing_rid_or_zero(const Bytes& stub) {
    if (stub.size() < 4) {
        return 0;
    }
    return read_u32_le(stub, stub.size() - 4);
}

std::uint32_t samr_user_handle_rid(const Bytes& stub) {
    if (stub.size() < 16 || read_u32_le(stub, 12) != samr_user_handle_marker) {
        return 0;
    }
    return read_u32_le(stub, 8);
}

std::uint32_t samr_group_handle_rid(const Bytes& stub) {
    if (stub.size() < 16 || read_u32_le(stub, 12) != samr_group_handle_marker) {
        return 0;
    }
    return read_u32_le(stub, 8);
}

std::uint32_t samr_alias_handle_rid(const Bytes& stub) {
    if (stub.size() < 16 || read_u32_le(stub, 12) != samr_alias_handle_marker) {
        return 0;
    }
    return read_u32_le(stub, 8);
}

std::uint32_t lsa_account_handle_rid(const Bytes& stub) {
    if (stub.size() < 16 || read_u32_le(stub, 12) != lsa_account_handle_marker) {
        return 0;
    }
    return read_u32_le(stub, 8);
}

std::uint32_t samr_user_information_class(const Bytes& stub) {
    if (stub.size() >= 24) {
        return read_u32_le(stub, 20);
    }
    if (stub.size() >= 4) {
        return read_u32_le(stub, stub.size() - 4);
    }
    return 0;
}

std::vector<std::uint32_t> unique_samr_group_rids(const SamrAccountRecord& record) {
    std::vector<std::uint32_t> groups;
    const auto add = [&](std::uint32_t rid) {
        if (rid == 0 || std::find(groups.begin(), groups.end(), rid) != groups.end()) {
            return;
        }
        groups.push_back(rid);
    };
    add(record.primary_group_rid);
    for (const auto rid : record.group_rids) {
        add(rid);
    }
    if (groups.empty()) {
        add(record.machine_account ? 515U : 513U);
    }
    return groups;
}

std::vector<std::uint32_t> samr_member_rids_for_group(
    const RpcRuntimeInfo& runtime,
    std::uint32_t group_rid) {
    std::vector<std::uint32_t> member_rids;
    for (const auto& record : samr_domain_records(runtime)) {
        if (!samr_record_is_user_or_machine(record) || record.rid == 0) {
            continue;
        }
        const auto groups = unique_samr_group_rids(record);
        if (std::find(groups.begin(), groups.end(), group_rid) != groups.end() &&
            std::find(member_rids.begin(), member_rids.end(), record.rid) == member_rids.end()) {
            member_rids.push_back(record.rid);
        }
    }
    return member_rids;
}

std::vector<std::uint32_t> samr_member_rids_for_alias(
    const RpcRuntimeInfo& runtime,
    std::uint32_t alias_rid) {
    std::vector<std::uint32_t> member_rids;
    const auto add = [&](std::uint32_t rid) {
        if (rid == 0 || std::find(member_rids.begin(), member_rids.end(), rid) != member_rids.end()) {
            return;
        }
        member_rids.push_back(rid);
    };

    if (const auto alias = well_known_samr_alias(alias_rid)) {
        for (const auto rid : alias->member_rids) {
            add(rid);
        }
    }

    for (const auto& record : samr_domain_records(runtime)) {
        if (!samr_record_is_user_or_machine(record) || record.rid == 0) {
            continue;
        }
        const auto groups = unique_samr_group_rids(record);
        if (std::find(groups.begin(), groups.end(), alias_rid) != groups.end()) {
            add(record.rid);
        }
    }
    return member_rids;
}

std::vector<std::uint32_t> ndr_u32_values_after(const Bytes& stub, std::size_t offset) {
    std::vector<std::uint32_t> values;
    for (auto current = offset; current + 4 <= stub.size(); current += 4) {
        values.push_back(read_u32_le(stub, current));
    }
    return values;
}

std::optional<std::uint32_t> last_u32_after(const Bytes& stub, std::size_t offset) {
    const auto values = ndr_u32_values_after(stub, offset);
    if (values.empty()) {
        return std::nullopt;
    }
    return values.back();
}

Bytes rc4_crypt(const Bytes& key, const Bytes& input) {
    if (key.empty()) {
        return {};
    }
    std::array<std::uint8_t, 256> state{};
    for (std::size_t index = 0; index < state.size(); ++index) {
        state[index] = static_cast<std::uint8_t>(index);
    }

    std::uint8_t j = 0;
    for (std::size_t index = 0; index < state.size(); ++index) {
        j = static_cast<std::uint8_t>(j + state[index] + key[index % key.size()]);
        std::swap(state[index], state[j]);
    }

    Bytes output;
    output.reserve(input.size());
    std::uint8_t i = 0;
    j = 0;
    for (const auto byte : input) {
        i = static_cast<std::uint8_t>(i + 1);
        j = static_cast<std::uint8_t>(j + state[i]);
        std::swap(state[i], state[j]);
        const auto k = state[static_cast<std::uint8_t>(state[i] + state[j])];
        output.push_back(static_cast<std::uint8_t>(byte ^ k));
    }
    return output;
}

std::optional<std::string> decode_samr_user_password_plaintext(const Bytes& plaintext) {
    if (plaintext.size() != 516) {
        return std::nullopt;
    }
    const auto length = read_u32_le(plaintext, 512);
    if (length == 0 || length > 512 || length % 2 != 0) {
        return std::nullopt;
    }
    auto password = decode_utf16le_password(plaintext, 512 - length, length);
    if (!password.has_value() || password->empty()) {
        return std::nullopt;
    }
    return password;
}

std::optional<std::string> extract_samr_user_password(
    const Bytes& stub,
    const Bytes& rc4_session_key) {
    constexpr std::size_t password_blob_size = 516;
    if (stub.size() < password_blob_size) {
        return std::nullopt;
    }

    for (std::size_t offset = 24; offset + password_blob_size <= stub.size(); ++offset) {
        Bytes candidate(
            stub.begin() + static_cast<std::ptrdiff_t>(offset),
            stub.begin() + static_cast<std::ptrdiff_t>(offset + password_blob_size));
        if (auto password = decode_samr_user_password_plaintext(candidate)) {
            return password;
        }
        if (rc4_session_key.size() == 16) {
            auto plaintext = rc4_crypt(rc4_session_key, candidate);
            if (auto password = decode_samr_user_password_plaintext(plaintext)) {
                return password;
            }
        }
    }
    return std::nullopt;
}

Bytes samr_account_name_info(const SamrAccountRecord& record) {
    return unicode_string_stub(record.sam_account_name);
}

Bytes samr_full_name_info(const SamrAccountRecord& record) {
    return unicode_string_stub(record.display_name.empty() ? record.sam_account_name : record.display_name);
}

Bytes samr_general_info(const SamrAccountRecord& record) {
    Bytes output;
    const auto account_name = samr_account_name_info(record);
    const auto full_name = samr_full_name_info(record);
    const auto empty = unicode_string_stub("");
    output.insert(output.end(), account_name.begin(), account_name.end());
    output.insert(output.end(), full_name.begin(), full_name.end());
    write_u32_le(output, record.rid);
    write_u32_le(output, record.primary_group_rid);
    output.insert(output.end(), empty.begin(), empty.end());
    output.insert(output.end(), empty.begin(), empty.end());
    return output;
}

Bytes samr_account_info(const SamrAccountRecord& record) {
    Bytes output;
    const auto account_name = samr_account_name_info(record);
    const auto full_name = samr_full_name_info(record);
    const auto empty = unicode_string_stub("");
    output.insert(output.end(), account_name.begin(), account_name.end());
    output.insert(output.end(), full_name.begin(), full_name.end());
    output.insert(output.end(), empty.begin(), empty.end());
    output.insert(output.end(), empty.begin(), empty.end());
    write_u32_le(output, record.rid);
    write_u32_le(output, record.primary_group_rid);
    write_u32_le(output, record.user_account_control);
    return output;
}

Bytes samr_all_info(const SamrAccountRecord& record) {
    Bytes output;
    const auto account_name = samr_account_name_info(record);
    const auto full_name = samr_full_name_info(record);
    const auto empty = unicode_string_stub("");
    output.insert(output.end(), account_name.begin(), account_name.end());
    output.insert(output.end(), full_name.begin(), full_name.end());
    output.insert(output.end(), empty.begin(), empty.end());
    write_u32_le(output, record.rid);
    write_u32_le(output, record.primary_group_rid);
    write_u32_le(output, record.user_account_control);
    write_u32_le(output, 0x00000007U);
    return output;
}

Bytes samr_query_info_payload(std::uint32_t info_class, const SamrAccountRecord& record) {
    Bytes output;
    write_u32_le(output, 0x00020020U);
    write_u32_le(output, info_class);
    switch (info_class) {
        case 1:
            append_bytes(output, samr_general_info(record));
            break;
        case 5:
            append_bytes(output, samr_account_info(record));
            break;
        case 7:
            append_bytes(output, samr_account_name_info(record));
            break;
        case 8:
            append_bytes(output, samr_full_name_info(record));
            break;
        case 9:
            write_u32_le(output, record.primary_group_rid);
            break;
        case 16:
            write_u32_le(output, record.user_account_control);
            break;
        case 21:
            append_bytes(output, samr_all_info(record));
            break;
        default:
            append_bytes(output, samr_account_info(record));
            break;
    }
    write_u32_le(output, nt_status_success);
    return output;
}

Bytes samr_open_user_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto rid = trailing_rid_or_zero(request.stub_data);
    const auto record = resolve_samr_account(runtime, {"", rid, false});
    if (!record.has_value() || record->rid == 0) {
        return response_with_stub(request, dword_stub(nt_status_no_trust_sam_account));
    }
    return response_with_stub(request, context_handle_stub(nt_status_success, record->rid, samr_user_handle_marker));
}

Bytes samr_create_or_open_user_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto strings = extract_ndr_utf16_strings(request.stub_data);
    const auto account_name = strings.empty() ? std::string{"machine$"} : strings.back();
    const auto record = resolve_samr_account(runtime, {account_name, 0, true});
    if (!record.has_value() || record->rid == 0) {
        return response_with_stub(request, dword_stub(nt_status_access_denied));
    }
    Bytes output = context_handle_bytes(record->rid, samr_user_handle_marker);
    write_u32_le(output, 0x001f01ffU);
    write_u32_le(output, record->rid);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_create_user_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto strings = extract_ndr_utf16_strings(request.stub_data);
    const auto account_name = strings.empty() ? std::string{"machine$"} : strings.back();
    const auto record = resolve_samr_account(runtime, {account_name, 0, true});
    if (!record.has_value() || record->rid == 0) {
        return response_with_stub(request, dword_stub(nt_status_access_denied));
    }
    Bytes output = context_handle_bytes(record->rid, samr_user_handle_marker);
    write_u32_le(output, record->rid);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_lookup_names_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto strings = extract_ndr_utf16_strings(request.stub_data);
    const auto account_name = strings.empty() ? std::string{"administrator"} : strings.back();
    const auto record = resolve_samr_account(runtime, {account_name, 0, false});
    const auto rid = record.has_value() && record->rid != 0 ? record->rid : synthetic_rid_for_name(account_name);
    const auto sid_name_use = record.has_value() ? record->sid_name_use : sid_name_use_user;
    Bytes output;
    write_u32_le(output, 0x00020008U);
    write_u32_le(output, 1);
    write_u32_le(output, 1);
    write_u32_le(output, rid);
    write_u32_le(output, 0x0002000cU);
    write_u32_le(output, 1);
    write_u32_le(output, 1);
    write_u32_le(output, sid_name_use);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

std::vector<std::uint32_t> samr_relative_ids_from_stub(const Bytes& stub) {
    std::vector<std::uint32_t> rids;
    for (std::size_t offset = 20; offset + 4 <= stub.size(); offset += 4) {
        const auto value = read_u32_le(stub, offset);
        if (value < 500 || std::find(rids.begin(), rids.end(), value) != rids.end()) {
            continue;
        }
        rids.push_back(value);
    }
    if (rids.empty()) {
        const auto rid = trailing_rid_or_zero(stub);
        if (rid >= 500) {
            rids.push_back(rid);
        }
    }
    return rids;
}

Bytes samr_lookup_ids_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    auto rids = samr_relative_ids_from_stub(request.stub_data);
    if (rids.empty()) {
        rids.push_back(500);
    }

    Bytes output;
    write_u32_le(output, 0x00020040U);
    write_u32_le(output, static_cast<std::uint32_t>(rids.size()));
    write_u32_le(output, 0x00020044U);
    write_u32_le(output, static_cast<std::uint32_t>(rids.size()));
    for (const auto rid : rids) {
        const auto record = resolve_samr_account(runtime, {"", rid, false});
        const auto name = record.has_value() && !record->sam_account_name.empty()
            ? record->sam_account_name
            : std::string{"RID-"} + std::to_string(rid);
        append_bytes(output, unicode_string_stub(name));
    }
    write_u32_le(output, 0x00020048U);
    write_u32_le(output, static_cast<std::uint32_t>(rids.size()));
    write_u32_le(output, static_cast<std::uint32_t>(rids.size()));
    for (const auto rid : rids) {
        const auto record = resolve_samr_account(runtime, {"", rid, false});
        write_u32_le(output, record.has_value() ? record->sid_name_use : sid_name_use_user);
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_query_user_info_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto rid = samr_user_handle_rid(request.stub_data);
    const auto info_class = samr_user_information_class(request.stub_data);
    auto record = resolve_samr_account(runtime, {"", rid, false});
    if (!record.has_value() || record->rid == 0) {
        return response_with_stub(request, dword_stub(nt_status_no_trust_sam_account));
    }
    return response_with_stub(request, samr_query_info_payload(info_class, *record));
}

Bytes samr_set_user_info_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    SamrAccountUpdate update;
    update.rid = samr_user_handle_rid(request.stub_data);
    const auto info_class = samr_user_information_class(request.stub_data);
    const auto strings = extract_ndr_utf16_strings(request.stub_data);
    if (!strings.empty()) {
        update.display_name = strings.back();
    }

    if (info_class == 9) {
        update.primary_group_rid = last_u32_after(request.stub_data, 24);
    } else if (info_class == 16) {
        update.user_account_control = last_u32_after(request.stub_data, 24);
    } else if (info_class == 5 || info_class == 21) {
        for (const auto value : ndr_u32_values_after(request.stub_data, 24)) {
            if (value == 513 || value == 514 || value == 515) {
                update.primary_group_rid = value;
            }
            if ((value & user_account_control_normal) != 0 ||
                (value & user_account_control_workstation_trust) != 0) {
                update.user_account_control = value;
            }
        }
    }
    if (info_class == 23 || info_class == 24 || info_class == 25 || info_class == 26 ||
        info_class == 31 || info_class == 32) {
        update.new_password = extract_samr_user_password(request.stub_data, runtime.samr_password_session_key);
    }

    if (runtime.samr_account_update_handler &&
        !runtime.samr_account_update_handler(update)) {
        return response_with_stub(request, dword_stub(nt_status_access_denied));
    }
    return response_with_stub(request, dword_stub(nt_status_success));
}

Bytes samr_get_groups_for_user_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto rid = samr_user_handle_rid(request.stub_data);
    auto record = resolve_samr_account(runtime, {"", rid, false});
    if (!record.has_value() || record->rid == 0) {
        return response_with_stub(request, dword_stub(nt_status_no_trust_sam_account));
    }

    const auto groups = unique_samr_group_rids(*record);
    Bytes output;
    write_u32_le(output, 0x00020030U);
    write_u32_le(output, static_cast<std::uint32_t>(groups.size()));
    write_u32_le(output, 0x00020034U);
    write_u32_le(output, static_cast<std::uint32_t>(groups.size()));
    for (const auto group_rid : groups) {
        write_u32_le(output, group_rid);
        write_u32_le(output, 0x00000007U);
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_password_policy_payload(bool trust_account) {
    Bytes output;
    write_u16_le(output, trust_account ? 0 : 8);
    write_u16_le(output, trust_account ? 0 : 24);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, nt_status_success);
    return output;
}

Bytes samr_user_domain_password_information_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto rid = samr_user_handle_rid(request.stub_data);
    const auto record = resolve_samr_account(runtime, {"", rid, false});
    const bool trust_account = record.has_value() && record->machine_account;
    return response_with_stub(request, samr_password_policy_payload(trust_account));
}

Bytes samr_domain_password_information_response(const RpcRequestInfo& request) {
    return response_with_stub(request, samr_password_policy_payload(false));
}

Bytes samr_rid_to_sid_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto rid = trailing_rid_or_zero(request.stub_data);
    if (rid == 0) {
        return response_with_stub(request, dword_stub(nt_status_no_trust_sam_account));
    }
    const auto sid = well_known_samr_alias(rid).has_value()
        ? std::string{"S-1-5-32-"} + std::to_string(rid)
        : runtime_domain_sid(runtime) + "-" + std::to_string(rid);
    Bytes output = sid_pointer_stub(sid);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_open_group_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto rid = trailing_rid_or_zero(request.stub_data);
    const auto record = resolve_samr_account(runtime, {"", rid, false});
    if (!record.has_value() || !samr_record_is_group(*record)) {
        return response_with_stub(request, dword_stub(nt_status_no_such_user));
    }
    return response_with_stub(request, context_handle_stub(nt_status_success, record->rid, samr_group_handle_marker));
}

std::uint32_t samr_group_information_class(const Bytes& stub) {
    if (stub.size() >= 24) {
        return read_u32_le(stub, 20);
    }
    if (stub.size() >= 4) {
        return read_u32_le(stub, stub.size() - 4);
    }
    return 1;
}

Bytes samr_query_group_info_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto rid = samr_group_handle_rid(request.stub_data);
    const auto record = resolve_samr_account(runtime, {"", rid, false});
    if (!record.has_value() || !samr_record_is_group(*record)) {
        return response_with_stub(request, dword_stub(nt_status_no_such_user));
    }

    const auto info_class = samr_group_information_class(request.stub_data);
    const auto member_rids = samr_member_rids_for_group(runtime, rid);
    Bytes output;
    write_u32_le(output, 0x00020058U);
    write_u32_le(output, info_class);
    append_bytes(output, unicode_string_stub(record->sam_account_name));
    write_u32_le(output, 0x00000007U);
    write_u32_le(output, static_cast<std::uint32_t>(member_rids.size()));
    append_bytes(output, unicode_string_stub(record->display_name.empty() ? record->sam_account_name : record->display_name));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_set_group_info_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto rid = samr_group_handle_rid(request.stub_data);
    const auto record = resolve_samr_account(runtime, {"", rid, false});
    if (!record.has_value() || !samr_record_is_group(*record)) {
        return response_with_stub(request, dword_stub(nt_status_no_such_user));
    }
    return response_with_stub(request, dword_stub(nt_status_success));
}

Bytes samr_group_membership_response(
    const RpcRequestInfo& request,
    const RpcRuntimeInfo& runtime,
    bool add_member) {
    const auto group_rid = samr_group_handle_rid(request.stub_data);
    const auto group = resolve_samr_account(runtime, {"", group_rid, false});
    if (!group.has_value() || !samr_record_is_group(*group)) {
        return response_with_stub(request, dword_stub(nt_status_no_such_user));
    }

    const auto member_rids = samr_relative_ids_from_stub(request.stub_data);
    if (member_rids.empty()) {
        return response_with_stub(request, dword_stub(win32_error_invalid_parameter));
    }

    if (runtime.samr_membership_update_handler) {
        SamrMembershipUpdate update;
        update.container_rid = group_rid;
        update.member_rids = member_rids;
        update.alias = false;
        update.add = add_member;
        if (!runtime.samr_membership_update_handler(update)) {
            return response_with_stub(request, dword_stub(nt_status_access_denied));
        }
    }
    return response_with_stub(request, dword_stub(nt_status_success));
}

Bytes samr_get_members_in_group_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto rid = samr_group_handle_rid(request.stub_data);
    const auto record = resolve_samr_account(runtime, {"", rid, false});
    if (!record.has_value() || !samr_record_is_group(*record)) {
        return response_with_stub(request, dword_stub(nt_status_no_such_user));
    }

    const auto member_rids = samr_member_rids_for_group(runtime, rid);
    Bytes output;
    write_u32_le(output, 0x0002005cU);
    write_u32_le(output, static_cast<std::uint32_t>(member_rids.size()));
    write_u32_le(output, 0x00020060U);
    write_u32_le(output, static_cast<std::uint32_t>(member_rids.size()));
    for (const auto member_rid : member_rids) {
        write_u32_le(output, member_rid);
    }
    write_u32_le(output, 0x00020064U);
    write_u32_le(output, static_cast<std::uint32_t>(member_rids.size()));
    for (std::size_t index = 0; index < member_rids.size(); ++index) {
        write_u32_le(output, 0x00000007U);
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_enumeration_response(
    const RpcRequestInfo& request,
    const std::vector<SamrAccountRecord>& records,
    std::uint32_t pointer_base) {
    Bytes output;
    write_u32_le(output, 0);
    write_u32_le(output, pointer_base);
    write_u32_le(output, static_cast<std::uint32_t>(records.size()));
    write_u32_le(output, pointer_base + 4U);
    write_u32_le(output, static_cast<std::uint32_t>(records.size()));
    for (const auto& record : records) {
        write_u32_le(output, record.rid);
        append_bytes(output, unicode_string_stub(record.sam_account_name));
    }
    write_u32_le(output, static_cast<std::uint32_t>(records.size()));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_enumerate_users_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    return samr_enumeration_response(request, samr_domain_users(runtime), 0x00020060U);
}

Bytes samr_enumerate_groups_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    return samr_enumeration_response(request, samr_domain_groups(runtime), 0x00020070U);
}

std::uint32_t samr_display_information_class(const Bytes& stub) {
    if (stub.size() >= 24) {
        return read_u32_le(stub, 20);
    }
    return 1;
}

std::uint32_t samr_display_start_index(const Bytes& stub) {
    if (stub.size() >= 28) {
        return read_u32_le(stub, 24);
    }
    return 0;
}

std::uint32_t samr_display_max_entries(const Bytes& stub) {
    if (stub.size() >= 32) {
        const auto requested = read_u32_le(stub, 28);
        if (requested > 0) {
            return std::min<std::uint32_t>(requested, 128);
        }
    }
    return 128;
}

std::vector<SamrAccountRecord> samr_display_records(
    const RpcRuntimeInfo& runtime,
    std::uint32_t display_class) {
    if (display_class == 3 || display_class == 5) {
        return samr_domain_groups(runtime);
    }

    std::vector<SamrAccountRecord> records;
    for (const auto& record : samr_domain_records(runtime)) {
        if (display_class == 2) {
            if (record.sid_name_use == sid_name_use_computer || record.machine_account) {
                records.push_back(record);
            }
            continue;
        }
        if (samr_record_is_user_or_machine(record)) {
            records.push_back(record);
        }
    }
    return records;
}

Bytes samr_query_display_information_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto display_class = samr_display_information_class(request.stub_data);
    const auto start_index = samr_display_start_index(request.stub_data);
    const auto max_entries = samr_display_max_entries(request.stub_data);
    const auto records = samr_display_records(runtime, display_class);

    Bytes output;
    write_u32_le(output, static_cast<std::uint32_t>(records.size() * 96U));
    if (start_index >= records.size()) {
        write_u32_le(output, 0);
        write_u32_le(output, 0x000200c0U);
        write_u32_le(output, 0);
        write_u32_le(output, nt_status_success);
        return response_with_stub(request, output);
    }

    const auto returned = std::min<std::uint32_t>(
        max_entries,
        static_cast<std::uint32_t>(records.size() - start_index));
    write_u32_le(output, returned);
    write_u32_le(output, 0x000200c0U);
    write_u32_le(output, returned);
    for (std::uint32_t index = 0; index < returned; ++index) {
        const auto& record = records[start_index + index];
        write_u32_le(output, start_index + index);
        write_u32_le(output, record.rid);
        write_u32_le(output, samr_record_is_group(record) ? 0x00000007U : record.user_account_control);
        append_bytes(output, unicode_string_stub(record.sam_account_name));
        append_bytes(output, unicode_string_stub(""));
        if (!samr_record_is_group(record)) {
            append_bytes(output, unicode_string_stub(record.display_name.empty() ? record.sam_account_name : record.display_name));
        }
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_get_display_enumeration_index_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto display_class = samr_display_information_class(request.stub_data);
    const auto strings = extract_ndr_utf16_strings(request.stub_data);
    const auto prefix = lower_ascii(strings.empty() ? std::string{} : strings.back());
    const auto records = samr_display_records(runtime, display_class);

    std::uint32_t index = 0;
    for (; index < records.size(); ++index) {
        const auto name = lower_ascii(records[index].sam_account_name);
        const auto display = lower_ascii(records[index].display_name);
        if (prefix.empty() || name.starts_with(prefix) || display.starts_with(prefix) || name >= prefix) {
            break;
        }
    }
    if (index >= records.size()) {
        index = records.empty() ? 0 : static_cast<std::uint32_t>(records.size() - 1U);
    }

    Bytes output;
    write_u32_le(output, index);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_enumerate_aliases_response(const RpcRequestInfo& request) {
    const auto aliases = well_known_samr_aliases();
    Bytes output;
    write_u32_le(output, 0);
    write_u32_le(output, 0x00020080U);
    write_u32_le(output, static_cast<std::uint32_t>(aliases.size()));
    write_u32_le(output, 0x00020084U);
    write_u32_le(output, static_cast<std::uint32_t>(aliases.size()));
    for (const auto& alias : aliases) {
        write_u32_le(output, alias.rid);
        append_bytes(output, unicode_string_stub(alias.name));
    }
    write_u32_le(output, static_cast<std::uint32_t>(aliases.size()));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

std::vector<std::uint32_t> embedded_sid_rids(const Bytes& stub) {
    std::vector<std::uint32_t> rids;
    for (std::size_t offset = 0; offset + 12 <= stub.size(); ++offset) {
        if (stub[offset] != 1 || stub[offset + 2] != 0 || stub[offset + 3] != 0 ||
            stub[offset + 4] != 0 || stub[offset + 5] != 0 || stub[offset + 6] != 0 ||
            stub[offset + 7] != 5) {
            continue;
        }
        const auto sub_authority_count = stub[offset + 1];
        if (sub_authority_count == 0 || sub_authority_count > 15) {
            continue;
        }
        const auto last = offset + 8 + (static_cast<std::size_t>(sub_authority_count) - 1U) * 4U;
        if (last + 4 > stub.size()) {
            continue;
        }
        const auto rid = read_u32_le(stub, last);
        if (rid >= 500 && std::find(rids.begin(), rids.end(), rid) == rids.end()) {
            rids.push_back(rid);
        }
    }
    if (rids.empty()) {
        rids = samr_relative_ids_from_stub(stub);
    }
    return rids;
}

Bytes samr_get_alias_membership_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto rids = embedded_sid_rids(request.stub_data);
    std::vector<std::uint32_t> alias_rids;
    for (const auto& alias : well_known_samr_aliases()) {
        const auto members = samr_member_rids_for_alias(runtime, alias.rid);
        const bool matched = std::any_of(rids.begin(), rids.end(), [&](const auto rid) {
            return std::find(members.begin(), members.end(), rid) != members.end();
        });
        if (matched) {
            alias_rids.push_back(alias.rid);
        }
    }

    Bytes output;
    write_u32_le(output, 0x00020090U);
    write_u32_le(output, static_cast<std::uint32_t>(alias_rids.size()));
    write_u32_le(output, 0x00020094U);
    write_u32_le(output, static_cast<std::uint32_t>(alias_rids.size()));
    for (const auto rid : alias_rids) {
        write_u32_le(output, rid);
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_alias_membership_response(
    const RpcRequestInfo& request,
    const RpcRuntimeInfo& runtime,
    bool add_member) {
    const auto alias_rid = samr_alias_handle_rid(request.stub_data);
    if (!well_known_samr_alias(alias_rid).has_value()) {
        return response_with_stub(request, dword_stub(nt_status_no_such_user));
    }

    const auto member_rids = embedded_sid_rids(request.stub_data);
    if (member_rids.empty()) {
        return response_with_stub(request, dword_stub(win32_error_invalid_parameter));
    }

    if (runtime.samr_membership_update_handler) {
        SamrMembershipUpdate update;
        update.container_rid = alias_rid;
        update.member_rids = member_rids;
        update.alias = true;
        update.add = add_member;
        if (!runtime.samr_membership_update_handler(update)) {
            return response_with_stub(request, dword_stub(nt_status_access_denied));
        }
    }
    return response_with_stub(request, dword_stub(nt_status_success));
}

Bytes samr_open_alias_response(const RpcRequestInfo& request) {
    const auto rid = trailing_rid_or_zero(request.stub_data);
    if (!well_known_samr_alias(rid).has_value()) {
        return response_with_stub(request, dword_stub(nt_status_no_such_user));
    }
    return response_with_stub(request, context_handle_stub(nt_status_success, rid, samr_alias_handle_marker));
}

std::uint32_t samr_alias_information_class(const Bytes& stub) {
    if (stub.size() >= 24) {
        return read_u32_le(stub, 20);
    }
    if (stub.size() >= 4) {
        return read_u32_le(stub, stub.size() - 4);
    }
    return 1;
}

Bytes samr_query_alias_info_response(const RpcRequestInfo& request) {
    const auto rid = samr_alias_handle_rid(request.stub_data);
    const auto alias = well_known_samr_alias(rid);
    if (!alias.has_value()) {
        return response_with_stub(request, dword_stub(nt_status_no_such_user));
    }
    const auto info_class = samr_alias_information_class(request.stub_data);
    Bytes output;
    write_u32_le(output, 0x00020098U);
    write_u32_le(output, info_class);
    if (info_class == 3) {
        append_bytes(output, unicode_string_stub(alias->description));
    } else {
        append_bytes(output, unicode_string_stub(alias->name));
        if (info_class == 1) {
            write_u32_le(output, static_cast<std::uint32_t>(alias->member_rids.size()));
            append_bytes(output, unicode_string_stub(alias->description));
        }
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_get_members_in_alias_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    const auto rid = samr_alias_handle_rid(request.stub_data);
    const auto alias = well_known_samr_alias(rid);
    if (!alias.has_value()) {
        return response_with_stub(request, dword_stub(nt_status_no_such_user));
    }

    const auto member_rids = samr_member_rids_for_alias(runtime, rid);
    Bytes output;
    write_u32_le(output, 0x000200a0U);
    write_u32_le(output, static_cast<std::uint32_t>(member_rids.size()));
    write_u32_le(output, 0x000200a4U);
    write_u32_le(output, static_cast<std::uint32_t>(member_rids.size()));
    for (const auto member_rid : member_rids) {
        append_bytes(output, sid_pointer_stub(runtime_domain_sid(runtime) + "-" + std::to_string(member_rid)));
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes samr_query_security_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    return response_with_stub(request, rpc_security_descriptor_payload(runtime, 0x000200b0U));
}

Bytes samr_stub_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    if (request.opnum == 5) {
        return samr_lookup_domain_response(request, runtime);
    }
    if (request.opnum == 6) {
        return samr_enumerate_domains_response(request, runtime);
    }
    if (request.opnum == 2) {
        return response_with_stub(request, dword_stub(nt_status_success));
    }
    if (request.opnum == 3) {
        return samr_query_security_response(request, runtime);
    }
    if (request.opnum == 7 || request.opnum == 0 || request.opnum == 57 || request.opnum == 62 || request.opnum == 64) {
        return response_with_stub(request, context_handle_stub(nt_status_success));
    }
    if (request.opnum == 1) {
        return response_with_stub(request, context_handle_stub(nt_status_success));
    }
    if (request.opnum == 8) {
        return samr_query_domain_info_response(request, runtime);
    }
    if (request.opnum == 9) {
        return response_with_stub(request, dword_stub(nt_status_success));
    }
    if (request.opnum == 11) {
        return samr_enumerate_groups_response(request, runtime);
    }
    if (request.opnum == 12) {
        return samr_create_user_response(request, runtime);
    }
    if (request.opnum == 13) {
        return samr_enumerate_users_response(request, runtime);
    }
    if (request.opnum == 15) {
        return samr_enumerate_aliases_response(request);
    }
    if (request.opnum == 16) {
        return samr_get_alias_membership_response(request, runtime);
    }
    if (request.opnum == 17) {
        return samr_lookup_names_response(request, runtime);
    }
    if (request.opnum == 18) {
        return samr_lookup_ids_response(request, runtime);
    }
    if (request.opnum == 19) {
        return samr_open_group_response(request, runtime);
    }
    if (request.opnum == 20) {
        return samr_query_group_info_response(request, runtime);
    }
    if (request.opnum == 21 || request.opnum == 26) {
        return samr_set_group_info_response(request, runtime);
    }
    if (request.opnum == 23) {
        return response_with_stub(request, dword_stub(nt_status_success));
    }
    if (request.opnum == 22) {
        return samr_group_membership_response(request, runtime, true);
    }
    if (request.opnum == 24) {
        return samr_group_membership_response(request, runtime, false);
    }
    if (request.opnum == 25) {
        return samr_get_members_in_group_response(request, runtime);
    }
    if (request.opnum == 27) {
        return samr_open_alias_response(request);
    }
    if (request.opnum == 28) {
        return samr_query_alias_info_response(request);
    }
    if (request.opnum == 29 || request.opnum == 30) {
        return response_with_stub(request, dword_stub(nt_status_success));
    }
    if (request.opnum == 31 || request.opnum == 52) {
        return samr_alias_membership_response(request, runtime, true);
    }
    if (request.opnum == 32 || request.opnum == 53) {
        return samr_alias_membership_response(request, runtime, false);
    }
    if (request.opnum == 33) {
        return samr_get_members_in_alias_response(request, runtime);
    }
    if (request.opnum == 34) {
        return samr_open_user_response(request, runtime);
    }
    if (request.opnum == 35 || request.opnum == 45) {
        return response_with_stub(request, dword_stub(nt_status_success));
    }
    if (request.opnum == 36 || request.opnum == 47) {
        return samr_query_user_info_response(request, runtime);
    }
    if (request.opnum == 39) {
        return samr_get_groups_for_user_response(request, runtime);
    }
    if (request.opnum == 40 || request.opnum == 48 || request.opnum == 51) {
        return samr_query_display_information_response(request, runtime);
    }
    if (request.opnum == 41 || request.opnum == 49) {
        return samr_get_display_enumeration_index_response(request, runtime);
    }
    if (request.opnum == 50) {
        return samr_create_or_open_user_response(request, runtime);
    }
    if (request.opnum == 37 || request.opnum == 58) {
        return samr_set_user_info_response(request, runtime);
    }
    if (request.opnum == 44) {
        return samr_user_domain_password_information_response(request, runtime);
    }
    if (request.opnum == 56) {
        return samr_domain_password_information_response(request);
    }
    if (request.opnum == 65) {
        return samr_rid_to_sid_response(request, runtime);
    }
    if (request.opnum == 46) {
        return samr_query_domain_info_response(request, runtime);
    }
    return response_with_stub(request, dword_stub(rpc_status_not_supported));
}

Bytes lsa_query_policy_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    Bytes output;
    write_u32_le(output, 0x00020010U);
    const auto name = unicode_string_stub(runtime_domain_netbios_name(runtime));
    output.insert(output.end(), name.begin(), name.end());
    const auto sid = sid_pointer_stub(runtime_domain_sid(runtime));
    output.insert(output.end(), sid.begin(), sid.end());
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

std::string lsa_account_name_from_input(std::string value, const RpcRuntimeInfo& runtime) {
    const auto slash = value.find_last_of("\\/");
    if (slash != std::string::npos) {
        value = value.substr(slash + 1);
    }
    const auto at = value.find('@');
    if (at != std::string::npos) {
        value = value.substr(0, at);
    }
    const auto domain_prefix = runtime_domain_netbios_name(runtime) + "\\";
    if (lower_ascii(value).starts_with(lower_ascii(domain_prefix))) {
        value = value.substr(domain_prefix.size());
    }
    return value;
}

std::vector<std::string> lsa_lookup_names_from_stub(const Bytes& stub, const RpcRuntimeInfo& runtime) {
    std::vector<std::string> names;
    for (auto value : extract_ndr_utf16_strings(stub)) {
        value = lsa_account_name_from_input(std::move(value), runtime);
        if (value.empty() || lower_ascii(value) == lower_ascii(runtime_domain_netbios_name(runtime))) {
            continue;
        }
        if (std::find(names.begin(), names.end(), value) == names.end()) {
            names.push_back(std::move(value));
        }
    }
    if (names.empty()) {
        names.push_back("administrator");
    }
    return names;
}

std::vector<std::uint32_t> lsa_relative_ids_from_sid_stub(const Bytes& stub) {
    std::vector<std::uint32_t> rids;
    for (std::size_t offset = 0; offset + 12 <= stub.size(); ++offset) {
        if (stub[offset] != 1 || stub[offset + 2] != 0 || stub[offset + 3] != 0 ||
            stub[offset + 4] != 0 || stub[offset + 5] != 0 || stub[offset + 6] != 0 ||
            stub[offset + 7] != 5) {
            continue;
        }
        const auto sub_authority_count = stub[offset + 1];
        if (sub_authority_count == 0 || sub_authority_count > 15) {
            continue;
        }
        const auto last = offset + 8 + (static_cast<std::size_t>(sub_authority_count) - 1U) * 4U;
        if (last + 4 > stub.size()) {
            continue;
        }
        const auto rid = read_u32_le(stub, last);
        if (rid >= 500 && std::find(rids.begin(), rids.end(), rid) == rids.end()) {
            rids.push_back(rid);
        }
    }
    if (rids.empty()) {
        rids = samr_relative_ids_from_stub(stub);
    }
    if (rids.empty()) {
        rids.push_back(500);
    }
    return rids;
}

void append_lsa_referenced_domain_list(Bytes& output, const RpcRuntimeInfo& runtime) {
    write_u32_le(output, 0x00020050U);
    write_u32_le(output, 1);
    write_u32_le(output, 0x00020054U);
    write_u32_le(output, 1);
    append_bytes(output, unicode_string_stub(runtime_domain_netbios_name(runtime)));
    append_bytes(output, sid_pointer_stub(runtime_domain_sid(runtime)));
    write_u32_le(output, 1);
}

Bytes lsa_lookup_names_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime, bool extended) {
    const auto names = lsa_lookup_names_from_stub(request.stub_data, runtime);
    Bytes output;
    append_lsa_referenced_domain_list(output, runtime);
    write_u32_le(output, 0x00020060U);
    write_u32_le(output, static_cast<std::uint32_t>(names.size()));
    write_u32_le(output, static_cast<std::uint32_t>(names.size()));
    for (const auto& name : names) {
        const auto record = resolve_samr_account(runtime, {name, 0, false});
        const auto rid = record.has_value() && record->rid != 0 ? record->rid : synthetic_rid_for_name(name);
        const auto use = record.has_value() ? record->sid_name_use : sid_name_use_user;
        write_u32_le(output, use);
        write_u32_le(output, rid);
        write_u32_le(output, 0);
        if (extended) {
            write_u32_le(output, 0);
        }
    }
    write_u32_le(output, static_cast<std::uint32_t>(names.size()));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes lsa_lookup_sids_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime, bool extended) {
    const auto rids = lsa_relative_ids_from_sid_stub(request.stub_data);
    Bytes output;
    append_lsa_referenced_domain_list(output, runtime);
    write_u32_le(output, 0x00020070U);
    write_u32_le(output, static_cast<std::uint32_t>(rids.size()));
    write_u32_le(output, static_cast<std::uint32_t>(rids.size()));
    for (const auto rid : rids) {
        const auto record = resolve_samr_account(runtime, {"", rid, false});
        const auto name = record.has_value() && !record->sam_account_name.empty()
            ? record->sam_account_name
            : std::string{"RID-"} + std::to_string(rid);
        const auto use = record.has_value() ? record->sid_name_use : sid_name_use_user;
        write_u32_le(output, use);
        append_bytes(output, unicode_string_stub(name));
        write_u32_le(output, 0);
        if (extended) {
            write_u32_le(output, 0);
        }
    }
    write_u32_le(output, static_cast<std::uint32_t>(rids.size()));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

std::vector<std::string> lsa_account_right_names(std::uint32_t rid) {
    std::vector<std::string> rights{
        "SeChangeNotifyPrivilege",
        "SeNetworkLogonRight",
        "SeInteractiveLogonRight",
    };
    if (rid != 501 && rid != 514) {
        rights.push_back("SeMachineAccountPrivilege");
    }
    if (rid == 500 || rid == 512 || rid == 544) {
        rights.push_back("SeBackupPrivilege");
        rights.push_back("SeRestorePrivilege");
        rights.push_back("SeSecurityPrivilege");
        rights.push_back("SeDebugPrivilege");
    }
    return rights;
}

std::vector<LsaPrivilegeRecord> lsa_account_privileges(std::uint32_t rid) {
    std::vector<LsaPrivilegeRecord> privileges;
    for (const auto& right : lsa_account_right_names(rid)) {
        if (auto privilege = well_known_lsa_privilege_by_name(right)) {
            privileges.push_back(*privilege);
        }
    }
    return privileges;
}

Bytes lsa_unicode_name_array_response(const RpcRequestInfo& request, const std::vector<std::string>& names) {
    Bytes output;
    write_u32_le(output, 0x00020080U);
    write_u32_le(output, static_cast<std::uint32_t>(names.size()));
    write_u32_le(output, static_cast<std::uint32_t>(names.size()));
    for (const auto& name : names) {
        append_bytes(output, unicode_string_stub(name));
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes lsa_privilege_set_response(
    const RpcRequestInfo& request,
    const std::vector<LsaPrivilegeRecord>& privileges) {
    Bytes output;
    write_u32_le(output, 0x00020084U);
    write_u32_le(output, static_cast<std::uint32_t>(privileges.size()));
    write_u32_le(output, static_cast<std::uint32_t>(privileges.size()));
    for (const auto& privilege : privileges) {
        write_u32_le(output, privilege.luid_low);
        write_u32_le(output, privilege.luid_high);
        write_u32_le(output, 0x00000002U);
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes lsa_enumerate_privileges_response(const RpcRequestInfo& request) {
    const auto privileges = well_known_lsa_privileges();
    Bytes output;
    write_u32_le(output, 0);
    write_u32_le(output, 0x00020088U);
    write_u32_le(output, static_cast<std::uint32_t>(privileges.size()));
    write_u32_le(output, static_cast<std::uint32_t>(privileges.size()));
    for (const auto& privilege : privileges) {
        write_u32_le(output, privilege.luid_low);
        write_u32_le(output, privilege.luid_high);
        append_bytes(output, unicode_string_stub(privilege.name));
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes lsa_enumerate_accounts_response(const RpcRequestInfo& request) {
    Bytes output;
    write_u32_le(output, 0);
    write_u32_le(output, 0x0002008cU);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes lsa_open_account_response(const RpcRequestInfo& request) {
    const auto rids = lsa_relative_ids_from_sid_stub(request.stub_data);
    const auto rid = rids.empty() ? 513U : rids.front();
    return response_with_stub(request, context_handle_stub(nt_status_success, rid, lsa_account_handle_marker));
}

Bytes lsa_quota_limits_response(const RpcRequestInfo& request) {
    Bytes output;
    write_u64_le(output, 0);
    write_u64_le(output, 0);
    write_u64_le(output, 0);
    write_u64_le(output, 0);
    write_u64_le(output, 0);
    write_u64_le(output, 0);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes lsa_get_user_name_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    Bytes output;
    append_bytes(output, unicode_string_stub("Administrator", 0x00020098U));
    append_bytes(output, unicode_string_stub(runtime_domain_netbios_name(runtime), 0x0002009cU));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes lsa_enumerate_privileges_account_response(const RpcRequestInfo& request) {
    auto rid = lsa_account_handle_rid(request.stub_data);
    if (rid == 0) {
        const auto rids = lsa_relative_ids_from_sid_stub(request.stub_data);
        rid = rids.empty() ? 513U : rids.front();
    }
    return lsa_privilege_set_response(request, lsa_account_privileges(rid));
}

Bytes lsa_get_system_access_account_response(const RpcRequestInfo& request) {
    Bytes output;
    write_u32_le(output, 0x00000001U);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes lsa_lookup_privilege_value_response(const RpcRequestInfo& request) {
    const auto names = extract_ndr_utf16_strings(request.stub_data);
    const auto name = names.empty() ? std::string{"SeChangeNotifyPrivilege"} : names.back();
    auto privilege = well_known_lsa_privilege_by_name(name);
    const auto low = privilege.has_value() ? privilege->luid_low : 0x1000U + (stable_hash32(name) % 0x0fffU);
    const auto high = privilege.has_value() ? privilege->luid_high : 0U;
    Bytes output;
    write_u32_le(output, low);
    write_u32_le(output, high);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

std::pair<std::uint32_t, std::uint32_t> lsa_luid_from_stub(const Bytes& stub) {
    if (stub.size() >= 8) {
        return {read_u32_le(stub, stub.size() - 8), read_u32_le(stub, stub.size() - 4)};
    }
    return {23, 0};
}

Bytes lsa_lookup_privilege_name_response(const RpcRequestInfo& request) {
    const auto [low, high] = lsa_luid_from_stub(request.stub_data);
    const auto privilege = well_known_lsa_privilege_by_luid(low, high);
    const auto name = privilege.has_value() ? privilege->name : std::string{"SeChangeNotifyPrivilege"};
    Bytes output = unicode_string_stub(name);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes lsa_lookup_privilege_display_name_response(const RpcRequestInfo& request) {
    const auto names = extract_ndr_utf16_strings(request.stub_data);
    const auto name = names.empty() ? std::string{"SeChangeNotifyPrivilege"} : names.back();
    const auto privilege = well_known_lsa_privilege_by_name(name);
    const auto display = privilege.has_value() ? privilege->display_name : name;
    Bytes output = unicode_string_stub(display);
    write_u32_le(output, 0);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes lsa_enumerate_accounts_with_user_right_response(
    const RpcRequestInfo& request,
    const RpcRuntimeInfo& runtime) {
    const auto names = extract_ndr_utf16_strings(request.stub_data);
    const auto requested = names.empty() ? std::string{} : lower_ascii(names.back());
    std::vector<std::string> sid_strings;
    if (requested.empty() || requested == "semachineaccountprivilege") {
        sid_strings.push_back(runtime_domain_sid(runtime) + "-513");
    }
    if (requested.empty() || requested == "seinteractivelogonright" || requested == "senetworklogonright") {
        sid_strings.push_back(runtime_domain_sid(runtime) + "-512");
    }

    Bytes output;
    write_u32_le(output, 0x00020090U);
    write_u32_le(output, static_cast<std::uint32_t>(sid_strings.size()));
    write_u32_le(output, static_cast<std::uint32_t>(sid_strings.size()));
    for (const auto& sid : sid_strings) {
        append_bytes(output, sid_pointer_stub(sid));
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes lsa_enumerate_account_rights_response(const RpcRequestInfo& request) {
    const auto rids = lsa_relative_ids_from_sid_stub(request.stub_data);
    const auto rid = rids.empty() ? lsa_account_handle_rid(request.stub_data) : rids.front();
    return lsa_unicode_name_array_response(request, lsa_account_right_names(rid == 0 ? 513U : rid));
}

Bytes lsa_account_rights_success_response(const RpcRequestInfo& request) {
    return response_with_stub(request, dword_stub(nt_status_success));
}

Bytes lsa_query_security_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    return response_with_stub(request, rpc_security_descriptor_payload(runtime, 0x00020094U));
}

Bytes lsa_trusted_domain_handle_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    return response_with_stub(
        request,
        context_handle_stub(nt_status_success, stable_hash32(runtime_domain_dns_name(runtime)), lsa_trusted_domain_handle_marker));
}

void append_lsa_trusted_domain_information(Bytes& output, const RpcRuntimeInfo& runtime, bool extended) {
    append_bytes(output, unicode_string_stub(runtime_domain_netbios_name(runtime), 0x000200a8U));
    append_bytes(output, sid_pointer_stub(runtime_domain_sid(runtime), 0x000200acU));
    if (extended) {
        append_bytes(output, unicode_string_stub(runtime_domain_dns_name(runtime), 0x000200b0U));
        write_u32_le(output, 0x00000001U);
        write_u32_le(output, 0x00000002U);
        write_u32_le(output, 0);
    }
}

Bytes lsa_enumerate_trusted_domains_response(
    const RpcRequestInfo& request,
    const RpcRuntimeInfo& runtime,
    bool extended) {
    Bytes output;
    write_u32_le(output, 0);
    write_u32_le(output, 0x000200a0U);
    write_u32_le(output, 1);
    write_u32_le(output, 0x000200a4U);
    write_u32_le(output, 1);
    append_lsa_trusted_domain_information(output, runtime, extended);
    write_u32_le(output, 1);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes lsa_query_trusted_domain_info_response(
    const RpcRequestInfo& request,
    const RpcRuntimeInfo& runtime) {
    const auto info_class = trailing_dword_or_zero(request.stub_data);
    Bytes output;
    write_u32_le(output, 0x000200b8U);
    write_u32_le(output, info_class == 0 ? 1U : info_class);
    append_bytes(output, unicode_string_stub(runtime_domain_netbios_name(runtime), 0x000200bcU));
    append_bytes(output, unicode_string_stub(runtime_domain_dns_name(runtime), 0x000200c0U));
    append_bytes(output, sid_pointer_stub(runtime_domain_sid(runtime), 0x000200c4U));
    write_u32_le(output, 0x00000001U);
    write_u32_le(output, 0x00000002U);
    write_u32_le(output, 0);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes lsarpc_stub_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    if (request.opnum == 0 || request.opnum == 6 || request.opnum == 44) {
        return response_with_stub(request, context_handle_stub(nt_status_success));
    }
    if (request.opnum == 2) {
        return lsa_enumerate_privileges_response(request);
    }
    if (request.opnum == 3) {
        return lsa_query_security_response(request, runtime);
    }
    if (request.opnum == 4) {
        return response_with_stub(request, dword_stub(nt_status_success));
    }
    if (request.opnum == 7 || request.opnum == 46) {
        return lsa_query_policy_response(request, runtime);
    }
    if (request.opnum == 10) {
        return lsa_open_account_response(request);
    }
    if (request.opnum == 11) {
        return lsa_enumerate_accounts_response(request);
    }
    if (request.opnum == 13) {
        return lsa_enumerate_trusted_domains_response(request, runtime, false);
    }
    if (request.opnum == 14) {
        return lsa_lookup_names_response(request, runtime, false);
    }
    if (request.opnum == 15) {
        return lsa_lookup_sids_response(request, runtime, false);
    }
    if (request.opnum == 17) {
        return lsa_open_account_response(request);
    }
    if (request.opnum == 18) {
        return lsa_enumerate_privileges_account_response(request);
    }
    if (request.opnum == 19 || request.opnum == 20) {
        return lsa_account_rights_success_response(request);
    }
    if (request.opnum == 21) {
        return lsa_quota_limits_response(request);
    }
    if (request.opnum == 22) {
        return lsa_account_rights_success_response(request);
    }
    if (request.opnum == 23) {
        return lsa_get_system_access_account_response(request);
    }
    if (request.opnum == 24 || request.opnum == 37 || request.opnum == 38) {
        return lsa_account_rights_success_response(request);
    }
    if (request.opnum == 25) {
        return lsa_trusted_domain_handle_response(request, runtime);
    }
    if (request.opnum == 26 || request.opnum == 39) {
        return lsa_query_trusted_domain_info_response(request, runtime);
    }
    if (request.opnum == 31) {
        return lsa_lookup_privilege_value_response(request);
    }
    if (request.opnum == 32) {
        return lsa_lookup_privilege_name_response(request);
    }
    if (request.opnum == 33) {
        return lsa_lookup_privilege_display_name_response(request);
    }
    if (request.opnum == 34) {
        return lsa_account_rights_success_response(request);
    }
    if (request.opnum == 35) {
        return lsa_enumerate_accounts_with_user_right_response(request, runtime);
    }
    if (request.opnum == 36) {
        return lsa_enumerate_account_rights_response(request);
    }
    if (request.opnum == 41) {
        return lsa_enumerate_trusted_domains_response(request, runtime, true);
    }
    if (request.opnum == 45) {
        return lsa_get_user_name_response(request, runtime);
    }
    if (request.opnum == 57 || request.opnum == 76) {
        return lsa_lookup_sids_response(request, runtime, true);
    }
    if (request.opnum == 58 || request.opnum == 68 || request.opnum == 77) {
        return lsa_lookup_names_response(request, runtime, true);
    }
    return response_with_stub(request, dword_stub(rpc_status_not_supported));
}

struct SrvsvcShareInfo {
    std::string name;
    std::uint32_t type{0};
    std::string remark;
};

std::vector<SrvsvcShareInfo> srvsvc_shares() {
    return {
        {"IPC$", 0x80000003U, "Remote IPC"},
        {"SYSVOL", 0x00000000U, "Endorium Nexus SYSVOL"},
        {"NETLOGON", 0x00000000U, "Endorium Nexus NETLOGON"},
    };
}

std::string srvsvc_requested_share_name(const Bytes& stub) {
    const auto strings = extract_ndr_utf16_strings(stub);
    for (auto value : strings) {
        value = trim_pipe_prefix(value);
        const auto slash = value.find_last_of("\\/");
        if (slash != std::string::npos) {
            value = value.substr(slash + 1);
        }
        const auto normalized = lower_ascii(value);
        if (normalized == "ipc$" || normalized == "sysvol" || normalized == "netlogon") {
            return value;
        }
    }
    return "SYSVOL";
}

SrvsvcShareInfo srvsvc_share_for_name(const std::string& requested) {
    const auto normalized = lower_ascii(requested);
    for (const auto& share : srvsvc_shares()) {
        if (lower_ascii(share.name) == normalized) {
            return share;
        }
    }
    return {"SYSVOL", 0x00000000U, "Endorium Nexus SYSVOL"};
}

void append_srvsvc_share_info_1(Bytes& output, const SrvsvcShareInfo& share) {
    append_bytes(output, unicode_string_stub(share.name));
    write_u32_le(output, share.type);
    append_bytes(output, unicode_string_stub(share.remark));
}

Bytes srvsvc_share_enum_response(const RpcRequestInfo& request) {
    const auto shares = srvsvc_shares();
    Bytes output;
    write_u32_le(output, 1);
    write_u32_le(output, 0x00020400U);
    write_u32_le(output, static_cast<std::uint32_t>(shares.size()));
    write_u32_le(output, 0x00020404U);
    write_u32_le(output, static_cast<std::uint32_t>(shares.size()));
    write_u32_le(output, static_cast<std::uint32_t>(shares.size()));
    for (const auto& share : shares) {
        append_srvsvc_share_info_1(output, share);
    }
    write_u32_le(output, static_cast<std::uint32_t>(shares.size()));
    write_u32_le(output, 0);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes srvsvc_share_get_info_response(const RpcRequestInfo& request) {
    const auto share = srvsvc_share_for_name(srvsvc_requested_share_name(request.stub_data));
    Bytes output;
    write_u32_le(output, 1);
    write_u32_le(output, 0x00020410U);
    append_srvsvc_share_info_1(output, share);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes srvsvc_server_get_info_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    Bytes output;
    write_u32_le(output, 102);
    write_u32_le(output, 0x00020420U);
    write_u32_le(output, 50331648U);
    append_bytes(output, unicode_string_stub(runtime_dc_dns_name(runtime)));
    write_u32_le(output, 0x00000002U);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    append_bytes(output, unicode_string_stub("Endorium Nexus Directory Server"));
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes srvsvc_stub_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    if (request.opnum == 15) {
        return srvsvc_share_enum_response(request);
    }
    if (request.opnum == 16) {
        return srvsvc_share_get_info_response(request);
    }
    if (request.opnum == 21) {
        return srvsvc_server_get_info_response(request, runtime);
    }
    return response_with_stub(request, dword_stub(rpc_status_not_supported));
}

Bytes wkssvc_get_info_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    Bytes output;
    write_u32_le(output, 100);
    write_u32_le(output, 0x00020500U);
    write_u32_le(output, 50331648U);
    append_bytes(output, unicode_string_stub(runtime_dc_dns_name(runtime)));
    append_bytes(output, unicode_string_stub(runtime_domain_netbios_name(runtime)));
    append_bytes(output, unicode_string_stub(runtime_domain_dns_name(runtime)));
    write_u32_le(output, 0);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes wkssvc_user_enum_response(const RpcRequestInfo& request) {
    Bytes output;
    write_u32_le(output, 1);
    write_u32_le(output, 0x00020510U);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, 0);
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes wkssvc_stub_response(const RpcRequestInfo& request, const RpcRuntimeInfo& runtime) {
    if (request.opnum == 0) {
        return wkssvc_get_info_response(request, runtime);
    }
    if (request.opnum == 2) {
        return wkssvc_user_enum_response(request);
    }
    return response_with_stub(request, dword_stub(rpc_status_not_supported));
}

std::uint16_t endpoint_for_pipe(const std::string& pipe_name, std::uint16_t fallback_port) {
    const auto pipe = trim_pipe_prefix(pipe_name);
    if (pipe == "netlogon") {
        return 445;
    }
    if (pipe == "samr" || pipe == "lsarpc" || pipe == "srvsvc" || pipe == "wkssvc" || pipe == "epmapper") {
        return 445;
    }
    return fallback_port;
}

bool bind_targets_pipe(const RpcRequestInfo& request, const std::string& pipe_name) {
    const auto pipe = trim_pipe_prefix(pipe_name);
    for (const auto& syntax : request.abstract_syntaxes) {
        const auto lower = lower_ascii(syntax);
        if (pipe == "netlogon" && lower == uuid_netlogon) {
            return true;
        }
        if (pipe == "samr" && lower == uuid_samr) {
            return true;
        }
        if (pipe == "lsarpc" && lower == uuid_lsarpc) {
            return true;
        }
        if (pipe == "srvsvc" && lower == uuid_srvsvc) {
            return true;
        }
        if (pipe == "wkssvc" && lower == uuid_wkssvc) {
            return true;
        }
        if (pipe == "epmapper" && lower == uuid_epmapper) {
            return true;
        }
        if (lower == uuid_epmapper) {
            return true;
        }
    }
    return request.abstract_syntaxes.empty();
}

Bytes named_pipe_request_response(
    const RpcRequestInfo& request,
    const std::string& pipe_name,
    const RpcRuntimeInfo& runtime) {
    const auto pipe = trim_pipe_prefix(pipe_name);
    if (pipe == "netlogon") {
        return netlogon_stub_response(request, runtime);
    }
    if (pipe == "samr") {
        return samr_stub_response(request, runtime);
    }
    if (pipe == "lsarpc") {
        return lsarpc_stub_response(request, runtime);
    }
    if (pipe == "srvsvc") {
        return srvsvc_stub_response(request, runtime);
    }
    if (pipe == "wkssvc") {
        return wkssvc_stub_response(request, runtime);
    }
    if (pipe == "epmapper") {
        if (request.opnum == 2) {
            return endpoint_mapper_lookup_response(request, 445);
        }
        if (request.opnum == 3) {
            return endpoint_mapper_map_response(request, 445);
        }
        if (request.opnum == 5) {
            return endpoint_mapper_alive_response(request, 445);
        }
        return fault_response(request);
    }
    return response_with_stub(request, dword_stub(rpc_status_not_supported));
}

Bytes fault_response(const RpcRequestInfo& request) {
    Bytes body;
    write_u32_le(body, 0);
    write_u16_le(body, request.context_id);
    body.push_back(0);
    body.push_back(0);
    write_u32_le(body, nca_s_op_rng_error);
    body.insert(body.end(), {0, 0, 0, 0});

    auto output = rpc_header(ptype_fault, request.call_id, body.size());
    output.insert(output.end(), body.begin(), body.end());
    return output;
}

Bytes uuid_bytes_from_string(const std::string& uuid) {
    auto hex = uuid;
    hex.erase(std::remove(hex.begin(), hex.end(), '-'), hex.end());
    auto bytes = hex_to_bytes(hex);
    if (!bytes.has_value() || bytes->size() != 16) {
        return {};
    }
    return {
        (*bytes)[3], (*bytes)[2], (*bytes)[1], (*bytes)[0],
        (*bytes)[5], (*bytes)[4],
        (*bytes)[7], (*bytes)[6],
        (*bytes)[8], (*bytes)[9],
        (*bytes)[10], (*bytes)[11], (*bytes)[12], (*bytes)[13], (*bytes)[14], (*bytes)[15],
    };
}

std::vector<RpcEndpointHint> endpoint_hints(std::uint16_t endpoint_port) {
    return {
        {uuid_netlogon, "Nexus Netlogon", "ncacn_np", "\\\\PIPE\\\\netlogon"},
        {uuid_samr, "Nexus SAMR", "ncacn_np", "\\\\PIPE\\\\samr"},
        {uuid_lsarpc, "Nexus LSA", "ncacn_np", "\\\\PIPE\\\\lsarpc"},
        {uuid_srvsvc, "Nexus Server Service", "ncacn_np", "\\\\PIPE\\\\srvsvc"},
        {uuid_wkssvc, "Nexus Workstation Service", "ncacn_np", "\\\\PIPE\\\\wkssvc"},
        {uuid_epmapper, "Nexus Endpoint Mapper", "ncacn_ip_tcp", std::to_string(endpoint_port)},
    };
}

bool request_mentions_endpoint(const RpcRequestInfo& request, const RpcEndpointHint& hint) {
    const auto uuid_bytes = uuid_bytes_from_string(hint.uuid);
    if (uuid_bytes.empty()) {
        return false;
    }
    return contains_bytes(request.stub_data, uuid_bytes);
}

std::vector<RpcEndpointHint> filtered_endpoint_hints(
    const RpcRequestInfo& request,
    std::uint16_t endpoint_port) {
    const auto all = endpoint_hints(endpoint_port);
    std::vector<RpcEndpointHint> matched;
    for (const auto& hint : all) {
        if (request_mentions_endpoint(request, hint)) {
            matched.push_back(hint);
        }
    }
    return matched.empty() ? all : matched;
}

Bytes endpoint_hint_payload(const RpcEndpointHint& hint) {
    Bytes output;
    append_bytes(output, unicode_string_stub(hint.uuid));
    append_bytes(output, unicode_string_stub(hint.annotation));
    append_bytes(output, unicode_string_stub(hint.protocol_sequence));
    append_bytes(output, unicode_string_stub(hint.endpoint));
    return output;
}

Bytes endpoint_mapper_lookup_response(
    const RpcRequestInfo& request,
    std::uint16_t endpoint_port) {
    const auto endpoints = filtered_endpoint_hints(request, endpoint_port);
    Bytes output;
    output.insert(output.end(), 20, 0);
    write_u32_le(output, static_cast<std::uint32_t>(endpoints.size()));
    write_u32_le(output, 0x00020600U);
    write_u32_le(output, static_cast<std::uint32_t>(endpoints.size()));
    write_u32_le(output, static_cast<std::uint32_t>(endpoints.size()));
    for (const auto& hint : endpoints) {
        append_bytes(output, endpoint_hint_payload(hint));
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes endpoint_mapper_map_response(
    const RpcRequestInfo& request,
    std::uint16_t endpoint_port) {
    const auto endpoints = filtered_endpoint_hints(request, endpoint_port);
    Bytes output;
    output.insert(output.end(), 20, 0);
    write_u32_le(output, static_cast<std::uint32_t>(endpoints.size()));
    write_u32_le(output, 0x00020620U);
    write_u32_le(output, static_cast<std::uint32_t>(endpoints.size()));
    write_u32_le(output, static_cast<std::uint32_t>(endpoints.size()));
    for (const auto& hint : endpoints) {
        append_bytes(output, endpoint_hint_payload(hint));
    }
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

Bytes endpoint_mapper_alive_response(
    const RpcRequestInfo& request,
    std::uint16_t endpoint_port) {
    Bytes output;
    write_u32_le(output, 0);
    append_bytes(output, unicode_string_stub("ncacn_ip_tcp"));
    append_bytes(output, unicode_string_stub(std::to_string(endpoint_port)));
    write_u32_le(output, nt_status_success);
    return response_with_stub(request, output);
}

}  // namespace

std::optional<NetlogonCredentialMaterial> compute_netlogon_aes_credentials(
    const std::string& nt_hash_hex,
    const std::vector<std::uint8_t>& client_challenge,
    const std::vector<std::uint8_t>& server_challenge) {
    if (client_challenge.size() != 8 || server_challenge.size() != 8) {
        return std::nullopt;
    }
    auto nt_hash = hex_to_bytes(nt_hash_hex);
    if (!nt_hash.has_value() || nt_hash->size() != 16) {
        return std::nullopt;
    }

    Bytes message;
    message.reserve(client_challenge.size() + server_challenge.size());
    message.insert(message.end(), client_challenge.begin(), client_challenge.end());
    message.insert(message.end(), server_challenge.begin(), server_challenge.end());
    auto digest = hmac_sha256(*nt_hash, message);
    if (!digest.has_value() || digest->size() < 16) {
        return std::nullopt;
    }

    Bytes session_key(digest->begin(), digest->begin() + 16);
    auto client_credential = compute_netlogon_aes_credential(session_key, client_challenge);
    auto server_credential = compute_netlogon_aes_credential(session_key, server_challenge);
    if (!client_credential.has_value() || !server_credential.has_value()) {
        return std::nullopt;
    }
    return NetlogonCredentialMaterial{
        session_key,
        *client_credential,
        *server_credential,
    };
}

std::optional<std::vector<std::uint8_t>> compute_netlogon_aes_credential(
    const std::vector<std::uint8_t>& session_key,
    const std::vector<std::uint8_t>& credential_seed) {
    if (credential_seed.size() != 8) {
        return std::nullopt;
    }
    return aes_128_cfb8_encrypt(session_key, credential_seed);
}

std::optional<std::vector<std::uint8_t>> compute_netlogon_ntlmv2_response(
    const std::string& nt_hash_hex,
    const std::string& sam_account_name,
    const std::string& domain_name,
    const std::vector<std::uint8_t>& server_challenge,
    const std::vector<std::uint8_t>& client_challenge,
    const std::vector<std::uint8_t>& target_info) {
    if (server_challenge.size() != 8 || client_challenge.size() != 8) {
        return std::nullopt;
    }
    auto response_key = ntlmv2_response_key(nt_hash_hex, sam_account_name, domain_name);
    if (!response_key.has_value()) {
        return std::nullopt;
    }
    const auto blob = ntlmv2_blob(client_challenge, target_info);
    auto proof = ntlmv2_proof(*response_key, server_challenge, blob);
    if (!proof.has_value()) {
        return std::nullopt;
    }
    Bytes output = *proof;
    append_bytes(output, blob);
    return output;
}

std::vector<std::uint8_t> advance_netlogon_credential_seed(
    const std::vector<std::uint8_t>& credential,
    std::uint32_t increment) {
    Bytes output(8, 0);
    std::copy_n(credential.begin(), std::min<std::size_t>(credential.size(), output.size()), output.begin());
    const auto low = read_u32_le(output, 0) + increment;
    output[0] = static_cast<std::uint8_t>(low & 0xffU);
    output[1] = static_cast<std::uint8_t>((low >> 8U) & 0xffU);
    output[2] = static_cast<std::uint8_t>((low >> 16U) & 0xffU);
    output[3] = static_cast<std::uint8_t>((low >> 24U) & 0xffU);
    return output;
}

std::optional<std::vector<std::uint8_t>> encrypt_netlogon_trust_password(
    const std::vector<std::uint8_t>& session_key,
    const std::string& password) {
    auto password_bytes = utf16le_from_utf8(password);
    if (password_bytes.size() > 512) {
        return std::nullopt;
    }

    Bytes plaintext(516, 0);
    const auto password_offset = 512 - password_bytes.size();
    std::copy(password_bytes.begin(), password_bytes.end(), plaintext.begin() + static_cast<std::ptrdiff_t>(password_offset));
    const auto length = static_cast<std::uint32_t>(password_bytes.size());
    plaintext[512] = static_cast<std::uint8_t>(length & 0xffU);
    plaintext[513] = static_cast<std::uint8_t>((length >> 8U) & 0xffU);
    plaintext[514] = static_cast<std::uint8_t>((length >> 16U) & 0xffU);
    plaintext[515] = static_cast<std::uint8_t>((length >> 24U) & 0xffU);
    return aes_128_cfb8_encrypt(session_key, plaintext);
}

std::optional<std::string> decrypt_netlogon_trust_password(
    const std::vector<std::uint8_t>& session_key,
    const std::vector<std::uint8_t>& encrypted_password) {
    if (encrypted_password.size() != 516) {
        return std::nullopt;
    }
    auto plaintext = aes_128_cfb8_decrypt(session_key, encrypted_password);
    if (!plaintext.has_value() || plaintext->size() != 516) {
        return std::nullopt;
    }
    const auto length = read_u32_le(*plaintext, 512);
    if (length > 512 || length % 2 != 0) {
        return std::nullopt;
    }
    return decode_utf16le_password(*plaintext, 512 - length, length);
}

RpcRequestInfo parse_rpc_request(const std::vector<std::uint8_t>& request) {
    RpcRequestInfo parsed;
    if (request.size() < 16 || request[0] != 5) {
        return parsed;
    }
    parsed.ptype = request[2];
    parsed.frag_length = read_u16_le(request, 8);
    parsed.call_id = read_u32_le(request, 12);
    if (parsed.frag_length < 16 || parsed.frag_length > request.size()) {
        return parsed;
    }

    if (parsed.ptype == ptype_bind) {
        if (request.size() < 28) {
            return parsed;
        }
        const auto count = request[24];
        std::size_t offset = 28;
        for (std::uint8_t index = 0; index < count; ++index) {
            if (offset + 44 > request.size()) {
                return parsed;
            }
            const auto context_id = read_u16_le(request, offset);
            const auto transfer_count = request[offset + 2];
            parsed.bind_context_ids.push_back(context_id);
            parsed.abstract_syntaxes.push_back(uuid_to_string(request, offset + 4));
            offset += 24 + (static_cast<std::size_t>(transfer_count) * 20U);
        }
    } else if (parsed.ptype == ptype_request) {
        if (request.size() < 24) {
            return parsed;
        }
        parsed.context_id = read_u16_le(request, 20);
        parsed.opnum = read_u16_le(request, 22);
        parsed.stub_data.assign(request.begin() + 24, request.begin() + parsed.frag_length);
    }

    parsed.valid = true;
    return parsed;
}

std::vector<std::uint8_t> rpc_endpoint_mapper_response(
    const std::vector<std::uint8_t>& request,
    std::uint16_t endpoint_port) {
    const auto parsed = parse_rpc_request(request);
    if (!parsed.valid) {
        return {};
    }
    if (parsed.ptype == ptype_bind) {
        return bind_ack(parsed, endpoint_port);
    }
    if (parsed.ptype == ptype_request) {
        if (parsed.opnum == 2) {
            return endpoint_mapper_lookup_response(parsed, endpoint_port);
        }
        if (parsed.opnum == 3) {
            return endpoint_mapper_map_response(parsed, endpoint_port);
        }
        if (parsed.opnum == 5) {
            return endpoint_mapper_alive_response(parsed, endpoint_port);
        }
        return fault_response(parsed);
    }
    return {};
}

std::vector<std::uint8_t> rpc_named_pipe_response(
    const std::vector<std::uint8_t>& request,
    const std::string& pipe_name) {
    return rpc_named_pipe_response(request, pipe_name, RpcRuntimeInfo{});
}

std::vector<std::uint8_t> rpc_named_pipe_response(
    const std::vector<std::uint8_t>& request,
    const std::string& pipe_name,
    const RpcRuntimeInfo& runtime) {
    const auto parsed = parse_rpc_request(request);
    if (!parsed.valid) {
        return {};
    }
    if (parsed.ptype == ptype_bind) {
        if (!bind_targets_pipe(parsed, pipe_name)) {
            return fault_response(parsed);
        }
        return bind_ack(parsed, endpoint_for_pipe(pipe_name, 445));
    }
    if (parsed.ptype == ptype_request) {
        return named_pipe_request_response(parsed, pipe_name, runtime);
    }
    return {};
}

}  // namespace nexus::protocol
