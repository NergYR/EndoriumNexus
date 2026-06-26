#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace nexus::protocol {

struct RpcRequestInfo {
    bool valid{false};
    std::uint8_t ptype{0};
    std::uint16_t frag_length{0};
    std::uint32_t call_id{0};
    std::uint16_t context_id{0};
    std::uint16_t opnum{0};
    std::vector<std::uint8_t> stub_data;
    std::vector<std::uint16_t> bind_context_ids;
    std::vector<std::string> abstract_syntaxes;
};

struct NetlogonAccountSecret {
    std::string sam_account_name;
    std::string nt_hash_hex;
    std::uint32_t rid{0};
    std::uint32_t user_account_control{0};
    bool account_expired{false};
};

struct NetlogonPasswordUpdate {
    std::string sam_account_name;
    std::string computer_name;
    std::string new_password;
};

struct NetlogonSamLogonRequest {
    std::string sam_account_name;
    std::string domain_name;
    std::string computer_name;
    std::uint32_t logon_level{0};
    std::uint32_t validation_level{0};
    std::uint32_t extra_flags{0};
    std::vector<std::uint8_t> raw_stub;
};

struct SamrAccountRequest {
    std::string sam_account_name;
    std::uint32_t rid{0};
    bool create_if_missing{false};
};

struct SamrAccountRecord {
    std::string sam_account_name;
    std::uint32_t rid{0};
    std::string display_name;
    std::uint32_t primary_group_rid{0};
    std::uint32_t user_account_control{0};
    bool machine_account{false};
    std::vector<std::uint32_t> group_rids;
    std::uint32_t sid_name_use{1};
};

struct SamrAccountUpdate {
    std::string sam_account_name;
    std::uint32_t rid{0};
    std::optional<std::string> display_name;
    std::optional<std::uint32_t> primary_group_rid;
    std::optional<std::uint32_t> user_account_control;
    std::optional<std::string> new_password;
};

struct SamrMembershipUpdate {
    std::uint32_t container_rid{0};
    std::vector<std::uint32_t> member_rids;
    bool alias{false};
    bool add{true};
};

struct NetlogonSamLogonResult {
    bool authenticated{false};
    std::uint32_t status{0};
    SamrAccountRecord account;
    std::vector<std::uint8_t> user_session_key;
};

struct RpcRuntimeInfo {
    std::vector<NetlogonAccountSecret> netlogon_accounts;
    std::function<bool(const NetlogonPasswordUpdate&)> netlogon_password_update_handler;
    std::function<std::optional<SamrAccountRecord>(const SamrAccountRequest&)> samr_account_handler;
    std::function<bool(const SamrAccountUpdate&)> samr_account_update_handler;
    std::vector<std::uint8_t> samr_password_session_key;
    std::string domain_netbios_name;
    std::string domain_dns_name;
    std::string domain_sid;
    std::string domain_controller_host;
    std::string domain_controller_address;
    std::string site_name;
    std::function<std::optional<NetlogonSamLogonResult>(const NetlogonSamLogonRequest&)> netlogon_logon_handler;
    std::function<std::vector<SamrAccountRecord>()> samr_account_enumerator;
    std::function<bool(const SamrMembershipUpdate&)> samr_membership_update_handler;
};

struct NetlogonCredentialMaterial {
    std::vector<std::uint8_t> session_key;
    std::vector<std::uint8_t> client_credential;
    std::vector<std::uint8_t> server_credential;
};

[[nodiscard]] RpcRequestInfo parse_rpc_request(const std::vector<std::uint8_t>& request);

[[nodiscard]] std::optional<NetlogonCredentialMaterial> compute_netlogon_aes_credentials(
    const std::string& nt_hash_hex,
    const std::vector<std::uint8_t>& client_challenge,
    const std::vector<std::uint8_t>& server_challenge);

[[nodiscard]] std::optional<std::vector<std::uint8_t>> compute_netlogon_aes_credential(
    const std::vector<std::uint8_t>& session_key,
    const std::vector<std::uint8_t>& credential_seed);

[[nodiscard]] std::optional<std::vector<std::uint8_t>> compute_netlogon_ntlmv2_response(
    const std::string& nt_hash_hex,
    const std::string& sam_account_name,
    const std::string& domain_name,
    const std::vector<std::uint8_t>& server_challenge,
    const std::vector<std::uint8_t>& client_challenge,
    const std::vector<std::uint8_t>& target_info = {});

[[nodiscard]] std::vector<std::uint8_t> advance_netlogon_credential_seed(
    const std::vector<std::uint8_t>& credential,
    std::uint32_t increment);

[[nodiscard]] std::optional<std::vector<std::uint8_t>> encrypt_netlogon_trust_password(
    const std::vector<std::uint8_t>& session_key,
    const std::string& password);

[[nodiscard]] std::optional<std::string> decrypt_netlogon_trust_password(
    const std::vector<std::uint8_t>& session_key,
    const std::vector<std::uint8_t>& encrypted_password);

[[nodiscard]] std::vector<std::uint8_t> rpc_endpoint_mapper_response(
    const std::vector<std::uint8_t>& request,
    std::uint16_t endpoint_port = 135);

[[nodiscard]] std::vector<std::uint8_t> rpc_named_pipe_response(
    const std::vector<std::uint8_t>& request,
    const std::string& pipe_name);

[[nodiscard]] std::vector<std::uint8_t> rpc_named_pipe_response(
    const std::vector<std::uint8_t>& request,
    const std::string& pipe_name,
    const RpcRuntimeInfo& runtime);

}  // namespace nexus::protocol
