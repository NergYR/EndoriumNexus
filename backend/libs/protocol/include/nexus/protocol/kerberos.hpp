#pragma once

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <vector>

namespace nexus::protocol {

struct KerberosKey {
    int enctype{0};
    std::string enctype_name;
    std::string salt;
    std::string key_hex;
};

struct KerberosEncryptedData {
    int enctype{0};
    std::vector<std::uint8_t> cipher;
};

struct KerberosPrincipal {
    std::string principal;
    std::string realm;
    bool has_key_material{false};
    std::vector<KerberosKey> keys;
    std::string object_sid;
    std::uint32_t rid{0};
    std::uint32_t primary_group_rid{513};
    std::vector<std::uint32_t> group_rids;
    std::string display_name;
    std::uint32_t user_account_control{0};
    bool account_expired{false};
};

struct KerberosRealmInfo {
    std::string realm;
    std::string kdc_name;
    std::vector<KerberosPrincipal> principals;
};

struct KerberosRequestInfo {
    bool valid{false};
    int message_type{0};
    std::string realm;
    std::string client_principal;
    std::string service_principal;
    int nonce{0};
    std::vector<int> requested_etypes;
    std::vector<int> padata_types;
    std::vector<int> encrypted_timestamp_etypes;
    std::vector<KerberosEncryptedData> encrypted_timestamps;
    std::vector<std::uint8_t> tgs_ap_req;
    bool has_padata{false};
};

struct KerberosPasswordChangeRequestInfo {
    bool valid{false};
    std::uint16_t message_length{0};
    std::uint16_t version{0};
    std::uint16_t ap_req_length{0};
    std::vector<std::uint8_t> ap_req;
    std::vector<std::uint8_t> encrypted_payload;
};

struct KerberosApReqValidationResult {
    bool ok{false};
    std::string client_principal;
    std::string service_principal;
    std::string realm;
    std::string diagnostic;
    std::vector<std::uint8_t> response_token;
    int session_key_enctype{0};
    std::vector<std::uint8_t> session_key;
    int subsession_key_enctype{0};
    std::vector<std::uint8_t> subsession_key;
};

struct KerberosPasswordChange {
    std::string principal;
    std::string realm;
    std::string target_principal;
    std::string target_realm;
    std::string new_password;
};

using KerberosPasswordChangeHandler = std::function<bool(const KerberosPasswordChange&)>;

[[nodiscard]] KerberosRequestInfo parse_kerberos_request(const std::vector<std::uint8_t>& request);
[[nodiscard]] KerberosPasswordChangeRequestInfo parse_kpasswd_request(const std::vector<std::uint8_t>& request);

[[nodiscard]] KerberosApReqValidationResult validate_kerberos_ap_req(
    const std::vector<std::uint8_t>& ap_req,
    const KerberosRealmInfo& realm,
    const std::optional<std::string>& expected_service_principal = std::nullopt);

[[nodiscard]] std::vector<std::uint8_t> kerberos_encrypt_aes_cts_hmac_sha1(
    const std::vector<std::uint8_t>& plaintext,
    const std::string& key_hex,
    int key_usage,
    const std::vector<std::uint8_t>& confounder = {});

// Computes an RFC 4121 GSS MIC token (acceptor, key usage 23) over `message` using the
// AES sub-session key `subkey_hex`. Used to build the SPNEGO mechListMIC that Windows
// requires in the SMB/LDAP session-setup acceptor reply.
[[nodiscard]] std::vector<std::uint8_t> kerberos_gss_acceptor_mic(
    const std::vector<std::uint8_t>& subkey,
    const std::vector<std::uint8_t>& message);

[[nodiscard]] std::vector<std::uint8_t> kerberos_minimal_pac(
    const std::string& client_principal,
    const std::string& realm,
    const KerberosPrincipal& client,
    const KerberosKey& service_key,
    const KerberosKey& kdc_key);

[[nodiscard]] std::vector<std::uint8_t> kerberos_error_response(
    const std::vector<std::uint8_t>& request,
    const KerberosRealmInfo& realm);

[[nodiscard]] std::vector<std::uint8_t> kerberos_tcp_error_response(
    const std::vector<std::uint8_t>& frame,
    const KerberosRealmInfo& realm);

[[nodiscard]] std::vector<std::uint8_t> kerberos_kpasswd_response(
    const std::vector<std::uint8_t>& request,
    const KerberosRealmInfo& realm,
    const KerberosPasswordChangeHandler& password_change_handler = {});

[[nodiscard]] std::vector<std::uint8_t> kerberos_tcp_kpasswd_response(
    const std::vector<std::uint8_t>& frame,
    const KerberosRealmInfo& realm,
    const KerberosPasswordChangeHandler& password_change_handler = {});

}  // namespace nexus::protocol
