#pragma once

#include <cstdint>
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
    std::vector<int> requested_etypes;
    std::vector<int> padata_types;
    std::vector<int> encrypted_timestamp_etypes;
    std::vector<KerberosEncryptedData> encrypted_timestamps;
    bool has_padata{false};
};

[[nodiscard]] KerberosRequestInfo parse_kerberos_request(const std::vector<std::uint8_t>& request);

[[nodiscard]] std::vector<std::uint8_t> kerberos_encrypt_aes_cts_hmac_sha1(
    const std::vector<std::uint8_t>& plaintext,
    const std::string& key_hex,
    int key_usage,
    const std::vector<std::uint8_t>& confounder = {});

[[nodiscard]] std::vector<std::uint8_t> kerberos_error_response(
    const std::vector<std::uint8_t>& request,
    const KerberosRealmInfo& realm);

[[nodiscard]] std::vector<std::uint8_t> kerberos_tcp_error_response(
    const std::vector<std::uint8_t>& frame,
    const KerberosRealmInfo& realm);

}  // namespace nexus::protocol
