#pragma once

#include <filesystem>
#include <optional>
#include <string>
#include <vector>

namespace nexus::security {

struct AdKerberosKey {
    std::string enctype;
    std::string salt;
    std::string key_hex;
};

struct AdCredentialMaterial {
    std::string nt_hash_hex;
    std::vector<AdKerberosKey> kerberos_keys;
};

[[nodiscard]] std::string ad_kerberos_salt(const std::string& realm, const std::string& principal);
[[nodiscard]] std::string derive_ad_kerberos_aes_key(
    const std::string& password,
    const std::string& salt,
    int key_bytes,
    int iterations = 4096);
[[nodiscard]] AdCredentialMaterial derive_ad_credentials(
    const std::string& password,
    const std::string& realm,
    const std::string& principal);
[[nodiscard]] std::string seal_ad_secret(
    const std::filesystem::path& key_file,
    const std::string& plaintext);
[[nodiscard]] std::optional<std::string> open_ad_secret(
    const std::filesystem::path& key_file,
    const std::string& sealed);

}  // namespace nexus::security
