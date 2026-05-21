#include "nexus/security/ad_crypto.hpp"

#include <openssl/evp.h>
#include <openssl/md4.h>
#include <openssl/rand.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <system_error>
#include <vector>

namespace nexus::security {

namespace {

using ByteVector = std::vector<unsigned char>;

std::string uppercase_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

std::string lowercase_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string bytes_to_hex(const unsigned char* data, std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < size; ++index) {
        output << std::setw(2) << static_cast<int>(data[index]);
    }
    return output.str();
}

std::string bytes_to_hex(const std::vector<unsigned char>& bytes) {
    return bytes_to_hex(bytes.data(), bytes.size());
}

std::optional<std::vector<unsigned char>> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        return std::nullopt;
    }
    std::vector<unsigned char> bytes;
    bytes.reserve(hex.size() / 2);
    for (std::size_t offset = 0; offset < hex.size(); offset += 2) {
        try {
            bytes.push_back(static_cast<unsigned char>(std::stoul(hex.substr(offset, 2), nullptr, 16)));
        } catch (...) {
            return std::nullopt;
        }
    }
    return bytes;
}

ByteVector random_bytes(std::size_t size) {
    ByteVector bytes(size);
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return bytes;
}

ByteVector load_or_create_key(const std::filesystem::path& key_file) {
    if (auto existing = [&]() -> std::optional<ByteVector> {
            if (!std::filesystem::exists(key_file)) {
                return std::nullopt;
            }
            std::ifstream input(key_file);
            std::string hex;
            input >> hex;
            auto key = hex_to_bytes(hex);
            if (key.has_value() && key->size() == 32) {
                return key;
            }
            return std::nullopt;
        }()) {
        return *existing;
    }

    auto key = random_bytes(32);
    if (key_file.has_parent_path()) {
        std::error_code error_code;
        std::filesystem::create_directories(key_file.parent_path(), error_code);
    }
    std::ofstream output(key_file, std::ios::trunc);
    output << bytes_to_hex(key);
    return key;
}

std::optional<ByteVector> load_existing_key(const std::filesystem::path& key_file) {
    if (!std::filesystem::exists(key_file)) {
        return std::nullopt;
    }
    std::ifstream input(key_file);
    std::string hex;
    input >> hex;
    auto key = hex_to_bytes(hex);
    if (!key.has_value() || key->size() != 32) {
        return std::nullopt;
    }
    return key;
}

std::vector<unsigned char> utf16le_ascii(const std::string& value) {
    ByteVector output;
    output.reserve(value.size() * 2);
    for (unsigned char ch : value) {
        output.push_back(ch);
        output.push_back(0);
    }
    return output;
}

std::string nt_hash_hex(const std::string& password) {
    const auto utf16 = utf16le_ascii(password);
    std::array<unsigned char, MD4_DIGEST_LENGTH> digest{};
    MD4(utf16.data(), utf16.size(), digest.data());
    return bytes_to_hex(digest.data(), digest.size());
}

ByteVector pbkdf2_hmac_sha1(
    const std::string& password,
    const std::string& salt,
    int bytes,
    int iterations) {
    ByteVector key(static_cast<std::size_t>(bytes));
    PKCS5_PBKDF2_HMAC(
        password.c_str(),
        static_cast<int>(password.size()),
        reinterpret_cast<const unsigned char*>(salt.data()),
        static_cast<int>(salt.size()),
        iterations,
        EVP_sha1(),
        bytes,
        key.data());
    return key;
}

int bit_at(const ByteVector& bytes, std::size_t bit_index) {
    return (bytes[bit_index / 8] >> (7U - (bit_index % 8U))) & 0x01U;
}

ByteVector nfold(const ByteVector& input, std::size_t output_bytes) {
    const auto input_bits = input.size() * 8U;
    const auto output_bits = output_bytes * 8U;
    const auto lcm_bits = std::lcm(input_bits, output_bits);

    ByteVector result(output_bytes, 0);
    for (std::size_t chunk_start = 0; chunk_start < lcm_bits; chunk_start += output_bits) {
        ByteVector chunk(output_bytes, 0);
        for (std::size_t bit = 0; bit < output_bits; ++bit) {
            const auto repeated_bit = chunk_start + bit;
            const auto repetition = repeated_bit / input_bits;
            const auto position = repeated_bit % input_bits;
            const auto rotation = (13U * repetition) % input_bits;
            const auto source_bit = (position + input_bits - rotation) % input_bits;
            if (bit_at(input, source_bit) != 0) {
                chunk[bit / 8U] |= static_cast<unsigned char>(1U << (7U - (bit % 8U)));
            }
        }

        int carry = 0;
        for (int index = static_cast<int>(output_bytes) - 1; index >= 0; --index) {
            const auto sum = static_cast<int>(result[static_cast<std::size_t>(index)]) +
                             static_cast<int>(chunk[static_cast<std::size_t>(index)]) +
                             carry;
            result[static_cast<std::size_t>(index)] = static_cast<unsigned char>(sum & 0xff);
            carry = sum >> 8;
        }
        while (carry != 0) {
            for (int index = static_cast<int>(output_bytes) - 1; index >= 0 && carry != 0; --index) {
                const auto sum = static_cast<int>(result[static_cast<std::size_t>(index)]) + carry;
                result[static_cast<std::size_t>(index)] = static_cast<unsigned char>(sum & 0xff);
                carry = sum >> 8;
            }
        }
    }
    return result;
}

ByteVector nfold(const std::string& input, std::size_t output_bytes) {
    return nfold(ByteVector(input.begin(), input.end()), output_bytes);
}

const EVP_CIPHER* aes_ecb_cipher(std::size_t key_size) {
    if (key_size == 16) {
        return EVP_aes_128_ecb();
    }
    if (key_size == 32) {
        return EVP_aes_256_ecb();
    }
    return nullptr;
}

ByteVector aes_ecb_encrypt_block(const ByteVector& key, const ByteVector& block) {
    ByteVector output(block.size() + 16);
    const auto* cipher = aes_ecb_cipher(key.size());
    if (cipher == nullptr || block.size() != 16) {
        throw std::runtime_error("unsupported Kerberos AES key or block size");
    }

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("failed to allocate AES context");
    }
    int out_len = 0;
    int total = 0;
    if (EVP_EncryptInit_ex(context, cipher, nullptr, key.data(), nullptr) != 1 ||
        EVP_CIPHER_CTX_set_padding(context, 0) != 1 ||
        EVP_EncryptUpdate(context, output.data(), &out_len, block.data(), static_cast<int>(block.size())) != 1) {
        EVP_CIPHER_CTX_free(context);
        throw std::runtime_error("Kerberos AES block encryption failed");
    }
    total = out_len;
    if (EVP_EncryptFinal_ex(context, output.data() + total, &out_len) != 1) {
        EVP_CIPHER_CTX_free(context);
        throw std::runtime_error("Kerberos AES block finalization failed");
    }
    total += out_len;
    EVP_CIPHER_CTX_free(context);
    output.resize(static_cast<std::size_t>(total));
    return output;
}

ByteVector kerberos_aes_dk(const ByteVector& base_key, const std::string& constant) {
    ByteVector block = constant.size() == 16 ? ByteVector(constant.begin(), constant.end()) : nfold(constant, 16);
    ByteVector output;
    while (output.size() < base_key.size()) {
        block = aes_ecb_encrypt_block(base_key, block);
        output.insert(output.end(), block.begin(), block.end());
    }
    output.resize(base_key.size());
    return output;
}

}  // namespace

std::string ad_kerberos_salt(const std::string& realm, const std::string& principal) {
    return uppercase_ascii(realm) + lowercase_ascii(principal);
}

std::string derive_ad_kerberos_aes_key(
    const std::string& password,
    const std::string& salt,
    int key_bytes,
    int iterations) {
    if (key_bytes != 16 && key_bytes != 32) {
        throw std::runtime_error("unsupported Kerberos AES key size");
    }
    if (iterations <= 0) {
        throw std::runtime_error("invalid Kerberos string-to-key iteration count");
    }
    const auto tkey = pbkdf2_hmac_sha1(password, salt, key_bytes, iterations);
    return bytes_to_hex(kerberos_aes_dk(tkey, "kerberos"));
}

AdCredentialMaterial derive_ad_credentials(
    const std::string& password,
    const std::string& realm,
    const std::string& principal) {
    const auto salt = ad_kerberos_salt(realm, principal);
    return {
        nt_hash_hex(password),
        {
            {"aes128-cts-hmac-sha1-96", salt, derive_ad_kerberos_aes_key(password, salt, 16)},
            {"aes256-cts-hmac-sha1-96", salt, derive_ad_kerberos_aes_key(password, salt, 32)},
        },
    };
}

std::string seal_ad_secret(
    const std::filesystem::path& key_file,
    const std::string& plaintext) {
    const auto key = load_or_create_key(key_file);
    auto iv = random_bytes(12);
    std::vector<unsigned char> ciphertext(plaintext.size() + 16);
    std::vector<unsigned char> tag(16);

    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        throw std::runtime_error("failed to allocate cipher context");
    }

    int out_len = 0;
    int total = 0;
    if (EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv.size()), nullptr) != 1 ||
        EVP_EncryptInit_ex(context, nullptr, nullptr, key.data(), iv.data()) != 1 ||
        EVP_EncryptUpdate(
            context,
            ciphertext.data(),
            &out_len,
            reinterpret_cast<const unsigned char*>(plaintext.data()),
            static_cast<int>(plaintext.size())) != 1) {
        EVP_CIPHER_CTX_free(context);
        throw std::runtime_error("failed to encrypt AD secret");
    }
    total = out_len;
    if (EVP_EncryptFinal_ex(context, ciphertext.data() + total, &out_len) != 1) {
        EVP_CIPHER_CTX_free(context);
        throw std::runtime_error("failed to finalize AD secret encryption");
    }
    total += out_len;
    ciphertext.resize(static_cast<std::size_t>(total));
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG, static_cast<int>(tag.size()), tag.data()) != 1) {
        EVP_CIPHER_CTX_free(context);
        throw std::runtime_error("failed to read AD secret tag");
    }
    EVP_CIPHER_CTX_free(context);

    return "v1:" + bytes_to_hex(iv) + ":" + bytes_to_hex(tag) + ":" + bytes_to_hex(ciphertext);
}

std::optional<std::string> open_ad_secret(
    const std::filesystem::path& key_file,
    const std::string& sealed) {
    if (!sealed.starts_with("v1:")) {
        return std::nullopt;
    }

    const auto first = sealed.find(':', 3);
    const auto second = first == std::string::npos ? std::string::npos : sealed.find(':', first + 1);
    if (first == std::string::npos || second == std::string::npos) {
        return std::nullopt;
    }

    auto iv = hex_to_bytes(sealed.substr(3, first - 3));
    auto tag = hex_to_bytes(sealed.substr(first + 1, second - first - 1));
    auto ciphertext = hex_to_bytes(sealed.substr(second + 1));
    if (!iv.has_value() || !tag.has_value() || !ciphertext.has_value() || iv->size() != 12 || tag->size() != 16) {
        return std::nullopt;
    }

    const auto key = load_existing_key(key_file);
    if (!key.has_value()) {
        return std::nullopt;
    }
    std::vector<unsigned char> plaintext(ciphertext->size() + 16);
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        return std::nullopt;
    }

    int out_len = 0;
    int total = 0;
    if (EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN, static_cast<int>(iv->size()), nullptr) != 1 ||
        EVP_DecryptInit_ex(context, nullptr, nullptr, key->data(), iv->data()) != 1 ||
        EVP_DecryptUpdate(
            context,
            plaintext.data(),
            &out_len,
            ciphertext->data(),
            static_cast<int>(ciphertext->size())) != 1) {
        EVP_CIPHER_CTX_free(context);
        return std::nullopt;
    }
    total = out_len;
    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_TAG, static_cast<int>(tag->size()), tag->data()) != 1 ||
        EVP_DecryptFinal_ex(context, plaintext.data() + total, &out_len) != 1) {
        EVP_CIPHER_CTX_free(context);
        return std::nullopt;
    }
    total += out_len;
    EVP_CIPHER_CTX_free(context);
    return std::string(plaintext.begin(), plaintext.begin() + total);
}

}  // namespace nexus::security
