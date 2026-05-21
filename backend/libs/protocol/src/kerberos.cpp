#include "nexus/protocol/kerberos.hpp"

#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/hmac.h>
#include <openssl/params.h>
#include <openssl/rand.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstring>
#include <ctime>
#include <iomanip>
#include <numeric>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <utility>

namespace nexus::protocol {

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr int kdc_err_preauth_required = 25;
constexpr int kdc_err_preauth_failed = 24;
constexpr int kdc_err_c_principal_unknown = 6;
constexpr int kdc_err_etype_nosupp = 14;
constexpr int krb_ap_err_msg_type = 40;
constexpr int pa_enc_timestamp = 2;
constexpr int pa_etype_info2 = 19;
constexpr int pa_enc_timestamp_key_usage = 1;
constexpr std::size_t aes_block_size = 16;
constexpr std::size_t hmac_sha1_96_size = 12;

struct Asn1Node {
    std::uint8_t tag{0};
    std::size_t content_offset{0};
    std::size_t content_length{0};
    std::size_t next_offset{0};
};

void append_length(Bytes& output, std::size_t length) {
    if (length < 0x80) {
        output.push_back(static_cast<std::uint8_t>(length));
        return;
    }
    if (length <= 0xff) {
        output.push_back(0x81);
        output.push_back(static_cast<std::uint8_t>(length));
        return;
    }
    output.push_back(0x82);
    output.push_back(static_cast<std::uint8_t>((length >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(length & 0xffU));
}

Bytes tlv(std::uint8_t tag, const Bytes& payload) {
    Bytes output{tag};
    append_length(output, payload.size());
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

void append_tlv(Bytes& output, std::uint8_t tag, const Bytes& payload) {
    const auto encoded = tlv(tag, payload);
    output.insert(output.end(), encoded.begin(), encoded.end());
}

Bytes integer_value(int value) {
    if (value >= 0 && value <= 127) {
        return {static_cast<std::uint8_t>(value)};
    }

    Bytes encoded;
    bool started = false;
    for (int shift = 24; shift >= 0; shift -= 8) {
        const auto byte = static_cast<std::uint8_t>((value >> shift) & 0xff);
        if (byte != 0 || started || shift == 0) {
            encoded.push_back(byte);
            started = true;
        }
    }
    if (!encoded.empty() && (encoded.front() & 0x80U) != 0) {
        encoded.insert(encoded.begin(), 0);
    }
    return encoded;
}

Bytes integer_tlv(int value) {
    return tlv(0x02, integer_value(value));
}

Bytes kerberos_string(const std::string& value) {
    return tlv(0x1b, Bytes(value.begin(), value.end()));
}

Bytes octet_string(const Bytes& value) {
    return tlv(0x04, value);
}

Bytes generalized_time_now() {
    const auto now = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    std::tm utc{};
    gmtime_r(&now, &utc);
    std::ostringstream output;
    output << std::put_time(&utc, "%Y%m%d%H%M%SZ");
    const auto text = output.str();
    return tlv(0x18, Bytes(text.begin(), text.end()));
}

Bytes context(std::uint8_t index, const Bytes& payload) {
    return tlv(static_cast<std::uint8_t>(0xa0U + index), payload);
}

Bytes principal_name(const std::string& primary, const std::string& instance) {
    Bytes name_strings;
    const auto primary_encoded = kerberos_string(primary);
    name_strings.insert(name_strings.end(), primary_encoded.begin(), primary_encoded.end());
    if (!instance.empty()) {
        const auto instance_encoded = kerberos_string(instance);
        name_strings.insert(name_strings.end(), instance_encoded.begin(), instance_encoded.end());
    }

    Bytes sequence_payload;
    append_tlv(sequence_payload, 0xa0, integer_tlv(instance.empty() ? 1 : 2));
    append_tlv(sequence_payload, 0xa1, tlv(0x30, name_strings));
    return tlv(0x30, sequence_payload);
}

std::string uppercase_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

std::uint32_t read_u32(const Bytes& input, std::size_t offset) {
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
           (static_cast<std::uint32_t>(input[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 2]) << 8U) |
           static_cast<std::uint32_t>(input[offset + 3]);
}

void write_u32_be(Bytes& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

bool read_length(const Bytes& input, std::size_t& offset, std::size_t& length) {
    if (offset >= input.size()) {
        return false;
    }
    const auto first = input[offset++];
    if ((first & 0x80U) == 0) {
        length = first;
        return true;
    }
    const auto bytes = first & 0x7fU;
    if (bytes == 0 || bytes > 4 || offset + bytes > input.size()) {
        return false;
    }
    length = 0;
    for (std::uint8_t index = 0; index < bytes; ++index) {
        length = (length << 8U) | input[offset++];
    }
    return true;
}

std::optional<Asn1Node> read_node(const Bytes& input, std::size_t offset, std::size_t limit) {
    if (offset >= limit || offset >= input.size()) {
        return std::nullopt;
    }
    Asn1Node node;
    node.tag = input[offset++];
    if (!read_length(input, offset, node.content_length)) {
        return std::nullopt;
    }
    node.content_offset = offset;
    node.next_offset = offset + node.content_length;
    if (node.next_offset > limit || node.next_offset > input.size()) {
        return std::nullopt;
    }
    return node;
}

std::optional<Asn1Node> first_child(const Bytes& input, const Asn1Node& parent) {
    return read_node(input, parent.content_offset, parent.content_offset + parent.content_length);
}

std::optional<Asn1Node> find_child(const Bytes& input, const Asn1Node& parent, std::uint8_t tag) {
    std::size_t offset = parent.content_offset;
    const auto limit = parent.content_offset + parent.content_length;
    while (offset < limit) {
        auto child = read_node(input, offset, limit);
        if (!child.has_value()) {
            return std::nullopt;
        }
        if (child->tag == tag) {
            return child;
        }
        offset = child->next_offset;
    }
    return std::nullopt;
}

int integer_from_content(const Bytes& input, const Asn1Node& node) {
    int value = 0;
    for (std::size_t offset = node.content_offset; offset < node.content_offset + node.content_length; ++offset) {
        value = (value << 8U) | input[offset];
    }
    return value;
}

std::optional<int> context_integer(const Bytes& input, const Asn1Node& context_node) {
    auto inner = first_child(input, context_node);
    if (!inner.has_value() || inner->tag != 0x02) {
        return std::nullopt;
    }
    return integer_from_content(input, *inner);
}

std::optional<std::string> context_string(const Bytes& input, const Asn1Node& context_node) {
    auto inner = first_child(input, context_node);
    if (!inner.has_value() || (inner->tag != 0x1b && inner->tag != 0x1c)) {
        return std::nullopt;
    }
    return std::string(
        input.begin() + static_cast<std::ptrdiff_t>(inner->content_offset),
        input.begin() + static_cast<std::ptrdiff_t>(inner->content_offset + inner->content_length));
}

std::optional<std::string> context_principal(const Bytes& input, const Asn1Node& context_node) {
    auto principal_sequence = first_child(input, context_node);
    if (!principal_sequence.has_value() || principal_sequence->tag != 0x30) {
        return std::nullopt;
    }
    auto name_string_context = find_child(input, *principal_sequence, 0xa1);
    if (!name_string_context.has_value()) {
        return std::nullopt;
    }
    auto name_strings = first_child(input, *name_string_context);
    if (!name_strings.has_value() || name_strings->tag != 0x30) {
        return std::nullopt;
    }

    std::vector<std::string> parts;
    std::size_t offset = name_strings->content_offset;
    const auto limit = name_strings->content_offset + name_strings->content_length;
    while (offset < limit) {
        auto part = read_node(input, offset, limit);
        if (!part.has_value()) {
            return std::nullopt;
        }
        if (part->tag == 0x1b || part->tag == 0x1c) {
            parts.emplace_back(
                input.begin() + static_cast<std::ptrdiff_t>(part->content_offset),
                input.begin() + static_cast<std::ptrdiff_t>(part->content_offset + part->content_length));
        }
        offset = part->next_offset;
    }

    std::string principal;
    for (const auto& part : parts) {
        if (!principal.empty()) {
            principal += "/";
        }
        principal += part;
    }
    return principal;
}

std::vector<int> context_integer_sequence(const Bytes& input, const Asn1Node& context_node) {
    std::vector<int> values;
    auto sequence = first_child(input, context_node);
    if (!sequence.has_value() || sequence->tag != 0x30) {
        return values;
    }

    std::size_t offset = sequence->content_offset;
    const auto limit = sequence->content_offset + sequence->content_length;
    while (offset < limit) {
        auto child = read_node(input, offset, limit);
        if (!child.has_value()) {
            return values;
        }
        if (child->tag == 0x02) {
            values.push_back(integer_from_content(input, *child));
        }
        offset = child->next_offset;
    }
    return values;
}

std::vector<int> context_padata_types(const Bytes& input, const Asn1Node& context_node) {
    std::vector<int> types;
    auto padata_sequence = first_child(input, context_node);
    if (!padata_sequence.has_value() || padata_sequence->tag != 0x30) {
        return types;
    }

    std::size_t offset = padata_sequence->content_offset;
    const auto limit = padata_sequence->content_offset + padata_sequence->content_length;
    while (offset < limit) {
        auto pa_data = read_node(input, offset, limit);
        if (!pa_data.has_value()) {
            return types;
        }
        if (pa_data->tag == 0x30) {
            if (auto type_context = find_child(input, *pa_data, 0xa1)) {
                if (auto type = context_integer(input, *type_context)) {
                    types.push_back(*type);
                }
            }
        }
        offset = pa_data->next_offset;
    }
    return types;
}

std::optional<int> encrypted_data_etype(const Bytes& encoded) {
    auto sequence = read_node(encoded, 0, encoded.size());
    if (!sequence.has_value() || sequence->tag != 0x30) {
        return std::nullopt;
    }
    auto etype_context = find_child(encoded, *sequence, 0xa0);
    if (!etype_context.has_value()) {
        return std::nullopt;
    }
    return context_integer(encoded, *etype_context);
}

std::optional<KerberosEncryptedData> encrypted_data_from_der(const Bytes& encoded) {
    auto sequence = read_node(encoded, 0, encoded.size());
    if (!sequence.has_value() || sequence->tag != 0x30) {
        return std::nullopt;
    }
    auto etype_context = find_child(encoded, *sequence, 0xa0);
    auto cipher_context = find_child(encoded, *sequence, 0xa2);
    if (!etype_context.has_value() || !cipher_context.has_value()) {
        return std::nullopt;
    }
    auto etype = context_integer(encoded, *etype_context);
    auto cipher = first_child(encoded, *cipher_context);
    if (!etype.has_value() || !cipher.has_value() || cipher->tag != 0x04) {
        return std::nullopt;
    }
    return KerberosEncryptedData{
        *etype,
        Bytes(
            encoded.begin() + static_cast<std::ptrdiff_t>(cipher->content_offset),
            encoded.begin() + static_cast<std::ptrdiff_t>(cipher->content_offset + cipher->content_length)),
    };
}

void read_padata(const Bytes& input, const Asn1Node& context_node, KerberosRequestInfo& parsed) {
    auto padata_sequence = first_child(input, context_node);
    if (!padata_sequence.has_value() || padata_sequence->tag != 0x30) {
        return;
    }

    std::size_t offset = padata_sequence->content_offset;
    const auto limit = padata_sequence->content_offset + padata_sequence->content_length;
    while (offset < limit) {
        auto pa_data = read_node(input, offset, limit);
        if (!pa_data.has_value()) {
            return;
        }
        if (pa_data->tag == 0x30) {
            int type = 0;
            if (auto type_context = find_child(input, *pa_data, 0xa1)) {
                if (auto parsed_type = context_integer(input, *type_context)) {
                    type = *parsed_type;
                    parsed.padata_types.push_back(type);
                }
            }

            if (type == pa_enc_timestamp) {
                if (auto value_context = find_child(input, *pa_data, 0xa2)) {
                    if (auto octets = first_child(input, *value_context); octets.has_value() && octets->tag == 0x04) {
                        Bytes encrypted_data(
                            input.begin() + static_cast<std::ptrdiff_t>(octets->content_offset),
                            input.begin() + static_cast<std::ptrdiff_t>(octets->content_offset + octets->content_length));
                        if (auto etype = encrypted_data_etype(encrypted_data)) {
                            parsed.encrypted_timestamp_etypes.push_back(*etype);
                        }
                        if (auto encrypted_timestamp = encrypted_data_from_der(encrypted_data)) {
                            parsed.encrypted_timestamps.push_back(*encrypted_timestamp);
                        }
                    }
                }
            }
        }
        offset = pa_data->next_offset;
    }
}

void write_u32(Bytes& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

int request_message_type(const Bytes& request) {
    if (request.empty()) {
        return 0;
    }
    if (request.front() == 0x6a) {
        return 10;
    }
    if (request.front() == 0x6c) {
        return 12;
    }
    return 0;
}

std::string lowercase_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

bool principal_matches(
    const KerberosPrincipal& principal,
    const KerberosRequestInfo& request,
    const KerberosRealmInfo& realm_info) {
    const auto request_realm = uppercase_ascii(request.realm.empty() ? realm_info.realm : request.realm);
    const auto principal_realm = uppercase_ascii(principal.realm.empty() ? realm_info.realm : principal.realm);
    if (request_realm != principal_realm) {
        return false;
    }

    const auto requested = lowercase_ascii(request.client_principal);
    const auto candidate = lowercase_ascii(principal.principal);
    if (requested == candidate) {
        return true;
    }
    return requested + "@" + lowercase_ascii(request_realm) == candidate;
}

std::optional<KerberosPrincipal> find_principal(
    const KerberosRealmInfo& realm_info,
    const KerberosRequestInfo& request) {
    for (const auto& principal : realm_info.principals) {
        if (principal_matches(principal, request, realm_info)) {
            return principal;
        }
    }
    return std::nullopt;
}

int enctype_from_name(const std::string& name) {
    const auto normalized = lowercase_ascii(name);
    if (normalized == "aes256-cts-hmac-sha1-96") {
        return 18;
    }
    if (normalized == "aes128-cts-hmac-sha1-96") {
        return 17;
    }
    return 0;
}

std::vector<KerberosKey> usable_keys(const KerberosPrincipal& principal) {
    std::vector<KerberosKey> keys;
    for (auto key : principal.keys) {
        if (key.enctype == 0) {
            key.enctype = enctype_from_name(key.enctype_name);
        }
        if (key.enctype != 0 && !key.key_hex.empty()) {
            keys.push_back(std::move(key));
        }
    }
    return keys;
}

bool has_key_for_etype(const KerberosPrincipal& principal, int enctype) {
    const auto keys = usable_keys(principal);
    return std::any_of(keys.begin(), keys.end(), [&](const auto& key) {
        return key.enctype == enctype;
    });
}

std::optional<KerberosKey> key_for_etype(const KerberosPrincipal& principal, int enctype) {
    for (const auto& key : usable_keys(principal)) {
        if (key.enctype == enctype) {
            return key;
        }
    }
    return std::nullopt;
}

std::optional<Bytes> hex_to_bytes(const std::string& hex) {
    if (hex.size() % 2 != 0) {
        return std::nullopt;
    }
    Bytes bytes;
    bytes.reserve(hex.size() / 2);
    for (std::size_t offset = 0; offset < hex.size(); offset += 2) {
        try {
            bytes.push_back(static_cast<std::uint8_t>(std::stoul(hex.substr(offset, 2), nullptr, 16)));
        } catch (...) {
            return std::nullopt;
        }
    }
    return bytes;
}

Bytes random_bytes(std::size_t size) {
    Bytes bytes(size);
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return bytes;
}

int bit_at(const Bytes& bytes, std::size_t bit_index) {
    return (bytes[bit_index / 8] >> (7U - (bit_index % 8U))) & 0x01U;
}

Bytes nfold(const Bytes& input, std::size_t output_bytes) {
    const auto input_bits = input.size() * 8U;
    const auto output_bits = output_bytes * 8U;
    const auto lcm_bits = std::lcm(input_bits, output_bits);

    Bytes result(output_bytes, 0);
    for (std::size_t chunk_start = 0; chunk_start < lcm_bits; chunk_start += output_bits) {
        Bytes chunk(output_bytes, 0);
        for (std::size_t bit = 0; bit < output_bits; ++bit) {
            const auto repeated_bit = chunk_start + bit;
            const auto repetition = repeated_bit / input_bits;
            const auto position = repeated_bit % input_bits;
            const auto rotation = (13U * repetition) % input_bits;
            const auto source_bit = (position + input_bits - rotation) % input_bits;
            if (bit_at(input, source_bit) != 0) {
                chunk[bit / 8U] |= static_cast<std::uint8_t>(1U << (7U - (bit % 8U)));
            }
        }

        int carry = 0;
        for (int index = static_cast<int>(output_bytes) - 1; index >= 0; --index) {
            const auto sum = static_cast<int>(result[static_cast<std::size_t>(index)]) +
                             static_cast<int>(chunk[static_cast<std::size_t>(index)]) +
                             carry;
            result[static_cast<std::size_t>(index)] = static_cast<std::uint8_t>(sum & 0xff);
            carry = sum >> 8;
        }
        while (carry != 0) {
            for (int index = static_cast<int>(output_bytes) - 1; index >= 0 && carry != 0; --index) {
                const auto sum = static_cast<int>(result[static_cast<std::size_t>(index)]) + carry;
                result[static_cast<std::size_t>(index)] = static_cast<std::uint8_t>(sum & 0xff);
                carry = sum >> 8;
            }
        }
    }
    return result;
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

Bytes aes_ecb_encrypt_block(const Bytes& key, const Bytes& block) {
    const auto* cipher = aes_ecb_cipher(key.size());
    if (cipher == nullptr || block.size() != aes_block_size) {
        throw std::runtime_error("unsupported Kerberos AES key or block size");
    }

    Bytes output(block.size() + aes_block_size);
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

Bytes kerberos_dk(const Bytes& base_key, const Bytes& constant) {
    Bytes block = constant.size() == aes_block_size ? constant : nfold(constant, aes_block_size);
    Bytes output;
    while (output.size() < base_key.size()) {
        block = aes_ecb_encrypt_block(base_key, block);
        output.insert(output.end(), block.begin(), block.end());
    }
    output.resize(base_key.size());
    return output;
}

Bytes key_usage_constant(int key_usage, std::uint8_t seed) {
    Bytes constant;
    write_u32_be(constant, static_cast<std::uint32_t>(key_usage));
    constant.push_back(seed);
    return constant;
}

Bytes kerberos_hmac_sha1_96(const Bytes& key, const Bytes& payload) {
    unsigned int digest_size = 0;
    const auto* digest = HMAC(
        EVP_sha1(),
        key.data(),
        static_cast<int>(key.size()),
        payload.data(),
        payload.size(),
        nullptr,
        &digest_size);
    if (digest == nullptr || digest_size < hmac_sha1_96_size) {
        throw std::runtime_error("Kerberos HMAC-SHA1 failed");
    }
    return Bytes(digest, digest + hmac_sha1_96_size);
}

Bytes aes_cts_crypt(const Bytes& key, const Bytes& input, bool encrypt) {
    if (input.size() < aes_block_size) {
        throw std::runtime_error("Kerberos AES-CTS payload is too short");
    }

    const char* cipher_name = key.size() == 16 ? "AES-128-CBC-CTS" : key.size() == 32 ? "AES-256-CBC-CTS" : nullptr;
    if (cipher_name == nullptr) {
        throw std::runtime_error("unsupported Kerberos AES key size");
    }

    EVP_CIPHER* cipher = EVP_CIPHER_fetch(nullptr, cipher_name, nullptr);
    if (cipher == nullptr) {
        throw std::runtime_error("AES-CBC-CTS cipher is unavailable");
    }

    Bytes output(input.size() + aes_block_size);
    Bytes iv(aes_block_size, 0);
    EVP_CIPHER_CTX* context = EVP_CIPHER_CTX_new();
    if (context == nullptr) {
        EVP_CIPHER_free(cipher);
        throw std::runtime_error("failed to allocate AES-CTS context");
    }

    int out_len = 0;
    int total = 0;
    char cts_mode[] = OSSL_CIPHER_CTS_MODE_CS3;
    OSSL_PARAM params[] = {
        OSSL_PARAM_construct_utf8_string(OSSL_CIPHER_PARAM_CTS_MODE, cts_mode, 0),
        OSSL_PARAM_construct_end(),
    };

    const int init_ok = encrypt != 0
        ? EVP_EncryptInit_ex(context, cipher, nullptr, key.data(), iv.data())
        : EVP_DecryptInit_ex(context, cipher, nullptr, key.data(), iv.data());
    const int update_ok = init_ok == 1 &&
                          EVP_CIPHER_CTX_set_params(context, params) == 1 &&
                          EVP_CIPHER_CTX_set_padding(context, 0) == 1 &&
                          (encrypt != 0
                               ? EVP_EncryptUpdate(context, output.data(), &out_len, input.data(), static_cast<int>(input.size()))
                               : EVP_DecryptUpdate(context, output.data(), &out_len, input.data(), static_cast<int>(input.size()))) == 1;
    if (!update_ok) {
        EVP_CIPHER_CTX_free(context);
        EVP_CIPHER_free(cipher);
        throw std::runtime_error("Kerberos AES-CTS update failed");
    }
    total = out_len;
    const int final_ok = encrypt != 0
        ? EVP_EncryptFinal_ex(context, output.data() + total, &out_len)
        : EVP_DecryptFinal_ex(context, output.data() + total, &out_len);
    if (final_ok != 1) {
        EVP_CIPHER_CTX_free(context);
        EVP_CIPHER_free(cipher);
        throw std::runtime_error("Kerberos AES-CTS finalization failed");
    }
    total += out_len;
    EVP_CIPHER_CTX_free(context);
    EVP_CIPHER_free(cipher);
    output.resize(static_cast<std::size_t>(total));
    return output;
}

std::optional<Bytes> kerberos_decrypt_aes_cts_hmac_sha1(
    const Bytes& ciphertext,
    const std::string& key_hex,
    int key_usage) {
    auto base_key = hex_to_bytes(key_hex);
    if (!base_key.has_value() || (base_key->size() != 16 && base_key->size() != 32) || ciphertext.size() <= hmac_sha1_96_size) {
        return std::nullopt;
    }

    try {
        const auto ke = kerberos_dk(*base_key, key_usage_constant(key_usage, 0xaa));
        const auto ki = kerberos_dk(*base_key, key_usage_constant(key_usage, 0x55));
        const Bytes encrypted(ciphertext.begin(), ciphertext.end() - static_cast<std::ptrdiff_t>(hmac_sha1_96_size));
        const Bytes checksum(ciphertext.end() - static_cast<std::ptrdiff_t>(hmac_sha1_96_size), ciphertext.end());
        const auto plaintext_with_confounder = aes_cts_crypt(ke, encrypted, false);
        const auto expected_checksum = kerberos_hmac_sha1_96(ki, plaintext_with_confounder);
        if (CRYPTO_memcmp(checksum.data(), expected_checksum.data(), hmac_sha1_96_size) != 0) {
            return std::nullopt;
        }
        if (plaintext_with_confounder.size() <= aes_block_size) {
            return std::nullopt;
        }
        return Bytes(plaintext_with_confounder.begin() + static_cast<std::ptrdiff_t>(aes_block_size), plaintext_with_confounder.end());
    } catch (...) {
        return std::nullopt;
    }
}

bool valid_encrypted_timestamp_plaintext(const Bytes& plaintext) {
    auto sequence = read_node(plaintext, 0, plaintext.size());
    if (!sequence.has_value() || sequence->tag != 0x30) {
        return false;
    }
    auto timestamp_context = find_child(plaintext, *sequence, 0xa0);
    if (!timestamp_context.has_value()) {
        return false;
    }
    auto timestamp = first_child(plaintext, *timestamp_context);
    return timestamp.has_value() && timestamp->tag == 0x18 && timestamp->content_length >= 15;
}

bool validate_encrypted_timestamp(const KerberosPrincipal& principal, const KerberosEncryptedData& encrypted_timestamp) {
    const auto key = key_for_etype(principal, encrypted_timestamp.enctype);
    if (!key.has_value()) {
        return false;
    }
    const auto plaintext = kerberos_decrypt_aes_cts_hmac_sha1(
        encrypted_timestamp.cipher,
        key->key_hex,
        pa_enc_timestamp_key_usage);
    return plaintext.has_value() && valid_encrypted_timestamp_plaintext(*plaintext);
}

Bytes etype_info2_entry(int enctype, const std::string& salt) {
    Bytes payload;
    append_tlv(payload, 0xa0, integer_tlv(enctype));
    append_tlv(payload, 0xa1, kerberos_string(salt));
    return tlv(0x30, payload);
}

Bytes etype_info2(const std::vector<int>& requested_etypes, const KerberosPrincipal* principal, const std::string& fallback_salt) {
    std::vector<KerberosKey> keys;
    if (principal != nullptr) {
        keys = usable_keys(*principal);
    }
    if (keys.empty()) {
        keys = {
            {18, "aes256-cts-hmac-sha1-96", fallback_salt, ""},
            {17, "aes128-cts-hmac-sha1-96", fallback_salt, ""},
        };
    }

    const auto has_etype = [&](int enctype) {
        return std::find(requested_etypes.begin(), requested_etypes.end(), enctype) != requested_etypes.end();
    };

    Bytes entries;
    for (const auto& key : keys) {
        if (!requested_etypes.empty() && !has_etype(key.enctype)) {
            continue;
        }
        const auto entry = etype_info2_entry(key.enctype, key.salt.empty() ? fallback_salt : key.salt);
        entries.insert(entries.end(), entry.begin(), entry.end());
    }
    if (entries.empty() && !keys.empty()) {
        const auto entry = etype_info2_entry(keys.front().enctype, keys.front().salt.empty() ? fallback_salt : keys.front().salt);
        entries.insert(entries.end(), entry.begin(), entry.end());
    }
    return tlv(0x30, entries);
}

Bytes pa_data(int type, const Bytes& value) {
    Bytes payload;
    append_tlv(payload, 0xa1, integer_tlv(type));
    append_tlv(payload, 0xa2, octet_string(value));
    return tlv(0x30, payload);
}

Bytes method_data(const std::vector<Bytes>& entries) {
    Bytes payload;
    for (const auto& entry : entries) {
        payload.insert(payload.end(), entry.begin(), entry.end());
    }
    return tlv(0x30, payload);
}

Bytes preauth_method_data(const KerberosRealmInfo& realm_info, const KerberosRequestInfo& request, const KerberosPrincipal* principal) {
    const auto realm = uppercase_ascii(request.realm.empty() ? realm_info.realm : request.realm);
    const auto salt = realm + lowercase_ascii(request.client_principal);
    return method_data({pa_data(pa_etype_info2, etype_info2(request.requested_etypes, principal, salt))});
}

bool has_padata_type(const KerberosRequestInfo& request, int type) {
    return std::find(request.padata_types.begin(), request.padata_types.end(), type) != request.padata_types.end();
}

Bytes krb_error(const KerberosRealmInfo& realm_info, int error_code, const std::string& error_text, const Bytes& e_data = {}) {
    const auto realm = uppercase_ascii(realm_info.realm.empty() ? "ENDORIUM.LOCAL" : realm_info.realm);
    const auto kdc_name = realm_info.kdc_name.empty() ? "krbtgt" : realm_info.kdc_name;

    Bytes sequence_payload;
    append_tlv(sequence_payload, 0xa0, integer_tlv(5));
    append_tlv(sequence_payload, 0xa1, integer_tlv(30));
    append_tlv(sequence_payload, 0xa4, generalized_time_now());
    append_tlv(sequence_payload, 0xa5, integer_tlv(0));
    append_tlv(sequence_payload, 0xa6, integer_tlv(error_code));
    append_tlv(sequence_payload, 0xa9, kerberos_string(realm));
    append_tlv(sequence_payload, 0xaa, principal_name(kdc_name, realm));
    if (!error_text.empty()) {
        append_tlv(sequence_payload, 0xab, kerberos_string(error_text));
    }
    if (!e_data.empty()) {
        append_tlv(sequence_payload, 0xac, octet_string(e_data));
    }

    return tlv(0x7e, tlv(0x30, sequence_payload));
}

}  // namespace

std::vector<std::uint8_t> kerberos_encrypt_aes_cts_hmac_sha1(
    const std::vector<std::uint8_t>& plaintext,
    const std::string& key_hex,
    int key_usage,
    const std::vector<std::uint8_t>& confounder) {
    auto base_key = hex_to_bytes(key_hex);
    if (!base_key.has_value() || (base_key->size() != 16 && base_key->size() != 32)) {
        throw std::runtime_error("invalid Kerberos AES key");
    }

    Bytes plaintext_with_confounder = confounder.empty() ? random_bytes(aes_block_size) : Bytes(confounder.begin(), confounder.end());
    if (plaintext_with_confounder.size() != aes_block_size) {
        throw std::runtime_error("Kerberos AES confounder must be 16 bytes");
    }
    plaintext_with_confounder.insert(plaintext_with_confounder.end(), plaintext.begin(), plaintext.end());

    const auto ke = kerberos_dk(*base_key, key_usage_constant(key_usage, 0xaa));
    const auto ki = kerberos_dk(*base_key, key_usage_constant(key_usage, 0x55));
    auto ciphertext = aes_cts_crypt(ke, plaintext_with_confounder, true);
    const auto checksum = kerberos_hmac_sha1_96(ki, plaintext_with_confounder);
    ciphertext.insert(ciphertext.end(), checksum.begin(), checksum.end());
    return ciphertext;
}

KerberosRequestInfo parse_kerberos_request(const std::vector<std::uint8_t>& request) {
    KerberosRequestInfo parsed;
    auto application = read_node(request, 0, request.size());
    if (!application.has_value() || (application->tag != 0x6a && application->tag != 0x6c)) {
        return parsed;
    }
    parsed.message_type = application->tag == 0x6a ? 10 : 12;

    auto kdc_req = first_child(request, *application);
    if (!kdc_req.has_value() || kdc_req->tag != 0x30) {
        return parsed;
    }

    if (auto msg_type_context = find_child(request, *kdc_req, 0xa2)) {
        if (auto msg_type = context_integer(request, *msg_type_context)) {
            parsed.message_type = *msg_type;
        }
    }
    if (auto padata_context = find_child(request, *kdc_req, 0xa3)) {
        parsed.has_padata = true;
        read_padata(request, *padata_context, parsed);
    }

    auto req_body_context = find_child(request, *kdc_req, 0xa4);
    if (!req_body_context.has_value()) {
        return parsed;
    }
    auto req_body = first_child(request, *req_body_context);
    if (!req_body.has_value() || req_body->tag != 0x30) {
        return parsed;
    }

    if (auto cname_context = find_child(request, *req_body, 0xa1)) {
        if (auto cname = context_principal(request, *cname_context)) {
            parsed.client_principal = *cname;
        }
    }
    if (auto realm_context = find_child(request, *req_body, 0xa2)) {
        if (auto realm = context_string(request, *realm_context)) {
            parsed.realm = *realm;
        }
    }
    if (auto etype_context = find_child(request, *req_body, 0xa8)) {
        parsed.requested_etypes = context_integer_sequence(request, *etype_context);
    }

    parsed.valid = true;
    return parsed;
}

std::vector<std::uint8_t> kerberos_error_response(
    const std::vector<std::uint8_t>& request,
    const KerberosRealmInfo& realm) {
    const auto parsed = parse_kerberos_request(request);
    const auto request_type = parsed.valid ? parsed.message_type : request_message_type(request);
    if (request_type == 10) {
        std::optional<KerberosPrincipal> principal;
        if (parsed.valid && !parsed.client_principal.empty()) {
            principal = find_principal(realm, parsed);
            if (!principal.has_value() || !principal->has_key_material) {
                return krb_error(realm, kdc_err_c_principal_unknown, "client principal unknown or missing key material");
            }
        }
        if (!parsed.has_padata || !has_padata_type(parsed, pa_enc_timestamp)) {
            return krb_error(
                realm,
                kdc_err_preauth_required,
                "pre-authentication required",
                parsed.valid ? preauth_method_data(realm, parsed, principal.has_value() ? &*principal : nullptr) : Bytes{});
        }
        if (principal.has_value()) {
            if (parsed.encrypted_timestamps.empty()) {
                return krb_error(realm, kdc_err_preauth_failed, "encrypted timestamp padata is malformed");
            }
            const auto& encrypted_timestamp = parsed.encrypted_timestamps.front();
            if (!has_key_for_etype(*principal, encrypted_timestamp.enctype)) {
                return krb_error(realm, kdc_err_etype_nosupp, "encrypted timestamp etype is not available for this principal");
            }
            if (!validate_encrypted_timestamp(*principal, encrypted_timestamp)) {
                return krb_error(realm, kdc_err_preauth_failed, "encrypted timestamp validation failed");
            }
        }
        return krb_error(realm, kdc_err_preauth_failed, "AS-REP/TGT issuance is not implemented yet");
    }
    if (request_type == 12) {
        return krb_error(realm, kdc_err_preauth_required, "ticket granting is waiting for AS support");
    }
    return krb_error(realm, krb_ap_err_msg_type, "unsupported Kerberos message");
}

std::vector<std::uint8_t> kerberos_tcp_error_response(
    const std::vector<std::uint8_t>& frame,
    const KerberosRealmInfo& realm) {
    if (frame.size() < 4) {
        return {};
    }

    const auto payload_size = read_u32(frame, 0);
    if (payload_size == 0 || frame.size() < static_cast<std::size_t>(payload_size) + 4) {
        return {};
    }

    Bytes payload(frame.begin() + 4, frame.begin() + 4 + payload_size);
    auto response = kerberos_error_response(payload, realm);
    if (response.empty()) {
        return {};
    }

    Bytes framed;
    write_u32(framed, static_cast<std::uint32_t>(response.size()));
    framed.insert(framed.end(), response.begin(), response.end());
    return framed;
}

}  // namespace nexus::protocol
