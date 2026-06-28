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
#include <string_view>
#include <utility>

namespace nexus::protocol {

namespace {

using Bytes = std::vector<std::uint8_t>;

constexpr int kdc_err_preauth_required = 25;
constexpr int kdc_err_preauth_failed = 24;
constexpr int kdc_err_c_principal_unknown = 6;
constexpr int kdc_err_s_principal_unknown = 7;
constexpr int kdc_err_etype_nosupp = 14;
constexpr int kdc_err_client_revoked = 18;
constexpr int kdc_err_service_revoked = 19;
constexpr int kdc_err_svc_unavailable = 29;
constexpr int krb_ap_err_msg_type = 40;
constexpr int pa_tgs_req = 1;
constexpr int pa_enc_timestamp = 2;
constexpr int pa_etype_info2 = 19;
constexpr int pa_enc_timestamp_key_usage = 1;
constexpr int ticket_key_usage = 2;
constexpr int as_rep_encrypted_part_key_usage = 3;
constexpr int tgs_req_authenticator_key_usage = 7;
constexpr int tgs_rep_encrypted_part_key_usage = 8;
constexpr int ap_req_authenticator_key_usage = 11;
constexpr int ap_rep_encrypted_part_key_usage = 12;
constexpr int krb_priv_encrypted_part_key_usage = 13;
constexpr std::uint32_t ap_option_mutual_required = 0x20000000U;
constexpr std::size_t aes_block_size = 16;
constexpr std::size_t hmac_sha1_96_size = 12;

struct Asn1Node {
    std::uint8_t tag{0};
    std::size_t tag_offset{0};
    std::size_t content_offset{0};
    std::size_t content_length{0};
    std::size_t next_offset{0};
};

struct TicketSession {
    std::string client_principal;
    std::string realm;
    int key_enctype{0};
    Bytes key_value;
};

struct ApReqInfo {
    bool valid{false};
    std::uint32_t ap_options{0};
    std::string ticket_realm;
    std::string ticket_sname;
    KerberosEncryptedData ticket_enc_part;
    KerberosEncryptedData authenticator;
};

struct AuthenticatorInfo {
    bool valid{false};
    std::int64_t cusec{0};
    std::string ctime;
    int subkey_enctype{0};
    Bytes subkey_value;
};

struct PasswordChangeData {
    std::string new_password;
    std::string target_principal;
    std::string target_realm;
};

Bytes encrypted_data(int enctype, const Bytes& cipher);

struct PacBuffer {
    std::uint32_t type{0};
    Bytes data;
};

struct PacIdentity {
    std::string principal;
    std::string realm;
    std::string display_name;
    std::string object_sid;
    std::uint32_t rid{0};
    std::uint32_t primary_group_rid{513};
    std::vector<std::uint32_t> group_rids;
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

Bytes bit_string(std::uint32_t flags) {
    return tlv(0x03, {
        0x00,
        static_cast<std::uint8_t>((flags >> 24U) & 0xffU),
        static_cast<std::uint8_t>((flags >> 16U) & 0xffU),
        static_cast<std::uint8_t>((flags >> 8U) & 0xffU),
        static_cast<std::uint8_t>(flags & 0xffU),
    });
}

Bytes generalized_time(std::chrono::system_clock::time_point time) {
    const auto now = std::chrono::system_clock::to_time_t(time);
    std::tm utc{};
    gmtime_r(&now, &utc);
    std::ostringstream output;
    output << std::put_time(&utc, "%Y%m%d%H%M%SZ");
    const auto text = output.str();
    return tlv(0x18, Bytes(text.begin(), text.end()));
}

Bytes generalized_time(const std::string& value) {
    return tlv(0x18, Bytes(value.begin(), value.end()));
}

Bytes generalized_time_now() {
    return generalized_time(std::chrono::system_clock::now());
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

std::vector<std::string> split_principal_components(const std::string& principal) {
    std::vector<std::string> parts;
    std::size_t start = 0;
    while (start <= principal.size()) {
        const auto slash = principal.find('/', start);
        const auto part = principal.substr(start, slash == std::string::npos ? std::string::npos : slash - start);
        if (!part.empty()) {
            parts.push_back(part);
        }
        if (slash == std::string::npos) {
            break;
        }
        start = slash + 1;
    }
    return parts;
}

Bytes principal_name_from_string(const std::string& principal) {
    const auto parts = split_principal_components(principal);
    if (parts.empty()) {
        return principal_name(principal, "");
    }

    Bytes name_strings;
    for (const auto& part : parts) {
        const auto encoded = kerberos_string(part);
        name_strings.insert(name_strings.end(), encoded.begin(), encoded.end());
    }

    Bytes sequence_payload;
    append_tlv(sequence_payload, 0xa0, integer_tlv(parts.size() > 1 ? 2 : 1));
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

std::uint16_t read_u16_be(const Bytes& input, std::size_t offset) {
    return static_cast<std::uint16_t>((input[offset] << 8U) | input[offset + 1]);
}

void write_u16_be(Bytes& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void write_u32_be(Bytes& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
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
    for (int shift = 0; shift <= 56; shift += 8) {
        output.push_back(static_cast<std::uint8_t>((value >> shift) & 0xffU));
    }
}

std::size_t align_to_8(std::size_t value) {
    return (value + 7U) & ~std::size_t{7U};
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
    node.tag_offset = offset;
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

Bytes node_der(const Bytes& input, const Asn1Node& node) {
    return Bytes(
        input.begin() + static_cast<std::ptrdiff_t>(node.tag_offset),
        input.begin() + static_cast<std::ptrdiff_t>(node.next_offset));
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

std::optional<std::uint32_t> context_bit_string(const Bytes& input, const Asn1Node& context_node) {
    auto inner = first_child(input, context_node);
    if (!inner.has_value() || inner->tag != 0x03 || inner->content_length < 2) {
        return std::nullopt;
    }
    std::uint32_t value = 0;
    for (std::size_t offset = inner->content_offset + 1; offset < inner->content_offset + inner->content_length; ++offset) {
        value = (value << 8U) | input[offset];
    }
    return value;
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

std::optional<Bytes> context_octet_string(const Bytes& input, const Asn1Node& context_node) {
    auto inner = first_child(input, context_node);
    if (!inner.has_value() || inner->tag != 0x04) {
        return std::nullopt;
    }
    return Bytes(
        input.begin() + static_cast<std::ptrdiff_t>(inner->content_offset),
        input.begin() + static_cast<std::ptrdiff_t>(inner->content_offset + inner->content_length));
}

std::optional<std::string> context_generalized_time(const Bytes& input, const Asn1Node& context_node) {
    auto inner = first_child(input, context_node);
    if (!inner.has_value() || inner->tag != 0x18) {
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

std::optional<KerberosEncryptedData> encrypted_data_from_context(const Bytes& input, const Asn1Node& context_node) {
    auto sequence = first_child(input, context_node);
    if (!sequence.has_value() || sequence->tag != 0x30) {
        return std::nullopt;
    }
    return encrypted_data_from_der(node_der(input, *sequence));
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

            if (auto value_context = find_child(input, *pa_data, 0xa2)) {
                if (auto octets = first_child(input, *value_context); octets.has_value() && octets->tag == 0x04) {
                    Bytes padata_value(
                        input.begin() + static_cast<std::ptrdiff_t>(octets->content_offset),
                        input.begin() + static_cast<std::ptrdiff_t>(octets->content_offset + octets->content_length));
                    if (type == pa_enc_timestamp) {
                        if (auto etype = encrypted_data_etype(padata_value)) {
                            parsed.encrypted_timestamp_etypes.push_back(*etype);
                        }
                        if (auto encrypted_timestamp = encrypted_data_from_der(padata_value)) {
                            parsed.encrypted_timestamps.push_back(*encrypted_timestamp);
                        }
                    } else if (type == pa_tgs_req) {
                        parsed.tgs_ap_req = std::move(padata_value);
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

bool equals_ascii_case(const std::string& left, const std::string& right) {
    return lowercase_ascii(left) == lowercase_ascii(right);
}

std::string trim_trailing_dot(std::string value) {
    if (!value.empty() && value.back() == '.') {
        value.pop_back();
    }
    return value;
}

std::string normalized_principal_lookup_key(std::string principal, const std::string& realm) {
    principal = lowercase_ascii(trim_trailing_dot(std::move(principal)));
    const auto normalized_realm = lowercase_ascii(trim_trailing_dot(realm));
    const auto at_realm = "@" + normalized_realm;
    if (!normalized_realm.empty() && principal.ends_with(at_realm)) {
        principal = principal.substr(0, principal.size() - at_realm.size());
        principal = trim_trailing_dot(principal);
    }
    if (!normalized_realm.empty() && principal == "krbtgt/" + normalized_realm) {
        return "krbtgt";
    }
    return principal;
}

std::vector<std::string> principal_lookup_keys(const std::string& principal, const std::string& realm) {
    std::vector<std::string> keys;
    const auto add = [&](const std::string& value) {
        if (!value.empty() && std::find(keys.begin(), keys.end(), value) == keys.end()) {
            keys.push_back(value);
        }
    };

    add(normalized_principal_lookup_key(principal, realm));
    add(lowercase_ascii(trim_trailing_dot(principal)));
    return keys;
}

bool principal_name_matches(const std::string& left, const std::string& right, const std::string& realm) {
    const auto left_keys = principal_lookup_keys(left, realm);
    const auto right_keys = principal_lookup_keys(right, realm);
    return std::any_of(left_keys.begin(), left_keys.end(), [&](const auto& left_key) {
        return std::find(right_keys.begin(), right_keys.end(), left_key) != right_keys.end();
    });
}

bool principal_account_disabled(const KerberosPrincipal& principal) {
    constexpr std::uint32_t user_account_control_accountdisable = 0x00000002U;
    return (principal.user_account_control & user_account_control_accountdisable) != 0;
}

std::optional<std::string> principal_account_blocking_reason(const KerberosPrincipal& principal) {
    if (principal_account_disabled(principal)) {
        return "principal account is disabled";
    }
    if (principal.account_expired) {
        return "principal account is expired";
    }
    return std::nullopt;
}

std::uint32_t stable_hash32(const std::string& value) {
    std::uint32_t hash = 2166136261U;
    for (const unsigned char ch : value) {
        hash ^= ch;
        hash *= 16777619U;
    }
    return hash;
}

std::string netbios_from_realm(const std::string& realm) {
    const auto dot = realm.find('.');
    auto value = uppercase_ascii(dot == std::string::npos ? realm : realm.substr(0, dot));
    value.erase(std::remove_if(value.begin(), value.end(), [](unsigned char ch) {
        return !std::isalnum(ch) && ch != '-';
    }), value.end());
    return value.empty() ? "ENDORIUM" : value;
}

std::string synthetic_domain_sid(const std::string& realm) {
    const auto lower = lowercase_ascii(realm);
    const auto a = 1000U + (stable_hash32(lower + ":a") % 1000000000U);
    const auto b = 1000U + (stable_hash32(lower + ":b") % 1000000000U);
    const auto c = 1000U + (stable_hash32(lower + ":c") % 1000000000U);
    return "S-1-5-21-" + std::to_string(a) + "-" + std::to_string(b) + "-" + std::to_string(c);
}

std::uint32_t synthetic_rid(const std::string& principal) {
    const auto normalized = lowercase_ascii(principal);
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

std::uint32_t rid_from_sid(const std::string& sid) {
    const auto dash = sid.find_last_of('-');
    if (dash == std::string::npos || dash + 1 >= sid.size()) {
        return 0;
    }
    try {
        return static_cast<std::uint32_t>(std::stoul(sid.substr(dash + 1)));
    } catch (...) {
        return 0;
    }
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

    return principal_name_matches(request.client_principal, principal.principal, request_realm);
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

std::optional<KerberosPrincipal> find_principal_by_name(
    const KerberosRealmInfo& realm_info,
    const std::string& name) {
    for (const auto& principal : realm_info.principals) {
        if (principal_name_matches(name, principal.principal, realm_info.realm)) {
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

std::string bytes_to_hex(const Bytes& bytes) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto byte : bytes) {
        output << std::setw(2) << static_cast<int>(byte);
    }
    return output.str();
}

Bytes random_bytes(std::size_t size) {
    Bytes bytes(size);
    if (RAND_bytes(bytes.data(), static_cast<int>(bytes.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }
    return bytes;
}

Bytes utf16le_ascii(const std::string& value) {
    Bytes output;
    output.reserve(value.size() * 2U);
    for (const unsigned char ch : value) {
        output.push_back(ch);
        output.push_back(0);
    }
    return output;
}

std::vector<std::uint32_t> sid_subauthorities(const std::string& sid) {
    constexpr std::string_view prefix{"S-1-5-"};
    if (!sid.starts_with(prefix)) {
        return {};
    }
    std::vector<std::uint32_t> values;
    std::size_t start = prefix.size();
    while (start < sid.size()) {
        const auto dash = sid.find('-', start);
        const auto part = sid.substr(start, dash == std::string::npos ? std::string::npos : dash - start);
        try {
            values.push_back(static_cast<std::uint32_t>(std::stoul(part)));
        } catch (...) {
            return {};
        }
        if (dash == std::string::npos) {
            break;
        }
        start = dash + 1;
    }
    return values;
}

Bytes ndr_sid(const std::string& sid) {
    const auto subauthorities = sid_subauthorities(sid);
    if (subauthorities.empty() || subauthorities.size() > 15) {
        return {};
    }

    Bytes output;
    write_u32_le(output, static_cast<std::uint32_t>(subauthorities.size()));
    output.push_back(1);
    output.push_back(static_cast<std::uint8_t>(subauthorities.size()));
    output.insert(output.end(), {0, 0, 0, 0, 0, 5});
    for (const auto subauthority : subauthorities) {
        write_u32_le(output, subauthority);
    }
    output.resize(align_to_8(output.size()), 0);
    return output;
}

std::uint64_t windows_filetime(std::chrono::system_clock::time_point time) {
    constexpr std::uint64_t unix_epoch_filetime_seconds = 11644473600ULL;
    const auto duration = time.time_since_epoch();
    const auto seconds = std::chrono::duration_cast<std::chrono::seconds>(duration).count();
    const auto ticks = std::chrono::duration_cast<std::chrono::nanoseconds>(duration - std::chrono::seconds(seconds)).count() / 100;
    return (static_cast<std::uint64_t>(seconds) + unix_epoch_filetime_seconds) * 10000000ULL +
           static_cast<std::uint64_t>(ticks);
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

std::optional<Bytes> kerberos_checksum_aes_hmac_sha1_96(
    const std::string& key_hex,
    int key_usage,
    const Bytes& payload) {
    auto base_key = hex_to_bytes(key_hex);
    if (!base_key.has_value() || (base_key->size() != 16 && base_key->size() != 32)) {
        return std::nullopt;
    }
    try {
        const auto ki = kerberos_dk(*base_key, key_usage_constant(key_usage, 0x99));
        return kerberos_hmac_sha1_96(ki, payload);
    } catch (...) {
        return std::nullopt;
    }
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

std::optional<std::pair<int, Bytes>> encryption_key_from_context(const Bytes& input, const Asn1Node& context_node) {
    auto sequence = first_child(input, context_node);
    if (!sequence.has_value() || sequence->tag != 0x30) {
        return std::nullopt;
    }
    auto enctype_context = find_child(input, *sequence, 0xa0);
    auto value_context = find_child(input, *sequence, 0xa1);
    if (!enctype_context.has_value() || !value_context.has_value()) {
        return std::nullopt;
    }
    auto enctype = context_integer(input, *enctype_context);
    auto value = first_child(input, *value_context);
    if (!enctype.has_value() || !value.has_value() || value->tag != 0x04) {
        return std::nullopt;
    }
    return std::make_pair(
        *enctype,
        Bytes(
            input.begin() + static_cast<std::ptrdiff_t>(value->content_offset),
            input.begin() + static_cast<std::ptrdiff_t>(value->content_offset + value->content_length)));
}

std::optional<TicketSession> parse_enc_ticket_part(const Bytes& plaintext) {
    auto application = read_node(plaintext, 0, plaintext.size());
    if (!application.has_value() || application->tag != 0x63) {
        return std::nullopt;
    }
    auto sequence = first_child(plaintext, *application);
    if (!sequence.has_value() || sequence->tag != 0x30) {
        return std::nullopt;
    }

    auto key_context = find_child(plaintext, *sequence, 0xa1);
    auto realm_context = find_child(plaintext, *sequence, 0xa2);
    auto cname_context = find_child(plaintext, *sequence, 0xa3);
    if (!key_context.has_value() || !realm_context.has_value() || !cname_context.has_value()) {
        return std::nullopt;
    }
    auto key = encryption_key_from_context(plaintext, *key_context);
    auto realm = context_string(plaintext, *realm_context);
    auto cname = context_principal(plaintext, *cname_context);
    if (!key.has_value() || !realm.has_value() || !cname.has_value()) {
        return std::nullopt;
    }

    return TicketSession{
        *cname,
        *realm,
        key->first,
        key->second,
    };
}

std::optional<ApReqInfo> parse_ap_req(const Bytes& ap_req) {
    auto application = read_node(ap_req, 0, ap_req.size());
    if (!application.has_value() || application->tag != 0x6e) {
        return std::nullopt;
    }
    auto sequence = first_child(ap_req, *application);
    if (!sequence.has_value() || sequence->tag != 0x30) {
        return std::nullopt;
    }

    auto options_context = find_child(ap_req, *sequence, 0xa2);
    auto ticket_context = find_child(ap_req, *sequence, 0xa3);
    auto authenticator_context = find_child(ap_req, *sequence, 0xa4);
    if (!ticket_context.has_value() || !authenticator_context.has_value()) {
        return std::nullopt;
    }
    auto ticket_application = first_child(ap_req, *ticket_context);
    if (!ticket_application.has_value() || ticket_application->tag != 0x61) {
        return std::nullopt;
    }
    auto ticket_sequence = first_child(ap_req, *ticket_application);
    if (!ticket_sequence.has_value() || ticket_sequence->tag != 0x30) {
        return std::nullopt;
    }

    auto realm_context = find_child(ap_req, *ticket_sequence, 0xa1);
    auto sname_context = find_child(ap_req, *ticket_sequence, 0xa2);
    auto enc_part_context = find_child(ap_req, *ticket_sequence, 0xa3);
    auto realm = realm_context.has_value() ? context_string(ap_req, *realm_context) : std::nullopt;
    auto sname = sname_context.has_value() ? context_principal(ap_req, *sname_context) : std::nullopt;
    auto ticket_enc_part = enc_part_context.has_value() ? encrypted_data_from_context(ap_req, *enc_part_context) : std::nullopt;
    auto authenticator = encrypted_data_from_context(ap_req, *authenticator_context);
    if (!realm.has_value() || !sname.has_value() || !ticket_enc_part.has_value() || !authenticator.has_value()) {
        return std::nullopt;
    }

    return ApReqInfo{
        true,
        options_context.has_value() ? context_bit_string(ap_req, *options_context).value_or(0) : 0,
        *realm,
        *sname,
        *ticket_enc_part,
        *authenticator,
    };
}

bool validate_tgs_authenticator(const KerberosEncryptedData& authenticator, const TicketSession& session) {
    if (authenticator.enctype != session.key_enctype) {
        return false;
    }
    const auto plaintext = kerberos_decrypt_aes_cts_hmac_sha1(
        authenticator.cipher,
        bytes_to_hex(session.key_value),
        tgs_req_authenticator_key_usage);
    if (!plaintext.has_value()) {
        return false;
    }
    auto application = read_node(*plaintext, 0, plaintext->size());
    return application.has_value() && application->tag == 0x62;
}

bool validate_ap_req_authenticator(const KerberosEncryptedData& authenticator, const TicketSession& session) {
    if (authenticator.enctype != session.key_enctype) {
        return false;
    }
    const auto plaintext = kerberos_decrypt_aes_cts_hmac_sha1(
        authenticator.cipher,
        bytes_to_hex(session.key_value),
        ap_req_authenticator_key_usage);
    if (!plaintext.has_value()) {
        return false;
    }
    auto application = read_node(*plaintext, 0, plaintext->size());
    return application.has_value() && application->tag == 0x62;
}

std::optional<AuthenticatorInfo> parse_ap_req_authenticator(
    const KerberosEncryptedData& authenticator,
    const TicketSession& session) {
    if (authenticator.enctype != session.key_enctype) {
        return std::nullopt;
    }
    const auto plaintext = kerberos_decrypt_aes_cts_hmac_sha1(
        authenticator.cipher,
        bytes_to_hex(session.key_value),
        ap_req_authenticator_key_usage);
    if (!plaintext.has_value()) {
        return std::nullopt;
    }
    auto application = read_node(*plaintext, 0, plaintext->size());
    if (!application.has_value() || application->tag != 0x62) {
        return std::nullopt;
    }
    auto sequence = first_child(*plaintext, *application);
    if (!sequence.has_value() || sequence->tag != 0x30) {
        return std::nullopt;
    }
    auto cusec_context = find_child(*plaintext, *sequence, 0xa4);
    auto ctime_context = find_child(*plaintext, *sequence, 0xa5);
    auto subkey_context = find_child(*plaintext, *sequence, 0xa6);
    auto cusec = cusec_context.has_value() ? context_integer(*plaintext, *cusec_context) : std::optional<int>{};
    auto ctime = ctime_context.has_value() ? context_generalized_time(*plaintext, *ctime_context) : std::optional<std::string>{};
    if (!cusec.has_value() || !ctime.has_value()) {
        return std::nullopt;
    }
    int subkey_enctype = 0;
    Bytes subkey_value;
    if (subkey_context.has_value()) {
        if (auto subkey = encryption_key_from_context(*plaintext, *subkey_context)) {
            subkey_enctype = subkey->first;
            subkey_value = std::move(subkey->second);
        }
    }
    return AuthenticatorInfo{true, *cusec, *ctime, subkey_enctype, std::move(subkey_value)};
}

int key_size_for_enctype(int enctype);
Bytes encryption_key(int enctype, const Bytes& key_value);

Bytes ap_rep_enc_part(
    const AuthenticatorInfo& authenticator,
    int subkey_enctype,
    const Bytes& subkey,
    std::uint32_t seq_number) {
    Bytes payload;
    append_tlv(payload, 0xa0, generalized_time(authenticator.ctime));
    append_tlv(payload, 0xa1, integer_tlv(static_cast<int>(authenticator.cusec)));
    // The acceptor subkey [2] and seq-number [3] establish the GSS-API context key.
    // Windows' SSPI uses this acceptor subkey to derive the SMB signing key; without
    // it the AP-REP is rejected with SEC_E_INVALID_TOKEN and the domain join fails.
    append_tlv(payload, 0xa2, encryption_key(subkey_enctype, subkey));
    append_tlv(payload, 0xa3, integer_tlv(static_cast<int>(seq_number)));
    return tlv(0x7b, tlv(0x30, payload));
}

Bytes ap_rep_token(
    const TicketSession& session,
    const AuthenticatorInfo& authenticator,
    int& out_subkey_enctype,
    Bytes& out_subkey) {
    out_subkey_enctype = session.key_enctype;
    const auto subkey_size = key_size_for_enctype(session.key_enctype);
    out_subkey = random_bytes(subkey_size > 0 ? static_cast<std::size_t>(subkey_size) : session.key_value.size());
    const auto seq_bytes = random_bytes(4);
    const std::uint32_t seq_number =
        (static_cast<std::uint32_t>(seq_bytes[0]) << 16U | static_cast<std::uint32_t>(seq_bytes[1]) << 8U |
         static_cast<std::uint32_t>(seq_bytes[2])) &
        0x7fffffffU;
    const auto encrypted = kerberos_encrypt_aes_cts_hmac_sha1(
        ap_rep_enc_part(authenticator, out_subkey_enctype, out_subkey, seq_number),
        bytes_to_hex(session.key_value),
        ap_rep_encrypted_part_key_usage);

    Bytes payload;
    append_tlv(payload, 0xa0, integer_tlv(5));
    append_tlv(payload, 0xa1, integer_tlv(15));
    append_tlv(payload, 0xa2, encrypted_data(session.key_enctype, encrypted));
    return tlv(0x6f, tlv(0x30, payload));
}

int pac_checksum_type(int enctype) {
    if (enctype == 18) {
        return 16;
    }
    if (enctype == 17) {
        return 15;
    }
    return 0;
}

Bytes pac_signature_data(int enctype, const Bytes& signature = {}) {
    Bytes output;
    write_u32_le(output, static_cast<std::uint32_t>(pac_checksum_type(enctype)));
    output.resize(4 + hmac_sha1_96_size, 0);
    for (std::size_t index = 0; index < std::min(signature.size(), hmac_sha1_96_size); ++index) {
        output[4 + index] = signature[index];
    }
    return output;
}

Bytes pac_client_info(const std::string& client_principal, std::chrono::system_clock::time_point now) {
    const auto name = utf16le_ascii(client_principal);
    Bytes output;
    write_u64_le(output, windows_filetime(now));
    write_u16_le(output, static_cast<std::uint16_t>(name.size()));
    output.insert(output.end(), name.begin(), name.end());
    return output;
}

Bytes pac_upn_dns_info(const std::string& client_principal, const std::string& realm) {
    const auto upn = utf16le_ascii(client_principal + "@" + lowercase_ascii(realm));
    const auto dns = utf16le_ascii(lowercase_ascii(realm));
    constexpr std::uint16_t header_size = 12;

    Bytes output;
    write_u16_le(output, static_cast<std::uint16_t>(upn.size()));
    write_u16_le(output, header_size);
    write_u16_le(output, static_cast<std::uint16_t>(dns.size()));
    write_u16_le(output, static_cast<std::uint16_t>(header_size + upn.size()));
    write_u32_le(output, 0);
    output.insert(output.end(), upn.begin(), upn.end());
    output.insert(output.end(), dns.begin(), dns.end());
    return output;
}

PacIdentity pac_identity_for(
    const std::string& client_principal,
    const std::string& realm,
    const KerberosPrincipal* principal) {
    const auto normalized_realm = uppercase_ascii(realm);
    const auto fallback_rid = synthetic_rid(client_principal);
    PacIdentity identity;
    identity.principal = client_principal;
    identity.realm = normalized_realm;
    identity.display_name = client_principal;
    identity.rid = fallback_rid;
    identity.primary_group_rid = 513;
    identity.group_rids = {513};
    identity.object_sid = synthetic_domain_sid(normalized_realm) + "-" + std::to_string(fallback_rid);

    if (principal != nullptr) {
        identity.display_name = principal->display_name.empty() ? identity.display_name : principal->display_name;
        identity.object_sid = principal->object_sid.empty() ? identity.object_sid : principal->object_sid;
        identity.rid = principal->rid != 0 ? principal->rid : rid_from_sid(identity.object_sid);
        if (identity.rid == 0) {
            identity.rid = fallback_rid;
        }
        identity.primary_group_rid = principal->primary_group_rid != 0 ? principal->primary_group_rid : identity.primary_group_rid;
        if (!principal->group_rids.empty()) {
            identity.group_rids = principal->group_rids;
        }
    }

    if (std::find(identity.group_rids.begin(), identity.group_rids.end(), identity.primary_group_rid) == identity.group_rids.end()) {
        identity.group_rids.push_back(identity.primary_group_rid);
    }
    return identity;
}

class NdrBuilder {
  public:
    void write_u16(std::uint16_t value) {
        write_u16_le(fixed_, value);
    }

    void write_u32(std::uint32_t value) {
        write_u32_le(fixed_, value);
    }

    void write_u64(std::uint64_t value) {
        write_u64_le(fixed_, value);
    }

    void write_unicode_string(const std::string& value) {
        const auto encoded = utf16le_ascii(value);
        write_u16_le(fixed_, static_cast<std::uint16_t>(encoded.size()));
        write_u16_le(fixed_, static_cast<std::uint16_t>(encoded.size()));
        if (encoded.empty()) {
            write_u32_le(fixed_, 0);
            return;
        }
        write_u32_le(fixed_, next_referent_++);

        Bytes deferred;
        const auto chars = static_cast<std::uint32_t>(encoded.size() / 2U);
        write_u32_le(deferred, chars);
        write_u32_le(deferred, 0);
        write_u32_le(deferred, chars);
        deferred.insert(deferred.end(), encoded.begin(), encoded.end());
        deferred.resize(align_to_8(deferred.size()), 0);
        deferred_.push_back(std::move(deferred));
    }

    void write_pointer(const Bytes& deferred) {
        if (deferred.empty()) {
            write_u32_le(fixed_, 0);
            return;
        }
        write_u32_le(fixed_, next_referent_++);
        auto aligned = deferred;
        aligned.resize(align_to_8(aligned.size()), 0);
        deferred_.push_back(std::move(aligned));
    }

    Bytes finish() const {
        Bytes output = fixed_;
        output.resize(align_to_8(output.size()), 0);
        for (const auto& deferred : deferred_) {
            output.insert(output.end(), deferred.begin(), deferred.end());
        }
        return output;
    }

  private:
    Bytes fixed_;
    std::uint32_t next_referent_{0x00020000};
    std::vector<Bytes> deferred_;
};

Bytes group_membership_array(const std::vector<std::uint32_t>& group_rids) {
    Bytes output;
    write_u32_le(output, static_cast<std::uint32_t>(group_rids.size()));
    for (const auto rid : group_rids) {
        write_u32_le(output, rid);
        write_u32_le(output, 0x00000007U);
    }
    return output;
}

Bytes pac_logon_info(const PacIdentity& identity, std::chrono::system_clock::time_point now) {
    constexpr std::uint64_t never_filetime = 0x7fffffffffffffffULL;
    const auto logon_time = windows_filetime(now);
    const auto domain = netbios_from_realm(identity.realm);
    const auto domain_sid = identity.object_sid.substr(0, identity.object_sid.find_last_of('-'));

    NdrBuilder ndr;
    ndr.write_u64(logon_time);
    ndr.write_u64(never_filetime);
    ndr.write_u64(never_filetime);
    ndr.write_u64(logon_time);
    ndr.write_u64(0);
    ndr.write_u64(never_filetime);
    ndr.write_unicode_string(identity.principal);
    ndr.write_unicode_string(identity.display_name);
    ndr.write_unicode_string("");
    ndr.write_unicode_string("");
    ndr.write_unicode_string("");
    ndr.write_unicode_string("");
    ndr.write_u16(0);
    ndr.write_u16(0);
    ndr.write_u32(identity.rid);
    ndr.write_u32(identity.primary_group_rid);
    ndr.write_u32(static_cast<std::uint32_t>(identity.group_rids.size()));
    ndr.write_pointer(group_membership_array(identity.group_rids));
    ndr.write_u32(0);
    for (int index = 0; index < 4; ++index) {
        ndr.write_u32(0);
    }
    ndr.write_unicode_string("NEXUS");
    ndr.write_unicode_string(domain);
    ndr.write_pointer(ndr_sid(domain_sid));
    ndr.write_u32(0);
    ndr.write_u32(0);
    ndr.write_u32(0x00000200U);
    ndr.write_u32(0);
    ndr.write_u64(0);
    ndr.write_u64(0);
    ndr.write_u32(0);
    ndr.write_u32(0);
    ndr.write_u32(0);
    ndr.write_pointer({});
    ndr.write_pointer({});
    ndr.write_u32(0);
    ndr.write_pointer({});
    return ndr.finish();
}

Bytes pac_type(const std::vector<PacBuffer>& buffers) {
    Bytes header;
    write_u32_le(header, static_cast<std::uint32_t>(buffers.size()));
    write_u32_le(header, 0);

    const auto descriptor_size = 16U;
    std::uint64_t data_offset = align_to_8(8 + buffers.size() * descriptor_size);
    Bytes data;

    for (const auto& buffer : buffers) {
        write_u32_le(header, buffer.type);
        write_u32_le(header, static_cast<std::uint32_t>(buffer.data.size()));
        write_u64_le(header, data_offset);

        const auto aligned_current = align_to_8(data.size());
        data.resize(aligned_current, 0);
        data.insert(data.end(), buffer.data.begin(), buffer.data.end());
        data_offset += align_to_8(buffer.data.size());
    }

    header.resize(static_cast<std::size_t>(align_to_8(header.size())), 0);
    header.insert(header.end(), data.begin(), data.end());
    return header;
}

std::optional<Bytes> minimal_pac(
    const std::string& client_principal,
    const std::string& realm,
    const KerberosPrincipal* client,
    const KerberosKey& service_key,
    const KerberosKey& kdc_key,
    std::chrono::system_clock::time_point now) {
    if (pac_checksum_type(service_key.enctype) == 0 || pac_checksum_type(kdc_key.enctype) == 0) {
        return std::nullopt;
    }

    const auto identity = pac_identity_for(client_principal, realm, client);
    std::vector<PacBuffer> buffers{
        {1, pac_logon_info(identity, now)},
        {10, pac_client_info(client_principal, now)},
        {12, pac_upn_dns_info(client_principal, realm)},
        {6, pac_signature_data(service_key.enctype)},
        {7, pac_signature_data(kdc_key.enctype)},
    };

    auto pac = pac_type(buffers);
    auto server_signature = kerberos_checksum_aes_hmac_sha1_96(service_key.key_hex, 17, pac);
    if (!server_signature.has_value()) {
        return std::nullopt;
    }
    buffers[3].data = pac_signature_data(service_key.enctype, *server_signature);

    const auto server_checksum_payload = buffers[3].data;
    auto kdc_signature = kerberos_checksum_aes_hmac_sha1_96(kdc_key.key_hex, 17, server_checksum_payload);
    if (!kdc_signature.has_value()) {
        return std::nullopt;
    }
    buffers[4].data = pac_signature_data(kdc_key.enctype, *kdc_signature);
    return pac_type(buffers);
}

Bytes authorization_data_with_pac(const Bytes& pac) {
    Bytes pac_entry_payload;
    append_tlv(pac_entry_payload, 0xa0, integer_tlv(128));
    append_tlv(pac_entry_payload, 0xa1, octet_string(pac));
    const auto pac_authorization_data = tlv(0x30, tlv(0x30, pac_entry_payload));

    Bytes if_relevant_payload;
    append_tlv(if_relevant_payload, 0xa0, integer_tlv(1));
    append_tlv(if_relevant_payload, 0xa1, octet_string(pac_authorization_data));
    return tlv(0x30, tlv(0x30, if_relevant_payload));
}

int key_size_for_enctype(int enctype) {
    if (enctype == 18) {
        return 32;
    }
    if (enctype == 17) {
        return 16;
    }
    return 0;
}

Bytes encryption_key(int enctype, const Bytes& key_value) {
    Bytes payload;
    append_tlv(payload, 0xa0, integer_tlv(enctype));
    append_tlv(payload, 0xa1, octet_string(key_value));
    return tlv(0x30, payload);
}

Bytes encrypted_data(int enctype, const Bytes& cipher) {
    Bytes payload;
    append_tlv(payload, 0xa0, integer_tlv(enctype));
    append_tlv(payload, 0xa2, octet_string(cipher));
    return tlv(0x30, payload);
}

Bytes transited_encoding() {
    Bytes payload;
    append_tlv(payload, 0xa0, integer_tlv(0));
    append_tlv(payload, 0xa1, octet_string({}));
    return tlv(0x30, payload);
}

Bytes last_req() {
    Bytes entry_payload;
    append_tlv(entry_payload, 0xa0, integer_tlv(0));
    append_tlv(entry_payload, 0xa1, generalized_time_now());
    return tlv(0x30, tlv(0x30, entry_payload));
}

Bytes enc_ticket_part_for_client(
    const std::string& realm,
    const std::string& client_principal,
    int enctype,
    const Bytes& session_key,
    std::chrono::system_clock::time_point now,
    const KerberosPrincipal* client = nullptr,
    const KerberosKey* service_key = nullptr,
    const KerberosKey* kdc_key = nullptr) {
    constexpr std::uint32_t ticket_flags = 0x40e10000U;
    const auto normalized_realm = uppercase_ascii(realm);
    const auto end_time = now + std::chrono::hours(10);
    const auto renew_till = now + std::chrono::hours(24 * 7);

    Bytes payload;
    append_tlv(payload, 0xa0, bit_string(ticket_flags));
    append_tlv(payload, 0xa1, encryption_key(enctype, session_key));
    append_tlv(payload, 0xa2, kerberos_string(normalized_realm));
    append_tlv(payload, 0xa3, principal_name_from_string(client_principal));
    append_tlv(payload, 0xa4, transited_encoding());
    append_tlv(payload, 0xa5, generalized_time(now));
    append_tlv(payload, 0xa6, generalized_time(now));
    append_tlv(payload, 0xa7, generalized_time(end_time));
    append_tlv(payload, 0xa8, generalized_time(renew_till));
    if (service_key != nullptr && kdc_key != nullptr) {
        if (auto pac = minimal_pac(client_principal, normalized_realm, client, *service_key, *kdc_key, now)) {
            append_tlv(payload, 0xaa, authorization_data_with_pac(*pac));
        }
    }
    return tlv(0x63, tlv(0x30, payload));
}

Bytes enc_ticket_part(
    const KerberosRealmInfo& realm_info,
    const KerberosRequestInfo& request,
    int enctype,
    const Bytes& session_key,
    std::chrono::system_clock::time_point now) {
    return enc_ticket_part_for_client(
        request.realm.empty() ? realm_info.realm : request.realm,
        request.client_principal,
        enctype,
        session_key,
        now);
}

Bytes ticket_for_service(
    const std::string& realm,
    const std::string& service_principal,
    int enctype,
    const Bytes& encrypted_ticket_part) {
    const auto normalized_realm = uppercase_ascii(realm);

    Bytes payload;
    append_tlv(payload, 0xa0, integer_tlv(5));
    append_tlv(payload, 0xa1, kerberos_string(normalized_realm));
    append_tlv(payload, 0xa2, principal_name_from_string(service_principal));
    append_tlv(payload, 0xa3, encrypted_data(enctype, encrypted_ticket_part));
    return tlv(0x61, tlv(0x30, payload));
}

Bytes ticket(
    const KerberosRealmInfo& realm_info,
    const KerberosRequestInfo& request,
    int enctype,
    const Bytes& encrypted_ticket_part) {
    const auto realm = uppercase_ascii(request.realm.empty() ? realm_info.realm : request.realm);
    const auto kdc_name = realm_info.kdc_name.empty() ? "krbtgt" : realm_info.kdc_name;
    return ticket_for_service(realm, kdc_name + "/" + realm, enctype, encrypted_ticket_part);
}

Bytes enc_as_rep_part(
    const KerberosRealmInfo& realm_info,
    const KerberosRequestInfo& request,
    int enctype,
    const Bytes& session_key,
    std::chrono::system_clock::time_point now) {
    constexpr std::uint32_t ticket_flags = 0x40e10000U;
    const auto realm = uppercase_ascii(request.realm.empty() ? realm_info.realm : request.realm);
    const auto end_time = now + std::chrono::hours(10);
    const auto renew_till = now + std::chrono::hours(24 * 7);
    const auto kdc_name = realm_info.kdc_name.empty() ? "krbtgt" : realm_info.kdc_name;

    Bytes payload;
    append_tlv(payload, 0xa0, encryption_key(enctype, session_key));
    append_tlv(payload, 0xa1, last_req());
    append_tlv(payload, 0xa2, integer_tlv(request.nonce));
    append_tlv(payload, 0xa4, bit_string(ticket_flags));
    append_tlv(payload, 0xa5, generalized_time(now));
    append_tlv(payload, 0xa6, generalized_time(now));
    append_tlv(payload, 0xa7, generalized_time(end_time));
    append_tlv(payload, 0xa8, generalized_time(renew_till));
    append_tlv(payload, 0xa9, kerberos_string(realm));
    append_tlv(payload, 0xaa, principal_name(kdc_name, realm));
    return tlv(0x79, tlv(0x30, payload));
}

Bytes as_rep(
    const KerberosRealmInfo& realm_info,
    const KerberosRequestInfo& request,
    const KerberosPrincipal& client,
    const KerberosKey& client_key,
    const KerberosKey& krbtgt_key,
    int enctype) {
    const auto realm = uppercase_ascii(request.realm.empty() ? realm_info.realm : request.realm);
    const auto session_key_size = key_size_for_enctype(enctype);
    if (session_key_size == 0) {
        throw std::runtime_error("unsupported AS-REP enctype");
    }

    const auto client_principal = client.principal.empty() ? request.client_principal : client.principal;
    const auto now = std::chrono::system_clock::now();
    const auto session_key = random_bytes(static_cast<std::size_t>(session_key_size));
    const auto encrypted_ticket_part = kerberos_encrypt_aes_cts_hmac_sha1(
        enc_ticket_part_for_client(realm, client_principal, enctype, session_key, now, &client, &krbtgt_key, &krbtgt_key),
        krbtgt_key.key_hex,
        ticket_key_usage);
    const auto encrypted_client_part = kerberos_encrypt_aes_cts_hmac_sha1(
        enc_as_rep_part(realm_info, request, enctype, session_key, now),
        client_key.key_hex,
        as_rep_encrypted_part_key_usage);

    Bytes payload;
    append_tlv(payload, 0xa0, integer_tlv(5));
    append_tlv(payload, 0xa1, integer_tlv(11));
    append_tlv(payload, 0xa3, kerberos_string(realm));
    append_tlv(payload, 0xa4, principal_name_from_string(client_principal));
    append_tlv(payload, 0xa5, ticket(realm_info, request, enctype, encrypted_ticket_part));
    append_tlv(payload, 0xa6, encrypted_data(enctype, encrypted_client_part));
    return tlv(0x6b, tlv(0x30, payload));
}

Bytes enc_tgs_rep_part(
    const KerberosRealmInfo& realm_info,
    const KerberosRequestInfo& request,
    const std::string& service_principal,
    int service_enctype,
    const Bytes& service_session_key,
    std::chrono::system_clock::time_point now) {
    constexpr std::uint32_t ticket_flags = 0x40e10000U;
    const auto realm = uppercase_ascii(request.realm.empty() ? realm_info.realm : request.realm);
    const auto end_time = now + std::chrono::hours(10);
    const auto renew_till = now + std::chrono::hours(24 * 7);

    Bytes payload;
    append_tlv(payload, 0xa0, encryption_key(service_enctype, service_session_key));
    append_tlv(payload, 0xa1, last_req());
    append_tlv(payload, 0xa2, integer_tlv(request.nonce));
    append_tlv(payload, 0xa4, bit_string(ticket_flags));
    append_tlv(payload, 0xa5, generalized_time(now));
    append_tlv(payload, 0xa6, generalized_time(now));
    append_tlv(payload, 0xa7, generalized_time(end_time));
    append_tlv(payload, 0xa8, generalized_time(renew_till));
    append_tlv(payload, 0xa9, kerberos_string(realm));
    append_tlv(payload, 0xaa, principal_name_from_string(service_principal));
    return tlv(0x7a, tlv(0x30, payload));
}

std::optional<KerberosKey> select_service_key(const KerberosPrincipal& service, const KerberosRequestInfo& request) {
    for (const auto enctype : request.requested_etypes) {
        if (auto key = key_for_etype(service, enctype)) {
            return key;
        }
    }
    const auto keys = usable_keys(service);
    if (keys.empty()) {
        return std::nullopt;
    }
    return keys.front();
}

std::optional<int> select_as_rep_enctype(
    const KerberosRequestInfo& request,
    const KerberosPrincipal& client,
    const KerberosPrincipal& krbtgt,
    int preauth_enctype) {
    const auto usable = [&](int enctype) {
        return key_for_etype(client, enctype).has_value() &&
               key_for_etype(krbtgt, enctype).has_value();
    };

    if (!request.requested_etypes.empty()) {
        for (const auto enctype : request.requested_etypes) {
            if (usable(enctype)) {
                return enctype;
            }
        }
        return std::nullopt;
    }

    if (usable(preauth_enctype)) {
        return preauth_enctype;
    }
    for (const auto& key : usable_keys(client)) {
        if (usable(key.enctype)) {
            return key.enctype;
        }
    }
    return std::nullopt;
}

Bytes tgs_rep(
    const KerberosRealmInfo& realm_info,
    const KerberosRequestInfo& request,
    const TicketSession& tgt_session,
    const KerberosPrincipal* client,
    const std::string& service_principal,
    const KerberosKey& service_key,
    const KerberosKey& krbtgt_key,
    int service_enctype) {
    const auto realm = uppercase_ascii(request.realm.empty() ? realm_info.realm : request.realm);
    const auto session_key_size = key_size_for_enctype(service_enctype);
    if (session_key_size == 0) {
        throw std::runtime_error("unsupported TGS-REP enctype");
    }

    const auto now = std::chrono::system_clock::now();
    const auto service_session_key = random_bytes(static_cast<std::size_t>(session_key_size));
    const auto encrypted_ticket_part = kerberos_encrypt_aes_cts_hmac_sha1(
        enc_ticket_part_for_client(
            realm,
            tgt_session.client_principal,
            service_enctype,
            service_session_key,
            now,
            client,
            &service_key,
            &krbtgt_key),
        service_key.key_hex,
        ticket_key_usage);
    const auto encrypted_client_part = kerberos_encrypt_aes_cts_hmac_sha1(
        enc_tgs_rep_part(realm_info, request, service_principal, service_enctype, service_session_key, now),
        bytes_to_hex(tgt_session.key_value),
        tgs_rep_encrypted_part_key_usage);

    Bytes payload;
    append_tlv(payload, 0xa0, integer_tlv(5));
    append_tlv(payload, 0xa1, integer_tlv(13));
    append_tlv(payload, 0xa3, kerberos_string(realm));
    append_tlv(payload, 0xa4, principal_name_from_string(tgt_session.client_principal));
    append_tlv(payload, 0xa5, ticket_for_service(realm, service_principal, service_enctype, encrypted_ticket_part));
    append_tlv(payload, 0xa6, encrypted_data(tgt_session.key_enctype, encrypted_client_part));
    return tlv(0x6d, tlv(0x30, payload));
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
    // Advertise PA-ENC-TIMESTAMP (type 2) as an empty entry so that strict clients
    // (MIT kinit, the Windows domain-join Kerberos client) know they must perform
    // encrypted-timestamp pre-authentication. Without this hint they only read the
    // ETYPE-INFO2 salt and re-send the request unauthenticated, which the KDC then
    // rejects as KDC_ERR_PREAUTH_FAILED ("the username or password is incorrect").
    // (Permissive clients such as impacket send the timestamp proactively and so
    // never exposed this gap.)
    return method_data({
        pa_data(pa_enc_timestamp, {}),
        pa_data(pa_etype_info2, etype_info2(request.requested_etypes, principal, salt)),
    });
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

std::string password_from_octets(const Bytes& octets) {
    if (octets.size() >= 2 && octets.size() % 2 == 0) {
        std::size_t zero_high_bytes = 0;
        for (std::size_t offset = 1; offset < octets.size(); offset += 2) {
            if (octets[offset] == 0) {
                ++zero_high_bytes;
            }
        }
        if (zero_high_bytes * 2U >= octets.size()) {
            std::string decoded;
            decoded.reserve(octets.size() / 2U);
            for (std::size_t offset = 0; offset + 1 < octets.size(); offset += 2) {
                decoded.push_back(static_cast<char>(octets[offset]));
            }
            return decoded;
        }
    }
    return std::string(octets.begin(), octets.end());
}

std::optional<PasswordChangeData> parse_change_password_data(const Bytes& input) {
    auto sequence = read_node(input, 0, input.size());
    if (!sequence.has_value() || sequence->tag != 0x30) {
        return std::nullopt;
    }
    auto password_context = find_child(input, *sequence, 0xa0);
    if (!password_context.has_value()) {
        return std::nullopt;
    }
    auto password = context_octet_string(input, *password_context);
    if (!password.has_value() || password->empty()) {
        return std::nullopt;
    }

    PasswordChangeData data;
    data.new_password = password_from_octets(*password);
    if (auto target_context = find_child(input, *sequence, 0xa1)) {
        if (auto target = context_principal(input, *target_context)) {
            data.target_principal = *target;
        }
    }
    if (auto realm_context = find_child(input, *sequence, 0xa2)) {
        if (auto realm = context_string(input, *realm_context)) {
            data.target_realm = *realm;
        }
    }
    return data;
}

std::optional<KerberosEncryptedData> krb_priv_encrypted_data(const Bytes& input) {
    auto application = read_node(input, 0, input.size());
    if (!application.has_value() || application->tag != 0x75) {
        return std::nullopt;
    }
    auto sequence = first_child(input, *application);
    if (!sequence.has_value() || sequence->tag != 0x30) {
        return std::nullopt;
    }
    auto msg_type_context = find_child(input, *sequence, 0xa1);
    auto enc_part_context = find_child(input, *sequence, 0xa3);
    if (!msg_type_context.has_value() || !enc_part_context.has_value()) {
        return std::nullopt;
    }
    const auto msg_type = context_integer(input, *msg_type_context);
    if (!msg_type.has_value() || *msg_type != 21) {
        return std::nullopt;
    }
    return encrypted_data_from_context(input, *enc_part_context);
}

std::optional<PasswordChangeData> decrypt_kpasswd_change_data(
    const KerberosEncryptedData& encrypted,
    const Bytes& key) {
    const auto plaintext = kerberos_decrypt_aes_cts_hmac_sha1(
        encrypted.cipher,
        bytes_to_hex(key),
        krb_priv_encrypted_part_key_usage);
    if (!plaintext.has_value()) {
        return std::nullopt;
    }
    auto application = read_node(*plaintext, 0, plaintext->size());
    if (!application.has_value() || application->tag != 0x7c) {
        return std::nullopt;
    }
    auto sequence = first_child(*plaintext, *application);
    if (!sequence.has_value() || sequence->tag != 0x30) {
        return std::nullopt;
    }
    auto user_data_context = find_child(*plaintext, *sequence, 0xa0);
    if (!user_data_context.has_value()) {
        return std::nullopt;
    }
    auto user_data = context_octet_string(*plaintext, *user_data_context);
    if (!user_data.has_value()) {
        return std::nullopt;
    }
    return parse_change_password_data(*user_data);
}

Bytes enc_krb_priv_part(const Bytes& user_data) {
    Bytes payload;
    append_tlv(payload, 0xa0, octet_string(user_data));
    append_tlv(payload, 0xa1, generalized_time_now());
    append_tlv(payload, 0xa2, integer_tlv(0));
    return tlv(0x7c, tlv(0x30, payload));
}

Bytes krb_priv_message(int enctype, const Bytes& cipher) {
    Bytes payload;
    append_tlv(payload, 0xa0, integer_tlv(5));
    append_tlv(payload, 0xa1, integer_tlv(21));
    append_tlv(payload, 0xa3, encrypted_data(enctype, cipher));
    return tlv(0x75, tlv(0x30, payload));
}

Bytes kpasswd_reply(
    const KerberosPasswordChangeRequestInfo& request,
    const Bytes& ap_rep,
    const Bytes& krb_priv) {
    const auto version = request.version == 0 ? static_cast<std::uint16_t>(0xff80U) : request.version;
    const auto total_size = static_cast<std::uint16_t>(6U + ap_rep.size() + krb_priv.size());

    Bytes output;
    write_u16_be(output, total_size);
    write_u16_be(output, version);
    write_u16_be(output, static_cast<std::uint16_t>(ap_rep.size()));
    output.insert(output.end(), ap_rep.begin(), ap_rep.end());
    output.insert(output.end(), krb_priv.begin(), krb_priv.end());
    return output;
}

Bytes kpasswd_success_reply(
    const KerberosPasswordChangeRequestInfo& request,
    const KerberosApReqValidationResult& validation,
    int reply_enctype,
    const Bytes& reply_key) {
    Bytes result_data;
    write_u16_be(result_data, 0);
    const auto encrypted = kerberos_encrypt_aes_cts_hmac_sha1(
        enc_krb_priv_part(result_data),
        bytes_to_hex(reply_key),
        krb_priv_encrypted_part_key_usage);
    return kpasswd_reply(
        request,
        validation.response_token,
        krb_priv_message(reply_enctype, encrypted));
}

Bytes kpasswd_error_reply(
    const KerberosRealmInfo& realm,
    const KerberosPasswordChangeRequestInfo& request,
    int error_code,
    const std::string& error_text) {
    const auto error = krb_error(realm, error_code, error_text);
    const auto version = request.version == 0 ? static_cast<std::uint16_t>(0xff80U) : request.version;
    const auto total_size = static_cast<std::uint16_t>(6U + error.size());

    Bytes output;
    write_u16_be(output, total_size);
    write_u16_be(output, version);
    write_u16_be(output, 0);
    output.insert(output.end(), error.begin(), error.end());
    return output;
}

}  // namespace

std::vector<std::uint8_t> kerberos_gss_acceptor_mic(
    const std::vector<std::uint8_t>& subkey,
    const std::vector<std::uint8_t>& message) {
    if (subkey.empty()) {
        return {};
    }
    // RFC 4121 §4.2.6.1 GSS per-message MIC token using the acceptor subkey. The
    // SPNEGO mechListMIC is such a MIC computed over the DER-encoded MechTypeList;
    // Windows requires it in the accept-completed reply (the chosen mechanism,
    // Kerberos, provides integrity) and otherwise rejects with SEC_E_INVALID_TOKEN.
    constexpr int kg_usage_acceptor_sign = 23;
    const auto checksum_key = kerberos_dk(subkey, key_usage_constant(kg_usage_acceptor_sign, 0x99));
    // Header: TOK_ID=0x0404, Flags=0x05 (SentByAcceptor|AcceptorSubkey), Filler=0xFF*5,
    // SND_SEQ=0 (8 bytes). The checksum covers message || header.
    std::vector<std::uint8_t> header{0x04, 0x04, 0x05, 0xff, 0xff, 0xff, 0xff, 0xff, 0, 0, 0, 0, 0, 0, 0, 0};
    std::vector<std::uint8_t> to_sign(message.begin(), message.end());
    to_sign.insert(to_sign.end(), header.begin(), header.end());
    const auto checksum = kerberos_hmac_sha1_96(checksum_key, to_sign);
    std::vector<std::uint8_t> token = std::move(header);
    token.insert(token.end(), checksum.begin(), checksum.end());
    return token;
}

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

std::vector<std::uint8_t> kerberos_minimal_pac(
    const std::string& client_principal,
    const std::string& realm,
    const KerberosPrincipal& client,
    const KerberosKey& service_key,
    const KerberosKey& kdc_key) {
    auto pac = minimal_pac(
        client_principal,
        realm,
        &client,
        service_key,
        kdc_key,
        std::chrono::system_clock::now());
    return pac.value_or(Bytes{});
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
    if (auto sname_context = find_child(request, *req_body, 0xa3)) {
        if (auto sname = context_principal(request, *sname_context)) {
            parsed.service_principal = *sname;
        }
    }
    if (auto nonce_context = find_child(request, *req_body, 0xa7)) {
        if (auto nonce = context_integer(request, *nonce_context)) {
            parsed.nonce = *nonce;
        }
    }
    if (auto etype_context = find_child(request, *req_body, 0xa8)) {
        parsed.requested_etypes = context_integer_sequence(request, *etype_context);
    }

    parsed.valid = true;
    return parsed;
}

KerberosPasswordChangeRequestInfo parse_kpasswd_request(const std::vector<std::uint8_t>& request) {
    KerberosPasswordChangeRequestInfo parsed;
    if (request.size() < 6) {
        return parsed;
    }

    parsed.message_length = read_u16_be(request, 0);
    if (parsed.message_length != request.size()) {
        return parsed;
    }

    parsed.version = read_u16_be(request, 2);
    parsed.ap_req_length = read_u16_be(request, 4);
    if (parsed.version != 1 && parsed.version != 0xff80U) {
        return parsed;
    }
    if (static_cast<std::size_t>(parsed.ap_req_length) + 6U > request.size()) {
        return parsed;
    }

    parsed.ap_req.assign(
        request.begin() + 6,
        request.begin() + 6 + static_cast<std::ptrdiff_t>(parsed.ap_req_length));
    parsed.encrypted_payload.assign(
        request.begin() + 6 + static_cast<std::ptrdiff_t>(parsed.ap_req_length),
        request.end());
    parsed.valid = true;
    return parsed;
}

KerberosApReqValidationResult validate_kerberos_ap_req(
    const std::vector<std::uint8_t>& ap_req,
    const KerberosRealmInfo& realm,
    const std::optional<std::string>& expected_service_principal) {
    KerberosApReqValidationResult result;
    const auto parsed = parse_ap_req(ap_req);
    if (!parsed.has_value() || !parsed->valid) {
        result.diagnostic = "AP-REQ is malformed";
        return result;
    }

    result.realm = parsed->ticket_realm;
    result.service_principal = parsed->ticket_sname;
    if (!equals_ascii_case(parsed->ticket_realm, realm.realm)) {
        result.diagnostic = "AP-REQ ticket realm does not match this KDC realm";
        return result;
    }
    if (expected_service_principal.has_value() &&
        !principal_name_matches(parsed->ticket_sname, *expected_service_principal, realm.realm)) {
        result.diagnostic = "AP-REQ service principal does not match the expected service";
        return result;
    }

    const auto service = find_principal_by_name(realm, parsed->ticket_sname);
    if (!service.has_value() || !service->has_key_material) {
        result.diagnostic = "AP-REQ service principal unknown or missing key material";
        return result;
    }
    if (auto reason = principal_account_blocking_reason(*service)) {
        result.diagnostic = "AP-REQ service " + *reason;
        return result;
    }
    const auto service_key = key_for_etype(*service, parsed->ticket_enc_part.enctype);
    if (!service_key.has_value()) {
        result.diagnostic = "AP-REQ service etype is not available";
        return result;
    }

    const auto decrypted_ticket = kerberos_decrypt_aes_cts_hmac_sha1(
        parsed->ticket_enc_part.cipher,
        service_key->key_hex,
        ticket_key_usage);
    if (!decrypted_ticket.has_value()) {
        result.diagnostic = "AP-REQ ticket decryption failed";
        return result;
    }
    const auto session = parse_enc_ticket_part(*decrypted_ticket);
    if (!session.has_value()) {
        result.diagnostic = "AP-REQ encrypted ticket part is malformed";
        return result;
    }
    if (!equals_ascii_case(session->realm, realm.realm)) {
        result.diagnostic = "AP-REQ client realm does not match this KDC realm";
        return result;
    }
    if (const auto client = find_principal_by_name(realm, session->client_principal)) {
        if (auto reason = principal_account_blocking_reason(*client)) {
            result.diagnostic = "AP-REQ client " + *reason;
            return result;
        }
    }
    const auto authenticator = parse_ap_req_authenticator(parsed->authenticator, *session);
    if (!authenticator.has_value()) {
        result.diagnostic = "AP-REQ authenticator validation failed";
        return result;
    }

    result.ok = true;
    result.client_principal = session->client_principal;
    result.realm = session->realm;
    result.session_key_enctype = session->key_enctype;
    result.session_key = session->key_value;
    result.subsession_key_enctype = authenticator->subkey_enctype;
    result.subsession_key = authenticator->subkey_value;
    if ((parsed->ap_options & ap_option_mutual_required) != 0) {
        int acceptor_subkey_enctype = 0;
        Bytes acceptor_subkey;
        result.response_token = ap_rep_token(*session, *authenticator, acceptor_subkey_enctype, acceptor_subkey);
        // Subsequent SMB/LDAP messages are signed with the GSS context key, which the
        // mutual-auth AP-REP just established as the acceptor subkey — not the ticket
        // session key — so the signing key the caller caches must be the subkey.
        result.session_key_enctype = acceptor_subkey_enctype;
        result.session_key = std::move(acceptor_subkey);
    }
    return result;
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
            if (auto reason = principal_account_blocking_reason(*principal)) {
                return krb_error(realm, kdc_err_client_revoked, "client " + *reason);
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
            const auto client_key = key_for_etype(*principal, encrypted_timestamp.enctype);
            if (!client_key.has_value()) {
                return krb_error(realm, kdc_err_etype_nosupp, "encrypted timestamp etype is not available for this principal");
            }
            if (!validate_encrypted_timestamp(*principal, encrypted_timestamp)) {
                return krb_error(realm, kdc_err_preauth_failed, "encrypted timestamp validation failed");
            }
            const auto tgt_principal = find_principal_by_name(realm, realm.kdc_name.empty() ? "krbtgt" : realm.kdc_name);
            if (!tgt_principal.has_value()) {
                return krb_error(realm, kdc_err_svc_unavailable, "krbtgt key material is unavailable");
            }
            const auto reply_enctype = select_as_rep_enctype(parsed, *principal, *tgt_principal, encrypted_timestamp.enctype);
            if (!reply_enctype.has_value()) {
                return krb_error(realm, kdc_err_etype_nosupp, "AS-REP etype is not available for client and krbtgt");
            }
            const auto reply_client_key = key_for_etype(*principal, *reply_enctype);
            const auto krbtgt_key = key_for_etype(*tgt_principal, *reply_enctype);
            if (!reply_client_key.has_value()) {
                return krb_error(realm, kdc_err_etype_nosupp, "client AS-REP etype is not available");
            }
            if (!krbtgt_key.has_value()) {
                return krb_error(realm, kdc_err_etype_nosupp, "krbtgt etype is not available");
            }
            try {
                return as_rep(realm, parsed, *principal, *reply_client_key, *krbtgt_key, *reply_enctype);
            } catch (const std::exception& error) {
                return krb_error(realm, kdc_err_svc_unavailable, error.what());
            }
        }
        if (!parsed.valid) {
            return krb_error(realm, krb_ap_err_msg_type, "malformed AS request");
        }
        if (parsed.client_principal.empty()) {
            return krb_error(realm, kdc_err_c_principal_unknown, "client principal is missing from AS request");
        }
        return krb_error(realm, kdc_err_preauth_failed, "AS request pre-authentication data is unusable");
    }
    if (request_type == 12) {
        if (!parsed.valid || parsed.service_principal.empty()) {
            return krb_error(realm, kdc_err_s_principal_unknown, "service principal is missing from TGS request");
        }
        if (!has_padata_type(parsed, pa_tgs_req) || parsed.tgs_ap_req.empty()) {
            return krb_error(realm, kdc_err_preauth_failed, "TGS request is missing PA-TGS-REQ");
        }

        const auto tgt_principal = find_principal_by_name(realm, realm.kdc_name.empty() ? "krbtgt" : realm.kdc_name);
        if (!tgt_principal.has_value()) {
            return krb_error(realm, kdc_err_svc_unavailable, "krbtgt key material is unavailable");
        }
        const auto ap_req = parse_ap_req(parsed.tgs_ap_req);
        if (!ap_req.has_value() || !ap_req->valid) {
            return krb_error(realm, kdc_err_preauth_failed, "PA-TGS-REQ AP-REQ is malformed");
        }
        const auto krbtgt_key = key_for_etype(*tgt_principal, ap_req->ticket_enc_part.enctype);
        if (!krbtgt_key.has_value()) {
            return krb_error(realm, kdc_err_etype_nosupp, "krbtgt etype is not available");
        }
        const auto decrypted_tgt = kerberos_decrypt_aes_cts_hmac_sha1(
            ap_req->ticket_enc_part.cipher,
            krbtgt_key->key_hex,
            ticket_key_usage);
        if (!decrypted_tgt.has_value()) {
            return krb_error(realm, kdc_err_preauth_failed, "TGT decryption failed");
        }
        const auto tgt_session = parse_enc_ticket_part(*decrypted_tgt);
        if (!tgt_session.has_value()) {
            return krb_error(realm, kdc_err_preauth_failed, "TGT encrypted part is malformed");
        }
        if (!validate_tgs_authenticator(ap_req->authenticator, *tgt_session)) {
            return krb_error(realm, kdc_err_preauth_failed, "TGS authenticator validation failed");
        }

        const auto client = find_principal_by_name(realm, tgt_session->client_principal);
        const auto service = find_principal_by_name(realm, parsed.service_principal);
        if (client.has_value()) {
            if (auto reason = principal_account_blocking_reason(*client)) {
                return krb_error(realm, kdc_err_client_revoked, "client " + *reason);
            }
        }
        if (!service.has_value() || !service->has_key_material) {
            return krb_error(realm, kdc_err_s_principal_unknown, "service principal unknown or missing key material");
        }
        if (auto reason = principal_account_blocking_reason(*service)) {
            return krb_error(realm, kdc_err_service_revoked, "service " + *reason);
        }
        const auto service_key = select_service_key(*service, parsed);
        if (!service_key.has_value()) {
            return krb_error(realm, kdc_err_etype_nosupp, "service etype is not available");
        }
        try {
            return tgs_rep(
                realm,
                parsed,
                *tgt_session,
                client.has_value() ? &*client : nullptr,
                service->principal.empty() ? parsed.service_principal : service->principal,
                *service_key,
                *krbtgt_key,
                service_key->enctype);
        } catch (const std::exception& error) {
            return krb_error(realm, kdc_err_svc_unavailable, error.what());
        }
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

std::vector<std::uint8_t> kerberos_kpasswd_response(
    const std::vector<std::uint8_t>& request,
    const KerberosRealmInfo& realm,
    const KerberosPasswordChangeHandler& password_change_handler) {
    const auto parsed = parse_kpasswd_request(request);
    if (!parsed.valid) {
        return kpasswd_error_reply(realm, parsed, krb_ap_err_msg_type, "malformed kpasswd request");
    }
    if (parsed.ap_req.empty() || parsed.encrypted_payload.empty()) {
        return kpasswd_error_reply(realm, parsed, krb_ap_err_msg_type, "kpasswd request missing AP-REQ or KRB-PRIV");
    }

    const auto validation = validate_kerberos_ap_req(parsed.ap_req, realm, std::string{"kadmin/changepw"});
    if (!validation.ok) {
        return kpasswd_error_reply(
            realm,
            parsed,
            krb_ap_err_msg_type,
            validation.diagnostic.empty() ? "kpasswd AP-REQ validation failed" : validation.diagnostic);
    }
    if (!password_change_handler) {
        return kpasswd_error_reply(realm, parsed, kdc_err_svc_unavailable, "kpasswd password change handler is not configured");
    }

    const auto encrypted_priv = krb_priv_encrypted_data(parsed.encrypted_payload);
    if (!encrypted_priv.has_value()) {
        return kpasswd_error_reply(realm, parsed, krb_ap_err_msg_type, "kpasswd KRB-PRIV payload is malformed");
    }

    const auto& decrypt_key = validation.subsession_key.empty() ? validation.session_key : validation.subsession_key;
    const auto decrypt_enctype = validation.subsession_key.empty()
        ? validation.session_key_enctype
        : validation.subsession_key_enctype;
    if (decrypt_key.empty()) {
        return kpasswd_error_reply(realm, parsed, krb_ap_err_msg_type, "kpasswd AP-REQ did not provide a usable session key");
    }

    const auto change_data = decrypt_kpasswd_change_data(*encrypted_priv, decrypt_key);
    if (!change_data.has_value() || change_data->new_password.empty()) {
        return kpasswd_error_reply(realm, parsed, krb_ap_err_msg_type, "kpasswd KRB-PRIV password data is malformed");
    }

    KerberosPasswordChange change{
        validation.client_principal,
        validation.realm,
        change_data->target_principal,
        change_data->target_realm,
        change_data->new_password,
    };
    if (!password_change_handler(change)) {
        return kpasswd_error_reply(realm, parsed, kdc_err_svc_unavailable, "kpasswd password change was rejected");
    }

    try {
        return kpasswd_success_reply(parsed, validation, decrypt_enctype, decrypt_key);
    } catch (const std::exception& error) {
        return kpasswd_error_reply(realm, parsed, kdc_err_svc_unavailable, error.what());
    }
}

std::vector<std::uint8_t> kerberos_tcp_kpasswd_response(
    const std::vector<std::uint8_t>& frame,
    const KerberosRealmInfo& realm,
    const KerberosPasswordChangeHandler& password_change_handler) {
    if (frame.size() < 4) {
        return {};
    }

    const auto payload_size = read_u32(frame, 0);
    if (payload_size == 0 || frame.size() < static_cast<std::size_t>(payload_size) + 4) {
        return {};
    }

    Bytes payload(frame.begin() + 4, frame.begin() + 4 + payload_size);
    auto response = kerberos_kpasswd_response(payload, realm, password_change_handler);
    if (response.empty()) {
        return {};
    }

    Bytes framed;
    write_u32(framed, static_cast<std::uint32_t>(response.size()));
    framed.insert(framed.end(), response.begin(), response.end());
    return framed;
}

}  // namespace nexus::protocol
