#include "nexus/protocol/ldap.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <map>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>
#include <utility>

namespace nexus::protocol {

namespace {

using Bytes = std::vector<std::uint8_t>;

struct LdapNode {
    std::uint8_t tag{0};
    std::size_t content_offset{0};
    std::size_t content_length{0};
    std::size_t next_offset{0};
};

struct LdapControl {
    std::string oid;
    bool critical{false};
    Bytes value;
};

struct LdapBindRequest {
    int version{0};
    std::string name;
    std::uint8_t auth_tag{0};
    std::string simple_password;
    std::string sasl_mechanism;
    Bytes sasl_credentials;
};

struct LdapEntryAttribute {
    std::string name;
    std::vector<std::string> string_values;
    std::vector<Bytes> binary_values;
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
    output.push_back(tag);
    append_length(output, payload.size());
    output.insert(output.end(), payload.begin(), payload.end());
}

void append_u16_le(Bytes& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

void append_u32_le(Bytes& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
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

Bytes ldap_string(const std::string& value) {
    return Bytes(value.begin(), value.end());
}

void append_octet_string(Bytes& output, const std::string& value) {
    append_tlv(output, 0x04, ldap_string(value));
}

void append_octet_bytes(Bytes& output, const Bytes& value) {
    append_tlv(output, 0x04, value);
}

Bytes result_payload(int result_code, const std::string& diagnostic = {}) {
    Bytes payload;
    append_tlv(payload, 0x0a, integer_value(result_code));
    append_octet_string(payload, "");
    append_octet_string(payload, diagnostic);
    return payload;
}

Bytes ldap_message(int message_id, std::uint8_t op_tag, const Bytes& op_payload) {
    Bytes payload;
    append_tlv(payload, 0x02, integer_value(message_id));
    append_tlv(payload, op_tag, op_payload);
    return tlv(0x30, payload);
}

Bytes bind_response_payload(int result_code, const std::string& diagnostic = {}, const Bytes& server_sasl_credentials = {}) {
    auto payload = result_payload(result_code, diagnostic);
    if (!server_sasl_credentials.empty()) {
        append_tlv(payload, 0x87, server_sasl_credentials);
    }
    return payload;
}

Bytes ldap_message_with_controls(
    int message_id,
    std::uint8_t op_tag,
    const Bytes& op_payload,
    const std::vector<LdapControl>& controls) {
    Bytes payload;
    append_tlv(payload, 0x02, integer_value(message_id));
    append_tlv(payload, op_tag, op_payload);
    if (!controls.empty()) {
        Bytes controls_payload;
        for (const auto& control : controls) {
            Bytes control_payload;
            append_octet_string(control_payload, control.oid);
            if (control.critical) {
                append_tlv(control_payload, 0x01, {0xff});
            }
            if (!control.value.empty()) {
                append_octet_bytes(control_payload, control.value);
            }
            const auto encoded = tlv(0x30, control_payload);
            controls_payload.insert(controls_payload.end(), encoded.begin(), encoded.end());
        }
        append_tlv(payload, 0xa0, controls_payload);
    }
    return tlv(0x30, payload);
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
    const auto count = first & 0x7fU;
    if (count == 0 || count > 4 || offset + count > input.size()) {
        return false;
    }
    length = 0;
    for (std::uint8_t index = 0; index < count; ++index) {
        length = (length << 8U) | input[offset++];
    }
    return true;
}

std::optional<LdapNode> read_node(const Bytes& input, std::size_t offset, std::size_t limit) {
    if (offset >= limit || offset >= input.size()) {
        return std::nullopt;
    }
    LdapNode node;
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

bool read_message_header(const Bytes& input, int& message_id, std::uint8_t& op_tag, LdapNode& op_node) {
    auto message = read_node(input, 0, input.size());
    if (!message.has_value() || message->tag != 0x30) {
        return false;
    }

    const auto limit = message->content_offset + message->content_length;
    auto message_id_node = read_node(input, message->content_offset, limit);
    if (!message_id_node.has_value() || message_id_node->tag != 0x02) {
        return false;
    }
    message_id = 0;
    for (std::size_t offset = message_id_node->content_offset; offset < message_id_node->content_offset + message_id_node->content_length; ++offset) {
        message_id = (message_id << 8U) | input[offset];
    }

    auto protocol_op = read_node(input, message_id_node->next_offset, limit);
    if (!protocol_op.has_value()) {
        return false;
    }
    op_tag = protocol_op->tag;
    op_node = *protocol_op;
    return true;
}

Bytes partial_attribute(const std::string& name, const std::vector<std::string>& values) {
    Bytes payload;
    append_octet_string(payload, name);

    Bytes set_payload;
    for (const auto& value : values) {
        append_octet_string(set_payload, value);
    }
    append_tlv(payload, 0x31, set_payload);
    return tlv(0x30, payload);
}

Bytes partial_attribute_bytes(const std::string& name, const std::vector<Bytes>& values) {
    Bytes payload;
    append_octet_string(payload, name);

    Bytes set_payload;
    for (const auto& value : values) {
        append_octet_bytes(set_payload, value);
    }
    append_tlv(payload, 0x31, set_payload);
    return tlv(0x30, payload);
}

bool contains_ascii_case(const Bytes& input, const std::string& needle) {
    if (needle.empty() || input.size() < needle.size()) {
        return false;
    }
    for (std::size_t offset = 0; offset + needle.size() <= input.size(); ++offset) {
        bool matched = true;
        for (std::size_t index = 0; index < needle.size(); ++index) {
            const auto left = static_cast<unsigned char>(input[offset + index]);
            const auto right = static_cast<unsigned char>(needle[index]);
            if (std::tolower(left) != std::tolower(right)) {
                matched = false;
                break;
            }
        }
        if (matched) {
            return true;
        }
    }
    return false;
}

std::string string_from_node(const Bytes& input, const LdapNode& node) {
    return std::string(
        input.begin() + static_cast<std::ptrdiff_t>(node.content_offset),
        input.begin() + static_cast<std::ptrdiff_t>(node.content_offset + node.content_length));
}

std::vector<LdapControl> read_message_controls(const Bytes& input) {
    std::vector<LdapControl> controls;
    auto message = read_node(input, 0, input.size());
    if (!message.has_value() || message->tag != 0x30) {
        return controls;
    }

    const auto limit = message->content_offset + message->content_length;
    auto message_id = read_node(input, message->content_offset, limit);
    if (!message_id.has_value()) {
        return controls;
    }
    auto protocol_op = read_node(input, message_id->next_offset, limit);
    if (!protocol_op.has_value()) {
        return controls;
    }
    auto controls_node = read_node(input, protocol_op->next_offset, limit);
    if (!controls_node.has_value() || controls_node->tag != 0xa0) {
        return controls;
    }

    std::size_t offset = controls_node->content_offset;
    const auto controls_limit = controls_node->content_offset + controls_node->content_length;
    while (offset < controls_limit) {
        auto control_sequence = read_node(input, offset, controls_limit);
        if (!control_sequence.has_value() || control_sequence->tag != 0x30) {
            return controls;
        }

        LdapControl control;
        std::size_t field_offset = control_sequence->content_offset;
        const auto field_limit = control_sequence->content_offset + control_sequence->content_length;
        auto oid = read_node(input, field_offset, field_limit);
        if (!oid.has_value() || oid->tag != 0x04) {
            return controls;
        }
        control.oid = string_from_node(input, *oid);
        field_offset = oid->next_offset;

        auto next = read_node(input, field_offset, field_limit);
        if (next.has_value() && next->tag == 0x01) {
            control.critical = next->content_length > 0 && input[next->content_offset] != 0;
            field_offset = next->next_offset;
            next = read_node(input, field_offset, field_limit);
        }
        if (next.has_value() && next->tag == 0x04) {
            control.value.assign(
                input.begin() + static_cast<std::ptrdiff_t>(next->content_offset),
                input.begin() + static_cast<std::ptrdiff_t>(next->content_offset + next->content_length));
        }
        controls.push_back(std::move(control));
        offset = control_sequence->next_offset;
    }
    return controls;
}

int integer_from_node(const Bytes& input, const LdapNode& node) {
    int value = 0;
    for (std::size_t offset = node.content_offset; offset < node.content_offset + node.content_length; ++offset) {
        value = (value << 8U) | input[offset];
    }
    return value;
}

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

bool equals_ascii_case(const std::string& left, const std::string& right) {
    return lowercase_ascii(left) == lowercase_ascii(right);
}

std::string trim_ascii_copy(const std::string& value) {
    const auto first = std::find_if_not(value.begin(), value.end(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    });
    if (first == value.end()) {
        return {};
    }
    const auto last = std::find_if_not(value.rbegin(), value.rend(), [](unsigned char ch) {
        return std::isspace(ch) != 0;
    }).base();
    return std::string(first, last);
}

bool is_supported_control(const std::string& oid) {
    static const std::array supported{
        "1.2.840.113556.1.4.319",
        "1.2.840.113556.1.4.473",
        "1.2.840.113556.1.4.474",
        "1.2.840.113556.1.4.417",
        "1.2.840.113556.1.4.528",
        "1.2.840.113556.1.4.529",
        "1.2.840.113556.1.4.801",
        "1.2.840.113556.1.4.805",
        "1.2.840.113556.1.4.841",
        "1.2.840.113556.1.4.970",
        "1.2.840.113556.1.4.1338",
        "1.2.840.113556.1.4.1339",
        "1.2.840.113556.1.4.1340",
        "1.2.840.113556.1.4.1413",
        "1.2.840.113556.1.4.1504",
        "1.2.840.113556.1.4.1852",
        "1.2.840.113556.1.4.1948",
        "1.2.840.113556.1.4.2064",
        "1.2.840.113556.1.4.2065",
        "1.2.840.113556.1.4.2239",
        "2.16.840.1.113730.3.4.9",
        "2.16.840.1.113730.3.4.10",
    };
    return std::any_of(supported.begin(), supported.end(), [&](const auto& supported_oid) {
        return oid == supported_oid;
    });
}

bool is_supported_sasl_mechanism(const std::string& mechanism) {
    return equals_ascii_case(mechanism, "GSS-SPNEGO") ||
           equals_ascii_case(mechanism, "GSSAPI") ||
           equals_ascii_case(mechanism, "EXTERNAL");
}

bool has_unsupported_critical_control(const std::vector<LdapControl>& controls) {
    return std::any_of(controls.begin(), controls.end(), [](const auto& control) {
        return control.critical && !is_supported_control(control.oid);
    });
}

bool has_paged_results_control(const std::vector<LdapControl>& controls) {
    return std::any_of(controls.begin(), controls.end(), [](const auto& control) {
        return control.oid == "1.2.840.113556.1.4.319";
    });
}

bool has_control(const std::vector<LdapControl>& controls, const std::string& oid) {
    return std::any_of(controls.begin(), controls.end(), [&](const auto& control) {
        return control.oid == oid;
    });
}

Bytes paged_results_response_value() {
    Bytes payload;
    append_tlv(payload, 0x02, integer_value(0));
    append_tlv(payload, 0x04, {});
    return tlv(0x30, payload);
}

Bytes sort_response_value() {
    Bytes payload;
    append_tlv(payload, 0x0a, integer_value(0));
    return tlv(0x30, payload);
}

Bytes vlv_response_value() {
    Bytes payload;
    append_tlv(payload, 0x02, integer_value(1));
    append_tlv(payload, 0x02, integer_value(1));
    append_tlv(payload, 0x0a, integer_value(0));
    append_tlv(payload, 0x04, {});
    return tlv(0x30, payload);
}

std::vector<LdapControl> search_done_controls(const std::vector<LdapControl>& request_controls) {
    std::vector<LdapControl> controls;
    if (has_paged_results_control(request_controls)) {
        controls.push_back(LdapControl{"1.2.840.113556.1.4.319", false, paged_results_response_value()});
    }
    if (has_control(request_controls, "1.2.840.113556.1.4.473")) {
        controls.push_back(LdapControl{"1.2.840.113556.1.4.474", false, sort_response_value()});
    }
    if (has_control(request_controls, "2.16.840.1.113730.3.4.9")) {
        controls.push_back(LdapControl{"2.16.840.1.113730.3.4.10", false, vlv_response_value()});
    }
    return controls;
}

bool ends_with_ascii_case(const std::string& value, const std::string& suffix) {
    if (value.size() < suffix.size()) {
        return false;
    }
    return equals_ascii_case(value.substr(value.size() - suffix.size()), suffix);
}

std::string ldap_attribute_base_name(const std::string& attribute) {
    const auto option = attribute.find(';');
    return option == std::string::npos ? attribute : attribute.substr(0, option);
}

bool ldap_attribute_matches(const std::string& attribute, const std::string& expected) {
    return equals_ascii_case(ldap_attribute_base_name(attribute), expected);
}

std::string parent_dn_from_dn(const std::string& dn) {
    bool escaped = false;
    for (std::size_t index = 0; index < dn.size(); ++index) {
        const auto ch = dn[index];
        if (escaped) {
            escaped = false;
            continue;
        }
        if (ch == '\\') {
            escaped = true;
            continue;
        }
        if (ch == ',') {
            return dn.substr(index + 1);
        }
    }
    return {};
}

std::string rdn_value_from_dn(const std::string& dn) {
    const auto first_part = dn.substr(0, dn.find(','));
    const auto equals = first_part.find('=');
    if (equals == std::string::npos || equals + 1 >= first_part.size()) {
        return first_part;
    }
    return first_part.substr(equals + 1);
}

std::vector<std::string> split_ldap_values(const std::string& attribute, const std::string& value) {
    if (!(equals_ascii_case(attribute, "servicePrincipalName") ||
          equals_ascii_case(attribute, "member") ||
          equals_ascii_case(attribute, "memberOf"))) {
        return {value};
    }

    std::vector<std::string> values;
    std::string entry;
    const auto push_entry = [&]() {
        const auto trimmed = trim_ascii_copy(entry);
        if (!trimmed.empty()) {
            values.push_back(trimmed);
        }
        entry.clear();
    };
    for (char ch : value) {
        if (ch == ';' || (equals_ascii_case(attribute, "servicePrincipalName") && ch == ',')) {
            push_entry();
            continue;
        }
        entry.push_back(ch);
    }
    push_entry();
    return values;
}

std::optional<std::pair<std::string, std::string>> find_object_attribute(
    const LdapObject& object,
    const std::string& attribute) {
    for (const auto& [key, value] : object.attributes) {
        if (equals_ascii_case(key, attribute)) {
            return std::make_pair(key, value);
        }
    }
    return std::nullopt;
}

void append_unique_value(std::vector<std::string>& values, std::string value) {
    value = trim_ascii_copy(value);
    if (value.empty()) {
        return;
    }
    const auto exists = std::any_of(values.begin(), values.end(), [&](const auto& current) {
        return equals_ascii_case(current, value);
    });
    if (!exists) {
        values.push_back(std::move(value));
    }
}

std::optional<std::uint32_t> parse_u32_decimal(const std::string& value) {
    try {
        std::size_t consumed = 0;
        const auto parsed = std::stoul(trim_ascii_copy(value), &consumed, 10);
        if (consumed == trim_ascii_copy(value).size() && parsed <= 0xffffffffUL) {
            return static_cast<std::uint32_t>(parsed);
        }
    } catch (...) {
    }
    return std::nullopt;
}

int hex_value(char ch) {
    if (ch >= '0' && ch <= '9') {
        return ch - '0';
    }
    if (ch >= 'a' && ch <= 'f') {
        return 10 + (ch - 'a');
    }
    if (ch >= 'A' && ch <= 'F') {
        return 10 + (ch - 'A');
    }
    return -1;
}

std::optional<Bytes> uuid_string_to_ad_guid_bytes(const std::string& value) {
    std::string hex;
    hex.reserve(32);
    for (const char ch : trim_ascii_copy(value)) {
        if (ch == '-' || ch == '{' || ch == '}') {
            continue;
        }
        if (hex_value(ch) < 0) {
            return std::nullopt;
        }
        hex.push_back(ch);
    }
    if (hex.size() != 32) {
        return std::nullopt;
    }

    Bytes raw;
    raw.reserve(16);
    for (std::size_t index = 0; index < hex.size(); index += 2) {
        const auto high = hex_value(hex[index]);
        const auto low = hex_value(hex[index + 1]);
        if (high < 0 || low < 0) {
            return std::nullopt;
        }
        raw.push_back(static_cast<std::uint8_t>((high << 4) | low));
    }

    return Bytes{
        raw[3],
        raw[2],
        raw[1],
        raw[0],
        raw[5],
        raw[4],
        raw[7],
        raw[6],
        raw[8],
        raw[9],
        raw[10],
        raw[11],
        raw[12],
        raw[13],
        raw[14],
        raw[15],
    };
}

Bytes stable_object_guid_bytes(const LdapObject& object) {
    std::uint64_t hash = 1469598103934665603ULL;
    const auto seed = lowercase_ascii(object.dn.empty() ? object.kind : object.dn);
    for (const unsigned char ch : seed) {
        hash ^= ch;
        hash *= 1099511628211ULL;
    }
    Bytes bytes(16);
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>((hash >> ((index % 8U) * 8U)) & 0xffU);
        hash ^= static_cast<std::uint64_t>(index + 17U) * 0x9e3779b97f4a7c15ULL;
        hash *= 1099511628211ULL;
    }
    bytes[7] = static_cast<std::uint8_t>((bytes[7] & 0x0fU) | 0x40U);
    bytes[8] = static_cast<std::uint8_t>((bytes[8] & 0x3fU) | 0x80U);
    return bytes;
}

Bytes object_guid_binary_value(const LdapObject& object) {
    if (auto guid = find_object_attribute(object, "objectGUID")) {
        if (auto encoded = uuid_string_to_ad_guid_bytes(guid->second)) {
            return *encoded;
        }
        if (guid->second.size() == 16) {
            return Bytes(guid->second.begin(), guid->second.end());
        }
    }
    return stable_object_guid_bytes(object);
}

std::optional<std::uint32_t> object_rid(const LdapObject& object) {
    if (auto rid = find_object_attribute(object, "rid")) {
        return parse_u32_decimal(rid->second);
    }
    if (auto sid = find_object_attribute(object, "objectSid")) {
        const auto dash = sid->second.find_last_of('-');
        if (dash != std::string::npos && dash + 1 < sid->second.size()) {
            return parse_u32_decimal(sid->second.substr(dash + 1));
        }
    }
    return std::nullopt;
}

std::vector<std::uint32_t> parse_rid_list(const std::string& value) {
    std::vector<std::uint32_t> rids;
    std::string token;
    const auto push_token = [&]() {
        if (auto rid = parse_u32_decimal(token)) {
            if (std::find(rids.begin(), rids.end(), *rid) == rids.end()) {
                rids.push_back(*rid);
            }
        }
        token.clear();
    };
    for (const char ch : value) {
        if (ch == ',' || ch == ';' || std::isspace(static_cast<unsigned char>(ch)) != 0) {
            push_token();
            continue;
        }
        token.push_back(ch);
    }
    push_token();
    return rids;
}

std::vector<std::uint32_t> object_group_rids(const LdapObject& object) {
    std::vector<std::uint32_t> rids;
    if (auto group_rids = find_object_attribute(object, "groupRids")) {
        rids = parse_rid_list(group_rids->second);
    }
    if (auto primary_group = find_object_attribute(object, "primaryGroupID")) {
        if (auto rid = parse_u32_decimal(primary_group->second)) {
            if (*rid != 0 && std::find(rids.begin(), rids.end(), *rid) == rids.end()) {
                rids.push_back(*rid);
            }
        }
    }
    return rids;
}

bool object_has_class(const LdapObject& object, const std::string& object_class) {
    return std::any_of(object.object_classes.begin(), object.object_classes.end(), [&](const auto& candidate) {
        return equals_ascii_case(candidate, object_class);
    });
}

bool is_group_object(const LdapObject& object) {
    return equals_ascii_case(object.kind, "group") || object_has_class(object, "group") ||
           find_object_attribute(object, "groupType").has_value();
}

bool is_computer_object(const LdapObject& object) {
    if (equals_ascii_case(object.kind, "computer") || object_has_class(object, "computer")) {
        return true;
    }
    if (auto sam = find_object_attribute(object, "sAMAccountName")) {
        return !sam->second.empty() && sam->second.back() == '$';
    }
    return false;
}

bool is_user_object(const LdapObject& object) {
    return equals_ascii_case(object.kind, "user") || object_has_class(object, "user") ||
           find_object_attribute(object, "userPrincipalName").has_value();
}

bool member_value_matches_dn(const std::string& member_values, const std::string& dn) {
    for (const auto& value : split_ldap_values("member", member_values)) {
        if (equals_ascii_case(value, dn)) {
            return true;
        }
    }
    return false;
}

bool group_contains_object(const LdapObject& group, const LdapObject& object) {
    if (!is_group_object(group) || equals_ascii_case(group.dn, object.dn)) {
        return false;
    }
    if (auto member = find_object_attribute(group, "member")) {
        if (member_value_matches_dn(member->second, object.dn)) {
            return true;
        }
    }
    const auto group_rid = object_rid(group);
    if (!group_rid.has_value()) {
        return false;
    }
    const auto member_rids = object_group_rids(object);
    return std::find(member_rids.begin(), member_rids.end(), *group_rid) != member_rids.end();
}

std::vector<std::string> constructed_member_of_values(
    const LdapObject& object,
    const std::vector<LdapObject>* all_objects) {
    std::vector<std::string> values;
    if (auto explicit_member_of = find_object_attribute(object, "memberOf")) {
        for (const auto& value : split_ldap_values(explicit_member_of->first, explicit_member_of->second)) {
            append_unique_value(values, value);
        }
    }
    if (all_objects == nullptr) {
        return values;
    }
    for (const auto& group : *all_objects) {
        if (group_contains_object(group, object)) {
            append_unique_value(values, group.dn);
        }
    }
    return values;
}

std::vector<std::string> constructed_member_values(
    const LdapObject& group,
    const std::vector<LdapObject>* all_objects) {
    std::vector<std::string> values;
    if (auto explicit_member = find_object_attribute(group, "member")) {
        for (const auto& value : split_ldap_values(explicit_member->first, explicit_member->second)) {
            append_unique_value(values, value);
        }
    }
    if (all_objects == nullptr || !is_group_object(group)) {
        return values;
    }
    const auto group_rid = object_rid(group);
    if (!group_rid.has_value()) {
        return values;
    }
    for (const auto& candidate : *all_objects) {
        if (equals_ascii_case(candidate.dn, group.dn)) {
            continue;
        }
        const auto group_rids = object_group_rids(candidate);
        if (std::find(group_rids.begin(), group_rids.end(), *group_rid) != group_rids.end()) {
            append_unique_value(values, candidate.dn);
        }
    }
    return values;
}

const LdapObject* find_object_by_dn(const std::vector<LdapObject>* all_objects, const std::string& dn) {
    if (all_objects == nullptr) {
        return nullptr;
    }
    const auto found = std::find_if(all_objects->begin(), all_objects->end(), [&](const auto& candidate) {
        return equals_ascii_case(candidate.dn, dn);
    });
    return found == all_objects->end() ? nullptr : &*found;
}

bool contains_visited_dn(const std::vector<std::string>& visited_dns, const std::string& dn) {
    return std::any_of(visited_dns.begin(), visited_dns.end(), [&](const auto& visited) {
        return equals_ascii_case(visited, dn);
    });
}

bool member_of_chain_contains(
    const LdapObject& object,
    const std::string& target_group_dn,
    const std::vector<LdapObject>* all_objects,
    std::vector<std::string>& visited_dns) {
    if (all_objects == nullptr || contains_visited_dn(visited_dns, object.dn)) {
        return false;
    }
    visited_dns.push_back(object.dn);
    for (const auto& group_dn : constructed_member_of_values(object, all_objects)) {
        if (equals_ascii_case(group_dn, target_group_dn)) {
            return true;
        }
        if (const auto* group = find_object_by_dn(all_objects, group_dn);
            group != nullptr && member_of_chain_contains(*group, target_group_dn, all_objects, visited_dns)) {
            return true;
        }
    }
    return false;
}

bool member_chain_contains(
    const LdapObject& group,
    const std::string& target_member_dn,
    const std::vector<LdapObject>* all_objects,
    std::vector<std::string>& visited_dns) {
    if (all_objects == nullptr || !is_group_object(group) || contains_visited_dn(visited_dns, group.dn)) {
        return false;
    }
    visited_dns.push_back(group.dn);
    for (const auto& member_dn : constructed_member_values(group, all_objects)) {
        if (equals_ascii_case(member_dn, target_member_dn)) {
            return true;
        }
        if (const auto* member = find_object_by_dn(all_objects, member_dn);
            member != nullptr && is_group_object(*member) &&
            member_chain_contains(*member, target_member_dn, all_objects, visited_dns)) {
            return true;
        }
    }
    return false;
}

bool object_attribute_transitive_matches(
    const LdapObject& object,
    const std::string& attribute,
    const std::string& expected,
    const std::vector<LdapObject>* all_objects) {
    if (all_objects == nullptr) {
        return false;
    }
    std::vector<std::string> visited_dns;
    if (ldap_attribute_matches(attribute, "memberOf")) {
        return member_of_chain_contains(object, expected, all_objects, visited_dns);
    }
    if (ldap_attribute_matches(attribute, "member")) {
        return member_chain_contains(object, expected, all_objects, visited_dns);
    }
    return false;
}

std::optional<std::string> sam_account_type(const LdapObject& object) {
    if (is_group_object(object)) {
        if (auto sid = find_object_attribute(object, "objectSid")) {
            if (sid->second.starts_with("S-1-5-32-")) {
                return "536870912";
            }
        }
        return "268435456";
    }
    if (is_computer_object(object)) {
        return "805306369";
    }
    if (is_user_object(object)) {
        return "805306368";
    }
    return std::nullopt;
}

std::vector<std::string> object_attribute_values(
    const LdapObject& object,
    const std::string& attribute,
    const std::vector<LdapObject>* all_objects = nullptr) {
    const auto base_attribute = ldap_attribute_base_name(attribute);
    if (ldap_attribute_matches(attribute, "objectClass")) {
        return object.object_classes;
    }
    if (ldap_attribute_matches(attribute, "distinguishedName") || ldap_attribute_matches(attribute, "dn")) {
        return {object.dn};
    }
    if (ldap_attribute_matches(attribute, "name")) {
        if (auto cn = find_object_attribute(object, "cn")) {
            return {cn->second};
        }
        return {rdn_value_from_dn(object.dn)};
    }
    if (ldap_attribute_matches(attribute, "objectCategory")) {
        return {object.kind};
    }
    if (ldap_attribute_matches(attribute, "memberOf")) {
        return constructed_member_of_values(object, all_objects);
    }
    if (ldap_attribute_matches(attribute, "member") && is_group_object(object)) {
        return constructed_member_values(object, all_objects);
    }
    if (ldap_attribute_matches(attribute, "primaryGroupToken") && is_group_object(object)) {
        if (const auto rid = object_rid(object)) {
            return {std::to_string(*rid)};
        }
        return {};
    }
    if (ldap_attribute_matches(attribute, "sAMAccountType")) {
        if (auto type = sam_account_type(object)) {
            return {*type};
        }
        return {};
    }
    if (ldap_attribute_matches(attribute, "whenCreated") || ldap_attribute_matches(attribute, "whenChanged")) {
        if (auto attribute_value = find_object_attribute(object, base_attribute)) {
            return split_ldap_values(attribute_value->first, attribute_value->second);
        }
        return {"20260101000000.0Z"};
    }
    if (ldap_attribute_matches(attribute, "uSNCreated") || ldap_attribute_matches(attribute, "uSNChanged")) {
        if (auto attribute_value = find_object_attribute(object, base_attribute)) {
            return split_ldap_values(attribute_value->first, attribute_value->second);
        }
        return {"1"};
    }
    if (ldap_attribute_matches(attribute, "userPasswordHash")) {
        return {};
    }
    if (auto attribute_value = find_object_attribute(object, base_attribute)) {
        return split_ldap_values(attribute_value->first, attribute_value->second);
    }
    return {};
}

std::optional<std::vector<std::uint32_t>> sid_subauthorities(const std::string& sid) {
    constexpr std::string_view prefix{"S-1-5-"};
    if (!sid.starts_with(prefix)) {
        return std::nullopt;
    }
    std::vector<std::uint32_t> values;
    std::size_t start = prefix.size();
    while (start < sid.size()) {
        const auto dash = sid.find('-', start);
        const auto part = sid.substr(start, dash == std::string::npos ? std::string::npos : dash - start);
        try {
            std::size_t consumed = 0;
            const auto value = std::stoul(part, &consumed);
            if (consumed != part.size()) {
                return std::nullopt;
            }
            values.push_back(static_cast<std::uint32_t>(value));
        } catch (...) {
            return std::nullopt;
        }
        if (dash == std::string::npos) {
            break;
        }
        start = dash + 1;
    }
    return values;
}

Bytes sid_bytes(const std::string& sid) {
    const auto subauthorities = sid_subauthorities(sid);
    if (!subauthorities.has_value() || subauthorities->empty() || subauthorities->size() > 15) {
        return {};
    }

    Bytes output;
    output.push_back(1);
    output.push_back(static_cast<std::uint8_t>(subauthorities->size()));
    output.insert(output.end(), {0, 0, 0, 0, 0, 5});
    for (const auto subauthority : *subauthorities) {
        append_u32_le(output, subauthority);
    }
    return output;
}

std::string domain_sid_from_object_sid(const std::string& sid) {
    const auto subauthorities = sid_subauthorities(sid);
    if (subauthorities.has_value() && subauthorities->size() <= 4) {
        return sid;
    }
    const auto dash = sid.find_last_of('-');
    return dash == std::string::npos ? sid : sid.substr(0, dash);
}

Bytes security_descriptor_ace(const std::string& sid, std::uint32_t access_mask) {
    const auto encoded_sid = sid_bytes(sid);
    if (encoded_sid.empty()) {
        return {};
    }
    Bytes output;
    output.push_back(0);
    output.push_back(0);
    append_u16_le(output, static_cast<std::uint16_t>(8U + encoded_sid.size()));
    append_u32_le(output, access_mask);
    output.insert(output.end(), encoded_sid.begin(), encoded_sid.end());
    return output;
}

Bytes security_descriptor_dacl(const std::vector<std::string>& allowed_sids) {
    Bytes aces;
    std::uint16_t ace_count = 0;
    for (const auto& sid : allowed_sids) {
        const auto ace = security_descriptor_ace(sid, 0x000f01ffU);
        if (ace.empty()) {
            continue;
        }
        aces.insert(aces.end(), ace.begin(), ace.end());
        ++ace_count;
    }

    Bytes output;
    output.push_back(2);
    output.push_back(0);
    append_u16_le(output, static_cast<std::uint16_t>(8U + aces.size()));
    append_u16_le(output, ace_count);
    append_u16_le(output, 0);
    output.insert(output.end(), aces.begin(), aces.end());
    return output;
}

Bytes minimal_security_descriptor(const LdapObject& object) {
    const auto object_sid = object_attribute_values(object, "objectSid");
    const auto domain_sid = object_sid.empty() ? std::string{} : domain_sid_from_object_sid(object_sid.front());
    const auto owner_sid = "S-1-5-32-544";
    const auto group_sid = domain_sid.empty() ? owner_sid : domain_sid + "-512";
    const auto owner = sid_bytes(owner_sid);
    const auto group = sid_bytes(group_sid);

    std::vector<std::string> allowed{"S-1-5-18", "S-1-5-32-544"};
    if (!domain_sid.empty()) {
        allowed.push_back(domain_sid + "-512");
    }
    const auto dacl = security_descriptor_dacl(allowed);
    if (owner.empty() || group.empty() || dacl.empty()) {
        return {};
    }

    constexpr std::uint32_t header_size = 20;
    const auto owner_offset = header_size;
    const auto group_offset = owner_offset + owner.size();
    const auto dacl_offset = group_offset + group.size();

    Bytes output;
    output.push_back(1);
    output.push_back(0);
    append_u16_le(output, 0x8004U);
    append_u32_le(output, static_cast<std::uint32_t>(owner_offset));
    append_u32_le(output, static_cast<std::uint32_t>(group_offset));
    append_u32_le(output, 0);
    append_u32_le(output, static_cast<std::uint32_t>(dacl_offset));
    output.insert(output.end(), owner.begin(), owner.end());
    output.insert(output.end(), group.begin(), group.end());
    output.insert(output.end(), dacl.begin(), dacl.end());
    return output;
}

std::vector<std::string> token_group_sid_values(
    const LdapObject& object,
    const std::vector<LdapObject>* all_objects) {
    std::vector<std::string> sids;
    if (all_objects != nullptr) {
        for (const auto& group : *all_objects) {
            if (!group_contains_object(group, object)) {
                continue;
            }
            if (auto sid = find_object_attribute(group, "objectSid")) {
                append_unique_value(sids, sid->second);
            }
        }
        return sids;
    }

    const auto object_sid_values = object_attribute_values(object, "objectSid");
    if (object_sid_values.empty()) {
        return sids;
    }
    const auto domain_sid = domain_sid_from_object_sid(object_sid_values.front());
    if (domain_sid.empty()) {
        return sids;
    }
    for (const auto rid : object_group_rids(object)) {
        append_unique_value(sids, domain_sid + "-" + std::to_string(rid));
    }
    return sids;
}

std::vector<Bytes> object_attribute_binary_values(
    const LdapObject& object,
    const std::string& attribute,
    const std::vector<LdapObject>* all_objects = nullptr) {
    if (ldap_attribute_matches(attribute, "objectGUID")) {
        return {object_guid_binary_value(object)};
    }
    if (ldap_attribute_matches(attribute, "objectSid")) {
        std::vector<Bytes> values;
        for (const auto& value : object_attribute_values(object, attribute)) {
            const auto encoded = sid_bytes(value);
            if (!encoded.empty()) {
                values.push_back(encoded);
            }
        }
        return values;
    }
    if (ldap_attribute_matches(attribute, "tokenGroups")) {
        std::vector<Bytes> values;
        for (const auto& sid : token_group_sid_values(object, all_objects)) {
            const auto encoded = sid_bytes(sid);
            if (!encoded.empty()) {
                values.push_back(encoded);
            }
        }
        return values;
    }
    if (ldap_attribute_matches(attribute, "nTSecurityDescriptor")) {
        const auto descriptor = minimal_security_descriptor(object);
        return descriptor.empty() ? std::vector<Bytes>{} : std::vector<Bytes>{descriptor};
    }
    return {};
}

bool object_has_attribute(
    const LdapObject& object,
    const std::string& attribute,
    const std::vector<LdapObject>* all_objects = nullptr) {
    if (ldap_attribute_matches(attribute, "objectGUID")) {
        return object_guid_binary_value(object).size() == 16;
    }
    if (ldap_attribute_matches(attribute, "nTSecurityDescriptor")) {
        return !minimal_security_descriptor(object).empty();
    }
    if (ldap_attribute_matches(attribute, "tokenGroups")) {
        return !object_attribute_binary_values(object, attribute, all_objects).empty();
    }
    return !object_attribute_values(object, attribute, all_objects).empty();
}

bool object_attribute_equals(
    const LdapObject& object,
    const std::string& attribute,
    const std::string& expected,
    const std::vector<LdapObject>* all_objects = nullptr) {
    const auto normalized_attribute = lowercase_ascii(ldap_attribute_base_name(attribute));
    if (normalized_attribute == "objectguid") {
        const auto actual = object_guid_binary_value(object);
        if (expected.size() == actual.size() &&
            std::equal(actual.begin(), actual.end(), expected.begin(), [](std::uint8_t left, char right) {
                return left == static_cast<std::uint8_t>(static_cast<unsigned char>(right));
            })) {
            return true;
        }
        if (auto expected_guid = uuid_string_to_ad_guid_bytes(expected)) {
            return *expected_guid == actual;
        }
        return false;
    }
    if (normalized_attribute == "objectsid") {
        if (const auto binary_sid = [&]() -> std::optional<std::string> {
                if (expected.size() < 8 || static_cast<unsigned char>(expected[0]) != 1) {
                    return std::nullopt;
                }
                const auto sub_authority_count = static_cast<unsigned char>(expected[1]);
                if (sub_authority_count == 0 || sub_authority_count > 15 ||
                    expected.size() < 8 + static_cast<std::size_t>(sub_authority_count) * 4U) {
                    return std::nullopt;
                }
                std::uint64_t authority = 0;
                for (std::size_t index = 2; index < 8; ++index) {
                    authority = (authority << 8U) | static_cast<unsigned char>(expected[index]);
                }
                std::string sid = "S-1-" + std::to_string(authority);
                std::size_t offset = 8;
                for (std::uint8_t index = 0; index < sub_authority_count; ++index) {
                    const auto value = static_cast<std::uint32_t>(static_cast<unsigned char>(expected[offset])) |
                                       (static_cast<std::uint32_t>(static_cast<unsigned char>(expected[offset + 1])) << 8U) |
                                       (static_cast<std::uint32_t>(static_cast<unsigned char>(expected[offset + 2])) << 16U) |
                                       (static_cast<std::uint32_t>(static_cast<unsigned char>(expected[offset + 3])) << 24U);
                    sid += "-" + std::to_string(value);
                    offset += 4;
                }
                return sid;
            }()) {
            return object_attribute_equals(object, attribute, *binary_sid, all_objects);
        }
    }
    if (normalized_attribute == "tokengroups") {
        const auto expected_sid = [&]() -> std::optional<std::string> {
            if (expected.size() < 8 || static_cast<unsigned char>(expected[0]) != 1) {
                return std::nullopt;
            }
            const auto sub_authority_count = static_cast<unsigned char>(expected[1]);
            if (sub_authority_count == 0 || sub_authority_count > 15 ||
                expected.size() < 8 + static_cast<std::size_t>(sub_authority_count) * 4U) {
                return std::nullopt;
            }
            std::uint64_t authority = 0;
            for (std::size_t index = 2; index < 8; ++index) {
                authority = (authority << 8U) | static_cast<unsigned char>(expected[index]);
            }
            std::string sid = "S-1-" + std::to_string(authority);
            std::size_t offset = 8;
            for (std::uint8_t index = 0; index < sub_authority_count; ++index) {
                const auto value = static_cast<std::uint32_t>(static_cast<unsigned char>(expected[offset])) |
                                   (static_cast<std::uint32_t>(static_cast<unsigned char>(expected[offset + 1])) << 8U) |
                                   (static_cast<std::uint32_t>(static_cast<unsigned char>(expected[offset + 2])) << 16U) |
                                   (static_cast<std::uint32_t>(static_cast<unsigned char>(expected[offset + 3])) << 24U);
                sid += "-" + std::to_string(value);
                offset += 4;
            }
            return sid;
        }();
        const auto sids = token_group_sid_values(object, all_objects);
        return std::any_of(sids.begin(), sids.end(), [&](const auto& sid) {
            return equals_ascii_case(sid, expected_sid.value_or(expected));
        });
    }
    if (normalized_attribute == "objectcategory") {
        auto token = lowercase_ascii(expected);
        const auto cn = token.find("cn=");
        if (cn != std::string::npos) {
            const auto start = cn + 3;
            const auto comma = token.find(',', start);
            token = token.substr(start, comma == std::string::npos ? std::string::npos : comma - start);
        }
        token.erase(std::remove_if(token.begin(), token.end(), [](char ch) {
            return ch == '-' || ch == '_' || std::isspace(static_cast<unsigned char>(ch)) != 0;
        }), token.end());
        const auto normalized_kind = [&]() {
            auto kind = lowercase_ascii(object.kind);
            kind.erase(std::remove_if(kind.begin(), kind.end(), [](char ch) {
                return ch == '-' || ch == '_' || std::isspace(static_cast<unsigned char>(ch)) != 0;
            }), kind.end());
            return kind;
        }();
        if (token == normalized_kind) {
            return true;
        }
        if ((token == "person" || token == "user") && normalized_kind == "user") {
            return true;
        }
        if (token == "organizationalunit" && normalized_kind == "organizationalunit") {
            return true;
        }
        if (std::any_of(object.object_classes.begin(), object.object_classes.end(), [&](const auto& object_class) {
                auto normalized_class = lowercase_ascii(object_class);
                normalized_class.erase(std::remove_if(normalized_class.begin(), normalized_class.end(), [](char ch) {
                    return ch == '-' || ch == '_' || std::isspace(static_cast<unsigned char>(ch)) != 0;
                }), normalized_class.end());
                return normalized_class == token;
            })) {
            return true;
        }
    }
    const auto values = object_attribute_values(object, attribute, all_objects);
    return std::any_of(values.begin(), values.end(), [&](const auto& value) {
        return equals_ascii_case(value, expected);
    });
}

bool substring_pattern_matches_value(
    const std::string& candidate,
    const std::optional<std::string>& initial,
    const std::vector<std::string>& any,
    const std::optional<std::string>& final) {
    const auto value = lowercase_ascii(candidate);
    std::size_t offset = 0;

    if (initial.has_value()) {
        const auto prefix = lowercase_ascii(*initial);
        if (!value.starts_with(prefix)) {
            return false;
        }
        offset = prefix.size();
    }

    for (const auto& fragment : any) {
        const auto needle = lowercase_ascii(fragment);
        const auto found = value.find(needle, offset);
        if (found == std::string::npos) {
            return false;
        }
        offset = found + needle.size();
    }

    if (final.has_value()) {
        const auto suffix = lowercase_ascii(*final);
        if (!value.ends_with(suffix)) {
            return false;
        }
        return value.size() >= suffix.size() && value.size() - suffix.size() >= offset;
    }

    return initial.has_value() || !any.empty();
}

bool object_attribute_substring_matches(
    const LdapObject& object,
    const std::string& attribute,
    const std::optional<std::string>& initial,
    const std::vector<std::string>& any,
    const std::optional<std::string>& final,
    const std::vector<LdapObject>* all_objects = nullptr) {
    const auto values = object_attribute_values(object, attribute, all_objects);
    return std::any_of(values.begin(), values.end(), [&](const auto& value) {
        return substring_pattern_matches_value(value, initial, any, final);
    });
}

std::optional<std::uint64_t> parse_u64(const std::string& value) {
    try {
        std::size_t consumed = 0;
        const auto parsed = std::stoull(value, &consumed, 0);
        if (consumed == value.size()) {
            return parsed;
        }
    } catch (...) {
    }
    return std::nullopt;
}

bool object_attribute_bitwise_matches(
    const LdapObject& object,
    const std::string& attribute,
    const std::string& expected,
    bool require_all_bits,
    const std::vector<LdapObject>* all_objects = nullptr) {
    const auto expected_value = parse_u64(expected);
    if (!expected_value.has_value()) {
        return false;
    }
    for (const auto& value : object_attribute_values(object, attribute, all_objects)) {
        const auto actual = parse_u64(value);
        if (!actual.has_value()) {
            continue;
        }
        if (require_all_bits && ((*actual & *expected_value) == *expected_value)) {
            return true;
        }
        if (!require_all_bits && ((*actual & *expected_value) != 0)) {
            return true;
        }
    }
    return false;
}

std::string netbios_domain_name(const LdapDirectoryInfo& directory) {
    const auto separator = directory.dns_name.find('.');
    return uppercase_ascii(separator == std::string::npos ? directory.dns_name : directory.dns_name.substr(0, separator));
}

std::uint32_t stable_hash32(const std::string& value) {
    std::uint32_t hash = 2166136261U;
    for (const auto ch : value) {
        hash ^= static_cast<std::uint8_t>(ch);
        hash *= 16777619U;
    }
    return hash;
}

std::string default_domain_sid(const LdapDirectoryInfo& directory) {
    if (!directory.domain_sid.empty()) {
        return directory.domain_sid;
    }
    const auto domain = directory.dns_name.empty() ? std::string{"endorium.local"} : lowercase_ascii(directory.dns_name);
    const auto a = 1000U + (stable_hash32(domain + ":a") % 1000000000U);
    const auto b = 1000U + (stable_hash32(domain + ":b") % 1000000000U);
    const auto c = 1000U + (stable_hash32(domain + ":c") % 1000000000U);
    return "S-1-5-21-" + std::to_string(a) + "-" + std::to_string(b) + "-" + std::to_string(c);
}

Bytes dns_compressed_name(const std::string& value) {
    Bytes output;
    std::size_t offset = 0;
    while (offset < value.size()) {
        const auto separator = value.find('.', offset);
        const auto length = (separator == std::string::npos ? value.size() : separator) - offset;
        if (length == 0 || length > 63) {
            break;
        }
        output.push_back(static_cast<std::uint8_t>(length));
        output.insert(output.end(), value.begin() + static_cast<std::ptrdiff_t>(offset), value.begin() + static_cast<std::ptrdiff_t>(offset + length));
        if (separator == std::string::npos) {
            break;
        }
        offset = separator + 1;
    }
    output.push_back(0);
    return output;
}

std::array<std::uint8_t, 16> stable_guid_bytes(const LdapDirectoryInfo& directory) {
    std::array<std::uint8_t, 16> bytes{};
    std::uint64_t hash = 1469598103934665603ULL;
    const auto seed = directory.dns_name + "|" + directory.base_dn;
    for (unsigned char ch : seed) {
        hash ^= ch;
        hash *= 1099511628211ULL;
    }
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        bytes[index] = static_cast<std::uint8_t>((hash >> ((index % 8) * 8U)) & 0xffU);
        hash ^= static_cast<std::uint64_t>(index + 1) * 0x9e3779b97f4a7c15ULL;
        hash *= 1099511628211ULL;
    }
    return bytes;
}

std::array<std::uint8_t, 4> ipv4_bytes(const std::string& value) {
    std::array<std::uint8_t, 4> bytes{127, 0, 0, 1};
    std::stringstream stream(value);
    std::string part;
    for (std::size_t index = 0; index < bytes.size(); ++index) {
        if (!std::getline(stream, part, '.')) {
            return {127, 0, 0, 1};
        }
        try {
            const auto octet = std::stoi(part);
            if (octet < 0 || octet > 255) {
                return {127, 0, 0, 1};
            }
            bytes[index] = static_cast<std::uint8_t>(octet);
        } catch (...) {
            return {127, 0, 0, 1};
        }
    }
    if (std::getline(stream, part, '.')) {
        return {127, 0, 0, 1};
    }
    return bytes;
}

Bytes netlogon_sam_logon_response_ex(const LdapDirectoryInfo& directory) {
    constexpr std::uint16_t logon_sam_logon_response_ex = 23;
    constexpr std::uint32_t flags =
        0x00000001U |  // PDC
        0x00000004U |  // GC
        0x00000008U |  // LDAP
        0x00000010U |  // DS
        0x00000020U |  // KDC
        0x00000040U |  // time server
        0x00000080U |  // closest site
        0x00000100U |  // writable
        0x00000200U |  // good time server
        0x00001000U |  // full secret domain
        0x00002000U |  // web service capable
        0x20000000U |  // DNS controller
        0x40000000U |  // DNS domain
        0x80000000U;   // DNS forest
    constexpr std::uint32_t nt_version_1 = 0x00000001U;
    constexpr std::uint32_t nt_version_5ex = 0x00000004U;
    constexpr std::uint32_t nt_version_5ex_with_ip = 0x00000008U;

    const auto dc_fqdn = directory.domain_controller_host + "." + directory.dns_name;
    const auto netbios_domain = netbios_domain_name(directory);
    const auto netbios_dc = uppercase_ascii(directory.domain_controller_host);

    Bytes response;
    append_u16_le(response, logon_sam_logon_response_ex);
    append_u16_le(response, 0);
    append_u32_le(response, flags);
    const auto guid = stable_guid_bytes(directory);
    response.insert(response.end(), guid.begin(), guid.end());
    for (const auto& value : {
             directory.dns_name,
             directory.dns_name,
             dc_fqdn,
             netbios_domain,
             netbios_dc,
             std::string{},
             directory.site_name,
             directory.site_name,
         }) {
        const auto encoded = dns_compressed_name(value);
        response.insert(response.end(), encoded.begin(), encoded.end());
    }

    response.push_back(16);
    append_u16_le(response, 2);
    append_u16_le(response, 0);
    const auto address = ipv4_bytes(directory.domain_controller_address);
    response.insert(response.end(), address.begin(), address.end());
    response.insert(response.end(), 8, 0);

    append_u32_le(response, nt_version_1 | nt_version_5ex | nt_version_5ex_with_ip);
    append_u16_le(response, 0xffff);
    append_u16_le(response, 0xffff);
    return response;
}

Bytes netlogon_entry(const LdapDirectoryInfo& directory) {
    Bytes attribute_list;
    const auto encoded = partial_attribute_bytes("NetLogon", {netlogon_sam_logon_response_ex(directory)});
    attribute_list.insert(attribute_list.end(), encoded.begin(), encoded.end());

    Bytes payload;
    append_octet_string(payload, "");
    append_tlv(payload, 0x30, attribute_list);
    return payload;
}

struct SearchRequest {
    std::string base_dn;
    int scope{0};
    std::optional<LdapNode> filter;
    std::vector<std::string> attributes;
};

struct CompareRequest {
    std::string dn;
    std::string attribute;
    std::string value;
};

std::optional<SearchRequest> parse_search_request(const Bytes& input, const LdapNode& op_node) {
    SearchRequest request;
    const auto limit = op_node.content_offset + op_node.content_length;
    std::size_t offset = op_node.content_offset;

    auto base = read_node(input, offset, limit);
    if (!base.has_value() || base->tag != 0x04) {
        return std::nullopt;
    }
    request.base_dn = string_from_node(input, *base);
    offset = base->next_offset;

    auto scope = read_node(input, offset, limit);
    if (!scope.has_value() || scope->tag != 0x0a) {
        return std::nullopt;
    }
    request.scope = integer_from_node(input, *scope);
    offset = scope->next_offset;

    for (int skipped = 0; skipped < 4; ++skipped) {
        auto node = read_node(input, offset, limit);
        if (!node.has_value()) {
            return std::nullopt;
        }
        offset = node->next_offset;
    }

    auto filter = read_node(input, offset, limit);
    if (!filter.has_value()) {
        return std::nullopt;
    }
    request.filter = *filter;
    offset = filter->next_offset;

    auto attributes = read_node(input, offset, limit);
    if (attributes.has_value() && attributes->tag == 0x30) {
        std::size_t attribute_offset = attributes->content_offset;
        const auto attribute_limit = attributes->content_offset + attributes->content_length;
        while (attribute_offset < attribute_limit) {
            auto attribute = read_node(input, attribute_offset, attribute_limit);
            if (!attribute.has_value()) {
                return request;
            }
            if (attribute->tag == 0x04) {
                request.attributes.push_back(string_from_node(input, *attribute));
            }
            attribute_offset = attribute->next_offset;
        }
    }

    return request;
}

std::optional<LdapBindRequest> parse_bind_request(const Bytes& input, const LdapNode& op_node) {
    LdapBindRequest request;
    const auto limit = op_node.content_offset + op_node.content_length;
    std::size_t offset = op_node.content_offset;

    auto version = read_node(input, offset, limit);
    if (!version.has_value() || version->tag != 0x02) {
        return std::nullopt;
    }
    request.version = integer_from_node(input, *version);
    offset = version->next_offset;

    auto name = read_node(input, offset, limit);
    if (!name.has_value() || name->tag != 0x04) {
        return std::nullopt;
    }
    request.name = string_from_node(input, *name);
    offset = name->next_offset;

    auto authentication = read_node(input, offset, limit);
    if (!authentication.has_value()) {
        return std::nullopt;
    }
    request.auth_tag = authentication->tag;
    if (authentication->tag == 0x80) {
        request.simple_password = string_from_node(input, *authentication);
        return request;
    }
    if (authentication->tag != 0xa3) {
        return request;
    }

    std::size_t sasl_offset = authentication->content_offset;
    std::size_t sasl_limit = authentication->content_offset + authentication->content_length;
    auto mechanism = read_node(input, sasl_offset, sasl_limit);
    if (mechanism.has_value() && mechanism->tag == 0x30) {
        sasl_offset = mechanism->content_offset;
        sasl_limit = mechanism->content_offset + mechanism->content_length;
        mechanism = read_node(input, sasl_offset, sasl_limit);
    }
    if (!mechanism.has_value() || mechanism->tag != 0x04) {
        return std::nullopt;
    }
    request.sasl_mechanism = string_from_node(input, *mechanism);
    sasl_offset = mechanism->next_offset;

    auto credentials = read_node(input, sasl_offset, sasl_limit);
    if (credentials.has_value() && credentials->tag == 0x04) {
        request.sasl_credentials.assign(
            input.begin() + static_cast<std::ptrdiff_t>(credentials->content_offset),
            input.begin() + static_cast<std::ptrdiff_t>(credentials->content_offset + credentials->content_length));
    }
    return request;
}

std::optional<CompareRequest> parse_compare_request(const Bytes& input, const LdapNode& op_node) {
    const auto limit = op_node.content_offset + op_node.content_length;
    std::size_t offset = op_node.content_offset;

    auto dn = read_node(input, offset, limit);
    if (!dn.has_value() || dn->tag != 0x04) {
        return std::nullopt;
    }
    offset = dn->next_offset;

    auto assertion = read_node(input, offset, limit);
    if (!assertion.has_value() || assertion->tag != 0x30) {
        return std::nullopt;
    }
    std::size_t assertion_offset = assertion->content_offset;
    const auto assertion_limit = assertion->content_offset + assertion->content_length;
    auto attribute = read_node(input, assertion_offset, assertion_limit);
    if (!attribute.has_value() || attribute->tag != 0x04) {
        return std::nullopt;
    }
    assertion_offset = attribute->next_offset;
    auto value = read_node(input, assertion_offset, assertion_limit);
    if (!value.has_value() || value->tag != 0x04) {
        return std::nullopt;
    }

    return CompareRequest{
        string_from_node(input, *dn),
        string_from_node(input, *attribute),
        string_from_node(input, *value),
    };
}

bool filter_matches_object(
    const Bytes& input,
    const LdapNode& filter,
    const LdapObject& object,
    const std::vector<LdapObject>* all_objects = nullptr) {
    const auto limit = filter.content_offset + filter.content_length;
    if (filter.tag == 0xa0) {
        std::size_t offset = filter.content_offset;
        while (offset < limit) {
            auto child = read_node(input, offset, limit);
            if (!child.has_value()) {
                return false;
            }
            if (!filter_matches_object(input, *child, object, all_objects)) {
                return false;
            }
            offset = child->next_offset;
        }
        return true;
    }
    if (filter.tag == 0xa1) {
        std::size_t offset = filter.content_offset;
        while (offset < limit) {
            auto child = read_node(input, offset, limit);
            if (!child.has_value()) {
                return false;
            }
            if (filter_matches_object(input, *child, object, all_objects)) {
                return true;
            }
            offset = child->next_offset;
        }
        return false;
    }
    if (filter.tag == 0xa2) {
        auto child = read_node(input, filter.content_offset, limit);
        return child.has_value() && !filter_matches_object(input, *child, object, all_objects);
    }
    if (filter.tag == 0x87) {
        return object_has_attribute(object, string_from_node(input, filter), all_objects);
    }
    if (filter.tag == 0xa3) {
        std::size_t offset = filter.content_offset;
        auto attribute = read_node(input, offset, limit);
        if (!attribute.has_value()) {
            return false;
        }
        if (attribute->tag == 0x30) {
            offset = attribute->content_offset;
            const auto sequence_limit = attribute->content_offset + attribute->content_length;
            attribute = read_node(input, offset, sequence_limit);
            if (!attribute.has_value()) {
                return false;
            }
            offset = attribute->next_offset;
            auto value = read_node(input, offset, sequence_limit);
            return value.has_value() &&
                   object_attribute_equals(
                       object,
                       string_from_node(input, *attribute),
                       string_from_node(input, *value),
                       all_objects);
        }
        offset = attribute->next_offset;
        auto value = read_node(input, offset, limit);
        return value.has_value() &&
               object_attribute_equals(
                   object,
                   string_from_node(input, *attribute),
                   string_from_node(input, *value),
                   all_objects);
    }
    if (filter.tag == 0xa4) {
        auto attribute = read_node(input, filter.content_offset, limit);
        if (!attribute.has_value() || attribute->tag != 0x04) {
            return false;
        }
        auto fragments = read_node(input, attribute->next_offset, limit);
        if (!fragments.has_value() || fragments->tag != 0x30) {
            return false;
        }
        std::optional<std::string> initial;
        std::optional<std::string> final;
        std::vector<std::string> any;
        std::size_t fragment_offset = fragments->content_offset;
        const auto fragment_limit = fragments->content_offset + fragments->content_length;
        while (fragment_offset < fragment_limit) {
            auto fragment = read_node(input, fragment_offset, fragment_limit);
            if (!fragment.has_value()) {
                return false;
            }
            if (fragment->tag == 0x80) {
                initial = string_from_node(input, *fragment);
            } else if (fragment->tag == 0x81) {
                any.push_back(string_from_node(input, *fragment));
            } else if (fragment->tag == 0x82) {
                final = string_from_node(input, *fragment);
            }
            fragment_offset = fragment->next_offset;
        }
        return object_attribute_substring_matches(
            object,
            string_from_node(input, *attribute),
            initial,
            any,
            final,
            all_objects);
    }
    if (filter.tag == 0xa9) {
        std::string matching_rule;
        std::string attribute;
        std::string match_value;
        std::size_t offset = filter.content_offset;
        while (offset < limit) {
            auto field = read_node(input, offset, limit);
            if (!field.has_value()) {
                return false;
            }
            if (field->tag == 0x81) {
                matching_rule = string_from_node(input, *field);
            } else if (field->tag == 0x82) {
                attribute = string_from_node(input, *field);
            } else if (field->tag == 0x83) {
                match_value = string_from_node(input, *field);
            }
            offset = field->next_offset;
        }
        if (attribute.empty()) {
            return false;
        }
        if (matching_rule == "1.2.840.113556.1.4.803") {
            return object_attribute_bitwise_matches(object, attribute, match_value, true, all_objects);
        }
        if (matching_rule == "1.2.840.113556.1.4.804") {
            return object_attribute_bitwise_matches(object, attribute, match_value, false, all_objects);
        }
        if (matching_rule == "1.2.840.113556.1.4.1941") {
            return object_attribute_transitive_matches(object, attribute, match_value, all_objects) ||
                   object_attribute_equals(object, attribute, match_value, all_objects);
        }
        if (matching_rule.empty()) {
            return object_attribute_equals(object, attribute, match_value, all_objects);
        }
        return false;
    }

    return true;
}

bool object_in_scope(const LdapObject& object, const SearchRequest& request) {
    if (request.base_dn.empty()) {
        return false;
    }
    if (request.scope == 0) {
        return equals_ascii_case(object.dn, request.base_dn);
    }
    const auto parent = object.parent_dn.empty() ? parent_dn_from_dn(object.dn) : object.parent_dn;
    if (request.scope == 1) {
        return equals_ascii_case(parent, request.base_dn);
    }
    return equals_ascii_case(object.dn, request.base_dn) || ends_with_ascii_case(object.dn, "," + request.base_dn);
}

bool wants_no_attributes(const std::vector<std::string>& requested_attributes) {
    return requested_attributes.size() == 1 && requested_attributes.front() == "1.1";
}

bool has_requested_attribute(const std::vector<std::string>& requested_attributes, const std::string& attribute) {
    return std::any_of(requested_attributes.begin(), requested_attributes.end(), [&](const auto& requested) {
        return equals_ascii_case(requested, attribute);
    });
}

std::vector<LdapEntryAttribute> ldap_attributes_for_object(
    const LdapObject& object,
    const std::vector<std::string>& requested_attributes,
    const std::vector<LdapObject>* all_objects = nullptr) {
    if (wants_no_attributes(requested_attributes)) {
        return {};
    }

    std::vector<LdapEntryAttribute> attributes;
    const auto add_attribute = [&](const std::string& name) {
        if (std::any_of(attributes.begin(), attributes.end(), [&](const auto& existing) {
                return equals_ascii_case(existing.name, name);
            })) {
            return;
        }

        const auto binary_values = object_attribute_binary_values(object, name, all_objects);
        if (!binary_values.empty()) {
            attributes.push_back({name, {}, binary_values});
            return;
        }
        const auto values = object_attribute_values(object, name, all_objects);
        if (!values.empty()) {
            attributes.push_back({name, values, {}});
        }
    };

    const bool all_user_attributes = requested_attributes.empty() || has_requested_attribute(requested_attributes, "*");
    const bool all_operational_attributes = has_requested_attribute(requested_attributes, "+");
    const auto add_constructed_attributes = [&]() {
        add_attribute("sAMAccountType");
        add_attribute("primaryGroupToken");
        add_attribute("memberOf");
        add_attribute("tokenGroups");
    };
    if (all_user_attributes) {
        add_attribute("objectClass");
        add_attribute("distinguishedName");
        add_attribute("name");
        add_attribute("objectGUID");
        add_attribute("whenCreated");
        add_attribute("whenChanged");
        add_attribute("uSNCreated");
        add_attribute("uSNChanged");
        for (const auto& [key, value] : object.attributes) {
            (void)value;
            if (!equals_ascii_case(key, "userPasswordHash")) {
                add_attribute(key);
            }
        }
        add_constructed_attributes();
        if (!all_operational_attributes) {
            return attributes;
        }
    }

    if (all_operational_attributes && !all_user_attributes) {
        add_constructed_attributes();
    }

    for (const auto& requested : requested_attributes) {
        if (requested == "*" || requested == "+") {
            continue;
        }
        add_attribute(requested);
    }
    return attributes;
}

Bytes search_result_entry(
    const LdapObject& object,
    const std::vector<std::string>& requested_attributes,
    const std::vector<LdapObject>* all_objects = nullptr) {
    Bytes attribute_list;
    for (const auto& attribute : ldap_attributes_for_object(object, requested_attributes, all_objects)) {
        const auto encoded = attribute.binary_values.empty()
            ? partial_attribute(attribute.name, attribute.string_values)
            : partial_attribute_bytes(attribute.name, attribute.binary_values);
        attribute_list.insert(attribute_list.end(), encoded.begin(), encoded.end());
    }

    Bytes payload;
    append_octet_string(payload, object.dn);
    append_tlv(payload, 0x30, attribute_list);
    return payload;
}

std::optional<std::pair<std::string, std::string>> rdn_attribute_from_dn(const std::string& dn);

Bytes root_dse_entry(const LdapDirectoryInfo& directory) {
    const auto configuration_dn = "cn=Configuration," + directory.base_dn;
    const auto schema_dn = "cn=Schema," + configuration_dn;
    const auto dc_fqdn = directory.domain_controller_host + "." + directory.dns_name;
    const auto ds_service_name = "cn=NTDS Settings,cn=" + directory.domain_controller_host +
                                 ",cn=Servers,cn=" + directory.site_name + ",cn=Sites," + configuration_dn;

    std::vector<std::pair<std::string, std::vector<std::string>>> attributes{
        {"defaultNamingContext", {directory.base_dn}},
        {"rootDomainNamingContext", {directory.base_dn}},
        {"configurationNamingContext", {configuration_dn}},
        {"schemaNamingContext", {schema_dn}},
        {"namingContexts", {directory.base_dn, configuration_dn, schema_dn}},
        {"subschemaSubentry", {schema_dn}},
        {"dnsHostName", {dc_fqdn}},
        {"ldapServiceName", {directory.dns_name + ":" + directory.domain_controller_host + "$@" + directory.realm}},
        {"serverName", {ds_service_name}},
        {"dsServiceName", {ds_service_name}},
        {"supportedLDAPVersion", {"3", "2"}},
        {"supportedSASLMechanisms", {"GSSAPI", "GSS-SPNEGO", "EXTERNAL"}},
        {"supportedCapabilities", {"1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670", "1.2.840.113556.1.4.1791"}},
        {"supportedControl", {
            "1.2.840.113556.1.4.319",
            "1.2.840.113556.1.4.473",
            "1.2.840.113556.1.4.474",
            "1.2.840.113556.1.4.417",
            "1.2.840.113556.1.4.528",
            "1.2.840.113556.1.4.529",
            "1.2.840.113556.1.4.801",
            "1.2.840.113556.1.4.805",
            "1.2.840.113556.1.4.841",
            "1.2.840.113556.1.4.970",
            "1.2.840.113556.1.4.1338",
            "1.2.840.113556.1.4.1339",
            "1.2.840.113556.1.4.1340",
            "1.2.840.113556.1.4.1413",
            "1.2.840.113556.1.4.1504",
            "1.2.840.113556.1.4.1852",
            "1.2.840.113556.1.4.1948",
            "1.2.840.113556.1.4.2064",
            "1.2.840.113556.1.4.2065",
            "1.2.840.113556.1.4.2239",
            "2.16.840.1.113730.3.4.9",
        }},
        {"domainControllerFunctionality", {"7"}},
        {"domainFunctionality", {"7"}},
        {"forestFunctionality", {"7"}},
        {"isGlobalCatalogReady", {"TRUE"}},
        {"highestCommittedUSN", {"1"}},
        {"vendorName", {"Endorium Nexus"}},
    };

    Bytes attribute_list;
    for (const auto& [name, values] : attributes) {
        const auto encoded = partial_attribute(name, values);
        attribute_list.insert(attribute_list.end(), encoded.begin(), encoded.end());
    }

    Bytes payload;
    append_octet_string(payload, "");
    append_tlv(payload, 0x30, attribute_list);
    return payload;
}

LdapObject virtual_object(
    const std::string& dn,
    const std::string& kind,
    std::vector<std::string> classes,
    std::map<std::string, std::string> attributes = {}) {
    const auto rdn = rdn_attribute_from_dn(dn);
    if (rdn.has_value()) {
        attributes[rdn->first] = rdn->second;
    }
    attributes["distinguishedName"] = dn;
    attributes["name"] = rdn.has_value() ? rdn->second : dn;
    return LdapObject{dn, parent_dn_from_dn(dn), kind, std::move(classes), std::move(attributes)};
}

std::vector<LdapObject> virtual_ad_objects(const LdapDirectoryInfo& directory) {
    const auto configuration_dn = "cn=Configuration," + directory.base_dn;
    const auto schema_dn = "cn=Schema," + configuration_dn;
    const auto sites_dn = "cn=Sites," + configuration_dn;
    const auto site_dn = "cn=" + directory.site_name + "," + sites_dn;
    const auto servers_dn = "cn=Servers," + site_dn;
    const auto dc_server_dn = "cn=" + directory.domain_controller_host + "," + servers_dn;
    const auto ntds_settings_dn = "cn=NTDS Settings," + dc_server_dn;
    const auto partitions_dn = "cn=Partitions," + configuration_dn;
    const auto domain_cross_ref_dn = "cn=" + directory.dns_name + "," + partitions_dn;
    const auto dc_fqdn = directory.domain_controller_host + "." + directory.dns_name;
    const auto netbios_domain = netbios_domain_name(directory);
    const auto domain_sid = default_domain_sid(directory);

    return {
        virtual_object(
            directory.base_dn,
            "domainDNS",
            {"top", "domain", "domainDNS"},
            {
                {"dc", rdn_value_from_dn(directory.base_dn)},
                {"dnsRoot", directory.dns_name},
                {"nETBIOSName", netbios_domain},
                {"objectSid", domain_sid},
            }),
        virtual_object("cn=Users," + directory.base_dn, "container", {"top", "container"}),
        virtual_object("cn=Computers," + directory.base_dn, "container", {"top", "container"}),
        virtual_object("ou=Domain Controllers," + directory.base_dn, "organizationalUnit", {"top", "organizationalUnit"}),
        virtual_object("cn=System," + directory.base_dn, "container", {"top", "container"}),
        virtual_object("cn=Policies,cn=System," + directory.base_dn, "container", {"top", "container"}),
        virtual_object("cn=ForeignSecurityPrincipals," + directory.base_dn, "container", {"top", "container"}),
        virtual_object("cn=Managed Service Accounts," + directory.base_dn, "container", {"top", "container"}),
        virtual_object("cn=Program Data," + directory.base_dn, "container", {"top", "container"}),
        virtual_object(configuration_dn, "configuration", {"top", "configuration"}, {{"objectCategory", "configuration"}}),
        virtual_object(schema_dn, "dMD", {"top", "dMD"}, {{"schemaInfo", "Endorium Nexus AD schema milestone"}}),
        virtual_object(sites_dn, "sitesContainer", {"top", "sitesContainer"}),
        virtual_object(site_dn, "site", {"top", "site"}),
        virtual_object(servers_dn, "serversContainer", {"top", "serversContainer"}),
        virtual_object(
            dc_server_dn,
            "server",
            {"top", "server"},
            {{"dNSHostName", dc_fqdn}, {"serverReference", "cn=" + directory.domain_controller_host + ",ou=Domain Controllers," + directory.base_dn}}),
        virtual_object(
            ntds_settings_dn,
            "nTDSDSA",
            {"top", "applicationSettings", "nTDSDSA"},
            {{"dMDLocation", schema_dn}, {"msDS-Behavior-Version", "7"}}),
        virtual_object(partitions_dn, "crossRefContainer", {"top", "crossRefContainer"}),
        virtual_object(
            domain_cross_ref_dn,
            "crossRef",
            {"top", "crossRef"},
            {{"nCName", directory.base_dn}, {"dnsRoot", directory.dns_name}, {"nETBIOSName", netbios_domain}, {"systemFlags", "3"}}),
    };
}

std::vector<LdapObject> merge_virtual_objects(
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects) {
    auto merged = objects;
    for (auto object : virtual_ad_objects(directory)) {
        const auto exists = std::any_of(merged.begin(), merged.end(), [&](const auto& existing) {
            return equals_ascii_case(existing.dn, object.dn);
        });
        if (!exists) {
            merged.push_back(std::move(object));
        }
    }
    return merged;
}

std::optional<std::pair<std::string, std::string>> rdn_attribute_from_dn(const std::string& dn) {
    const auto first_part = dn.substr(0, dn.find(','));
    const auto equals = first_part.find('=');
    if (equals == std::string::npos || equals == 0 || equals + 1 >= first_part.size()) {
        return std::nullopt;
    }
    return std::make_pair(first_part.substr(0, equals), first_part.substr(equals + 1));
}

std::optional<std::vector<std::string>> find_attribute_values(
    const std::map<std::string, std::vector<std::string>>& attributes,
    const std::string& name) {
    for (const auto& [key, values] : attributes) {
        if (equals_ascii_case(key, name)) {
            return values;
        }
    }
    return std::nullopt;
}

std::string joined_attribute_values(const std::vector<std::string>& values) {
    std::string joined;
    for (const auto& value : values) {
        if (!joined.empty()) {
            joined.push_back(';');
        }
        joined += value;
    }
    return joined;
}

std::vector<std::string> values_from_set(const Bytes& input, const LdapNode& set_node) {
    std::vector<std::string> values;
    if (set_node.tag != 0x31) {
        return values;
    }

    std::size_t offset = set_node.content_offset;
    const auto limit = set_node.content_offset + set_node.content_length;
    while (offset < limit) {
        auto value = read_node(input, offset, limit);
        if (!value.has_value()) {
            break;
        }
        if (value->tag == 0x04) {
            values.push_back(string_from_node(input, *value));
        }
        offset = value->next_offset;
    }
    return values;
}

std::optional<std::map<std::string, std::vector<std::string>>> parse_attribute_sequence(
    const Bytes& input,
    const LdapNode& attributes_node) {
    if (attributes_node.tag != 0x30) {
        return std::nullopt;
    }

    std::map<std::string, std::vector<std::string>> attributes;
    std::size_t offset = attributes_node.content_offset;
    const auto limit = attributes_node.content_offset + attributes_node.content_length;
    while (offset < limit) {
        auto attribute = read_node(input, offset, limit);
        if (!attribute.has_value() || attribute->tag != 0x30) {
            return std::nullopt;
        }

        std::size_t attribute_offset = attribute->content_offset;
        const auto attribute_limit = attribute->content_offset + attribute->content_length;
        auto type = read_node(input, attribute_offset, attribute_limit);
        if (!type.has_value() || type->tag != 0x04) {
            return std::nullopt;
        }
        attribute_offset = type->next_offset;

        auto values = read_node(input, attribute_offset, attribute_limit);
        if (!values.has_value()) {
            return std::nullopt;
        }

        attributes[string_from_node(input, *type)] = values_from_set(input, *values);
        offset = attribute->next_offset;
    }
    return attributes;
}

bool has_object_class(const std::vector<std::string>& classes, const std::string& expected) {
    return std::any_of(classes.begin(), classes.end(), [&](const auto& value) {
        return equals_ascii_case(value, expected);
    });
}

std::string infer_object_kind(const std::string& dn, const std::vector<std::string>& classes) {
    if (has_object_class(classes, "computer")) {
        return "computer";
    }
    if (has_object_class(classes, "group")) {
        return "group";
    }
    if (has_object_class(classes, "organizationalUnit")) {
        return "organizationalUnit";
    }
    if (has_object_class(classes, "container")) {
        return "container";
    }
    if (has_object_class(classes, "user") || has_object_class(classes, "person") || has_object_class(classes, "inetOrgPerson")) {
        return "user";
    }

    const auto rdn = rdn_attribute_from_dn(dn);
    if (rdn.has_value() && equals_ascii_case(rdn->first, "ou")) {
        return "organizationalUnit";
    }
    return "container";
}

std::map<std::string, std::string> storage_attributes_from_values(
    const std::map<std::string, std::vector<std::string>>& values) {
    std::map<std::string, std::string> attributes;
    for (const auto& [key, entries] : values) {
        if (!equals_ascii_case(key, "objectClass")) {
            attributes[key] = joined_attribute_values(entries);
        }
    }
    return attributes;
}

std::optional<LdapMutation> parse_add_request(const Bytes& input, const LdapNode& op_node) {
    const auto limit = op_node.content_offset + op_node.content_length;
    std::size_t offset = op_node.content_offset;

    auto dn = read_node(input, offset, limit);
    if (!dn.has_value() || dn->tag != 0x04) {
        return std::nullopt;
    }
    offset = dn->next_offset;

    auto attributes = read_node(input, offset, limit);
    if (!attributes.has_value()) {
        return std::nullopt;
    }

    auto parsed_attributes = parse_attribute_sequence(input, *attributes);
    if (!parsed_attributes.has_value()) {
        return std::nullopt;
    }

    LdapMutation mutation;
    mutation.type = LdapMutationType::add;
    mutation.object.dn = string_from_node(input, *dn);
    mutation.object.parent_dn = parent_dn_from_dn(mutation.object.dn);
    if (const auto classes = find_attribute_values(*parsed_attributes, "objectClass")) {
        mutation.object.object_classes = *classes;
    }
    mutation.object.kind = infer_object_kind(mutation.object.dn, mutation.object.object_classes);
    mutation.object.attributes = storage_attributes_from_values(*parsed_attributes);
    if (const auto rdn = rdn_attribute_from_dn(mutation.object.dn);
        rdn.has_value() && find_object_attribute(mutation.object, rdn->first) == std::nullopt) {
        mutation.object.attributes[rdn->first] = rdn->second;
    }
    mutation.attributes = mutation.object.attributes;
    return mutation;
}

std::optional<LdapMutation> parse_modify_request(const Bytes& input, const LdapNode& op_node) {
    const auto limit = op_node.content_offset + op_node.content_length;
    std::size_t offset = op_node.content_offset;

    auto dn = read_node(input, offset, limit);
    if (!dn.has_value() || dn->tag != 0x04) {
        return std::nullopt;
    }
    offset = dn->next_offset;

    auto changes = read_node(input, offset, limit);
    if (!changes.has_value() || changes->tag != 0x30) {
        return std::nullopt;
    }

    LdapMutation mutation;
    mutation.type = LdapMutationType::modify;
    mutation.object.dn = string_from_node(input, *dn);
    mutation.object.parent_dn = parent_dn_from_dn(mutation.object.dn);

    std::size_t change_offset = changes->content_offset;
    const auto changes_limit = changes->content_offset + changes->content_length;
    while (change_offset < changes_limit) {
        auto change = read_node(input, change_offset, changes_limit);
        if (!change.has_value() || change->tag != 0x30) {
            return std::nullopt;
        }

        std::size_t field_offset = change->content_offset;
        const auto field_limit = change->content_offset + change->content_length;
        auto operation = read_node(input, field_offset, field_limit);
        if (!operation.has_value() || operation->tag != 0x0a) {
            return std::nullopt;
        }
        field_offset = operation->next_offset;

        auto partial = read_node(input, field_offset, field_limit);
        if (!partial.has_value() || partial->tag != 0x30) {
            return std::nullopt;
        }

        std::size_t partial_offset = partial->content_offset;
        const auto partial_limit = partial->content_offset + partial->content_length;
        auto attribute_type = read_node(input, partial_offset, partial_limit);
        if (!attribute_type.has_value() || attribute_type->tag != 0x04) {
            return std::nullopt;
        }
        partial_offset = attribute_type->next_offset;
        auto values = read_node(input, partial_offset, partial_limit);
        if (!values.has_value()) {
            return std::nullopt;
        }

        const auto operation_code = integer_from_node(input, *operation);
        const auto attribute_name = string_from_node(input, *attribute_type);
        const auto value_list = values_from_set(input, *values);
        mutation.attributes[attribute_name] = joined_attribute_values(value_list);
        mutation.attribute_operations[attribute_name] = operation_code;
        change_offset = change->next_offset;
    }

    mutation.object.attributes = mutation.attributes;
    return mutation;
}

std::optional<LdapMutation> parse_delete_request(const Bytes& input, const LdapNode& op_node) {
    LdapMutation mutation;
    mutation.type = LdapMutationType::remove;
    mutation.object.dn = string_from_node(input, op_node);
    mutation.object.parent_dn = parent_dn_from_dn(mutation.object.dn);
    if (mutation.object.dn.empty()) {
        return std::nullopt;
    }
    return mutation;
}

std::optional<LdapMutation> parse_modify_dn_request(const Bytes& input, const LdapNode& op_node) {
    const auto limit = op_node.content_offset + op_node.content_length;
    std::size_t offset = op_node.content_offset;

    auto entry = read_node(input, offset, limit);
    if (!entry.has_value() || entry->tag != 0x04) {
        return std::nullopt;
    }
    offset = entry->next_offset;

    auto new_rdn = read_node(input, offset, limit);
    if (!new_rdn.has_value() || new_rdn->tag != 0x04) {
        return std::nullopt;
    }
    offset = new_rdn->next_offset;

    auto delete_old_rdn = read_node(input, offset, limit);
    if (!delete_old_rdn.has_value() || delete_old_rdn->tag != 0x01) {
        return std::nullopt;
    }
    offset = delete_old_rdn->next_offset;

    std::string new_parent_dn;
    if (offset < limit) {
        auto new_superior = read_node(input, offset, limit);
        if (!new_superior.has_value() || new_superior->tag != 0x80) {
            return std::nullopt;
        }
        new_parent_dn = string_from_node(input, *new_superior);
        offset = new_superior->next_offset;
    }
    if (offset != limit) {
        return std::nullopt;
    }

    const auto previous_dn = string_from_node(input, *entry);
    const auto new_rdn_value = string_from_node(input, *new_rdn);
    if (previous_dn.empty() || new_rdn_value.empty()) {
        return std::nullopt;
    }
    if (new_parent_dn.empty()) {
        new_parent_dn = parent_dn_from_dn(previous_dn);
    }

    const auto new_dn = new_parent_dn.empty() ? new_rdn_value : new_rdn_value + "," + new_parent_dn;
    if (!is_valid_dn(previous_dn) || !is_valid_dn(new_dn)) {
        return std::nullopt;
    }

    LdapMutation mutation;
    mutation.type = LdapMutationType::rename;
    mutation.previous_dn = previous_dn;
    mutation.object.dn = new_dn;
    mutation.object.parent_dn = new_parent_dn;
    if (const auto rdn = rdn_attribute_from_dn(new_rdn_value); rdn.has_value()) {
        mutation.attributes[rdn->first] = rdn->second;
        mutation.attributes["name"] = rdn->second;
    }
    mutation.attributes["distinguishedName"] = new_dn;
    mutation.object.attributes = mutation.attributes;
    return mutation;
}

// Minimal AD schema enforcement for LDAP Add: reject objects that Windows would
// never create. Kept intentionally narrow so legitimate join-time machine and
// account objects pass while malformed writes are refused with AD result codes
// (65 objectClassViolation, 19 constraintViolation).
std::optional<std::pair<int, std::string>> validate_add_schema(const LdapObject& object) {
    if (object.object_classes.empty()) {
        return std::make_pair(65, "LDAP add requires at least one objectClass");
    }
    if (equals_ascii_case(object.kind, "computer")) {
        const auto sam = find_object_attribute(object, "sAMAccountName");
        if (!sam.has_value() || sam->second.empty()) {
            return std::make_pair(65, "computer accounts require a sAMAccountName attribute");
        }
        if (sam->second.back() != '$') {
            return std::make_pair(19, "computer sAMAccountName must end with '$'");
        }
    }
    if (const auto uac = find_object_attribute(object, "userAccountControl")) {
        if (uac->second.empty() ||
            !std::all_of(uac->second.begin(), uac->second.end(),
                         [](unsigned char ch) { return ch >= '0' && ch <= '9'; })) {
            return std::make_pair(19, "userAccountControl must be a numeric value");
        }
    }
    return std::nullopt;
}

Bytes write_response(
    int message_id,
    std::uint8_t response_tag,
    const std::optional<LdapMutation>& mutation,
    const LdapMutationHandler& mutation_handler,
    const std::string& malformed_message,
    const LdapSessionInfo* session = nullptr) {
    if (!mutation.has_value() || !is_valid_dn(mutation->object.dn)) {
        return ldap_message(message_id, response_tag, result_payload(34, malformed_message));
    }
    if (mutation->type == LdapMutationType::rename &&
        (mutation->previous_dn.empty() || !is_valid_dn(mutation->previous_dn))) {
        return ldap_message(message_id, response_tag, result_payload(34, malformed_message));
    }
    if (session != nullptr && !session->authenticated) {
        return ldap_message(message_id, response_tag, result_payload(50, "LDAP write requires an authenticated bind"));
    }
    if (mutation->type == LdapMutationType::add) {
        if (const auto violation = validate_add_schema(mutation->object)) {
            return ldap_message(message_id, response_tag, result_payload(violation->first, violation->second));
        }
    }
    if (!mutation_handler) {
        return ldap_message(message_id, response_tag, result_payload(53, "LDAP write handler unavailable"));
    }

    const auto result = mutation_handler(*mutation);
    if (!result.ok) {
        const auto code = result.result_code == 0 ? 80 : result.result_code;
        return ldap_message(message_id, response_tag, result_payload(code, result.diagnostic));
    }
    return ldap_message(message_id, response_tag, result_payload(0));
}

Bytes compare_response(
    int message_id,
    const std::optional<CompareRequest>& compare,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects) {
    if (!compare.has_value() || !is_valid_dn(compare->dn)) {
        return ldap_message(message_id, 0x6f, result_payload(34, "malformed LDAP compare request"));
    }

    const auto searchable_objects = merge_virtual_objects(directory, objects);
    const auto object = std::find_if(searchable_objects.begin(), searchable_objects.end(), [&](const auto& candidate) {
        return equals_ascii_case(candidate.dn, compare->dn);
    });
    if (object == searchable_objects.end()) {
        return ldap_message(message_id, 0x6f, result_payload(32, "LDAP object was not found"));
    }

    return ldap_message(
        message_id,
        0x6f,
        result_payload(object_attribute_equals(*object, compare->attribute, compare->value, &searchable_objects) ? 6 : 5));
}

std::vector<std::uint8_t> extract_kerberos_ap_req(const Bytes& credentials) {
    for (std::size_t offset = 0; offset < credentials.size(); ++offset) {
        auto node = read_node(credentials, offset, credentials.size());
        if (node.has_value() && node->tag == 0x6e) {
            return Bytes(
                credentials.begin() + static_cast<std::ptrdiff_t>(offset),
                credentials.begin() + static_cast<std::ptrdiff_t>(node->next_offset));
        }
    }
    return {};
}

std::string ldap_service_principal(const LdapDirectoryInfo& directory) {
    return "ldap/" + lowercase_ascii(directory.domain_controller_host + "." + directory.dns_name);
}

Bytes spnego_response_token(const Bytes& response_token) {
    Bytes neg_token_payload;
    append_tlv(neg_token_payload, 0xa0, tlv(0x0a, {0}));
    append_tlv(neg_token_payload, 0xa2, tlv(0x04, response_token));

    Bytes payload{
        0x06, 0x06, 0x2b, 0x06, 0x01, 0x05, 0x05, 0x02,
    };
    const auto neg_token_resp = tlv(0xa1, tlv(0x30, neg_token_payload));
    payload.insert(payload.end(), neg_token_resp.begin(), neg_token_resp.end());
    return tlv(0x60, payload);
}

Bytes sasl_response_token(const LdapBindRequest& request, const Bytes& response_token) {
    if (response_token.empty()) {
        return {};
    }
    if (equals_ascii_case(request.sasl_mechanism, "GSS-SPNEGO")) {
        return spnego_response_token(response_token);
    }
    return response_token;
}

Bytes bind_response(
    int message_id,
    const std::optional<LdapBindRequest>& request,
    const LdapDirectoryInfo& directory,
    const KerberosRealmInfo* kerberos_realm,
    LdapSessionInfo* session,
    const LdapSimpleBindVerifier* simple_bind_verifier) {
    if (!request.has_value()) {
        return ldap_message(message_id, 0x61, bind_response_payload(2, "malformed LDAP bind request"));
    }
    if (request->version != 2 && request->version != 3) {
        return ldap_message(message_id, 0x61, bind_response_payload(2, "unsupported LDAP bind version"));
    }
    if (request->auth_tag == 0x80) {
        if (request->name.empty() && request->simple_password.empty()) {
            if (session != nullptr) {
                session->authenticated = false;
                session->bind_dn.clear();
                session->principal.clear();
                session->sasl_mechanism.clear();
            }
            return ldap_message(message_id, 0x61, bind_response_payload(0));
        }
        if (simple_bind_verifier != nullptr) {
            const auto verified_principal = (*simple_bind_verifier)(request->name, request->simple_password);
            if (!verified_principal.has_value()) {
                if (session != nullptr) {
                    session->authenticated = false;
                    session->bind_dn = request->name;
                    session->principal.clear();
                    session->sasl_mechanism.clear();
                }
                return ldap_message(message_id, 0x61, bind_response_payload(49, "LDAP simple bind credentials are invalid"));
            }
            if (session != nullptr) {
                session->authenticated = true;
                session->bind_dn = request->name;
                session->principal = verified_principal->empty() ? request->name : *verified_principal;
                session->sasl_mechanism.clear();
            }
            return ldap_message(message_id, 0x61, bind_response_payload(0));
        }
        if (session != nullptr) {
            session->authenticated = !request->simple_password.empty();
            session->bind_dn = request->name;
            session->principal = request->name;
            session->sasl_mechanism.clear();
        }
        return ldap_message(message_id, 0x61, bind_response_payload(0));
    }
    if (request->auth_tag == 0xa3) {
        if (!is_supported_sasl_mechanism(request->sasl_mechanism)) {
            return ldap_message(message_id, 0x61, bind_response_payload(7, "unsupported LDAP SASL mechanism"));
        }
        if (kerberos_realm != nullptr && !request->sasl_credentials.empty() &&
            (equals_ascii_case(request->sasl_mechanism, "GSS-SPNEGO") ||
             equals_ascii_case(request->sasl_mechanism, "GSSAPI"))) {
            const auto ap_req = extract_kerberos_ap_req(request->sasl_credentials);
            if (ap_req.empty()) {
                return ldap_message(message_id, 0x61, bind_response_payload(49, "LDAP SASL Kerberos AP-REQ is missing"));
            }
            const auto validation =
                validate_kerberos_ap_req(ap_req, *kerberos_realm, ldap_service_principal(directory));
            if (!validation.ok) {
                return ldap_message(message_id, 0x61, bind_response_payload(49, validation.diagnostic));
            }
            if (session != nullptr) {
                session->authenticated = true;
                session->bind_dn = request->name;
                session->principal = validation.client_principal;
                session->sasl_mechanism = request->sasl_mechanism;
            }
            return ldap_message(
                message_id,
                0x61,
                bind_response_payload(0, "", sasl_response_token(*request, validation.response_token)));
        }
        if (session != nullptr) {
            session->authenticated = equals_ascii_case(request->sasl_mechanism, "EXTERNAL") ||
                                     !request->sasl_credentials.empty();
            session->bind_dn = request->name;
            session->principal = request->name;
            session->sasl_mechanism = request->sasl_mechanism;
        }
        return ldap_message(message_id, 0x61, bind_response_payload(0));
    }
    return ldap_message(message_id, 0x61, bind_response_payload(7, "unsupported LDAP authentication choice"));
}

std::vector<std::uint8_t> ldap_ad_response_impl(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects,
    const LdapMutationHandler& mutation_handler,
    const KerberosRealmInfo* kerberos_realm,
    LdapSessionInfo* session,
    const LdapSimpleBindVerifier* simple_bind_verifier) {
    int message_id = 0;
    std::uint8_t op_tag = 0;
    LdapNode op_node;
    if (!read_message_header(request, message_id, op_tag, op_node)) {
        return {};
    }

    if (op_tag == 0x60) {
        return bind_response(
            message_id,
            parse_bind_request(request, op_node),
            directory,
            kerberos_realm,
            session,
            simple_bind_verifier);
    }

    if (op_tag == 0x63) {
        const auto request_controls = read_message_controls(request);
        if (has_unsupported_critical_control(request_controls)) {
            return ldap_message(message_id, 0x65, result_payload(12, "unsupported critical LDAP control"));
        }
        const auto response_controls = search_done_controls(request_controls);
        const auto search = parse_search_request(request, op_node);
        if (!search.has_value()) {
            return ldap_message(message_id, 0x65, result_payload(2, "malformed LDAP search request"));
        }

        if (contains_ascii_case(request, "netlogon") || has_requested_attribute(search->attributes, "netlogon")) {
            Bytes response = ldap_message(message_id, 0x64, netlogon_entry(directory));
            const auto done = ldap_message_with_controls(message_id, 0x65, result_payload(0), response_controls);
            response.insert(response.end(), done.begin(), done.end());
            return response;
        }

        if (search->base_dn.empty()) {
            Bytes response = ldap_message(message_id, 0x64, root_dse_entry(directory));
            const auto done = ldap_message_with_controls(message_id, 0x65, result_payload(0), response_controls);
            response.insert(response.end(), done.begin(), done.end());
            return response;
        }

        Bytes response;
        const auto searchable_objects = merge_virtual_objects(directory, objects);
        for (const auto& object : searchable_objects) {
            if (!object_in_scope(object, *search)) {
                continue;
            }
            if (search->filter.has_value() && !filter_matches_object(request, *search->filter, object, &searchable_objects)) {
                continue;
            }
            const auto entry = ldap_message(message_id, 0x64, search_result_entry(object, search->attributes, &searchable_objects));
            response.insert(response.end(), entry.begin(), entry.end());
        }
        const auto done = ldap_message_with_controls(message_id, 0x65, result_payload(0), response_controls);
        response.insert(response.end(), done.begin(), done.end());
        return response;
    }

    if (op_tag == 0x42) {
        return {};
    }

    if (op_tag == 0x68) {
        return write_response(
            message_id,
            0x69,
            parse_add_request(request, op_node),
            mutation_handler,
            "malformed LDAP add request",
            session);
    }

    if (op_tag == 0x66) {
        return write_response(
            message_id,
            0x67,
            parse_modify_request(request, op_node),
            mutation_handler,
            "malformed LDAP modify request",
            session);
    }

    if (op_tag == 0x4a) {
        return write_response(
            message_id,
            0x6b,
            parse_delete_request(request, op_node),
            mutation_handler,
            "malformed LDAP delete request",
            session);
    }

    if (op_tag == 0x6c) {
        return write_response(
            message_id,
            0x6d,
            parse_modify_dn_request(request, op_node),
            mutation_handler,
            "malformed LDAP modifyDN request",
            session);
    }

    if (op_tag == 0x6e) {
        return compare_response(message_id, parse_compare_request(request, op_node), directory, objects);
    }

    return ldap_message(message_id, 0x65, result_payload(2, "operation is not implemented in this AD milestone"));
}

}  // namespace

std::vector<std::string> split_dn(const std::string& distinguished_name) {
    std::vector<std::string> parts;
    std::string current;
    bool escaped = false;

    for (char ch : distinguished_name) {
        if (escaped) {
            current.push_back(ch);
            escaped = false;
            continue;
        }

        if (ch == '\\') {
            escaped = true;
            current.push_back(ch);
            continue;
        }

        if (ch == ',') {
            if (!current.empty()) {
                parts.push_back(current);
                current.clear();
            }
            continue;
        }

        current.push_back(ch);
    }

    if (!current.empty()) {
        parts.push_back(current);
    }

    return parts;
}

bool is_valid_dn(const std::string& distinguished_name) {
    const auto parts = split_dn(distinguished_name);
    if (parts.empty()) {
        return false;
    }

    return std::all_of(parts.begin(), parts.end(), [](const auto& part) {
        const auto position = part.find('=');
        return position != std::string::npos && position > 0 && position < part.size() - 1;
    });
}

std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory) {
    return ldap_ad_response(request, directory, {}, {});
}

std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects) {
    return ldap_ad_response(request, directory, objects, {});
}

std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects,
    const LdapMutationHandler& mutation_handler) {
    return ldap_ad_response_impl(request, directory, objects, mutation_handler, nullptr, nullptr, nullptr);
}

std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects,
    const LdapMutationHandler& mutation_handler,
    const KerberosRealmInfo& kerberos_realm) {
    return ldap_ad_response_impl(request, directory, objects, mutation_handler, &kerberos_realm, nullptr, nullptr);
}

std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects,
    const LdapMutationHandler& mutation_handler,
    const KerberosRealmInfo& kerberos_realm,
    LdapSessionInfo* session) {
    return ldap_ad_response_impl(request, directory, objects, mutation_handler, &kerberos_realm, session, nullptr);
}

std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects,
    const LdapMutationHandler& mutation_handler,
    const KerberosRealmInfo& kerberos_realm,
    LdapSessionInfo* session,
    const LdapSimpleBindVerifier& simple_bind_verifier) {
    return ldap_ad_response_impl(
        request,
        directory,
        objects,
        mutation_handler,
        &kerberos_realm,
        session,
        &simple_bind_verifier);
}

}  // namespace nexus::protocol
