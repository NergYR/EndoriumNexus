#include "nexus/protocol/ldap.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <cstdint>
#include <map>
#include <optional>
#include <sstream>
#include <string>
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

bool ends_with_ascii_case(const std::string& value, const std::string& suffix) {
    if (value.size() < suffix.size()) {
        return false;
    }
    return equals_ascii_case(value.substr(value.size() - suffix.size()), suffix);
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
    std::stringstream stream(value);
    std::string entry;
    while (std::getline(stream, entry, ';')) {
        if (!entry.empty()) {
            values.push_back(entry);
        }
    }
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

std::vector<std::string> object_attribute_values(const LdapObject& object, const std::string& attribute) {
    if (equals_ascii_case(attribute, "objectClass")) {
        return object.object_classes;
    }
    if (equals_ascii_case(attribute, "distinguishedName") || equals_ascii_case(attribute, "dn")) {
        return {object.dn};
    }
    if (equals_ascii_case(attribute, "name")) {
        if (auto cn = find_object_attribute(object, "cn")) {
            return {cn->second};
        }
        return {rdn_value_from_dn(object.dn)};
    }
    if (equals_ascii_case(attribute, "objectCategory")) {
        return {object.kind};
    }
    if (equals_ascii_case(attribute, "userPasswordHash")) {
        return {};
    }
    if (auto attribute_value = find_object_attribute(object, attribute)) {
        return split_ldap_values(attribute_value->first, attribute_value->second);
    }
    return {};
}

bool object_has_attribute(const LdapObject& object, const std::string& attribute) {
    return !object_attribute_values(object, attribute).empty();
}

bool object_attribute_equals(const LdapObject& object, const std::string& attribute, const std::string& expected) {
    const auto values = object_attribute_values(object, attribute);
    return std::any_of(values.begin(), values.end(), [&](const auto& value) {
        return equals_ascii_case(value, expected);
    });
}

std::string netbios_domain_name(const LdapDirectoryInfo& directory) {
    const auto separator = directory.dns_name.find('.');
    return uppercase_ascii(separator == std::string::npos ? directory.dns_name : directory.dns_name.substr(0, separator));
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

bool filter_matches_object(const Bytes& input, const LdapNode& filter, const LdapObject& object) {
    const auto limit = filter.content_offset + filter.content_length;
    if (filter.tag == 0xa0) {
        std::size_t offset = filter.content_offset;
        while (offset < limit) {
            auto child = read_node(input, offset, limit);
            if (!child.has_value()) {
                return false;
            }
            if (!filter_matches_object(input, *child, object)) {
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
            if (filter_matches_object(input, *child, object)) {
                return true;
            }
            offset = child->next_offset;
        }
        return false;
    }
    if (filter.tag == 0xa2) {
        auto child = read_node(input, filter.content_offset, limit);
        return child.has_value() && !filter_matches_object(input, *child, object);
    }
    if (filter.tag == 0x87) {
        return object_has_attribute(object, string_from_node(input, filter));
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
                   object_attribute_equals(object, string_from_node(input, *attribute), string_from_node(input, *value));
        }
        offset = attribute->next_offset;
        auto value = read_node(input, offset, limit);
        return value.has_value() &&
               object_attribute_equals(object, string_from_node(input, *attribute), string_from_node(input, *value));
    }
    if (filter.tag == 0xa4) {
        auto attribute = read_node(input, filter.content_offset, limit);
        return attribute.has_value() && object_has_attribute(object, string_from_node(input, *attribute));
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

std::vector<std::pair<std::string, std::vector<std::string>>> ldap_attributes_for_object(
    const LdapObject& object,
    const std::vector<std::string>& requested_attributes) {
    if (wants_no_attributes(requested_attributes)) {
        return {};
    }

    std::vector<std::pair<std::string, std::vector<std::string>>> attributes;
    const auto add_attribute = [&](const std::string& name) {
        const auto values = object_attribute_values(object, name);
        if (!values.empty() && std::none_of(attributes.begin(), attributes.end(), [&](const auto& existing) {
                return equals_ascii_case(existing.first, name);
            })) {
            attributes.push_back({name, values});
        }
    };

    const bool all_user_attributes = requested_attributes.empty() || has_requested_attribute(requested_attributes, "*");
    if (all_user_attributes) {
        add_attribute("objectClass");
        add_attribute("distinguishedName");
        add_attribute("name");
        for (const auto& [key, value] : object.attributes) {
            (void)value;
            if (!equals_ascii_case(key, "userPasswordHash")) {
                add_attribute(key);
            }
        }
        return attributes;
    }

    for (const auto& requested : requested_attributes) {
        add_attribute(requested);
    }
    return attributes;
}

Bytes search_result_entry(const LdapObject& object, const std::vector<std::string>& requested_attributes) {
    Bytes attribute_list;
    for (const auto& [name, values] : ldap_attributes_for_object(object, requested_attributes)) {
        const auto encoded = partial_attribute(name, values);
        attribute_list.insert(attribute_list.end(), encoded.begin(), encoded.end());
    }

    Bytes payload;
    append_octet_string(payload, object.dn);
    append_tlv(payload, 0x30, attribute_list);
    return payload;
}

Bytes root_dse_entry(const LdapDirectoryInfo& directory) {
    const auto configuration_dn = "cn=Configuration," + directory.base_dn;
    const auto schema_dn = "cn=Schema," + configuration_dn;
    const auto dc_fqdn = directory.domain_controller_host + "." + directory.dns_name;

    std::vector<std::pair<std::string, std::vector<std::string>>> attributes{
        {"defaultNamingContext", {directory.base_dn}},
        {"rootDomainNamingContext", {directory.base_dn}},
        {"configurationNamingContext", {configuration_dn}},
        {"schemaNamingContext", {schema_dn}},
        {"namingContexts", {directory.base_dn, configuration_dn, schema_dn}},
        {"dnsHostName", {dc_fqdn}},
        {"ldapServiceName", {directory.dns_name + ":" + directory.domain_controller_host + "$@" + directory.realm}},
        {"serverName", {"cn=NTDS Settings,cn=" + directory.domain_controller_host + ",cn=Servers,cn=" + directory.site_name + ",cn=Sites," + configuration_dn}},
        {"supportedLDAPVersion", {"3", "2"}},
        {"supportedSASLMechanisms", {"GSSAPI", "GSS-SPNEGO", "EXTERNAL"}},
        {"supportedCapabilities", {"1.2.840.113556.1.4.800", "1.2.840.113556.1.4.1670", "1.2.840.113556.1.4.1791"}},
        {"domainControllerFunctionality", {"7"}},
        {"domainFunctionality", {"7"}},
        {"forestFunctionality", {"7"}},
        {"isGlobalCatalogReady", {"TRUE"}},
        {"highestCommittedUSN", {"1"}},
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
    return ldap_ad_response(request, directory, {});
}

std::vector<std::uint8_t> ldap_ad_response(
    const std::vector<std::uint8_t>& request,
    const LdapDirectoryInfo& directory,
    const std::vector<LdapObject>& objects) {
    int message_id = 0;
    std::uint8_t op_tag = 0;
    LdapNode op_node;
    if (!read_message_header(request, message_id, op_tag, op_node)) {
        return {};
    }

    if (op_tag == 0x60) {
        return ldap_message(message_id, 0x61, result_payload(0));
    }

    if (op_tag == 0x63) {
        const auto search = parse_search_request(request, op_node);
        if (!search.has_value()) {
            return ldap_message(message_id, 0x65, result_payload(2, "malformed LDAP search request"));
        }

        if (contains_ascii_case(request, "netlogon") || has_requested_attribute(search->attributes, "netlogon")) {
            Bytes response = ldap_message(message_id, 0x64, netlogon_entry(directory));
            const auto done = ldap_message(message_id, 0x65, result_payload(0));
            response.insert(response.end(), done.begin(), done.end());
            return response;
        }

        if (search->base_dn.empty()) {
            Bytes response = ldap_message(message_id, 0x64, root_dse_entry(directory));
            const auto done = ldap_message(message_id, 0x65, result_payload(0));
            response.insert(response.end(), done.begin(), done.end());
            return response;
        }

        Bytes response;
        for (const auto& object : objects) {
            if (!object_in_scope(object, *search)) {
                continue;
            }
            if (search->filter.has_value() && !filter_matches_object(request, *search->filter, object)) {
                continue;
            }
            const auto entry = ldap_message(message_id, 0x64, search_result_entry(object, search->attributes));
            response.insert(response.end(), entry.begin(), entry.end());
        }
        const auto done = ldap_message(message_id, 0x65, result_payload(0));
        response.insert(response.end(), done.begin(), done.end());
        return response;
    }

    if (op_tag == 0x42) {
        return {};
    }

    return ldap_message(message_id, 0x65, result_payload(2, "operation is not implemented in this AD milestone"));
}

}  // namespace nexus::protocol
