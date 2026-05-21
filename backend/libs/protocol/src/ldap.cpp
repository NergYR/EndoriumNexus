#include "nexus/protocol/ldap.hpp"

#include <algorithm>
#include <cstdint>
#include <utility>

namespace nexus::protocol {

namespace {

using Bytes = std::vector<std::uint8_t>;

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

bool read_message_header(const Bytes& input, int& message_id, std::uint8_t& op_tag) {
    std::size_t offset = 0;
    std::size_t length = 0;
    if (input.empty() || input[offset++] != 0x30 || !read_length(input, offset, length) || offset + length > input.size()) {
        return false;
    }
    if (offset >= input.size() || input[offset++] != 0x02 || !read_length(input, offset, length) || offset + length > input.size()) {
        return false;
    }
    message_id = 0;
    for (std::size_t index = 0; index < length; ++index) {
        message_id = (message_id << 8U) | input[offset++];
    }
    if (offset >= input.size()) {
        return false;
    }
    op_tag = input[offset];
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
    int message_id = 0;
    std::uint8_t op_tag = 0;
    if (!read_message_header(request, message_id, op_tag)) {
        return {};
    }

    if (op_tag == 0x60) {
        return ldap_message(message_id, 0x61, result_payload(0));
    }

    if (op_tag == 0x63) {
        Bytes response = ldap_message(message_id, 0x64, root_dse_entry(directory));
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
