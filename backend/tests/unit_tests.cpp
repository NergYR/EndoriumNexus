#include "nexus/core/models.hpp"
#include "nexus/apt/repository.hpp"
#include "nexus/jobs/queue.hpp"
#include "nexus/protocol/dhcp.hpp"
#include "nexus/protocol/dns.hpp"
#include "nexus/protocol/kerberos.hpp"
#include "nexus/protocol/ldap.hpp"
#include "nexus/protocol/repo.hpp"
#include "nexus/protocol/rpc.hpp"
#include "nexus/protocol/smb.hpp"
#include "nexus/security/ad_crypto.hpp"
#include "nexus/security/password_hasher.hpp"
#include "nexus/security/pki.hpp"
#include "nexus/security/totp.hpp"
#include "nexus/vcs/repository.hpp"

#include "apps/api/platform_state.hpp"

#include <algorithm>
#include <cassert>
#include <cstdlib>
#include <cstdint>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <initializer_list>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {

using TestBytes = std::vector<std::uint8_t>;

void append_test_length(TestBytes& output, std::size_t length) {
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

TestBytes test_tlv(std::uint8_t tag, const TestBytes& payload) {
    TestBytes output{tag};
    append_test_length(output, payload.size());
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

TestBytes test_concat(std::initializer_list<TestBytes> chunks) {
    TestBytes output;
    for (const auto& chunk : chunks) {
        output.insert(output.end(), chunk.begin(), chunk.end());
    }
    return output;
}

TestBytes test_int(int value) {
    TestBytes encoded;
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
    return test_tlv(0x02, encoded);
}

TestBytes test_seq(const TestBytes& payload) {
    return test_tlv(0x30, payload);
}

TestBytes test_ctx(int index, const TestBytes& payload) {
    return test_tlv(static_cast<std::uint8_t>(0xa0 + index), payload);
}

TestBytes test_kerberos_string(const std::string& value) {
    return test_tlv(0x1b, TestBytes(value.begin(), value.end()));
}

TestBytes test_generalized_time(const std::string& value) {
    return test_tlv(0x18, TestBytes(value.begin(), value.end()));
}

TestBytes test_octet_string(const TestBytes& value) {
    return test_tlv(0x04, value);
}

TestBytes test_ldap_string(const std::string& value) {
    return test_tlv(0x04, TestBytes(value.begin(), value.end()));
}

TestBytes test_ldap_enum(int value) {
    return test_tlv(0x0a, {static_cast<std::uint8_t>(value)});
}

TestBytes test_ldap_attribute(const std::string& name, const std::vector<std::string>& values) {
    TestBytes value_set;
    for (const auto& value : values) {
        const auto encoded_value = test_ldap_string(value);
        value_set.insert(value_set.end(), encoded_value.begin(), encoded_value.end());
    }
    return test_seq(test_concat({
        test_ldap_string(name),
        test_tlv(0x31, value_set),
    }));
}

TestBytes test_ldap_message(int message_id, std::uint8_t operation_tag, const TestBytes& operation_payload) {
    return test_seq(test_concat({
        test_int(message_id),
        test_tlv(operation_tag, operation_payload),
    }));
}

TestBytes test_ldap_simple_bind_request(
    int message_id,
    int version,
    const std::string& bind_dn,
    const std::string& password) {
    return test_ldap_message(message_id, 0x60, test_concat({
        test_int(version),
        test_ldap_string(bind_dn),
        test_tlv(0x80, TestBytes(password.begin(), password.end())),
    }));
}

TestBytes test_ldap_sasl_bind_request(
    int message_id,
    int version,
    const std::string& bind_dn,
    const std::string& mechanism,
    const TestBytes& credentials = {}) {
    TestBytes sasl_payload = test_ldap_string(mechanism);
    if (!credentials.empty()) {
        const auto encoded_credentials = test_tlv(0x04, credentials);
        sasl_payload.insert(sasl_payload.end(), encoded_credentials.begin(), encoded_credentials.end());
    }
    return test_ldap_message(message_id, 0x60, test_concat({
        test_int(version),
        test_ldap_string(bind_dn),
        test_tlv(0xa3, sasl_payload),
    }));
}

TestBytes test_spnego_token_with_ap_req(const TestBytes& ap_req) {
    return test_tlv(0x60, test_concat({
        test_tlv(0x06, {0x2b, 0x06, 0x01, 0x05, 0x05, 0x02}),
        test_tlv(0xa0, test_seq(test_tlv(0xa2, test_octet_string(ap_req)))),
    }));
}

TestBytes test_ldap_add_request(
    int message_id,
    const std::string& dn,
    const std::vector<TestBytes>& attributes) {
    TestBytes attribute_list;
    for (const auto& attribute : attributes) {
        attribute_list.insert(attribute_list.end(), attribute.begin(), attribute.end());
    }
    return test_ldap_message(message_id, 0x68, test_concat({
        test_ldap_string(dn),
        test_seq(attribute_list),
    }));
}

TestBytes test_ldap_modify_request(
    int message_id,
    const std::string& dn,
    const std::string& attribute,
    const std::vector<std::string>& values,
    int operation = 2) {
    const auto change = test_seq(test_concat({
        test_ldap_enum(operation),
        test_ldap_attribute(attribute, values),
    }));
    return test_ldap_message(message_id, 0x66, test_concat({
        test_ldap_string(dn),
        test_seq(change),
    }));
}

TestBytes test_ldap_delete_request(int message_id, const std::string& dn) {
    return test_ldap_message(message_id, 0x4a, TestBytes(dn.begin(), dn.end()));
}

TestBytes test_ldap_modify_dn_request(
    int message_id,
    const std::string& dn,
    const std::string& new_rdn,
    bool delete_old_rdn,
    const std::optional<std::string>& new_superior = std::nullopt) {
    TestBytes payload = test_concat({
        test_ldap_string(dn),
        test_ldap_string(new_rdn),
        test_tlv(0x01, {static_cast<std::uint8_t>(delete_old_rdn ? 0xff : 0x00)}),
    });
    if (new_superior.has_value()) {
        const auto encoded = test_tlv(0x80, TestBytes(new_superior->begin(), new_superior->end()));
        payload.insert(payload.end(), encoded.begin(), encoded.end());
    }
    return test_ldap_message(message_id, 0x6c, payload);
}

TestBytes test_ldap_compare_request(
    int message_id,
    const std::string& dn,
    const std::string& attribute,
    const std::string& value) {
    return test_ldap_message(message_id, 0x6e, test_concat({
        test_ldap_string(dn),
        test_seq(test_concat({
            test_ldap_string(attribute),
            test_ldap_string(value),
        })),
    }));
}

bool test_has_ldap_result_code(const TestBytes& response, int result_code) {
    for (std::size_t offset = 0; offset + 2 < response.size(); ++offset) {
        if (response[offset] == 0x0a && response[offset + 1] == 0x01 &&
            response[offset + 2] == static_cast<std::uint8_t>(result_code)) {
            return true;
        }
    }
    return false;
}

TestBytes test_ldap_search_request(
    int message_id,
    const std::string& base_dn,
    int scope,
    const std::vector<std::string>& attributes) {
    TestBytes attribute_list;
    for (const auto& attribute : attributes) {
        const auto encoded = test_ldap_string(attribute);
        attribute_list.insert(attribute_list.end(), encoded.begin(), encoded.end());
    }
    return test_ldap_message(message_id, 0x63, test_concat({
        test_ldap_string(base_dn),
        test_ldap_enum(scope),
        test_ldap_enum(0),
        test_int(0),
        test_int(0),
        test_tlv(0x01, {0}),
        test_tlv(0x87, TestBytes{'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's'}),
        test_seq(attribute_list),
    }));
}

TestBytes test_ldap_search_request_with_filter(
    int message_id,
    const std::string& base_dn,
    int scope,
    const TestBytes& filter,
    const std::vector<std::string>& attributes) {
    TestBytes attribute_list;
    for (const auto& attribute : attributes) {
        const auto encoded = test_ldap_string(attribute);
        attribute_list.insert(attribute_list.end(), encoded.begin(), encoded.end());
    }
    return test_ldap_message(message_id, 0x63, test_concat({
        test_ldap_string(base_dn),
        test_ldap_enum(scope),
        test_ldap_enum(0),
        test_int(0),
        test_int(0),
        test_tlv(0x01, {0}),
        filter,
        test_seq(attribute_list),
    }));
}

TestBytes test_ldap_default_control_value() {
    return test_seq(test_concat({test_int(1000), test_tlv(0x04, {})}));
}

TestBytes test_ldap_control(
    const std::string& control_oid,
    bool critical,
    const TestBytes& value) {
    TestBytes control_payload;
    const auto control_type = test_ldap_string(control_oid);
    control_payload.insert(control_payload.end(), control_type.begin(), control_type.end());
    if (critical) {
        const auto criticality = test_tlv(0x01, {0xff});
        control_payload.insert(control_payload.end(), criticality.begin(), criticality.end());
    }
    const auto control_value = test_tlv(0x04, value);
    control_payload.insert(control_payload.end(), control_value.begin(), control_value.end());
    return test_seq(control_payload);
}

TestBytes test_ldap_control(const std::string& control_oid, bool critical = true) {
    return test_ldap_control(control_oid, critical, test_ldap_default_control_value());
}

TestBytes test_ldap_search_request_with_controls(
    int message_id,
    const std::string& base_dn,
    int scope,
    const std::vector<std::string>& attributes,
    const std::vector<TestBytes>& controls) {
    TestBytes attribute_list;
    for (const auto& attribute : attributes) {
        const auto encoded = test_ldap_string(attribute);
        attribute_list.insert(attribute_list.end(), encoded.begin(), encoded.end());
    }
    const auto operation_payload = test_concat({
        test_ldap_string(base_dn),
        test_ldap_enum(scope),
        test_ldap_enum(0),
        test_int(0),
        test_int(0),
        test_tlv(0x01, {0}),
        test_tlv(0x87, TestBytes{'o', 'b', 'j', 'e', 'c', 't', 'C', 'l', 'a', 's', 's'}),
        test_seq(attribute_list),
    });

    TestBytes controls_payload;
    for (const auto& control : controls) {
        controls_payload.insert(controls_payload.end(), control.begin(), control.end());
    }
    return test_seq(test_concat({
        test_int(message_id),
        test_tlv(0x63, operation_payload),
        test_tlv(0xa0, controls_payload),
    }));
}

TestBytes test_ldap_search_request_with_control(
    int message_id,
    const std::string& base_dn,
    int scope,
    const std::vector<std::string>& attributes,
    const std::string& control_oid,
    bool critical = true) {
    return test_ldap_search_request_with_controls(
        message_id,
        base_dn,
        scope,
        attributes,
        {test_ldap_control(control_oid, critical)});
}

TestBytes test_ldap_extensible_filter(
    const std::string& matching_rule,
    const std::string& attribute,
    const std::string& value) {
    return test_tlv(0xa9, test_concat({
        test_tlv(0x81, TestBytes(matching_rule.begin(), matching_rule.end())),
        test_tlv(0x82, TestBytes(attribute.begin(), attribute.end())),
        test_tlv(0x83, TestBytes(value.begin(), value.end())),
    }));
}

TestBytes test_ldap_substring_filter(
    const std::string& attribute,
    const std::vector<std::pair<std::uint8_t, std::string>>& fragments) {
    TestBytes substring_payload;
    for (const auto& [tag, value] : fragments) {
        const auto encoded = test_tlv(tag, TestBytes(value.begin(), value.end()));
        substring_payload.insert(substring_payload.end(), encoded.begin(), encoded.end());
    }
    return test_tlv(0xa4, test_concat({
        test_ldap_string(attribute),
        test_seq(substring_payload),
    }));
}

TestBytes test_ldap_equality_filter(const std::string& attribute, const TestBytes& value) {
    return test_tlv(0xa3, test_concat({
        test_ldap_string(attribute),
        test_octet_string(value),
    }));
}

TestBytes test_ldap_equality_filter(const std::string& attribute, const std::string& value) {
    return test_ldap_equality_filter(attribute, TestBytes(value.begin(), value.end()));
}

TestBytes test_principal(const std::string& primary, int name_type = 1) {
    return test_seq(test_concat({
        test_ctx(0, test_int(name_type)),
        test_ctx(1, test_seq(test_kerberos_string(primary))),
    }));
}

std::vector<std::string> test_split_principal(const std::string& principal) {
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

TestBytes test_principal_from_string(const std::string& principal) {
    const auto parts = test_split_principal(principal);
    TestBytes names;
    for (const auto& part : parts) {
        const auto encoded = test_kerberos_string(part);
        names.insert(names.end(), encoded.begin(), encoded.end());
    }
    return test_seq(test_concat({
        test_ctx(0, test_int(parts.size() > 1 ? 2 : 1)),
        test_ctx(1, test_seq(names)),
    }));
}

TestBytes test_bit_string(std::uint32_t flags) {
    return test_tlv(0x03, {
        0x00,
        static_cast<std::uint8_t>((flags >> 24U) & 0xffU),
        static_cast<std::uint8_t>((flags >> 16U) & 0xffU),
        static_cast<std::uint8_t>((flags >> 8U) & 0xffU),
        static_cast<std::uint8_t>(flags & 0xffU),
    });
}

TestBytes test_encrypted_data(int enctype, const TestBytes& cipher) {
    return test_seq(test_concat({
        test_ctx(0, test_int(enctype)),
        test_ctx(2, test_octet_string(cipher)),
    }));
}

TestBytes test_pa_data(int type, const TestBytes& value) {
    return test_seq(test_concat({
        test_ctx(1, test_int(type)),
        test_ctx(2, test_octet_string(value)),
    }));
}

std::string test_bytes_to_hex(const TestBytes& bytes) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (const auto byte : bytes) {
        output << std::setw(2) << static_cast<int>(byte);
    }
    return output.str();
}

TestBytes test_encryption_key(int enctype, const TestBytes& key) {
    return test_seq(test_concat({
        test_ctx(0, test_int(enctype)),
        test_ctx(1, test_octet_string(key)),
    }));
}

TestBytes test_ticket(
    const std::string& realm,
    const std::string& service_principal,
    int enc_part_enctype,
    const TestBytes& enc_part_cipher) {
    return test_tlv(0x61, test_seq(test_concat({
        test_ctx(0, test_int(5)),
        test_ctx(1, test_kerberos_string(realm)),
        test_ctx(2, test_principal_from_string(service_principal)),
        test_ctx(3, test_encrypted_data(enc_part_enctype, enc_part_cipher)),
    })));
}

TestBytes test_enc_ticket_part(
    const std::string& realm,
    const std::string& client_principal,
    int session_key_enctype,
    const TestBytes& session_key) {
    return test_tlv(0x63, test_seq(test_concat({
        test_ctx(0, test_bit_string(0x40e10000U)),
        test_ctx(1, test_encryption_key(session_key_enctype, session_key)),
        test_ctx(2, test_kerberos_string(realm)),
        test_ctx(3, test_principal_from_string(client_principal)),
        test_ctx(4, test_seq(test_concat({test_ctx(0, test_int(0)), test_ctx(1, test_octet_string({}))}))),
        test_ctx(5, test_generalized_time("20260530120000Z")),
        test_ctx(6, test_generalized_time("20260530120000Z")),
        test_ctx(7, test_generalized_time("20260530220000Z")),
    })));
}

TestBytes test_authenticator(const std::string& realm, const std::string& client_principal) {
    return test_tlv(0x62, test_seq(test_concat({
        test_ctx(0, test_int(5)),
        test_ctx(1, test_kerberos_string(realm)),
        test_ctx(2, test_principal_from_string(client_principal)),
        test_ctx(4, test_int(0)),
        test_ctx(5, test_generalized_time("20260530120000Z")),
    })));
}

TestBytes test_ap_req(
    const TestBytes& ticket,
    int authenticator_enctype,
    const TestBytes& authenticator_cipher,
    std::uint32_t ap_options = 0) {
    return test_tlv(0x6e, test_seq(test_concat({
        test_ctx(0, test_int(5)),
        test_ctx(1, test_int(14)),
        test_ctx(2, test_bit_string(ap_options)),
        test_ctx(3, ticket),
        test_ctx(4, test_encrypted_data(authenticator_enctype, authenticator_cipher)),
    })));
}

TestBytes test_as_req(
    const std::string& principal,
    const std::string& realm,
    bool include_encrypted_timestamp = false,
    const TestBytes& encrypted_timestamp_cipher = {},
    int principal_name_type = 1,
    const std::vector<int>& requested_etypes = {18, 17}) {
    TestBytes etype_values;
    for (const auto etype : requested_etypes) {
        const auto encoded = test_int(etype);
        etype_values.insert(etype_values.end(), encoded.begin(), encoded.end());
    }
    TestBytes body_payload = test_concat({
        test_ctx(1, test_principal(principal, principal_name_type)),
        test_ctx(2, test_kerberos_string(realm)),
        test_ctx(7, test_int(42)),
        test_ctx(8, test_seq(etype_values)),
    });

    TestBytes request_payload = test_concat({
        test_ctx(1, test_int(5)),
        test_ctx(2, test_int(10)),
    });
    if (include_encrypted_timestamp) {
        const auto encrypted_timestamp = test_encrypted_data(18, encrypted_timestamp_cipher);
        const auto padata = test_seq(test_pa_data(2, encrypted_timestamp));
        const auto with_padata = test_ctx(3, padata);
        request_payload.insert(request_payload.end(), with_padata.begin(), with_padata.end());
    }
    const auto body = test_ctx(4, test_seq(body_payload));
    request_payload.insert(request_payload.end(), body.begin(), body.end());
    return test_tlv(0x6a, test_seq(request_payload));
}

TestBytes test_tgs_req(
    const std::string& service_principal,
    const std::string& realm,
    const TestBytes& ap_req) {
    const TestBytes body_payload = test_concat({
        test_ctx(2, test_kerberos_string(realm)),
        test_ctx(3, test_principal_from_string(service_principal)),
        test_ctx(7, test_int(84)),
        test_ctx(8, test_seq(test_concat({test_int(18), test_int(17)}))),
    });
    return test_tlv(0x6c, test_seq(test_concat({
        test_ctx(1, test_int(5)),
        test_ctx(2, test_int(12)),
        test_ctx(3, test_seq(test_pa_data(1, ap_req))),
        test_ctx(4, test_seq(body_payload)),
    })));
}

void test_rpc_write_u16(TestBytes& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

void test_rpc_write_u32(TestBytes& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
}

std::uint16_t test_rpc_read_u16(const TestBytes& input, std::size_t offset) {
    return static_cast<std::uint16_t>(input[offset]) |
           static_cast<std::uint16_t>(input[offset + 1] << 8U);
}

std::uint32_t test_rpc_read_u32(const TestBytes& input, std::size_t offset) {
    return static_cast<std::uint32_t>(input[offset]) |
           (static_cast<std::uint32_t>(input[offset + 1]) << 8U) |
           (static_cast<std::uint32_t>(input[offset + 2]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 3]) << 24U);
}

std::uint64_t test_rpc_read_u64(const TestBytes& input, std::size_t offset) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8; ++index) {
        value |= static_cast<std::uint64_t>(input[offset + index]) << (index * 8U);
    }
    return value;
}

struct TestPacBuffer {
    std::uint32_t type{0};
    TestBytes data;
};

std::vector<TestPacBuffer> test_parse_pac_buffers(const TestBytes& pac) {
    std::vector<TestPacBuffer> buffers;
    if (pac.size() < 8) {
        return buffers;
    }
    const auto count = test_rpc_read_u32(pac, 0);
    for (std::uint32_t index = 0; index < count; ++index) {
        const auto descriptor_offset = 8 + static_cast<std::size_t>(index) * 16;
        if (descriptor_offset + 16 > pac.size()) {
            return {};
        }
        const auto type = test_rpc_read_u32(pac, descriptor_offset);
        const auto size = test_rpc_read_u32(pac, descriptor_offset + 4);
        const auto data_offset = test_rpc_read_u64(pac, descriptor_offset + 8);
        if (data_offset > pac.size() || size > pac.size() - static_cast<std::size_t>(data_offset)) {
            return {};
        }
        buffers.push_back({
            type,
            TestBytes(
                pac.begin() + static_cast<std::ptrdiff_t>(data_offset),
                pac.begin() + static_cast<std::ptrdiff_t>(data_offset + size)),
        });
    }
    return buffers;
}

void test_write_u16_be(TestBytes& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void test_write_u32_be(TestBytes& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

std::uint16_t test_read_u16_be(const TestBytes& input, std::size_t offset) {
    return static_cast<std::uint16_t>((input[offset] << 8U) | input[offset + 1]);
}

std::uint32_t test_read_u32_be(const TestBytes& input, std::size_t offset) {
    return (static_cast<std::uint32_t>(input[offset]) << 24U) |
           (static_cast<std::uint32_t>(input[offset + 1]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 2]) << 8U) |
           static_cast<std::uint32_t>(input[offset + 3]);
}

void test_dns_write_name(TestBytes& output, const std::string& name) {
    std::size_t start = 0;
    while (start < name.size()) {
        const auto dot = name.find('.', start);
        const auto end = dot == std::string::npos ? name.size() : dot;
        output.push_back(static_cast<std::uint8_t>(end - start));
        output.insert(
            output.end(),
            name.begin() + static_cast<std::ptrdiff_t>(start),
            name.begin() + static_cast<std::ptrdiff_t>(end));
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    output.push_back(0);
}

TestBytes test_dns_update_query(std::uint16_t transaction_id, const std::string& zone_name) {
    TestBytes output;
    test_write_u16_be(output, transaction_id);
    test_write_u16_be(output, static_cast<std::uint16_t>(5U << 11U));
    test_write_u16_be(output, 1);
    test_write_u16_be(output, 0);
    test_write_u16_be(output, 1);
    test_write_u16_be(output, 0);
    test_dns_write_name(output, zone_name);
    test_write_u16_be(output, 6);
    test_write_u16_be(output, 1);
    test_dns_write_name(output, "ws99." + zone_name);
    test_write_u16_be(output, 1);
    test_write_u16_be(output, 1);
    test_write_u32_be(output, 300);
    test_write_u16_be(output, 4);
    output.insert(output.end(), {10, 10, 10, 99});
    return output;
}

TestBytes test_dns_standard_query(std::uint16_t transaction_id, const std::string& name, std::uint16_t qtype) {
    TestBytes output;
    test_write_u16_be(output, transaction_id);
    test_write_u16_be(output, 0x0100);  // standard query, recursion desired
    test_write_u16_be(output, 1);       // qdcount
    test_write_u16_be(output, 0);       // ancount
    test_write_u16_be(output, 0);       // nscount
    test_write_u16_be(output, 0);       // arcount
    test_dns_write_name(output, name);
    test_write_u16_be(output, qtype);
    test_write_u16_be(output, 1);       // class IN
    return output;
}

TestBytes test_kpasswd_request(
    const TestBytes& ap_req,
    const TestBytes& encrypted_payload,
    std::uint16_t version = 0xff80U) {
    TestBytes output;
    test_write_u16_be(output, static_cast<std::uint16_t>(6 + ap_req.size() + encrypted_payload.size()));
    test_write_u16_be(output, version);
    test_write_u16_be(output, static_cast<std::uint16_t>(ap_req.size()));
    output.insert(output.end(), ap_req.begin(), ap_req.end());
    output.insert(output.end(), encrypted_payload.begin(), encrypted_payload.end());
    return output;
}

TestBytes test_kpasswd_change_data(const std::string& password) {
    const TestBytes password_bytes(password.begin(), password.end());
    return test_seq(test_ctx(0, test_octet_string(password_bytes)));
}

TestBytes test_enc_krb_priv_part(const TestBytes& user_data) {
    return test_tlv(0x7c, test_seq(test_concat({
        test_ctx(0, test_octet_string(user_data)),
        test_ctx(1, test_generalized_time("20260530120000Z")),
        test_ctx(2, test_int(0)),
    })));
}

TestBytes test_krb_priv(const TestBytes& encrypted_payload, int enctype = 18) {
    return test_tlv(0x75, test_seq(test_concat({
        test_ctx(0, test_int(5)),
        test_ctx(1, test_int(21)),
        test_ctx(3, test_encrypted_data(enctype, encrypted_payload)),
    })));
}

TestBytes test_kerberos_tcp_frame(const TestBytes& payload) {
    TestBytes output;
    test_write_u32_be(output, static_cast<std::uint32_t>(payload.size()));
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

TestBytes test_rpc_header(std::uint8_t ptype, std::uint32_t call_id, const TestBytes& body) {
    TestBytes output{5, 0, ptype, 0x03, 0x10, 0, 0, 0};
    test_rpc_write_u16(output, static_cast<std::uint16_t>(16 + body.size()));
    test_rpc_write_u16(output, 0);
    test_rpc_write_u32(output, call_id);
    output.insert(output.end(), body.begin(), body.end());
    return output;
}

TestBytes test_rpc_ndr_syntax() {
    return {
        0x04, 0x5d, 0x88, 0x8a, 0xeb, 0x1c, 0xc9, 0x11,
        0x9f, 0xe8, 0x08, 0x00, 0x2b, 0x10, 0x48, 0x60,
        0x02, 0x00, 0x00, 0x00,
    };
}

TestBytes test_rpc_bind_with_abstract_syntax(const TestBytes& abstract_syntax, std::uint32_t call_id) {
    TestBytes body;
    test_rpc_write_u16(body, 4280);
    test_rpc_write_u16(body, 4280);
    test_rpc_write_u32(body, 0);
    body.insert(body.end(), {1, 0, 0, 0});
    test_rpc_write_u16(body, 0);
    body.push_back(1);
    body.push_back(0);
    body.insert(body.end(), abstract_syntax.begin(), abstract_syntax.end());
    test_rpc_write_u32(body, 3);
    const auto transfer = test_rpc_ndr_syntax();
    body.insert(body.end(), transfer.begin(), transfer.end());
    return test_rpc_header(0x0b, call_id, body);
}

TestBytes test_rpc_epm_bind() {
    return test_rpc_bind_with_abstract_syntax({
        0x08, 0x83, 0xaf, 0xe1, 0x1f, 0x5d, 0xc9, 0x11,
        0x91, 0xa4, 0x08, 0x00, 0x2b, 0x14, 0xa0, 0xfa,
    }, 7);
}

TestBytes test_rpc_netlogon_bind() {
    return test_rpc_bind_with_abstract_syntax({
        0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
        0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb,
    }, 9);
}

TestBytes test_rpc_samr_bind() {
    return test_rpc_bind_with_abstract_syntax({
        0x78, 0x57, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
        0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0x89, 0xac,
    }, 10);
}

TestBytes test_rpc_srvsvc_bind() {
    return test_rpc_bind_with_abstract_syntax({
        0xc8, 0x4f, 0x32, 0x4b, 0x70, 0x16, 0xd3, 0x01,
        0x12, 0x78, 0x5a, 0x47, 0xbf, 0x6e, 0xe1, 0x88,
    }, 11);
}

TestBytes test_rpc_wkssvc_bind() {
    return test_rpc_bind_with_abstract_syntax({
        0x98, 0xd0, 0xff, 0x6b, 0x12, 0xa1, 0x10, 0x36,
        0x98, 0x33, 0x46, 0xc3, 0xf8, 0x7e, 0x34, 0x5a,
    }, 12);
}

TestBytes test_rpc_request_opnum(std::uint16_t opnum, std::uint32_t call_id, const TestBytes& stub = {}) {
    TestBytes body;
    test_rpc_write_u32(body, static_cast<std::uint32_t>(stub.size()));
    test_rpc_write_u16(body, 0);
    test_rpc_write_u16(body, opnum);
    body.insert(body.end(), stub.begin(), stub.end());
    return test_rpc_header(0x00, call_id, body);
}

TestBytes test_rpc_request() {
    return test_rpc_request_opnum(3, 8);
}

TestBytes test_rpc_netlogon_uuid_stub() {
    return {
        0x78, 0x56, 0x34, 0x12, 0x34, 0x12, 0xcd, 0xab,
        0xef, 0x00, 0x01, 0x23, 0x45, 0x67, 0xcf, 0xfb,
    };
}

TestBytes test_rpc_ndr_utf16_string(const std::string& value) {
    TestBytes output;
    const auto count = static_cast<std::uint32_t>(value.size() + 1);
    test_rpc_write_u32(output, count);
    test_rpc_write_u32(output, 0);
    test_rpc_write_u32(output, count);
    for (const auto ch : value) {
        output.push_back(static_cast<std::uint8_t>(ch));
        output.push_back(0);
    }
    output.push_back(0);
    output.push_back(0);
    while (output.size() % 4 != 0) {
        output.push_back(0);
    }
    return output;
}

TestBytes test_samr_user_password_blob(const std::string& password) {
    TestBytes output(516, 0);
    TestBytes password_bytes;
    for (const auto ch : password) {
        password_bytes.push_back(static_cast<std::uint8_t>(ch));
        password_bytes.push_back(0);
    }
    const auto password_offset = 512 - password_bytes.size();
    std::copy(password_bytes.begin(), password_bytes.end(), output.begin() + static_cast<std::ptrdiff_t>(password_offset));
    const auto length = static_cast<std::uint32_t>(password_bytes.size());
    output[512] = static_cast<std::uint8_t>(length & 0xffU);
    output[513] = static_cast<std::uint8_t>((length >> 8U) & 0xffU);
    output[514] = static_cast<std::uint8_t>((length >> 16U) & 0xffU);
    output[515] = static_cast<std::uint8_t>((length >> 24U) & 0xffU);
    return output;
}

TestBytes test_rpc_sid(const std::vector<std::uint32_t>& sub_authorities) {
    TestBytes output{1, static_cast<std::uint8_t>(sub_authorities.size()), 0, 0, 0, 0, 0, 5};
    for (const auto value : sub_authorities) {
        test_rpc_write_u32(output, value);
    }
    return output;
}

TestBytes test_netlogon_req_challenge_stub(const std::string& computer_name, const TestBytes& client_challenge) {
    auto output = test_rpc_ndr_utf16_string("\\\\DC1");
    const auto computer = test_rpc_ndr_utf16_string(computer_name);
    output.insert(output.end(), computer.begin(), computer.end());
    output.insert(output.end(), client_challenge.begin(), client_challenge.end());
    return output;
}

TestBytes test_netlogon_authenticate3_stub(
    const std::string& account_name,
    const std::string& computer_name,
    const TestBytes& client_credential,
    std::uint32_t flags) {
    auto output = test_rpc_ndr_utf16_string("\\\\DC1");
    const auto account = test_rpc_ndr_utf16_string(account_name);
    output.insert(output.end(), account.begin(), account.end());
    test_rpc_write_u32(output, 2);
    const auto computer = test_rpc_ndr_utf16_string(computer_name);
    output.insert(output.end(), computer.begin(), computer.end());
    output.insert(output.end(), client_credential.begin(), client_credential.end());
    test_rpc_write_u32(output, flags);
    return output;
}

TestBytes test_netlogon_authenticate_stub(
    const std::string& account_name,
    const std::string& computer_name,
    const TestBytes& client_credential) {
    auto output = test_rpc_ndr_utf16_string("\\\\DC1");
    const auto account = test_rpc_ndr_utf16_string(account_name);
    output.insert(output.end(), account.begin(), account.end());
    test_rpc_write_u32(output, 2);
    const auto computer = test_rpc_ndr_utf16_string(computer_name);
    output.insert(output.end(), computer.begin(), computer.end());
    output.insert(output.end(), client_credential.begin(), client_credential.end());
    return output;
}

TestBytes test_netlogon_secure_channel_stub(
    const std::string& account_name,
    const std::string& computer_name,
    const TestBytes& authenticator_credential,
    std::uint32_t timestamp,
    const TestBytes& encrypted_password = TestBytes(516, 0)) {
    auto output = test_rpc_ndr_utf16_string("\\\\DC1");
    const auto account = test_rpc_ndr_utf16_string(account_name);
    output.insert(output.end(), account.begin(), account.end());
    test_rpc_write_u32(output, 2);
    const auto computer = test_rpc_ndr_utf16_string(computer_name);
    output.insert(output.end(), computer.begin(), computer.end());
    output.insert(output.end(), authenticator_credential.begin(), authenticator_credential.end());
    test_rpc_write_u32(output, timestamp);
    output.insert(output.end(), encrypted_password.begin(), encrypted_password.end());
    return output;
}

TestBytes test_netlogon_capabilities_stub(
    const std::string& account_name,
    const std::string& computer_name,
    const TestBytes& authenticator_credential,
    std::uint32_t timestamp,
    std::uint32_t query_level) {
    auto output = test_netlogon_secure_channel_stub(
        account_name,
        computer_name,
        authenticator_credential,
        timestamp,
        {});
    test_rpc_write_u32(output, query_level);
    return output;
}

TestBytes test_netlogon_control_stub(std::uint32_t function_code, std::uint32_t query_level) {
    auto output = test_rpc_ndr_utf16_string("\\\\DC1");
    test_rpc_write_u32(output, function_code);
    test_rpc_write_u32(output, query_level);
    return output;
}

TestBytes test_netlogon_sam_logon_stub(
    const std::string& machine_account_name,
    const std::string& computer_name,
    const std::string& user_name,
    const TestBytes& authenticator_credential,
    std::uint32_t timestamp,
    std::uint32_t validation_level,
    std::uint32_t extra_flags,
    bool include_authenticator,
    const TestBytes& server_challenge = {},
    const TestBytes& ntlm_response = {}) {
    auto output = test_rpc_ndr_utf16_string("\\\\DC1");
    const auto account = test_rpc_ndr_utf16_string(machine_account_name);
    output.insert(output.end(), account.begin(), account.end());
    test_rpc_write_u32(output, 2);
    const auto computer = test_rpc_ndr_utf16_string(computer_name);
    output.insert(output.end(), computer.begin(), computer.end());
    if (include_authenticator) {
        output.insert(output.end(), authenticator_credential.begin(), authenticator_credential.end());
        test_rpc_write_u32(output, timestamp);
    }
    const auto domain = test_rpc_ndr_utf16_string("ENDORIUM");
    output.insert(output.end(), domain.begin(), domain.end());
    const auto user = test_rpc_ndr_utf16_string(user_name);
    output.insert(output.end(), user.begin(), user.end());
    const auto workstation = test_rpc_ndr_utf16_string(computer_name);
    output.insert(output.end(), workstation.begin(), workstation.end());
    output.insert(output.end(), server_challenge.begin(), server_challenge.end());
    output.insert(output.end(), ntlm_response.begin(), ntlm_response.end());
    test_rpc_write_u32(output, 2);
    test_rpc_write_u32(output, validation_level);
    test_rpc_write_u32(output, extra_flags);
    return output;
}

void test_smb2_write_u64(TestBytes& output, std::uint64_t value) {
    for (int index = 0; index < 8; ++index) {
        output.push_back(static_cast<std::uint8_t>((value >> (index * 8U)) & 0xffU));
    }
}

TestBytes test_smb2_netbios_frame(const TestBytes& payload) {
    TestBytes output{
        0x00,
        static_cast<std::uint8_t>((payload.size() >> 16U) & 0xffU),
        static_cast<std::uint8_t>((payload.size() >> 8U) & 0xffU),
        static_cast<std::uint8_t>(payload.size() & 0xffU),
    };
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

TestBytes test_smb2_header(
    std::uint16_t command,
    std::uint64_t message_id,
    const TestBytes& body,
    std::uint32_t tree_id = 0,
    std::uint64_t session_id = 0) {
    TestBytes output{0xfe, 'S', 'M', 'B'};
    test_rpc_write_u16(output, 64);
    test_rpc_write_u16(output, 0);
    test_rpc_write_u32(output, 0);
    test_rpc_write_u16(output, command);
    test_rpc_write_u16(output, 1);
    test_rpc_write_u32(output, 0);
    test_rpc_write_u32(output, 0);
    test_smb2_write_u64(output, message_id);
    test_rpc_write_u32(output, 0);
    test_rpc_write_u32(output, tree_id);
    test_smb2_write_u64(output, session_id);
    output.insert(output.end(), 16, 0);
    output.insert(output.end(), body.begin(), body.end());
    return output;
}

TestBytes test_smb2_negotiate_request() {
    TestBytes body;
    test_rpc_write_u16(body, 36);
    test_rpc_write_u16(body, 5);
    test_rpc_write_u16(body, 1);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u32(body, 0);
    body.insert(body.end(), 16, 0x42);
    test_rpc_write_u32(body, 0);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u16(body, 0);
    for (const auto dialect : {0x0202, 0x0210, 0x0300, 0x0302, 0x0311}) {
        test_rpc_write_u16(body, static_cast<std::uint16_t>(dialect));
    }
    return test_smb2_netbios_frame(test_smb2_header(0, 99, body));
}

void test_smb2_write_utf16le(TestBytes& output, const std::string& value) {
    for (const auto ch : value) {
        output.push_back(static_cast<std::uint8_t>(ch));
        output.push_back(0);
    }
}

TestBytes test_smb2_session_setup_request(
    const TestBytes& security_blob = {},
    std::uint64_t message_id = 100,
    std::uint64_t session_id = 0) {
    TestBytes body;
    test_rpc_write_u16(body, 25);
    body.push_back(0);
    body.push_back(1);
    test_rpc_write_u32(body, 0);
    test_rpc_write_u32(body, 0);
    test_rpc_write_u16(body, 88);
    test_rpc_write_u16(body, static_cast<std::uint16_t>(security_blob.size()));
    test_smb2_write_u64(body, 0);
    body.insert(body.end(), security_blob.begin(), security_blob.end());
    return test_smb2_netbios_frame(test_smb2_header(1, message_id, body, 0, session_id));
}

TestBytes test_smb2_tree_connect_request(
    const std::string& path,
    std::uint64_t session_id,
    std::uint64_t message_id = 101) {
    TestBytes path_bytes;
    test_smb2_write_utf16le(path_bytes, path);
    TestBytes body;
    test_rpc_write_u16(body, 9);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u16(body, 72);
    test_rpc_write_u16(body, static_cast<std::uint16_t>(path_bytes.size()));
    body.insert(body.end(), path_bytes.begin(), path_bytes.end());
    return test_smb2_netbios_frame(test_smb2_header(3, message_id, body, 0, session_id));
}

TestBytes test_smb2_create_request(
    const std::string& name,
    std::uint32_t tree_id,
    std::uint64_t session_id,
    std::uint64_t message_id = 104) {
    TestBytes name_bytes;
    test_smb2_write_utf16le(name_bytes, name);
    TestBytes body;
    test_rpc_write_u16(body, 57);
    body.push_back(0);
    body.push_back(0);
    test_rpc_write_u32(body, 2);
    test_smb2_write_u64(body, 0);
    test_smb2_write_u64(body, 0);
    test_rpc_write_u32(body, 0x0012019fU);
    test_rpc_write_u32(body, 0);
    test_rpc_write_u32(body, 7);
    test_rpc_write_u32(body, 1);
    test_rpc_write_u32(body, 0x40);
    test_rpc_write_u16(body, 120);
    test_rpc_write_u16(body, static_cast<std::uint16_t>(name_bytes.size()));
    test_rpc_write_u32(body, 0);
    test_rpc_write_u32(body, 0);
    body.insert(body.end(), name_bytes.begin(), name_bytes.end());
    return test_smb2_netbios_frame(test_smb2_header(5, message_id, body, tree_id, session_id));
}

TestBytes test_smb2_ioctl_request(
    const TestBytes& input,
    std::uint32_t tree_id,
    std::uint64_t session_id,
    std::uint64_t file_id_persistent,
    std::uint64_t file_id_volatile,
    std::uint64_t message_id = 106,
    std::uint32_t max_output_response = 4280) {
    TestBytes body;
    test_rpc_write_u16(body, 57);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u32(body, 0x0011c017U);
    test_smb2_write_u64(body, file_id_persistent);
    test_smb2_write_u64(body, file_id_volatile);
    test_rpc_write_u32(body, 120);
    test_rpc_write_u32(body, static_cast<std::uint32_t>(input.size()));
    test_rpc_write_u32(body, 0);
    test_rpc_write_u32(body, 0);
    test_rpc_write_u32(body, 0);
    test_rpc_write_u32(body, max_output_response);
    test_rpc_write_u32(body, 1);
    test_rpc_write_u32(body, 0);
    body.insert(body.end(), input.begin(), input.end());
    return test_smb2_netbios_frame(test_smb2_header(11, message_id, body, tree_id, session_id));
}

TestBytes test_smb2_query_directory_request(
    std::uint32_t tree_id,
    std::uint64_t session_id,
    std::uint64_t file_id_persistent,
    std::uint64_t file_id_volatile,
    std::uint64_t message_id = 110) {
    TestBytes body;
    test_rpc_write_u16(body, 33);
    body.push_back(1);
    body.push_back(0);
    test_rpc_write_u32(body, 0);
    test_smb2_write_u64(body, file_id_persistent);
    test_smb2_write_u64(body, file_id_volatile);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u32(body, 4096);
    return test_smb2_netbios_frame(test_smb2_header(14, message_id, body, tree_id, session_id));
}

TestBytes test_smb2_change_notify_request(
    std::uint32_t tree_id,
    std::uint64_t session_id,
    std::uint64_t file_id_persistent,
    std::uint64_t file_id_volatile,
    std::uint64_t message_id = 143) {
    TestBytes body;
    test_rpc_write_u16(body, 32);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u32(body, 4096);
    test_smb2_write_u64(body, file_id_persistent);
    test_smb2_write_u64(body, file_id_volatile);
    test_rpc_write_u32(body, 0x0000017fU);
    test_rpc_write_u32(body, 0);
    return test_smb2_netbios_frame(test_smb2_header(15, message_id, body, tree_id, session_id));
}

TestBytes test_smb2_query_info_request(
    std::uint32_t tree_id,
    std::uint64_t session_id,
    std::uint64_t file_id_persistent,
    std::uint64_t file_id_volatile,
    std::uint8_t file_info_class = 5,
    std::uint64_t message_id = 111,
    std::uint8_t info_type = 1) {
    TestBytes body;
    test_rpc_write_u16(body, 41);
    body.push_back(info_type);
    body.push_back(file_info_class);
    test_rpc_write_u32(body, 4096);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u32(body, 0);
    test_rpc_write_u32(body, 0);
    test_rpc_write_u32(body, 0);
    test_smb2_write_u64(body, file_id_persistent);
    test_smb2_write_u64(body, file_id_volatile);
    return test_smb2_netbios_frame(test_smb2_header(16, message_id, body, tree_id, session_id));
}

TestBytes test_smb2_cancel_request(std::uint64_t session_id, std::uint64_t message_id = 144) {
    TestBytes body;
    test_rpc_write_u16(body, 4);
    test_rpc_write_u16(body, 0);
    return test_smb2_netbios_frame(test_smb2_header(12, message_id, body, 0, session_id));
}

TestBytes test_smb2_read_request(
    std::uint32_t tree_id,
    std::uint64_t session_id,
    std::uint64_t file_id_persistent,
    std::uint64_t file_id_volatile,
    std::uint32_t length = 4096,
    std::uint64_t offset = 0,
    std::uint64_t message_id = 112) {
    TestBytes body;
    test_rpc_write_u16(body, 49);
    body.push_back(0);
    body.push_back(0);
    test_rpc_write_u32(body, length);
    test_smb2_write_u64(body, offset);
    test_smb2_write_u64(body, file_id_persistent);
    test_smb2_write_u64(body, file_id_volatile);
    test_rpc_write_u32(body, 1);
    test_rpc_write_u32(body, 0);
    test_rpc_write_u32(body, 0);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u16(body, 0);
    return test_smb2_netbios_frame(test_smb2_header(8, message_id, body, tree_id, session_id));
}

TestBytes test_smb2_write_request(
    const TestBytes& data,
    std::uint32_t tree_id,
    std::uint64_t session_id,
    std::uint64_t file_id_persistent,
    std::uint64_t file_id_volatile,
    std::uint64_t message_id = 113) {
    TestBytes body;
    test_rpc_write_u16(body, 49);
    test_rpc_write_u16(body, 112);
    test_rpc_write_u32(body, static_cast<std::uint32_t>(data.size()));
    test_smb2_write_u64(body, 0);
    test_smb2_write_u64(body, file_id_persistent);
    test_smb2_write_u64(body, file_id_volatile);
    test_rpc_write_u32(body, 0);
    test_rpc_write_u32(body, 0);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u32(body, 0);
    body.insert(body.end(), data.begin(), data.end());
    return test_smb2_netbios_frame(test_smb2_header(9, message_id, body, tree_id, session_id));
}

TestBytes test_smb2_close_request(
    std::uint32_t tree_id,
    std::uint64_t session_id,
    std::uint64_t file_id_persistent,
    std::uint64_t file_id_volatile,
    std::uint64_t message_id = 113) {
    TestBytes body;
    test_rpc_write_u16(body, 24);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u32(body, 0);
    test_smb2_write_u64(body, file_id_persistent);
    test_smb2_write_u64(body, file_id_volatile);
    return test_smb2_netbios_frame(test_smb2_header(6, message_id, body, tree_id, session_id));
}

TestBytes test_smb2_flush_request(
    std::uint32_t tree_id,
    std::uint64_t session_id,
    std::uint64_t file_id_persistent,
    std::uint64_t file_id_volatile,
    std::uint64_t message_id = 114) {
    TestBytes body;
    test_rpc_write_u16(body, 24);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u32(body, 0);
    test_smb2_write_u64(body, file_id_persistent);
    test_smb2_write_u64(body, file_id_volatile);
    return test_smb2_netbios_frame(test_smb2_header(7, message_id, body, tree_id, session_id));
}

TestBytes test_smb2_lock_request(
    std::uint32_t tree_id,
    std::uint64_t session_id,
    std::uint64_t file_id_persistent,
    std::uint64_t file_id_volatile,
    std::uint64_t message_id = 145) {
    TestBytes body;
    test_rpc_write_u16(body, 48);
    test_rpc_write_u16(body, 1);
    test_rpc_write_u32(body, 0);
    test_smb2_write_u64(body, file_id_persistent);
    test_smb2_write_u64(body, file_id_volatile);
    test_smb2_write_u64(body, 0);
    test_smb2_write_u64(body, 1);
    test_rpc_write_u32(body, 0x00000001U);
    test_rpc_write_u32(body, 0);
    return test_smb2_netbios_frame(test_smb2_header(10, message_id, body, tree_id, session_id));
}

TestBytes test_smb2_echo_request(std::uint64_t session_id, std::uint64_t message_id = 115) {
    TestBytes body;
    test_rpc_write_u16(body, 4);
    test_rpc_write_u16(body, 0);
    return test_smb2_netbios_frame(test_smb2_header(13, message_id, body, 0, session_id));
}

TestBytes test_smb2_set_info_request(
    std::uint32_t tree_id,
    std::uint64_t session_id,
    std::uint64_t file_id_persistent,
    std::uint64_t file_id_volatile,
    std::uint8_t info_type = 1,
    std::uint8_t file_info_class = 4,
    std::uint64_t message_id = 116) {
    TestBytes body;
    test_rpc_write_u16(body, 33);
    body.push_back(info_type);
    body.push_back(file_info_class);
    test_rpc_write_u32(body, 0);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u16(body, 0);
    test_rpc_write_u32(body, 0);
    test_smb2_write_u64(body, file_id_persistent);
    test_smb2_write_u64(body, file_id_volatile);
    return test_smb2_netbios_frame(test_smb2_header(17, message_id, body, tree_id, session_id));
}

}  // namespace

// ---------------------------------------------------------------------------
// End-to-end native Active Directory domain-join flow.
//
// This harness threads a SINGLE in-memory directory state through the real
// protocol handlers in the exact order a Windows client drives them during a
// native domain join:
//   DNS DC locator -> LDAP RootDSE -> Kerberos AS-REQ/TGS-REQ ->
//   SMB2 Kerberos session -> machine-account creation over LDAP ->
//   Netlogon secure channel (ReqChallenge/Authenticate3) ->
//   NetrServerPasswordSet2 -> NetrLogonSamLogon.
// Every step asserts the real wire response AND that the shared state mutated
// as a real DC would persist, so the machine created over LDAP is the same
// account that authenticates over Netlogon and Kerberos. Passing this function
// is the executable definition of `windows-join-acceptance`.
// ---------------------------------------------------------------------------
struct JoinDirectoryState {
    nexus::protocol::LdapDirectoryInfo ldap_directory{
        "endorium.local",
        "dc=endorium,dc=local",
        "ENDORIUM.LOCAL",
        "Default-First-Site-Name",
        "dc1",
        "10.10.10.1",
        "S-1-5-21-1001-2002-3003",
    };
    std::vector<nexus::protocol::LdapObject> ldap_objects;
    nexus::protocol::KerberosRealmInfo realm{"ENDORIUM.LOCAL", "krbtgt", {}};
    std::vector<nexus::protocol::NetlogonAccountSecret> netlogon_accounts;
    std::map<std::string, nexus::protocol::SamrAccountRecord> samr_accounts;
    std::map<std::string, std::string> machine_passwords;
    std::uint32_t next_rid{1100};

    static std::string lower(std::string value) {
        for (auto& ch : value) {
            if (ch >= 'A' && ch <= 'Z') {
                ch = static_cast<char>(ch + 32);
            }
        }
        return value;
    }

    // Register a machine account everywhere a real DC persists it: a Kerberos
    // principal (AES keys), a SAMR record and a Netlogon trust secret (NT hash).
    // All derive from the SAME machine password so Kerberos and Netlogon agree.
    std::uint32_t register_machine_account(const std::string& sam_account, const std::string& password) {
        const auto rid = next_rid++;
        machine_passwords[lower(sam_account)] = password;
        const auto creds = nexus::security::derive_ad_credentials(password, "ENDORIUM.LOCAL", sam_account);

        nexus::protocol::KerberosPrincipal principal;
        principal.principal = sam_account;
        principal.realm = "ENDORIUM.LOCAL";
        principal.has_key_material = true;
        for (const auto& key : creds.kerberos_keys) {
            const int enctype = key.enctype == "aes256-cts-hmac-sha1-96" ? 18 : 17;
            principal.keys.push_back({enctype, key.enctype, key.salt, key.key_hex});
        }
        principal.rid = rid;
        principal.primary_group_rid = 515;
        principal.user_account_control = 0x00001000U;  // WORKSTATION_TRUST_ACCOUNT
        realm.principals.push_back(principal);

        netlogon_accounts.push_back({lower(sam_account), creds.nt_hash_hex, rid, 0x00001000U, false});

        nexus::protocol::SamrAccountRecord record;
        record.sam_account_name = sam_account;
        record.rid = rid;
        record.display_name = sam_account;
        record.primary_group_rid = 515;
        record.user_account_control = 0x00001000U;
        record.machine_account = true;
        record.group_rids = {515};
        samr_accounts[lower(sam_account)] = record;
        return rid;
    }
};

void test_full_domain_join_flow() {
    using namespace nexus;

    JoinDirectoryState state;

    // --- System secrets the DC bootstraps before any client can join. ---
    const std::string krbtgt_password = "krbtgt-system-secret";
    const std::string dc_service_password = "dc-service-secret";
    const std::string admin_password = "Passw0rd-Join!";

    const auto admin_salt = security::ad_kerberos_salt("ENDORIUM.LOCAL", "Administrator");
    const auto admin_key = security::derive_ad_kerberos_aes_key(admin_password, admin_salt, 32);
    const auto krbtgt_salt = security::ad_kerberos_salt("ENDORIUM.LOCAL", "krbtgt");
    const auto krbtgt_key = security::derive_ad_kerberos_aes_key(krbtgt_password, krbtgt_salt, 32);
    const auto ldap_salt = security::ad_kerberos_salt("ENDORIUM.LOCAL", "ldap/dc1.endorium.local");
    const auto ldap_key = security::derive_ad_kerberos_aes_key(dc_service_password, ldap_salt, 32);
    const auto cifs_salt = security::ad_kerberos_salt("ENDORIUM.LOCAL", "cifs/dc1.endorium.local");
    const auto cifs_key = security::derive_ad_kerberos_aes_key(dc_service_password, cifs_salt, 32);

    protocol::KerberosPrincipal admin_principal{
        "Administrator", "ENDORIUM.LOCAL", true,
        {{18, "aes256-cts-hmac-sha1-96", admin_salt, admin_key}},
    };
    admin_principal.rid = 500;
    admin_principal.primary_group_rid = 513;
    admin_principal.group_rids = {512, 513, 518, 519};
    const protocol::KerberosPrincipal krbtgt_principal{
        "krbtgt", "ENDORIUM.LOCAL", true,
        {{18, "aes256-cts-hmac-sha1-96", krbtgt_salt, krbtgt_key}},
    };
    const protocol::KerberosPrincipal ldap_principal{
        "ldap/dc1.endorium.local", "ENDORIUM.LOCAL", true,
        {{18, "aes256-cts-hmac-sha1-96", ldap_salt, ldap_key}},
    };
    const protocol::KerberosPrincipal cifs_principal{
        "cifs/dc1.endorium.local", "ENDORIUM.LOCAL", true,
        {{18, "aes256-cts-hmac-sha1-96", cifs_salt, cifs_key}},
    };
    state.realm.principals = {admin_principal, krbtgt_principal, ldap_principal, cifs_principal};

    // Seed the well-known containers so the joining computer has a parent.
    state.ldap_objects.push_back(
        {"dc=endorium,dc=local", "", "domain", {"top", "domain", "domainDNS"}, {{"name", "endorium"}}});
    state.ldap_objects.push_back(
        {"cn=Computers,dc=endorium,dc=local", "dc=endorium,dc=local", "container", {"top", "container"},
         {{"name", "Computers"}}});

    // === Step 1: DNS DC locator =========================================
    const auto ad_zone = protocol::make_active_directory_dns_zone({
        "endorium.local", "Default-First-Site-Name", "dc1", "10.10.10.1", 389, 88, 464, 3268,
    });
    const std::vector<core::DnsZone> zones{ad_zone};
    const auto locator_response = protocol::resolve_dns_query(
        test_dns_standard_query(0x1000, "_ldap._tcp.dc._msdcs.endorium.local", 33), zones);
    assert(!locator_response.empty());
    assert(test_read_u16_be(locator_response, 0) == 0x1000);
    assert(test_read_u16_be(locator_response, 6) >= 1);  // ANCOUNT: the DC SRV record resolved
    const auto dc_a_response = protocol::resolve_dns_query(
        test_dns_standard_query(0x1001, "dc1.endorium.local", 1), zones);
    assert(test_read_u16_be(dc_a_response, 6) >= 1);  // DC host A record resolved

    // === Step 2: LDAP RootDSE probe =====================================
    const auto rootdse = protocol::ldap_ad_response(
        test_ldap_search_request(1, "", 0, {"defaultNamingContext", "dnsHostName", "ldapServiceName"}),
        state.ldap_directory,
        state.ldap_objects);
    assert(!rootdse.empty());
    const std::string rootdse_text(rootdse.begin(), rootdse.end());
    assert(rootdse_text.find("dc=endorium,dc=local") != std::string::npos);

    // === Step 3: Kerberos AS-REQ (pre-authentication) for the admin ======
    const TestBytes timestamp_plaintext = test_seq(test_ctx(0, test_generalized_time("20260530120000Z")));
    const TestBytes ts_confounder{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    const auto encrypted_timestamp =
        protocol::kerberos_encrypt_aes_cts_hmac_sha1(timestamp_plaintext, admin_key, 1, ts_confounder);
    const auto as_rep = protocol::kerberos_error_response(
        test_as_req("Administrator", "ENDORIUM.LOCAL", true, encrypted_timestamp), state.realm);
    assert(!as_rep.empty());
    assert(as_rep.front() == 0x6b);  // AS-REP, the admin received a TGT

    // === Step 4: Kerberos TGS-REQ for ldap/ and cifs/ service tickets =====
    const TestBytes tgt_session_key{
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
    const TestBytes tgt_confounder{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    const auto encrypted_tgt = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        test_enc_ticket_part("ENDORIUM.LOCAL", "Administrator", 18, tgt_session_key), krbtgt_key, 2, tgt_confounder);
    const auto tgt_ticket = test_ticket("ENDORIUM.LOCAL", "krbtgt/ENDORIUM.LOCAL", 18, encrypted_tgt);
    const TestBytes tgs_authenticator_confounder{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
    const auto encrypted_tgs_authenticator = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        test_authenticator("ENDORIUM.LOCAL", "Administrator"), test_bytes_to_hex(tgt_session_key), 7,
        tgs_authenticator_confounder);
    const auto tgs_ap_req = test_ap_req(tgt_ticket, 18, encrypted_tgs_authenticator);
    for (const std::string& spn : {std::string("ldap/dc1.endorium.local"), std::string("cifs/dc1.endorium.local")}) {
        const auto tgs_rep = protocol::kerberos_error_response(
            test_tgs_req(spn, "ENDORIUM.LOCAL", tgs_ap_req), state.realm);
        assert(!tgs_rep.empty());
        assert(tgs_rep.front() == 0x6d);  // TGS-REP, a service ticket was issued
    }

    // === Step 5: SMB2 negotiate =========================================
    const auto smb_negotiate = protocol::smb2_response(test_smb2_negotiate_request());
    assert(!smb_negotiate.empty());
    assert(test_rpc_read_u16(smb_negotiate, 4 + 64 + 4) == 0x0302);

    // === Step 6: SMB2 SESSION_SETUP with the cifs Kerberos AP-REQ ========
    const TestBytes cifs_session_key{
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f};
    const TestBytes cifs_ticket_confounder{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5};
    const auto encrypted_cifs_ticket = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        test_enc_ticket_part("ENDORIUM.LOCAL", "Administrator", 18, cifs_session_key), cifs_key, 2,
        cifs_ticket_confounder);
    const auto cifs_ticket = test_ticket("ENDORIUM.LOCAL", "cifs/dc1.endorium.local", 18, encrypted_cifs_ticket);
    const TestBytes cifs_authenticator_confounder{6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6};
    const auto encrypted_cifs_authenticator = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        test_authenticator("ENDORIUM.LOCAL", "Administrator"), test_bytes_to_hex(cifs_session_key), 11,
        cifs_authenticator_confounder);
    const auto cifs_ap_req = test_ap_req(cifs_ticket, 18, encrypted_cifs_authenticator);
    const protocol::Smb2RuntimeInfo smb_runtime{{}, state.realm, "cifs/dc1.endorium.local"};
    const auto smb_session_response = protocol::smb2_response(
        test_smb2_session_setup_request(test_spnego_token_with_ap_req(cifs_ap_req), 118), smb_runtime);
    assert(test_rpc_read_u32(smb_session_response, 4 + 8) == 0);  // STATUS_SUCCESS
    const auto smb_session_id = test_rpc_read_u64(smb_session_response, 4 + 40);
    assert(smb_session_id != 0);
    assert((test_rpc_read_u32(smb_session_response, 4 + 16) & 0x00000008U) != 0);  // SMB2_FLAGS_SIGNED

    // === Step 7: Machine-account creation over LDAP ======================
    bool computer_persisted = false;
    const auto mutation_handler =
        [&](const protocol::LdapMutation& mutation) -> protocol::LdapMutationResult {
        if (mutation.type == protocol::LdapMutationType::add) {
            state.ldap_objects.push_back(mutation.object);
            if (mutation.object.kind == "computer") {
                const auto sam = mutation.object.attributes.find("sAMAccountName");
                if (sam != mutation.object.attributes.end()) {
                    state.register_machine_account(sam->second, "machine-join-secret");
                    computer_persisted = true;
                }
            }
        }
        return {true, 0, ""};
    };
    const auto machine_add_response = protocol::ldap_ad_response(
        test_ldap_add_request(
            2,
            "cn=WS01,cn=Computers,dc=endorium,dc=local",
            {
                test_ldap_attribute("objectClass", {"top", "person", "organizationalPerson", "user", "computer"}),
                test_ldap_attribute("sAMAccountName", {"WS01$"}),
                test_ldap_attribute("userAccountControl", {"4096"}),
                test_ldap_attribute("dNSHostName", {"ws01.endorium.local"}),
                test_ldap_attribute("servicePrincipalName",
                    {"HOST/ws01.endorium.local", "RestrictedKrbHost/ws01"}),
            }),
        state.ldap_directory,
        state.ldap_objects,
        mutation_handler,
        state.realm);
    assert(test_has_ldap_result_code(machine_add_response, 0));
    assert(computer_persisted);
    // The machine account is now visible across protocols from the shared state.
    assert(state.netlogon_accounts.size() == 1);
    assert(state.samr_accounts.count("ws01$") == 1);
    const auto machine_rid = state.samr_accounts.at("ws01$").rid;
    const auto machine_nt_hash = state.netlogon_accounts.front().nt_hash_hex;
    // The Kerberos realm now carries the machine principal with usable keys.
    assert(std::any_of(state.realm.principals.begin(), state.realm.principals.end(),
        [](const protocol::KerberosPrincipal& p) { return p.principal == "WS01$" && !p.keys.empty(); }));

    // LDAP search confirms the freshly created computer object is searchable.
    const auto computer_search = protocol::ldap_ad_response(
        test_ldap_search_request_with_filter(
            3,
            "dc=endorium,dc=local",
            2,
            test_ldap_equality_filter("sAMAccountName", "WS01$"),
            {"sAMAccountName", "objectClass"}),
        state.ldap_directory,
        state.ldap_objects,
        mutation_handler,
        state.realm);
    const std::string computer_search_text(computer_search.begin(), computer_search.end());
    assert(computer_search_text.find("WS01") != std::string::npos);

    // === Step 8/9: Netlogon secure channel using the joined machine secret ==
    const protocol::RpcRuntimeInfo rpc_runtime{state.netlogon_accounts};
    const TestBytes client_challenge{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    const auto challenge_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(4, 11, test_netlogon_req_challenge_stub("WS01", client_challenge)),
        "netlogon", rpc_runtime);
    assert(!challenge_response.empty());
    assert(challenge_response[2] == 0x02);
    const TestBytes server_challenge(challenge_response.begin() + 24, challenge_response.begin() + 32);
    const auto material = protocol::compute_netlogon_aes_credentials(machine_nt_hash, client_challenge, server_challenge);
    assert(material.has_value());
    const auto authenticate3 = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(26, 13,
            test_netlogon_authenticate3_stub("WS01$", "WS01", material->client_credential, 0x81004000U)),
        "netlogon", rpc_runtime);
    assert(!authenticate3.empty());
    assert(authenticate3[2] == 0x02);
    assert(std::equal(material->server_credential.begin(), material->server_credential.end(),
        authenticate3.begin() + 24));  // mutual authentication of the secure channel
    assert(test_rpc_read_u32(authenticate3, 36) == machine_rid);
    assert(test_rpc_read_u32(authenticate3, 40) == 0);  // STATUS_SUCCESS

    // === Step 10a: NetrServerPasswordSet2 rotates the machine secret ======
    bool password_rotated = false;
    protocol::RpcRuntimeInfo secure_runtime = rpc_runtime;
    secure_runtime.netlogon_password_update_handler =
        [&](const protocol::NetlogonPasswordUpdate& update) {
            password_rotated = true;
            assert(update.sam_account_name == "ws01$");
            state.machine_passwords[update.sam_account_name] = update.new_password;
            return true;
        };
    const std::uint32_t secure_channel_timestamp = 1760000100U;
    const auto secure_channel_seed =
        protocol::advance_netlogon_credential_seed(material->client_credential, secure_channel_timestamp);
    const auto secure_channel_credential =
        protocol::compute_netlogon_aes_credential(material->session_key, secure_channel_seed);
    assert(secure_channel_credential.has_value());
    const auto encrypted_machine_password =
        protocol::encrypt_netlogon_trust_password(material->session_key, "rotated-machine-secret");
    assert(encrypted_machine_password.has_value());
    const auto password_set_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(30, 14,
            test_netlogon_secure_channel_stub("WS01$", "WS01", *secure_channel_credential,
                secure_channel_timestamp, *encrypted_machine_password)),
        "netlogon", secure_runtime);
    assert(password_rotated);
    assert(!password_set_response.empty());
    assert(password_set_response[2] == 0x02);
    assert(test_rpc_read_u32(password_set_response, 32) == 0);  // STATUS_SUCCESS
    assert(state.machine_passwords.at("ws01$") == "rotated-machine-secret");

    // === Step 10b: NetrLogonSamLogon validates an interactive admin logon =
    const auto admin_nt_hash =
        security::derive_ad_credentials(admin_password, "ENDORIUM.LOCAL", "Administrator").nt_hash_hex;
    protocol::RpcRuntimeInfo logon_runtime = secure_runtime;
    logon_runtime.netlogon_accounts.push_back({"administrator", admin_nt_hash, 500});
    logon_runtime.samr_account_handler =
        [](const protocol::SamrAccountRequest& request) -> std::optional<protocol::SamrAccountRecord> {
            if (request.sam_account_name == "administrator" || request.rid == 500) {
                return protocol::SamrAccountRecord{
                    "administrator", 500, "Administrator", 513, 0x00000200U, false, {513, 512}};
            }
            return std::nullopt;
        };
    const TestBytes sam_logon_server_challenge{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28};
    const TestBytes sam_logon_client_challenge{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    const auto sam_logon_proof = protocol::compute_netlogon_ntlmv2_response(
        admin_nt_hash, "administrator", "ENDORIUM", sam_logon_server_challenge, sam_logon_client_challenge);
    assert(sam_logon_proof.has_value());
    const auto sam_logon_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(39, 21,
            test_netlogon_sam_logon_stub("WS01$", "WS01", "administrator", {}, 0, 6, 0x00000001U, false,
                sam_logon_server_challenge, *sam_logon_proof)),
        "netlogon", logon_runtime);
    assert(!sam_logon_response.empty());
    assert(test_rpc_read_u32(sam_logon_response, 28) == 6);  // NETLOGON_VALIDATION_SAM_INFO4 echoed
    // A tampered NTLMv2 proof for the same account must be refused.
    auto tampered_proof = *sam_logon_proof;
    tampered_proof[0] ^= 0xffU;
    const auto bad_sam_logon_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(39, 22,
            test_netlogon_sam_logon_stub("WS01$", "WS01", "administrator", {}, 0, 6, 0x00000001U, false,
                sam_logon_server_challenge, tampered_proof)),
        "netlogon", logon_runtime);
    assert(test_rpc_read_u32(bad_sam_logon_response, bad_sam_logon_response.size() - 4) == 0xc0000022U);
}

// Writable SYSVOL / Group Policy authoring. Runs LAST in main() so the
// read-only skeleton assertions earlier in the suite observe the unmodified
// templates before this test persists authored policy into the overlay.
void test_writable_sysvol_gpo() {
    using namespace nexus;

    const auto negotiate = protocol::smb2_response(test_smb2_negotiate_request());
    assert(!negotiate.empty());
    const auto session_response = protocol::smb2_response(test_smb2_session_setup_request());
    const auto session_id = test_rpc_read_u64(session_response, 4 + 40);
    assert(session_id != 0);
    const auto sysvol_tree =
        protocol::smb2_response(test_smb2_tree_connect_request("\\\\dc1\\SYSVOL", session_id, 200));
    assert(test_rpc_read_u32(sysvol_tree, 4 + 8) == 0);
    assert(test_rpc_read_u32(sysvol_tree, 4 + 36) == 2);  // SYSVOL tree id

    const std::string gpt_path =
        "endorium.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\gpt.ini";
    const auto gpt_create = protocol::smb2_response(test_smb2_create_request(gpt_path, 2, session_id, 201));
    assert(test_rpc_read_u32(gpt_create, 4 + 8) == 0);
    const auto gpt_persistent = test_rpc_read_u64(gpt_create, 4 + 64 + 64);
    const auto gpt_volatile = test_rpc_read_u64(gpt_create, 4 + 64 + 72);

    // The read-only skeleton starts at Version=0.
    const auto baseline_read = protocol::smb2_response(
        test_smb2_read_request(2, session_id, gpt_persistent, gpt_volatile, 256, 0, 202));
    assert(test_rpc_read_u32(baseline_read, 4 + 8) == 0);
    const std::string baseline_text(baseline_read.begin(), baseline_read.end());
    assert(baseline_text.find("Version=0") != std::string::npos);

    // Author the GPO by writing an incremented gpt.ini.
    const std::string authored = "[General]\r\nVersion=7\r\ndisplayName=Default Domain Policy\r\n";
    const TestBytes authored_bytes(authored.begin(), authored.end());
    const auto gpt_write = protocol::smb2_response(
        test_smb2_write_request(authored_bytes, 2, session_id, gpt_persistent, gpt_volatile, 203));
    assert(test_rpc_read_u32(gpt_write, 4 + 8) == 0);
    assert(test_rpc_read_u32(gpt_write, 4 + 64 + 4) == authored_bytes.size());

    // Read back: the authored content now persists over the skeleton.
    const auto authored_read = protocol::smb2_response(
        test_smb2_read_request(2, session_id, gpt_persistent, gpt_volatile, 256, 0, 204));
    assert(test_rpc_read_u32(authored_read, 4 + 8) == 0);
    const std::string authored_text(authored_read.begin(), authored_read.end());
    assert(authored_text.find("Version=7") != std::string::npos);

    // Registry.pol round-trips arbitrary policy bytes too.
    const std::string regpol_path =
        "endorium.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Registry.pol";
    const auto regpol_create = protocol::smb2_response(test_smb2_create_request(regpol_path, 2, session_id, 205));
    assert(test_rpc_read_u32(regpol_create, 4 + 8) == 0);
    const auto regpol_persistent = test_rpc_read_u64(regpol_create, 4 + 64 + 64);
    const auto regpol_volatile = test_rpc_read_u64(regpol_create, 4 + 64 + 72);
    const TestBytes regpol_bytes{'P', 'R', 'e', 'g', 1, 0, 0, 0, 0x5b, 0x00, 0x41, 0x00};
    const auto regpol_write = protocol::smb2_response(
        test_smb2_write_request(regpol_bytes, 2, session_id, regpol_persistent, regpol_volatile, 206));
    assert(test_rpc_read_u32(regpol_write, 4 + 8) == 0);
    assert(test_rpc_read_u32(regpol_write, 4 + 64 + 4) == regpol_bytes.size());
    const auto regpol_read = protocol::smb2_response(
        test_smb2_read_request(2, session_id, regpol_persistent, regpol_volatile, 64, 0, 207));
    assert(test_rpc_read_u32(regpol_read, 4 + 8) == 0);
    assert(regpol_read.size() >= 4 + 64 + regpol_bytes.size());

    // Writing the SYSVOL root (a directory) is refused.
    const auto root_create = protocol::smb2_response(test_smb2_create_request("", 2, session_id, 208));
    assert(test_rpc_read_u32(root_create, 4 + 8) == 0);
    const auto root_persistent = test_rpc_read_u64(root_create, 4 + 64 + 64);
    const auto root_volatile = test_rpc_read_u64(root_create, 4 + 64 + 72);
    const auto root_write = protocol::smb2_response(
        test_smb2_write_request({1, 2, 3}, 2, session_id, root_persistent, root_volatile, 209));
    assert(test_rpc_read_u32(root_write, 4 + 8) != 0);  // directories are not writable
}

// Real SMB clients (smbclient, Windows) open with an SMB1 multi-protocol
// negotiate; the server must upgrade them to SMB2 instead of dropping them.
void test_smb1_negotiate_upgrade() {
    using namespace nexus;
    // Minimal SMB1 SMB_COM_NEGOTIATE (0xFF 'SMB' 0x72) advertising "SMB 2.???".
    TestBytes smb1_payload{0xff, 'S', 'M', 'B', 0x72};
    smb1_payload.insert(smb1_payload.end(), 27, 0);  // remainder of the SMB1 header
    const TestBytes dialect_marker{0x02, 'S', 'M', 'B', ' ', '2', '.', '?', '?', '?', 0x00};
    smb1_payload.insert(smb1_payload.end(), dialect_marker.begin(), dialect_marker.end());
    TestBytes smb1_negotiate{
        0x00,
        static_cast<std::uint8_t>((smb1_payload.size() >> 16) & 0xff),
        static_cast<std::uint8_t>((smb1_payload.size() >> 8) & 0xff),
        static_cast<std::uint8_t>(smb1_payload.size() & 0xff)};
    smb1_negotiate.insert(smb1_negotiate.end(), smb1_payload.begin(), smb1_payload.end());

    const auto parsed = protocol::parse_smb2_request(smb1_negotiate);
    assert(parsed.valid);
    assert(parsed.smb1_multiprotocol_negotiate);
    const auto response = protocol::smb2_response(smb1_negotiate);
    assert(!response.empty());
    assert(response[0] == 0x00);          // NetBIOS framed
    assert(response[4] == 0xfe);          // SMB2 magic
    assert(response[5] == 'S');
    assert(test_rpc_read_u16(response, 4 + 64 + 4) == 0x02ff);  // SMB2 wildcard revision
}

int main() {
    using namespace nexus;

    test_full_domain_join_flow();
    test_smb1_negotiate_upgrade();

    assert(protocol::is_valid_dn("cn=alice,ou=People,dc=endorium,dc=local"));
    assert(!protocol::is_valid_dn("this-is-not-a-dn"));

    const protocol::LdapDirectoryInfo ldap_directory{
        "endorium.local",
        "dc=endorium,dc=local",
        "ENDORIUM.LOCAL",
        "Default-First-Site-Name",
        "dc1",
        "127.0.0.1",
    };
    std::vector<protocol::LdapMutation> ldap_mutations;
    const auto ldap_mutation_handler = [&](const protocol::LdapMutation& mutation) {
        ldap_mutations.push_back(mutation);
        return protocol::LdapMutationResult{true, 0, ""};
    };
    const auto ldap_anonymous_bind_response = protocol::ldap_ad_response(
        test_ldap_simple_bind_request(21, 3, "", ""),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(test_has_ldap_result_code(ldap_anonymous_bind_response, 0));
    const auto ldap_spnego_bind_response = protocol::ldap_ad_response(
        test_ldap_sasl_bind_request(22, 3, "", "GSS-SPNEGO", {0x60, 0x03, 0x06, 0x01, 0x2b}),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(test_has_ldap_result_code(ldap_spnego_bind_response, 0));
    const auto ldap_unsupported_sasl_bind_response = protocol::ldap_ad_response(
        test_ldap_sasl_bind_request(23, 3, "", "UNKNOWN-MECH", {0x01, 0x02}),
        ldap_directory,
        {},
        ldap_mutation_handler);
    const std::string ldap_unsupported_sasl_text(
        ldap_unsupported_sasl_bind_response.begin(),
        ldap_unsupported_sasl_bind_response.end());
    assert(test_has_ldap_result_code(ldap_unsupported_sasl_bind_response, 7));
    assert(ldap_unsupported_sasl_text.find("unsupported LDAP SASL mechanism") != std::string::npos);
    const auto ldap_bad_version_bind_response = protocol::ldap_ad_response(
        test_ldap_simple_bind_request(24, 4, "", ""),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(test_has_ldap_result_code(ldap_bad_version_bind_response, 2));
    const protocol::KerberosRealmInfo empty_ldap_kerberos_realm{"ENDORIUM.LOCAL", "krbtgt", {}};
    protocol::LdapSessionInfo ldap_simple_session;
    const auto ldap_verified_simple_bind_response = protocol::ldap_ad_response(
        test_ldap_simple_bind_request(25, 3, "alice@endorium.local", "alice-secret"),
        ldap_directory,
        {},
        ldap_mutation_handler,
        empty_ldap_kerberos_realm,
        &ldap_simple_session,
        [](const std::string& bind_name, const std::string& password) -> std::optional<std::string> {
            if (bind_name == "alice@endorium.local" && password == "alice-secret") {
                return "alice";
            }
            return std::nullopt;
        });
    assert(test_has_ldap_result_code(ldap_verified_simple_bind_response, 0));
    assert(ldap_simple_session.authenticated);
    assert(ldap_simple_session.bind_dn == "alice@endorium.local");
    assert(ldap_simple_session.principal == "alice");

    const auto ldap_rejected_simple_bind_response = protocol::ldap_ad_response(
        test_ldap_simple_bind_request(26, 3, "alice@endorium.local", "wrong-secret"),
        ldap_directory,
        {},
        ldap_mutation_handler,
        empty_ldap_kerberos_realm,
        &ldap_simple_session,
        [](const std::string&, const std::string&) -> std::optional<std::string> {
            return std::nullopt;
        });
    assert(test_has_ldap_result_code(ldap_rejected_simple_bind_response, 49));
    assert(!ldap_simple_session.authenticated);

    const auto ldap_rejected_session_add_count = ldap_mutations.size();
    const auto ldap_rejected_session_add_response = protocol::ldap_ad_response(
        test_ldap_add_request(
            28,
            "cn=Rejected,cn=Computers,dc=endorium,dc=local",
            {
                test_ldap_attribute("objectClass", {"top", "person", "organizationalPerson", "user", "computer"}),
                test_ldap_attribute("sAMAccountName", {"Rejected$"}),
            }),
        ldap_directory,
        {},
        ldap_mutation_handler,
        empty_ldap_kerberos_realm,
        &ldap_simple_session,
        [](const std::string&, const std::string&) -> std::optional<std::string> {
            return std::nullopt;
        });
    assert(test_has_ldap_result_code(ldap_rejected_session_add_response, 50));
    assert(ldap_mutations.size() == ldap_rejected_session_add_count);

    const auto ldap_verified_anonymous_bind_response = protocol::ldap_ad_response(
        test_ldap_simple_bind_request(27, 3, "", ""),
        ldap_directory,
        {},
        ldap_mutation_handler,
        empty_ldap_kerberos_realm,
        &ldap_simple_session,
        [](const std::string&, const std::string&) -> std::optional<std::string> {
            return "unexpected";
        });
    assert(test_has_ldap_result_code(ldap_verified_anonymous_bind_response, 0));
    assert(!ldap_simple_session.authenticated);

    const auto ldap_add_response = protocol::ldap_ad_response(
        test_ldap_add_request(
            31,
            "cn=WS03,cn=Computers,dc=endorium,dc=local",
            {
                test_ldap_attribute("objectClass", {"top", "person", "organizationalPerson", "user", "computer"}),
                test_ldap_attribute("sAMAccountName", {"WS03$"}),
                test_ldap_attribute("servicePrincipalName", {"HOST/ws03.endorium.local", "LDAP/ws03.endorium.local"}),
            }),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(!ldap_add_response.empty());
    assert(std::find(ldap_add_response.begin(), ldap_add_response.end(), 0x69) != ldap_add_response.end());
    assert(ldap_mutations.size() == 1);
    assert(ldap_mutations.back().type == protocol::LdapMutationType::add);
    assert(ldap_mutations.back().object.kind == "computer");
    assert(ldap_mutations.back().object.parent_dn == "cn=Computers,dc=endorium,dc=local");
    assert(ldap_mutations.back().object.attributes.at("sAMAccountName") == "WS03$");
    assert(ldap_mutations.back().object.attributes.at("servicePrincipalName").find("LDAP/ws03.endorium.local") != std::string::npos);

    // AD schema enforcement on LDAP Add: malformed objects are refused with AD
    // result codes before the mutation handler runs, and the handler is not called.
    const auto ldap_add_no_class_response = protocol::ldap_ad_response(
        test_ldap_add_request(
            33,
            "cn=NoClass,cn=Computers,dc=endorium,dc=local",
            {test_ldap_attribute("sAMAccountName", {"NoClass$"})}),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(test_has_ldap_result_code(ldap_add_no_class_response, 65));
    assert(ldap_mutations.size() == 1);  // handler not invoked

    const auto ldap_add_bad_sam_response = protocol::ldap_ad_response(
        test_ldap_add_request(
            34,
            "cn=BadSam,cn=Computers,dc=endorium,dc=local",
            {
                test_ldap_attribute("objectClass", {"top", "person", "organizationalPerson", "user", "computer"}),
                test_ldap_attribute("sAMAccountName", {"BadSam"}),
            }),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(test_has_ldap_result_code(ldap_add_bad_sam_response, 19));
    assert(ldap_mutations.size() == 1);

    const auto ldap_add_bad_uac_response = protocol::ldap_ad_response(
        test_ldap_add_request(
            35,
            "cn=BadUac,cn=Computers,dc=endorium,dc=local",
            {
                test_ldap_attribute("objectClass", {"top", "person", "organizationalPerson", "user", "computer"}),
                test_ldap_attribute("sAMAccountName", {"BadUac$"}),
                test_ldap_attribute("userAccountControl", {"not-a-number"}),
            }),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(test_has_ldap_result_code(ldap_add_bad_uac_response, 19));
    assert(ldap_mutations.size() == 1);

    const auto ldap_modify_response = protocol::ldap_ad_response(
        test_ldap_modify_request(
            32,
            "cn=WS03,cn=Computers,dc=endorium,dc=local",
            "userAccountControl",
            {"4096"}),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(!ldap_modify_response.empty());
    assert(std::find(ldap_modify_response.begin(), ldap_modify_response.end(), 0x67) != ldap_modify_response.end());
    assert(ldap_mutations.size() == 2);
    assert(ldap_mutations.back().type == protocol::LdapMutationType::modify);
    assert(ldap_mutations.back().object.dn == "cn=WS03,cn=Computers,dc=endorium,dc=local");
    assert(ldap_mutations.back().attributes.at("userAccountControl") == "4096");
    assert(ldap_mutations.back().attribute_operations.at("userAccountControl") == 2);

    const auto ldap_add_spn_modify_response = protocol::ldap_ad_response(
        test_ldap_modify_request(
            53,
            "cn=WS03,cn=Computers,dc=endorium,dc=local",
            "servicePrincipalName",
            {"CIFS/ws03.endorium.local"},
            0),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(!ldap_add_spn_modify_response.empty());
    assert(std::find(ldap_add_spn_modify_response.begin(), ldap_add_spn_modify_response.end(), 0x67) != ldap_add_spn_modify_response.end());
    assert(ldap_mutations.size() == 3);
    assert(ldap_mutations.back().type == protocol::LdapMutationType::modify);
    assert(ldap_mutations.back().attributes.at("servicePrincipalName") == "CIFS/ws03.endorium.local");
    assert(ldap_mutations.back().attribute_operations.at("servicePrincipalName") == 0);

    const auto ldap_delete_spn_modify_response = protocol::ldap_ad_response(
        test_ldap_modify_request(
            54,
            "cn=WS03,cn=Computers,dc=endorium,dc=local",
            "servicePrincipalName",
            {"LDAP/ws03.endorium.local"},
            1),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(!ldap_delete_spn_modify_response.empty());
    assert(std::find(ldap_delete_spn_modify_response.begin(), ldap_delete_spn_modify_response.end(), 0x67) != ldap_delete_spn_modify_response.end());
    assert(ldap_mutations.size() == 4);
    assert(ldap_mutations.back().type == protocol::LdapMutationType::modify);
    assert(ldap_mutations.back().attributes.at("servicePrincipalName") == "LDAP/ws03.endorium.local");
    assert(ldap_mutations.back().attribute_operations.at("servicePrincipalName") == 1);

    const auto ldap_add_group_member_modify_response = protocol::ldap_ad_response(
        test_ldap_modify_request(
            55,
            "cn=Domain Computers,cn=Users,dc=endorium,dc=local",
            "member",
            {"cn=WS03,cn=Computers,dc=endorium,dc=local"},
            0),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(!ldap_add_group_member_modify_response.empty());
    assert(std::find(
        ldap_add_group_member_modify_response.begin(),
        ldap_add_group_member_modify_response.end(),
        0x67) != ldap_add_group_member_modify_response.end());
    assert(ldap_mutations.size() == 5);
    assert(ldap_mutations.back().type == protocol::LdapMutationType::modify);
    assert(ldap_mutations.back().attributes.at("member") == "cn=WS03,cn=Computers,dc=endorium,dc=local");
    assert(ldap_mutations.back().attribute_operations.at("member") == 0);

    const auto ldap_modify_dn_response = protocol::ldap_ad_response(
        test_ldap_modify_dn_request(
            33,
            "cn=WS03,cn=Computers,dc=endorium,dc=local",
            "cn=WS03-Renamed",
            true,
            "ou=Workstations,dc=endorium,dc=local"),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(!ldap_modify_dn_response.empty());
    assert(std::find(ldap_modify_dn_response.begin(), ldap_modify_dn_response.end(), 0x6d) != ldap_modify_dn_response.end());
    assert(ldap_mutations.size() == 6);
    assert(ldap_mutations.back().type == protocol::LdapMutationType::rename);
    assert(ldap_mutations.back().previous_dn == "cn=WS03,cn=Computers,dc=endorium,dc=local");
    assert(ldap_mutations.back().object.dn == "cn=WS03-Renamed,ou=Workstations,dc=endorium,dc=local");
    assert(ldap_mutations.back().object.parent_dn == "ou=Workstations,dc=endorium,dc=local");
    assert(ldap_mutations.back().attributes.at("cn") == "WS03-Renamed");
    assert(ldap_mutations.back().attributes.at("name") == "WS03-Renamed");
    assert(ldap_mutations.back().attributes.at("distinguishedName") == "cn=WS03-Renamed,ou=Workstations,dc=endorium,dc=local");

    const auto ldap_bad_modify_dn_response = protocol::ldap_ad_response(
        test_ldap_modify_dn_request(
            34,
            "this-is-not-a-dn",
            "cn=Bad",
            true),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(test_has_ldap_result_code(ldap_bad_modify_dn_response, 34));
    assert(ldap_mutations.size() == 6);

    const auto ldap_delete_response = protocol::ldap_ad_response(
        test_ldap_delete_request(35, "cn=WS03-Renamed,ou=Workstations,dc=endorium,dc=local"),
        ldap_directory,
        {},
        ldap_mutation_handler);
    assert(!ldap_delete_response.empty());
    assert(std::find(ldap_delete_response.begin(), ldap_delete_response.end(), 0x6b) != ldap_delete_response.end());
    assert(ldap_mutations.size() == 7);
    assert(ldap_mutations.back().type == protocol::LdapMutationType::remove);

    const auto ldap_rootdse_response = protocol::ldap_ad_response(
        test_ldap_search_request(34, "", 0, {"dsServiceName", "supportedControl"}),
        ldap_directory,
        {},
        ldap_mutation_handler);
    const std::string ldap_rootdse_text(ldap_rootdse_response.begin(), ldap_rootdse_response.end());
    assert(ldap_rootdse_text.find("cn=NTDS Settings,cn=dc1") != std::string::npos);
    assert(ldap_rootdse_text.find("1.2.840.113556.1.4.319") != std::string::npos);
    assert(ldap_rootdse_text.find("1.2.840.113556.1.4.417") != std::string::npos);
    assert(ldap_rootdse_text.find("1.2.840.113556.1.4.529") != std::string::npos);
    assert(ldap_rootdse_text.find("1.2.840.113556.1.4.841") != std::string::npos);
    assert(ldap_rootdse_text.find("1.2.840.113556.1.4.1339") != std::string::npos);
    assert(ldap_rootdse_text.find("1.2.840.113556.1.4.1948") != std::string::npos);
    assert(ldap_rootdse_text.find("2.16.840.1.113730.3.4.9") != std::string::npos);

    const auto ldap_config_response = protocol::ldap_ad_response(
        test_ldap_search_request(
            35,
            "cn=Configuration,dc=endorium,dc=local",
            2,
            {"distinguishedName", "objectClass", "dnsRoot", "nCName", "dNSHostName"}),
        ldap_directory,
        {},
        ldap_mutation_handler);
    const std::string ldap_config_text(ldap_config_response.begin(), ldap_config_response.end());
    assert(ldap_config_text.find("cn=Sites,cn=Configuration,dc=endorium,dc=local") != std::string::npos);
    assert(ldap_config_text.find("cn=Partitions,cn=Configuration,dc=endorium,dc=local") != std::string::npos);
    assert(ldap_config_text.find("cn=endorium.local,cn=Partitions,cn=Configuration,dc=endorium,dc=local") != std::string::npos);
    assert(ldap_config_text.find("dc1.endorium.local") != std::string::npos);
    const auto ldap_paged_response = protocol::ldap_ad_response(
        test_ldap_search_request_with_control(
            36,
            "cn=Users,dc=endorium,dc=local",
            0,
            {"cn"},
            "1.2.840.113556.1.4.319"),
        ldap_directory,
        {},
        ldap_mutation_handler);
    const std::string ldap_paged_text(ldap_paged_response.begin(), ldap_paged_response.end());
    assert(ldap_paged_text.find("1.2.840.113556.1.4.319") != std::string::npos);
    assert(ldap_paged_text.find("cn=Users,dc=endorium,dc=local") != std::string::npos);
    const auto ldap_windows_controls_response = protocol::ldap_ad_response(
        test_ldap_search_request_with_controls(
            39,
            "dc=endorium,dc=local",
            2,
            {"cn", "nTSecurityDescriptor"},
            {
                test_ldap_control("1.2.840.113556.1.4.473", true),
                test_ldap_control("1.2.840.113556.1.4.801", true),
                test_ldap_control("1.2.840.113556.1.4.1339", true),
                test_ldap_control("1.2.840.113556.1.4.417", true),
                test_ldap_control("2.16.840.1.113730.3.4.9", true),
            }),
        ldap_directory,
        {},
        ldap_mutation_handler);
    const std::string ldap_windows_controls_text(
        ldap_windows_controls_response.begin(),
        ldap_windows_controls_response.end());
    assert(ldap_windows_controls_text.find("unsupported critical LDAP control") == std::string::npos);
    assert(ldap_windows_controls_text.find("1.2.840.113556.1.4.474") != std::string::npos);
    assert(ldap_windows_controls_text.find("2.16.840.1.113730.3.4.10") != std::string::npos);
    assert(ldap_windows_controls_text.find("nTSecurityDescriptor") != std::string::npos);
    const auto ldap_unsupported_critical_response = protocol::ldap_ad_response(
        test_ldap_search_request_with_control(
            37,
            "cn=Users,dc=endorium,dc=local",
            0,
            {"cn"},
            "1.2.3.4.5.6.7"),
        ldap_directory,
        {},
        ldap_mutation_handler);
    const std::string ldap_unsupported_critical_text(
        ldap_unsupported_critical_response.begin(),
        ldap_unsupported_critical_response.end());
    assert(ldap_unsupported_critical_text.find("unsupported critical LDAP control") != std::string::npos);
    const std::vector<protocol::LdapObject> ldap_filter_objects{
        {
            "cn=Enabled User,cn=Users,dc=endorium,dc=local",
            "cn=Users,dc=endorium,dc=local",
            "user",
            {"top", "person", "user"},
            {
                {"cn", "Enabled User"},
                {"groupRids", "513,512,544"},
                {"objectCategory", "person"},
                {"objectSid", "S-1-5-21-111-222-333-1701"},
                {"primaryGroupID", "513"},
                {"rid", "1701"},
                {"sAMAccountName", "enabled"},
                {"userAccountControl", "512"},
            },
        },
        {
            "cn=Disabled User,cn=Users,dc=endorium,dc=local",
            "cn=Users,dc=endorium,dc=local",
            "user",
            {"top", "person", "user"},
            {
                {"cn", "Disabled User"},
                {"groupRids", "513"},
                {"objectCategory", "person"},
                {"objectSid", "S-1-5-21-111-222-333-1702"},
                {"primaryGroupID", "513"},
                {"rid", "1702"},
                {"sAMAccountName", "disabled"},
                {"userAccountControl", "514"},
            },
        },
        {
            "cn=Nested User,cn=Users,dc=endorium,dc=local",
            "cn=Users,dc=endorium,dc=local",
            "user",
            {"top", "person", "user"},
            {
                {"cn", "Nested User"},
                {"groupRids", "513"},
                {"objectCategory", "person"},
                {"objectSid", "S-1-5-21-111-222-333-1703"},
                {"primaryGroupID", "513"},
                {"rid", "1703"},
                {"sAMAccountName", "nested"},
                {"userAccountControl", "512"},
            },
        },
        {
            "cn=DC1,ou=Domain Controllers,dc=endorium,dc=local",
            "ou=Domain Controllers,dc=endorium,dc=local",
            "computer",
            {"top", "person", "user", "computer"},
            {
                {"cn", "DC1"},
                {"groupRids", "516,515"},
                {"objectCategory", "computer"},
                {"objectGUID", "00112233-4455-6677-8899-aabbccddeeff"},
                {"objectSid", "S-1-5-21-111-222-333-1201"},
                {"primaryGroupID", "516"},
                {"rid", "1201"},
                {"sAMAccountName", "DC1$"},
                {"servicePrincipalName", "HOST/dc1,LDAP/dc1.endorium.local,CIFS/dc1.endorium.local"},
            },
        },
        {
            "cn=Domain Admins,cn=Users,dc=endorium,dc=local",
            "cn=Users,dc=endorium,dc=local",
            "group",
            {"top", "group"},
            {
                {"cn", "Domain Admins"},
                {"groupType", "-2147483646"},
                {"member", "cn=Tier 1 Admins,cn=Users,dc=endorium,dc=local"},
                {"objectSid", "S-1-5-21-111-222-333-512"},
                {"primaryGroupID", "0"},
                {"rid", "512"},
                {"sAMAccountName", "Domain Admins"},
            },
        },
        {
            "cn=Tier 1 Admins,cn=Users,dc=endorium,dc=local",
            "cn=Users,dc=endorium,dc=local",
            "group",
            {"top", "group"},
            {
                {"cn", "Tier 1 Admins"},
                {"groupType", "-2147483646"},
                {"member", "cn=Nested User,cn=Users,dc=endorium,dc=local"},
                {"objectSid", "S-1-5-21-111-222-333-1100"},
                {"primaryGroupID", "0"},
                {"rid", "1100"},
                {"sAMAccountName", "Tier 1 Admins"},
            },
        },
        {
            "cn=Domain Users,cn=Users,dc=endorium,dc=local",
            "cn=Users,dc=endorium,dc=local",
            "group",
            {"top", "group"},
            {
                {"cn", "Domain Users"},
                {"groupType", "-2147483646"},
                {"objectSid", "S-1-5-21-111-222-333-513"},
                {"primaryGroupID", "0"},
                {"rid", "513"},
                {"sAMAccountName", "Domain Users"},
            },
        },
        {
            "cn=Administrators,cn=Builtin,dc=endorium,dc=local",
            "cn=Builtin,dc=endorium,dc=local",
            "group",
            {"top", "group"},
            {
                {"cn", "Administrators"},
                {"groupType", "-2147483644"},
                {"objectSid", "S-1-5-32-544"},
                {"primaryGroupID", "0"},
                {"rid", "544"},
                {"sAMAccountName", "Administrators"},
            },
        },
    };
    const auto disabled_filter_response = protocol::ldap_ad_response(
        test_ldap_search_request_with_filter(
            38,
            "cn=Users,dc=endorium,dc=local",
            2,
            test_ldap_extensible_filter("1.2.840.113556.1.4.803", "userAccountControl", "2"),
            {"cn", "userAccountControl"}),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    const std::string disabled_filter_text(disabled_filter_response.begin(), disabled_filter_response.end());
    assert(disabled_filter_text.find("Disabled User") != std::string::npos);
    assert(disabled_filter_text.find("Enabled User") == std::string::npos);
    const auto substring_filter_response = protocol::ldap_ad_response(
        test_ldap_search_request_with_filter(
            39,
            "cn=Users,dc=endorium,dc=local",
            2,
            test_ldap_substring_filter("cn", {{0x80, "En"}, {0x82, "User"}}),
            {"cn"}),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    const std::string substring_filter_text(substring_filter_response.begin(), substring_filter_response.end());
    assert(substring_filter_text.find("Enabled User") != std::string::npos);
    assert(substring_filter_text.find("Disabled User") == std::string::npos);
    const auto spn_substring_filter_response = protocol::ldap_ad_response(
        test_ldap_search_request_with_filter(
            40,
            "ou=Domain Controllers,dc=endorium,dc=local",
            2,
            test_ldap_substring_filter("servicePrincipalName", {{0x80, "LDAP/"}, {0x82, ".endorium.local"}}),
            {"cn", "servicePrincipalName"}),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    const std::string spn_substring_filter_text(spn_substring_filter_response.begin(), spn_substring_filter_response.end());
    assert(spn_substring_filter_text.find("DC1") != std::string::npos);
    assert(spn_substring_filter_text.find("LDAP/dc1.endorium.local") != std::string::npos);
    const auto object_category_dn_filter_response = protocol::ldap_ad_response(
        test_ldap_search_request_with_filter(
            43,
            "ou=Domain Controllers,dc=endorium,dc=local",
            2,
            test_ldap_equality_filter(
                "objectCategory",
                "CN=Computer,CN=Schema,CN=Configuration,DC=endorium,DC=local"),
            {"cn", "objectCategory"}),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    const std::string object_category_dn_filter_text(
        object_category_dn_filter_response.begin(),
        object_category_dn_filter_response.end());
    assert(object_category_dn_filter_text.find("DC1") != std::string::npos);
    assert(object_category_dn_filter_text.find("Enabled User") == std::string::npos);
    const auto object_sid_binary_filter_response = protocol::ldap_ad_response(
        test_ldap_search_request_with_filter(
            44,
            "dc=endorium,dc=local",
            2,
            test_ldap_equality_filter("objectSid", test_rpc_sid({21, 111, 222, 333, 1201})),
            {"cn", "objectSid"}),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    const std::string object_sid_binary_filter_text(
        object_sid_binary_filter_response.begin(),
        object_sid_binary_filter_response.end());
    assert(object_sid_binary_filter_text.find("DC1") != std::string::npos);
    assert(object_sid_binary_filter_text.find("Enabled User") == std::string::npos);
    const auto ldap_binary_ad_attributes_response = protocol::ldap_ad_response(
        test_ldap_search_request_with_control(
            47,
            "ou=Domain Controllers,dc=endorium,dc=local",
            2,
            {"cn", "objectGUID", "objectSid", "whenCreated", "whenChanged", "uSNCreated", "uSNChanged", "nTSecurityDescriptor"},
            "1.2.840.113556.1.4.801"),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    const std::string ldap_binary_ad_attributes_text(
        ldap_binary_ad_attributes_response.begin(),
        ldap_binary_ad_attributes_response.end());
    assert(ldap_binary_ad_attributes_text.find("nTSecurityDescriptor") != std::string::npos);
    assert(ldap_binary_ad_attributes_text.find("objectGUID") != std::string::npos);
    assert(ldap_binary_ad_attributes_text.find("whenCreated") != std::string::npos);
    assert(ldap_binary_ad_attributes_text.find("whenChanged") != std::string::npos);
    assert(ldap_binary_ad_attributes_text.find("uSNCreated") != std::string::npos);
    assert(ldap_binary_ad_attributes_text.find("uSNChanged") != std::string::npos);
    const TestBytes dc1_guid{0x33, 0x22, 0x11, 0x00, 0x55, 0x44, 0x77, 0x66, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff};
    assert(std::search(
        ldap_binary_ad_attributes_response.begin(),
        ldap_binary_ad_attributes_response.end(),
        dc1_guid.begin(),
        dc1_guid.end()) != ldap_binary_ad_attributes_response.end());
    const auto dc1_sid = test_rpc_sid({21, 111, 222, 333, 1201});
    assert(std::search(
        ldap_binary_ad_attributes_response.begin(),
        ldap_binary_ad_attributes_response.end(),
        dc1_sid.begin(),
        dc1_sid.end()) != ldap_binary_ad_attributes_response.end());
    const TestBytes self_relative_security_descriptor_header{1, 0, 0x04, 0x80, 0x14, 0, 0, 0};
    assert(std::search(
        ldap_binary_ad_attributes_response.begin(),
        ldap_binary_ad_attributes_response.end(),
        self_relative_security_descriptor_header.begin(),
        self_relative_security_descriptor_header.end()) != ldap_binary_ad_attributes_response.end());
    const auto object_guid_binary_filter_response = protocol::ldap_ad_response(
        test_ldap_search_request_with_filter(
            53,
            "dc=endorium,dc=local",
            2,
            test_ldap_equality_filter("objectGUID", dc1_guid),
            {"cn", "objectGUID"}),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    const std::string object_guid_binary_filter_text(
        object_guid_binary_filter_response.begin(),
        object_guid_binary_filter_response.end());
    assert(object_guid_binary_filter_text.find("DC1") != std::string::npos);
    assert(object_guid_binary_filter_text.find("Enabled User") == std::string::npos);
    const auto ldap_constructed_membership_response = protocol::ldap_ad_response(
        test_ldap_search_request(
            50,
            "cn=Enabled User,cn=Users,dc=endorium,dc=local",
            0,
            {"cn", "memberOf", "sAMAccountType", "tokenGroups"}),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    const std::string ldap_constructed_membership_text(
        ldap_constructed_membership_response.begin(),
        ldap_constructed_membership_response.end());
    assert(ldap_constructed_membership_text.find("memberOf") != std::string::npos);
    assert(ldap_constructed_membership_text.find("cn=Domain Users,cn=Users,dc=endorium,dc=local") != std::string::npos);
    assert(ldap_constructed_membership_text.find("cn=Domain Admins,cn=Users,dc=endorium,dc=local") != std::string::npos);
    assert(ldap_constructed_membership_text.find("cn=Administrators,cn=Builtin,dc=endorium,dc=local") != std::string::npos);
    assert(ldap_constructed_membership_text.find("sAMAccountType") != std::string::npos);
    assert(ldap_constructed_membership_text.find("805306368") != std::string::npos);
    assert(ldap_constructed_membership_text.find("tokenGroups") != std::string::npos);
    const auto domain_admins_sid = test_rpc_sid({21, 111, 222, 333, 512});
    const auto domain_users_sid = test_rpc_sid({21, 111, 222, 333, 513});
    const auto builtin_admins_sid = test_rpc_sid({32, 544});
    assert(std::search(
        ldap_constructed_membership_response.begin(),
        ldap_constructed_membership_response.end(),
        domain_admins_sid.begin(),
        domain_admins_sid.end()) != ldap_constructed_membership_response.end());
    assert(std::search(
        ldap_constructed_membership_response.begin(),
        ldap_constructed_membership_response.end(),
        domain_users_sid.begin(),
        domain_users_sid.end()) != ldap_constructed_membership_response.end());
    assert(std::search(
        ldap_constructed_membership_response.begin(),
        ldap_constructed_membership_response.end(),
        builtin_admins_sid.begin(),
        builtin_admins_sid.end()) != ldap_constructed_membership_response.end());
    const auto ldap_group_constructed_response = protocol::ldap_ad_response(
        test_ldap_search_request(
            51,
            "cn=Domain Users,cn=Users,dc=endorium,dc=local",
            0,
            {"cn", "member;range=0-*", "primaryGroupToken", "sAMAccountType"}),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    const std::string ldap_group_constructed_text(
        ldap_group_constructed_response.begin(),
        ldap_group_constructed_response.end());
    assert(ldap_group_constructed_text.find("primaryGroupToken") != std::string::npos);
    assert(ldap_group_constructed_text.find("member;range=0-*") != std::string::npos);
    assert(ldap_group_constructed_text.find("513") != std::string::npos);
    assert(ldap_group_constructed_text.find("268435456") != std::string::npos);
    assert(ldap_group_constructed_text.find("cn=Enabled User,cn=Users,dc=endorium,dc=local") != std::string::npos);
    const auto ldap_member_of_filter_response = protocol::ldap_ad_response(
        test_ldap_search_request_with_filter(
            52,
            "cn=Users,dc=endorium,dc=local",
            2,
            test_ldap_equality_filter("memberOf", "cn=Domain Admins,cn=Users,dc=endorium,dc=local"),
            {"cn", "memberOf"}),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    const std::string ldap_member_of_filter_text(
        ldap_member_of_filter_response.begin(),
        ldap_member_of_filter_response.end());
    assert(ldap_member_of_filter_text.find("Enabled User") != std::string::npos);
    assert(ldap_member_of_filter_text.find("Disabled User") == std::string::npos);
    assert(ldap_member_of_filter_text.find("Nested User") == std::string::npos);
    const auto ldap_transitive_member_of_filter_response = protocol::ldap_ad_response(
        test_ldap_search_request_with_filter(
            54,
            "cn=Users,dc=endorium,dc=local",
            2,
            test_ldap_extensible_filter(
                "1.2.840.113556.1.4.1941",
                "memberOf",
                "cn=Domain Admins,cn=Users,dc=endorium,dc=local"),
            {"cn", "memberOf"}),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    const std::string ldap_transitive_member_of_filter_text(
        ldap_transitive_member_of_filter_response.begin(),
        ldap_transitive_member_of_filter_response.end());
    assert(ldap_transitive_member_of_filter_text.find("Enabled User") != std::string::npos);
    assert(ldap_transitive_member_of_filter_text.find("Nested User") != std::string::npos);
    assert(ldap_transitive_member_of_filter_text.find("Disabled User") == std::string::npos);
    const auto ldap_transitive_member_filter_response = protocol::ldap_ad_response(
        test_ldap_search_request_with_filter(
            55,
            "cn=Users,dc=endorium,dc=local",
            2,
            test_ldap_extensible_filter(
                "1.2.840.113556.1.4.1941",
                "member",
                "cn=Nested User,cn=Users,dc=endorium,dc=local"),
            {"cn", "member"}),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    const std::string ldap_transitive_member_filter_text(
        ldap_transitive_member_filter_response.begin(),
        ldap_transitive_member_filter_response.end());
    assert(ldap_transitive_member_filter_text.find("Domain Admins") != std::string::npos);
    assert(ldap_transitive_member_filter_text.find("Tier 1 Admins") != std::string::npos);
    const auto ldap_compare_true_response = protocol::ldap_ad_response(
        test_ldap_compare_request(
            48,
            "cn=Enabled User,cn=Users,dc=endorium,dc=local",
            "sAMAccountName",
            "enabled"),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    assert(test_has_ldap_result_code(ldap_compare_true_response, 6));
    const auto ldap_compare_false_response = protocol::ldap_ad_response(
        test_ldap_compare_request(
            49,
            "cn=Enabled User,cn=Users,dc=endorium,dc=local",
            "sAMAccountName",
            "disabled"),
        ldap_directory,
        ldap_filter_objects,
        ldap_mutation_handler);
    assert(test_has_ldap_result_code(ldap_compare_false_response, 5));

    const core::DnsZone zone{
        "endorium.local",
        2026042401,
        {
            {"@", "NS", "ns1.endorium.local.", "IN", 3600, 0, 0, 0, ""},
            {"api", "A", "10.10.10.10", "IN", 300, 0, 0, 0, ""},
            {"_ldap._tcp", "SRV", "directory.endorium.local.", "IN", 300, 10, 20, 389, ""},
            {"@", "CAA", "letsencrypt.org", "IN", 300, 0, 0, 0, "issue"},
        }};
    const auto zone_text = protocol::render_zone_file(zone, "ns1.endorium.local", "hostmaster.endorium.local");
    assert(zone_text.find("SOA") != std::string::npos);
    assert(zone_text.find("2026042401") != std::string::npos);
    assert(zone_text.find("_ldap._tcp 300 IN SRV 10 20 389 directory.endorium.local.") != std::string::npos);
    assert(zone_text.find("@ 300 IN CAA 0 issue \"letsencrypt.org\"") != std::string::npos);
    const auto ad_dns_zone = protocol::make_active_directory_dns_zone({
        "endorium.local",
        "Paris",
        "dc9",
        "10.10.10.9",
        1389,
        1088,
        1464,
        13268,
    });
    const auto gc_record = std::find_if(ad_dns_zone.records.begin(), ad_dns_zone.records.end(), [](const auto& record) {
        return record.name == "_gc._tcp" && record.type == "SRV";
    });
    assert(gc_record != ad_dns_zone.records.end());
    assert(gc_record->port == 13268);
    assert(gc_record->value == "dc9.endorium.local.");
    const auto kpasswd_record = std::find_if(ad_dns_zone.records.begin(), ad_dns_zone.records.end(), [](const auto& record) {
        return record.name == "_kpasswd._tcp" && record.type == "SRV";
    });
    assert(kpasswd_record != ad_dns_zone.records.end());
    assert(kpasswd_record->port == 1464);
    std::vector<core::DnsZone> stored_zones{
        {"endorium.local", 2026060101, {{"@", "A", "10.10.10.20", "IN", 300, 0, 0, 0, ""}}},
    };
    protocol::merge_active_directory_dns_zone(stored_zones, ad_dns_zone);
    assert(stored_zones.size() == 1);
    assert(std::any_of(stored_zones[0].records.begin(), stored_zones[0].records.end(), [](const auto& record) {
        return record.name == "_gc._tcp" && record.type == "SRV" && record.port == 13268;
    }));
    const auto records_after_first_merge = stored_zones[0].records.size();
    protocol::merge_active_directory_dns_zone(stored_zones, ad_dns_zone);
    assert(stored_zones[0].records.size() == records_after_first_merge);
    std::vector<core::DnsZone> empty_zones;
    protocol::merge_active_directory_dns_zone(empty_zones, ad_dns_zone);
    assert(empty_zones.size() == 1);
    const auto dns_update_query = test_dns_update_query(0x4d51, "endorium.local");
    const auto parsed_dns_update = protocol::parse_dns_dynamic_update(dns_update_query, stored_zones);
    assert(parsed_dns_update.is_update);
    assert(parsed_dns_update.valid);
    assert(parsed_dns_update.authorized);
    assert(parsed_dns_update.zone_name == "endorium.local");
    assert(parsed_dns_update.records.size() == 1);
    assert(!parsed_dns_update.records[0].deletion);
    assert(parsed_dns_update.records[0].record.name == "ws99");
    assert(parsed_dns_update.records[0].record.type == "A");
    assert(parsed_dns_update.records[0].record.value == "10.10.10.99");
    assert(parsed_dns_update.records[0].record.ttl == 300);
    const auto dns_update_response =
        protocol::resolve_dns_query(dns_update_query, stored_zones);
    assert(test_read_u16_be(dns_update_response, 0) == 0x4d51);
    assert(((test_read_u16_be(dns_update_response, 2) >> 11U) & 0x0fU) == 5);
    assert((test_read_u16_be(dns_update_response, 2) & 0x000fU) == 0);
    assert(test_read_u16_be(dns_update_response, 4) == 1);
    const auto dns_msdcs_update_response =
        protocol::resolve_dns_query(test_dns_update_query(0x4d52, "_msdcs.endorium.local"), stored_zones);
    assert((test_read_u16_be(dns_msdcs_update_response, 2) & 0x000fU) == 0);
    const auto dns_foreign_update_response =
        protocol::resolve_dns_query(test_dns_update_query(0x4d53, "example.invalid"), stored_zones);
    assert((test_read_u16_be(dns_foreign_update_response, 2) & 0x000fU) == 9);
    const TestBytes malformed_update{0x4d, 0x54, 0x28, 0x00, 0, 0, 0, 0, 0, 0, 0, 0};
    const auto dns_malformed_update_response = protocol::resolve_dns_query(malformed_update, stored_zones);
    assert((test_read_u16_be(dns_malformed_update_response, 2) & 0x000fU) == 1);

    const auto rpc_bind = test_rpc_epm_bind();
    const auto parsed_rpc_bind = protocol::parse_rpc_request(rpc_bind);
    assert(parsed_rpc_bind.valid);
    assert(parsed_rpc_bind.ptype == 0x0b);
    assert(parsed_rpc_bind.call_id == 7);
    assert(parsed_rpc_bind.bind_context_ids.size() == 1);
    assert(parsed_rpc_bind.abstract_syntaxes[0] == "e1af8308-5d1f-11c9-91a4-08002b14a0fa");
    const auto rpc_bind_ack = protocol::rpc_endpoint_mapper_response(rpc_bind, 8135);
    assert(!rpc_bind_ack.empty());
    assert(rpc_bind_ack[2] == 0x0c);
    assert(test_rpc_read_u16(rpc_bind_ack, 8) == rpc_bind_ack.size());
    assert(rpc_bind_ack[26] == '8');
    const auto rpc_pipe_bind_ack = protocol::rpc_named_pipe_response(rpc_bind, "epmapper");
    assert(!rpc_pipe_bind_ack.empty());
    assert(rpc_pipe_bind_ack[2] == 0x0c);
    assert(test_rpc_read_u16(rpc_pipe_bind_ack, 8) == rpc_pipe_bind_ack.size());
    assert(rpc_pipe_bind_ack[26] == '4');
    const auto rpc_lookup = protocol::rpc_endpoint_mapper_response(test_rpc_request_opnum(2, 8), 8135);
    assert(!rpc_lookup.empty());
    assert(rpc_lookup[2] == 0x02);
    assert(test_rpc_read_u32(rpc_lookup, 16) > 100);
    const TestBytes epm_netlogon_utf16{'n', 0, 'e', 0, 't', 0, 'l', 0, 'o', 0, 'g', 0, 'o', 0, 'n', 0};
    assert(std::search(
        rpc_lookup.begin(),
        rpc_lookup.end(),
        epm_netlogon_utf16.begin(),
        epm_netlogon_utf16.end()) != rpc_lookup.end());
    const auto rpc_pipe_lookup = protocol::rpc_named_pipe_response(test_rpc_request_opnum(2, 96), "epmapper");
    assert(!rpc_pipe_lookup.empty());
    assert(rpc_pipe_lookup[2] == 0x02);
    assert(test_rpc_read_u32(rpc_pipe_lookup, 16) > 100);
    assert(std::search(
        rpc_pipe_lookup.begin(),
        rpc_pipe_lookup.end(),
        epm_netlogon_utf16.begin(),
        epm_netlogon_utf16.end()) != rpc_pipe_lookup.end());
    const auto rpc_map = protocol::rpc_endpoint_mapper_response(
        test_rpc_request_opnum(3, 9, test_rpc_netlogon_uuid_stub()),
        8135);
    assert(!rpc_map.empty());
    assert(rpc_map[2] == 0x02);
    assert(std::search(
        rpc_map.begin(),
        rpc_map.end(),
        epm_netlogon_utf16.begin(),
        epm_netlogon_utf16.end()) != rpc_map.end());
    const auto rpc_alive = protocol::rpc_endpoint_mapper_response(test_rpc_request_opnum(5, 10), 8135);
    assert(!rpc_alive.empty());
    assert(rpc_alive[2] == 0x02);
    const TestBytes rpc_port_utf16{'8', 0, '1', 0, '3', 0, '5', 0};
    assert(std::search(
        rpc_alive.begin(),
        rpc_alive.end(),
        rpc_port_utf16.begin(),
        rpc_port_utf16.end()) != rpc_alive.end());
    const auto rpc_fault = protocol::rpc_endpoint_mapper_response(test_rpc_request_opnum(99, 11), 8135);
    assert(!rpc_fault.empty());
    assert(rpc_fault[2] == 0x03);

    const auto netlogon_bind = test_rpc_netlogon_bind();
    const auto parsed_netlogon_bind = protocol::parse_rpc_request(netlogon_bind);
    assert(parsed_netlogon_bind.valid);
    assert(parsed_netlogon_bind.abstract_syntaxes[0] == "12345678-1234-abcd-ef00-01234567cffb");
    const auto netlogon_bind_ack = protocol::rpc_named_pipe_response(netlogon_bind, "netlogon");
    assert(!netlogon_bind_ack.empty());
    assert(netlogon_bind_ack[2] == 0x0c);
    const TestBytes client_challenge{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17};
    const auto netlogon_challenge = test_rpc_request_opnum(4, 11, test_netlogon_req_challenge_stub("WS01", client_challenge));
    const auto parsed_netlogon_challenge = protocol::parse_rpc_request(netlogon_challenge);
    assert(parsed_netlogon_challenge.valid);
    assert(parsed_netlogon_challenge.opnum == 4);
    assert(!parsed_netlogon_challenge.stub_data.empty());
    const auto netlogon_challenge_response = protocol::rpc_named_pipe_response(netlogon_challenge, "netlogon");
    assert(!netlogon_challenge_response.empty());
    assert(netlogon_challenge_response[2] == 0x02);
    assert(test_rpc_read_u32(netlogon_challenge_response, 16) == 12);
    assert(test_rpc_read_u32(netlogon_challenge_response, 32) == 0);
    const TestBytes server_challenge(netlogon_challenge_response.begin() + 24, netlogon_challenge_response.begin() + 32);
    const std::string machine_nt_hash = "0123456789abcdeffedcba9876543210";
    const auto netlogon_material = protocol::compute_netlogon_aes_credentials(
        machine_nt_hash,
        client_challenge,
        server_challenge);
    assert(netlogon_material.has_value());
    assert(netlogon_material->session_key.size() == 16);
    assert(netlogon_material->client_credential.size() == 8);
    assert(netlogon_material->server_credential.size() == 8);
    const protocol::RpcRuntimeInfo rpc_runtime{{{"WS01$", machine_nt_hash, 1201}}};
    constexpr std::uint32_t requested_netlogon_flags = 0x81004000U;
    constexpr std::uint32_t negotiated_netlogon_flags = 0x01004000U;
    const auto netlogon_auth_legacy = test_rpc_request_opnum(
        5,
        27,
        test_netlogon_authenticate_stub("WS01$", "WS01", netlogon_material->client_credential));
    const auto netlogon_auth_legacy_response =
        protocol::rpc_named_pipe_response(netlogon_auth_legacy, "netlogon", rpc_runtime);
    assert(!netlogon_auth_legacy_response.empty());
    assert(netlogon_auth_legacy_response[2] == 0x02);
    assert(test_rpc_read_u32(netlogon_auth_legacy_response, 16) == 12);
    assert(std::equal(
        netlogon_material->server_credential.begin(),
        netlogon_material->server_credential.end(),
        netlogon_auth_legacy_response.begin() + 24));
    assert(test_rpc_read_u32(netlogon_auth_legacy_response, 32) == 0);
    const auto netlogon_auth2 = test_rpc_request_opnum(
        15,
        13,
        test_netlogon_authenticate3_stub("WS01$", "WS01", netlogon_material->client_credential, requested_netlogon_flags));
    const auto netlogon_auth2_response = protocol::rpc_named_pipe_response(netlogon_auth2, "netlogon", rpc_runtime);
    assert(!netlogon_auth2_response.empty());
    assert(netlogon_auth2_response[2] == 0x02);
    assert(test_rpc_read_u32(netlogon_auth2_response, 16) == 16);
    assert(std::equal(
        netlogon_material->server_credential.begin(),
        netlogon_material->server_credential.end(),
        netlogon_auth2_response.begin() + 24));
    assert(test_rpc_read_u32(netlogon_auth2_response, 32) == negotiated_netlogon_flags);
    assert(test_rpc_read_u32(netlogon_auth2_response, 36) == 0);
    const auto netlogon_auth = test_rpc_request_opnum(
        26,
        12,
        test_netlogon_authenticate3_stub("WS01$", "WS01", netlogon_material->client_credential, requested_netlogon_flags));
    const auto netlogon_auth_response = protocol::rpc_named_pipe_response(netlogon_auth, "netlogon", rpc_runtime);
    assert(!netlogon_auth_response.empty());
    assert(netlogon_auth_response[2] == 0x02);
    assert(test_rpc_read_u32(netlogon_auth_response, 16) == 20);
    assert(std::equal(
        netlogon_material->server_credential.begin(),
        netlogon_material->server_credential.end(),
        netlogon_auth_response.begin() + 24));
    assert(test_rpc_read_u32(netlogon_auth_response, 32) == negotiated_netlogon_flags);
    assert(test_rpc_read_u32(netlogon_auth_response, 36) == 1201);
    assert(test_rpc_read_u32(netlogon_auth_response, 40) == 0);
    const protocol::RpcRuntimeInfo disabled_machine_rpc_runtime{
        {{"WS01$", machine_nt_hash, 1201, 0x00001002U, false}},
    };
    const auto disabled_machine_netlogon_auth_response =
        protocol::rpc_named_pipe_response(netlogon_auth, "netlogon", disabled_machine_rpc_runtime);
    assert(!disabled_machine_netlogon_auth_response.empty());
    assert(test_rpc_read_u32(disabled_machine_netlogon_auth_response, 16) == 20);
    assert(test_rpc_read_u32(disabled_machine_netlogon_auth_response, 40) == 0xc0000072U);
    const protocol::RpcRuntimeInfo expired_machine_rpc_runtime{
        {{"WS01$", machine_nt_hash, 1201, 0x00001000U, true}},
    };
    const auto expired_machine_netlogon_auth_response =
        protocol::rpc_named_pipe_response(netlogon_auth, "netlogon", expired_machine_rpc_runtime);
    assert(!expired_machine_netlogon_auth_response.empty());
    assert(test_rpc_read_u32(expired_machine_netlogon_auth_response, 16) == 20);
    assert(test_rpc_read_u32(expired_machine_netlogon_auth_response, 40) == 0xc0000193U);
    const std::uint32_t secure_channel_timestamp = 1760000000U;
    const auto secure_channel_seed = protocol::advance_netlogon_credential_seed(
        netlogon_material->client_credential,
        secure_channel_timestamp);
    const auto secure_channel_credential = protocol::compute_netlogon_aes_credential(
        netlogon_material->session_key,
        secure_channel_seed);
    assert(secure_channel_credential.has_value());
    const auto encrypted_machine_password = protocol::encrypt_netlogon_trust_password(
        netlogon_material->session_key,
        "new-machine-secret");
    assert(encrypted_machine_password.has_value());
    const auto decrypted_machine_password =
        protocol::decrypt_netlogon_trust_password(netlogon_material->session_key, *encrypted_machine_password);
    assert(decrypted_machine_password.has_value());
    assert(*decrypted_machine_password == "new-machine-secret");
    const std::string unicode_machine_password = std::string("machine-") + "\xc3\xa9" + "-seal";
    const auto encrypted_unicode_machine_password = protocol::encrypt_netlogon_trust_password(
        netlogon_material->session_key,
        unicode_machine_password);
    assert(encrypted_unicode_machine_password.has_value());
    const auto decrypted_unicode_machine_password =
        protocol::decrypt_netlogon_trust_password(netlogon_material->session_key, *encrypted_unicode_machine_password);
    assert(decrypted_unicode_machine_password.has_value());
    assert(*decrypted_unicode_machine_password == unicode_machine_password);
    bool password_update_seen = false;
    protocol::RpcRuntimeInfo password_update_runtime = rpc_runtime;
    password_update_runtime.netlogon_password_update_handler =
        [&](const protocol::NetlogonPasswordUpdate& update) {
            password_update_seen = true;
            assert(update.sam_account_name == "ws01$");
            assert(update.computer_name == "ws01");
            assert(update.new_password == "new-machine-secret");
            return true;
        };
    const auto password_set = test_rpc_request_opnum(
        30,
        14,
        test_netlogon_secure_channel_stub(
            "WS01$",
            "WS01",
            *secure_channel_credential,
            secure_channel_timestamp,
            *encrypted_machine_password));
    const auto password_set_response = protocol::rpc_named_pipe_response(password_set, "netlogon", password_update_runtime);
    assert(password_update_seen);
    assert(!password_set_response.empty());
    assert(password_set_response[2] == 0x02);
    assert(test_rpc_read_u32(password_set_response, 16) == 16);
    const auto expected_return_seed = protocol::advance_netlogon_credential_seed(secure_channel_seed, 1);
    const auto expected_return_credential = protocol::compute_netlogon_aes_credential(
        netlogon_material->session_key,
        expected_return_seed);
    assert(expected_return_credential.has_value());
    assert(std::equal(
        expected_return_credential->begin(),
        expected_return_credential->end(),
        password_set_response.begin() + 24));
    assert(test_rpc_read_u32(password_set_response, 32) == 0);
    assert(test_rpc_read_u32(password_set_response, 36) == 0);
    password_update_runtime.domain_netbios_name = "ENDORIUM";
    password_update_runtime.domain_dns_name = "endorium.local";
    password_update_runtime.domain_sid = "S-1-5-21-111-222-333";
    password_update_runtime.domain_controller_host = "dc9";
    password_update_runtime.domain_controller_address = "10.10.10.9";
    password_update_runtime.site_name = "Paris";
    const std::uint32_t domain_info_timestamp = secure_channel_timestamp + 2;
    const auto domain_info_seed = protocol::advance_netlogon_credential_seed(
        *expected_return_credential,
        domain_info_timestamp);
    const auto domain_info_credential = protocol::compute_netlogon_aes_credential(
        netlogon_material->session_key,
        domain_info_seed);
    assert(domain_info_credential.has_value());
    const auto domain_info_request = test_rpc_request_opnum(
        29,
        16,
        test_netlogon_secure_channel_stub(
            "WS01$",
            "WS01",
            *domain_info_credential,
            domain_info_timestamp,
            {}));
    const auto domain_info_response =
        protocol::rpc_named_pipe_response(domain_info_request, "netlogon", password_update_runtime);
    assert(!domain_info_response.empty());
    assert(domain_info_response[2] == 0x02);
    assert(test_rpc_read_u32(domain_info_response, 16) > 120);
    assert(test_rpc_read_u32(domain_info_response, 36) == 1);
    const TestBytes domain_utf16{'e', 0, 'n', 0, 'd', 0, 'o', 0, 'r', 0, 'i', 0, 'u', 0, 'm', 0};
    assert(std::search(
        domain_info_response.begin(),
        domain_info_response.end(),
        domain_utf16.begin(),
        domain_utf16.end()) != domain_info_response.end());
    const auto domain_info_return_seed = protocol::advance_netlogon_credential_seed(domain_info_seed, 1);
    const auto domain_info_return_credential = protocol::compute_netlogon_aes_credential(
        netlogon_material->session_key,
        domain_info_return_seed);
    assert(domain_info_return_credential.has_value());
    assert(std::equal(
        domain_info_return_credential->begin(),
        domain_info_return_credential->end(),
        domain_info_response.begin() + 24));
    const auto dsr_get_dc_name_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(34, 23), "netlogon", password_update_runtime);
    assert(!dsr_get_dc_name_response.empty());
    assert(test_rpc_read_u32(dsr_get_dc_name_response, 16) > 120);
    assert(test_rpc_read_u32(dsr_get_dc_name_response, dsr_get_dc_name_response.size() - 4) == 0);
    const TestBytes dc9_fqdn_utf16{
        'd', 0, 'c', 0, '9', 0, '.', 0, 'e', 0, 'n', 0, 'd', 0, 'o', 0, 'r', 0, 'i', 0, 'u', 0, 'm', 0,
        '.', 0, 'l', 0, 'o', 0, 'c', 0, 'a', 0, 'l', 0};
    assert(std::search(
        dsr_get_dc_name_response.begin(),
        dsr_get_dc_name_response.end(),
        dc9_fqdn_utf16.begin(),
        dc9_fqdn_utf16.end()) != dsr_get_dc_name_response.end());
    const TestBytes dc_address_utf16{'1', 0, '0', 0, '.', 0, '1', 0, '0', 0, '.', 0, '1', 0, '0', 0, '.', 0, '9', 0};
    assert(std::search(
        dsr_get_dc_name_response.begin(),
        dsr_get_dc_name_response.end(),
        dc_address_utf16.begin(),
        dc_address_utf16.end()) != dsr_get_dc_name_response.end());
    const TestBytes site_utf16{'P', 0, 'a', 0, 'r', 0, 'i', 0, 's', 0};
    assert(std::search(
        dsr_get_dc_name_response.begin(),
        dsr_get_dc_name_response.end(),
        site_utf16.begin(),
        site_utf16.end()) != dsr_get_dc_name_response.end());
    const auto dsr_get_dc_name_legacy_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(20, 24), "netlogon", password_update_runtime);
    assert(test_rpc_read_u32(dsr_get_dc_name_legacy_response, dsr_get_dc_name_legacy_response.size() - 4) == 0);
    assert(std::search(
        dsr_get_dc_name_legacy_response.begin(),
        dsr_get_dc_name_legacy_response.end(),
        dc9_fqdn_utf16.begin(),
        dc9_fqdn_utf16.end()) != dsr_get_dc_name_legacy_response.end());
    const auto dsr_get_site_name_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(28, 25), "netlogon", password_update_runtime);
    assert(test_rpc_read_u32(dsr_get_site_name_response, dsr_get_site_name_response.size() - 4) == 0);
    assert(std::search(
        dsr_get_site_name_response.begin(),
        dsr_get_site_name_response.end(),
        site_utf16.begin(),
        site_utf16.end()) != dsr_get_site_name_response.end());
    auto address_to_site_stub = test_rpc_ndr_utf16_string("\\\\DC1");
    test_rpc_write_u32(address_to_site_stub, 2);
    const auto address_to_site_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(33, 76, address_to_site_stub), "netlogon", password_update_runtime);
    assert(!address_to_site_response.empty());
    assert(address_to_site_response[2] == 0x02);
    assert(test_rpc_read_u32(address_to_site_response, 16) > 60);
    assert(test_rpc_read_u32(address_to_site_response, 24) != 0);
    assert(test_rpc_read_u32(address_to_site_response, 28) == 2);
    assert(test_rpc_read_u32(address_to_site_response, address_to_site_response.size() - 4) == 0);
    auto first_site_match = std::search(
        address_to_site_response.begin(),
        address_to_site_response.end(),
        site_utf16.begin(),
        site_utf16.end());
    assert(first_site_match != address_to_site_response.end());
    assert(std::search(
        first_site_match + static_cast<std::ptrdiff_t>(site_utf16.size()),
        address_to_site_response.end(),
        site_utf16.begin(),
        site_utf16.end()) != address_to_site_response.end());
    const auto address_to_site_ex_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(37, 78, address_to_site_stub), "netlogon", password_update_runtime);
    assert(!address_to_site_ex_response.empty());
    assert(test_rpc_read_u32(address_to_site_ex_response, 16) > 80);
    assert(test_rpc_read_u32(address_to_site_ex_response, 24) != 0);
    assert(test_rpc_read_u32(address_to_site_ex_response, 28) == 2);
    assert(test_rpc_read_u32(address_to_site_ex_response, address_to_site_ex_response.size() - 4) == 0);
    const auto first_site_ex_match = std::search(
        address_to_site_ex_response.begin(),
        address_to_site_ex_response.end(),
        site_utf16.begin(),
        site_utf16.end());
    assert(first_site_ex_match != address_to_site_ex_response.end());
    assert(std::search(
        first_site_ex_match + static_cast<std::ptrdiff_t>(site_utf16.size()),
        address_to_site_ex_response.end(),
        site_utf16.begin(),
        site_utf16.end()) != address_to_site_ex_response.end());
    const auto site_coverage_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(38, 79), "netlogon", password_update_runtime);
    assert(!site_coverage_response.empty());
    assert(test_rpc_read_u32(site_coverage_response, 16) > 32);
    assert(test_rpc_read_u32(site_coverage_response, 24) != 0);
    assert(test_rpc_read_u32(site_coverage_response, 28) == 1);
    assert(test_rpc_read_u32(site_coverage_response, site_coverage_response.size() - 4) == 0);
    assert(std::search(
        site_coverage_response.begin(),
        site_coverage_response.end(),
        site_utf16.begin(),
        site_utf16.end()) != site_coverage_response.end());
    const auto netr_get_dc_name_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(11, 26), "netlogon", password_update_runtime);
    assert(test_rpc_read_u32(netr_get_dc_name_response, netr_get_dc_name_response.size() - 4) == 0);
    const TestBytes dc9_netbios_utf16{'D', 0, 'C', 0, '9', 0};
    assert(std::search(
        netr_get_dc_name_response.begin(),
        netr_get_dc_name_response.end(),
        dc9_netbios_utf16.begin(),
        dc9_netbios_utf16.end()) != netr_get_dc_name_response.end());
    const auto netlogon_control_query_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(12, 69, test_netlogon_control_stub(1, 1)),
        "netlogon",
        password_update_runtime);
    assert(!netlogon_control_query_response.empty());
    assert(netlogon_control_query_response[2] == 0x02);
    assert(test_rpc_read_u32(netlogon_control_query_response, 16) == 16);
    assert(test_rpc_read_u32(netlogon_control_query_response, 24) != 0);
    assert(test_rpc_read_u32(netlogon_control_query_response, 32) == 0);
    assert(test_rpc_read_u32(netlogon_control_query_response, 36) == 0);
    const auto netlogon_control_verify_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(18, 70, test_netlogon_control_stub(10, 2)),
        "netlogon",
        password_update_runtime);
    assert(!netlogon_control_verify_response.empty());
    assert(test_rpc_read_u32(netlogon_control_verify_response, 16) > 40);
    assert(test_rpc_read_u32(netlogon_control_verify_response, netlogon_control_verify_response.size() - 4) == 0);
    assert(std::search(
        netlogon_control_verify_response.begin(),
        netlogon_control_verify_response.end(),
        dc9_fqdn_utf16.begin(),
        dc9_fqdn_utf16.end()) != netlogon_control_verify_response.end());
    const auto netlogon_control_dns_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(14, 71, test_netlogon_control_stub(12, 1)),
        "netlogon",
        password_update_runtime);
    assert(test_rpc_read_u32(netlogon_control_dns_response, netlogon_control_dns_response.size() - 4) == 0);
    const auto netlogon_control_invalid_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(18, 72, test_netlogon_control_stub(10, 3)),
        "netlogon",
        password_update_runtime);
    assert(test_rpc_read_u32(netlogon_control_invalid_response, 16) == 8);
    assert(test_rpc_read_u32(netlogon_control_invalid_response, 28) == 0x00000057U);
    const auto trusted_domains_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(36, 73), "netlogon", password_update_runtime);
    assert(!trusted_domains_response.empty());
    assert(test_rpc_read_u32(trusted_domains_response, 16) > 80);
    assert(test_rpc_read_u32(trusted_domains_response, 24) == 1);
    assert(test_rpc_read_u32(trusted_domains_response, 32) == 1);
    assert(test_rpc_read_u32(trusted_domains_response, trusted_domains_response.size() - 4) == 0);
    assert(std::search(
        trusted_domains_response.begin(),
        trusted_domains_response.end(),
        domain_utf16.begin(),
        domain_utf16.end()) != trusted_domains_response.end());
    const auto legacy_trusted_domains_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(19, 75), "netlogon", password_update_runtime);
    assert(!legacy_trusted_domains_response.empty());
    assert(test_rpc_read_u32(legacy_trusted_domains_response, 16) > 24);
    assert(test_rpc_read_u32(legacy_trusted_domains_response, 24) != 0);
    assert(test_rpc_read_u32(legacy_trusted_domains_response, 28) >= 4);
    assert(test_rpc_read_u32(legacy_trusted_domains_response, legacy_trusted_domains_response.size() - 4) == 0);
    const TestBytes endorium_netbios_utf16{'E', 0, 'N', 0, 'D', 0, 'O', 0, 'R', 0, 'I', 0, 'U', 0, 'M', 0};
    assert(std::search(
        legacy_trusted_domains_response.begin(),
        legacy_trusted_domains_response.end(),
        endorium_netbios_utf16.begin(),
        endorium_netbios_utf16.end()) != legacy_trusted_domains_response.end());
    const auto dsr_trusts_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(40, 74), "netlogon", password_update_runtime);
    assert(!dsr_trusts_response.empty());
    assert(test_rpc_read_u32(dsr_trusts_response, 24) == 1);
    assert(std::search(
        dsr_trusts_response.begin(),
        dsr_trusts_response.end(),
        dc9_fqdn_utf16.begin(),
        dc9_fqdn_utf16.end()) == dsr_trusts_response.end());
    const auto forest_trust_info_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(43, 77), "netlogon", password_update_runtime);
    assert(!forest_trust_info_response.empty());
    assert(test_rpc_read_u32(forest_trust_info_response, 16) > 100);
    assert(test_rpc_read_u32(forest_trust_info_response, 24) != 0);
    assert(test_rpc_read_u32(forest_trust_info_response, 28) == 2);
    assert(test_rpc_read_u32(forest_trust_info_response, forest_trust_info_response.size() - 4) == 0);
    const TestBytes domain_dns_utf16{
        'e', 0, 'n', 0, 'd', 0, 'o', 0, 'r', 0, 'i', 0, 'u', 0, 'm', 0,
        '.', 0, 'l', 0, 'o', 0, 'c', 0, 'a', 0, 'l', 0};
    assert(std::search(
        forest_trust_info_response.begin(),
        forest_trust_info_response.end(),
        domain_dns_utf16.begin(),
        domain_dns_utf16.end()) != forest_trust_info_response.end());
    assert(std::search(
        forest_trust_info_response.begin(),
        forest_trust_info_response.end(),
        endorium_netbios_utf16.begin(),
        endorium_netbios_utf16.end()) != forest_trust_info_response.end());
    const auto deregister_dns_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(41, 80), "netlogon", password_update_runtime);
    assert(!deregister_dns_response.empty());
    assert(test_rpc_read_u32(deregister_dns_response, 16) == 4);
    assert(test_rpc_read_u32(deregister_dns_response, 24) == 0);
    const auto netr_forest_trust_info_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(44, 81), "netlogon", password_update_runtime);
    assert(!netr_forest_trust_info_response.empty());
    assert(test_rpc_read_u32(netr_forest_trust_info_response, 16) > 100);
    assert(test_rpc_read_u32(netr_forest_trust_info_response, 28) == 2);
    assert(test_rpc_read_u32(netr_forest_trust_info_response, netr_forest_trust_info_response.size() - 4) == 0);
    assert(std::search(
        netr_forest_trust_info_response.begin(),
        netr_forest_trust_info_response.end(),
        domain_dns_utf16.begin(),
        domain_dns_utf16.end()) != netr_forest_trust_info_response.end());
    TestBytes invalid_capabilities_stub;
    test_rpc_write_u32(invalid_capabilities_stub, 99);
    const auto invalid_capabilities_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(21, 17, invalid_capabilities_stub),
        "netlogon",
        password_update_runtime);
    assert(test_rpc_read_u32(invalid_capabilities_response, 16) == 16);
    assert(test_rpc_read_u32(invalid_capabilities_response, 36) == 0xc0000148U);
    const std::uint32_t capabilities_timestamp = domain_info_timestamp + 2;
    const auto capabilities_seed = protocol::advance_netlogon_credential_seed(
        *domain_info_return_credential,
        capabilities_timestamp);
    const auto capabilities_credential = protocol::compute_netlogon_aes_credential(
        netlogon_material->session_key,
        capabilities_seed);
    assert(capabilities_credential.has_value());
    const auto capabilities_request = test_rpc_request_opnum(
        21,
        18,
        test_netlogon_capabilities_stub(
            "WS01$",
            "WS01",
            *capabilities_credential,
            capabilities_timestamp,
            1));
    const auto capabilities_response =
        protocol::rpc_named_pipe_response(capabilities_request, "netlogon", password_update_runtime);
    assert(!capabilities_response.empty());
    assert(test_rpc_read_u32(capabilities_response, 16) == 24);
    const auto capabilities_return_seed = protocol::advance_netlogon_credential_seed(capabilities_seed, 1);
    const auto capabilities_return_credential = protocol::compute_netlogon_aes_credential(
        netlogon_material->session_key,
        capabilities_return_seed);
    assert(capabilities_return_credential.has_value());
    assert(std::equal(
        capabilities_return_credential->begin(),
        capabilities_return_credential->end(),
        capabilities_response.begin() + 24));
    assert(test_rpc_read_u32(capabilities_response, 36) == 1);
    assert(test_rpc_read_u32(capabilities_response, 40) == negotiated_netlogon_flags);
    assert(test_rpc_read_u32(capabilities_response, 44) == 0);
    const std::uint32_t requested_flags_timestamp = capabilities_timestamp + 2;
    const auto requested_flags_seed = protocol::advance_netlogon_credential_seed(
        *capabilities_return_credential,
        requested_flags_timestamp);
    const auto requested_flags_credential = protocol::compute_netlogon_aes_credential(
        netlogon_material->session_key,
        requested_flags_seed);
    assert(requested_flags_credential.has_value());
    const auto requested_flags_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(
            21,
            19,
            test_netlogon_capabilities_stub(
                "WS01$",
                "WS01",
                *requested_flags_credential,
                requested_flags_timestamp,
                2)),
        "netlogon",
        password_update_runtime);
    assert(test_rpc_read_u32(requested_flags_response, 16) == 24);
    assert(test_rpc_read_u32(requested_flags_response, 36) == 2);
    assert(test_rpc_read_u32(requested_flags_response, 40) == requested_netlogon_flags);
    assert(test_rpc_read_u32(requested_flags_response, 44) == 0);
    const auto requested_flags_return_seed = protocol::advance_netlogon_credential_seed(requested_flags_seed, 1);
    const auto requested_flags_return_credential = protocol::compute_netlogon_aes_credential(
        netlogon_material->session_key,
        requested_flags_return_seed);
    assert(requested_flags_return_credential.has_value());
    const auto alice_nt_hash = security::derive_ad_credentials("alice-secret", "ENDORIUM.LOCAL", "alice").nt_hash_hex;
    password_update_runtime.netlogon_accounts.push_back({"alice", alice_nt_hash, 1701});
    password_update_runtime.samr_account_handler =
        [](const protocol::SamrAccountRequest& request) -> std::optional<protocol::SamrAccountRecord> {
            if (request.sam_account_name == "alice" || request.rid == 1701) {
                return protocol::SamrAccountRecord{"alice", 1701, "Alice Example", 513, 0x00000200U, false, {513, 512}};
            }
            return std::nullopt;
        };
    const TestBytes sam_logon_server_challenge{0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28};
    const TestBytes sam_logon_client_challenge{0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38};
    const auto sam_logon_ntlmv2 = protocol::compute_netlogon_ntlmv2_response(
        alice_nt_hash,
        "alice",
        "ENDORIUM",
        sam_logon_server_challenge,
        sam_logon_client_challenge);
    assert(sam_logon_ntlmv2.has_value());
    auto bad_sam_logon_ntlmv2 = *sam_logon_ntlmv2;
    bad_sam_logon_ntlmv2[0] ^= 0xffU;
    const auto bad_sam_logon_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(
            39,
            20,
            test_netlogon_sam_logon_stub(
                "WS01$",
                "WS01",
                "alice",
                {},
                0,
                6,
                0x00000001U,
                false,
                sam_logon_server_challenge,
                bad_sam_logon_ntlmv2)),
        "netlogon",
        password_update_runtime);
    assert(test_rpc_read_u32(bad_sam_logon_response, bad_sam_logon_response.size() - 4) == 0xc0000022U);
    const auto sam_logon_ex_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(
            39,
            21,
            test_netlogon_sam_logon_stub(
                "WS01$",
                "WS01",
                "alice",
                {},
                0,
                6,
                0x00000001U,
                false,
                sam_logon_server_challenge,
                *sam_logon_ntlmv2)),
        "netlogon",
        password_update_runtime);
    assert(!sam_logon_ex_response.empty());
    assert(test_rpc_read_u32(sam_logon_ex_response, 16) > 180);
    assert(test_rpc_read_u32(sam_logon_ex_response, 24) == 0x00020300U);
    assert(test_rpc_read_u32(sam_logon_ex_response, 28) == 6);
    const TestBytes alice_utf16{'a', 0, 'l', 0, 'i', 0, 'c', 0, 'e', 0};
    assert(std::search(
        sam_logon_ex_response.begin(),
        sam_logon_ex_response.end(),
        alice_utf16.begin(),
        alice_utf16.end()) != sam_logon_ex_response.end());
    const TestBytes sam_logon_rid_1701{0xa5, 0x06, 0x00, 0x00};
    assert(std::search(
        sam_logon_ex_response.begin(),
        sam_logon_ex_response.end(),
        sam_logon_rid_1701.begin(),
        sam_logon_rid_1701.end()) != sam_logon_ex_response.end());
    assert(test_rpc_read_u32(sam_logon_ex_response, sam_logon_ex_response.size() - 4) == 0);
    password_update_runtime.samr_account_handler =
        [](const protocol::SamrAccountRequest& request) -> std::optional<protocol::SamrAccountRecord> {
            if (request.sam_account_name == "alice" || request.rid == 1701) {
                return protocol::SamrAccountRecord{"alice", 1701, "Alice Example", 513, 0x00000202U, false, {513, 512}};
            }
            return std::nullopt;
        };
    const auto disabled_sam_logon_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(
            39,
            76,
            test_netlogon_sam_logon_stub(
                "WS01$",
                "WS01",
                "alice",
                {},
                0,
                6,
                0x00000001U,
                false,
                sam_logon_server_challenge,
                *sam_logon_ntlmv2)),
        "netlogon",
        password_update_runtime);
    assert(test_rpc_read_u32(disabled_sam_logon_response, disabled_sam_logon_response.size() - 4) == 0xc0000072U);
    password_update_runtime.samr_account_handler =
        [](const protocol::SamrAccountRequest& request) -> std::optional<protocol::SamrAccountRecord> {
            if (request.sam_account_name == "alice" || request.rid == 1701) {
                return protocol::SamrAccountRecord{"alice", 1701, "Alice Example", 513, 0x00000200U, false, {513, 512}};
            }
            return std::nullopt;
        };
    const std::uint32_t sam_logon_timestamp = requested_flags_timestamp + 2;
    const auto sam_logon_seed = protocol::advance_netlogon_credential_seed(
        *requested_flags_return_credential,
        sam_logon_timestamp);
    const auto sam_logon_credential = protocol::compute_netlogon_aes_credential(
        netlogon_material->session_key,
        sam_logon_seed);
    assert(sam_logon_credential.has_value());
    const auto sam_logon_with_flags_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(
            45,
            22,
            test_netlogon_sam_logon_stub(
                "WS01$",
                "WS01",
                "alice",
                *sam_logon_credential,
                sam_logon_timestamp,
                3,
                0x00000002U,
                true,
                sam_logon_server_challenge,
                *sam_logon_ntlmv2)),
        "netlogon",
        password_update_runtime);
    assert(!sam_logon_with_flags_response.empty());
    assert(test_rpc_read_u32(sam_logon_with_flags_response, 16) > 180);
    const auto expected_sam_logon_return_seed = protocol::advance_netlogon_credential_seed(sam_logon_seed, 1);
    const auto expected_sam_logon_return_credential = protocol::compute_netlogon_aes_credential(
        netlogon_material->session_key,
        expected_sam_logon_return_seed);
    assert(expected_sam_logon_return_credential.has_value());
    assert(std::equal(
        expected_sam_logon_return_credential->begin(),
        expected_sam_logon_return_credential->end(),
        sam_logon_with_flags_response.begin() + 24));
    assert(test_rpc_read_u32(sam_logon_with_flags_response, 36) == 0x00020300U);
    assert(test_rpc_read_u32(sam_logon_with_flags_response, 40) == 3);
    assert(test_rpc_read_u32(sam_logon_with_flags_response, sam_logon_with_flags_response.size() - 4) == 0);

    const auto samr_bind = test_rpc_samr_bind();
    const auto parsed_samr_bind = protocol::parse_rpc_request(samr_bind);
    assert(parsed_samr_bind.valid);
    assert(parsed_samr_bind.abstract_syntaxes[0] == "12345778-1234-abcd-ef00-0123456789ac");
    assert(protocol::rpc_named_pipe_response(samr_bind, "samr")[2] == 0x0c);
    protocol::RpcRuntimeInfo domain_runtime = rpc_runtime;
    domain_runtime.domain_netbios_name = "ENDORIUM";
    domain_runtime.domain_dns_name = "endorium.local";
    domain_runtime.domain_sid = "S-1-5-21-111-222-333";
    bool samr_create_seen = false;
    bool samr_update_seen = false;
    bool samr_password_update_seen = false;
    bool samr_group_member_add_seen = false;
    bool samr_group_member_delete_seen = false;
    bool samr_alias_member_add_seen = false;
    bool samr_alias_member_delete_seen = false;
    domain_runtime.samr_account_handler = [&](const protocol::SamrAccountRequest& request) -> std::optional<protocol::SamrAccountRecord> {
        if (request.create_if_missing) {
            samr_create_seen = true;
            assert(request.sam_account_name == "WS02$");
            return protocol::SamrAccountRecord{request.sam_account_name, 4242, "WS02", 515, 0x00001020U, true};
        }
        if (request.sam_account_name == "alice") {
            return protocol::SamrAccountRecord{"alice", 1701, "Alice", 513, 0x00000200U, false};
        }
        if (request.sam_account_name == "WS02$") {
            return protocol::SamrAccountRecord{"WS02$", 4242, "WS02", 515, 0x00001020U, true};
        }
        if (request.rid == 4242) {
            return protocol::SamrAccountRecord{"WS02$", 4242, "WS02", 515, 0x00001020U, true};
        }
        return std::nullopt;
    };
    domain_runtime.samr_account_update_handler = [&](const protocol::SamrAccountUpdate& update) {
        samr_update_seen = true;
        assert(update.rid == 4242);
        if (update.user_account_control.has_value()) {
            assert(*update.user_account_control == 0x00001000U);
        }
        if (update.new_password.has_value()) {
            samr_password_update_seen = true;
            assert(*update.new_password == "machine-samr-secret");
        }
        return true;
    };
    domain_runtime.samr_membership_update_handler = [&](const protocol::SamrMembershipUpdate& update) {
        assert(update.member_rids.size() == 1);
        if (!update.alias) {
            assert(update.container_rid == 515);
            assert(update.member_rids[0] == 1701);
            if (update.add) {
                samr_group_member_add_seen = true;
            } else {
                samr_group_member_delete_seen = true;
            }
            return true;
        }

        assert(update.container_rid == 544);
        assert(update.member_rids[0] == 4242);
        if (update.add) {
            samr_alias_member_add_seen = true;
        } else {
            samr_alias_member_delete_seen = true;
        }
        return true;
    };
    domain_runtime.samr_account_enumerator = []() {
        return std::vector<protocol::SamrAccountRecord>{
            {"alice", 1701, "Alice", 513, 0x00000200U, false, {513}, 1},
            {"WS02$", 4242, "WS02", 515, 0x00001020U, true, {515}, 9},
        };
    };
    const TestBytes ws02_utf16{'W', 0, 'S', 0, '0', 0, '2', 0, '$', 0};
    const TestBytes domain_admins_utf16{
        'D', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0, ' ', 0, 'A', 0, 'd', 0, 'm', 0, 'i', 0, 'n', 0, 's', 0};
    const TestBytes domain_computers_utf16{
        'D', 0, 'o', 0, 'm', 0, 'a', 0, 'i', 0, 'n', 0, ' ', 0, 'C', 0, 'o', 0, 'm', 0, 'p', 0, 'u', 0, 't', 0, 'e', 0, 'r', 0, 's', 0};
    const auto samr_lookup_domain_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(5, 16), "samr", domain_runtime);
    assert(!samr_lookup_domain_response.empty());
    assert(samr_lookup_domain_response[2] == 0x02);
    assert(test_rpc_read_u32(samr_lookup_domain_response, 16) == 32);
    assert(samr_lookup_domain_response[28] == 1);
    assert(samr_lookup_domain_response[29] == 4);
    assert(test_rpc_read_u32(samr_lookup_domain_response, 36) == 21);
    assert(test_rpc_read_u32(samr_lookup_domain_response, 52) == 0);
    const auto samr_open_domain_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(7, 17), "samr", domain_runtime);
    assert(test_rpc_read_u32(samr_open_domain_response, 16) == 24);
    assert(test_rpc_read_u32(samr_open_domain_response, 44) == 0);
    const auto samr_connect4_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(62, 69), "samr", domain_runtime);
    assert(test_rpc_read_u32(samr_connect4_response, 16) == 24);
    assert(test_rpc_read_u32(samr_connect4_response, 44) == 0);
    const auto samr_enumerate_domains_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(6, 89), "samr", domain_runtime);
    assert(test_rpc_read_u32(samr_enumerate_domains_response, 16) > 40);
    assert(test_rpc_read_u32(samr_enumerate_domains_response, samr_enumerate_domains_response.size() - 4) == 0);
    const TestBytes endorium_utf16{'E', 0, 'N', 0, 'D', 0, 'O', 0, 'R', 0, 'I', 0, 'U', 0, 'M', 0};
    assert(std::search(
        samr_enumerate_domains_response.begin(),
        samr_enumerate_domains_response.end(),
        endorium_utf16.begin(),
        endorium_utf16.end()) != samr_enumerate_domains_response.end());
    const auto samr_query_domain_info_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(8, 57), "samr", domain_runtime);
    assert(test_rpc_read_u32(samr_query_domain_info_response, samr_query_domain_info_response.size() - 4) == 0);
    assert(std::search(
        samr_query_domain_info_response.begin(),
        samr_query_domain_info_response.end(),
        endorium_utf16.begin(),
        endorium_utf16.end()) != samr_query_domain_info_response.end());
    assert(std::search(
        samr_query_domain_info_response.begin(),
        samr_query_domain_info_response.end(),
        domain_dns_utf16.begin(),
        domain_dns_utf16.end()) != samr_query_domain_info_response.end());
    TestBytes samr_query_domain2_stub(20, 0);
    test_rpc_write_u32(samr_query_domain2_stub, 13);
    const auto samr_query_domain_info2_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(46, 70, samr_query_domain2_stub), "samr", domain_runtime);
    assert(test_rpc_read_u32(samr_query_domain_info2_response, 16) > 70);
    assert(test_rpc_read_u32(samr_query_domain_info2_response, 28) == 13);
    assert(test_rpc_read_u32(samr_query_domain_info2_response, samr_query_domain_info2_response.size() - 4) == 0);
    assert(std::search(
        samr_query_domain_info2_response.begin(),
        samr_query_domain_info2_response.end(),
        domain_dns_utf16.begin(),
        domain_dns_utf16.end()) != samr_query_domain_info2_response.end());
    const auto samr_set_domain_info_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(9, 71, samr_query_domain2_stub), "samr", domain_runtime);
    assert(test_rpc_read_u32(samr_set_domain_info_response, 16) == 4);
    assert(test_rpc_read_u32(samr_set_domain_info_response, 24) == 0);
    samr_create_seen = false;
    const auto samr_create_user_legacy_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(12, 72, test_rpc_ndr_utf16_string("WS02$")),
        "samr",
        domain_runtime);
    assert(!samr_create_user_legacy_response.empty());
    assert(test_rpc_read_u32(samr_create_user_legacy_response, 16) == 28);
    assert(test_rpc_read_u32(samr_create_user_legacy_response, 32) == 4242);
    assert(test_rpc_read_u32(samr_create_user_legacy_response, 36) == 0x55535253U);
    assert(test_rpc_read_u32(samr_create_user_legacy_response, 44) == 4242);
    assert(test_rpc_read_u32(samr_create_user_legacy_response, 48) == 0);
    assert(samr_create_seen);
    samr_create_seen = false;
    const auto samr_create_user_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(50, 18, test_rpc_ndr_utf16_string("WS02$")),
        "samr",
        domain_runtime);
    assert(!samr_create_user_response.empty());
    assert(test_rpc_read_u32(samr_create_user_response, 16) == 32);
    assert(test_rpc_read_u32(samr_create_user_response, 44) == 0x001f01ffU);
    assert(test_rpc_read_u32(samr_create_user_response, 48) == 4242);
    assert(test_rpc_read_u32(samr_create_user_response, 52) == 0);
    assert(samr_create_seen);
    const auto samr_lookup_names_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(17, 20, test_rpc_ndr_utf16_string("alice")),
        "samr",
        domain_runtime);
    assert(!samr_lookup_names_response.empty());
    assert(test_rpc_read_u32(samr_lookup_names_response, 36) == 1701);
    const auto samr_lookup_domain_admins_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(17, 41, test_rpc_ndr_utf16_string("Domain Admins")),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_lookup_domain_admins_response, 36) == 512);
    assert(test_rpc_read_u32(samr_lookup_domain_admins_response, 52) == 2);
    const auto samr_lookup_administrators_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(17, 42, test_rpc_ndr_utf16_string("Administrators")),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_lookup_administrators_response, 36) == 544);
    assert(test_rpc_read_u32(samr_lookup_administrators_response, 52) == 4);
    TestBytes samr_lookup_ids_stub(20, 0);
    test_rpc_write_u32(samr_lookup_ids_stub, 1);
    test_rpc_write_u32(samr_lookup_ids_stub, 1);
    test_rpc_write_u32(samr_lookup_ids_stub, 4242);
    const auto samr_lookup_ids_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(18, 27, samr_lookup_ids_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_lookup_ids_response, 16) > 40);
    assert(std::search(
        samr_lookup_ids_response.begin(),
        samr_lookup_ids_response.end(),
        ws02_utf16.begin(),
        ws02_utf16.end()) != samr_lookup_ids_response.end());
    TestBytes samr_lookup_group_ids_stub(20, 0);
    test_rpc_write_u32(samr_lookup_group_ids_stub, 1);
    test_rpc_write_u32(samr_lookup_group_ids_stub, 1);
    test_rpc_write_u32(samr_lookup_group_ids_stub, 512);
    const auto samr_lookup_group_ids_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(18, 43, samr_lookup_group_ids_stub),
        "samr",
        domain_runtime);
    assert(std::search(
        samr_lookup_group_ids_response.begin(),
        samr_lookup_group_ids_response.end(),
        domain_admins_utf16.begin(),
        domain_admins_utf16.end()) != samr_lookup_group_ids_response.end());
    const auto samr_enumerate_users_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(13, 44), "samr", domain_runtime);
    assert(test_rpc_read_u32(samr_enumerate_users_response, 16) > 120);
    assert(test_rpc_read_u32(samr_enumerate_users_response, samr_enumerate_users_response.size() - 4) == 0);
    assert(std::search(
        samr_enumerate_users_response.begin(),
        samr_enumerate_users_response.end(),
        alice_utf16.begin(),
        alice_utf16.end()) != samr_enumerate_users_response.end());
    assert(std::search(
        samr_enumerate_users_response.begin(),
        samr_enumerate_users_response.end(),
        ws02_utf16.begin(),
        ws02_utf16.end()) != samr_enumerate_users_response.end());
    const auto samr_enumerate_groups_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(11, 45), "samr", domain_runtime);
    assert(test_rpc_read_u32(samr_enumerate_groups_response, 16) > 120);
    assert(std::search(
        samr_enumerate_groups_response.begin(),
        samr_enumerate_groups_response.end(),
        domain_admins_utf16.begin(),
        domain_admins_utf16.end()) != samr_enumerate_groups_response.end());
    TestBytes samr_open_group_stub(8, 0);
    test_rpc_write_u32(samr_open_group_stub, 515);
    const auto samr_open_group_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(19, 58, samr_open_group_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_open_group_response, 16) == 24);
    assert(test_rpc_read_u32(samr_open_group_response, 32) == 515);
    assert(test_rpc_read_u32(samr_open_group_response, 36) == 0x50524753U);
    assert(test_rpc_read_u32(samr_open_group_response, 44) == 0);
    const TestBytes samr_group_handle(samr_open_group_response.begin() + 24, samr_open_group_response.begin() + 44);
    auto samr_query_group_stub = samr_group_handle;
    test_rpc_write_u32(samr_query_group_stub, 1);
    const auto samr_query_group_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(20, 59, samr_query_group_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_query_group_response, samr_query_group_response.size() - 4) == 0);
    assert(std::search(
        samr_query_group_response.begin(),
        samr_query_group_response.end(),
        domain_computers_utf16.begin(),
        domain_computers_utf16.end()) != samr_query_group_response.end());
    const auto samr_group_members_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(25, 60, samr_group_handle),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_group_members_response, samr_group_members_response.size() - 4) == 0);
    const TestBytes ws02_rid{0x92, 0x10, 0, 0};
    assert(std::search(
        samr_group_members_response.begin(),
        samr_group_members_response.end(),
        ws02_rid.begin(),
        ws02_rid.end()) != samr_group_members_response.end());
    const auto samr_set_group_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(21, 61, samr_query_group_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_set_group_response, samr_set_group_response.size() - 4) == 0);
    const auto samr_delete_group_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(23, 90, samr_group_handle),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_delete_group_response, 24) == 0);
    auto samr_add_group_member_stub = samr_group_handle;
    test_rpc_write_u32(samr_add_group_member_stub, 1701);
    test_rpc_write_u32(samr_add_group_member_stub, 0x00000007U);
    const auto samr_add_group_member_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(22, 62, samr_add_group_member_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_add_group_member_response, 24) == 0);
    assert(samr_group_member_add_seen);
    auto samr_delete_group_member_stub = samr_group_handle;
    test_rpc_write_u32(samr_delete_group_member_stub, 1701);
    const auto samr_delete_group_member_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(24, 63, samr_delete_group_member_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_delete_group_member_response, 24) == 0);
    assert(samr_group_member_delete_seen);
    TestBytes samr_display_stub(20, 0);
    test_rpc_write_u32(samr_display_stub, 1);
    test_rpc_write_u32(samr_display_stub, 0);
    test_rpc_write_u32(samr_display_stub, 16);
    test_rpc_write_u32(samr_display_stub, 4096);
    const auto samr_query_display_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(40, 46, samr_display_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_query_display_response, samr_query_display_response.size() - 4) == 0);
    assert(std::search(
        samr_query_display_response.begin(),
        samr_query_display_response.end(),
        alice_utf16.begin(),
        alice_utf16.end()) != samr_query_display_response.end());
    TestBytes samr_display_index_stub(20, 0);
    test_rpc_write_u32(samr_display_index_stub, 1);
    const auto alice_prefix = test_rpc_ndr_utf16_string("alice");
    samr_display_index_stub.insert(samr_display_index_stub.end(), alice_prefix.begin(), alice_prefix.end());
    const auto samr_display_index_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(41, 47, samr_display_index_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_display_index_response, 16) == 8);
    assert(test_rpc_read_u32(samr_display_index_response, samr_display_index_response.size() - 4) == 0);
    const auto samr_enumerate_aliases_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(15, 48), "samr", domain_runtime);
    assert(test_rpc_read_u32(samr_enumerate_aliases_response, 16) > 120);
    const TestBytes administrators_utf16{
        'A', 0, 'd', 0, 'm', 0, 'i', 0, 'n', 0, 'i', 0, 's', 0, 't', 0, 'r', 0, 'a', 0, 't', 0, 'o', 0, 'r', 0, 's', 0};
    assert(std::search(
        samr_enumerate_aliases_response.begin(),
        samr_enumerate_aliases_response.end(),
        administrators_utf16.begin(),
        administrators_utf16.end()) != samr_enumerate_aliases_response.end());
    TestBytes samr_alias_membership_stub(20, 0);
    const auto administrator_sid = test_rpc_sid({21, 111, 222, 333, 500});
    samr_alias_membership_stub.insert(
        samr_alias_membership_stub.end(),
        administrator_sid.begin(),
        administrator_sid.end());
    const auto samr_alias_membership_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(16, 49, samr_alias_membership_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_alias_membership_response, samr_alias_membership_response.size() - 4) == 0);
    const TestBytes administrators_rid{0x20, 0x02, 0, 0};
    assert(std::search(
        samr_alias_membership_response.begin(),
        samr_alias_membership_response.end(),
        administrators_rid.begin(),
        administrators_rid.end()) != samr_alias_membership_response.end());
    TestBytes samr_open_alias_stub(8, 0);
    test_rpc_write_u32(samr_open_alias_stub, 544);
    const auto samr_open_alias_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(27, 50, samr_open_alias_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_open_alias_response, 16) == 24);
    assert(test_rpc_read_u32(samr_open_alias_response, 32) == 544);
    assert(test_rpc_read_u32(samr_open_alias_response, 36) == 0x53494c41U);
    assert(test_rpc_read_u32(samr_open_alias_response, 44) == 0);
    const TestBytes samr_alias_handle(samr_open_alias_response.begin() + 24, samr_open_alias_response.begin() + 44);
    auto samr_query_alias_stub = samr_alias_handle;
    test_rpc_write_u32(samr_query_alias_stub, 1);
    const auto samr_query_alias_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(28, 47, samr_query_alias_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_query_alias_response, 16) > 80);
    assert(std::search(
        samr_query_alias_response.begin(),
        samr_query_alias_response.end(),
        administrators_utf16.begin(),
        administrators_utf16.end()) != samr_query_alias_response.end());
    const auto samr_set_alias_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(29, 91, samr_query_alias_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_set_alias_response, 24) == 0);
    const auto samr_delete_alias_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(30, 92, samr_alias_handle),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_delete_alias_response, 24) == 0);
    const auto samr_alias_members_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(33, 48, samr_alias_handle),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_alias_members_response, samr_alias_members_response.size() - 4) == 0);
    const TestBytes domain_admins_rid{0x00, 0x02, 0, 0};
    assert(std::search(
        samr_alias_members_response.begin(),
        samr_alias_members_response.end(),
        domain_admins_rid.begin(),
        domain_admins_rid.end()) != samr_alias_members_response.end());
    auto samr_add_alias_member_stub = samr_alias_handle;
    const auto ws02_sid = test_rpc_sid({21, 111, 222, 333, 4242});
    samr_add_alias_member_stub.insert(
        samr_add_alias_member_stub.end(),
        ws02_sid.begin(),
        ws02_sid.end());
    const auto samr_add_alias_member_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(31, 64, samr_add_alias_member_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_add_alias_member_response, 24) == 0);
    assert(samr_alias_member_add_seen);
    auto samr_delete_alias_member_stub = samr_alias_handle;
    samr_delete_alias_member_stub.insert(
        samr_delete_alias_member_stub.end(),
        ws02_sid.begin(),
        ws02_sid.end());
    const auto samr_delete_alias_member_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(32, 65, samr_delete_alias_member_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_delete_alias_member_response, 24) == 0);
    assert(samr_alias_member_delete_seen);
    const auto samr_open_user_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(34, 21, {0, 0, 0, 0, 0, 0, 0, 0, 0x92, 0x10, 0, 0}),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_open_user_response, 16) == 24);
    assert(test_rpc_read_u32(samr_open_user_response, 44) == 0);
    const TestBytes samr_user_handle(samr_open_user_response.begin() + 24, samr_open_user_response.begin() + 44);
    TestBytes samr_query_security_stub = samr_user_handle;
    test_rpc_write_u32(samr_query_security_stub, 0x00000007U);
    const auto samr_query_security_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(3, 66, samr_query_security_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_query_security_response, 16) > 100);
    assert(test_rpc_read_u32(samr_query_security_response, 24) != 0);
    assert(test_rpc_read_u32(samr_query_security_response, samr_query_security_response.size() - 4) == 0);
    const TestBytes self_relative_sd_header{1, 0, 4, 0x80};
    assert(std::search(
        samr_query_security_response.begin(),
        samr_query_security_response.end(),
        self_relative_sd_header.begin(),
        self_relative_sd_header.end()) != samr_query_security_response.end());
    const TestBytes builtin_admins_sid_bytes{1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0, 0};
    assert(std::search(
        samr_query_security_response.begin(),
        samr_query_security_response.end(),
        builtin_admins_sid_bytes.begin(),
        builtin_admins_sid_bytes.end()) != samr_query_security_response.end());
    const auto samr_set_security_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(2, 67, samr_user_handle),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_set_security_response, 16) == 4);
    assert(test_rpc_read_u32(samr_set_security_response, 24) == 0);
    const auto samr_delete_user_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(35, 93, samr_user_handle),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_delete_user_response, 24) == 0);
    auto samr_remove_foreign_member_stub = samr_user_handle;
    samr_remove_foreign_member_stub.insert(
        samr_remove_foreign_member_stub.end(),
        ws02_sid.begin(),
        ws02_sid.end());
    const auto samr_remove_foreign_member_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(45, 94, samr_remove_foreign_member_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_remove_foreign_member_response, 24) == 0);
    auto samr_query_stub = samr_user_handle;
    test_rpc_write_u32(samr_query_stub, 16);
    const auto samr_query_user_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(47, 22, samr_query_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_query_user_response, 16) == 16);
    assert(test_rpc_read_u32(samr_query_user_response, 28) == 16);
    assert(test_rpc_read_u32(samr_query_user_response, 32) == 0x00001020U);
    assert(test_rpc_read_u32(samr_query_user_response, 36) == 0);
    auto samr_query_v1_stub = samr_user_handle;
    test_rpc_write_u32(samr_query_v1_stub, 9);
    const auto samr_query_user_v1_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(36, 24, samr_query_v1_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_query_user_v1_response, 28) == 9);
    assert(test_rpc_read_u32(samr_query_user_v1_response, 32) == 515);
    const auto samr_groups_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(39, 25, samr_user_handle),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_groups_response, 16) == 28);
    assert(test_rpc_read_u32(samr_groups_response, 28) == 1);
    assert(test_rpc_read_u32(samr_groups_response, 36) == 1);
    assert(test_rpc_read_u32(samr_groups_response, 40) == 515);
    assert(test_rpc_read_u32(samr_groups_response, 44) == 0x00000007U);
    assert(test_rpc_read_u32(samr_groups_response, 48) == 0);
    const auto samr_user_password_info_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(44, 28, samr_user_handle),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_user_password_info_response, 16) == 28);
    assert(test_rpc_read_u16(samr_user_password_info_response, 24) == 0);
    const auto samr_domain_password_info_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(56, 29),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_domain_password_info_response, 16) == 28);
    assert(test_rpc_read_u16(samr_domain_password_info_response, 24) == 8);
    auto samr_rid_to_sid_stub = samr_user_handle;
    test_rpc_write_u32(samr_rid_to_sid_stub, 4242);
    const auto samr_rid_to_sid_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(65, 30, samr_rid_to_sid_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_rid_to_sid_response, 16) == 36);
    assert(samr_rid_to_sid_response[29] == 5);
    assert(test_rpc_read_u32(samr_rid_to_sid_response, 52) == 4242);
    auto samr_set_stub = samr_user_handle;
    test_rpc_write_u32(samr_set_stub, 16);
    test_rpc_write_u32(samr_set_stub, 0x00001000U);
    const auto samr_set_user_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(58, 23, samr_set_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_set_user_response, 16) == 4);
    assert(test_rpc_read_u32(samr_set_user_response, 24) == 0);
    assert(samr_update_seen);
    auto samr_set_password_stub = samr_user_handle;
    test_rpc_write_u32(samr_set_password_stub, 24);
    const auto samr_password_blob = test_samr_user_password_blob("machine-samr-secret");
    samr_set_password_stub.insert(samr_set_password_stub.end(), samr_password_blob.begin(), samr_password_blob.end());
    samr_set_password_stub.push_back(0);
    const auto samr_set_password_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(58, 26, samr_set_password_stub),
        "samr",
        domain_runtime);
    assert(test_rpc_read_u32(samr_set_password_response, 16) == 4);
    assert(test_rpc_read_u32(samr_set_password_response, 24) == 0);
    assert(samr_password_update_seen);
    const auto lsa_domain_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(46, 19), "lsarpc", domain_runtime);
    assert(!lsa_domain_response.empty());
    assert(lsa_domain_response[2] == 0x02);
    assert(test_rpc_read_u32(lsa_domain_response, 16) > 40);
    assert(test_rpc_read_u32(lsa_domain_response, 24) == 0x00020010U);
    const auto lsa_open_policy_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(6, 31), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_open_policy_response, 16) == 24);
    assert(test_rpc_read_u32(lsa_open_policy_response, 44) == 0);
    const TestBytes lsa_policy_handle(lsa_open_policy_response.begin() + 24, lsa_open_policy_response.begin() + 44);
    TestBytes lsa_query_security_stub = lsa_policy_handle;
    test_rpc_write_u32(lsa_query_security_stub, 0x00000007U);
    const auto lsa_query_security_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(3, 82, lsa_query_security_stub),
        "lsarpc",
        domain_runtime);
    assert(test_rpc_read_u32(lsa_query_security_response, 16) > 100);
    assert(test_rpc_read_u32(lsa_query_security_response, 24) != 0);
    assert(test_rpc_read_u32(lsa_query_security_response, lsa_query_security_response.size() - 4) == 0);
    assert(std::search(
        lsa_query_security_response.begin(),
        lsa_query_security_response.end(),
        self_relative_sd_header.begin(),
        self_relative_sd_header.end()) != lsa_query_security_response.end());
    const auto lsa_set_security_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(4, 83, lsa_policy_handle), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_set_security_response, 16) == 4);
    assert(test_rpc_read_u32(lsa_set_security_response, 24) == 0);
    const auto lsa_trusted_domains_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(13, 84, lsa_policy_handle), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_trusted_domains_response, 16) > 60);
    assert(test_rpc_read_u32(lsa_trusted_domains_response, 24) == 0);
    assert(test_rpc_read_u32(lsa_trusted_domains_response, 32) == 1);
    assert(test_rpc_read_u32(lsa_trusted_domains_response, lsa_trusted_domains_response.size() - 4) == 0);
    assert(std::search(
        lsa_trusted_domains_response.begin(),
        lsa_trusted_domains_response.end(),
        endorium_netbios_utf16.begin(),
        endorium_netbios_utf16.end()) != lsa_trusted_domains_response.end());
    const auto lsa_domain_sid_bytes = test_rpc_sid({21, 111, 222, 333});
    assert(std::search(
        lsa_trusted_domains_response.begin(),
        lsa_trusted_domains_response.end(),
        lsa_domain_sid_bytes.begin(),
        lsa_domain_sid_bytes.end()) != lsa_trusted_domains_response.end());
    const auto lsa_trusted_domains_ex_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(41, 85, lsa_policy_handle), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_trusted_domains_ex_response, 16) > 90);
    assert(test_rpc_read_u32(lsa_trusted_domains_ex_response, 32) == 1);
    assert(test_rpc_read_u32(lsa_trusted_domains_ex_response, lsa_trusted_domains_ex_response.size() - 4) == 0);
    assert(std::search(
        lsa_trusted_domains_ex_response.begin(),
        lsa_trusted_domains_ex_response.end(),
        domain_dns_utf16.begin(),
        domain_dns_utf16.end()) != lsa_trusted_domains_ex_response.end());
    TestBytes lsa_open_trust_stub = lsa_policy_handle;
    lsa_open_trust_stub.insert(lsa_open_trust_stub.end(), lsa_domain_sid_bytes.begin(), lsa_domain_sid_bytes.end());
    const auto lsa_open_trusted_domain_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(25, 86, lsa_open_trust_stub), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_open_trusted_domain_response, 16) == 24);
    assert(test_rpc_read_u32(lsa_open_trusted_domain_response, 36) == 0x5453444dU);
    assert(test_rpc_read_u32(lsa_open_trusted_domain_response, 44) == 0);
    const TestBytes lsa_trust_handle(lsa_open_trusted_domain_response.begin() + 24, lsa_open_trusted_domain_response.begin() + 44);
    TestBytes lsa_query_trust_stub = lsa_trust_handle;
    test_rpc_write_u32(lsa_query_trust_stub, 1);
    const auto lsa_query_trusted_domain_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(26, 87, lsa_query_trust_stub), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_query_trusted_domain_response, 16) > 80);
    assert(test_rpc_read_u32(lsa_query_trusted_domain_response, lsa_query_trusted_domain_response.size() - 4) == 0);
    assert(std::search(
        lsa_query_trusted_domain_response.begin(),
        lsa_query_trusted_domain_response.end(),
        endorium_netbios_utf16.begin(),
        endorium_netbios_utf16.end()) != lsa_query_trusted_domain_response.end());
    assert(std::search(
        lsa_query_trusted_domain_response.begin(),
        lsa_query_trusted_domain_response.end(),
        domain_dns_utf16.begin(),
        domain_dns_utf16.end()) != lsa_query_trusted_domain_response.end());
    const auto lsa_query_trusted_domain_by_name_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(39, 88, test_rpc_ndr_utf16_string("endorium.local")),
        "lsarpc",
        domain_runtime);
    assert(test_rpc_read_u32(lsa_query_trusted_domain_by_name_response, 16) > 80);
    assert(test_rpc_read_u32(
        lsa_query_trusted_domain_by_name_response,
        lsa_query_trusted_domain_by_name_response.size() - 4) == 0);
    assert(std::search(
        lsa_query_trusted_domain_by_name_response.begin(),
        lsa_query_trusted_domain_by_name_response.end(),
        domain_dns_utf16.begin(),
        domain_dns_utf16.end()) != lsa_query_trusted_domain_by_name_response.end());
    const TestBytes se_machine_utf16{
        'S', 0, 'e', 0, 'M', 0, 'a', 0, 'c', 0, 'h', 0, 'i', 0, 'n', 0, 'e', 0,
        'A', 0, 'c', 0, 'c', 0, 'o', 0, 'u', 0, 'n', 0, 't', 0,
        'P', 0, 'r', 0, 'i', 0, 'v', 0, 'i', 0, 'l', 0, 'e', 0, 'g', 0, 'e', 0};
    const auto lsa_enumerate_privileges_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(2, 58), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_enumerate_privileges_response, lsa_enumerate_privileges_response.size() - 4) == 0);
    assert(std::search(
        lsa_enumerate_privileges_response.begin(),
        lsa_enumerate_privileges_response.end(),
        se_machine_utf16.begin(),
        se_machine_utf16.end()) != lsa_enumerate_privileges_response.end());
    const auto lsa_privilege_value_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(31, 59, test_rpc_ndr_utf16_string("SeMachineAccountPrivilege")),
        "lsarpc",
        domain_runtime);
    assert(test_rpc_read_u32(lsa_privilege_value_response, 16) == 12);
    assert(test_rpc_read_u32(lsa_privilege_value_response, 24) == 6);
    assert(test_rpc_read_u32(lsa_privilege_value_response, 32) == 0);
    TestBytes lsa_privilege_luid_stub(20, 0);
    test_rpc_write_u32(lsa_privilege_luid_stub, 6);
    test_rpc_write_u32(lsa_privilege_luid_stub, 0);
    const auto lsa_privilege_name_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(32, 60, lsa_privilege_luid_stub),
        "lsarpc",
        domain_runtime);
    assert(std::search(
        lsa_privilege_name_response.begin(),
        lsa_privilege_name_response.end(),
        se_machine_utf16.begin(),
        se_machine_utf16.end()) != lsa_privilege_name_response.end());
    const auto lsa_privilege_display_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(33, 61, test_rpc_ndr_utf16_string("SeMachineAccountPrivilege")),
        "lsarpc",
        domain_runtime);
    const TestBytes add_workstations_utf16{
        'A', 0, 'd', 0, 'd', 0, ' ', 0, 'w', 0, 'o', 0, 'r', 0, 'k', 0, 's', 0,
        't', 0, 'a', 0, 't', 0, 'i', 0, 'o', 0, 'n', 0, 's', 0};
    assert(std::search(
        lsa_privilege_display_response.begin(),
        lsa_privilege_display_response.end(),
        add_workstations_utf16.begin(),
        add_workstations_utf16.end()) != lsa_privilege_display_response.end());
    const auto lsa_ws02_sid = test_rpc_sid({21, 111, 222, 333, 4242});
    TestBytes lsa_open_account_stub(20, 0);
    lsa_open_account_stub.insert(lsa_open_account_stub.end(), lsa_ws02_sid.begin(), lsa_ws02_sid.end());
    const auto lsa_create_account_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(10, 89, lsa_open_account_stub), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_create_account_response, 16) == 24);
    assert(test_rpc_read_u32(lsa_create_account_response, 32) == 4242);
    assert(test_rpc_read_u32(lsa_create_account_response, 36) == 0x54434341U);
    assert(test_rpc_read_u32(lsa_create_account_response, 44) == 0);
    const auto lsa_open_account_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(17, 62, lsa_open_account_stub), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_open_account_response, 16) == 24);
    assert(test_rpc_read_u32(lsa_open_account_response, 32) == 4242);
    assert(test_rpc_read_u32(lsa_open_account_response, 36) == 0x54434341U);
    assert(test_rpc_read_u32(lsa_open_account_response, 44) == 0);
    const TestBytes lsa_account_handle(lsa_open_account_response.begin() + 24, lsa_open_account_response.begin() + 44);
    const auto lsa_account_privileges_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(18, 63, lsa_account_handle), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_account_privileges_response, lsa_account_privileges_response.size() - 4) == 0);
    const auto lsa_add_privileges_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(19, 90, lsa_account_handle), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_add_privileges_response, 24) == 0);
    const auto lsa_remove_privileges_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(20, 91, lsa_account_handle), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_remove_privileges_response, 24) == 0);
    const auto lsa_quota_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(21, 92, lsa_account_handle), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_quota_response, 16) == 52);
    assert(test_rpc_read_u32(lsa_quota_response, lsa_quota_response.size() - 4) == 0);
    const auto lsa_set_quota_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(22, 93, lsa_account_handle), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_set_quota_response, 24) == 0);
    const auto lsa_system_access_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(23, 64, lsa_account_handle), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_system_access_response, 16) == 8);
    assert(test_rpc_read_u32(lsa_system_access_response, 28) == 0);
    const auto lsa_delete_object_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(34, 94, lsa_account_handle), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_delete_object_response, 24) == 0);
    const auto lsa_account_rights_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(36, 65, lsa_open_account_stub), "lsarpc", domain_runtime);
    assert(std::search(
        lsa_account_rights_response.begin(),
        lsa_account_rights_response.end(),
        se_machine_utf16.begin(),
        se_machine_utf16.end()) != lsa_account_rights_response.end());
    const auto lsa_accounts_with_right_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(35, 66, test_rpc_ndr_utf16_string("SeMachineAccountPrivilege")),
        "lsarpc",
        domain_runtime);
    assert(test_rpc_read_u32(lsa_accounts_with_right_response, lsa_accounts_with_right_response.size() - 4) == 0);
    assert(test_rpc_read_u32(
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(37, 67, lsa_open_account_stub), "lsarpc", domain_runtime),
        24) == 0);
    assert(test_rpc_read_u32(
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(38, 68, lsa_open_account_stub), "lsarpc", domain_runtime),
        24) == 0);
    const auto lsa_get_user_name_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(45, 95), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_get_user_name_response, lsa_get_user_name_response.size() - 4) == 0);
    const TestBytes administrator_utf16{
        'A', 0, 'd', 0, 'm', 0, 'i', 0, 'n', 0, 'i', 0, 's', 0, 't', 0,
        'r', 0, 'a', 0, 't', 0, 'o', 0, 'r', 0};
    assert(std::search(
        lsa_get_user_name_response.begin(),
        lsa_get_user_name_response.end(),
        administrator_utf16.begin(),
        administrator_utf16.end()) != lsa_get_user_name_response.end());
    const auto lsa_lookup_names_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(14, 32, test_rpc_ndr_utf16_string("alice")), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_lookup_names_response, 16) > 40);
    const TestBytes rid_1701{0xa5, 0x06, 0, 0};
    assert(std::search(
        lsa_lookup_names_response.begin(),
        lsa_lookup_names_response.end(),
        rid_1701.begin(),
        rid_1701.end()) != lsa_lookup_names_response.end());
    const auto lsa_lookup_names3_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(68, 33, test_rpc_ndr_utf16_string("WS02$")), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_lookup_names3_response, 16) > 40);
    const TestBytes rid_4242{0x92, 0x10, 0, 0};
    assert(std::search(
        lsa_lookup_names3_response.begin(),
        lsa_lookup_names3_response.end(),
        rid_4242.begin(),
        rid_4242.end()) != lsa_lookup_names3_response.end());
    TestBytes lsa_sid_lookup_stub(20, 0);
    lsa_sid_lookup_stub.insert(lsa_sid_lookup_stub.end(), lsa_ws02_sid.begin(), lsa_ws02_sid.end());
    const auto lsa_lookup_sids_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(15, 34, lsa_sid_lookup_stub), "lsarpc", domain_runtime);
    assert(test_rpc_read_u32(lsa_lookup_sids_response, 16) > 40);
    assert(std::search(
        lsa_lookup_sids_response.begin(),
        lsa_lookup_sids_response.end(),
        ws02_utf16.begin(),
        ws02_utf16.end()) != lsa_lookup_sids_response.end());
    const auto samr_connect_response = protocol::rpc_named_pipe_response(test_rpc_request_opnum(64, 12), "samr");
    assert(!samr_connect_response.empty());
    assert(samr_connect_response[2] == 0x02);
    assert(test_rpc_read_u32(samr_connect_response, 16) == 24);
    assert(test_rpc_read_u32(samr_connect_response, 44) == 0);
    const auto srvsvc_bind = test_rpc_srvsvc_bind();
    const auto parsed_srvsvc_bind = protocol::parse_rpc_request(srvsvc_bind);
    assert(parsed_srvsvc_bind.valid);
    assert(parsed_srvsvc_bind.abstract_syntaxes[0] == "4b324fc8-1670-01d3-1278-5a47bf6ee188");
    const auto srvsvc_bind_ack = protocol::rpc_named_pipe_response(srvsvc_bind, "srvsvc", domain_runtime);
    assert(!srvsvc_bind_ack.empty());
    assert(srvsvc_bind_ack[2] == 0x0c);
    const auto srvsvc_share_enum_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(15, 35), "srvsvc", domain_runtime);
    assert(test_rpc_read_u32(srvsvc_share_enum_response, 16) > 120);
    const TestBytes sysvol_utf16{'S', 0, 'Y', 0, 'S', 0, 'V', 0, 'O', 0, 'L', 0};
    const TestBytes netlogon_utf16{'N', 0, 'E', 0, 'T', 0, 'L', 0, 'O', 0, 'G', 0, 'O', 0, 'N', 0};
    assert(std::search(
        srvsvc_share_enum_response.begin(),
        srvsvc_share_enum_response.end(),
        sysvol_utf16.begin(),
        sysvol_utf16.end()) != srvsvc_share_enum_response.end());
    assert(std::search(
        srvsvc_share_enum_response.begin(),
        srvsvc_share_enum_response.end(),
        netlogon_utf16.begin(),
        netlogon_utf16.end()) != srvsvc_share_enum_response.end());
    assert(test_rpc_read_u32(srvsvc_share_enum_response, srvsvc_share_enum_response.size() - 4) == 0);
    const auto srvsvc_share_get_response = protocol::rpc_named_pipe_response(
        test_rpc_request_opnum(16, 36, test_rpc_ndr_utf16_string("NETLOGON")),
        "srvsvc",
        domain_runtime);
    assert(test_rpc_read_u32(srvsvc_share_get_response, 16) > 40);
    assert(std::search(
        srvsvc_share_get_response.begin(),
        srvsvc_share_get_response.end(),
        netlogon_utf16.begin(),
        netlogon_utf16.end()) != srvsvc_share_get_response.end());
    const auto srvsvc_server_info_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(21, 37), "srvsvc", domain_runtime);
    assert(test_rpc_read_u32(srvsvc_server_info_response, 16) > 60);
    const TestBytes dc1_utf16{'d', 0, 'c', 0, '1', 0};
    assert(std::search(
        srvsvc_server_info_response.begin(),
        srvsvc_server_info_response.end(),
        dc1_utf16.begin(),
        dc1_utf16.end()) != srvsvc_server_info_response.end());
    const auto wkssvc_bind = test_rpc_wkssvc_bind();
    const auto parsed_wkssvc_bind = protocol::parse_rpc_request(wkssvc_bind);
    assert(parsed_wkssvc_bind.valid);
    assert(parsed_wkssvc_bind.abstract_syntaxes[0] == "6bffd098-a112-3610-9833-46c3f87e345a");
    const auto wkssvc_bind_ack = protocol::rpc_named_pipe_response(wkssvc_bind, "wkssvc", domain_runtime);
    assert(!wkssvc_bind_ack.empty());
    assert(wkssvc_bind_ack[2] == 0x0c);
    const auto wkssvc_info_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(0, 38), "wkssvc", domain_runtime);
    assert(test_rpc_read_u32(wkssvc_info_response, 16) > 60);
    assert(std::search(
        wkssvc_info_response.begin(),
        wkssvc_info_response.end(),
        dc1_utf16.begin(),
        dc1_utf16.end()) != wkssvc_info_response.end());
    const auto wkssvc_user_enum_response =
        protocol::rpc_named_pipe_response(test_rpc_request_opnum(2, 39), "wkssvc", domain_runtime);
    assert(test_rpc_read_u32(wkssvc_user_enum_response, 16) == 24);
    assert(test_rpc_read_u32(wkssvc_user_enum_response, 44) == 0);

    const auto smb_negotiate = test_smb2_negotiate_request();
    const auto parsed_smb = protocol::parse_smb2_request(smb_negotiate);
    assert(parsed_smb.valid);
    assert(parsed_smb.netbios_framed);
    assert(parsed_smb.command == 0);
    assert(parsed_smb.message_id == 99);
    assert(parsed_smb.dialects.size() == 5);
    assert(parsed_smb.selected_dialect == 0x0302);
    const auto smb_response = protocol::smb2_response(smb_negotiate);
    assert(!smb_response.empty());
    assert(smb_response[0] == 0x00);
    assert(test_rpc_read_u16(smb_response, 4 + 12) == 0);
    assert(test_rpc_read_u16(smb_response, 4 + 64 + 4) == 0x0302);
    const auto smb_security_offset = test_rpc_read_u16(smb_response, 4 + 64 + 56);
    const auto smb_security_length = test_rpc_read_u16(smb_response, 4 + 64 + 58);
    assert(smb_security_offset == 128);
    assert(smb_security_length > 0);
    assert(4 + smb_security_offset < smb_response.size());
    assert(smb_response[4 + smb_security_offset] == 0x60);

    const auto smb_session_setup = test_smb2_session_setup_request();
    const auto parsed_smb_session_setup = protocol::parse_smb2_request(smb_session_setup);
    assert(parsed_smb_session_setup.valid);
    assert(parsed_smb_session_setup.command == 1);
    const auto smb_session_response = protocol::smb2_response(smb_session_setup);
    assert(!smb_session_response.empty());
    assert(test_rpc_read_u32(smb_session_response, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_session_response, 4 + 12) == 1);
    const auto smb_session_id = test_rpc_read_u64(smb_session_response, 4 + 40);
    assert(smb_session_id != 0);
    assert(test_rpc_read_u16(smb_session_response, 4 + 64) == 9);
    const TestBytes smb_security_builtin_admins_sid{
        1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 0x02, 0, 0};
    const auto smb_echo = test_smb2_echo_request(smb_session_id, 134);
    const auto parsed_smb_echo = protocol::parse_smb2_request(smb_echo);
    assert(parsed_smb_echo.valid);
    assert(parsed_smb_echo.command == 13);
    assert(parsed_smb_echo.session_id == smb_session_id);
    const auto smb_echo_response = protocol::smb2_response(smb_echo);
    assert(test_rpc_read_u32(smb_echo_response, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_echo_response, 4 + 12) == 13);
    assert(test_rpc_read_u16(smb_echo_response, 4 + 64) == 4);
    const auto smb_cancel = test_smb2_cancel_request(smb_session_id, 144);
    const auto parsed_smb_cancel = protocol::parse_smb2_request(smb_cancel);
    assert(parsed_smb_cancel.valid);
    assert(parsed_smb_cancel.command == 12);
    assert(parsed_smb_cancel.session_id == smb_session_id);
    assert(protocol::smb2_response(smb_cancel).empty());

    const auto smb_tree_connect = test_smb2_tree_connect_request("\\\\dc1\\IPC$", smb_session_id);
    const auto parsed_smb_tree = protocol::parse_smb2_request(smb_tree_connect);
    assert(parsed_smb_tree.valid);
    assert(parsed_smb_tree.command == 3);
    assert(parsed_smb_tree.session_id == smb_session_id);
    assert(parsed_smb_tree.tree_path == "\\\\dc1\\IPC$");
    const auto smb_tree_response = protocol::smb2_response(smb_tree_connect);
    assert(!smb_tree_response.empty());
    assert(test_rpc_read_u32(smb_tree_response, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_tree_response, 4 + 12) == 3);
    assert(test_rpc_read_u32(smb_tree_response, 4 + 36) == 1);
    assert(test_rpc_read_u64(smb_tree_response, 4 + 40) == smb_session_id);
    assert(test_rpc_read_u16(smb_tree_response, 4 + 64) == 16);
    assert(smb_tree_response[4 + 66] == 0x02);

    const auto smb_sysvol_tree_response = protocol::smb2_response(test_smb2_tree_connect_request("\\\\dc1\\SYSVOL", smb_session_id, 102));
    assert(test_rpc_read_u32(smb_sysvol_tree_response, 4 + 8) == 0);
    assert(test_rpc_read_u32(smb_sysvol_tree_response, 4 + 36) == 2);
    assert(smb_sysvol_tree_response[4 + 66] == 0x01);
    const auto smb_sysvol_root_create = protocol::smb2_response(test_smb2_create_request("", 2, smb_session_id, 110));
    assert(test_rpc_read_u32(smb_sysvol_root_create, 4 + 8) == 0);
    const auto sysvol_root_persistent = test_rpc_read_u64(smb_sysvol_root_create, 4 + 64 + 64);
    const auto sysvol_root_volatile = test_rpc_read_u64(smb_sysvol_root_create, 4 + 64 + 72);
    const auto smb_sysvol_fs_attr = protocol::smb2_response(
        test_smb2_query_info_request(2, smb_session_id, sysvol_root_persistent, sysvol_root_volatile, 5, 111, 2));
    assert(test_rpc_read_u32(smb_sysvol_fs_attr, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_sysvol_fs_attr, 4 + 64) == 9);
    assert(test_rpc_read_u32(smb_sysvol_fs_attr, 4 + 64 + 4) == 20);
    assert(test_rpc_read_u32(smb_sysvol_fs_attr, 4 + 64 + 8) == 0x0000000fU);
    assert(test_rpc_read_u32(smb_sysvol_fs_attr, 4 + 64 + 12) == 255);
    const TestBytes ntfs_utf16{'N', 0, 'T', 0, 'F', 0, 'S', 0};
    assert(std::search(
        smb_sysvol_fs_attr.begin(),
        smb_sysvol_fs_attr.end(),
        ntfs_utf16.begin(),
        ntfs_utf16.end()) != smb_sysvol_fs_attr.end());
    const auto smb_sysvol_fs_size = protocol::smb2_response(
        test_smb2_query_info_request(2, smb_session_id, sysvol_root_persistent, sysvol_root_volatile, 7, 112, 2));
    assert(test_rpc_read_u32(smb_sysvol_fs_size, 4 + 8) == 0);
    assert(test_rpc_read_u32(smb_sysvol_fs_size, 4 + 64 + 4) == 32);
    assert(test_rpc_read_u64(smb_sysvol_fs_size, 4 + 64 + 8) > 0);
    const auto smb_sysvol_query_dir = protocol::smb2_response(
        test_smb2_query_directory_request(2, smb_session_id, sysvol_root_persistent, sysvol_root_volatile, 113));
    assert(test_rpc_read_u32(smb_sysvol_query_dir, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_sysvol_query_dir, 4 + 64) == 9);
    const auto sysvol_query_offset = test_rpc_read_u16(smb_sysvol_query_dir, 4 + 64 + 2);
    const auto sysvol_query_count = test_rpc_read_u32(smb_sysvol_query_dir, 4 + 64 + 4);
    assert(sysvol_query_offset == 72);
    assert(sysvol_query_count > 0);
    const TestBytes domain_listing_utf16{'e', 0, 'n', 0, 'd', 0, 'o', 0, 'r', 0, 'i', 0, 'u', 0, 'm', 0};
    assert(std::search(
        smb_sysvol_query_dir.begin(),
        smb_sysvol_query_dir.end(),
        domain_listing_utf16.begin(),
        domain_listing_utf16.end()) != smb_sysvol_query_dir.end());
    const auto smb_sysvol_change_notify_request =
        test_smb2_change_notify_request(2, smb_session_id, sysvol_root_persistent, sysvol_root_volatile, 143);
    const auto parsed_smb_sysvol_change_notify = protocol::parse_smb2_request(smb_sysvol_change_notify_request);
    assert(parsed_smb_sysvol_change_notify.valid);
    assert(parsed_smb_sysvol_change_notify.command == 15);
    assert(parsed_smb_sysvol_change_notify.file_id_persistent == sysvol_root_persistent);
    const auto smb_sysvol_change_notify = protocol::smb2_response(smb_sysvol_change_notify_request);
    assert(test_rpc_read_u32(smb_sysvol_change_notify, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_sysvol_change_notify, 4 + 12) == 15);
    assert(test_rpc_read_u16(smb_sysvol_change_notify, 4 + 64) == 9);
    assert(test_rpc_read_u32(smb_sysvol_change_notify, 4 + 64 + 4) == 0);
    const auto smb_gpt_create = protocol::smb2_response(test_smb2_create_request(
        "endorium.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\gpt.ini",
        2,
        smb_session_id,
        114));
    assert(test_rpc_read_u32(smb_gpt_create, 4 + 8) == 0);
    const auto gpt_file_persistent = test_rpc_read_u64(smb_gpt_create, 4 + 64 + 64);
    const auto gpt_file_volatile = test_rpc_read_u64(smb_gpt_create, 4 + 64 + 72);
    const auto smb_gpt_query_info = protocol::smb2_response(
        test_smb2_query_info_request(2, smb_session_id, gpt_file_persistent, gpt_file_volatile, 5, 115));
    assert(test_rpc_read_u32(smb_gpt_query_info, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_gpt_query_info, 4 + 64) == 9);
    assert(test_rpc_read_u32(smb_gpt_query_info, 4 + 64 + 4) == 24);
    const auto smb_gpt_network_info = protocol::smb2_response(
        test_smb2_query_info_request(2, smb_session_id, gpt_file_persistent, gpt_file_volatile, 34, 141));
    assert(test_rpc_read_u32(smb_gpt_network_info, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_gpt_network_info, 4 + 12) == 16);
    assert(test_rpc_read_u32(smb_gpt_network_info, 4 + 64 + 4) == 56);
    const auto smb_gpt_network_offset = test_rpc_read_u16(smb_gpt_network_info, 4 + 64 + 2);
    const auto smb_gpt_network_base = 4 + static_cast<std::size_t>(smb_gpt_network_offset);
    assert(test_rpc_read_u64(smb_gpt_network_info, smb_gpt_network_base + 40) > 0);
    assert(test_rpc_read_u32(smb_gpt_network_info, smb_gpt_network_base + 48) == 0x00000020U);
    const auto smb_gpt_all_info = protocol::smb2_response(
        test_smb2_query_info_request(2, smb_session_id, gpt_file_persistent, gpt_file_volatile, 18, 142));
    assert(test_rpc_read_u32(smb_gpt_all_info, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_gpt_all_info, 4 + 12) == 16);
    assert(test_rpc_read_u32(smb_gpt_all_info, 4 + 64 + 4) > 100);
    const auto smb_gpt_all_offset = test_rpc_read_u16(smb_gpt_all_info, 4 + 64 + 2);
    const auto smb_gpt_all_base = 4 + static_cast<std::size_t>(smb_gpt_all_offset);
    assert(test_rpc_read_u32(smb_gpt_all_info, smb_gpt_all_base + 48) > 0);
    assert(test_rpc_read_u32(smb_gpt_all_info, smb_gpt_all_base + 96) == 14);
    const TestBytes gpt_ini_name_utf16{'g', 0, 'p', 0, 't', 0, '.', 0, 'i', 0, 'n', 0, 'i', 0};
    assert(std::search(
        smb_gpt_all_info.begin(),
        smb_gpt_all_info.end(),
        gpt_ini_name_utf16.begin(),
        gpt_ini_name_utf16.end()) != smb_gpt_all_info.end());
    const auto smb_gpt_security_info = protocol::smb2_response(
        test_smb2_query_info_request(2, smb_session_id, gpt_file_persistent, gpt_file_volatile, 0, 139, 3));
    assert(test_rpc_read_u32(smb_gpt_security_info, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_gpt_security_info, 4 + 12) == 16);
    assert(test_rpc_read_u16(smb_gpt_security_info, 4 + 64) == 9);
    assert(test_rpc_read_u16(smb_gpt_security_info, 4 + 64 + 2) == 72);
    assert(test_rpc_read_u32(smb_gpt_security_info, 4 + 64 + 4) > 80);
    const auto smb_gpt_security_offset = test_rpc_read_u16(smb_gpt_security_info, 4 + 64 + 2);
    const auto smb_gpt_security_base = 4 + static_cast<std::size_t>(smb_gpt_security_offset);
    assert(smb_gpt_security_info[smb_gpt_security_base] == 1);
    assert(smb_gpt_security_info[smb_gpt_security_base + 1] == 0);
    assert(test_rpc_read_u16(smb_gpt_security_info, smb_gpt_security_base + 2) == 0x8004U);
    assert(test_rpc_read_u32(smb_gpt_security_info, smb_gpt_security_base + 4) == 20);
    assert(std::search(
        smb_gpt_security_info.begin(),
        smb_gpt_security_info.end(),
        smb_security_builtin_admins_sid.begin(),
        smb_security_builtin_admins_sid.end()) != smb_gpt_security_info.end());
    const auto smb_gpt_set_info_request = test_smb2_set_info_request(
        2,
        smb_session_id,
        gpt_file_persistent,
        gpt_file_volatile,
        1,
        4,
        135);
    const auto parsed_smb_gpt_set_info = protocol::parse_smb2_request(smb_gpt_set_info_request);
    assert(parsed_smb_gpt_set_info.valid);
    assert(parsed_smb_gpt_set_info.command == 17);
    assert(parsed_smb_gpt_set_info.set_info_type == 1);
    assert(parsed_smb_gpt_set_info.set_file_info_class == 4);
    assert(parsed_smb_gpt_set_info.file_id_persistent == gpt_file_persistent);
    const auto smb_gpt_set_info = protocol::smb2_response(smb_gpt_set_info_request);
    assert(test_rpc_read_u32(smb_gpt_set_info, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_gpt_set_info, 4 + 12) == 17);
    assert(test_rpc_read_u16(smb_gpt_set_info, 4 + 64) == 2);
    const auto smb_gpt_flush = protocol::smb2_response(
        test_smb2_flush_request(2, smb_session_id, gpt_file_persistent, gpt_file_volatile, 136));
    assert(test_rpc_read_u32(smb_gpt_flush, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_gpt_flush, 4 + 12) == 7);
    assert(test_rpc_read_u16(smb_gpt_flush, 4 + 64) == 4);
    const auto smb_gpt_lock_request =
        test_smb2_lock_request(2, smb_session_id, gpt_file_persistent, gpt_file_volatile, 145);
    const auto parsed_smb_gpt_lock = protocol::parse_smb2_request(smb_gpt_lock_request);
    assert(parsed_smb_gpt_lock.valid);
    assert(parsed_smb_gpt_lock.command == 10);
    assert(parsed_smb_gpt_lock.file_id_persistent == gpt_file_persistent);
    const auto smb_gpt_lock = protocol::smb2_response(smb_gpt_lock_request);
    assert(test_rpc_read_u32(smb_gpt_lock, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_gpt_lock, 4 + 12) == 10);
    assert(test_rpc_read_u16(smb_gpt_lock, 4 + 64) == 4);
    const auto smb_gpt_read = protocol::smb2_response(
        test_smb2_read_request(2, smb_session_id, gpt_file_persistent, gpt_file_volatile, 128, 0, 116));
    assert(test_rpc_read_u32(smb_gpt_read, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_gpt_read, 4 + 64) == 17);
    assert(test_rpc_read_u32(smb_gpt_read, 4 + 64 + 4) > 0);
    const std::string gpt_text(smb_gpt_read.begin(), smb_gpt_read.end());
    assert(gpt_text.find("[General]") != std::string::npos);
    assert(gpt_text.find("Default Domain Policy") != std::string::npos);
    const auto smb_gpt_close = protocol::smb2_response(
        test_smb2_close_request(2, smb_session_id, gpt_file_persistent, gpt_file_volatile, 117));
    assert(test_rpc_read_u32(smb_gpt_close, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_gpt_close, 4 + 64) == 60);
    const auto smb_unknown_gpo_file = protocol::smb2_response(test_smb2_create_request(
        "endorium.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\unknown.txt",
        2,
        smb_session_id,
        118));
    assert(test_rpc_read_u32(smb_unknown_gpo_file, 4 + 8) == 0xc0000034U);
    const auto smb_machine_create = protocol::smb2_response(test_smb2_create_request(
        "endorium.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine",
        2,
        smb_session_id,
        121));
    assert(test_rpc_read_u32(smb_machine_create, 4 + 8) == 0);
    assert(test_rpc_read_u32(smb_machine_create, 4 + 64 + 56) == 0x00000010U);
    const auto machine_persistent = test_rpc_read_u64(smb_machine_create, 4 + 64 + 64);
    const auto machine_volatile = test_rpc_read_u64(smb_machine_create, 4 + 64 + 72);
    const auto smb_machine_query_dir = protocol::smb2_response(
        test_smb2_query_directory_request(2, smb_session_id, machine_persistent, machine_volatile, 122));
    assert(test_rpc_read_u32(smb_machine_query_dir, 4 + 8) == 0);
    const TestBytes registry_pol_utf16{
        'R', 0, 'e', 0, 'g', 0, 'i', 0, 's', 0, 't', 0, 'r', 0, 'y', 0, '.', 0, 'p', 0, 'o', 0, 'l', 0};
    assert(std::search(
        smb_machine_query_dir.begin(),
        smb_machine_query_dir.end(),
        registry_pol_utf16.begin(),
        registry_pol_utf16.end()) != smb_machine_query_dir.end());
    const auto smb_registry_create = protocol::smb2_response(test_smb2_create_request(
        "endorium.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Registry.pol",
        2,
        smb_session_id,
        123));
    assert(test_rpc_read_u32(smb_registry_create, 4 + 8) == 0);
    assert(test_rpc_read_u32(smb_registry_create, 4 + 64 + 56) == 0x00000020U);
    const auto registry_persistent = test_rpc_read_u64(smb_registry_create, 4 + 64 + 64);
    const auto registry_volatile = test_rpc_read_u64(smb_registry_create, 4 + 64 + 72);
    const auto smb_registry_read = protocol::smb2_response(
        test_smb2_read_request(2, smb_session_id, registry_persistent, registry_volatile, 64, 0, 124));
    assert(test_rpc_read_u32(smb_registry_read, 4 + 8) == 0);
    const TestBytes registry_magic{'P', 'R', 'e', 'g', 1, 0, 0, 0};
    assert(std::search(
        smb_registry_read.begin(),
        smb_registry_read.end(),
        registry_magic.begin(),
        registry_magic.end()) != smb_registry_read.end());
    const auto smb_gpttmpl_create = protocol::smb2_response(test_smb2_create_request(
        "endorium.local\\Policies\\{31B2F340-016D-11D2-945F-00C04FB984F9}\\Machine\\Microsoft\\Windows NT\\SecEdit\\GptTmpl.inf",
        2,
        smb_session_id,
        125));
    assert(test_rpc_read_u32(smb_gpttmpl_create, 4 + 8) == 0);
    const auto gpttmpl_persistent = test_rpc_read_u64(smb_gpttmpl_create, 4 + 64 + 64);
    const auto gpttmpl_volatile = test_rpc_read_u64(smb_gpttmpl_create, 4 + 64 + 72);
    const auto smb_gpttmpl_read = protocol::smb2_response(
        test_smb2_read_request(2, smb_session_id, gpttmpl_persistent, gpttmpl_volatile, 1024, 0, 126));
    assert(test_rpc_read_u32(smb_gpttmpl_read, 4 + 8) == 0);
    const std::string gpttmpl_text(smb_gpttmpl_read.begin(), smb_gpttmpl_read.end());
    assert(gpttmpl_text.find("$CHICAGO$") != std::string::npos);
    assert(gpttmpl_text.find("[System Access]") != std::string::npos);
    assert(gpttmpl_text.find("placeholder") == std::string::npos);

    const auto smb_netlogon_tree_response =
        protocol::smb2_response(test_smb2_tree_connect_request("\\\\dc1\\NETLOGON", smb_session_id, 130));
    assert(test_rpc_read_u32(smb_netlogon_tree_response, 4 + 8) == 0);
    assert(test_rpc_read_u32(smb_netlogon_tree_response, 4 + 36) == 3);
    assert(smb_netlogon_tree_response[4 + 66] == 0x01);
    const auto smb_netlogon_readme_create =
        protocol::smb2_response(test_smb2_create_request("README.txt", 3, smb_session_id, 131));
    assert(test_rpc_read_u32(smb_netlogon_readme_create, 4 + 8) == 0);
    const auto netlogon_readme_persistent = test_rpc_read_u64(smb_netlogon_readme_create, 4 + 64 + 64);
    const auto netlogon_readme_volatile = test_rpc_read_u64(smb_netlogon_readme_create, 4 + 64 + 72);
    const auto smb_netlogon_readme_read = protocol::smb2_response(
        test_smb2_read_request(3, smb_session_id, netlogon_readme_persistent, netlogon_readme_volatile, 256, 0, 132));
    assert(test_rpc_read_u32(smb_netlogon_readme_read, 4 + 8) == 0);
    const std::string netlogon_readme_text(smb_netlogon_readme_read.begin(), smb_netlogon_readme_read.end());
    assert(netlogon_readme_text.find("No logon scripts are configured") != std::string::npos);
    assert(netlogon_readme_text.find("placeholder") == std::string::npos);
    const auto smb_netlogon_missing_script =
        protocol::smb2_response(test_smb2_create_request("missing.cmd", 3, smb_session_id, 133));
    assert(test_rpc_read_u32(smb_netlogon_missing_script, 4 + 8) == 0xc0000034U);

    const auto smb_bad_tree_response = protocol::smb2_response(test_smb2_tree_connect_request("\\\\dc1\\NOPE", smb_session_id, 103));
    assert(test_rpc_read_u32(smb_bad_tree_response, 4 + 8) == 0xc00000ccU);

    const auto smb_create = test_smb2_create_request("netlogon", 1, smb_session_id);
    const auto parsed_smb_create = protocol::parse_smb2_request(smb_create);
    assert(parsed_smb_create.valid);
    assert(parsed_smb_create.command == 5);
    assert(parsed_smb_create.tree_id == 1);
    assert(parsed_smb_create.session_id == smb_session_id);
    assert(parsed_smb_create.create_name == "netlogon");
    const auto smb_create_response = protocol::smb2_response(smb_create);
    assert(!smb_create_response.empty());
    assert(test_rpc_read_u32(smb_create_response, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_create_response, 4 + 12) == 5);
    assert(test_rpc_read_u32(smb_create_response, 4 + 36) == 1);
    assert(test_rpc_read_u64(smb_create_response, 4 + 40) == smb_session_id);
    assert(test_rpc_read_u16(smb_create_response, 4 + 64) == 89);
    assert(test_rpc_read_u64(smb_create_response, 4 + 64 + 64) != 0);
    assert(test_rpc_read_u64(smb_create_response, 4 + 64 + 72) != 0);
    const auto file_id_persistent = test_rpc_read_u64(smb_create_response, 4 + 64 + 64);
    const auto file_id_volatile = test_rpc_read_u64(smb_create_response, 4 + 64 + 72);
    const auto smb_pipe_set_info = protocol::smb2_response(
        test_smb2_set_info_request(1, smb_session_id, file_id_persistent, file_id_volatile, 1, 4, 137));
    assert(test_rpc_read_u32(smb_pipe_set_info, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_pipe_set_info, 4 + 12) == 17);
    assert(test_rpc_read_u16(smb_pipe_set_info, 4 + 64) == 2);
    const auto smb_pipe_flush = protocol::smb2_response(
        test_smb2_flush_request(1, smb_session_id, file_id_persistent, file_id_volatile, 138));
    assert(test_rpc_read_u32(smb_pipe_flush, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_pipe_flush, 4 + 12) == 7);
    assert(test_rpc_read_u16(smb_pipe_flush, 4 + 64) == 4);
    const auto smb_ipc_fs_device = protocol::smb2_response(
        test_smb2_query_info_request(1, smb_session_id, file_id_persistent, file_id_volatile, 4, 118, 2));
    assert(test_rpc_read_u32(smb_ipc_fs_device, 4 + 8) == 0);
    assert(test_rpc_read_u32(smb_ipc_fs_device, 4 + 64 + 4) == 8);
    assert(test_rpc_read_u32(smb_ipc_fs_device, 4 + 64 + 8) == 0x00000011U);
    const auto smb_pipe_security_info = protocol::smb2_response(
        test_smb2_query_info_request(1, smb_session_id, file_id_persistent, file_id_volatile, 0, 140, 3));
    assert(test_rpc_read_u32(smb_pipe_security_info, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_pipe_security_info, 4 + 12) == 16);
    assert(test_rpc_read_u16(smb_pipe_security_info, 4 + 64) == 9);
    assert(test_rpc_read_u32(smb_pipe_security_info, 4 + 64 + 4) > 80);
    assert(std::search(
        smb_pipe_security_info.begin(),
        smb_pipe_security_info.end(),
        smb_security_builtin_admins_sid.begin(),
        smb_security_builtin_admins_sid.end()) != smb_pipe_security_info.end());
    const auto smb_srvsvc_create = protocol::smb2_response(test_smb2_create_request("srvsvc", 1, smb_session_id, 121));
    assert(test_rpc_read_u32(smb_srvsvc_create, 4 + 8) == 0);
    const auto srvsvc_file_id_persistent = test_rpc_read_u64(smb_srvsvc_create, 4 + 64 + 64);
    const auto srvsvc_file_id_volatile = test_rpc_read_u64(smb_srvsvc_create, 4 + 64 + 72);
    const auto smb_srvsvc_ioctl = protocol::smb2_response(
        test_smb2_ioctl_request(
            test_rpc_request_opnum(15, 40),
            1,
            smb_session_id,
            srvsvc_file_id_persistent,
            srvsvc_file_id_volatile,
            122));
    assert(test_rpc_read_u32(smb_srvsvc_ioctl, 4 + 8) == 0);
    const auto srvsvc_output_offset = test_rpc_read_u32(smb_srvsvc_ioctl, 4 + 64 + 32);
    const auto srvsvc_output_count = test_rpc_read_u32(smb_srvsvc_ioctl, 4 + 64 + 36);
    assert(srvsvc_output_count > 120);
    assert(std::search(
        smb_srvsvc_ioctl.begin() + static_cast<std::ptrdiff_t>(4 + srvsvc_output_offset),
        smb_srvsvc_ioctl.end(),
        sysvol_utf16.begin(),
        sysvol_utf16.end()) != smb_srvsvc_ioctl.end());
    const auto smb_srvsvc_small_ioctl = protocol::smb2_response(
        test_smb2_ioctl_request(
            test_rpc_request_opnum(15, 40),
            1,
            smb_session_id,
            srvsvc_file_id_persistent,
            srvsvc_file_id_volatile,
            127,
            80));
    assert(test_rpc_read_u32(smb_srvsvc_small_ioctl, 4 + 8) == 0);
    assert(test_rpc_read_u32(smb_srvsvc_small_ioctl, 4 + 64 + 36) == 80);
    const auto smb_srvsvc_remainder_read = protocol::smb2_response(
        test_smb2_read_request(1, smb_session_id, srvsvc_file_id_persistent, srvsvc_file_id_volatile, 32, 0, 128));
    assert(test_rpc_read_u32(smb_srvsvc_remainder_read, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_srvsvc_remainder_read, 4 + 12) == 8);
    assert(test_rpc_read_u32(smb_srvsvc_remainder_read, 4 + 64 + 4) == 32);
    const auto smb_srvsvc_remainder_tail = protocol::smb2_response(
        test_smb2_read_request(1, smb_session_id, srvsvc_file_id_persistent, srvsvc_file_id_volatile, 4096, 0, 129));
    assert(test_rpc_read_u32(smb_srvsvc_remainder_tail, 4 + 8) == 0);
    assert(test_rpc_read_u32(smb_srvsvc_remainder_tail, 4 + 64 + 4) > 0);
    const auto smb_epmapper_create = protocol::smb2_response(test_smb2_create_request("epmapper", 1, smb_session_id, 145));
    assert(test_rpc_read_u32(smb_epmapper_create, 4 + 8) == 0);
    const auto epmapper_file_id_persistent = test_rpc_read_u64(smb_epmapper_create, 4 + 64 + 64);
    const auto epmapper_file_id_volatile = test_rpc_read_u64(smb_epmapper_create, 4 + 64 + 72);
    const auto smb_epmapper_ioctl = protocol::smb2_response(
        test_smb2_ioctl_request(
            test_rpc_request_opnum(2, 97),
            1,
            smb_session_id,
            epmapper_file_id_persistent,
            epmapper_file_id_volatile,
            146));
    assert(test_rpc_read_u32(smb_epmapper_ioctl, 4 + 8) == 0);
    const auto epmapper_output_offset = test_rpc_read_u32(smb_epmapper_ioctl, 4 + 64 + 32);
    const auto epmapper_output_count = test_rpc_read_u32(smb_epmapper_ioctl, 4 + 64 + 36);
    assert(epmapper_output_count > 100);
    assert(std::search(
        smb_epmapper_ioctl.begin() + static_cast<std::ptrdiff_t>(4 + epmapper_output_offset),
        smb_epmapper_ioctl.end(),
        epm_netlogon_utf16.begin(),
        epm_netlogon_utf16.end()) != smb_epmapper_ioctl.end());

    const auto smb_pipe_write = test_smb2_write_request(netlogon_bind, 1, smb_session_id, file_id_persistent, file_id_volatile, 119);
    const auto parsed_smb_pipe_write = protocol::parse_smb2_request(smb_pipe_write);
    assert(parsed_smb_pipe_write.valid);
    assert(parsed_smb_pipe_write.command == 9);
    assert(parsed_smb_pipe_write.file_id_persistent == file_id_persistent);
    assert(parsed_smb_pipe_write.file_id_volatile == file_id_volatile);
    assert(parsed_smb_pipe_write.write_data == netlogon_bind);
    const auto smb_pipe_write_response = protocol::smb2_response(smb_pipe_write);
    assert(test_rpc_read_u32(smb_pipe_write_response, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_pipe_write_response, 4 + 12) == 9);
    assert(test_rpc_read_u16(smb_pipe_write_response, 4 + 64) == 17);
    assert(test_rpc_read_u32(smb_pipe_write_response, 4 + 64 + 4) == netlogon_bind.size());
    const auto smb_pipe_read_response = protocol::smb2_response(
        test_smb2_read_request(1, smb_session_id, file_id_persistent, file_id_volatile, 4096, 0, 120));
    assert(test_rpc_read_u32(smb_pipe_read_response, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_pipe_read_response, 4 + 12) == 8);
    const auto pipe_read_offset = smb_pipe_read_response[4 + 64 + 2];
    const auto pipe_read_count = test_rpc_read_u32(smb_pipe_read_response, 4 + 64 + 4);
    assert(pipe_read_count > 0);
    assert(smb_pipe_read_response[4 + pipe_read_offset + 2] == 0x0c);
    const TestBytes netlogon_bind_fragment_a(netlogon_bind.begin(), netlogon_bind.begin() + 10);
    const TestBytes netlogon_bind_fragment_b(netlogon_bind.begin() + 10, netlogon_bind.end());
    const auto smb_pipe_write_fragment_a = protocol::smb2_response(
        test_smb2_write_request(
            netlogon_bind_fragment_a,
            1,
            smb_session_id,
            file_id_persistent,
            file_id_volatile,
            220));
    assert(test_rpc_read_u32(smb_pipe_write_fragment_a, 4 + 8) == 0);
    assert(test_rpc_read_u32(smb_pipe_write_fragment_a, 4 + 64 + 4) == netlogon_bind_fragment_a.size());
    const auto smb_pipe_empty_after_fragment = protocol::smb2_response(
        test_smb2_read_request(1, smb_session_id, file_id_persistent, file_id_volatile, 4096, 0, 221));
    assert(test_rpc_read_u32(smb_pipe_empty_after_fragment, 4 + 8) == 0xc00000d9U);
    const auto smb_pipe_write_fragment_b = protocol::smb2_response(
        test_smb2_write_request(
            netlogon_bind_fragment_b,
            1,
            smb_session_id,
            file_id_persistent,
            file_id_volatile,
            222));
    assert(test_rpc_read_u32(smb_pipe_write_fragment_b, 4 + 8) == 0);
    assert(test_rpc_read_u32(smb_pipe_write_fragment_b, 4 + 64 + 4) == netlogon_bind_fragment_b.size());
    const auto smb_pipe_fragment_read_response = protocol::smb2_response(
        test_smb2_read_request(1, smb_session_id, file_id_persistent, file_id_volatile, 4096, 0, 223));
    assert(test_rpc_read_u32(smb_pipe_fragment_read_response, 4 + 8) == 0);
    const auto pipe_fragment_read_offset = smb_pipe_fragment_read_response[4 + 64 + 2];
    const auto pipe_fragment_read_count = test_rpc_read_u32(smb_pipe_fragment_read_response, 4 + 64 + 4);
    assert(pipe_fragment_read_count > 0);
    assert(smb_pipe_fragment_read_response[4 + pipe_fragment_read_offset + 2] == 0x0c);

    const auto smb_bad_create_response = protocol::smb2_response(test_smb2_create_request("not-a-pipe", 1, smb_session_id, 105));
    assert(test_rpc_read_u32(smb_bad_create_response, 4 + 8) == 0xc0000034U);

    const auto smb_ioctl = test_smb2_ioctl_request(rpc_bind, 1, smb_session_id, file_id_persistent, file_id_volatile);
    const auto parsed_smb_ioctl = protocol::parse_smb2_request(smb_ioctl);
    assert(parsed_smb_ioctl.valid);
    assert(parsed_smb_ioctl.command == 11);
    assert(parsed_smb_ioctl.ioctl_ctl_code == 0x0011c017U);
    assert(parsed_smb_ioctl.file_id_persistent == file_id_persistent);
    assert(parsed_smb_ioctl.file_id_volatile == file_id_volatile);
    assert(parsed_smb_ioctl.ioctl_input.size() == rpc_bind.size());
    const auto smb_ioctl_response = protocol::smb2_response(smb_ioctl);
    assert(!smb_ioctl_response.empty());
    assert(test_rpc_read_u32(smb_ioctl_response, 4 + 8) == 0);
    assert(test_rpc_read_u16(smb_ioctl_response, 4 + 12) == 11);
    assert(test_rpc_read_u32(smb_ioctl_response, 4 + 64 + 4) == 0x0011c017U);
    const auto ioctl_output_offset = test_rpc_read_u32(smb_ioctl_response, 4 + 64 + 32);
    const auto ioctl_output_count = test_rpc_read_u32(smb_ioctl_response, 4 + 64 + 36);
    assert(ioctl_output_offset == 112);
    assert(ioctl_output_count > 0);
    assert(smb_ioctl_response[4 + ioctl_output_offset + 2] == 0x0c);

    const auto smb_netlogon_ioctl = test_smb2_ioctl_request(netlogon_challenge, 1, smb_session_id, file_id_persistent, file_id_volatile, 107);
    const auto smb_netlogon_ioctl_response = protocol::smb2_response(smb_netlogon_ioctl);
    assert(!smb_netlogon_ioctl_response.empty());
    const auto netlogon_output_offset = test_rpc_read_u32(smb_netlogon_ioctl_response, 4 + 64 + 32);
    const auto netlogon_output_count = test_rpc_read_u32(smb_netlogon_ioctl_response, 4 + 64 + 36);
    assert(netlogon_output_count == 36);
    assert(smb_netlogon_ioctl_response[4 + netlogon_output_offset + 2] == 0x02);
    assert(test_rpc_read_u32(smb_netlogon_ioctl_response, 4 + netlogon_output_offset + 32) == 0);

    const TestBytes smb_server_challenge(
        smb_netlogon_ioctl_response.begin() + static_cast<std::ptrdiff_t>(4 + netlogon_output_offset + 24),
        smb_netlogon_ioctl_response.begin() + static_cast<std::ptrdiff_t>(4 + netlogon_output_offset + 32));
    const auto smb_netlogon_material = protocol::compute_netlogon_aes_credentials(
        machine_nt_hash,
        client_challenge,
        smb_server_challenge);
    assert(smb_netlogon_material.has_value());
    const auto smb_netlogon_auth = test_rpc_request_opnum(
        26,
        13,
        test_netlogon_authenticate3_stub("WS01$", "WS01", smb_netlogon_material->client_credential, 0x01004000U));
    bool smb_password_update_seen = false;
    protocol::RpcRuntimeInfo smb_rpc_runtime = rpc_runtime;
    smb_rpc_runtime.netlogon_password_update_handler =
        [&](const protocol::NetlogonPasswordUpdate& update) {
            smb_password_update_seen = true;
            assert(update.sam_account_name == "ws01$");
            assert(update.computer_name == "ws01");
            assert(update.new_password == "new-smb-machine-secret");
            return true;
        };
    const protocol::Smb2RuntimeInfo smb_runtime{smb_rpc_runtime};
    const auto smb_netlogon_auth_ioctl =
        test_smb2_ioctl_request(smb_netlogon_auth, 1, smb_session_id, file_id_persistent, file_id_volatile, 108);
    const auto smb_netlogon_auth_response = protocol::smb2_response(smb_netlogon_auth_ioctl, smb_runtime);
    assert(!smb_netlogon_auth_response.empty());
    const auto netlogon_auth_output_offset = test_rpc_read_u32(smb_netlogon_auth_response, 4 + 64 + 32);
    const auto netlogon_auth_output_count = test_rpc_read_u32(smb_netlogon_auth_response, 4 + 64 + 36);
    assert(netlogon_auth_output_count == 44);
    assert(smb_netlogon_auth_response[4 + netlogon_auth_output_offset + 2] == 0x02);
    assert(test_rpc_read_u32(smb_netlogon_auth_response, 4 + netlogon_auth_output_offset + 16) == 20);
    assert(test_rpc_read_u32(smb_netlogon_auth_response, 4 + netlogon_auth_output_offset + 40) == 0);
    const std::uint32_t smb_secure_channel_timestamp = 1760000001U;
    const auto smb_secure_channel_seed = protocol::advance_netlogon_credential_seed(
        smb_netlogon_material->client_credential,
        smb_secure_channel_timestamp);
    const auto smb_secure_channel_credential = protocol::compute_netlogon_aes_credential(
        smb_netlogon_material->session_key,
        smb_secure_channel_seed);
    assert(smb_secure_channel_credential.has_value());
    const auto smb_encrypted_machine_password = protocol::encrypt_netlogon_trust_password(
        smb_netlogon_material->session_key,
        "new-smb-machine-secret");
    assert(smb_encrypted_machine_password.has_value());
    const auto smb_password_set = test_rpc_request_opnum(
        30,
        15,
        test_netlogon_secure_channel_stub(
            "WS01$",
            "WS01",
            *smb_secure_channel_credential,
            smb_secure_channel_timestamp,
            *smb_encrypted_machine_password));
    const auto smb_password_set_ioctl =
        test_smb2_ioctl_request(smb_password_set, 1, smb_session_id, file_id_persistent, file_id_volatile, 109);
    const auto smb_password_set_response = protocol::smb2_response(smb_password_set_ioctl, smb_runtime);
    assert(!smb_password_set_response.empty());
    const auto smb_password_set_offset = test_rpc_read_u32(smb_password_set_response, 4 + 64 + 32);
    const auto smb_password_set_count = test_rpc_read_u32(smb_password_set_response, 4 + 64 + 36);
    assert(smb_password_set_count == 40);
    assert(smb_password_set_response[4 + smb_password_set_offset + 2] == 0x02);
    assert(test_rpc_read_u32(smb_password_set_response, 4 + smb_password_set_offset + 16) == 16);
    assert(test_rpc_read_u32(smb_password_set_response, 4 + smb_password_set_offset + 36) == 0);
    assert(smb_password_update_seen);

    const core::DhcpPool pool{
        "office",
        "10.10.10.0/24",
        "10.10.10.100",
        "10.10.10.102",
        {{"router", "10.10.10.1"}},
        {
            {"10.10.10.100", "client-01", "ws-01", "active", "2026-04-24T12:00:00Z"},
        }};
    const auto lease = protocol::allocate_next_lease(pool, pool.leases, "client-02", "ws-02");
    assert(lease.has_value());
    assert(lease->ip_address == "10.10.10.101");

    security::PasswordHasher hasher;
    const auto hash = hasher.hash_password("endorium-admin");
    assert(hasher.verify_password("endorium-admin", hash));
    assert(!hasher.verify_password("wrong-password", hash));

    const auto admin_salt = security::ad_kerberos_salt("ENDORIUM.LOCAL", "Administrator");
    const auto krbtgt_salt = security::ad_kerberos_salt("ENDORIUM.LOCAL", "krbtgt");
    const auto admin_key = security::derive_ad_kerberos_aes_key("ChangeMe-AD-1", admin_salt, 32);
    const auto admin_aes128_key = security::derive_ad_kerberos_aes_key("ChangeMe-AD-1", admin_salt, 16);
    const auto krbtgt_key = security::derive_ad_kerberos_aes_key("krbtgt-secret", krbtgt_salt, 32);
    const auto krbtgt_aes128_key = security::derive_ad_kerberos_aes_key("krbtgt-secret", krbtgt_salt, 16);
    const TestBytes timestamp_plaintext = test_seq(test_ctx(0, test_generalized_time("20260530120000Z")));
    const TestBytes confounder{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15};
    const auto encrypted_timestamp = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        timestamp_plaintext,
        admin_key,
        1,
        confounder);
    const auto valid_as_req = test_as_req("Administrator", "ENDORIUM.LOCAL", true, encrypted_timestamp);
    const protocol::KerberosPrincipal admin_principal{
        "Administrator",
        "ENDORIUM.LOCAL",
        true,
        {{18, "aes256-cts-hmac-sha1-96", admin_salt, admin_key}},
    };
    const protocol::KerberosPrincipal krbtgt_principal{
        "krbtgt",
        "ENDORIUM.LOCAL",
        true,
        {{18, "aes256-cts-hmac-sha1-96", krbtgt_salt, krbtgt_key}},
    };
    const protocol::KerberosPrincipal admin_dual_key_principal{
        "Administrator",
        "ENDORIUM.LOCAL",
        true,
        {
            {18, "aes256-cts-hmac-sha1-96", admin_salt, admin_key},
            {17, "aes128-cts-hmac-sha1-96", admin_salt, admin_aes128_key},
        },
    };
    const protocol::KerberosPrincipal krbtgt_dual_key_principal{
        "krbtgt",
        "ENDORIUM.LOCAL",
        true,
        {
            {18, "aes256-cts-hmac-sha1-96", krbtgt_salt, krbtgt_key},
            {17, "aes128-cts-hmac-sha1-96", krbtgt_salt, krbtgt_aes128_key},
        },
    };
    const protocol::KerberosRealmInfo ad_realm{"ENDORIUM.LOCAL", "krbtgt", {admin_principal, krbtgt_principal}};
    const protocol::KerberosRealmInfo ad_realm_dual_key{
        "ENDORIUM.LOCAL",
        "krbtgt",
        {admin_dual_key_principal, krbtgt_dual_key_principal},
    };
    const auto parsed_as_req = protocol::parse_kerberos_request(valid_as_req);
    assert(parsed_as_req.valid);
    assert(parsed_as_req.message_type == 10);
    assert(parsed_as_req.client_principal == "Administrator");
    assert(parsed_as_req.nonce == 42);
    assert(parsed_as_req.encrypted_timestamps.size() == 1);
    const auto as_rep = protocol::kerberos_error_response(valid_as_req, ad_realm);
    assert(!as_rep.empty());
    assert(as_rep.front() == 0x6b);
    const std::string as_rep_text(as_rep.begin(), as_rep.end());
    assert(as_rep_text.find("krbtgt") != std::string::npos);
    const auto aes128_as_req = test_as_req("Administrator", "ENDORIUM.LOCAL", true, encrypted_timestamp, 1, {17});
    const auto aes128_as_rep = protocol::kerberos_error_response(aes128_as_req, ad_realm_dual_key);
    assert(!aes128_as_rep.empty());
    assert(aes128_as_rep.front() == 0x6b);
    const TestBytes aes128_etype_marker{0xa0, 0x03, 0x02, 0x01, 0x11};
    assert(std::search(
        aes128_as_rep.begin(),
        aes128_as_rep.end(),
        aes128_etype_marker.begin(),
        aes128_etype_marker.end()) != aes128_as_rep.end());
    const auto unsupported_etype_as_error = protocol::kerberos_error_response(
        test_as_req("Administrator", "ENDORIUM.LOCAL", true, encrypted_timestamp, 1, {23}),
        ad_realm_dual_key);
    const std::string unsupported_etype_as_text(
        unsupported_etype_as_error.begin(),
        unsupported_etype_as_error.end());
    assert(!unsupported_etype_as_error.empty());
    assert(unsupported_etype_as_error.front() == 0x7e);
    assert(unsupported_etype_as_text.find("AS-REP etype is not available") != std::string::npos);

    auto disabled_admin_principal = admin_principal;
    disabled_admin_principal.user_account_control = 0x00000202U;
    const auto disabled_admin_as_error = protocol::kerberos_error_response(
        valid_as_req,
        {"ENDORIUM.LOCAL", "krbtgt", {disabled_admin_principal, krbtgt_principal}});
    const std::string disabled_admin_as_text(disabled_admin_as_error.begin(), disabled_admin_as_error.end());
    assert(!disabled_admin_as_error.empty());
    assert(disabled_admin_as_error.front() == 0x7e);
    assert(disabled_admin_as_text.find("client principal account is disabled") != std::string::npos);

    auto expired_admin_principal = admin_principal;
    expired_admin_principal.account_expired = true;
    const auto expired_admin_as_error = protocol::kerberos_error_response(
        valid_as_req,
        {"ENDORIUM.LOCAL", "krbtgt", {expired_admin_principal, krbtgt_principal}});
    const std::string expired_admin_as_text(expired_admin_as_error.begin(), expired_admin_as_error.end());
    assert(!expired_admin_as_error.empty());
    assert(expired_admin_as_error.front() == 0x7e);
    assert(expired_admin_as_text.find("client principal account is expired") != std::string::npos);

    const auto enterprise_upn_as_req =
        test_as_req("Administrator@ENDORIUM.LOCAL", "ENDORIUM.LOCAL", true, encrypted_timestamp, 10);
    const auto parsed_enterprise_upn_as_req = protocol::parse_kerberos_request(enterprise_upn_as_req);
    assert(parsed_enterprise_upn_as_req.valid);
    assert(parsed_enterprise_upn_as_req.client_principal == "Administrator@ENDORIUM.LOCAL");
    const auto enterprise_upn_as_rep = protocol::kerberos_error_response(enterprise_upn_as_req, ad_realm);
    assert(!enterprise_upn_as_rep.empty());
    assert(enterprise_upn_as_rep.front() == 0x6b);
    const std::string enterprise_upn_as_rep_text(enterprise_upn_as_rep.begin(), enterprise_upn_as_rep.end());
    assert(enterprise_upn_as_rep_text.find("Administrator") != std::string::npos);
    assert(enterprise_upn_as_rep_text.find("Administrator@ENDORIUM.LOCAL") == std::string::npos);

    const auto missing_tgt = protocol::kerberos_error_response(
        valid_as_req,
        {"ENDORIUM.LOCAL", "krbtgt", {admin_principal}});
    const std::string missing_tgt_text(missing_tgt.begin(), missing_tgt.end());
    assert(!missing_tgt.empty());
    assert(missing_tgt.front() == 0x7e);
    assert(missing_tgt_text.find("krbtgt key material") != std::string::npos);

    const auto bad_timestamp = protocol::kerberos_error_response(
        test_as_req("Administrator", "ENDORIUM.LOCAL", true, {0, 1, 2}),
        ad_realm);
    const std::string bad_timestamp_text(bad_timestamp.begin(), bad_timestamp.end());
    assert(!bad_timestamp.empty());
    assert(bad_timestamp.front() == 0x7e);
    assert(bad_timestamp_text.find("encrypted timestamp validation failed") != std::string::npos);

    const auto preauth_probe = protocol::kerberos_error_response(
        test_as_req("Administrator", "ENDORIUM.LOCAL"),
        ad_realm);
    const std::string preauth_probe_text(preauth_probe.begin(), preauth_probe.end());
    assert(!preauth_probe.empty());
    assert(preauth_probe.front() == 0x7e);
    assert(preauth_probe_text.find("pre-authentication required") != std::string::npos);
    // Regression (real-client interop): the KDC_ERR_PREAUTH_REQUIRED method-data must
    // advertise PA-ENC-TIMESTAMP (type 2) as an empty entry. Strict clients (MIT kinit,
    // the Windows domain-join Kerberos client) only perform encrypted-timestamp
    // pre-authentication when the KDC advertises it; otherwise they re-send the request
    // unauthenticated and the join fails with "the username or password is incorrect".
    // DER for pa_data(2, {}): 30 09 a1 03 02 01 02 a2 02 04 00.
    const std::vector<std::uint8_t> pa_enc_timestamp_entry{
        0x30, 0x09, 0xa1, 0x03, 0x02, 0x01, 0x02, 0xa2, 0x02, 0x04, 0x00};
    assert(std::search(
               preauth_probe.begin(), preauth_probe.end(),
               pa_enc_timestamp_entry.begin(), pa_enc_timestamp_entry.end()) != preauth_probe.end());

    const auto ldap_salt = security::ad_kerberos_salt("ENDORIUM.LOCAL", "ldap/dc1.endorium.local");
    const auto ldap_key = security::derive_ad_kerberos_aes_key("dc-service-secret", ldap_salt, 32);
    const protocol::KerberosPrincipal ldap_principal{
        "ldap/dc1.endorium.local",
        "ENDORIUM.LOCAL",
        true,
        {{18, "aes256-cts-hmac-sha1-96", ldap_salt, ldap_key}},
    };
    const auto cifs_salt = security::ad_kerberos_salt("ENDORIUM.LOCAL", "cifs/dc1.endorium.local");
    const auto cifs_key = security::derive_ad_kerberos_aes_key("dc-service-secret", cifs_salt, 32);
    const protocol::KerberosPrincipal cifs_principal{
        "cifs/dc1.endorium.local",
        "ENDORIUM.LOCAL",
        true,
        {{18, "aes256-cts-hmac-sha1-96", cifs_salt, cifs_key}},
    };
    const protocol::KerberosPrincipal kpasswd_principal{
        "kadmin/changepw",
        "ENDORIUM.LOCAL",
        true,
        {{18, "aes256-cts-hmac-sha1-96", krbtgt_salt, krbtgt_key}},
    };
    const protocol::KerberosRealmInfo ad_realm_with_service{
        "ENDORIUM.LOCAL",
        "krbtgt",
        {admin_principal, krbtgt_principal, ldap_principal, cifs_principal, kpasswd_principal},
    };
    const TestBytes pac = protocol::kerberos_minimal_pac(
        "Administrator",
        "ENDORIUM.LOCAL",
        admin_principal,
        ldap_principal.keys.front(),
        krbtgt_principal.keys.front());
    assert(!pac.empty());
    const auto pac_buffers = test_parse_pac_buffers(pac);
    assert(pac_buffers.size() == 5);
    auto find_pac_buffer = [&](std::uint32_t type) {
        return std::find_if(pac_buffers.begin(), pac_buffers.end(), [&](const auto& buffer) {
            return buffer.type == type;
        });
    };
    const auto pac_logon_info = find_pac_buffer(1);
    const auto pac_client_info = find_pac_buffer(10);
    const auto pac_upn_dns_info = find_pac_buffer(12);
    const auto pac_server_checksum = find_pac_buffer(6);
    const auto pac_kdc_checksum = find_pac_buffer(7);
    assert(pac_logon_info != pac_buffers.end());
    assert(pac_client_info != pac_buffers.end());
    assert(pac_upn_dns_info != pac_buffers.end());
    assert(pac_server_checksum != pac_buffers.end());
    assert(pac_kdc_checksum != pac_buffers.end());
    assert(pac_upn_dns_info->data.size() > 16);
    assert(pac_server_checksum->data.size() == 16);
    assert(pac_kdc_checksum->data.size() == 16);
    assert(test_rpc_read_u32(pac_server_checksum->data, 0) == 16);
    assert(test_rpc_read_u32(pac_kdc_checksum->data, 0) == 16);
    assert(std::any_of(
        pac_server_checksum->data.begin() + 4,
        pac_server_checksum->data.end(),
        [](std::uint8_t value) { return value != 0; }));
    assert(std::any_of(
        pac_kdc_checksum->data.begin() + 4,
        pac_kdc_checksum->data.end(),
        [](std::uint8_t value) { return value != 0; }));
    const TestBytes ldap_session_key{
        0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37,
        0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
        0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47,
        0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f};
    const TestBytes ldap_ticket_confounder{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3};
    const auto encrypted_ldap_ticket = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        test_enc_ticket_part("ENDORIUM.LOCAL", "Administrator", 18, ldap_session_key),
        ldap_key,
        2,
        ldap_ticket_confounder);
    const auto ldap_ticket = test_ticket("ENDORIUM.LOCAL", "ldap/dc1.endorium.local", 18, encrypted_ldap_ticket);
    const TestBytes ldap_authenticator_confounder{4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4, 4};
    const auto encrypted_ldap_authenticator = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        test_authenticator("ENDORIUM.LOCAL", "Administrator"),
        test_bytes_to_hex(ldap_session_key),
        11,
        ldap_authenticator_confounder);
    const auto ldap_ap_req = test_ap_req(ldap_ticket, 18, encrypted_ldap_authenticator);
    const auto ldap_mutual_ap_req = test_ap_req(ldap_ticket, 18, encrypted_ldap_authenticator, 0x20000000U);
    const auto valid_ldap_ap_req = protocol::validate_kerberos_ap_req(
        ldap_ap_req,
        ad_realm_with_service,
        "ldap/dc1.endorium.local");
    assert(valid_ldap_ap_req.ok);
    assert(valid_ldap_ap_req.client_principal == "Administrator");
    assert(valid_ldap_ap_req.service_principal == "ldap/dc1.endorium.local");
    const protocol::KerberosRealmInfo ad_realm_with_disabled_apreq_client{
        "ENDORIUM.LOCAL",
        "krbtgt",
        {disabled_admin_principal, krbtgt_principal, ldap_principal, cifs_principal, kpasswd_principal},
    };
    const auto disabled_client_ldap_ap_req = protocol::validate_kerberos_ap_req(
        ldap_ap_req,
        ad_realm_with_disabled_apreq_client,
        "ldap/dc1.endorium.local");
    assert(!disabled_client_ldap_ap_req.ok);
    assert(disabled_client_ldap_ap_req.diagnostic.find("client principal account is disabled") != std::string::npos);
    const protocol::KerberosRealmInfo ad_realm_with_expired_apreq_client{
        "ENDORIUM.LOCAL",
        "krbtgt",
        {expired_admin_principal, krbtgt_principal, ldap_principal, cifs_principal, kpasswd_principal},
    };
    const auto expired_client_ldap_ap_req = protocol::validate_kerberos_ap_req(
        ldap_ap_req,
        ad_realm_with_expired_apreq_client,
        "ldap/dc1.endorium.local");
    assert(!expired_client_ldap_ap_req.ok);
    assert(expired_client_ldap_ap_req.diagnostic.find("client principal account is expired") != std::string::npos);
    auto disabled_ldap_principal = ldap_principal;
    disabled_ldap_principal.user_account_control = 0x00000002U;
    const protocol::KerberosRealmInfo ad_realm_with_disabled_ldap{
        "ENDORIUM.LOCAL",
        "krbtgt",
        {admin_principal, krbtgt_principal, disabled_ldap_principal, cifs_principal, kpasswd_principal},
    };
    const auto disabled_service_ldap_ap_req = protocol::validate_kerberos_ap_req(
        ldap_ap_req,
        ad_realm_with_disabled_ldap,
        "ldap/dc1.endorium.local");
    assert(!disabled_service_ldap_ap_req.ok);
    assert(disabled_service_ldap_ap_req.diagnostic.find("service principal account is disabled") != std::string::npos);
    const auto valid_ldap_mutual_ap_req = protocol::validate_kerberos_ap_req(
        ldap_mutual_ap_req,
        ad_realm_with_service,
        "ldap/dc1.endorium.local");
    assert(valid_ldap_mutual_ap_req.ok);
    assert(!valid_ldap_mutual_ap_req.response_token.empty());
    assert(valid_ldap_mutual_ap_req.response_token.front() == 0x6f);
    const auto unknown_service_ldap_ap_req = protocol::validate_kerberos_ap_req(
        ldap_ap_req,
        ad_realm,
        "ldap/dc1.endorium.local");
    assert(!unknown_service_ldap_ap_req.ok);
    assert(unknown_service_ldap_ap_req.diagnostic.find("service principal unknown") != std::string::npos);
    const auto ldap_sasl_ap_req_bind_response = protocol::ldap_ad_response(
        test_ldap_sasl_bind_request(43, 3, "", "GSSAPI", ldap_ap_req),
        ldap_directory,
        {},
        ldap_mutation_handler,
        ad_realm_with_service);
    assert(test_has_ldap_result_code(ldap_sasl_ap_req_bind_response, 0));
    const auto ldap_spnego_ap_req_bind_response = protocol::ldap_ad_response(
        test_ldap_sasl_bind_request(45, 3, "", "GSS-SPNEGO", test_spnego_token_with_ap_req(ldap_ap_req)),
        ldap_directory,
        {},
        ldap_mutation_handler,
        ad_realm_with_service);
    assert(test_has_ldap_result_code(ldap_spnego_ap_req_bind_response, 0));
    const auto ldap_mutual_ap_req_bind_response = protocol::ldap_ad_response(
        test_ldap_sasl_bind_request(46, 3, "", "GSSAPI", ldap_mutual_ap_req),
        ldap_directory,
        {},
        ldap_mutation_handler,
        ad_realm_with_service);
    assert(test_has_ldap_result_code(ldap_mutual_ap_req_bind_response, 0));
    assert(std::find(ldap_mutual_ap_req_bind_response.begin(), ldap_mutual_ap_req_bind_response.end(), 0x87) !=
           ldap_mutual_ap_req_bind_response.end());
    assert(std::find(ldap_mutual_ap_req_bind_response.begin(), ldap_mutual_ap_req_bind_response.end(), 0x6f) !=
           ldap_mutual_ap_req_bind_response.end());
    const auto ldap_sasl_invalid_ap_req_bind_response = protocol::ldap_ad_response(
        test_ldap_sasl_bind_request(44, 3, "", "GSS-SPNEGO", {0x60, 0x01, 0x00}),
        ldap_directory,
        {},
        ldap_mutation_handler,
        ad_realm_with_service);
    const std::string ldap_sasl_invalid_ap_req_text(
        ldap_sasl_invalid_ap_req_bind_response.begin(),
        ldap_sasl_invalid_ap_req_bind_response.end());
    assert(test_has_ldap_result_code(ldap_sasl_invalid_ap_req_bind_response, 49));
    assert(ldap_sasl_invalid_ap_req_text.find("AP-REQ is missing") != std::string::npos);
    protocol::LdapSessionInfo ldap_session;
    const auto ldap_mutations_before_session_auth = ldap_mutations.size();
    const auto ldap_unauthenticated_add_response = protocol::ldap_ad_response(
        test_ldap_add_request(
            50,
            "cn=WS04,cn=Computers,dc=endorium,dc=local",
            {
                test_ldap_attribute("objectClass", {"top", "person", "organizationalPerson", "user", "computer"}),
                test_ldap_attribute("sAMAccountName", {"WS04$"}),
            }),
        ldap_directory,
        {},
        ldap_mutation_handler,
        ad_realm_with_service,
        &ldap_session);
    assert(test_has_ldap_result_code(ldap_unauthenticated_add_response, 50));
    assert(ldap_mutations.size() == ldap_mutations_before_session_auth);
    assert(!ldap_session.authenticated);
    const auto ldap_session_bind_response = protocol::ldap_ad_response(
        test_ldap_sasl_bind_request(51, 3, "", "GSSAPI", ldap_ap_req),
        ldap_directory,
        {},
        ldap_mutation_handler,
        ad_realm_with_service,
        &ldap_session);
    assert(test_has_ldap_result_code(ldap_session_bind_response, 0));
    assert(ldap_session.authenticated);
    assert(ldap_session.principal == "Administrator");
    const auto ldap_authenticated_add_response = protocol::ldap_ad_response(
        test_ldap_add_request(
            52,
            "cn=WS04,cn=Computers,dc=endorium,dc=local",
            {
                test_ldap_attribute("objectClass", {"top", "person", "organizationalPerson", "user", "computer"}),
                test_ldap_attribute("sAMAccountName", {"WS04$"}),
            }),
        ldap_directory,
        {},
        ldap_mutation_handler,
        ad_realm_with_service,
        &ldap_session);
    assert(test_has_ldap_result_code(ldap_authenticated_add_response, 0));
    assert(ldap_mutations.size() == ldap_mutations_before_session_auth + 1);
    assert(ldap_mutations.back().object.dn == "cn=WS04,cn=Computers,dc=endorium,dc=local");
    const TestBytes cifs_session_key{
        0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57,
        0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
        0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67,
        0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f};
    const TestBytes cifs_ticket_confounder{5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5, 5};
    const auto encrypted_cifs_ticket = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        test_enc_ticket_part("ENDORIUM.LOCAL", "Administrator", 18, cifs_session_key),
        cifs_key,
        2,
        cifs_ticket_confounder);
    const auto cifs_ticket = test_ticket("ENDORIUM.LOCAL", "cifs/dc1.endorium.local", 18, encrypted_cifs_ticket);
    const TestBytes cifs_authenticator_confounder{6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6, 6};
    const auto encrypted_cifs_authenticator = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        test_authenticator("ENDORIUM.LOCAL", "Administrator"),
        test_bytes_to_hex(cifs_session_key),
        11,
        cifs_authenticator_confounder);
    const auto cifs_ap_req = test_ap_req(cifs_ticket, 18, encrypted_cifs_authenticator);
    const auto cifs_mutual_ap_req = test_ap_req(cifs_ticket, 18, encrypted_cifs_authenticator, 0x20000000U);
    const auto cifs_enterprise_ticket =
        test_ticket("ENDORIUM.LOCAL", "CIFS/DC1.ENDORIUM.LOCAL@ENDORIUM.LOCAL", 18, encrypted_cifs_ticket);
    const auto cifs_enterprise_ap_req = test_ap_req(cifs_enterprise_ticket, 18, encrypted_cifs_authenticator);
    const auto valid_cifs_enterprise_ap_req = protocol::validate_kerberos_ap_req(
        cifs_enterprise_ap_req,
        ad_realm_with_service,
        "cifs/dc1.endorium.local");
    assert(valid_cifs_enterprise_ap_req.ok);
    assert(valid_cifs_enterprise_ap_req.service_principal == "CIFS/DC1.ENDORIUM.LOCAL@ENDORIUM.LOCAL");
    const protocol::Smb2RuntimeInfo smb_kerberos_runtime{
        {},
        ad_realm_with_service,
        "cifs/dc1.endorium.local",
    };
    const auto smb_kerberos_session_setup =
        test_smb2_session_setup_request(test_spnego_token_with_ap_req(cifs_ap_req), 118);
    const auto parsed_smb_kerberos_session_setup = protocol::parse_smb2_request(smb_kerberos_session_setup);
    assert(parsed_smb_kerberos_session_setup.valid);
    assert(!parsed_smb_kerberos_session_setup.security_blob.empty());
    const auto smb_kerberos_session_response =
        protocol::smb2_response(smb_kerberos_session_setup, smb_kerberos_runtime);
    assert(test_rpc_read_u32(smb_kerberos_session_response, 4 + 8) == 0);
    assert(test_rpc_read_u64(smb_kerberos_session_response, 4 + 40) != 0);
    assert((test_rpc_read_u32(smb_kerberos_session_response, 4 + 16) & 0x00000008U) != 0);
    assert(std::any_of(
        smb_kerberos_session_response.begin() + 4 + 48,
        smb_kerberos_session_response.begin() + 4 + 64,
        [](const auto byte) { return byte != 0; }));
    const auto smb_kerberos_session_id = test_rpc_read_u64(smb_kerberos_session_response, 4 + 40);
    const auto smb_signed_tree_response = protocol::smb2_response(
        test_smb2_tree_connect_request("\\\\dc1\\IPC$", smb_kerberos_session_id, 130),
        smb_kerberos_runtime);
    assert(test_rpc_read_u32(smb_signed_tree_response, 4 + 8) == 0);
    assert((test_rpc_read_u32(smb_signed_tree_response, 4 + 16) & 0x00000008U) != 0);
    assert(std::any_of(
        smb_signed_tree_response.begin() + 4 + 48,
        smb_signed_tree_response.begin() + 4 + 64,
        [](const auto byte) { return byte != 0; }));
    const auto smb_mutual_kerberos_session_setup =
        test_smb2_session_setup_request(test_spnego_token_with_ap_req(cifs_mutual_ap_req), 120);
    const auto smb_mutual_kerberos_session_response =
        protocol::smb2_response(smb_mutual_kerberos_session_setup, smb_kerberos_runtime);
    assert(test_rpc_read_u32(smb_mutual_kerberos_session_response, 4 + 8) == 0);
    const auto smb_mutual_security_offset = test_rpc_read_u16(smb_mutual_kerberos_session_response, 4 + 64 + 4);
    const auto smb_mutual_security_length = test_rpc_read_u16(smb_mutual_kerberos_session_response, 4 + 64 + 6);
    assert(smb_mutual_security_offset == 72);
    assert(smb_mutual_security_length > 0);
    assert(smb_mutual_kerberos_session_response[4 + smb_mutual_security_offset] == 0x60);
    assert(std::find(smb_mutual_kerberos_session_response.begin(), smb_mutual_kerberos_session_response.end(), 0x6f) !=
           smb_mutual_kerberos_session_response.end());
    const auto smb_invalid_kerberos_session_response = protocol::smb2_response(
        test_smb2_session_setup_request({0x60, 0x01, 0x00}, 119),
        smb_kerberos_runtime);
    assert(test_rpc_read_u32(smb_invalid_kerberos_session_response, 4 + 8) == 0xc000006dU);
    const TestBytes tgt_session_key{
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
        0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
        0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f};
    const TestBytes tgt_confounder{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1};
    const auto encrypted_tgt = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        test_enc_ticket_part("ENDORIUM.LOCAL", "Administrator", 18, tgt_session_key),
        krbtgt_key,
        2,
        tgt_confounder);
    const auto tgt_ticket = test_ticket("ENDORIUM.LOCAL", "krbtgt/ENDORIUM.LOCAL", 18, encrypted_tgt);
    const TestBytes authenticator_confounder{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2};
    const auto encrypted_authenticator = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        test_authenticator("ENDORIUM.LOCAL", "Administrator"),
        test_bytes_to_hex(tgt_session_key),
        7,
        authenticator_confounder);
    const auto ap_req = test_ap_req(tgt_ticket, 18, encrypted_authenticator);
    const auto tgs_req = test_tgs_req("ldap/dc1.endorium.local", "ENDORIUM.LOCAL", ap_req);
    const auto parsed_tgs_req = protocol::parse_kerberos_request(tgs_req);
    assert(parsed_tgs_req.valid);
    assert(parsed_tgs_req.message_type == 12);
    assert(parsed_tgs_req.service_principal == "ldap/dc1.endorium.local");
    assert(parsed_tgs_req.nonce == 84);
    assert(!parsed_tgs_req.tgs_ap_req.empty());
    const auto tgs_rep = protocol::kerberos_error_response(tgs_req, ad_realm_with_service);
    assert(!tgs_rep.empty());
    assert(tgs_rep.front() == 0x6d);
    const std::string tgs_rep_text(tgs_rep.begin(), tgs_rep.end());
    assert(tgs_rep_text.find("ldap") != std::string::npos);
    assert(tgs_rep_text.find("dc1.endorium.local") != std::string::npos);

    const auto disabled_client_tgs_error = protocol::kerberos_error_response(
        tgs_req,
        {"ENDORIUM.LOCAL", "krbtgt", {disabled_admin_principal, krbtgt_principal, ldap_principal}});
    const std::string disabled_client_tgs_text(disabled_client_tgs_error.begin(), disabled_client_tgs_error.end());
    assert(!disabled_client_tgs_error.empty());
    assert(disabled_client_tgs_error.front() == 0x7e);
    assert(disabled_client_tgs_text.find("client principal account is disabled") != std::string::npos);

    const auto disabled_service_tgs_error = protocol::kerberos_error_response(
        tgs_req,
        {"ENDORIUM.LOCAL", "krbtgt", {admin_principal, krbtgt_principal, disabled_ldap_principal}});
    const std::string disabled_service_tgs_text(disabled_service_tgs_error.begin(), disabled_service_tgs_error.end());
    assert(!disabled_service_tgs_error.empty());
    assert(disabled_service_tgs_error.front() == 0x7e);
    assert(disabled_service_tgs_text.find("service principal account is disabled") != std::string::npos);

    const auto canonicalized_tgs_req =
        test_tgs_req("LDAP/DC1.ENDORIUM.LOCAL@ENDORIUM.LOCAL", "ENDORIUM.LOCAL", ap_req);
    const auto parsed_canonicalized_tgs_req = protocol::parse_kerberos_request(canonicalized_tgs_req);
    assert(parsed_canonicalized_tgs_req.valid);
    assert(parsed_canonicalized_tgs_req.service_principal == "LDAP/DC1.ENDORIUM.LOCAL@ENDORIUM.LOCAL");
    const auto canonicalized_tgs_rep =
        protocol::kerberos_error_response(canonicalized_tgs_req, ad_realm_with_service);
    assert(!canonicalized_tgs_rep.empty());
    assert(canonicalized_tgs_rep.front() == 0x6d);
    const std::string canonicalized_tgs_rep_text(canonicalized_tgs_rep.begin(), canonicalized_tgs_rep.end());
    assert(canonicalized_tgs_rep_text.find("ldap") != std::string::npos);
    assert(canonicalized_tgs_rep_text.find("dc1.endorium.local") != std::string::npos);
    assert(canonicalized_tgs_rep_text.find("LDAP/DC1.ENDORIUM.LOCAL@ENDORIUM.LOCAL") == std::string::npos);

    const auto missing_service_tgs = protocol::kerberos_error_response(tgs_req, ad_realm);
    const std::string missing_service_text(missing_service_tgs.begin(), missing_service_tgs.end());
    assert(!missing_service_tgs.empty());
    assert(missing_service_tgs.front() == 0x7e);
    assert(missing_service_text.find("service principal unknown") != std::string::npos);

    const TestBytes kpasswd_session_key{
        0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77,
        0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
        0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
        0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f};
    const TestBytes kpasswd_ticket_confounder{7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7, 7};
    const auto encrypted_kpasswd_ticket = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        test_enc_ticket_part("ENDORIUM.LOCAL", "Administrator", 18, kpasswd_session_key),
        krbtgt_key,
        2,
        kpasswd_ticket_confounder);
    const auto kpasswd_ticket = test_ticket("ENDORIUM.LOCAL", "kadmin/changepw", 18, encrypted_kpasswd_ticket);
    const TestBytes kpasswd_authenticator_confounder{8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8, 8};
    const auto encrypted_kpasswd_authenticator = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        test_authenticator("ENDORIUM.LOCAL", "Administrator"),
        test_bytes_to_hex(kpasswd_session_key),
        11,
        kpasswd_authenticator_confounder);
    const auto kpasswd_ap_req = test_ap_req(kpasswd_ticket, 18, encrypted_kpasswd_authenticator);
    const auto encrypted_kpasswd_priv = protocol::kerberos_encrypt_aes_cts_hmac_sha1(
        test_enc_krb_priv_part(test_kpasswd_change_data("EvenNewer-AD-1")),
        test_bytes_to_hex(kpasswd_session_key),
        13,
        {9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9, 9});
    const auto kpasswd_request = test_kpasswd_request(kpasswd_ap_req, test_krb_priv(encrypted_kpasswd_priv));
    const auto parsed_kpasswd = protocol::parse_kpasswd_request(kpasswd_request);
    assert(parsed_kpasswd.valid);
    assert(parsed_kpasswd.version == 0xff80U);
    assert(parsed_kpasswd.ap_req_length == kpasswd_ap_req.size());
    assert(parsed_kpasswd.ap_req == kpasswd_ap_req);
    assert(!parsed_kpasswd.encrypted_payload.empty());
    std::optional<protocol::KerberosPasswordChange> captured_kpasswd_change;
    const auto kpasswd_response = protocol::kerberos_kpasswd_response(
        kpasswd_request,
        ad_realm_with_service,
        [&](const protocol::KerberosPasswordChange& change) {
            captured_kpasswd_change = change;
            return true;
        });
    assert(!kpasswd_response.empty());
    assert(test_read_u16_be(kpasswd_response, 0) == kpasswd_response.size());
    assert(test_read_u16_be(kpasswd_response, 2) == 0xff80U);
    assert(test_read_u16_be(kpasswd_response, 4) == 0);
    assert(kpasswd_response[6] == 0x75);
    assert(captured_kpasswd_change.has_value());
    assert(captured_kpasswd_change->principal == "Administrator");
    assert(captured_kpasswd_change->new_password == "EvenNewer-AD-1");
    const auto rejected_kpasswd_response = protocol::kerberos_kpasswd_response(
        kpasswd_request,
        ad_realm_with_service,
        [](const protocol::KerberosPasswordChange&) {
            return false;
        });
    assert(!rejected_kpasswd_response.empty());
    assert(rejected_kpasswd_response[6] == 0x7e);
    const auto invalid_kpasswd_payload_response = protocol::kerberos_kpasswd_response(
        test_kpasswd_request(kpasswd_ap_req, {0x76, 0x01, 0x00}),
        ad_realm_with_service,
        [](const protocol::KerberosPasswordChange&) {
            return true;
        });
    const std::string invalid_kpasswd_text(invalid_kpasswd_payload_response.begin(), invalid_kpasswd_payload_response.end());
    assert(invalid_kpasswd_payload_response[6] == 0x7e);
    assert(invalid_kpasswd_text.find("KRB-PRIV") != std::string::npos);
    const auto malformed_kpasswd_response = protocol::kerberos_kpasswd_response({0, 1, 2}, ad_realm_with_service);
    assert(!malformed_kpasswd_response.empty());
    assert(test_read_u16_be(malformed_kpasswd_response, 2) == 0xff80U);
    const auto tcp_kpasswd_response = protocol::kerberos_tcp_kpasswd_response(
        test_kerberos_tcp_frame(kpasswd_request),
        ad_realm_with_service,
        [](const protocol::KerberosPasswordChange&) {
            return true;
        });
    assert(!tcp_kpasswd_response.empty());
    assert(test_read_u32_be(tcp_kpasswd_response, 0) == tcp_kpasswd_response.size() - 4);
    assert(tcp_kpasswd_response[10] == 0x75);

    security::Totp totp;
    const auto secret = totp.generate_secret();
    const auto now = std::chrono::system_clock::now();
    const auto code = totp.code_at(secret, now);
    assert(totp.verify(secret, code, now));

    security::PkiService pki;
    const auto root = pki.create_root_ca({"Endorium Root", "Endorium", {"endorium.local"}}, 3650);
    const auto leaf = pki.issue_leaf_certificate(root, {"api.endorium.local", "Endorium", {"api.endorium.local"}}, 365);
    assert(root.certificate_pem.find("BEGIN CERTIFICATE") != std::string::npos);
    assert(leaf.private_key_pem.find("BEGIN PRIVATE KEY") != std::string::npos);

    core::AptPackage agent_package;
    agent_package.name = "endorium-agent";
    agent_package.version = "0.1.0";
    agent_package.architecture = "amd64";
    agent_package.component = "main";
    agent_package.filename = "pool/main/e/endorium-agent_0.1.0_amd64.deb";
    agent_package.storage_path = agent_package.filename;
    agent_package.sha256 = "abc123";
    agent_package.size = 12345;
    agent_package.control_json = R"JSON({"Description":"Endorium agent\nextended details","Depends":"curl (>= 7.0)","Maintainer":"Endorium <ops@endorium.local>","Priority":"standard"})JSON";
    const core::AptRepository repository{
        "bookworm",
        "main",
        {agent_package}};
    const auto packages = protocol::render_packages_index(repository);
    const auto release = protocol::render_release_file(repository, "Endorium", "stable", "abc123", packages.size());
    const auto gzip = protocol::gzip_bytes(packages);
    assert(packages.find("Package: endorium-agent") != std::string::npos);
    assert(release.find("Codename: bookworm") != std::string::npos);
    assert(!gzip.empty());
    const auto control_fields = apt::parse_control_fields(
        "Package: endorium-agent\n"
        "Version: 0.1.0\n"
        "Architecture: amd64\n"
        "Description: Endorium agent\n"
        " continued description\n");
    assert(control_fields.at("Package") == "endorium-agent");
    assert(control_fields.at("Description").find("continued description") != std::string::npos);
    const auto apt_packages = apt::render_packages_index({agent_package});
    assert(apt_packages.find("Filename: pool/main/e/endorium-agent_0.1.0_amd64.deb") != std::string::npos);
    assert(apt_packages.find("Maintainer: Endorium <ops@endorium.local>") != std::string::npos);
    assert(apt_packages.find("Depends: curl (>= 7.0)") != std::string::npos);
    assert(apt_packages.find("Description: Endorium agent\n extended details") != std::string::npos);
    const auto deb_test_root = std::filesystem::temp_directory_path() / "endorium-nexus-deb-metadata-test";
    std::filesystem::remove_all(deb_test_root);
    std::filesystem::create_directories(deb_test_root / "pkg" / "DEBIAN");
    std::filesystem::create_directories(deb_test_root / "pkg" / "usr" / "share" / "endorium-agent");
    {
        std::ofstream control(deb_test_root / "pkg" / "DEBIAN" / "control");
        control << "Package: endorium-agent\n";
        control << "Version: 1.2.3\n";
        control << "Architecture: amd64\n";
        control << "Maintainer: Endorium <ops@endorium.local>\n";
        control << "Description: Endorium test agent\n";
    }
    {
        std::ofstream payload(deb_test_root / "pkg" / "usr" / "share" / "endorium-agent" / "README");
        payload << "test\n";
    }
    const auto deb_path = deb_test_root / "endorium-agent_1.2.3_amd64.deb";
    const auto build_command = "dpkg-deb --build " + (deb_test_root / "pkg").string() + " " + deb_path.string() + " >/dev/null 2>&1";
    assert(std::system(build_command.c_str()) == 0);
    const auto deb_fields = apt::extract_deb_control_fields(deb_path);
    assert(deb_fields.at("Package") == "endorium-agent");
    assert(deb_fields.at("Version") == "1.2.3");
    assert(deb_fields.at("Architecture") == "amd64");
    std::filesystem::remove_all(deb_test_root);
    const auto apt_test_root = std::filesystem::temp_directory_path() / "endorium-nexus-apt-path-test";
    std::filesystem::remove_all(apt_test_root);
    std::filesystem::create_directories(apt_test_root / "blobs" / "apt" / "pool" / "main" / "e");
    {
        std::ofstream artifact(apt_test_root / "blobs" / "apt" / "pool" / "main" / "e" / "endorium-agent.deb");
        artifact << "deb";
    }
    apt::RepositoryService apt_service("", apt_test_root / "blobs", apt_test_root / "state", "Endorium");
    assert(apt_service.artifact_path("pool/main/e/endorium-agent.deb").has_value());
    assert(!apt_service.artifact_path("../secret.deb").has_value());
    assert(!apt_service.artifact_path("pool/../../secret.deb").has_value());
    std::filesystem::remove_all(apt_test_root);

    assert(vcs::is_valid_repository_name("infra-tools"));
    assert(vcs::is_valid_repository_name("api.v2"));
    assert(!vcs::is_valid_repository_name("../infra"));
    assert(!vcs::is_valid_repository_name("infra.git"));
    assert(!vcs::is_valid_repository_name("infra/tools"));
    assert(vcs::is_valid_branch_name("main"));
    assert(vcs::is_valid_branch_name("feature/git-http"));
    assert(!vcs::is_valid_branch_name("feature git"));
    assert(!vcs::is_valid_branch_name("feature..git"));
    assert(vcs::token_scope_allows("read", false));
    assert(!vcs::token_scope_allows("read", true));
    assert(vcs::token_scope_allows("write", false));
    assert(vcs::token_scope_allows("write", true));
    assert(!vcs::token_scope_allows("admin", false));
    const auto git_ref_root = std::filesystem::temp_directory_path() / "endorium-nexus-git-ref-test";
    std::filesystem::remove_all(git_ref_root);
    std::filesystem::create_directories(git_ref_root);
    const auto git_work = git_ref_root / "work";
    const auto git_bare = git_ref_root / "repo.git";
    assert(std::system(("git init -q " + git_work.string()).c_str()) == 0);
    assert(std::system(("git -C " + git_work.string() + " config user.email tester@endorium.local").c_str()) == 0);
    assert(std::system(("git -C " + git_work.string() + " config user.name Tester").c_str()) == 0);
    assert(std::system(("git -C " + git_work.string() + " checkout -q -b main").c_str()) == 0);
    assert(std::system(("git -C " + git_work.string() + " commit --allow-empty -q -m initial").c_str()) == 0);
    assert(std::system(("git -C " + git_work.string() + " tag v1").c_str()) == 0);
    assert(std::system(("git clone --bare -q " + git_work.string() + " " + git_bare.string()).c_str()) == 0);
    const auto git_refs = vcs::list_repository_refs(git_bare);
    assert(std::any_of(git_refs.begin(), git_refs.end(), [](const auto& ref) {
        return ref.type == "branch" && ref.short_name == "main";
    }));
    assert(std::any_of(git_refs.begin(), git_refs.end(), [](const auto& ref) {
        return ref.type == "tag" && ref.short_name == "v1";
    }));
    std::filesystem::remove_all(git_ref_root);

    jobs::JobQueue queue;
    assert(queue.pending_count() >= 1);
    const auto job = queue.enqueue("dns", "Reload zone");
    assert(job.domain == "dns");

    const auto state_root = std::filesystem::temp_directory_path() / "endorium-nexus-settings-test";
    std::filesystem::remove_all(state_root);

    core::Config config;
    config.environment = "development";
    config.domain = "endorium.local";
    config.http = {"127.0.0.1", 8080};
    config.dns_udp = {"127.0.0.1", 8053};
    config.dns_tcp = {"127.0.0.1", 8053};
    config.dhcp = {"127.0.0.1", 8067};
    config.ldap = {"127.0.0.1", 8389};
    config.ldaps = {"127.0.0.1", 8636};
    config.gc = {"127.0.0.1", 8326};
    config.kerberos = {"127.0.0.1", 8088};
    config.kpasswd = {"127.0.0.1", 8464};
    config.rpc = {"127.0.0.1", 8135};
    config.smb = {"127.0.0.1", 8445};
    config.database_url = "";
    config.sql_migrations_dir = "backend/sql/migrations";
    config.admin_email = "admin@endorium.local";
    config.admin_password_hash = hash;
    config.state_root = state_root;

    nexus::api::PlatformState first_state(config);
    const auto ad_readiness = first_state.active_directory_readiness();
    assert(!ad_readiness.supported);
    assert(!ad_readiness.items.empty());
    const auto protocol_status_item = std::find_if(
        ad_readiness.items.begin(),
        ad_readiness.items.end(),
        [](const auto& item) { return item.id == "protocol-status-store"; });
    assert(protocol_status_item != ad_readiness.items.end());
    assert(!protocol_status_item->ready);
    const auto kerberos_kdc_item = std::find_if(
        ad_readiness.items.begin(),
        ad_readiness.items.end(),
        [](const auto& item) { return item.id == "kerberos-kdc"; });
    assert(kerberos_kdc_item != ad_readiness.items.end());
    assert(!kerberos_kdc_item->ready);
    assert(kerberos_kdc_item->blocking);
    const auto seed_item = std::find_if(
        ad_readiness.items.begin(),
        ad_readiness.items.end(),
        [](const auto& item) { return item.id == "ad-default-seed"; });
    assert(seed_item != ad_readiness.items.end());
    assert(seed_item->ready);
    const auto seeded_directory_count = first_state.directory_objects().size();
    assert(seeded_directory_count >= 18);
    const auto seeded_ad_objects = first_state.active_directory_objects();
    assert(seeded_ad_objects.size() == seeded_directory_count);
    const auto administrator_ad_object = std::find_if(
        seeded_ad_objects.begin(),
        seeded_ad_objects.end(),
        [](const auto& object) { return object.dn == "cn=Administrator,cn=Users,dc=endorium,dc=local"; });
    assert(administrator_ad_object != seeded_ad_objects.end());
    assert(!administrator_ad_object->object_guid.empty());
    assert(administrator_ad_object->object_sid.starts_with("S-1-5-21-"));
    const auto sid_attribute = std::find_if(
        administrator_ad_object->attributes.begin(),
        administrator_ad_object->attributes.end(),
        [](const auto& attribute) { return attribute.name == "objectSid"; });
    assert(sid_attribute != administrator_ad_object->attributes.end());
    assert(sid_attribute->type == "sid");
    assert(!sid_attribute->values.empty());
    assert(sid_attribute->values.front().encoding == "sddl");
    const auto object_class_attribute = std::find_if(
        administrator_ad_object->attributes.begin(),
        administrator_ad_object->attributes.end(),
        [](const auto& attribute) { return attribute.name == "objectClass"; });
    assert(object_class_attribute != administrator_ad_object->attributes.end());
    assert(object_class_attribute->multi_valued);
    assert(std::none_of(
        administrator_ad_object->attributes.begin(),
        administrator_ad_object->attributes.end(),
        [](const auto& attribute) { return attribute.name == "userPasswordHash"; }));

    core::DirectoryObject user{
        "uid=alice,ou=People,dc=endorium,dc=local",
        "ou=People,dc=endorium,dc=local",
        "user",
        {"inetOrgPerson", "person"},
        {{"cn", "Alice Admin"}, {"sn", "Admin"}, {"uid", "alice"}}};
    assert(first_state.create_directory_object(user, "alice-secret", "tester"));
    auto directory = first_state.directory_objects();
    assert(directory.size() == seeded_directory_count + 1);
    const auto alice_object = std::find_if(
        directory.begin(),
        directory.end(),
        [](const auto& object) { return object.dn == "uid=alice,ou=People,dc=endorium,dc=local"; });
    assert(alice_object != directory.end());
    assert(alice_object->attributes.count("userPasswordHash") == 1);
    assert(alice_object->attributes.at("userPasswordHash") != "alice-secret");
    assert(alice_object->attributes.at("sAMAccountName") == "alice");
    assert(alice_object->attributes.at("userPrincipalName") == "alice@endorium.local");
    assert(alice_object->attributes.at("objectSid").starts_with("S-1-5-21-"));
    assert(alice_object->attributes.at("primaryGroupID") == "513");
    assert(alice_object->attributes.at("groupRids") == "513");
    assert(alice_object->attributes.at("userAccountControl") == "512");
    assert(alice_object->attributes.at("accountExpires") == "9223372036854775807");
    assert(alice_object->attributes.at("badPwdCount") == "0");
    assert(alice_object->attributes.at("logonCount") == "0");
    assert(alice_object->attributes.at("msDS-SupportedEncryptionTypes") == "28");
    assert(alice_object->attributes.at("pwdLastSet") != "0");
    core::DirectoryObject computer{
        "cn=ws01,cn=Computers,dc=endorium,dc=local",
        "cn=Computers,dc=endorium,dc=local",
        "computer",
        {"computer"},
        {{"cn", "ws01"}, {"servicePrincipalName", "HOST/ws01"}}};
    assert(first_state.create_directory_object(computer, "machine-secret", "tester"));
    const auto directory_with_computer = first_state.directory_objects();
    const auto computer_object = std::find_if(
        directory_with_computer.begin(),
        directory_with_computer.end(),
        [](const auto& object) { return object.dn == "cn=ws01,cn=Computers,dc=endorium,dc=local"; });
    assert(computer_object != directory_with_computer.end());
    assert(computer_object->attributes.at("sAMAccountName") == "ws01$");
    assert(computer_object->attributes.at("primaryGroupID") == "515");
    assert(computer_object->attributes.at("groupRids") == "515");
    assert(computer_object->attributes.at("userAccountControl") == "4096");
    assert(computer_object->attributes.at("accountExpires") == "9223372036854775807");
    assert(computer_object->attributes.at("badPwdCount") == "0");
    assert(computer_object->attributes.at("logonCount") == "0");
    assert(computer_object->attributes.at("msDS-SupportedEncryptionTypes") == "28");
    assert(computer_object->attributes.at("pwdLastSet") != "0");
    assert(computer_object->attributes.at("dNSHostName") == "ws01.endorium.local");
    assert(computer_object->attributes.at("servicePrincipalName").find("HOST/ws01,") != std::string::npos);
    assert(computer_object->attributes.at("servicePrincipalName").find("RestrictedKrbHost/ws01") != std::string::npos);
    assert(computer_object->attributes.at("servicePrincipalName").find("LDAP/ws01.endorium.local") != std::string::npos);
    assert(computer_object->attributes.at("servicePrincipalName").find("CIFS/ws01.endorium.local") != std::string::npos);
    assert(first_state.delete_directory_object("cn=ws01,cn=Computers,dc=endorium,dc=local", "tester"));
    assert(!first_state.create_directory_object({"not-a-dn", "", "user", {"person"}, {}}, "", "tester"));
    user.attributes["mail"] = "alice@endorium.local";
    assert(first_state.update_directory_object("uid=alice,ou=People,dc=endorium,dc=local", user, "", "tester"));
    assert(first_state.delete_directory_object("uid=alice,ou=People,dc=endorium,dc=local", "tester"));
    assert(!first_state.delete_directory_object("uid=missing,dc=endorium,dc=local", "tester"));

    assert(first_state.create_pki_authority("root-ca", {"Endorium Root CA", "Endorium", {"ca.endorium.local"}}, 3650, "tester"));
    assert(first_state.pki_authorities().size() == 1);
    assert(first_state.issue_pki_certificate("root-ca", {"api.endorium.local", "Endorium", {"api.endorium.local"}}, 365, "tester"));
    auto issued_certs = first_state.pki_certificates();
    assert(issued_certs.size() == 1);
    assert(issued_certs[0].certificate_pem.find("BEGIN CERTIFICATE") != std::string::npos);
    assert(first_state.revoke_certificate(issued_certs[0].serial_hex, issued_certs[0].common_name, "cessationOfOperation", "tester"));
    assert(first_state.pki_revocations().size() == 1);
    assert(!first_state.revoke_certificate(issued_certs[0].serial_hex, issued_certs[0].common_name, "cessationOfOperation", "tester"));

    assert(first_state.create_apt_repository("bookworm", "main", "tester"));
    core::AptPackage persisted_agent_package;
    persisted_agent_package.name = "endorium-agent";
    persisted_agent_package.version = "0.1.0";
    persisted_agent_package.architecture = "amd64";
    persisted_agent_package.component = "main";
    persisted_agent_package.filename = "pool/main/e/endorium-agent_0.1.0_amd64.deb";
    persisted_agent_package.storage_path = persisted_agent_package.filename;
    persisted_agent_package.sha256 = "abc123";
    persisted_agent_package.size = 12345;
    assert(first_state.add_apt_package(
        "bookworm",
        "main",
        persisted_agent_package,
        "tester"));
    auto replacement_agent_package = persisted_agent_package;
    replacement_agent_package.sha256 = "def456";
    replacement_agent_package.size = 23456;
    assert(first_state.add_apt_package(
        "bookworm",
        "main",
        replacement_agent_package,
        "tester"));
    const auto repositories_after_replacement = first_state.apt_repositories();
    assert(repositories_after_replacement.size() == 1);
    assert(repositories_after_replacement[0].packages.size() == 1);
    assert(repositories_after_replacement[0].packages[0].sha256 == "def456");
    const auto rendered_packages = first_state.render_apt_packages("bookworm", "main");
    const auto rendered_release = first_state.render_apt_release("bookworm", "main");
    assert(rendered_packages.has_value());
    assert(rendered_packages->find("Package: endorium-agent") != std::string::npos);
    assert(rendered_release.has_value());
    assert(rendered_release->find("Codename: bookworm") != std::string::npos);
    assert(first_state.delete_apt_package("bookworm", "main", 0, "tester"));
    assert(first_state.delete_apt_repository("bookworm", "main", "tester"));

    auto updated = config;
    updated.domain = "control.endorium.local";
    updated.ad_port_profile = "standard";
    updated.http.port = 18080;
    updated.gc.port = 18326;
    updated.kpasswd.port = 18464;
    updated.directory.base_dn = "dc=control,dc=endorium,dc=local";
    updated.directory.site_name = "Paris";
    updated.directory.domain_controller_host = "dc9";
    updated.directory.domain_controller_address = "10.10.10.9";
    updated.sql_migrations_dir = state_root / "sql-migrations";
    updated.pki.common_name = "Control Root CA";
    updated.repo.distribution = "trixie";
    assert(first_state.update_settings(updated, "tester"));

    const auto settings_file = state_root / "settings.json";
    assert(std::filesystem::exists(settings_file));

    nexus::api::PlatformState second_state(config);
    assert(second_state.config().domain == "control.endorium.local");
    assert(second_state.config().ad_port_profile == "standard");
    assert(second_state.config().http.port == 18080);
    assert(second_state.config().gc.port == 18326);
    assert(second_state.config().kpasswd.port == 18464);
    assert(second_state.config().state_root == state_root);
    assert(second_state.config().directory.base_dn == "dc=control,dc=endorium,dc=local");
    assert(second_state.config().directory.site_name == "Paris");
    assert(second_state.config().directory.domain_controller_host == "dc9");
    assert(second_state.config().directory.domain_controller_address == "10.10.10.9");
    assert(second_state.config().sql_migrations_dir == state_root / "sql-migrations");
    assert(second_state.config().pki.common_name == "Control Root CA");
    assert(second_state.config().repo.distribution == "trixie");

    std::filesystem::remove_all(state_root);

    test_writable_sysvol_gpo();
    return 0;
}
