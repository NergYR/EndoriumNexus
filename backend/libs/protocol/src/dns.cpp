#include "nexus/protocol/dns.hpp"

#include <algorithm>
#include <array>
#include <cctype>
#include <charconv>
#include <sstream>
#include <system_error>

namespace nexus::protocol {

namespace {

constexpr std::uint16_t dns_type_a = 1;
constexpr std::uint16_t dns_type_ns = 2;
constexpr std::uint16_t dns_type_cname = 5;
constexpr std::uint16_t dns_type_soa = 6;
constexpr std::uint16_t dns_type_txt = 16;
constexpr std::uint16_t dns_type_aaaa = 28;
constexpr std::uint16_t dns_type_srv = 33;
constexpr std::uint16_t dns_type_any = 255;
constexpr std::uint16_t dns_class_in = 1;

struct DnsQuestion {
    std::string name;
    std::uint16_t type{0};
    std::uint16_t qclass{0};
    std::size_t end_offset{0};
};

std::string quoted_dns_text(const std::string& value) {
    if (!value.empty() && value.front() == '"') {
        return value;
    }
    return "\"" + value + "\"";
}

std::string lowercase_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string trim_trailing_dot(std::string value) {
    while (!value.empty() && value.back() == '.') {
        value.pop_back();
    }
    return value;
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& bytes, std::size_t offset) {
    return static_cast<std::uint16_t>((bytes[offset] << 8U) | bytes[offset + 1]);
}

void write_u16(std::vector<std::uint8_t>& bytes, std::uint16_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

void write_u32(std::vector<std::uint8_t>& bytes, std::uint32_t value) {
    bytes.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    bytes.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    bytes.push_back(static_cast<std::uint8_t>(value & 0xffU));
}

bool read_dns_name(const std::vector<std::uint8_t>& bytes, std::size_t& offset, std::string& name, int depth = 0) {
    if (depth > 8) {
        return false;
    }

    std::string output;
    while (offset < bytes.size()) {
        const auto length = bytes[offset++];
        if (length == 0) {
            name = output.empty() ? "." : output;
            return true;
        }

        if ((length & 0xc0U) == 0xc0U) {
            if (offset >= bytes.size()) {
                return false;
            }
            std::size_t pointer = static_cast<std::size_t>(((length & 0x3fU) << 8U) | bytes[offset++]);
            std::string pointed;
            if (!read_dns_name(bytes, pointer, pointed, depth + 1)) {
                return false;
            }
            if (!output.empty() && pointed != ".") {
                output += ".";
            }
            if (pointed != ".") {
                output += pointed;
            }
            name = output.empty() ? "." : output;
            return true;
        }

        if ((length & 0xc0U) != 0 || offset + length > bytes.size()) {
            return false;
        }

        if (!output.empty()) {
            output += ".";
        }
        output.append(reinterpret_cast<const char*>(bytes.data() + offset), length);
        offset += length;
    }

    return false;
}

void write_dns_name(std::vector<std::uint8_t>& bytes, const std::string& name) {
    const auto normalized = trim_trailing_dot(name);
    if (normalized.empty() || normalized == "@") {
        bytes.push_back(0);
        return;
    }

    std::size_t start = 0;
    while (start < normalized.size()) {
        const auto dot = normalized.find('.', start);
        const auto end = dot == std::string::npos ? normalized.size() : dot;
        const auto label_size = end - start;
        if (label_size > 63) {
            bytes.push_back(0);
            return;
        }
        bytes.push_back(static_cast<std::uint8_t>(label_size));
        bytes.insert(
            bytes.end(),
            normalized.begin() + static_cast<std::ptrdiff_t>(start),
            normalized.begin() + static_cast<std::ptrdiff_t>(end));
        if (dot == std::string::npos) {
            break;
        }
        start = dot + 1;
    }
    bytes.push_back(0);
}

bool parse_question(const std::vector<std::uint8_t>& query, DnsQuestion& question) {
    if (query.size() < 12 || read_u16(query, 4) == 0) {
        return false;
    }

    std::size_t offset = 12;
    if (!read_dns_name(query, offset, question.name) || offset + 4 > query.size()) {
        return false;
    }
    question.name = lowercase_ascii(trim_trailing_dot(question.name));
    question.type = read_u16(query, offset);
    question.qclass = read_u16(query, offset + 2);
    question.end_offset = offset + 4;
    return true;
}

std::uint16_t type_code(const std::string& type) {
    const auto normalized = lowercase_ascii(type);
    if (normalized == "a") return dns_type_a;
    if (normalized == "ns") return dns_type_ns;
    if (normalized == "cname") return dns_type_cname;
    if (normalized == "soa") return dns_type_soa;
    if (normalized == "txt") return dns_type_txt;
    if (normalized == "aaaa") return dns_type_aaaa;
    if (normalized == "srv") return dns_type_srv;
    return 0;
}

std::string record_fqdn(const nexus::core::DnsZone& zone, const nexus::core::DnsRecord& record) {
    if (record.name == "@" || record.name.empty()) {
        return lowercase_ascii(trim_trailing_dot(zone.name));
    }
    const auto name = lowercase_ascii(trim_trailing_dot(record.name));
    const auto zone_name = lowercase_ascii(trim_trailing_dot(zone.name));
    if (name == zone_name || (name.size() > zone_name.size() && name.ends_with("." + zone_name))) {
        return name;
    }
    return name + "." + zone_name;
}

std::array<std::uint8_t, 4> ipv4_bytes(const std::string& value, bool& ok) {
    std::array<std::uint8_t, 4> result{};
    std::size_t start = 0;
    for (std::size_t index = 0; index < result.size(); ++index) {
        const auto dot = value.find('.', start);
        const auto end = dot == std::string::npos ? value.size() : dot;
        int part = 0;
        const auto* begin = value.data() + start;
        const auto* finish = value.data() + end;
        const auto parsed = std::from_chars(begin, finish, part);
        if (parsed.ec != std::errc{} || parsed.ptr != finish || part < 0 || part > 255) {
            ok = false;
            return result;
        }
        result[index] = static_cast<std::uint8_t>(part);
        start = end + 1;
        if (index < result.size() - 1 && dot == std::string::npos) {
            ok = false;
            return result;
        }
    }
    ok = true;
    return result;
}

void append_record_data(std::vector<std::uint8_t>& response, const nexus::core::DnsRecord& record) {
    if (record.type == "A") {
        bool ok = false;
        const auto parts = ipv4_bytes(record.value, ok);
        if (ok) {
            response.insert(response.end(), parts.begin(), parts.end());
        }
        return;
    }

    if (record.type == "SRV") {
        write_u16(response, record.priority);
        write_u16(response, record.weight);
        write_u16(response, record.port);
        write_dns_name(response, record.value);
        return;
    }

    if (record.type == "NS" || record.type == "CNAME") {
        write_dns_name(response, record.value);
        return;
    }

    if (record.type == "TXT") {
        const auto size = std::min<std::size_t>(record.value.size(), 255);
        response.push_back(static_cast<std::uint8_t>(size));
        response.insert(response.end(), record.value.begin(), record.value.begin() + static_cast<std::ptrdiff_t>(size));
    }
}

bool matches_question(const DnsQuestion& question, const nexus::core::DnsZone& zone, const nexus::core::DnsRecord& record) {
    const auto record_type = type_code(record.type);
    if (record_type == 0) {
        return false;
    }
    const bool type_matches = question.type == dns_type_any || question.type == record_type;
    const bool class_matches = question.qclass == dns_class_in || question.qclass == dns_type_any;
    return type_matches && class_matches && question.name == record_fqdn(zone, record);
}

std::vector<nexus::core::DnsRecord> matching_records(const DnsQuestion& question, const std::vector<nexus::core::DnsZone>& zones) {
    std::vector<nexus::core::DnsRecord> records;
    for (const auto& zone : zones) {
        for (const auto& record : zone.records) {
            if (matches_question(question, zone, record)) {
                records.push_back(record);
            }
        }
    }
    return records;
}

}  // namespace

std::string render_zone_file(
    const nexus::core::DnsZone& zone,
    const std::string& primary_ns,
    const std::string& admin_mailbox) {
    std::ostringstream output;
    output << "$ORIGIN " << zone.name << ".\n";
    output << "$TTL 3600\n";
    output << "@ IN SOA " << primary_ns << ". " << admin_mailbox << ". (\n";
    output << "  " << zone.serial << " ; serial\n";
    output << "  3600 ; refresh\n";
    output << "  600 ; retry\n";
    output << "  604800 ; expire\n";
    output << "  300 ; minimum\n";
    output << ")\n";

    for (const auto& record : zone.records) {
        output << record.name << " " << record.ttl << " IN " << record.type << " ";
        if (record.type == "SRV") {
            output << record.priority << " " << record.weight << " " << record.port << " ";
        } else if (record.type == "MX") {
            output << record.priority << " ";
        } else if (record.type == "CAA") {
            output << record.priority << " " << record.flags << " " << quoted_dns_text(record.value) << "\n";
            continue;
        }
        output << record.value << "\n";
    }

    return output.str();
}

nexus::core::DnsZone make_active_directory_dns_zone(const ActiveDirectoryDnsConfig& config) {
    const auto dns_name = trim_trailing_dot(config.dns_name);
    const auto site_name = config.site_name.empty() ? "Default-First-Site-Name" : config.site_name;
    const auto dc_host = config.domain_controller_host.empty() ? "dc1" : config.domain_controller_host;
    const auto dc_address = config.domain_controller_address.empty() ? "127.0.0.1" : config.domain_controller_address;
    const auto dc_target = dc_host + "." + dns_name + ".";

    std::vector<nexus::core::DnsRecord> records{
        {"@", "NS", dc_target, "IN", 3600, 0, 0, 0, ""},
        {dc_host, "A", dc_address, "IN", 300, 0, 0, 0, ""},
        {"_ldap._tcp", "SRV", dc_target, "IN", 300, 0, 100, config.ldap_port, ""},
        {"_ldap._tcp.dc._msdcs", "SRV", dc_target, "IN", 300, 0, 100, config.ldap_port, ""},
        {"_ldap._tcp." + site_name + "._sites", "SRV", dc_target, "IN", 300, 0, 100, config.ldap_port, ""},
        {"_ldap._tcp." + site_name + "._sites.dc._msdcs", "SRV", dc_target, "IN", 300, 0, 100, config.ldap_port, ""},
        {"_kerberos._tcp", "SRV", dc_target, "IN", 300, 0, 100, config.kerberos_port, ""},
        {"_kerberos._udp", "SRV", dc_target, "IN", 300, 0, 100, config.kerberos_port, ""},
        {"_kerberos._tcp." + site_name + "._sites", "SRV", dc_target, "IN", 300, 0, 100, config.kerberos_port, ""},
        {"_kpasswd._tcp", "SRV", dc_target, "IN", 300, 0, 100, config.kpasswd_port, ""},
        {"_kpasswd._udp", "SRV", dc_target, "IN", 300, 0, 100, config.kpasswd_port, ""},
        {"_gc._tcp", "SRV", dc_target, "IN", 300, 0, 100, config.global_catalog_port, ""},
        {"_gc._tcp." + site_name + "._sites", "SRV", dc_target, "IN", 300, 0, 100, config.global_catalog_port, ""},
        {"_ldap._tcp.gc._msdcs", "SRV", dc_target, "IN", 300, 0, 100, config.global_catalog_port, ""},
    };

    return {dns_name, 1, std::move(records)};
}

std::vector<std::uint8_t> resolve_dns_query(
    const std::vector<std::uint8_t>& query,
    const std::vector<nexus::core::DnsZone>& zones) {
    if (query.size() < 12) {
        return {};
    }

    DnsQuestion question;
    const auto transaction_id = read_u16(query, 0);
    if (!parse_question(query, question)) {
        std::vector<std::uint8_t> response;
        write_u16(response, transaction_id);
        write_u16(response, 0x8181);
        write_u16(response, 0);
        write_u16(response, 0);
        write_u16(response, 0);
        write_u16(response, 0);
        return response;
    }

    const auto answers = matching_records(question, zones);
    std::vector<std::uint8_t> response;
    write_u16(response, transaction_id);
    write_u16(response, 0x8180);
    write_u16(response, 1);
    write_u16(response, static_cast<std::uint16_t>(answers.size()));
    write_u16(response, 0);
    write_u16(response, 0);
    response.insert(response.end(), query.begin() + 12, query.begin() + static_cast<std::ptrdiff_t>(question.end_offset));

    for (const auto& answer : answers) {
        write_dns_name(response, question.name);
        write_u16(response, type_code(answer.type));
        write_u16(response, dns_class_in);
        write_u32(response, answer.ttl);
        const auto rdlength_offset = response.size();
        write_u16(response, 0);
        const auto rdata_start = response.size();
        append_record_data(response, answer);
        const auto rdata_size = response.size() - rdata_start;
        response[rdlength_offset] = static_cast<std::uint8_t>((rdata_size >> 8U) & 0xffU);
        response[rdlength_offset + 1] = static_cast<std::uint8_t>(rdata_size & 0xffU);
    }

    return response;
}

std::vector<std::uint8_t> resolve_dns_tcp_query(
    const std::vector<std::uint8_t>& frame,
    const std::vector<nexus::core::DnsZone>& zones) {
    if (frame.size() < 2) {
        return {};
    }
    const auto expected_size = read_u16(frame, 0);
    if (expected_size == 0 || frame.size() < static_cast<std::size_t>(expected_size) + 2) {
        return {};
    }

    std::vector<std::uint8_t> query(frame.begin() + 2, frame.begin() + 2 + expected_size);
    auto response = resolve_dns_query(query, zones);
    if (response.empty()) {
        return {};
    }

    std::vector<std::uint8_t> framed;
    write_u16(framed, static_cast<std::uint16_t>(response.size()));
    framed.insert(framed.end(), response.begin(), response.end());
    return framed;
}

}  // namespace nexus::protocol
