#include "nexus/protocol/dns.hpp"

#include <sstream>

namespace nexus::protocol {

namespace {

std::string quoted_dns_text(const std::string& value) {
    if (!value.empty() && value.front() == '"') {
        return value;
    }
    return "\"" + value + "\"";
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

}  // namespace nexus::protocol
