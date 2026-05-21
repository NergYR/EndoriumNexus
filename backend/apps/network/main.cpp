#include "nexus/core/config.hpp"
#include "nexus/core/uv_runtime.hpp"
#include "nexus/protocol/dns.hpp"

#include <libpq-fe.h>

#include <algorithm>
#include <iostream>
#include <string>
#include <vector>

namespace {

nexus::core::DnsZone fallback_ad_zone(const nexus::core::Config& config) {
    return nexus::protocol::make_active_directory_dns_zone({
        config.domain,
        config.directory.site_name,
        config.directory.domain_controller_host,
        config.directory.domain_controller_address,
        static_cast<std::uint16_t>(config.ldap.port),
        static_cast<std::uint16_t>(config.kerberos.port),
        static_cast<std::uint16_t>(config.kpasswd.port),
        static_cast<std::uint16_t>(config.global_catalog.port),
    });
}

std::vector<nexus::core::DnsZone> load_dns_zones(const nexus::core::Config& config) {
    if (config.database_url.empty()) {
        return {fallback_ad_zone(config)};
    }

    PGconn* conn = PQconnectdb(config.database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "[nexus-network] database unavailable; serving synthetic AD DNS zone\n";
        PQfinish(conn);
        return {fallback_ad_zone(config)};
    }

    PGresult* zones_result = PQexec(conn, "select name, serial from dns_zones order by name");
    if (PQresultStatus(zones_result) != PGRES_TUPLES_OK) {
        PQclear(zones_result);
        PQfinish(conn);
        return {fallback_ad_zone(config)};
    }

    std::vector<nexus::core::DnsZone> zones;
    for (int index = 0; index < PQntuples(zones_result); ++index) {
        zones.push_back({
            PQgetvalue(zones_result, index, 0),
            static_cast<std::uint64_t>(std::stoull(PQgetvalue(zones_result, index, 1))),
            {},
        });
    }
    PQclear(zones_result);

    PGresult* records_result = PQexec(
        conn,
        "select zone_name,name,type,value,ttl,priority,coalesce(weight,0),coalesce(port,0),coalesce(flags,''),coalesce(dns_class,'IN') "
        "from dns_records order by zone_name,id");
    if (PQresultStatus(records_result) == PGRES_TUPLES_OK) {
        for (int index = 0; index < PQntuples(records_result); ++index) {
            const std::string zone_name = PQgetvalue(records_result, index, 0);
            auto zone = std::find_if(zones.begin(), zones.end(), [&](const auto& candidate) {
                return candidate.name == zone_name;
            });
            if (zone == zones.end()) {
                continue;
            }
            zone->records.push_back({
                PQgetvalue(records_result, index, 1),
                PQgetvalue(records_result, index, 2),
                PQgetvalue(records_result, index, 3),
                PQgetvalue(records_result, index, 9),
                static_cast<std::uint32_t>(std::stoul(PQgetvalue(records_result, index, 4))),
                static_cast<std::uint16_t>(std::stoul(PQgetvalue(records_result, index, 5))),
                static_cast<std::uint16_t>(std::stoul(PQgetvalue(records_result, index, 6))),
                static_cast<std::uint16_t>(std::stoul(PQgetvalue(records_result, index, 7))),
                PQgetvalue(records_result, index, 8),
            });
        }
    }
    PQclear(records_result);
    PQfinish(conn);

    if (zones.empty()) {
        zones.push_back(fallback_ad_zone(config));
    }
    return zones;
}

}  // namespace

int main() {
    const auto config = nexus::core::Config::from_env();
    auto zones = load_dns_zones(config);

    auto dns_udp = [zones](const std::string&, const nexus::core::UvPacket& packet) {
        return nexus::protocol::resolve_dns_query(packet, zones);
    };
    auto dns_tcp = [zones](const std::string&, const nexus::core::UvPacket& packet) {
        return nexus::protocol::resolve_dns_tcp_query(packet, zones);
    };

    return nexus::core::run_uv_daemon(
        "network",
        {
            {"dns-tcp", config.dns_tcp.host, config.dns_tcp.port, nexus::core::UvTransport::tcp, dns_tcp},
            {"dns-udp", config.dns_udp.host, config.dns_udp.port, nexus::core::UvTransport::udp, dns_udp},
            {"dhcp-udp", config.dhcp.host, config.dhcp.port, nexus::core::UvTransport::udp},
        });
}
