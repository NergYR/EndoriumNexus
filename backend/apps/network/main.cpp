#include "nexus/core/config.hpp"
#include "nexus/core/uv_runtime.hpp"
#include "nexus/protocol/dns.hpp"

#include <libpq-fe.h>

#include <algorithm>
#include <cctype>
#include <memory>
#include <mutex>
#include <iostream>
#include <optional>
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
        static_cast<std::uint16_t>(config.gc.port),
    });
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

std::string sql_literal(PGconn* connection, const std::string& value) {
    char* escaped = PQescapeLiteral(connection, value.c_str(), static_cast<unsigned long>(value.size()));
    if (escaped == nullptr) {
        return "''";
    }
    std::string result(escaped);
    PQfreemem(escaped);
    return result;
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

    nexus::protocol::merge_active_directory_dns_zone(zones, fallback_ad_zone(config));
    return zones;
}

bool dns_records_match_for_delete(
    const nexus::core::DnsRecord& candidate,
    const nexus::core::DnsRecord& requested,
    bool delete_rrset) {
    if (lowercase_ascii(trim_trailing_dot(candidate.name)) != lowercase_ascii(trim_trailing_dot(requested.name))) {
        return false;
    }
    const auto requested_type = lowercase_ascii(requested.type);
    if (requested_type != "any" && lowercase_ascii(candidate.type) != requested_type) {
        return false;
    }
    if (delete_rrset || requested.value.empty()) {
        return true;
    }
    return lowercase_ascii(trim_trailing_dot(candidate.value)) == lowercase_ascii(trim_trailing_dot(requested.value));
}

void apply_dns_dynamic_update_to_memory(
    std::vector<nexus::core::DnsZone>& zones,
    const nexus::protocol::DnsDynamicUpdate& update) {
    if (!update.valid || !update.authorized || update.zone_name.empty()) {
        return;
    }

    auto zone = std::find_if(zones.begin(), zones.end(), [&](const auto& candidate) {
        return lowercase_ascii(trim_trailing_dot(candidate.name)) == lowercase_ascii(trim_trailing_dot(update.zone_name));
    });
    if (zone == zones.end()) {
        zones.push_back({update.zone_name, 1, {}});
        zone = std::prev(zones.end());
    }

    bool changed = false;
    for (const auto& entry : update.records) {
        auto& records = zone->records;
        const auto old_size = records.size();
        records.erase(
            std::remove_if(records.begin(), records.end(), [&](const auto& candidate) {
                return dns_records_match_for_delete(candidate, entry.record, entry.delete_rrset || !entry.deletion);
            }),
            records.end());
        changed = changed || records.size() != old_size;
        if (!entry.deletion && !entry.record.value.empty()) {
            records.push_back(entry.record);
            changed = true;
        }
    }
    if (changed) {
        ++zone->serial;
    }
}

bool persist_dns_dynamic_update(
    const nexus::core::Config& config,
    const nexus::protocol::DnsDynamicUpdate& update) {
    if (config.database_url.empty() || !update.valid || !update.authorized || update.zone_name.empty()) {
        return true;
    }

    PGconn* conn = PQconnectdb(config.database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "[nexus-network] database unavailable; DNS UPDATE was applied in-memory only\n";
        PQfinish(conn);
        return false;
    }

    const std::string zone_sql =
        "insert into dns_zones(name,serial,updated_at) values (" +
        sql_literal(conn, update.zone_name) + ",1,now()) "
        "on conflict (name) do update set serial=dns_zones.serial+1, updated_at=now();";
    PGresult* zone_result = PQexec(conn, zone_sql.c_str());
    bool ok = PQresultStatus(zone_result) == PGRES_COMMAND_OK;
    if (!ok) {
        std::cerr << "[nexus-network] failed to upsert DNS UPDATE zone: "
                  << PQresultErrorMessage(zone_result) << '\n';
    }
    PQclear(zone_result);

    for (const auto& entry : update.records) {
        if (!ok) {
            break;
        }
        const auto& record = entry.record;
        std::string delete_sql =
            "delete from dns_records where zone_name = " + sql_literal(conn, update.zone_name) +
            " and lower(name) = lower(" + sql_literal(conn, record.name) + ")";
        if (lowercase_ascii(record.type) != "any") {
            delete_sql += " and lower(type) = lower(" + sql_literal(conn, record.type) + ")";
        }
        if (entry.deletion && !entry.delete_rrset && !record.value.empty()) {
            delete_sql += " and lower(value) = lower(" + sql_literal(conn, record.value) + ")";
        }
        delete_sql += ";";
        PGresult* delete_result = PQexec(conn, delete_sql.c_str());
        ok = PQresultStatus(delete_result) == PGRES_COMMAND_OK;
        if (!ok) {
            std::cerr << "[nexus-network] failed to delete DNS UPDATE record: "
                      << PQresultErrorMessage(delete_result) << '\n';
        }
        PQclear(delete_result);
        if (!ok || entry.deletion || record.value.empty()) {
            continue;
        }

        const std::string insert_sql =
            "insert into dns_records(zone_name,name,type,value,ttl,priority,weight,port,flags,dns_class) values (" +
            sql_literal(conn, update.zone_name) + "," +
            sql_literal(conn, record.name) + "," +
            sql_literal(conn, record.type) + "," +
            sql_literal(conn, record.value) + "," +
            std::to_string(record.ttl) + "," +
            std::to_string(record.priority) + "," +
            std::to_string(record.weight) + "," +
            std::to_string(record.port) + "," +
            sql_literal(conn, record.flags) + "," +
            sql_literal(conn, record.dns_class.empty() ? "IN" : record.dns_class) + ");";
        PGresult* insert_result = PQexec(conn, insert_sql.c_str());
        ok = PQresultStatus(insert_result) == PGRES_COMMAND_OK;
        if (!ok) {
            std::cerr << "[nexus-network] failed to insert DNS UPDATE record: "
                      << PQresultErrorMessage(insert_result) << '\n';
        }
        PQclear(insert_result);
    }

    PQfinish(conn);
    return ok;
}

std::optional<std::vector<std::uint8_t>> dns_tcp_payload(const std::vector<std::uint8_t>& frame) {
    if (frame.size() < 2) {
        return std::nullopt;
    }
    const auto expected_size =
        (static_cast<std::size_t>(frame[0]) << 8U) | static_cast<std::size_t>(frame[1]);
    if (frame.size() < expected_size + 2) {
        return std::nullopt;
    }
    return std::vector<std::uint8_t>(frame.begin() + 2, frame.begin() + 2 + static_cast<std::ptrdiff_t>(expected_size));
}

}  // namespace

int main() {
    const auto config = nexus::core::Config::from_env();
    auto zones = std::make_shared<std::vector<nexus::core::DnsZone>>(load_dns_zones(config));
    auto zones_mutex = std::make_shared<std::mutex>();

    auto dns_udp = [config, zones, zones_mutex](const std::string&, const nexus::core::UvPacket& packet) {
        std::scoped_lock lock(*zones_mutex);
        const auto update = nexus::protocol::parse_dns_dynamic_update(packet, *zones);
        if (update.is_update && update.valid && update.authorized && !update.records.empty()) {
            persist_dns_dynamic_update(config, update);
            apply_dns_dynamic_update_to_memory(*zones, update);
        }
        return nexus::protocol::resolve_dns_query(packet, *zones);
    };
    auto dns_tcp = [config, zones, zones_mutex](const std::string&, const nexus::core::UvPacket& packet) {
        std::scoped_lock lock(*zones_mutex);
        const auto payload = dns_tcp_payload(packet);
        if (payload.has_value()) {
            const auto update = nexus::protocol::parse_dns_dynamic_update(*payload, *zones);
            if (update.is_update && update.valid && update.authorized && !update.records.empty()) {
                persist_dns_dynamic_update(config, update);
                apply_dns_dynamic_update_to_memory(*zones, update);
            }
        }
        return nexus::protocol::resolve_dns_tcp_query(packet, *zones);
    };

    return nexus::core::run_uv_daemon(
        "network",
        {
            {"dns-tcp", config.dns_tcp.host, config.dns_tcp.port, nexus::core::UvTransport::tcp, dns_tcp},
            {"dns-udp", config.dns_udp.host, config.dns_udp.port, nexus::core::UvTransport::udp, dns_udp},
            {"dhcp-udp", config.dhcp.host, config.dhcp.port, nexus::core::UvTransport::udp},
        });
}
