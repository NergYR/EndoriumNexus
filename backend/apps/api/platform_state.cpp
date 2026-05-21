#include "platform_state.hpp"

#include "nexus/core/time.hpp"
#include "nexus/protocol/dns.hpp"
#include "nexus/protocol/ldap.hpp"
#include "nexus/protocol/repo.hpp"

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <libpq-fe.h>

#include <algorithm>
#include <cctype>
#include <cstdint>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <numeric>
#include <system_error>
#include <sstream>

namespace nexus::api {

namespace {

PGconn* connect_database(const std::string& connection_string) {
    if (connection_string.empty()) {
        return nullptr;
    }

    PGconn* connection = PQconnectdb(connection_string.c_str());
    if (PQstatus(connection) != CONNECTION_OK) {
        PQfinish(connection);
        return nullptr;
    }
    return connection;
}

bool ensure_feature_flags_table(PGconn* connection) {
    const char* sql = R"SQL(
        create table if not exists feature_flags (
            service_id text primary key,
            enabled boolean not null,
            updated_at timestamptz not null default now()
        )
    )SQL";
    PGresult* result = PQexec(connection, sql);
    const bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    PQclear(result);
    return ok;
}

std::map<std::string, bool> feature_flag_defaults(const nexus::core::Config& config) {
    std::map<std::string, bool> flags;
    for (const auto& service : nexus::core::service_definitions()) {
        if (service.feature_flag.empty()) {
            continue;
        }
        const auto it = config.features.find(service.feature_flag);
        flags[service.feature_flag] = it != config.features.end() && it->second;
    }
    return flags;
}

std::string get_service_blocking_reason(const std::string& service_id, const std::string& database_url) {
    if (database_url.empty()) {
        return "database not configured";
    }

    PGconn* conn = PQconnectdb(database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        PQfinish(conn);
        return "database connection failed";
    }

    std::string reason;

    if (service_id == "network") {
        // Network service needs at least one DNS zone and one DHCP pool
        PGresult* zones_result = PQexec(conn, "SELECT COUNT(*) FROM dns_zones");
        PGresult* pools_result = PQexec(conn, "SELECT COUNT(*) FROM dhcp_pools");

        if (PQresultStatus(zones_result) == PGRES_TUPLES_OK && PQresultStatus(pools_result) == PGRES_TUPLES_OK) {
            try {
                const int zone_count = std::stoi(PQgetvalue(zones_result, 0, 0));
                const int pool_count = std::stoi(PQgetvalue(pools_result, 0, 0));

                if (zone_count == 0 || pool_count == 0) {
                    reason = "Requires ≥1 DNS zone (" + std::to_string(zone_count) + " found) and ≥1 DHCP pool (" + std::to_string(pool_count) + " found)";
                }
            } catch (...) {
                reason = "Cannot verify prerequisites";
            }
        }

        PQclear(zones_result);
        PQclear(pools_result);
    } else if (service_id == "pki-repo") {
        // PKI repository needs at least one certificate authority
        PGresult* authorities_result = PQexec(conn, "SELECT COUNT(*) FROM pki_authorities");

        if (PQresultStatus(authorities_result) == PGRES_TUPLES_OK) {
            try {
                const int authority_count = std::stoi(PQgetvalue(authorities_result, 0, 0));

                if (authority_count == 0) {
                    reason = "Requires ≥1 PKI authority (0 found)";
                }
            } catch (...) {
                reason = "Cannot verify prerequisites";
            }
        }

        PQclear(authorities_result);
    }
    // directory and other services have no special prerequisites

    PQfinish(conn);
    return reason;  // Empty string means no blocking reason
}

bool persist_dhcp_pool_to_database(const nexus::core::DhcpPool& pool, const std::string& database_url, std::string* out_err) {
    if (database_url.empty()) {
        if (out_err) *out_err = "database not configured";
        return false;
    }

    PGconn* conn = PQconnectdb(database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        if (out_err) *out_err = "database connection failed";
        PQfinish(conn);
        return false;
    }

    // Build options JSON
    std::string options_json = "{";
    bool first = true;
    for (const auto& [k, v] : pool.options) {
        if (!first) options_json += ",";
        first = false;
        // naive JSON escaping for keys/values (quotes/backslashes)
        auto escape = [](const std::string& s){
            std::string out;
            for (char c : s) {
                if (c == '\\' || c == '"') {
                    out.push_back('\\');
                    out.push_back(c);
                } else if (c == '\n') {
                    out += "\\n";
                } else {
                    out.push_back(c);
                }
            }
            return out;
        };
        options_json += "\"" + escape(k) + "\":\"" + escape(v) + "\"";
    }
    options_json += "}";

    // Escape literals using libpq
    char* name_esc = PQescapeLiteral(conn, pool.name.c_str(), static_cast<unsigned long>(pool.name.size()));
    char* subnet_esc = PQescapeLiteral(conn, pool.subnet.c_str(), static_cast<unsigned long>(pool.subnet.size()));
    char* start_esc = PQescapeLiteral(conn, pool.range_start.c_str(), static_cast<unsigned long>(pool.range_start.size()));
    char* end_esc = PQescapeLiteral(conn, pool.range_end.c_str(), static_cast<unsigned long>(pool.range_end.size()));
    char* opts_esc = PQescapeLiteral(conn, options_json.c_str(), static_cast<unsigned long>(options_json.size()));

    if (!name_esc || !subnet_esc || !start_esc || !end_esc || !opts_esc) {
        if (out_err) *out_err = "failed to escape SQL literals";
        if (name_esc) PQfreemem(name_esc);
        if (subnet_esc) PQfreemem(subnet_esc);
        if (start_esc) PQfreemem(start_esc);
        if (end_esc) PQfreemem(end_esc);
        if (opts_esc) PQfreemem(opts_esc);
        PQfinish(conn);
        return false;
    }

    std::string sql = "INSERT INTO dhcp_pools(name, subnet, range_start, range_end, options) VALUES (" +
                      std::string(name_esc) + "," + std::string(subnet_esc) + "," + std::string(start_esc) + "," + std::string(end_esc) + "," + std::string(opts_esc) + "::jsonb) ON CONFLICT (name) DO UPDATE SET subnet=excluded.subnet, range_start=excluded.range_start, range_end=excluded.range_end, options=excluded.options;";

    PGresult* res = PQexec(conn, sql.c_str());
    bool ok = PQresultStatus(res) == PGRES_COMMAND_OK;
    if (!ok && out_err) {
        *out_err = PQresultErrorMessage(res);
    }
    PQclear(res);

    PQfreemem(name_esc);
    PQfreemem(subnet_esc);
    PQfreemem(start_esc);
    PQfreemem(end_esc);
    PQfreemem(opts_esc);
    PQfinish(conn);
    return ok;
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

std::string json_string_array(const std::vector<std::string>& values) {
    Json::Value array(Json::arrayValue);
    for (const auto& value : values) {
        array.append(value);
    }
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    return Json::writeString(builder, array);
}

std::string json_string_object(const std::map<std::string, std::string>& values) {
    Json::Value object(Json::objectValue);
    for (const auto& [key, value] : values) {
        object[key] = value;
    }
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    return Json::writeString(builder, object);
}

std::string uppercase_ascii(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::toupper(ch));
    });
    return value;
}

std::string base_dn_from_dns_name(const std::string& dns_name) {
    std::stringstream stream(dns_name);
    std::string label;
    std::string base_dn;
    while (std::getline(stream, label, '.')) {
        if (label.empty()) {
            return "";
        }
        if (!base_dn.empty()) {
            base_dn += ",";
        }
        base_dn += "dc=" + label;
    }
    return base_dn;
}

bool is_valid_netbios_name(const std::string& value) {
    if (value.empty() || value.size() > 15) {
        return false;
    }
    return std::all_of(value.begin(), value.end(), [](unsigned char ch) {
        return std::isalnum(ch) || ch == '-';
    });
}

std::string random_domain_sid() {
    unsigned char bytes[12];
    RAND_bytes(bytes, sizeof(bytes));
    const auto part = [&](int offset) {
        std::uint32_t value = 0;
        value |= static_cast<std::uint32_t>(bytes[offset]) << 24;
        value |= static_cast<std::uint32_t>(bytes[offset + 1]) << 16;
        value |= static_cast<std::uint32_t>(bytes[offset + 2]) << 8;
        value |= static_cast<std::uint32_t>(bytes[offset + 3]);
        return value % 900000000U + 100000000U;
    };
    return "S-1-5-21-" + std::to_string(part(0)) + "-" + std::to_string(part(4)) + "-" + std::to_string(part(8));
}

std::string sha256_hex(const std::string& payload) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(reinterpret_cast<const unsigned char*>(payload.data()), payload.size(), digest);
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned char byte : digest) {
        output << std::setw(2) << static_cast<int>(byte);
    }
    return output.str();
}

void persist_active_directory_domain_to_database(
    const nexus::core::ActiveDirectoryDomain& domain,
    const std::string& domain_controller_host,
    const std::string& domain_controller_address,
    const std::string& site_name,
    const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const auto dc_address_sql = domain_controller_address.empty() ? "null" : sql_literal(conn, domain_controller_address);
    const std::string sql =
        "INSERT INTO ad_domains(dns_name,netbios_name,realm,base_dn,domain_sid,site_name,dc_host,dc_address,created_at) VALUES (" +
        sql_literal(conn, domain.dns_name) + "," +
        sql_literal(conn, domain.netbios_name) + "," +
        sql_literal(conn, domain.realm) + "," +
        sql_literal(conn, domain.base_dn) + "," +
        sql_literal(conn, domain.domain_sid) + "," +
        sql_literal(conn, site_name) + "," +
        sql_literal(conn, domain_controller_host) + "," +
        dc_address_sql + ",now()) "
        "ON CONFLICT (dns_name) DO UPDATE SET netbios_name=excluded.netbios_name, realm=excluded.realm, "
        "base_dn=excluded.base_dn, domain_sid=excluded.domain_sid, site_name=excluded.site_name, "
        "dc_host=excluded.dc_host, dc_address=excluded.dc_address;";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist active directory domain: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

std::optional<nexus::core::ActiveDirectoryDomain> load_active_directory_domain_from_database(const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return std::nullopt;
    }
    PGresult* result = PQexec(conn, "SELECT dns_name,netbios_name,realm,base_dn,domain_sid,created_at::text FROM ad_domains ORDER BY created_at DESC LIMIT 1;");
    if (PQresultStatus(result) != PGRES_TUPLES_OK || PQntuples(result) == 0) {
        PQclear(result);
        PQfinish(conn);
        return std::nullopt;
    }
    nexus::core::ActiveDirectoryDomain domain{
        PQgetvalue(result, 0, 0),
        PQgetvalue(result, 0, 1),
        PQgetvalue(result, 0, 2),
        PQgetvalue(result, 0, 3),
        PQgetvalue(result, 0, 4),
        PQgetvalue(result, 0, 5)};
    PQclear(result);
    PQfinish(conn);
    return domain;
}

void persist_directory_object_to_database(const nexus::core::DirectoryObject& object, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string sql =
        "INSERT INTO identity_objects(dn,parent_dn,kind,object_classes,attributes,updated_at) VALUES (" +
        sql_literal(conn, object.dn) + "," +
        sql_literal(conn, object.parent_dn) + "," +
        sql_literal(conn, object.kind) + "," +
        sql_literal(conn, json_string_array(object.object_classes)) + "::jsonb," +
        sql_literal(conn, json_string_object(object.attributes)) + "::jsonb,now()) "
        "ON CONFLICT (dn) DO UPDATE SET parent_dn=excluded.parent_dn, kind=excluded.kind, "
        "object_classes=excluded.object_classes, attributes=excluded.attributes, updated_at=now();";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist directory object: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

void delete_directory_object_from_database(const std::string& dn, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string sql = "DELETE FROM identity_objects WHERE dn = " + sql_literal(conn, dn) + ";";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to delete directory object: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

std::vector<std::string> json_array_from_string(const std::string& payload) {
    Json::CharReaderBuilder builder;
    Json::Value value;
    std::string errors;
    std::istringstream input(payload);
    std::vector<std::string> result;
    if (!Json::parseFromStream(builder, input, &value, &errors) || !value.isArray()) {
        return result;
    }
    for (const auto& entry : value) {
        result.push_back(entry.asString());
    }
    return result;
}

std::map<std::string, std::string> json_object_from_string(const std::string& payload) {
    Json::CharReaderBuilder builder;
    Json::Value value;
    std::string errors;
    std::istringstream input(payload);
    std::map<std::string, std::string> result;
    if (!Json::parseFromStream(builder, input, &value, &errors) || !value.isObject()) {
        return result;
    }
    for (const auto& key : value.getMemberNames()) {
        result[key] = value[key].asString();
    }
    return result;
}

std::vector<nexus::core::DirectoryObject> load_directory_objects_from_database(const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return {};
    }
    PGresult* result = PQexec(conn, "SELECT dn,parent_dn,kind,object_classes::text,attributes::text FROM identity_objects ORDER BY dn;");
    std::vector<nexus::core::DirectoryObject> objects;
    if (PQresultStatus(result) == PGRES_TUPLES_OK) {
        for (int index = 0; index < PQntuples(result); ++index) {
            objects.push_back({
                PQgetvalue(result, index, 0),
                PQgetvalue(result, index, 1),
                PQgetvalue(result, index, 2),
                json_array_from_string(PQgetvalue(result, index, 3)),
                json_object_from_string(PQgetvalue(result, index, 4)),
            });
        }
    }
    PQclear(result);
    PQfinish(conn);
    return objects;
}

void persist_dns_zone_to_database(const nexus::core::DnsZone& zone, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }

    PGresult* begin = PQexec(conn, "begin");
    if (PQresultStatus(begin) != PGRES_COMMAND_OK) {
        PQclear(begin);
        PQfinish(conn);
        return;
    }
    PQclear(begin);

    bool ok = true;
    const std::string upsert_zone =
        "INSERT INTO dns_zones(name,serial,updated_at) VALUES (" +
        sql_literal(conn, zone.name) + "," + std::to_string(zone.serial) + ",now()) "
        "ON CONFLICT (name) DO UPDATE SET serial=excluded.serial, updated_at=now();";
    PGresult* zone_result = PQexec(conn, upsert_zone.c_str());
    ok = PQresultStatus(zone_result) == PGRES_COMMAND_OK;
    PQclear(zone_result);

    if (ok) {
        const std::string delete_records = "DELETE FROM dns_records WHERE zone_name = " + sql_literal(conn, zone.name) + ";";
        PGresult* delete_result = PQexec(conn, delete_records.c_str());
        ok = PQresultStatus(delete_result) == PGRES_COMMAND_OK;
        PQclear(delete_result);
    }

    for (const auto& record : zone.records) {
        if (!ok) {
            break;
        }
        const std::string insert_record =
            "INSERT INTO dns_records(zone_name,name,type,value,ttl,priority,dns_class,weight,port,flags) VALUES (" +
            sql_literal(conn, zone.name) + "," +
            sql_literal(conn, record.name) + "," +
            sql_literal(conn, record.type) + "," +
            sql_literal(conn, record.value) + "," +
            std::to_string(record.ttl) + "," +
            std::to_string(record.priority) + "," +
            sql_literal(conn, record.dns_class) + "," +
            std::to_string(record.weight) + "," +
            std::to_string(record.port) + "," +
            sql_literal(conn, record.flags) + ");";
        PGresult* record_result = PQexec(conn, insert_record.c_str());
        ok = PQresultStatus(record_result) == PGRES_COMMAND_OK;
        if (!ok) {
            std::cerr << "[nexus-api] failed to persist dns record: " << PQresultErrorMessage(record_result) << '\n';
        }
        PQclear(record_result);
    }

    PGresult* end = PQexec(conn, ok ? "commit" : "rollback");
    PQclear(end);
    PQfinish(conn);
}

void delete_dns_zone_from_database(const std::string& zone_name, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string sql = "DELETE FROM dns_zones WHERE name = " + sql_literal(conn, zone_name) + ";";
    PGresult* result = PQexec(conn, sql.c_str());
    PQclear(result);
    PQfinish(conn);
}

std::vector<nexus::core::DnsZone> load_dns_zones_from_database(const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return {};
    }

    PGresult* zones_result = PQexec(conn, "SELECT name,serial FROM dns_zones ORDER BY name;");
    std::vector<nexus::core::DnsZone> zones;
    if (PQresultStatus(zones_result) == PGRES_TUPLES_OK) {
        for (int index = 0; index < PQntuples(zones_result); ++index) {
            zones.push_back({
                PQgetvalue(zones_result, index, 0),
                static_cast<std::uint64_t>(std::stoull(PQgetvalue(zones_result, index, 1))),
                {},
            });
        }
    }
    PQclear(zones_result);

    PGresult* records_result = PQexec(
        conn,
        "SELECT zone_name,name,type,value,ttl,priority,coalesce(dns_class,'IN'),coalesce(weight,0),coalesce(port,0),coalesce(flags,'') "
        "FROM dns_records ORDER BY zone_name,id;");
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
                PQgetvalue(records_result, index, 6),
                static_cast<std::uint32_t>(std::stoul(PQgetvalue(records_result, index, 4))),
                static_cast<std::uint16_t>(std::stoul(PQgetvalue(records_result, index, 5))),
                static_cast<std::uint16_t>(std::stoul(PQgetvalue(records_result, index, 7))),
                static_cast<std::uint16_t>(std::stoul(PQgetvalue(records_result, index, 8))),
                PQgetvalue(records_result, index, 9),
            });
        }
    }
    PQclear(records_result);
    PQfinish(conn);
    return zones;
}

void persist_pki_authority_to_database(const nexus::core::PkiAuthority& authority, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string sql =
        "INSERT INTO pki_authorities(name,certificate_pem,private_key_pem,created_at) VALUES (" +
        sql_literal(conn, authority.name) + "," +
        sql_literal(conn, authority.certificate_pem) + "," +
        sql_literal(conn, authority.private_key_pem) + ",now()) "
        "ON CONFLICT (name) DO UPDATE SET certificate_pem=excluded.certificate_pem, private_key_pem=excluded.private_key_pem;";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist pki authority: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

void persist_pki_certificate_to_database(const nexus::core::PkiCertificate& certificate, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string authority_sql = "SELECT id FROM pki_authorities WHERE name = " + sql_literal(conn, certificate.authority_name) + " LIMIT 1;";
    PGresult* authority_result = PQexec(conn, authority_sql.c_str());
    if (PQresultStatus(authority_result) != PGRES_TUPLES_OK || PQntuples(authority_result) == 0) {
        PQclear(authority_result);
        PQfinish(conn);
        return;
    }
    const std::string authority_id = PQgetvalue(authority_result, 0, 0);
    PQclear(authority_result);
    const std::string sql =
        "INSERT INTO pki_certificates(serial,authority_id,common_name,certificate_pem,revoked,created_at) VALUES (" +
        sql_literal(conn, certificate.serial_hex) + "," + authority_id + "," +
        sql_literal(conn, certificate.common_name) + "," +
        sql_literal(conn, certificate.certificate_pem) + "," +
        std::string(certificate.revoked ? "true" : "false") + ",now()) "
        "ON CONFLICT (serial) DO UPDATE SET common_name=excluded.common_name, certificate_pem=excluded.certificate_pem, revoked=excluded.revoked;";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist pki certificate: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

void persist_pki_revocation_to_database(const nexus::core::PkiRevocation& revocation, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string update_sql = "UPDATE pki_certificates SET revoked = true WHERE serial = " + sql_literal(conn, revocation.serial) + ";";
    PGresult* update = PQexec(conn, update_sql.c_str());
    PQclear(update);
    const std::string sql =
        "INSERT INTO pki_revocations(serial,reason,revoked_at) VALUES (" +
        sql_literal(conn, revocation.serial) + "," +
        sql_literal(conn, revocation.reason) + ",now()) ON CONFLICT (serial) DO UPDATE SET reason=excluded.reason, revoked_at=now();";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist pki revocation: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

void persist_apt_repository_to_database(const nexus::core::AptRepository& repository, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string sql =
        "INSERT INTO repo_repositories(distribution,component) VALUES (" +
        sql_literal(conn, repository.distribution) + "," + sql_literal(conn, repository.component) + ") "
        "ON CONFLICT (distribution,component) DO NOTHING;";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist apt repository: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

void persist_apt_package_to_database(
    const std::string& distribution,
    const std::string& component,
    const nexus::core::AptPackage& package,
    const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string sql =
        "INSERT INTO repo_packages(distribution,component,name,version,architecture,filename,sha256,size) VALUES (" +
        sql_literal(conn, distribution) + "," + sql_literal(conn, component) + "," +
        sql_literal(conn, package.name) + "," + sql_literal(conn, package.version) + "," +
        sql_literal(conn, package.architecture) + "," + sql_literal(conn, package.filename) + "," +
        sql_literal(conn, package.sha256) + "," + std::to_string(package.size) + ");";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-api] failed to persist apt package: " << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
}

void delete_apt_repository_from_database(const std::string& distribution, const std::string& component, const std::string& database_url) {
    PGconn* conn = connect_database(database_url);
    if (conn == nullptr) {
        return;
    }
    const std::string delete_packages =
        "DELETE FROM repo_packages WHERE distribution = " + sql_literal(conn, distribution) +
        " AND component = " + sql_literal(conn, component) + ";";
    PGresult* packages = PQexec(conn, delete_packages.c_str());
    PQclear(packages);
    const std::string delete_repo =
        "DELETE FROM repo_repositories WHERE distribution = " + sql_literal(conn, distribution) +
        " AND component = " + sql_literal(conn, component) + ";";
    PGresult* repo = PQexec(conn, delete_repo.c_str());
    PQclear(repo);
    PQfinish(conn);
}

bool sync_feature_flags(PGconn* connection, const std::map<std::string, bool>& flags) {
    if (!ensure_feature_flags_table(connection)) {
        return false;
    }

    PGresult* begin = PQexec(connection, "begin");
    if (PQresultStatus(begin) != PGRES_COMMAND_OK) {
        PQclear(begin);
        return false;
    }
    PQclear(begin);

    bool ok = true;
    for (const auto& service : nexus::core::service_definitions()) {
        if (service.feature_flag.empty()) {
            continue;
        }

        const auto it = flags.find(service.feature_flag);
        const bool enabled = it != flags.end() && it->second;
        const std::string sql = "insert into feature_flags(service_id, enabled, updated_at) values('" + service.feature_flag + "', " + (enabled ? std::string{"true"} : std::string{"false"}) + ", now()) on conflict(service_id) do update set enabled = excluded.enabled, updated_at = now()";
        PGresult* result = PQexec(connection, sql.c_str());
        if (PQresultStatus(result) != PGRES_COMMAND_OK) {
            ok = false;
        }
        PQclear(result);
        if (!ok) {
            break;
        }
    }

    PGresult* end = PQexec(connection, ok ? "commit" : "rollback");
    const bool committed = PQresultStatus(end) == PGRES_COMMAND_OK;
    PQclear(end);
    return ok && committed;
}

std::map<std::string, bool> load_feature_flags(PGconn* connection) {
    std::map<std::string, bool> flags;
    if (!ensure_feature_flags_table(connection)) {
        return flags;
    }

    PGresult* result = PQexec(connection, "select service_id, enabled from feature_flags");
    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        PQclear(result);
        return flags;
    }

    const int rows = PQntuples(result);
    for (int index = 0; index < rows; ++index) {
        const std::string service_id = PQgetvalue(result, index, 0);
        const std::string enabled = PQgetvalue(result, index, 1);
        flags[service_id] = enabled == "t" || enabled == "true" || enabled == "1";
    }
    PQclear(result);
    return flags;
}

std::vector<nexus::core::ServiceStatus> make_services(const nexus::core::Config& config) {
    const auto enabled_for = [&](const std::string& id) {
        auto it = config.features.find(id);
        if (it == config.features.end()) {
            return false;
        }
        return it->second;
    };

    const auto service_state = [&](bool enabled) {
        return enabled ? "healthy" : "disabled";
    };

    std::vector<nexus::core::ServiceStatus> services;
    const auto definitions = nexus::core::service_definitions();
    services.reserve(definitions.size());

    for (const auto& definition : definitions) {
        const bool enabled = definition.feature_flag.empty() ? true : enabled_for(definition.feature_flag);
        services.push_back({
            definition.id,
            definition.label,
            service_state(enabled),
            enabled ? definition.enabled_summary : definition.disabled_summary,
            definition.endpoints(config),
            definition.capabilities,
            definition.critical,
            enabled,
            get_service_blocking_reason(definition.id, config.database_url)
        });
    }

    return services;
}

bool is_valid_zone_name(const std::string& zone_name) {
    if (zone_name.empty() || zone_name.front() == '.' || zone_name.back() == '.') {
        return false;
    }
    bool seen_dot = false;
    for (char c : zone_name) {
        if (c == '.') {
            seen_dot = true;
            continue;
        }
        if (std::isalnum(static_cast<unsigned char>(c)) || c == '-') {
            continue;
        }
        return false;
    }
    return seen_dot;
}

std::uint64_t default_zone_serial() {
    return 1;
}

Json::Value config_to_json_value(const nexus::core::Config& config) {
    Json::Value node(Json::objectValue);
    node["environment"] = config.environment;
    node["domain"] = config.domain;
    node["blobRoot"] = config.blob_root.string();
    node["stateRoot"] = config.state_root.string();
    node["databaseUrl"] = config.database_url;
    node["adminEmail"] = config.admin_email;
    node["adminPasswordHash"] = config.admin_password_hash;
    node["adminTotpSecret"] = config.admin_totp_secret;
    node["ports"]["http"] = config.http.port;
    node["ports"]["ldap"] = config.ldap.port;
    node["ports"]["ldaps"] = config.ldaps.port;
    node["ports"]["kerberos"] = config.kerberos.port;
    node["ports"]["kpasswd"] = config.kpasswd.port;
    node["ports"]["globalCatalog"] = config.global_catalog.port;
    node["ports"]["rpc"] = config.rpc_endpoint_mapper.port;
    node["ports"]["smb"] = config.smb.port;
    node["ports"]["dnsTcp"] = config.dns_tcp.port;
    node["ports"]["dnsUdp"] = config.dns_udp.port;
    node["ports"]["dhcp"] = config.dhcp.port;
    node["directory"]["baseDn"] = config.directory.base_dn;
    node["directory"]["organization"] = config.directory.organization;
    node["directory"]["realm"] = config.directory.realm;
    node["directory"]["adPortProfile"] = config.directory.ad_port_profile;
    node["directory"]["siteName"] = config.directory.site_name;
    node["directory"]["domainControllerHost"] = config.directory.domain_controller_host;
    node["directory"]["domainControllerAddress"] = config.directory.domain_controller_address;
    node["directory"]["keyEncryptionKeyFile"] = config.directory.key_encryption_key_file;
    node["dns"]["primaryNs"] = config.dns.primary_ns;
    node["dns"]["adminMailbox"] = config.dns.admin_mailbox;
    node["dns"]["defaultTtl"] = Json::UInt(config.dns.default_ttl);
    node["dhcp"]["subnet"] = config.dhcp_service.subnet;
    node["dhcp"]["rangeStart"] = config.dhcp_service.range_start;
    node["dhcp"]["rangeEnd"] = config.dhcp_service.range_end;
    node["dhcp"]["router"] = config.dhcp_service.router;
    node["pki"]["organization"] = config.pki.organization;
    node["pki"]["commonName"] = config.pki.common_name;
    node["pki"]["leafDaysValid"] = config.pki.leaf_days_valid;
    node["repo"]["origin"] = config.repo.origin;
    node["repo"]["distribution"] = config.repo.distribution;
    node["repo"]["component"] = config.repo.component;
    Json::Value features(Json::objectValue);
    for (const auto& [k, v] : config.features) {
        features[k] = v;
    }
    node["features"] = features;
    return node;
}

nexus::core::Config config_from_json_value(const nexus::core::Config& current, const Json::Value& body) {
    auto read_string = [&](const char* key, const std::string& fallback) {
        return body.isMember(key) ? body[key].asString() : fallback;
    };

    auto read_port = [&](const char* key, int fallback) {
        if (!body.isMember(key)) {
            return fallback;
        }
        const int value = body[key].asInt();
        return value > 0 ? value : fallback;
    };

    nexus::core::Config updated = current;
    updated.environment = read_string("environment", current.environment);
    updated.domain = read_string("domain", current.domain);
    updated.blob_root = read_string("blobRoot", current.blob_root.string());
    updated.state_root = read_string("stateRoot", current.state_root.string());
    updated.database_url = read_string("databaseUrl", current.database_url);
    updated.admin_email = read_string("adminEmail", current.admin_email);
    updated.admin_password_hash = read_string("adminPasswordHash", current.admin_password_hash);
    updated.admin_totp_secret = read_string("adminTotpSecret", current.admin_totp_secret);
    updated.http.port = read_port("httpPort", current.http.port);
    updated.ldap.port = read_port("ldapPort", current.ldap.port);
    updated.ldaps.port = read_port("ldapsPort", current.ldaps.port);
    updated.kerberos.port = read_port("kerberosPort", current.kerberos.port);
    updated.kpasswd.port = read_port("kpasswdPort", current.kpasswd.port);
    updated.global_catalog.port = read_port("globalCatalogPort", current.global_catalog.port);
    updated.rpc_endpoint_mapper.port = read_port("rpcPort", current.rpc_endpoint_mapper.port);
    updated.smb.port = read_port("smbPort", current.smb.port);
    updated.dns_tcp.port = read_port("dnsTcpPort", current.dns_tcp.port);
    updated.dns_udp.port = read_port("dnsUdpPort", current.dns_udp.port);
    updated.dhcp.port = read_port("dhcpPort", current.dhcp.port);
    if (body.isMember("ports") && body["ports"].isObject()) {
        const auto& ports = body["ports"];
        if (ports.isMember("http")) updated.http.port = ports["http"].asInt();
        if (ports.isMember("ldap")) updated.ldap.port = ports["ldap"].asInt();
        if (ports.isMember("ldaps")) updated.ldaps.port = ports["ldaps"].asInt();
        if (ports.isMember("kerberos")) updated.kerberos.port = ports["kerberos"].asInt();
        if (ports.isMember("kpasswd")) updated.kpasswd.port = ports["kpasswd"].asInt();
        if (ports.isMember("globalCatalog")) updated.global_catalog.port = ports["globalCatalog"].asInt();
        if (ports.isMember("rpc")) updated.rpc_endpoint_mapper.port = ports["rpc"].asInt();
        if (ports.isMember("smb")) updated.smb.port = ports["smb"].asInt();
        if (ports.isMember("dnsTcp")) updated.dns_tcp.port = ports["dnsTcp"].asInt();
        if (ports.isMember("dnsUdp")) updated.dns_udp.port = ports["dnsUdp"].asInt();
        if (ports.isMember("dhcp")) updated.dhcp.port = ports["dhcp"].asInt();
    }
    if (body.isMember("directory") && body["directory"].isObject()) {
        const auto& directory = body["directory"];
        updated.directory.base_dn = directory.isMember("baseDn") ? directory["baseDn"].asString() : current.directory.base_dn;
        updated.directory.organization = directory.isMember("organization") ? directory["organization"].asString() : current.directory.organization;
        updated.directory.realm = directory.isMember("realm") ? directory["realm"].asString() : current.directory.realm;
        updated.directory.ad_port_profile = directory.isMember("adPortProfile") ? directory["adPortProfile"].asString() : current.directory.ad_port_profile;
        updated.directory.site_name = directory.isMember("siteName") ? directory["siteName"].asString() : current.directory.site_name;
        updated.directory.domain_controller_host = directory.isMember("domainControllerHost") ? directory["domainControllerHost"].asString() : current.directory.domain_controller_host;
        updated.directory.domain_controller_address = directory.isMember("domainControllerAddress") ? directory["domainControllerAddress"].asString() : current.directory.domain_controller_address;
        updated.directory.key_encryption_key_file = directory.isMember("keyEncryptionKeyFile") ? directory["keyEncryptionKeyFile"].asString() : current.directory.key_encryption_key_file;
    }
    if (body.isMember("dns") && body["dns"].isObject()) {
        const auto& dns = body["dns"];
        updated.dns.primary_ns = dns.isMember("primaryNs") ? dns["primaryNs"].asString() : current.dns.primary_ns;
        updated.dns.admin_mailbox = dns.isMember("adminMailbox") ? dns["adminMailbox"].asString() : current.dns.admin_mailbox;
        if (dns.isMember("defaultTtl") && dns["defaultTtl"].asUInt() > 0) {
            updated.dns.default_ttl = dns["defaultTtl"].asUInt();
        }
    }
    if (body.isMember("dhcp") && body["dhcp"].isObject()) {
        const auto& dhcp = body["dhcp"];
        updated.dhcp_service.subnet = dhcp.isMember("subnet") ? dhcp["subnet"].asString() : current.dhcp_service.subnet;
        updated.dhcp_service.range_start = dhcp.isMember("rangeStart") ? dhcp["rangeStart"].asString() : current.dhcp_service.range_start;
        updated.dhcp_service.range_end = dhcp.isMember("rangeEnd") ? dhcp["rangeEnd"].asString() : current.dhcp_service.range_end;
        updated.dhcp_service.router = dhcp.isMember("router") ? dhcp["router"].asString() : current.dhcp_service.router;
    }
    if (body.isMember("pki") && body["pki"].isObject()) {
        const auto& pki = body["pki"];
        updated.pki.organization = pki.isMember("organization") ? pki["organization"].asString() : current.pki.organization;
        updated.pki.common_name = pki.isMember("commonName") ? pki["commonName"].asString() : current.pki.common_name;
        if (pki.isMember("leafDaysValid") && pki["leafDaysValid"].asInt() > 0) {
            updated.pki.leaf_days_valid = pki["leafDaysValid"].asInt();
        }
    }
    if (body.isMember("repo") && body["repo"].isObject()) {
        const auto& repo = body["repo"];
        updated.repo.origin = repo.isMember("origin") ? repo["origin"].asString() : current.repo.origin;
        updated.repo.distribution = repo.isMember("distribution") ? repo["distribution"].asString() : current.repo.distribution;
        updated.repo.component = repo.isMember("component") ? repo["component"].asString() : current.repo.component;
    }
    if (body.isMember("features") && body["features"].isObject()) {
        updated.features.clear();
        const auto& f = body["features"];
        for (const auto& key : f.getMemberNames()) {
            updated.features[key] = f[key].asBool();
        }
    }
    return updated;
}

}  // namespace

PlatformState::PlatformState(nexus::core::Config config)
    : config_(std::move(config)) {
    if (!load_persisted_settings()) {
        std::cerr << "[nexus-api] using environment settings; no persisted settings loaded\n";
    }
    if (!load_feature_flags_from_database()) {
        config_.features = feature_flag_defaults(config_);
    }
    initialize_runtime_state();
}

const nexus::core::Config& PlatformState::config() const {
    return config_;
}

bool PlatformState::update_settings(const nexus::core::Config& config, const std::string& actor) {
    if (!sync_feature_flags_to_database(config)) {
        return false;
    }

    if (!persist_settings(config)) {
        return false;
    }

    {
        std::scoped_lock lock(mutex_);
        config_ = config;
        services_ = make_services(config_);
        ++revision_;
        record_audit_locked(actor, "config", "update", "Updated platform settings");
    }

    return true;
}

std::map<std::string, bool> PlatformState::feature_flags() const {
    std::scoped_lock lock(mutex_);
    return config_.features;
}

bool PlatformState::update_feature_flags(const std::map<std::string, bool>& features, const std::string& actor) {
    nexus::core::Config updated;
    {
        std::scoped_lock lock(mutex_);
        updated = config_;
        updated.features = features;
    }

    if (!sync_feature_flags_to_database(updated)) {
        return false;
    }

    if (!persist_settings(updated)) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    config_.features = features;
    services_ = make_services(config_);
    ++revision_;
    record_audit_locked(actor, "config", "feature_flags.update", "Updated service feature flags");
    return true;
}

bool PlatformState::create_active_directory_domain(
    const nexus::core::ActiveDirectoryDomain& requested_domain,
    const std::string& admin_sam_account,
    const std::string& admin_display_name,
    const std::string& admin_password,
    const std::string& domain_controller_host,
    const std::string& domain_controller_address,
    const std::string& actor) {
    if (!is_valid_zone_name(requested_domain.dns_name) ||
        !is_valid_netbios_name(requested_domain.netbios_name) ||
        admin_sam_account.empty() ||
        admin_password.empty() ||
        domain_controller_host.empty() ||
        domain_controller_address.empty()) {
        return false;
    }

    const auto base_dn = requested_domain.base_dn.empty() ? base_dn_from_dns_name(requested_domain.dns_name) : requested_domain.base_dn;
    if (!nexus::protocol::is_valid_dn(base_dn)) {
        return false;
    }

    nexus::core::ActiveDirectoryDomain domain{
        requested_domain.dns_name,
        uppercase_ascii(requested_domain.netbios_name),
        requested_domain.realm.empty() ? uppercase_ascii(requested_domain.dns_name) : uppercase_ascii(requested_domain.realm),
        base_dn,
        requested_domain.domain_sid.empty() ? random_domain_sid() : requested_domain.domain_sid,
        nexus::core::utc_timestamp()};

    {
        std::scoped_lock lock(mutex_);
        if (ad_domain_.has_value()) {
            return false;
        }
    }

    const auto sid = [&](int rid) {
        return domain.domain_sid + "-" + std::to_string(rid);
    };

    std::vector<nexus::core::DirectoryObject> objects{
        {domain.base_dn, "", "domainDNS", {"top", "domain", "domainDNS"}, {{"dc", domain.dns_name.substr(0, domain.dns_name.find('.'))}, {"objectSid", domain.domain_sid}, {"nETBIOSName", domain.netbios_name}}},
        {"cn=Builtin," + domain.base_dn, domain.base_dn, "builtinDomain", {"top", "builtinDomain"}, {{"cn", "Builtin"}, {"objectSid", "S-1-5-32"}}},
        {"ou=Users," + domain.base_dn, domain.base_dn, "organizationalUnit", {"top", "organizationalUnit"}, {{"ou", "Users"}, {"description", "Default user container"}}},
        {"ou=Groups," + domain.base_dn, domain.base_dn, "organizationalUnit", {"top", "organizationalUnit"}, {{"ou", "Groups"}, {"description", "Default group container"}}},
        {"ou=Domain Controllers," + domain.base_dn, domain.base_dn, "organizationalUnit", {"top", "organizationalUnit"}, {{"ou", "Domain Controllers"}, {"description", "Domain controller container"}}},
        {"cn=Computers," + domain.base_dn, domain.base_dn, "container", {"top", "container"}, {{"cn", "Computers"}, {"description", "Default computer account container"}}},
        {"cn=Domain Users,ou=Groups," + domain.base_dn, "ou=Groups," + domain.base_dn, "group", {"top", "group"}, {{"cn", "Domain Users"}, {"sAMAccountName", "Domain Users"}, {"groupType", "-2147483646"}, {"objectSid", sid(513)}}},
        {"cn=Domain Admins,ou=Groups," + domain.base_dn, "ou=Groups," + domain.base_dn, "group", {"top", "group"}, {{"cn", "Domain Admins"}, {"sAMAccountName", "Domain Admins"}, {"groupType", "-2147483646"}, {"objectSid", sid(512)}}},
        {"cn=Administrators,cn=Builtin," + domain.base_dn, "cn=Builtin," + domain.base_dn, "group", {"top", "group"}, {{"cn", "Administrators"}, {"sAMAccountName", "Administrators"}, {"groupType", "-2147483643"}, {"objectSid", "S-1-5-32-544"}}},
        {"cn=Guest,ou=Users," + domain.base_dn, "ou=Users," + domain.base_dn, "user", {"top", "person", "organizationalPerson", "user"}, {{"cn", "Guest"}, {"sAMAccountName", "Guest"}, {"userAccountControl", "66082"}, {"objectSid", sid(501)}}},
        {"cn=krbtgt,ou=Users," + domain.base_dn, "ou=Users," + domain.base_dn, "user", {"top", "person", "organizationalPerson", "user"}, {{"cn", "krbtgt"}, {"sAMAccountName", "krbtgt"}, {"userAccountControl", "514"}, {"servicePrincipalName", "krbtgt/" + domain.realm}, {"objectSid", sid(502)}}},
        {"cn=" + domain_controller_host + ",ou=Domain Controllers," + domain.base_dn, "ou=Domain Controllers," + domain.base_dn, "computer", {"top", "person", "organizationalPerson", "user", "computer"}, {{"cn", domain_controller_host}, {"sAMAccountName", uppercase_ascii(domain_controller_host) + "$"}, {"dNSHostName", domain_controller_host + "." + domain.dns_name}, {"userAccountControl", "532480"}, {"servicePrincipalName", "HOST/" + domain_controller_host + "." + domain.dns_name + ";LDAP/" + domain_controller_host + "." + domain.dns_name + ";GC/" + domain_controller_host + "." + domain.dns_name + ";CIFS/" + domain_controller_host + "." + domain.dns_name}, {"objectSid", sid(1000)}}},
    };

    const auto admin_cn = admin_display_name.empty() ? admin_sam_account : admin_display_name;
    nexus::core::DirectoryObject administrator{
        "cn=" + admin_cn + ",ou=Users," + domain.base_dn,
        "ou=Users," + domain.base_dn,
        "user",
        {"top", "person", "organizationalPerson", "user"},
        {
            {"cn", admin_cn},
            {"displayName", admin_cn},
            {"sAMAccountName", admin_sam_account},
            {"userPrincipalName", admin_sam_account + "@" + domain.dns_name},
            {"userAccountControl", "512"},
            {"objectSid", sid(500)},
            {"memberOf", "cn=Domain Admins,ou=Groups," + domain.base_dn},
        }};
    administrator.attributes["userPasswordHash"] = password_hasher_.hash_password(admin_password);
    objects.push_back(std::move(administrator));

    persist_active_directory_domain_to_database(
        domain,
        domain_controller_host,
        domain_controller_address,
        config_.directory.site_name,
        config_.database_url);
    for (const auto& object : objects) {
        persist_directory_object_to_database(object, config_.database_url);
    }

    std::scoped_lock lock(mutex_);
    ad_domain_ = domain;
    for (auto& object : objects) {
        const auto existing = std::find_if(directory_.begin(), directory_.end(), [&](const auto& current) {
            return current.dn == object.dn;
        });
        if (existing == directory_.end()) {
            directory_.push_back(std::move(object));
        }
    }

    auto zone = std::find_if(zones_.begin(), zones_.end(), [&](const auto& current) {
        return current.name == domain.dns_name;
    });
    if (zone == zones_.end()) {
        zones_.push_back({domain.dns_name, default_zone_serial(), {}});
        zone = std::prev(zones_.end());
    }

    const auto ad_zone = nexus::protocol::make_active_directory_dns_zone({
        domain.dns_name,
        config_.directory.site_name,
        domain_controller_host,
        domain_controller_address,
        static_cast<std::uint16_t>(config_.ldap.port),
        static_cast<std::uint16_t>(config_.kerberos.port),
        static_cast<std::uint16_t>(config_.kpasswd.port),
        static_cast<std::uint16_t>(config_.global_catalog.port),
    });
    for (const auto& record : ad_zone.records) {
        const auto duplicate = std::find_if(zone->records.begin(), zone->records.end(), [&](const auto& current) {
            return current.name == record.name && current.type == record.type && current.value == record.value && current.port == record.port;
        });
        if (duplicate == zone->records.end()) {
            zone->records.push_back(record);
        }
    }
    zone->serial += 1;
    persist_dns_zone_to_database(*zone, config_.database_url);

    jobs_.enqueue("directory", "Create Windows domain " + domain.dns_name);
    jobs_.enqueue("dns", "Publish Active Directory SRV records for " + domain.dns_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "ad", "domain.created", domain.dns_name + " / " + domain.netbios_name});
    revision_ += 1;
    return true;
}

nexus::core::DashboardSnapshot PlatformState::dashboard() const {
    std::scoped_lock lock(mutex_);
    nexus::core::DashboardSnapshot snapshot;
    snapshot.services = services_;
    snapshot.directory_objects = directory_.size();
    snapshot.pki_revocations = revocations_.size();
    snapshot.pending_jobs = jobs_.pending_count();
    snapshot.repo_packages = std::accumulate(
        repositories_.begin(),
        repositories_.end(),
        std::size_t{0},
        [](std::size_t total, const auto& repository) { return total + repository.packages.size(); });
    snapshot.dns_records = std::accumulate(
        zones_.begin(),
        zones_.end(),
        std::size_t{0},
        [](std::size_t total, const auto& zone) { return total + zone.records.size(); });
    snapshot.dhcp_leases = std::accumulate(
        pools_.begin(),
        pools_.end(),
        std::size_t{0},
        [](std::size_t total, const auto& pool) { return total + pool.leases.size(); });
    return snapshot;
}

std::vector<nexus::core::ServiceStatus> PlatformState::services() const {
    std::scoped_lock lock(mutex_);
    return services_;
}

std::optional<nexus::core::ActiveDirectoryDomain> PlatformState::active_directory_domain() const {
    std::scoped_lock lock(mutex_);
    return ad_domain_;
}

std::vector<nexus::core::ActiveDirectoryReadinessItem> PlatformState::active_directory_readiness() const {
    std::scoped_lock lock(mutex_);
    const bool has_domain = ad_domain_.has_value();
    const bool has_dns_zone = has_domain && std::any_of(zones_.begin(), zones_.end(), [&](const auto& zone) {
        return zone.name == ad_domain_->dns_name;
    });
    const bool has_dns_locator = has_domain && std::any_of(zones_.begin(), zones_.end(), [&](const auto& zone) {
        return zone.name == ad_domain_->dns_name && std::any_of(zone.records.begin(), zone.records.end(), [](const auto& record) {
            return record.type == "SRV" && (record.name == "_ldap._tcp" || record.name == "_ldap._tcp.dc._msdcs");
        });
    });
    const bool has_admin_user = has_domain && std::any_of(directory_.begin(), directory_.end(), [&](const auto& object) {
        const auto membership = object.attributes.find("memberOf");
        return object.kind == "user" && membership != object.attributes.end() && membership->second == "cn=Domain Admins,ou=Groups," + ad_domain_->base_dn;
    });
    const bool has_machine_container = has_domain && std::any_of(directory_.begin(), directory_.end(), [&](const auto& object) {
        return object.dn == "cn=Computers," + ad_domain_->base_dn;
    });

    return {
        {"domain", "Windows domain model", has_domain, has_domain ? ad_domain_->dns_name + " / " + ad_domain_->netbios_name : "Create the Windows domain first"},
        {"dns", "AD DNS zone", has_dns_zone, has_dns_zone ? "DNS zone exists for the domain" : "The domain DNS zone is missing"},
        {"dns-locator", "AD DNS locator records", has_dns_locator, has_dns_locator ? "LDAP/Kerberos SRV locator records are published" : "Publish _ldap and _kerberos SRV records"},
        {"administrator", "Domain administrator", has_admin_user, has_admin_user ? "Administrator account exists" : "Create the initial Administrator user"},
        {"computers", "Computer account container", has_machine_container, has_machine_container ? "CN=Computers container exists" : "Create the default computer container"},
        {"ldap-rootdse", "LDAP RootDSE discovery", true, "LDAP bind and RootDSE probes are served by nexus-directory"},
        {"ldap-ad", "LDAP AD object protocol", false, "Object search/add/modify still need schema-aware AD LDAP semantics"},
        {"kerberos", "Kerberos KDC", false, "AS/TGS ticket handling is not implemented yet"},
        {"netlogon", "Netlogon / MS-RPC", false, "Windows domain join still needs Netlogon, SAMR and LSA RPC"},
        {"sysvol", "SMB SYSVOL / NETLOGON", false, "SYSVOL and NETLOGON shares are not implemented yet"},
    };
}

Json::Value PlatformState::active_directory_join_guide() const {
    std::scoped_lock lock(mutex_);
    Json::Value guide(Json::objectValue);
    guide["supported"] = false;
    guide["target"] = "Windows 11 Pro";
    guide["message"] = ad_domain_.has_value()
        ? "The domain model is configured, but native LDAP/Kerberos/Netlogon/SMB protocol milestones are still required before Windows can join."
        : "Create a Windows domain in Nexus before attempting a Windows join.";
    if (ad_domain_.has_value()) {
        guide["domain"] = ad_domain_->dns_name;
        guide["netbiosName"] = ad_domain_->netbios_name;
        guide["realm"] = ad_domain_->realm;
        guide["dnsServer"] = "Point the Windows client DNS server to this Nexus host.";
        guide["windowsSteps"].append("Settings > System > About > Domain or workgroup");
        guide["windowsSteps"].append("Join domain: " + ad_domain_->dns_name);
        guide["windowsSteps"].append("Use the Nexus-created Administrator account once protocol readiness is complete.");
    }
    guide["blockingProtocols"].append("LDAP AD-compatible bind/search");
    guide["blockingProtocols"].append("Kerberos KDC AS/TGS");
    guide["blockingProtocols"].append("MS-RPC Netlogon/SAMR/LSA");
    guide["blockingProtocols"].append("SMB SYSVOL/NETLOGON");
    return guide;
}

std::vector<nexus::core::DirectoryObject> PlatformState::directory_objects() const {
    std::scoped_lock lock(mutex_);
    return directory_;
}

std::vector<nexus::core::DnsZone> PlatformState::dns_zones() const {
    std::scoped_lock lock(mutex_);
    return zones_;
}

std::vector<nexus::core::DhcpPool> PlatformState::dhcp_pools() const {
    std::scoped_lock lock(mutex_);
    return pools_;
}

std::vector<nexus::core::PkiAuthority> PlatformState::pki_authorities() const {
    std::scoped_lock lock(mutex_);
    return authorities_;
}

std::vector<nexus::core::PkiCertificate> PlatformState::pki_certificates() const {
    std::scoped_lock lock(mutex_);
    return certificates_;
}

std::vector<nexus::core::PkiRevocation> PlatformState::pki_revocations() const {
    std::scoped_lock lock(mutex_);
    return revocations_;
}

std::vector<nexus::core::AptRepository> PlatformState::apt_repositories() const {
    std::scoped_lock lock(mutex_);
    return repositories_;
}

std::vector<nexus::core::AuditEvent> PlatformState::audit_events() const {
    std::scoped_lock lock(mutex_);
    auto events = audit_events_;
    std::reverse(events.begin(), events.end());
    return events;
}

std::vector<nexus::core::JobSummary> PlatformState::jobs() const {
    return jobs_.list();
}

std::optional<nexus::core::DnsZone> PlatformState::find_zone(const std::string& zone_name) const {
    std::scoped_lock lock(mutex_);
    auto it = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (it == zones_.end()) {
        return std::nullopt;
    }
    return *it;
}

std::optional<std::string> PlatformState::render_zone(const std::string& zone_name) const {
    const auto zone = find_zone(zone_name);
    if (!zone.has_value()) {
        return std::nullopt;
    }
    return nexus::protocol::render_zone_file(*zone, "ns1." + zone->name, "hostmaster." + zone->name);
}

std::uint64_t PlatformState::stream_revision() const {
    std::scoped_lock lock(mutex_);
    return revision_;
}

PlatformState::LoginResult PlatformState::login(
    const std::string& email,
    const std::string& password,
    const std::string& totp_code) {
    if (config_.admin_password_hash.empty()) {
        return {.ok = false, .error = "admin bootstrap required: set NEXUS_ADMIN_PASSWORD_HASH"};
    }

    if (email != config_.admin_email) {
        return {.ok = false, .error = "unknown user"};
    }

    if (!password_hasher_.verify_password(password, config_.admin_password_hash)) {
        return {.ok = false, .error = "invalid credentials"};
    }

    if (!config_.admin_totp_secret.empty()) {
        if (totp_code.empty() || !totp_.verify(config_.admin_totp_secret, totp_code, std::chrono::system_clock::now())) {
            return {.ok = false, .error = "invalid mfa code"};
        }
    }

    const auto session_token = random_token(32);
    const auto csrf_token = random_token(24);

    {
        std::scoped_lock lock(mutex_);
        sessions_[session_token] = Session{
            email,
            csrf_token,
            {"superadmin", "directory-admin", "network-admin", "pki-admin", "repo-admin", "auditor"},
            std::chrono::system_clock::now() + std::chrono::hours(12)};
    }

    record_audit(email, "auth", "login", "Local admin login");
    return {
        .ok = true,
        .session_token = session_token,
        .csrf_token = csrf_token,
        .roles = {"superadmin", "directory-admin", "network-admin", "pki-admin", "repo-admin", "auditor"}};
}

bool PlatformState::authenticate(
    const std::string& session_token,
    std::string* actor_out,
    std::vector<std::string>* roles_out) const {
    std::scoped_lock lock(mutex_);
    expire_sessions_locked(std::chrono::system_clock::now());
    auto it = sessions_.find(session_token);
    if (it == sessions_.end()) {
        return false;
    }

    if (actor_out != nullptr) {
        *actor_out = it->second.email;
    }
    if (roles_out != nullptr) {
        *roles_out = it->second.roles;
    }
    return true;
}

bool PlatformState::authorize_mutation(
    const std::string& session_token,
    const std::string& csrf_token,
    std::string* actor_out,
    std::vector<std::string>* roles_out) const {
    std::scoped_lock lock(mutex_);
    expire_sessions_locked(std::chrono::system_clock::now());
    auto it = sessions_.find(session_token);
    if (it == sessions_.end() || it->second.csrf_token != csrf_token) {
        return false;
    }

    if (actor_out != nullptr) {
        *actor_out = it->second.email;
    }
    if (roles_out != nullptr) {
        *roles_out = it->second.roles;
    }
    return true;
}

void PlatformState::logout(const std::string& session_token) {
    std::scoped_lock lock(mutex_);
    sessions_.erase(session_token);
}

bool PlatformState::create_dns_zone(const std::string& zone_name, const std::string& actor) {
    if (!is_valid_zone_name(zone_name)) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    const auto existing = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (existing != zones_.end()) {
        return false;
    }

    zones_.push_back({zone_name, default_zone_serial(), {}});
    persist_dns_zone_to_database(zones_.back(), config_.database_url);
    jobs_.enqueue("dns", "Create zone " + zone_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "zone.created", zone_name});
    revision_ += 1;
    return true;
}

bool PlatformState::update_dns_zone(const std::string& zone_name, const std::string& new_name, const std::string& actor) {
    if (!is_valid_zone_name(new_name)) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    auto target = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (target == zones_.end()) {
        return false;
    }

    if (zone_name != new_name) {
        const auto duplicate = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == new_name; });
        if (duplicate != zones_.end()) {
            return false;
        }
    }

    target->name = new_name;
    target->serial += 1;
    persist_dns_zone_to_database(*target, config_.database_url);
    if (zone_name != new_name) {
        delete_dns_zone_from_database(zone_name, config_.database_url);
    }
    jobs_.enqueue("dns", "Rename zone " + zone_name + " to " + new_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "zone.updated", zone_name + " -> " + new_name});
    revision_ += 1;
    return true;
}

bool PlatformState::delete_dns_zone(const std::string& zone_name, const std::string& actor) {
    std::scoped_lock lock(mutex_);
    const auto it = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (it == zones_.end()) {
        return false;
    }

    zones_.erase(it);
    delete_dns_zone_from_database(zone_name, config_.database_url);
    jobs_.enqueue("dns", "Delete zone " + zone_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "zone.deleted", zone_name});
    revision_ += 1;
    return true;
}

bool PlatformState::add_dns_record(
    const std::string& zone_name,
    const nexus::core::DnsRecord& record,
    const std::string& actor) {
    std::scoped_lock lock(mutex_);
    auto it = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (it == zones_.end()) {
        return false;
    }

    it->records.push_back(record);
    it->serial += 1;
    persist_dns_zone_to_database(*it, config_.database_url);
    jobs_.enqueue("dns", "Apply zone update for " + zone_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "record.created", record.name + " " + record.type});
    revision_ += 1;
    return true;
}

bool PlatformState::update_dns_record(
    const std::string& zone_name,
    std::size_t record_index,
    const nexus::core::DnsRecord& record,
    const std::string& actor) {
    std::scoped_lock lock(mutex_);
    auto it = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (it == zones_.end() || record_index >= it->records.size()) {
        return false;
    }

    it->records[record_index] = record;
    it->serial += 1;
    persist_dns_zone_to_database(*it, config_.database_url);
    jobs_.enqueue("dns", "Update record in " + zone_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "record.updated", zone_name + " #" + std::to_string(record_index)});
    revision_ += 1;
    return true;
}

bool PlatformState::delete_dns_record(const std::string& zone_name, std::size_t record_index, const std::string& actor) {
    std::scoped_lock lock(mutex_);
    auto it = std::find_if(zones_.begin(), zones_.end(), [&](const auto& zone) { return zone.name == zone_name; });
    if (it == zones_.end() || record_index >= it->records.size()) {
        return false;
    }

    it->records.erase(it->records.begin() + static_cast<std::ptrdiff_t>(record_index));
    it->serial += 1;
    persist_dns_zone_to_database(*it, config_.database_url);
    jobs_.enqueue("dns", "Delete record in " + zone_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "record.deleted", zone_name + " #" + std::to_string(record_index)});
    revision_ += 1;
    return true;
}

bool PlatformState::restart_dns_service(const std::string& actor) {
    std::scoped_lock lock(mutex_);
    // Persist current state before restarting
    if (!persist_settings(config_)) {
        return false;
    }
    
    // Record audit event for restart
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dns", "service.restarted", "DNS service restart requested"});
    jobs_.enqueue("dns", "DNS service restart");
    revision_ += 1;
    
    // Note: The actual systemctl restart is handled at the system level
    // This just records the request and persists state
    return true;
}

bool PlatformState::restart_dhcp_service(const std::string& actor) {
    std::scoped_lock lock(mutex_);
    // Persist current state before restarting
    if (!persist_settings(config_)) {
        return false;
    }
    
    // Record audit event for restart
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dhcp", "service.restarted", "DHCP service restart requested"});
    jobs_.enqueue("dhcp", "DHCP service restart");
    revision_ += 1;
    
    // Note: The actual systemctl restart is handled at the system level
    // This just records the request and persists state
    return true;
}

bool PlatformState::sync_feature_flags_to_database(const nexus::core::Config& config) const {
    PGconn* connection = connect_database(config.database_url);
    if (connection == nullptr) {
        return true;
    }

    const bool ok = sync_feature_flags(connection, config.features);
    PQfinish(connection);
    return ok;
}

bool PlatformState::load_feature_flags_from_database() {
    PGconn* connection = connect_database(config_.database_url);
    if (connection == nullptr) {
        return false;
    }

    const auto flags = load_feature_flags(connection);
    PQfinish(connection);
    if (flags.empty()) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    config_.features = flags;
    return true;
}

bool PlatformState::create_directory_object(
    nexus::core::DirectoryObject object,
    const std::string& password,
    const std::string& actor) {
    if (!nexus::protocol::is_valid_dn(object.dn) || object.kind.empty() || object.object_classes.empty()) {
        return false;
    }
    if (!object.parent_dn.empty() && !nexus::protocol::is_valid_dn(object.parent_dn)) {
        return false;
    }
    if (!password.empty()) {
        object.attributes["userPasswordHash"] = password_hasher_.hash_password(password);
    }

    persist_directory_object_to_database(object, config_.database_url);

    std::scoped_lock lock(mutex_);
    const auto duplicate = std::find_if(directory_.begin(), directory_.end(), [&](const auto& current) { return current.dn == object.dn; });
    if (duplicate != directory_.end()) {
        return false;
    }
    directory_.push_back(std::move(object));
    jobs_.enqueue("directory", "Create object " + directory_.back().dn);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "directory", "object.created", directory_.back().dn});
    revision_ += 1;
    return true;
}

bool PlatformState::update_directory_object(
    const std::string& dn,
    nexus::core::DirectoryObject object,
    const std::string& password,
    const std::string& actor) {
    if (!nexus::protocol::is_valid_dn(dn) || !nexus::protocol::is_valid_dn(object.dn) || object.kind.empty() || object.object_classes.empty()) {
        return false;
    }
    if (!object.parent_dn.empty() && !nexus::protocol::is_valid_dn(object.parent_dn)) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    auto it = std::find_if(directory_.begin(), directory_.end(), [&](const auto& current) { return current.dn == dn; });
    if (it == directory_.end()) {
        return false;
    }
    if (dn != object.dn) {
        const auto duplicate = std::find_if(directory_.begin(), directory_.end(), [&](const auto& current) { return current.dn == object.dn; });
        if (duplicate != directory_.end()) {
            return false;
        }
    }
    if (password.empty()) {
        const auto existing_hash = it->attributes.find("userPasswordHash");
        if (existing_hash != it->attributes.end() && object.attributes.find("userPasswordHash") == object.attributes.end()) {
            object.attributes["userPasswordHash"] = existing_hash->second;
        }
    } else {
        object.attributes["userPasswordHash"] = password_hasher_.hash_password(password);
    }

    persist_directory_object_to_database(object, config_.database_url);
    if (dn != object.dn) {
        delete_directory_object_from_database(dn, config_.database_url);
    }

    *it = std::move(object);
    jobs_.enqueue("directory", "Update object " + dn);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "directory", "object.updated", dn});
    revision_ += 1;
    return true;
}

bool PlatformState::delete_directory_object(const std::string& dn, const std::string& actor) {
    std::scoped_lock lock(mutex_);
    const auto it = std::find_if(directory_.begin(), directory_.end(), [&](const auto& current) { return current.dn == dn; });
    if (it == directory_.end()) {
        return false;
    }
    delete_directory_object_from_database(dn, config_.database_url);
    directory_.erase(it);
    jobs_.enqueue("directory", "Delete object " + dn);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "directory", "object.deleted", dn});
    revision_ += 1;
    return true;
}

bool PlatformState::create_dhcp_pool(const nexus::core::DhcpPool& pool, const std::string& actor) {
    if (pool.name.empty() || pool.subnet.empty() || pool.range_start.empty() || pool.range_end.empty()) {
        return false;
    }

    // Try to persist to database first; if DB not configured, fallback to runtime-only
    std::string db_err;
    if (!config_.database_url.empty()) {
        if (!persist_dhcp_pool_to_database(pool, config_.database_url, &db_err)) {
            std::cerr << "[nexus-api] failed to persist dhcp pool to database: " << db_err << '\n';
            // continue and keep runtime state so UI still reflects the change
        }
    }

    std::scoped_lock lock(mutex_);
    const auto duplicate = std::find_if(pools_.begin(), pools_.end(), [&](const auto& current) { return current.name == pool.name; });
    if (duplicate != pools_.end()) {
        return false;
    }

    pools_.push_back(pool);
    jobs_.enqueue("dhcp", "Create pool " + pool.name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dhcp", "pool.created", pool.name});
    revision_ += 1;
    return true;
}

bool PlatformState::update_dhcp_pool(const std::string& pool_name, const nexus::core::DhcpPool& pool, const std::string& actor) {
    if (pool.name.empty() || pool.subnet.empty() || pool.range_start.empty() || pool.range_end.empty()) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    auto it = std::find_if(pools_.begin(), pools_.end(), [&](const auto& current) { return current.name == pool_name; });
    if (it == pools_.end()) {
        return false;
    }

    if (pool_name != pool.name) {
        const auto duplicate = std::find_if(pools_.begin(), pools_.end(), [&](const auto& current) { return current.name == pool.name; });
        if (duplicate != pools_.end()) {
            return false;
        }
    }

    // Persist update to database if configured
    std::string db_err;
    if (!config_.database_url.empty()) {
        if (!persist_dhcp_pool_to_database(pool, config_.database_url, &db_err)) {
            std::cerr << "[nexus-api] failed to persist dhcp pool update to database: " << db_err << '\n';
            // still continue with runtime update
        }
    }

    *it = pool;
    jobs_.enqueue("dhcp", "Update pool " + pool_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dhcp", "pool.updated", pool_name + " -> " + pool.name});
    revision_ += 1;
    return true;
}

bool PlatformState::delete_dhcp_pool(const std::string& pool_name, const std::string& actor) {
    std::scoped_lock lock(mutex_);
    const auto it = std::find_if(pools_.begin(), pools_.end(), [&](const auto& current) { return current.name == pool_name; });
    if (it == pools_.end()) {
        return false;
    }

    // Delete from DB if configured
    if (!config_.database_url.empty()) {
        PGconn* conn = PQconnectdb(config_.database_url.c_str());
        if (PQstatus(conn) == CONNECTION_OK) {
            char* name_esc = PQescapeLiteral(conn, pool_name.c_str(), static_cast<unsigned long>(pool_name.size()));
            if (name_esc) {
                std::string sql = "DELETE FROM dhcp_pools WHERE name = " + std::string(name_esc) + ";";
                PGresult* res = PQexec(conn, sql.c_str());
                if (PQresultStatus(res) != PGRES_COMMAND_OK) {
                    std::cerr << "[nexus-api] failed to delete dhcp pool from database: " << PQresultErrorMessage(res) << '\n';
                }
                PQclear(res);
                PQfreemem(name_esc);
            }
            PQfinish(conn);
        } else {
            PQfinish(conn);
            std::cerr << "[nexus-api] could not connect to database to delete dhcp pool" << '\n';
        }
    }

    pools_.erase(it);
    jobs_.enqueue("dhcp", "Delete pool " + pool_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "dhcp", "pool.deleted", pool_name});
    revision_ += 1;
    return true;
}

bool PlatformState::create_pki_authority(
    const std::string& name,
    const nexus::security::CertificateSubject& subject,
    int days_valid,
    const std::string& actor) {
    if (name.empty() || subject.common_name.empty() || subject.organization.empty() || days_valid <= 0) {
        return false;
    }

    nexus::security::PkiService pki;
    const auto issued = pki.create_root_ca(subject, days_valid);
    nexus::core::PkiAuthority authority{
        name,
        subject.common_name,
        subject.organization,
        issued.serial_hex,
        issued.certificate_pem,
        issued.private_key_pem,
        nexus::core::utc_timestamp()};

    persist_pki_authority_to_database(authority, config_.database_url);

    std::scoped_lock lock(mutex_);
    const auto duplicate = std::find_if(authorities_.begin(), authorities_.end(), [&](const auto& current) { return current.name == name; });
    if (duplicate != authorities_.end()) {
        return false;
    }
    authorities_.push_back(std::move(authority));
    jobs_.enqueue("pki", "Create authority " + name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "pki", "authority.created", name});
    revision_ += 1;
    return true;
}

bool PlatformState::issue_pki_certificate(
    const std::string& authority_name,
    const nexus::security::CertificateSubject& subject,
    int days_valid,
    const std::string& actor) {
    if (authority_name.empty() || subject.common_name.empty() || subject.organization.empty() || days_valid <= 0) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    const auto authority = std::find_if(authorities_.begin(), authorities_.end(), [&](const auto& current) { return current.name == authority_name; });
    if (authority == authorities_.end()) {
        return false;
    }

    nexus::security::PkiService pki;
    const nexus::security::IssuedCertificate issuing_ca{
        authority->serial_hex,
        authority->certificate_pem,
        authority->private_key_pem};
    const auto issued = pki.issue_leaf_certificate(issuing_ca, subject, days_valid);
    nexus::core::PkiCertificate certificate{
        issued.serial_hex,
        authority_name,
        subject.common_name,
        subject.organization,
        subject.dns_subject_alternative_names,
        issued.certificate_pem,
        issued.private_key_pem,
        false,
        nexus::core::utc_timestamp()};

    persist_pki_certificate_to_database(certificate, config_.database_url);

    certificates_.push_back(std::move(certificate));
    jobs_.enqueue("pki", "Issue certificate " + subject.common_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "pki", "certificate.issued", subject.common_name});
    revision_ += 1;
    return true;
}

bool PlatformState::revoke_certificate(
    const std::string& serial,
    const std::string& common_name,
    const std::string& reason,
    const std::string& actor) {
    if (serial.empty() || reason.empty()) {
        return false;
    }

    std::scoped_lock lock(mutex_);
    auto certificate = std::find_if(certificates_.begin(), certificates_.end(), [&](const auto& current) { return current.serial_hex == serial; });
    if (certificate != certificates_.end()) {
        certificate->revoked = true;
    }
    const auto duplicate = std::find_if(revocations_.begin(), revocations_.end(), [&](const auto& current) { return current.serial == serial; });
    if (duplicate != revocations_.end()) {
        return false;
    }
    const auto resolved_common_name = !common_name.empty() ? common_name : (certificate != certificates_.end() ? certificate->common_name : "");
    nexus::core::PkiRevocation revocation{serial, resolved_common_name, reason, nexus::core::utc_timestamp()};
    persist_pki_revocation_to_database(revocation, config_.database_url);
    revocations_.push_back(std::move(revocation));
    jobs_.enqueue("pki", "Publish CRL for serial " + serial);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "pki", "certificate.revoked", serial + " " + reason});
    revision_ += 1;
    return true;
}

bool PlatformState::create_apt_repository(
    const std::string& distribution,
    const std::string& component,
    const std::string& actor) {
    if (distribution.empty() || component.empty()) {
        return false;
    }
    nexus::core::AptRepository repository{distribution, component, {}};
    persist_apt_repository_to_database(repository, config_.database_url);
    std::scoped_lock lock(mutex_);
    const auto duplicate = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (duplicate != repositories_.end()) {
        return false;
    }
    repositories_.push_back(std::move(repository));
    jobs_.enqueue("repo", "Create repository " + distribution + "/" + component);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "repo", "repository.created", distribution + "/" + component});
    revision_ += 1;
    return true;
}

bool PlatformState::delete_apt_repository(
    const std::string& distribution,
    const std::string& component,
    const std::string& actor) {
    std::scoped_lock lock(mutex_);
    const auto it = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (it == repositories_.end()) {
        return false;
    }
    delete_apt_repository_from_database(distribution, component, config_.database_url);
    repositories_.erase(it);
    jobs_.enqueue("repo", "Delete repository " + distribution + "/" + component);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "repo", "repository.deleted", distribution + "/" + component});
    revision_ += 1;
    return true;
}

bool PlatformState::add_apt_package(
    const std::string& distribution,
    const std::string& component,
    const nexus::core::AptPackage& package,
    const std::string& actor) {
    if (package.name.empty() || package.version.empty() || package.architecture.empty() || package.filename.empty() || package.sha256.empty() || package.size == 0) {
        return false;
    }
    std::scoped_lock lock(mutex_);
    auto repository = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (repository == repositories_.end()) {
        return false;
    }
    auto stored = package;
    stored.component = component;
    persist_apt_package_to_database(distribution, component, stored, config_.database_url);
    repository->packages.push_back(stored);
    jobs_.enqueue("repo", "Add package " + package.name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "repo", "package.created", package.name + " " + package.version});
    revision_ += 1;
    return true;
}

bool PlatformState::update_apt_package(
    const std::string& distribution,
    const std::string& component,
    std::size_t package_index,
    const nexus::core::AptPackage& package,
    const std::string& actor) {
    if (package.name.empty() || package.version.empty() || package.architecture.empty() || package.filename.empty() || package.sha256.empty() || package.size == 0) {
        return false;
    }
    std::scoped_lock lock(mutex_);
    auto repository = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (repository == repositories_.end() || package_index >= repository->packages.size()) {
        return false;
    }
    auto stored = package;
    stored.component = component;
    repository->packages[package_index] = stored;
    persist_apt_package_to_database(distribution, component, stored, config_.database_url);
    jobs_.enqueue("repo", "Update package " + package.name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "repo", "package.updated", package.name + " " + package.version});
    revision_ += 1;
    return true;
}

bool PlatformState::delete_apt_package(
    const std::string& distribution,
    const std::string& component,
    std::size_t package_index,
    const std::string& actor) {
    std::scoped_lock lock(mutex_);
    auto repository = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (repository == repositories_.end() || package_index >= repository->packages.size()) {
        return false;
    }
    const auto package_name = repository->packages[package_index].name;
    repository->packages.erase(repository->packages.begin() + static_cast<std::ptrdiff_t>(package_index));
    jobs_.enqueue("repo", "Delete package " + package_name);
    audit_events_.push_back({nexus::core::utc_timestamp(), actor, "repo", "package.deleted", package_name});
    revision_ += 1;
    return true;
}

std::optional<std::string> PlatformState::render_apt_packages(
    const std::string& distribution,
    const std::string& component) const {
    std::scoped_lock lock(mutex_);
    const auto repository = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (repository == repositories_.end()) {
        return std::nullopt;
    }
    return nexus::protocol::render_packages_index(*repository);
}

std::optional<std::string> PlatformState::render_apt_release(
    const std::string& distribution,
    const std::string& component) const {
    std::scoped_lock lock(mutex_);
    const auto repository = std::find_if(repositories_.begin(), repositories_.end(), [&](const auto& current) {
        return current.distribution == distribution && current.component == component;
    });
    if (repository == repositories_.end()) {
        return std::nullopt;
    }
    const auto packages = nexus::protocol::render_packages_index(*repository);
    return nexus::protocol::render_release_file(*repository, config_.repo.origin, distribution, sha256_hex(packages), packages.size());
}

void PlatformState::initialize_runtime_state() {
    std::scoped_lock lock(mutex_);
    services_ = make_services(config_);
    ad_domain_ = load_active_directory_domain_from_database(config_.database_url);
    directory_ = load_directory_objects_from_database(config_.database_url);
    zones_ = load_dns_zones_from_database(config_.database_url);
    pools_.clear();
    authorities_.clear();
    certificates_.clear();
    revocations_.clear();
    repositories_.clear();
    audit_events_ = {
        {nexus::core::utc_timestamp(), "system", "bootstrap", "platform.started", "Runtime initialized without demo seed data"},
    };
    revision_ = 1;
}

std::filesystem::path PlatformState::settings_file_path() const {
    return config_.state_root / "settings.json";
}

bool PlatformState::load_persisted_settings() {
    const auto path = settings_file_path();
    if (!std::filesystem::exists(path)) {
        return false;
    }

    std::ifstream input(path);
    if (!input.is_open()) {
        return false;
    }

    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    Json::Value body;
    std::string errors;
    if (!Json::parseFromStream(builder, input, &body, &errors)) {
        std::cerr << "[nexus-api] failed to read persisted settings: " << errors << '\n';
        return false;
    }

    config_ = config_from_json_value(config_, body);
    return true;
}

bool PlatformState::persist_settings(const nexus::core::Config& config) const {
    std::error_code error_code;
    std::filesystem::create_directories(config.state_root, error_code);
    if (error_code) {
        std::cerr << "[nexus-api] failed to create state root: " << error_code.message() << '\n';
        return false;
    }

    const auto path = config.state_root / "settings.json";
    const auto temp_path = path.string() + ".tmp";

    std::ofstream output(temp_path, std::ios::trunc);
    if (!output.is_open()) {
        std::cerr << "[nexus-api] failed to open settings file for writing\n";
        return false;
    }

    Json::StreamWriterBuilder builder;
    builder["indentation"] = "  ";
    output << Json::writeString(builder, config_to_json_value(config));
    output.close();
    if (!output) {
        std::cerr << "[nexus-api] failed to flush settings file\n";
        return false;
    }

    std::filesystem::rename(temp_path, path, error_code);
    if (error_code) {
        std::filesystem::remove(temp_path);
        std::cerr << "[nexus-api] failed to persist settings: " << error_code.message() << '\n';
        return false;
    }

    return true;
}

void PlatformState::record_audit(std::string actor, std::string domain, std::string action, std::string detail) {
    std::scoped_lock lock(mutex_);
    record_audit_locked(std::move(actor), std::move(domain), std::move(action), std::move(detail));
}

void PlatformState::record_audit_locked(std::string actor, std::string domain, std::string action, std::string detail) {
    audit_events_.push_back({nexus::core::utc_timestamp(), std::move(actor), std::move(domain), std::move(action), std::move(detail)});
    revision_ += 1;
}

void PlatformState::expire_sessions_locked(std::chrono::system_clock::time_point now) const {
    auto* sessions = const_cast<std::unordered_map<std::string, Session>*>(&sessions_);
    for (auto it = sessions->begin(); it != sessions->end();) {
        if (it->second.expires_at <= now) {
            it = sessions->erase(it);
        } else {
            ++it;
        }
    }
}

std::string PlatformState::random_token(std::size_t bytes) {
    std::vector<unsigned char> buffer(bytes);
    RAND_bytes(buffer.data(), static_cast<int>(buffer.size()));
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (unsigned char byte : buffer) {
        output << std::setw(2) << static_cast<int>(byte);
    }
    return output.str();
}

}  // namespace nexus::api
