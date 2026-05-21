#include "nexus/core/config.hpp"
#include "nexus/core/uv_runtime.hpp"
#include "nexus/protocol/kerberos.hpp"
#include "nexus/protocol/ldap.hpp"
#include "nexus/security/ad_crypto.hpp"

#include <json/json.h>
#include <libpq-fe.h>

#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::vector<nexus::protocol::KerberosKey> parse_wrapped_kerberos_keys(
    const nexus::core::Config& config,
    const std::string& wrapped_keys_json) {
    Json::CharReaderBuilder builder;
    Json::Value keys;
    std::string errors;
    std::istringstream input(wrapped_keys_json.empty() ? "{}" : wrapped_keys_json);
    if (!Json::parseFromStream(builder, input, &keys, &errors) || !keys.isObject()) {
        return {};
    }

    std::vector<nexus::protocol::KerberosKey> parsed;
    for (const auto& enctype_name : keys.getMemberNames()) {
        const auto& node = keys[enctype_name];
        if (!node.isObject()) {
            continue;
        }
        const auto wrapped = node.get("wrapped", "").asString();
        if (wrapped.empty()) {
            continue;
        }
        auto key_hex = nexus::security::open_ad_secret(config.directory.key_encryption_key_file, wrapped);
        if (!key_hex.has_value()) {
            continue;
        }
        parsed.push_back({
            0,
            enctype_name,
            node.get("salt", "").asString(),
            *key_hex,
        });
    }
    return parsed;
}

void add_principal_alias(
    std::vector<nexus::protocol::KerberosPrincipal>& principals,
    const std::string& name,
    const std::string& realm,
    const std::vector<nexus::protocol::KerberosKey>& keys) {
    if (name.empty()) {
        return;
    }
    principals.push_back({name, realm, !keys.empty(), keys});
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

std::vector<nexus::protocol::LdapObject> load_ldap_objects(const nexus::core::Config& config) {
    if (config.database_url.empty()) {
        return {};
    }

    PGconn* conn = PQconnectdb(config.database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "[nexus-directory] database unavailable; LDAP object directory is empty\n";
        PQfinish(conn);
        return {};
    }

    PGresult* result = PQexec(
        conn,
        "select dn,parent_dn,kind,object_classes::text,attributes::text "
        "from identity_objects "
        "order by dn");

    std::vector<nexus::protocol::LdapObject> objects;
    if (PQresultStatus(result) == PGRES_TUPLES_OK) {
        for (int index = 0; index < PQntuples(result); ++index) {
            objects.push_back({
                PQgetvalue(result, index, 0),
                PQgetisnull(result, index, 1) ? "" : PQgetvalue(result, index, 1),
                PQgetvalue(result, index, 2),
                json_array_from_string(PQgetvalue(result, index, 3)),
                json_object_from_string(PQgetvalue(result, index, 4)),
            });
        }
    } else {
        std::cerr << "[nexus-directory] failed to load LDAP objects: " << PQresultErrorMessage(result) << '\n';
    }

    PQclear(result);
    PQfinish(conn);
    return objects;
}

std::vector<nexus::protocol::KerberosPrincipal> load_kerberos_principals(const nexus::core::Config& config) {
    if (config.database_url.empty()) {
        return {};
    }

    PGconn* conn = PQconnectdb(config.database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "[nexus-directory] database unavailable; KDC principal directory is empty\n";
        PQfinish(conn);
        return {};
    }

    PGresult* result = PQexec(
        conn,
        "select "
        "  attributes->>'sAMAccountName', "
        "  attributes->>'userPrincipalName', "
        "  coalesce(s.wrapped_kerberos_keys::text, '{}') "
        "from identity_objects o "
        "left join ad_account_secrets s on s.object_dn = o.dn "
        "where attributes ? 'sAMAccountName' "
        "order by o.dn");

    std::vector<nexus::protocol::KerberosPrincipal> principals;
    if (PQresultStatus(result) == PGRES_TUPLES_OK) {
        for (int index = 0; index < PQntuples(result); ++index) {
            const std::string sam = PQgetvalue(result, index, 0);
            const std::string upn = PQgetisnull(result, index, 1) ? "" : PQgetvalue(result, index, 1);
            const std::string wrapped_keys = PQgetisnull(result, index, 2) ? "{}" : PQgetvalue(result, index, 2);
            const auto keys = parse_wrapped_kerberos_keys(config, wrapped_keys);
            add_principal_alias(principals, sam, config.directory.realm, keys);
            add_principal_alias(principals, upn, config.directory.realm, keys);
        }
    } else {
        std::cerr << "[nexus-directory] failed to load KDC principals: " << PQresultErrorMessage(result) << '\n';
    }

    PQclear(result);
    PQfinish(conn);
    return principals;
}

}  // namespace

int main() {
    const auto config = nexus::core::Config::from_env();
    const nexus::protocol::LdapDirectoryInfo directory{
        config.domain,
        config.directory.base_dn,
        config.directory.realm,
        config.directory.site_name,
        config.directory.domain_controller_host,
        config.directory.domain_controller_address,
    };

    const auto ldap_objects = load_ldap_objects(config);
    auto ldap_handler = [directory, ldap_objects](const std::string&, const nexus::core::UvPacket& packet) {
        return nexus::protocol::ldap_ad_response(packet, directory, ldap_objects);
    };
    const nexus::protocol::KerberosRealmInfo kerberos_realm{
        config.directory.realm,
        "krbtgt",
        load_kerberos_principals(config),
    };
    auto kerberos_udp_handler = [kerberos_realm](const std::string&, const nexus::core::UvPacket& packet) {
        return nexus::protocol::kerberos_error_response(packet, kerberos_realm);
    };
    auto kerberos_tcp_handler = [kerberos_realm](const std::string&, const nexus::core::UvPacket& packet) {
        return nexus::protocol::kerberos_tcp_error_response(packet, kerberos_realm);
    };

    return nexus::core::run_uv_daemon(
        "directory",
        {
            {"ldap", config.ldap.host, config.ldap.port, nexus::core::UvTransport::tcp, ldap_handler},
            {"cldap", config.ldap.host, config.ldap.port, nexus::core::UvTransport::udp, ldap_handler},
            {"ldaps", config.ldaps.host, config.ldaps.port, nexus::core::UvTransport::tcp},
            {"global-catalog", config.global_catalog.host, config.global_catalog.port, nexus::core::UvTransport::tcp, ldap_handler},
            {"kerberos-tcp", config.kerberos.host, config.kerberos.port, nexus::core::UvTransport::tcp, kerberos_tcp_handler},
            {"kerberos-udp", config.kerberos.host, config.kerberos.port, nexus::core::UvTransport::udp, kerberos_udp_handler},
            {"kpasswd-tcp", config.kpasswd.host, config.kpasswd.port, nexus::core::UvTransport::tcp},
            {"kpasswd-udp", config.kpasswd.host, config.kpasswd.port, nexus::core::UvTransport::udp},
            {"rpc-endpoint-mapper", config.rpc_endpoint_mapper.host, config.rpc_endpoint_mapper.port, nexus::core::UvTransport::tcp},
            {"smb", config.smb.host, config.smb.port, nexus::core::UvTransport::tcp},
        });
}
