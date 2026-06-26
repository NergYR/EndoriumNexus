#include "nexus/core/config.hpp"
#include "nexus/core/uv_runtime.hpp"
#include "nexus/protocol/kerberos.hpp"
#include "nexus/protocol/ldap.hpp"
#include "nexus/protocol/rpc.hpp"
#include "nexus/protocol/smb.hpp"
#include "nexus/security/ad_crypto.hpp"

#include <json/json.h>
#include <libpq-fe.h>

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdint>
#include <exception>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string sql_literal(PGconn* connection, const std::string& value);
bool persist_ad_account_secret(
    PGconn* conn,
    const nexus::core::Config& config,
    const std::string& object_dn,
    const std::string& sam,
    const std::string& password,
    const std::string& source);

std::filesystem::path kerberos_key_file(const nexus::core::Config& config) {
    if (!config.directory.key_encryption_key_file.empty()) {
        return config.directory.key_encryption_key_file;
    }
    return config.state_root / "ad" / "kerberos_keys.hex";
}

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
        auto key_hex = nexus::security::open_ad_secret(kerberos_key_file(config), wrapped);
        if (!key_hex.has_value()) {
            continue;
        }
        parsed.push_back(nexus::protocol::KerberosKey{
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
    const std::vector<nexus::protocol::KerberosKey>& keys,
    const std::string& object_sid = "",
    std::uint32_t rid = 0,
    std::uint32_t primary_group_rid = 513,
    const std::vector<std::uint32_t>& group_rids = {},
    const std::string& display_name = "",
    std::uint32_t user_account_control = 0,
    bool account_expired = false) {
    if (name.empty()) {
        return;
    }
    principals.push_back({
        name,
        realm,
        !keys.empty(),
        keys,
        object_sid,
        rid,
        primary_group_rid,
        group_rids,
        display_name,
        user_account_control,
        account_expired,
    });
}

std::vector<std::string> split_multi_value_attribute(const std::string& value) {
    std::vector<std::string> result;
    std::string current;
    for (const auto ch : value) {
        if (ch == ',' || ch == ';' || ch == '\n' || ch == '\r' || ch == '\t') {
            if (!current.empty()) {
                result.push_back(current);
                current.clear();
            }
            continue;
        }
        current.push_back(ch);
    }
    if (!current.empty()) {
        result.push_back(current);
    }
    return result;
}

std::string trim_copy(const std::string& value) {
    const auto first = value.find_first_not_of(' ');
    if (first == std::string::npos) {
        return "";
    }
    const auto last = value.find_last_not_of(' ');
    return value.substr(first, last - first + 1);
}

std::string join_multi_value_attribute(const std::vector<std::string>& values) {
    std::string joined;
    for (const auto& value : values) {
        const auto trimmed = trim_copy(value);
        if (trimmed.empty()) {
            continue;
        }
        if (!joined.empty()) {
            joined.push_back(',');
        }
        joined += trimmed;
    }
    return joined;
}

std::string lowercase_ascii(std::string value) {
    for (auto& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

std::string uppercase_ascii(std::string value) {
    for (auto& ch : value) {
        ch = static_cast<char>(std::toupper(static_cast<unsigned char>(ch)));
    }
    return value;
}

std::uint32_t stable_hash32(const std::string& value) {
    std::uint32_t hash = 2166136261U;
    for (const auto ch : value) {
        hash ^= static_cast<std::uint8_t>(ch);
        hash *= 16777619U;
    }
    return hash;
}

std::string synthetic_domain_sid(const std::string& domain) {
    const auto lower = lowercase_ascii(domain);
    const auto a = 1000U + (stable_hash32(lower + ":a") % 1000000000U);
    const auto b = 1000U + (stable_hash32(lower + ":b") % 1000000000U);
    const auto c = 1000U + (stable_hash32(lower + ":c") % 1000000000U);
    return "S-1-5-21-" + std::to_string(a) + "-" + std::to_string(b) + "-" + std::to_string(c);
}

std::uint32_t synthetic_rid(const std::string& sam_account_name) {
    const auto normalized = lowercase_ascii(sam_account_name);
    if (normalized == "administrator") {
        return 500;
    }
    if (normalized == "guest") {
        return 501;
    }
    if (normalized == "krbtgt") {
        return 502;
    }
    return 1000U + (stable_hash32(normalized) % 900000U);
}

std::string netbios_name_from_domain(const std::string& domain) {
    const auto dot = domain.find('.');
    auto name = dot == std::string::npos ? domain : domain.substr(0, dot);
    if (name.empty()) {
        name = "ENDORIUM";
    }
    return uppercase_ascii(name);
}

std::string machine_host_from_sam(std::string sam) {
    if (!sam.empty() && sam.back() == '$') {
        sam.pop_back();
    }
    return lowercase_ascii(sam);
}

std::string machine_spn_attribute(const std::string& host, const std::string& dns_host) {
    std::vector<std::string> spns;
    const auto add_spn = [&](const std::string& value) {
        if (value.empty()) {
            return;
        }
        const auto normalized = lowercase_ascii(value);
        const auto exists = std::any_of(spns.begin(), spns.end(), [&](const auto& current) {
            return lowercase_ascii(current) == normalized;
        });
        if (!exists) {
            spns.push_back(value);
        }
    };
    for (const auto& service : {"HOST", "RestrictedKrbHost", "LDAP", "CIFS"}) {
        if (!host.empty()) {
            add_spn(std::string(service) + "/" + host);
        }
        if (!dns_host.empty()) {
            add_spn(std::string(service) + "/" + dns_host);
        }
    }

    std::string joined;
    for (const auto& spn : spns) {
        if (!joined.empty()) {
            joined.push_back(',');
        }
        joined += spn;
    }
    return joined;
}

std::string merge_machine_spn_attribute(
    const std::string& existing,
    const std::string& host,
    const std::string& dns_host) {
    std::vector<std::string> spns;
    const auto add_spn = [&](const std::string& value) {
        const auto trimmed = trim_copy(value);
        if (trimmed.empty()) {
            return;
        }
        const auto normalized = lowercase_ascii(trimmed);
        const auto exists = std::any_of(spns.begin(), spns.end(), [&](const auto& current) {
            return lowercase_ascii(current) == normalized;
        });
        if (!exists) {
            spns.push_back(trimmed);
        }
    };
    for (const auto& spn : split_multi_value_attribute(existing)) {
        add_spn(spn);
    }
    for (const auto& spn : split_multi_value_attribute(machine_spn_attribute(host, dns_host))) {
        add_spn(spn);
    }
    return join_multi_value_attribute(spns);
}

std::uint32_t parse_u32_or(const std::string& value, std::uint32_t fallback) {
    if (value.empty()) {
        return fallback;
    }
    try {
        return static_cast<std::uint32_t>(std::stoul(value));
    } catch (...) {
        return fallback;
    }
}

std::vector<std::uint32_t> parse_u32_list(const std::string& value) {
    std::vector<std::uint32_t> result;
    for (const auto& item : split_multi_value_attribute(value)) {
        const auto trimmed = trim_copy(item);
        if (trimmed.empty()) {
            continue;
        }
        try {
            result.push_back(static_cast<std::uint32_t>(std::stoul(trimmed)));
        } catch (...) {
        }
    }
    return result;
}

std::vector<std::string> split_ldap_member_dns(const std::string& value) {
    std::vector<std::string> result;
    std::string current;
    for (const auto ch : value) {
        if (ch == ';' || ch == '\n' || ch == '\r' || ch == '\t') {
            const auto trimmed = trim_copy(current);
            if (!trimmed.empty()) {
                result.push_back(trimmed);
            }
            current.clear();
            continue;
        }
        current.push_back(ch);
    }
    const auto trimmed = trim_copy(current);
    if (!trimmed.empty()) {
        result.push_back(trimmed);
    }
    return result;
}

std::string current_ad_filetime_string() {
    constexpr std::int64_t windows_epoch_offset_ticks = 116444736000000000LL;
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto ticks_since_unix_epoch = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count() / 100LL;
    return std::to_string(windows_epoch_offset_ticks + ticks_since_unix_epoch);
}

bool ad_account_expired(const std::string& account_expires) {
    if (account_expires.empty()) {
        return false;
    }
    try {
        const auto expires = std::stoull(account_expires);
        constexpr std::uint64_t never_expires = 0x7fffffffffffffffULL;
        if (expires == 0 || expires >= never_expires) {
            return false;
        }
        const auto now = std::stoull(current_ad_filetime_string());
        return expires <= now;
    } catch (...) {
        return false;
    }
}

void stamp_ad_password_metadata(
    std::map<std::string, std::string>& attributes,
    const std::string& sam_account_name) {
    attributes["pwdLastSet"] = current_ad_filetime_string();
    attributes["badPwdCount"] = "0";
    const auto normalized_sam = lowercase_ascii(sam_account_name);
    if (!normalized_sam.empty() && normalized_sam.back() == '$') {
        const auto uac = parse_u32_or(attributes["userAccountControl"], 0);
        constexpr std::uint32_t user_account_control_passwd_notreqd = 0x00000020U;
        constexpr std::uint32_t user_account_control_workstation_trust = 0x00001000U;
        if ((uac & user_account_control_workstation_trust) != 0 &&
            (uac & user_account_control_passwd_notreqd) != 0) {
            attributes["userAccountControl"] = std::to_string(uac & ~user_account_control_passwd_notreqd);
        }
    }
}

bool stamp_ad_password_metadata_to_database(PGconn* conn, const std::string& object_dn) {
    if (object_dn.empty()) {
        return true;
    }
    const auto pwd_last_set = sql_literal(conn, current_ad_filetime_string());
    const std::string attributes_expression =
        "jsonb_set(jsonb_set(attributes, '{pwdLastSet}', to_jsonb(" + pwd_last_set +
        "::text), true), '{badPwdCount}', to_jsonb('0'::text), true)";

    const std::string identity_sql =
        "update identity_objects set attributes = " + attributes_expression +
        ", updated_at = now() where dn = " + sql_literal(conn, object_dn) + ";";
    PGresult* identity_result = PQexec(conn, identity_sql.c_str());
    const bool identity_ok = PQresultStatus(identity_result) == PGRES_COMMAND_OK;
    PQclear(identity_result);

    const std::string ad_sql =
        "update ad_objects set attributes = " + attributes_expression +
        ", when_changed = now(), uSNChanged = nextval('ad_usn_sequence') where dn = " +
        sql_literal(conn, object_dn) + ";";
    PGresult* ad_result = PQexec(conn, ad_sql.c_str());
    const bool ad_ok = PQresultStatus(ad_result) == PGRES_COMMAND_OK;
    PQclear(ad_result);
    return identity_ok && ad_ok;
}

std::string join_u32_list(const std::vector<std::uint32_t>& values) {
    std::string joined;
    for (const auto value : values) {
        if (!joined.empty()) {
            joined.push_back(',');
        }
        joined += std::to_string(value);
    }
    return joined;
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

std::string sql_literal(PGconn* connection, const std::string& value) {
    char* escaped = PQescapeLiteral(connection, value.c_str(), static_cast<unsigned long>(value.size()));
    if (escaped == nullptr) {
        return "''";
    }
    std::string result(escaped);
    PQfreemem(escaped);
    return result;
}

std::string wrapped_kerberos_keys_json(
    const nexus::security::AdCredentialMaterial& material,
    const nexus::core::Config& config) {
    Json::Value keys(Json::objectValue);
    for (const auto& key : material.kerberos_keys) {
        keys[key.enctype]["salt"] = key.salt;
        keys[key.enctype]["wrapped"] = nexus::security::seal_ad_secret(kerberos_key_file(config), key.key_hex);
    }
    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";
    return Json::writeString(builder, keys);
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

std::string sql_nullable_literal(PGconn* conn, const std::string& value) {
    return value.empty() ? std::string{"NULL"} : sql_literal(conn, value);
}

std::string sql_nullable_bigint(const std::string& value) {
    if (value.empty()) {
        return "NULL";
    }
    try {
        return std::to_string(std::stoll(value));
    } catch (...) {
        return "NULL";
    }
}

bool exec_ad_schema_command(PGconn* conn, const std::string& description, const char* sql) {
    PGresult* result = PQexec(conn, sql);
    const bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    if (!ok) {
        std::cerr << "[nexus-directory] failed to " << description << ": "
                  << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    return ok;
}

bool ensure_ad_domains_schema(PGconn* conn) {
    const char* domain_table_sql = R"SQL(
        create extension if not exists pgcrypto;

        create table if not exists ad_domains (
            dns_name text primary key,
            netbios_name text not null unique,
            realm text not null,
            base_dn text not null,
            domain_sid text not null,
            domain_guid uuid not null default gen_random_uuid(),
            invocation_id uuid not null default gen_random_uuid(),
            site_name text not null default 'Default-First-Site-Name',
            dc_host text not null default 'dc1',
            dc_address inet,
            next_rid bigint not null default 1000,
            created_at timestamptz not null default now()
        );
    )SQL";
    if (!exec_ad_schema_command(conn, "ensure AD domain table", domain_table_sql)) {
        return false;
    }

    const char* domain_columns_sql = R"SQL(
        alter table ad_domains add column if not exists domain_guid uuid not null default gen_random_uuid();
        alter table ad_domains add column if not exists invocation_id uuid not null default gen_random_uuid();
        alter table ad_domains add column if not exists site_name text not null default 'Default-First-Site-Name';
        alter table ad_domains add column if not exists dc_host text not null default 'dc1';
        alter table ad_domains add column if not exists dc_address inet;
        alter table ad_domains add column if not exists next_rid bigint not null default 1000;
        update ad_domains set site_name = 'Default-First-Site-Name' where site_name is null or site_name = '';
        update ad_domains set dc_host = 'dc1' where dc_host is null or dc_host = '';
        update ad_domains set next_rid = 1000 where next_rid is null or next_rid < 1000;
    )SQL";
    return exec_ad_schema_command(conn, "repair AD domain columns", domain_columns_sql);
}

bool result_sqlstate_is(PGresult* result, const char* expected) {
    const char* sqlstate = PQresultErrorField(result, PG_DIAG_SQLSTATE);
    return sqlstate != nullptr && std::string{sqlstate} == expected;
}

std::string first_rdn(const std::string& dn) {
    const auto comma = dn.find(',');
    return comma == std::string::npos ? dn : dn.substr(0, comma);
}

std::string exact_attribute_or_empty(
    const nexus::protocol::LdapObject& object,
    const std::string& attribute) {
    const auto it = object.attributes.find(attribute);
    return it == object.attributes.end() ? "" : it->second;
}

nexus::protocol::LdapObject ldap_object_from_row(PGresult* result, int row) {
    return nexus::protocol::LdapObject{
        PQgetvalue(result, row, 0),
        PQgetisnull(result, row, 1) ? "" : PQgetvalue(result, row, 1),
        PQgetvalue(result, row, 2),
        json_array_from_string(PQgetvalue(result, row, 3)),
        json_object_from_string(PQgetvalue(result, row, 4)),
    };
}

bool ensure_ad_domain_row(PGconn* conn, const nexus::core::Config& config) {
    if (!ensure_ad_domains_schema(conn)) {
        return false;
    }

    const char* schema_sql = R"SQL(
        create extension if not exists pgcrypto;

        create table if not exists ad_domains (
            dns_name text primary key,
            netbios_name text not null unique,
            realm text not null,
            base_dn text not null,
            domain_sid text not null,
            domain_guid uuid not null default gen_random_uuid(),
            invocation_id uuid not null default gen_random_uuid(),
            site_name text not null default 'Default-First-Site-Name',
            dc_host text not null default 'dc1',
            dc_address inet,
            next_rid bigint not null default 1000,
            created_at timestamptz not null default now()
        );

        alter table ad_domains add column if not exists domain_guid uuid not null default gen_random_uuid();
        alter table ad_domains add column if not exists invocation_id uuid not null default gen_random_uuid();
        alter table ad_domains add column if not exists site_name text not null default 'Default-First-Site-Name';
        alter table ad_domains add column if not exists dc_host text not null default 'dc1';
        alter table ad_domains add column if not exists dc_address inet;
        alter table ad_domains add column if not exists next_rid bigint not null default 1000;

        alter table dns_records add column if not exists dns_class text not null default 'IN';
        alter table dns_records add column if not exists weight integer not null default 0;
        alter table dns_records add column if not exists port integer not null default 0;
        alter table dns_records add column if not exists flags text not null default '';

        create sequence if not exists ad_usn_sequence as bigint start with 1 increment by 1;

        create table if not exists ad_objects (
            object_guid uuid default gen_random_uuid(),
            domain_dns_name text not null references ad_domains(dns_name) on delete cascade,
            dn text not null,
            parent_dn text,
            rdn text not null,
            kind text not null,
            object_sid text,
            rid bigint,
            object_classes jsonb not null default '[]'::jsonb,
            attributes jsonb not null default '{}'::jsonb,
            when_created timestamptz not null default now(),
            when_changed timestamptz not null default now(),
            uSNCreated bigint not null default nextval('ad_usn_sequence'),
            uSNChanged bigint not null default nextval('ad_usn_sequence')
        );
        alter table ad_objects add column if not exists object_guid uuid default gen_random_uuid();
        alter table ad_objects add column if not exists domain_dns_name text;
        alter table ad_objects add column if not exists dn text;
        alter table ad_objects add column if not exists parent_dn text;
        alter table ad_objects add column if not exists rdn text;
        alter table ad_objects add column if not exists kind text;
        alter table ad_objects add column if not exists object_sid text;
        alter table ad_objects add column if not exists rid bigint;
        alter table ad_objects add column if not exists object_classes jsonb not null default '[]'::jsonb;
        alter table ad_objects add column if not exists attributes jsonb not null default '{}'::jsonb;
        alter table ad_objects add column if not exists when_created timestamptz not null default now();
        alter table ad_objects add column if not exists when_changed timestamptz not null default now();
        alter table ad_objects add column if not exists uSNCreated bigint not null default nextval('ad_usn_sequence');
        alter table ad_objects add column if not exists uSNChanged bigint not null default nextval('ad_usn_sequence');
        update ad_objects set object_guid = gen_random_uuid() where object_guid is null;
        create unique index if not exists ad_objects_dn_key on ad_objects(dn);
        create unique index if not exists ad_objects_object_sid_key on ad_objects(object_sid);

        create table if not exists ad_memberships (
            group_dn text not null,
            member_dn text not null,
            primary key (group_dn, member_dn)
        );
        create unique index if not exists ad_memberships_group_member_key on ad_memberships(group_dn, member_dn);

        create table if not exists ad_service_principals (
            principal text primary key,
            object_dn text not null,
            created_at timestamptz not null default now()
        );

        create table if not exists ad_account_secrets (
            object_dn text primary key,
            encryption_version integer not null default 1,
            wrapped_nt_hash text not null,
            wrapped_kerberos_keys jsonb not null default '{}'::jsonb,
            updated_at timestamptz not null default now()
        );

        create table if not exists ad_protocol_status (
            protocol text primary key,
            implemented boolean not null default false,
            detail text not null,
            updated_at timestamptz not null default now()
        );
    )SQL";
    PGresult* schema_result = PQexec(conn, schema_sql);
    if (PQresultStatus(schema_result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-directory] failed to ensure AD database schema: "
                  << PQresultErrorMessage(schema_result) << '\n';
        PQclear(schema_result);
        return false;
    }
    PQclear(schema_result);

    const std::string sql =
        "insert into ad_domains(dns_name,netbios_name,realm,base_dn,domain_sid,site_name,dc_host,dc_address) values (" +
        sql_literal(conn, config.domain) + "," +
        sql_literal(conn, netbios_name_from_domain(config.domain)) + "," +
        sql_literal(conn, config.directory.realm) + "," +
        sql_literal(conn, config.directory.base_dn) + "," +
        sql_literal(conn, synthetic_domain_sid(config.domain)) + "," +
        sql_literal(conn, config.directory.site_name) + "," +
        sql_literal(conn, config.directory.domain_controller_host) + "," +
        sql_nullable_literal(conn, config.directory.domain_controller_address) + "::inet) "
        "on conflict (dns_name) do update set "
        "netbios_name=excluded.netbios_name, "
        "realm=excluded.realm, "
        "base_dn=excluded.base_dn, "
        "domain_sid=excluded.domain_sid, "
        "site_name=excluded.site_name, "
        "dc_host=excluded.dc_host, "
        "dc_address=excluded.dc_address;";
    PGresult* result = PQexec(conn, sql.c_str());
    bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    const bool can_retry_schema_repair = !ok && result_sqlstate_is(result, "42703");
    if (!ok && can_retry_schema_repair) {
        std::cerr << "[nexus-directory] AD domain schema is missing a column during upsert; repairing and retrying\n";
    }
    PQclear(result);
    if (!ok && can_retry_schema_repair && ensure_ad_domains_schema(conn)) {
        result = PQexec(conn, sql.c_str());
        ok = PQresultStatus(result) == PGRES_COMMAND_OK;
        if (!ok) {
            std::cerr << "[nexus-directory] failed to persist AD domain row after schema repair: "
                      << PQresultErrorMessage(result) << '\n';
        }
        PQclear(result);
    } else if (!ok) {
        std::cerr << "[nexus-directory] failed to persist AD domain row: "
                  << PQresultErrorMessage(result) << '\n';
    }
    return ok;
}

void refresh_ad_service_principals(
    PGconn* conn,
    const std::string& object_dn,
    const std::string& service_principal_names) {
    const std::string delete_sql =
        "delete from ad_service_principals where object_dn = " + sql_literal(conn, object_dn) + ";";
    PGresult* delete_result = PQexec(conn, delete_sql.c_str());
    PQclear(delete_result);

    for (const auto& raw_spn : split_multi_value_attribute(service_principal_names)) {
        const auto spn = trim_copy(raw_spn);
        if (spn.empty()) {
            continue;
        }
        const std::string spn_sql =
            "insert into ad_service_principals(principal,object_dn,created_at) values (" +
            sql_literal(conn, spn) + "," +
            sql_literal(conn, object_dn) + ",now()) "
            "on conflict (principal) do update set object_dn=excluded.object_dn;";
        PGresult* spn_result = PQexec(conn, spn_sql.c_str());
        if (PQresultStatus(spn_result) != PGRES_COMMAND_OK) {
            std::cerr << "[nexus-directory] failed to persist AD SPN "
                      << spn << ": " << PQresultErrorMessage(spn_result) << '\n';
        }
        PQclear(spn_result);
    }
}

bool persist_ldap_object_to_connection(
    PGconn* conn,
    const nexus::core::Config& config,
    const nexus::protocol::LdapObject& object,
    bool merge_attributes) {
    if (!ensure_ad_domain_row(conn, config)) {
        return false;
    }

    const auto object_classes = json_string_array(object.object_classes);
    const auto attributes = json_string_object(object.attributes);
    const auto object_sid = exact_attribute_or_empty(object, "objectSid");
    const auto rid = exact_attribute_or_empty(object, "rid");
    const auto identity_merge =
        merge_attributes ? std::string{"identity_objects.attributes || excluded.attributes"}
                         : std::string{"excluded.attributes"};
    const std::string identity_sql =
        "insert into identity_objects(dn,parent_dn,kind,object_classes,attributes,updated_at) values (" +
        sql_literal(conn, object.dn) + "," +
        sql_literal(conn, object.parent_dn) + "," +
        sql_literal(conn, object.kind) + "," +
        sql_literal(conn, object_classes) + "::jsonb," +
        sql_literal(conn, attributes) + "::jsonb,now()) "
        "on conflict (dn) do update set "
        "parent_dn=excluded.parent_dn, "
        "kind=excluded.kind, "
        "object_classes=excluded.object_classes, "
        "attributes=" + identity_merge + ", "
        "updated_at=now();";
    PGresult* identity_result = PQexec(conn, identity_sql.c_str());
    const bool identity_ok = PQresultStatus(identity_result) == PGRES_COMMAND_OK;
    if (!identity_ok) {
        std::cerr << "[nexus-directory] failed to persist identity object projection: "
                  << PQresultErrorMessage(identity_result) << '\n';
    }
    PQclear(identity_result);
    if (!identity_ok) {
        return false;
    }

    const auto ad_attribute_merge =
        merge_attributes ? std::string{"ad_objects.attributes || excluded.attributes"}
                         : std::string{"excluded.attributes"};
    const auto ad_sid_merge =
        merge_attributes ? std::string{"coalesce(excluded.object_sid, ad_objects.object_sid)"}
                         : std::string{"excluded.object_sid"};
    const auto ad_rid_merge =
        merge_attributes ? std::string{"coalesce(excluded.rid, ad_objects.rid)"}
                         : std::string{"excluded.rid"};
    const std::string ad_sql =
        "insert into ad_objects(domain_dns_name,dn,parent_dn,rdn,kind,object_sid,rid,object_classes,attributes,when_changed,uSNChanged) values (" +
        sql_literal(conn, config.domain) + "," +
        sql_literal(conn, object.dn) + "," +
        sql_nullable_literal(conn, object.parent_dn) + "," +
        sql_literal(conn, first_rdn(object.dn)) + "," +
        sql_literal(conn, object.kind) + "," +
        sql_nullable_literal(conn, object_sid) + "," +
        sql_nullable_bigint(rid) + "," +
        sql_literal(conn, object_classes) + "::jsonb," +
        sql_literal(conn, attributes) + "::jsonb,now(),nextval('ad_usn_sequence')) "
        "on conflict (dn) do update set "
        "domain_dns_name=excluded.domain_dns_name, "
        "parent_dn=excluded.parent_dn, "
        "rdn=excluded.rdn, "
        "kind=excluded.kind, "
        "object_sid=" + ad_sid_merge + ", "
        "rid=" + ad_rid_merge + ", "
        "object_classes=excluded.object_classes, "
        "attributes=" + ad_attribute_merge + ", "
        "when_changed=now(), "
        "uSNChanged=nextval('ad_usn_sequence');";
    PGresult* ad_result = PQexec(conn, ad_sql.c_str());
    const bool ad_ok = PQresultStatus(ad_result) == PGRES_COMMAND_OK;
    if (!ad_ok) {
        std::cerr << "[nexus-directory] failed to persist canonical AD object: "
                  << PQresultErrorMessage(ad_result) << '\n';
    }
    PQclear(ad_result);
    if (!ad_ok) {
        return false;
    }

    if (const auto it = object.attributes.find("servicePrincipalName"); it != object.attributes.end()) {
        refresh_ad_service_principals(conn, object.dn, it->second);
    }
    return true;
}

bool mirror_identity_objects_into_ad_objects(PGconn* conn, const nexus::core::Config& config) {
    if (!ensure_ad_domain_row(conn, config)) {
        return false;
    }

    const std::string sql =
        "insert into ad_objects(domain_dns_name,dn,parent_dn,rdn,kind,object_sid,rid,object_classes,attributes,when_changed,uSNChanged) "
        "select " +
        sql_literal(conn, config.domain) + ", "
        "i.dn, nullif(i.parent_dn, ''), split_part(i.dn, ',', 1), i.kind, "
        "nullif(i.attributes->>'objectSid', ''), "
        "case when coalesce(i.attributes->>'rid', '') ~ '^[0-9]+$' then (i.attributes->>'rid')::bigint else null end, "
        "i.object_classes, i.attributes, now(), nextval('ad_usn_sequence') "
        "from identity_objects i "
        "where not exists (select 1 from ad_objects a where a.dn = i.dn);";
    PGresult* result = PQexec(conn, sql.c_str());
    const bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    if (!ok) {
        std::cerr << "[nexus-directory] failed to mirror identity_objects into ad_objects: "
                  << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    return ok;
}

std::optional<nexus::protocol::LdapObject> lookup_ldap_object_where(
    PGconn* conn,
    const std::string& where) {
    const std::string sql =
        "select dn,parent_dn,kind,object_classes::text,"
        "(attributes || jsonb_build_object("
        "'objectGUID', object_guid::text,"
        "'whenCreated', to_char(when_created at time zone 'UTC', 'YYYYMMDDHH24MISS.0Z'),"
        "'whenChanged', to_char(when_changed at time zone 'UTC', 'YYYYMMDDHH24MISS.0Z'),"
        "'uSNCreated', uSNCreated::text,"
        "'uSNChanged', uSNChanged::text))::text "
        "from ad_objects "
        "where " + where + " "
        "order by dn "
        "limit 1";
    PGresult* result = PQexec(conn, sql.c_str());
    std::optional<nexus::protocol::LdapObject> object;
    if (PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) > 0) {
        object = ldap_object_from_row(result, 0);
    }
    PQclear(result);
    return object;
}

std::optional<nexus::protocol::LdapObject> lookup_ldap_object_by_dn(
    PGconn* conn,
    const std::string& dn) {
    return lookup_ldap_object_where(conn, "dn = " + sql_literal(conn, dn));
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
    mirror_identity_objects_into_ad_objects(conn, config);

    PGresult* result = PQexec(
        conn,
        "select dn,parent_dn,kind,object_classes::text,"
        "(attributes || jsonb_build_object("
        "'objectGUID', object_guid::text,"
        "'whenCreated', to_char(when_created at time zone 'UTC', 'YYYYMMDDHH24MISS.0Z'),"
        "'whenChanged', to_char(when_changed at time zone 'UTC', 'YYYYMMDDHH24MISS.0Z'),"
        "'uSNCreated', uSNCreated::text,"
        "'uSNChanged', uSNChanged::text))::text "
        "from ad_objects "
        "order by dn");

    std::vector<nexus::protocol::LdapObject> objects;
    if (PQresultStatus(result) == PGRES_TUPLES_OK) {
        for (int index = 0; index < PQntuples(result); ++index) {
            objects.push_back(ldap_object_from_row(result, index));
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
    mirror_identity_objects_into_ad_objects(conn, config);

    PGresult* result = PQexec(
        conn,
        "select "
        "  attributes->>'sAMAccountName', "
        "  attributes->>'userPrincipalName', "
        "  attributes->>'servicePrincipalName', "
        "  attributes->>'dNSHostName', "
        "  attributes->>'objectSid', "
        "  attributes->>'rid', "
        "  attributes->>'primaryGroupID', "
        "  attributes->>'groupRids', "
        "  attributes->>'displayName', "
        "  attributes->>'userAccountControl', "
        "  attributes->>'accountExpires', "
        "  coalesce(s.wrapped_kerberos_keys::text, '{}') "
        "from ad_objects o "
        "left join ad_account_secrets s on s.object_dn = o.dn "
        "where attributes ? 'sAMAccountName' "
        "order by o.dn");

    std::vector<nexus::protocol::KerberosPrincipal> principals;
    if (PQresultStatus(result) == PGRES_TUPLES_OK) {
        for (int index = 0; index < PQntuples(result); ++index) {
            const std::string sam = PQgetvalue(result, index, 0);
            const std::string upn = PQgetisnull(result, index, 1) ? "" : PQgetvalue(result, index, 1);
            const std::string service_principal_names = PQgetisnull(result, index, 2) ? "" : PQgetvalue(result, index, 2);
            const std::string dns_host_name = PQgetisnull(result, index, 3) ? "" : PQgetvalue(result, index, 3);
            const std::string object_sid = PQgetisnull(result, index, 4) ? "" : PQgetvalue(result, index, 4);
            const auto rid = parse_u32_or(PQgetisnull(result, index, 5) ? "" : PQgetvalue(result, index, 5), 0);
            const auto primary_group_rid = parse_u32_or(PQgetisnull(result, index, 6) ? "" : PQgetvalue(result, index, 6), 513);
            const auto group_rids = parse_u32_list(PQgetisnull(result, index, 7) ? "" : PQgetvalue(result, index, 7));
            const std::string display_name = PQgetisnull(result, index, 8) ? "" : PQgetvalue(result, index, 8);
            const auto user_account_control = parse_u32_or(PQgetisnull(result, index, 9) ? "" : PQgetvalue(result, index, 9), 0);
            const bool account_expired = ad_account_expired(PQgetisnull(result, index, 10) ? "" : PQgetvalue(result, index, 10));
            const std::string wrapped_keys = PQgetisnull(result, index, 11) ? "{}" : PQgetvalue(result, index, 11);
            const auto keys = parse_wrapped_kerberos_keys(config, wrapped_keys);
            add_principal_alias(
                principals,
                sam,
                config.directory.realm,
                keys,
                object_sid,
                rid,
                primary_group_rid,
                group_rids,
                display_name,
                user_account_control,
                account_expired);
            if (lowercase_ascii(sam) == "krbtgt") {
                add_principal_alias(
                    principals,
                    "kadmin/changepw",
                    config.directory.realm,
                    keys,
                    object_sid,
                    rid,
                    primary_group_rid,
                    group_rids,
                    display_name,
                    user_account_control,
                    account_expired);
            }
            add_principal_alias(
                principals,
                upn,
                config.directory.realm,
                keys,
                object_sid,
                rid,
                primary_group_rid,
                group_rids,
                display_name,
                user_account_control,
                account_expired);
            for (const auto& spn : split_multi_value_attribute(service_principal_names)) {
                add_principal_alias(
                    principals,
                    trim_copy(spn),
                    config.directory.realm,
                    keys,
                    object_sid,
                    rid,
                    primary_group_rid,
                    group_rids,
                    display_name,
                    user_account_control,
                    account_expired);
            }
            if (!dns_host_name.empty()) {
                const auto dot = dns_host_name.find('.');
                const auto short_host = dot == std::string::npos ? dns_host_name : dns_host_name.substr(0, dot);
                for (const auto& spn : split_multi_value_attribute(machine_spn_attribute(short_host, dns_host_name))) {
                    add_principal_alias(
                        principals,
                        trim_copy(spn),
                        config.directory.realm,
                        keys,
                        object_sid,
                        rid,
                        primary_group_rid,
                        group_rids,
                        display_name,
                        user_account_control,
                        account_expired);
                }
            }
        }
    } else {
        std::cerr << "[nexus-directory] failed to load KDC principals: " << PQresultErrorMessage(result) << '\n';
    }

    PQclear(result);
    PQfinish(conn);
    return principals;
}

std::vector<nexus::protocol::NetlogonAccountSecret> load_netlogon_account_secrets(const nexus::core::Config& config) {
    if (config.database_url.empty()) {
        return {};
    }

    PGconn* conn = PQconnectdb(config.database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "[nexus-directory] database unavailable; Netlogon machine secrets are empty\n";
        PQfinish(conn);
        return {};
    }
    mirror_identity_objects_into_ad_objects(conn, config);

    PGresult* result = PQexec(
        conn,
        "select "
        "  attributes->>'sAMAccountName', "
        "  attributes->>'rid', "
        "  attributes->>'userAccountControl', "
        "  attributes->>'accountExpires', "
        "  s.wrapped_nt_hash "
        "from ad_objects o "
        "join ad_account_secrets s on s.object_dn = o.dn "
        "where attributes ? 'sAMAccountName' "
        "order by o.dn");

    std::vector<nexus::protocol::NetlogonAccountSecret> accounts;
    if (PQresultStatus(result) == PGRES_TUPLES_OK) {
        for (int index = 0; index < PQntuples(result); ++index) {
            const std::string sam = PQgetvalue(result, index, 0);
            const auto rid = parse_u32_or(PQgetisnull(result, index, 1) ? "" : PQgetvalue(result, index, 1), 0);
            const auto user_account_control = parse_u32_or(PQgetisnull(result, index, 2) ? "" : PQgetvalue(result, index, 2), 0);
            const bool account_expired = ad_account_expired(PQgetisnull(result, index, 3) ? "" : PQgetvalue(result, index, 3));
            const std::string wrapped_nt_hash = PQgetisnull(result, index, 4) ? "" : PQgetvalue(result, index, 4);
            auto nt_hash = nexus::security::open_ad_secret(kerberos_key_file(config), wrapped_nt_hash);
            if (sam.empty() || !nt_hash.has_value()) {
                continue;
            }
            accounts.push_back({sam, *nt_hash, rid, user_account_control, account_expired});
        }
    } else {
        std::cerr << "[nexus-directory] failed to load Netlogon account secrets: " << PQresultErrorMessage(result) << '\n';
    }

    PQclear(result);
    PQfinish(conn);
    return accounts;
}

bool constant_time_equal(std::string left, std::string right) {
    left = lowercase_ascii(std::move(left));
    right = lowercase_ascii(std::move(right));
    std::uint8_t diff = static_cast<std::uint8_t>(left.size() ^ right.size());
    const auto limit = std::max(left.size(), right.size());
    for (std::size_t index = 0; index < limit; ++index) {
        const auto left_ch = index < left.size() ? static_cast<std::uint8_t>(left[index]) : 0;
        const auto right_ch = index < right.size() ? static_cast<std::uint8_t>(right[index]) : 0;
        diff = static_cast<std::uint8_t>(diff | (left_ch ^ right_ch));
    }
    return diff == 0;
}

std::string sam_candidate_from_bind_name(const std::string& bind_name) {
    auto candidate = trim_copy(bind_name);
    const auto slash = candidate.find_last_of('\\');
    if (slash != std::string::npos && slash + 1 < candidate.size()) {
        candidate = candidate.substr(slash + 1);
    }
    const auto at = candidate.find('@');
    if (at != std::string::npos) {
        candidate = candidate.substr(0, at);
    }
    return trim_copy(candidate);
}

std::optional<std::string> verify_ldap_simple_bind(
    const nexus::core::Config& config,
    const std::string& bind_name,
    const std::string& password) {
    const auto trimmed_name = trim_copy(bind_name);
    if (config.database_url.empty() || trimmed_name.empty() || password.empty()) {
        return std::nullopt;
    }

    PGconn* conn = PQconnectdb(config.database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "[nexus-directory] database unavailable; LDAP simple bind rejected\n";
        PQfinish(conn);
        return std::nullopt;
    }
    mirror_identity_objects_into_ad_objects(conn, config);

    const auto sam_candidate = sam_candidate_from_bind_name(trimmed_name);
    const auto upn_candidate = sam_candidate.empty() ? trimmed_name : sam_candidate + "@" + lowercase_ascii(config.domain);
    const std::string sql =
        "select "
        "  o.dn, "
        "  coalesce(o.attributes->>'sAMAccountName', ''), "
        "  coalesce(o.attributes->>'userPrincipalName', ''), "
        "  coalesce(o.attributes->>'userAccountControl', '0'), "
        "  s.wrapped_nt_hash "
        "from ad_objects o "
        "join ad_account_secrets s on s.object_dn = o.dn "
        "where lower(o.dn) = lower(" + sql_literal(conn, trimmed_name) + ") "
        "   or lower(o.attributes->>'sAMAccountName') = lower(" + sql_literal(conn, trimmed_name) + ") "
        "   or lower(o.attributes->>'sAMAccountName') = lower(" + sql_literal(conn, sam_candidate) + ") "
        "   or lower(o.attributes->>'userPrincipalName') = lower(" + sql_literal(conn, trimmed_name) + ") "
        "   or lower(o.attributes->>'userPrincipalName') = lower(" + sql_literal(conn, upn_candidate) + ") "
        "order by case when lower(o.dn) = lower(" + sql_literal(conn, trimmed_name) + ") then 0 else 1 end, o.dn "
        "limit 1;";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) != PGRES_TUPLES_OK) {
        std::cerr << "[nexus-directory] failed to load LDAP simple bind secret: "
                  << PQresultErrorMessage(result) << '\n';
        PQclear(result);
        PQfinish(conn);
        return std::nullopt;
    }
    if (PQntuples(result) == 0) {
        PQclear(result);
        PQfinish(conn);
        return std::nullopt;
    }

    const std::string sam = PQgetvalue(result, 0, 1);
    const auto user_account_control = parse_u32_or(PQgetvalue(result, 0, 3), 0);
    const std::string wrapped_nt_hash = PQgetisnull(result, 0, 4) ? "" : PQgetvalue(result, 0, 4);
    PQclear(result);
    PQfinish(conn);

    if (sam.empty() || (user_account_control & 0x00000002U) != 0) {
        return std::nullopt;
    }
    const auto stored_nt_hash = nexus::security::open_ad_secret(kerberos_key_file(config), wrapped_nt_hash);
    if (!stored_nt_hash.has_value()) {
        return std::nullopt;
    }

    try {
        const auto candidate_material = nexus::security::derive_ad_credentials(password, config.directory.realm, sam);
        if (!constant_time_equal(*stored_nt_hash, candidate_material.nt_hash_hex)) {
            return std::nullopt;
        }
        return sam;
    } catch (const std::exception& error) {
        std::cerr << "[nexus-directory] failed to verify LDAP simple bind: "
                  << error.what() << '\n';
        return std::nullopt;
    }
}

std::optional<nexus::protocol::SamrAccountRecord> samr_account_record_from_row(PGresult* result, int row) {
    const std::string sam = PQgetisnull(result, row, 0) ? "" : PQgetvalue(result, row, 0);
    const auto rid = parse_u32_or(PQgetisnull(result, row, 1) ? "" : PQgetvalue(result, row, 1), 0);
    auto display = PQgetisnull(result, row, 2) ? "" : std::string(PQgetvalue(result, row, 2));
    const auto kind = lowercase_ascii(PQgetisnull(result, row, 6) ? "" : PQgetvalue(result, row, 6));
    const bool machine = kind == "computer" || (!sam.empty() && sam.back() == '$');
    const bool group = kind == "group";
    const std::uint32_t sid_name_use = machine ? 9U : (group ? 2U : 1U);
    if (display.empty()) {
        display = sam;
        if (!display.empty() && display.back() == '$') {
            display.pop_back();
        }
    }
    const auto primary_group = parse_u32_or(
        PQgetisnull(result, row, 3) ? "" : PQgetvalue(result, row, 3),
        group ? 0U : (machine ? 515U : 513U));
    const auto user_account_control = parse_u32_or(
        PQgetisnull(result, row, 4) ? "" : PQgetvalue(result, row, 4),
        group ? 0U : (machine ? 0x00001020U : 0x00000200U));
    auto group_rids = parse_u32_list(PQgetisnull(result, row, 5) ? "" : PQgetvalue(result, row, 5));
    if (group_rids.empty() && primary_group != 0) {
        group_rids.push_back(primary_group);
    }
    if (sam.empty() || rid == 0) {
        return std::nullopt;
    }
    return nexus::protocol::SamrAccountRecord{
        sam,
        rid,
        display,
        primary_group,
        user_account_control,
        machine,
        group_rids,
        sid_name_use,
    };
}

std::optional<nexus::protocol::SamrAccountRecord> lookup_samr_account(
    PGconn* conn,
    const nexus::protocol::SamrAccountRequest& request) {
    std::string where;
    if (!request.sam_account_name.empty()) {
        where = "lower(attributes->>'sAMAccountName') = lower(" + sql_literal(conn, request.sam_account_name) + ")";
    } else if (request.rid != 0) {
        where = "attributes->>'rid' = " + sql_literal(conn, std::to_string(request.rid));
    } else {
        return std::nullopt;
    }

    const std::string sql =
        "select "
        "  attributes->>'sAMAccountName', "
        "  attributes->>'rid', "
        "  coalesce(attributes->>'displayName', attributes->>'cn', ''), "
        "  attributes->>'primaryGroupID', "
        "  attributes->>'userAccountControl', "
        "  attributes->>'groupRids', "
        "  kind "
        "from ad_objects "
        "where " + where + " "
        "limit 1";
    PGresult* result = PQexec(conn, sql.c_str());
    std::optional<nexus::protocol::SamrAccountRecord> record;
    if (PQresultStatus(result) == PGRES_TUPLES_OK && PQntuples(result) > 0) {
        record = samr_account_record_from_row(result, 0);
    }
    PQclear(result);
    return record;
}

std::vector<nexus::protocol::SamrAccountRecord> load_samr_account_records(
    const nexus::core::Config& config) {
    std::vector<nexus::protocol::SamrAccountRecord> records;
    if (config.database_url.empty()) {
        return records;
    }

    PGconn* conn = PQconnectdb(config.database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "[nexus-directory] database unavailable; SAMR enumeration used built-in records only\n";
        PQfinish(conn);
        return records;
    }
    mirror_identity_objects_into_ad_objects(conn, config);

    const std::string sql =
        "select "
        "  attributes->>'sAMAccountName', "
        "  attributes->>'rid', "
        "  coalesce(attributes->>'displayName', attributes->>'cn', ''), "
        "  attributes->>'primaryGroupID', "
        "  attributes->>'userAccountControl', "
        "  attributes->>'groupRids', "
        "  kind "
        "from ad_objects "
        "where attributes ? 'sAMAccountName' "
        "  and attributes ? 'rid' "
        "  and kind in ('user','computer','group') "
        "order by attributes->>'rid', attributes->>'sAMAccountName' "
        "limit 1024";
    PGresult* result = PQexec(conn, sql.c_str());
    if (PQresultStatus(result) == PGRES_TUPLES_OK) {
        for (int row = 0; row < PQntuples(result); ++row) {
            if (auto record = samr_account_record_from_row(result, row)) {
                records.push_back(*record);
            }
        }
    } else {
        std::cerr << "[nexus-directory] failed to enumerate SAMR accounts: "
                  << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    PQfinish(conn);
    return records;
}

std::optional<nexus::protocol::SamrAccountRecord> create_samr_machine_account(
    PGconn* conn,
    const nexus::core::Config& config,
    const std::string& sam_account_name) {
    if (sam_account_name.empty()) {
        return std::nullopt;
    }

    const auto host = machine_host_from_sam(sam_account_name);
    if (host.empty()) {
        return std::nullopt;
    }
    const auto sam = sam_account_name.back() == '$' ? sam_account_name : sam_account_name + "$";
    const auto rid = synthetic_rid(sam);
    const auto domain_sid = synthetic_domain_sid(config.domain);
    const auto dns_host = host + "." + lowercase_ascii(config.domain);
    const auto parent_dn = "cn=Computers," + config.directory.base_dn;
    const auto dn = "cn=" + host + "," + parent_dn;
    nexus::protocol::LdapObject object{
        dn,
        parent_dn,
        "computer",
        {"top", "person", "organizationalPerson", "user", "computer"},
        {
            {"cn", host},
            {"dNSHostName", dns_host},
            {"displayName", host},
            {"groupRids", "515"},
            {"objectSid", domain_sid + "-" + std::to_string(rid)},
            {"primaryGroupID", "515"},
            {"rid", std::to_string(rid)},
            {"sAMAccountName", sam},
            {"servicePrincipalName", machine_spn_attribute(host, dns_host)},
            {"userAccountControl", "4128"},
        },
    };

    const bool ok = persist_ldap_object_to_connection(conn, config, object, true);
    if (!ok) {
        std::cerr << "[nexus-directory] failed to create SAMR machine account "
                  << sam << '\n';
    }
    if (!ok) {
        return std::nullopt;
    }
    return nexus::protocol::SamrAccountRecord{sam, rid, host, 515, 0x00001020U, true, {515}, 9};
}

std::optional<nexus::protocol::SamrAccountRecord> handle_samr_account_request(
    const nexus::core::Config& config,
    const nexus::protocol::SamrAccountRequest& request) {
    if (config.database_url.empty()) {
        if (!request.create_if_missing && request.sam_account_name.empty() && request.rid == 0) {
            return std::nullopt;
        }
        const auto sam = request.sam_account_name.empty() ? "machine$" : request.sam_account_name;
        const bool machine = !sam.empty() && sam.back() == '$';
        auto display = sam;
        if (!display.empty() && display.back() == '$') {
            display.pop_back();
        }
        return nexus::protocol::SamrAccountRecord{
            sam,
            request.rid != 0 ? request.rid : synthetic_rid(sam),
            display,
            machine ? 515U : 513U,
            machine ? 0x00001020U : 0x00000200U,
            machine,
            {machine ? 515U : 513U},
            machine ? 9U : 1U,
        };
    }

    PGconn* conn = PQconnectdb(config.database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "[nexus-directory] database unavailable; SAMR account request used synthetic result\n";
        PQfinish(conn);
        const auto sam = request.sam_account_name.empty() ? "machine$" : request.sam_account_name;
        const bool machine = !sam.empty() && sam.back() == '$';
        auto display = sam;
        if (!display.empty() && display.back() == '$') {
            display.pop_back();
        }
        return nexus::protocol::SamrAccountRecord{
            sam,
            request.rid != 0 ? request.rid : synthetic_rid(sam),
            display,
            machine ? 515U : 513U,
            machine ? 0x00001020U : 0x00000200U,
            machine,
            {machine ? 515U : 513U},
            machine ? 9U : 1U,
        };
    }
    mirror_identity_objects_into_ad_objects(conn, config);

    auto existing = lookup_samr_account(conn, request);
    if (existing.has_value() || !request.create_if_missing) {
        PQfinish(conn);
        return existing;
    }

    auto created = create_samr_machine_account(conn, config, request.sam_account_name);
    PQfinish(conn);
    return created;
}

bool handle_samr_account_update(
    const nexus::core::Config& config,
    const nexus::protocol::SamrAccountUpdate& update) {
    std::map<std::string, std::string> attributes;
    if (update.display_name.has_value()) {
        attributes["displayName"] = *update.display_name;
    }
    if (update.primary_group_rid.has_value()) {
        attributes["primaryGroupID"] = std::to_string(*update.primary_group_rid);
    }
    if (update.user_account_control.has_value()) {
        attributes["userAccountControl"] = std::to_string(*update.user_account_control);
    }
    if (attributes.empty() && !update.new_password.has_value()) {
        return true;
    }
    if (config.database_url.empty()) {
        return true;
    }

    PGconn* conn = PQconnectdb(config.database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "[nexus-directory] database unavailable; SAMR account update was accepted in-memory only\n";
        PQfinish(conn);
        return true;
    }

    std::string where;
    if (update.rid != 0) {
        where = "attributes->>'rid' = " + sql_literal(conn, std::to_string(update.rid));
    } else if (!update.sam_account_name.empty()) {
        where = "lower(attributes->>'sAMAccountName') = lower(" + sql_literal(conn, update.sam_account_name) + ")";
    } else {
        PQfinish(conn);
        return false;
    }

    mirror_identity_objects_into_ad_objects(conn, config);
    auto object = lookup_ldap_object_where(conn, where);
    if (!object.has_value()) {
        std::cerr << "[nexus-directory] SAMR update ignored for unknown account\n";
        PQfinish(conn);
        return false;
    }

    if (!attributes.empty()) {
        for (const auto& [name, value] : attributes) {
            object->attributes[name] = value;
        }
        if (!persist_ldap_object_to_connection(conn, config, *object, false)) {
            std::cerr << "[nexus-directory] failed to persist SAMR account update: "
                      << object->dn << '\n';
            PQfinish(conn);
            return false;
        }
    }

    if (update.new_password.has_value() && !update.new_password->empty()) {
        const std::string object_dn = object->dn;
        const std::string sam = exact_attribute_or_empty(*object, "sAMAccountName");
        if (sam.empty()) {
            PQfinish(conn);
            return false;
        }

        stamp_ad_password_metadata(object->attributes, sam);
        if (!persist_ldap_object_to_connection(conn, config, *object, false)) {
            std::cerr << "[nexus-directory] failed to persist SAMR password metadata: "
                      << object_dn << '\n';
            PQfinish(conn);
            return false;
        }
        if (!persist_ad_account_secret(conn, config, object_dn, sam, *update.new_password, "SAMR")) {
            PQfinish(conn);
            return false;
        }
    }

    PQfinish(conn);
    return true;
}

std::optional<std::string> find_ad_attribute(
    const std::map<std::string, std::string>& attributes,
    const std::string& name) {
    for (const auto& [key, value] : attributes) {
        if (lowercase_ascii(key) == lowercase_ascii(name)) {
            return value;
        }
    }
    return std::nullopt;
}

void set_ad_attribute(
    std::map<std::string, std::string>& attributes,
    const std::string& name,
    const std::string& value,
    bool only_if_missing = false) {
    for (auto& [key, existing] : attributes) {
        if (lowercase_ascii(key) == lowercase_ascii(name)) {
            if (!only_if_missing || existing.empty()) {
                existing = value;
            }
            return;
        }
    }
    attributes[name] = value;
}

std::optional<std::string> remove_ad_attribute(
    std::map<std::string, std::string>& attributes,
    const std::string& name) {
    for (auto it = attributes.begin(); it != attributes.end(); ++it) {
        if (lowercase_ascii(it->first) == lowercase_ascii(name)) {
            const auto value = it->second;
            attributes.erase(it);
            return value;
        }
    }
    return std::nullopt;
}

std::vector<std::string> split_attribute_values_for_modify(
    const std::string& name,
    const std::string& value) {
    return lowercase_ascii(name) == "member"
        ? split_ldap_member_dns(value)
        : split_multi_value_attribute(value);
}

std::string join_attribute_values_for_modify(
    const std::string& name,
    const std::vector<std::string>& values) {
    if (lowercase_ascii(name) != "member") {
        return join_multi_value_attribute(values);
    }

    std::string joined;
    for (const auto& value : values) {
        const auto trimmed = trim_copy(value);
        if (trimmed.empty()) {
            continue;
        }
        if (!joined.empty()) {
            joined.push_back(';');
        }
        joined += trimmed;
    }
    return joined;
}

void apply_ldap_attribute_modify(
    std::map<std::string, std::string>& attributes,
    const std::string& name,
    const std::string& value,
    int operation) {
    if (operation == 1) {
        if (value.empty()) {
            remove_ad_attribute(attributes, name);
            return;
        }

        const auto existing = remove_ad_attribute(attributes, name);
        if (!existing.has_value()) {
            return;
        }
        const auto values_to_remove = split_attribute_values_for_modify(name, value);
        std::vector<std::string> kept_values;
        for (const auto& existing_value : split_attribute_values_for_modify(name, *existing)) {
            const auto trimmed_existing = trim_copy(existing_value);
            const auto should_remove = std::any_of(values_to_remove.begin(), values_to_remove.end(), [&](const auto& remove_value) {
                return lowercase_ascii(trim_copy(remove_value)) == lowercase_ascii(trimmed_existing);
            });
            if (!trimmed_existing.empty() && !should_remove) {
                kept_values.push_back(trimmed_existing);
            }
        }
        const auto joined = join_attribute_values_for_modify(name, kept_values);
        if (!joined.empty()) {
            set_ad_attribute(attributes, name, joined);
        }
        return;
    }

    if (operation == 0) {
        std::vector<std::string> merged_values;
        if (const auto existing = find_ad_attribute(attributes, name)) {
            for (const auto& existing_value : split_attribute_values_for_modify(name, *existing)) {
                const auto trimmed = trim_copy(existing_value);
                if (!trimmed.empty()) {
                    merged_values.push_back(trimmed);
                }
            }
        }
        for (const auto& add_value : split_attribute_values_for_modify(name, value)) {
            const auto trimmed = trim_copy(add_value);
            if (trimmed.empty()) {
                continue;
            }
            const auto exists = std::any_of(merged_values.begin(), merged_values.end(), [&](const auto& existing_value) {
                return lowercase_ascii(existing_value) == lowercase_ascii(trimmed);
            });
            if (!exists) {
                merged_values.push_back(trimmed);
            }
        }
        set_ad_attribute(attributes, name, join_attribute_values_for_modify(name, merged_values));
        return;
    }

    if (value.empty()) {
        remove_ad_attribute(attributes, name);
        return;
    }
    set_ad_attribute(attributes, name, value);
}

std::optional<nexus::protocol::LdapObject> lookup_ldap_object_by_rid(PGconn* conn, std::uint32_t rid) {
    if (rid == 0) {
        return std::nullopt;
    }
    const auto rid_text = std::to_string(rid);
    return lookup_ldap_object_where(
        conn,
        "(rid = " + rid_text + " or attributes->>'rid' = " + sql_literal(conn, rid_text) + ")");
}

void apply_group_rid_membership(
    nexus::protocol::LdapObject& member,
    std::uint32_t group_rid,
    bool add) {
    auto group_rids = parse_u32_list(find_ad_attribute(member.attributes, "groupRids").value_or(""));
    const auto exists = std::find(group_rids.begin(), group_rids.end(), group_rid) != group_rids.end();
    if (add && !exists) {
        group_rids.push_back(group_rid);
    } else if (!add) {
        group_rids.erase(
            std::remove(group_rids.begin(), group_rids.end(), group_rid),
            group_rids.end());
    }

    const auto joined = join_u32_list(group_rids);
    if (joined.empty()) {
        remove_ad_attribute(member.attributes, "groupRids");
    } else {
        set_ad_attribute(member.attributes, "groupRids", joined);
    }
}

bool persist_samr_membership_update(
    PGconn* conn,
    const nexus::core::Config& config,
    const nexus::protocol::SamrMembershipUpdate& update,
    std::uint32_t member_rid) {
    auto group = lookup_ldap_object_by_rid(conn, update.container_rid);
    auto member = lookup_ldap_object_by_rid(conn, member_rid);
    if (!group.has_value() || !member.has_value()) {
        std::cerr << "[nexus-directory] SAMR membership update ignored for unknown "
                  << (group.has_value() ? "member RID " : "container RID ")
                  << (group.has_value() ? member_rid : update.container_rid) << '\n';
        return false;
    }

    apply_group_rid_membership(*member, update.container_rid, update.add);
    if (!persist_ldap_object_to_connection(conn, config, *member, false)) {
        std::cerr << "[nexus-directory] failed to persist SAMR membership attribute update for "
                  << member->dn << '\n';
        return false;
    }

    std::string membership_sql;
    if (update.add) {
        membership_sql =
            "insert into ad_memberships(group_dn,member_dn) values (" +
            sql_literal(conn, group->dn) + "," +
            sql_literal(conn, member->dn) + ") "
            "on conflict (group_dn, member_dn) do nothing;";
    } else {
        membership_sql =
            "delete from ad_memberships where group_dn = " +
            sql_literal(conn, group->dn) + " and member_dn = " +
            sql_literal(conn, member->dn) + ";";
    }

    PGresult* result = PQexec(conn, membership_sql.c_str());
    const bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
    if (!ok) {
        std::cerr << "[nexus-directory] failed to persist SAMR "
                  << (update.alias ? "alias" : "group") << " membership update: "
                  << PQresultErrorMessage(result) << '\n';
    }
    PQclear(result);
    return ok;
}

bool handle_samr_membership_update(
    const nexus::core::Config& config,
    const nexus::protocol::SamrMembershipUpdate& update) {
    if (update.container_rid == 0 || update.member_rids.empty()) {
        return false;
    }
    if (config.database_url.empty()) {
        return true;
    }

    PGconn* conn = PQconnectdb(config.database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "[nexus-directory] database unavailable; SAMR membership update was accepted in-memory only\n";
        PQfinish(conn);
        return true;
    }
    mirror_identity_objects_into_ad_objects(conn, config);

    bool ok = true;
    for (const auto member_rid : update.member_rids) {
        ok = persist_samr_membership_update(conn, config, update, member_rid) && ok;
    }

    PQfinish(conn);
    return ok;
}

bool sync_ldap_group_memberships(
    PGconn* conn,
    const nexus::core::Config& config,
    nexus::protocol::LdapObject& group,
    const std::vector<std::string>& previous_member_dns) {
    const auto group_rid = parse_u32_or(find_ad_attribute(group.attributes, "rid").value_or(""), 0);
    if (group_rid == 0) {
        return true;
    }

    const auto current_member_dns = split_ldap_member_dns(find_ad_attribute(group.attributes, "member").value_or(""));
    std::vector<std::string> affected_dns;
    const auto add_affected = [&](const std::string& dn) {
        const auto normalized = lowercase_ascii(trim_copy(dn));
        if (normalized.empty()) {
            return;
        }
        const auto exists = std::any_of(affected_dns.begin(), affected_dns.end(), [&](const auto& current) {
            return lowercase_ascii(current) == normalized;
        });
        if (!exists) {
            affected_dns.push_back(trim_copy(dn));
        }
    };
    for (const auto& dn : previous_member_dns) {
        add_affected(dn);
    }
    for (const auto& dn : current_member_dns) {
        add_affected(dn);
    }

    bool ok = true;
    const auto current_contains = [&](const std::string& dn) {
        const auto normalized = lowercase_ascii(trim_copy(dn));
        return std::any_of(current_member_dns.begin(), current_member_dns.end(), [&](const auto& current) {
            return lowercase_ascii(trim_copy(current)) == normalized;
        });
    };

    for (const auto& member_dn : affected_dns) {
        auto member = lookup_ldap_object_by_dn(conn, member_dn);
        if (!member.has_value()) {
            continue;
        }
        apply_group_rid_membership(*member, group_rid, current_contains(member_dn));
        if (!persist_ldap_object_to_connection(conn, config, *member, false)) {
            ok = false;
        }
    }

    const std::string delete_sql =
        "delete from ad_memberships where group_dn = " + sql_literal(conn, group.dn) + ";";
    PGresult* delete_result = PQexec(conn, delete_sql.c_str());
    ok = (PQresultStatus(delete_result) == PGRES_COMMAND_OK) && ok;
    if (PQresultStatus(delete_result) != PGRES_COMMAND_OK) {
        std::cerr << "[nexus-directory] failed to clear LDAP group memberships: "
                  << PQresultErrorMessage(delete_result) << '\n';
    }
    PQclear(delete_result);

    for (const auto& member_dn : current_member_dns) {
        auto member = lookup_ldap_object_by_dn(conn, member_dn);
        if (!member.has_value()) {
            continue;
        }
        const std::string insert_sql =
            "insert into ad_memberships(group_dn,member_dn) values (" +
            sql_literal(conn, group.dn) + "," +
            sql_literal(conn, member->dn) + ") "
            "on conflict (group_dn, member_dn) do nothing;";
        PGresult* insert_result = PQexec(conn, insert_sql.c_str());
        const bool insert_ok = PQresultStatus(insert_result) == PGRES_COMMAND_OK;
        if (!insert_ok) {
            std::cerr << "[nexus-directory] failed to persist LDAP group membership: "
                      << PQresultErrorMessage(insert_result) << '\n';
        }
        PQclear(insert_result);
        ok = insert_ok && ok;
    }

    return ok;
}

std::string decode_ldap_password_value(const std::string& value) {
    std::string decoded;
    std::size_t utf16_markers = 0;
    if (value.size() >= 2 && value.size() % 2 == 0) {
        for (std::size_t index = 1; index < value.size(); index += 2) {
            if (value[index] == '\0') {
                ++utf16_markers;
            }
        }
    }
    if (utf16_markers >= value.size() / 4) {
        for (std::size_t index = 0; index + 1 < value.size(); index += 2) {
            decoded.push_back(value[index]);
        }
    } else {
        decoded = value;
    }

    if (decoded.size() >= 2 && decoded.front() == '"' && decoded.back() == '"') {
        decoded = decoded.substr(1, decoded.size() - 2);
    }
    return decoded;
}

std::optional<std::string> remove_password_attribute(std::map<std::string, std::string>& attributes) {
    for (const auto& name : {"unicodePwd", "userPassword", "clearTextPassword"}) {
        auto value = remove_ad_attribute(attributes, name);
        if (value.has_value() && !value->empty()) {
            return decode_ldap_password_value(*value);
        }
    }
    return std::nullopt;
}

bool has_object_class(const std::vector<std::string>& object_classes, const std::string& expected) {
    return std::any_of(object_classes.begin(), object_classes.end(), [&](const auto& value) {
        return lowercase_ascii(value) == lowercase_ascii(expected);
    });
}

void ensure_object_class(std::vector<std::string>& object_classes, const std::string& value) {
    if (!has_object_class(object_classes, value)) {
        object_classes.push_back(value);
    }
}

std::optional<std::pair<std::string, std::string>> rdn_attribute_from_dn(const std::string& dn) {
    const auto first_part = dn.substr(0, dn.find(','));
    const auto equals = first_part.find('=');
    if (equals == std::string::npos || equals == 0 || equals + 1 >= first_part.size()) {
        return std::nullopt;
    }
    return std::make_pair(first_part.substr(0, equals), first_part.substr(equals + 1));
}

std::string infer_ldap_object_kind(const nexus::protocol::LdapObject& object) {
    if (!object.kind.empty()) {
        return object.kind;
    }
    if (has_object_class(object.object_classes, "computer")) {
        return "computer";
    }
    if (has_object_class(object.object_classes, "group")) {
        return "group";
    }
    if (has_object_class(object.object_classes, "organizationalUnit")) {
        return "organizationalUnit";
    }
    if (has_object_class(object.object_classes, "container")) {
        return "container";
    }
    if (has_object_class(object.object_classes, "user") ||
        has_object_class(object.object_classes, "person") ||
        has_object_class(object.object_classes, "inetOrgPerson")) {
        return "user";
    }
    const auto rdn = rdn_attribute_from_dn(object.dn);
    if (rdn.has_value() && lowercase_ascii(rdn->first) == "ou") {
        return "organizationalUnit";
    }
    return "container";
}

void enrich_ldap_ad_object(
    const nexus::core::Config& config,
    nexus::protocol::LdapObject& object) {
    object.kind = infer_ldap_object_kind(object);
    if (object.parent_dn.empty()) {
        const auto comma = object.dn.find(',');
        object.parent_dn = comma == std::string::npos ? "" : object.dn.substr(comma + 1);
    }

    const auto rdn = rdn_attribute_from_dn(object.dn);
    if (rdn.has_value()) {
        set_ad_attribute(object.attributes, rdn->first, rdn->second, true);
    }

    if (object.kind == "computer") {
        ensure_object_class(object.object_classes, "top");
        ensure_object_class(object.object_classes, "person");
        ensure_object_class(object.object_classes, "organizationalPerson");
        ensure_object_class(object.object_classes, "user");
        ensure_object_class(object.object_classes, "computer");

        auto sam = find_ad_attribute(object.attributes, "sAMAccountName").value_or("");
        if (sam.empty()) {
            sam = find_ad_attribute(object.attributes, "cn").value_or(rdn.has_value() ? rdn->second : "machine");
        }
        if (sam.empty()) {
            sam = "machine";
        }
        if (sam.back() != '$') {
            sam.push_back('$');
        }
        const auto host = machine_host_from_sam(sam);
        const auto rid = synthetic_rid(sam);
        const auto domain_sid = synthetic_domain_sid(config.domain);
        const auto dns_host = find_ad_attribute(object.attributes, "dNSHostName")
                                  .value_or(host + "." + lowercase_ascii(config.domain));

        set_ad_attribute(object.attributes, "cn", host, true);
        set_ad_attribute(object.attributes, "displayName", host, true);
        set_ad_attribute(object.attributes, "sAMAccountName", sam);
        set_ad_attribute(object.attributes, "dNSHostName", dns_host, true);
        set_ad_attribute(object.attributes, "rid", std::to_string(rid), true);
        set_ad_attribute(object.attributes, "objectSid", domain_sid + "-" + std::to_string(rid), true);
        set_ad_attribute(object.attributes, "primaryGroupID", "515", true);
        set_ad_attribute(object.attributes, "groupRids", "515", true);
        set_ad_attribute(object.attributes, "userAccountControl", "4128", true);
        set_ad_attribute(object.attributes, "accountExpires", "9223372036854775807", true);
        set_ad_attribute(object.attributes, "pwdLastSet", "0", true);
        set_ad_attribute(object.attributes, "badPwdCount", "0", true);
        set_ad_attribute(object.attributes, "logonCount", "0", true);
        set_ad_attribute(object.attributes, "msDS-SupportedEncryptionTypes", "28", true);
        set_ad_attribute(
            object.attributes,
            "servicePrincipalName",
            merge_machine_spn_attribute(
                find_ad_attribute(object.attributes, "servicePrincipalName").value_or(""),
                host,
                dns_host));
        return;
    }

    if (object.kind == "user") {
        ensure_object_class(object.object_classes, "top");
        ensure_object_class(object.object_classes, "person");
        ensure_object_class(object.object_classes, "organizationalPerson");
        ensure_object_class(object.object_classes, "user");

        auto sam = find_ad_attribute(object.attributes, "sAMAccountName").value_or("");
        if (sam.empty()) {
            sam = find_ad_attribute(object.attributes, "uid").value_or("");
        }
        if (sam.empty()) {
            sam = find_ad_attribute(object.attributes, "cn").value_or(rdn.has_value() ? rdn->second : "user");
        }
        const auto rid = synthetic_rid(sam);
        const auto domain_sid = synthetic_domain_sid(config.domain);
        set_ad_attribute(object.attributes, "sAMAccountName", sam);
        set_ad_attribute(object.attributes, "userPrincipalName", sam + "@" + lowercase_ascii(config.domain), true);
        set_ad_attribute(object.attributes, "displayName", find_ad_attribute(object.attributes, "cn").value_or(sam), true);
        set_ad_attribute(object.attributes, "rid", std::to_string(rid), true);
        set_ad_attribute(object.attributes, "objectSid", domain_sid + "-" + std::to_string(rid), true);
        set_ad_attribute(object.attributes, "primaryGroupID", "513", true);
        set_ad_attribute(object.attributes, "groupRids", "513", true);
        set_ad_attribute(object.attributes, "userAccountControl", "512", true);
        set_ad_attribute(object.attributes, "accountExpires", "9223372036854775807", true);
        set_ad_attribute(object.attributes, "pwdLastSet", "0", true);
        set_ad_attribute(object.attributes, "badPwdCount", "0", true);
        set_ad_attribute(object.attributes, "logonCount", "0", true);
        set_ad_attribute(object.attributes, "msDS-SupportedEncryptionTypes", "28", true);
        return;
    }

    if (object.kind == "group") {
        ensure_object_class(object.object_classes, "top");
        ensure_object_class(object.object_classes, "group");
        const auto sam = find_ad_attribute(object.attributes, "sAMAccountName")
                             .value_or(find_ad_attribute(object.attributes, "cn").value_or(rdn.has_value() ? rdn->second : "group"));
        const auto rid = synthetic_rid(sam);
        const auto domain_sid = synthetic_domain_sid(config.domain);
        set_ad_attribute(object.attributes, "sAMAccountName", sam);
        set_ad_attribute(object.attributes, "rid", std::to_string(rid), true);
        set_ad_attribute(object.attributes, "objectSid", domain_sid + "-" + std::to_string(rid), true);
        set_ad_attribute(object.attributes, "groupType", "-2147483646", true);
        return;
    }

    if (object.kind == "organizationalUnit") {
        ensure_object_class(object.object_classes, "top");
        ensure_object_class(object.object_classes, "organizationalUnit");
    } else {
        ensure_object_class(object.object_classes, "top");
        ensure_object_class(object.object_classes, "container");
    }
}

bool persist_ad_account_secret(
    PGconn* conn,
    const nexus::core::Config& config,
    const std::string& object_dn,
    const std::string& sam,
    const std::string& password,
    const std::string& source) {
    if (object_dn.empty() || sam.empty() || password.empty()) {
        return true;
    }
    try {
        const auto material = nexus::security::derive_ad_credentials(password, config.directory.realm, sam);
        const auto wrapped_nt_hash = nexus::security::seal_ad_secret(kerberos_key_file(config), material.nt_hash_hex);
        const auto wrapped_keys = wrapped_kerberos_keys_json(material, config);
        const std::string secret_sql =
            "insert into ad_account_secrets(object_dn,wrapped_nt_hash,wrapped_kerberos_keys,updated_at) values (" +
            sql_literal(conn, object_dn) + "," +
            sql_literal(conn, wrapped_nt_hash) + "," +
            sql_literal(conn, wrapped_keys) + "::jsonb,now()) "
            "on conflict (object_dn) do update set "
            "wrapped_nt_hash=excluded.wrapped_nt_hash, "
            "wrapped_kerberos_keys=excluded.wrapped_kerberos_keys, "
            "updated_at=now();";
        PGresult* result = PQexec(conn, secret_sql.c_str());
        const bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
        if (!ok) {
            std::cerr << "[nexus-directory] failed to persist " << source << " AD secret: "
                      << PQresultErrorMessage(result) << '\n';
        }
        PQclear(result);
        return ok && stamp_ad_password_metadata_to_database(conn, object_dn);
    } catch (const std::exception& error) {
        std::cerr << "[nexus-directory] failed to derive " << source << " AD secret: "
                  << error.what() << '\n';
        return false;
    }
}

nexus::protocol::LdapMutationResult persist_ldap_mutation(
    const nexus::core::Config& config,
    const nexus::protocol::LdapMutation& mutation) {
    if (mutation.object.dn.empty() || !nexus::protocol::is_valid_dn(mutation.object.dn)) {
        return {false, 34, "invalid distinguished name"};
    }
    if (config.database_url.empty()) {
        return {true, 0, ""};
    }

    PGconn* conn = PQconnectdb(config.database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "[nexus-directory] database unavailable; LDAP write was accepted in-memory only\n";
        PQfinish(conn);
        return {true, 0, ""};
    }
    mirror_identity_objects_into_ad_objects(conn, config);

    if (mutation.type == nexus::protocol::LdapMutationType::remove) {
        const auto object_dn = sql_literal(conn, mutation.object.dn);
        PGresult* secrets = PQexec(conn, ("delete from ad_account_secrets where object_dn = " + object_dn + ";").c_str());
        const bool secrets_ok = PQresultStatus(secrets) == PGRES_COMMAND_OK;
        PQclear(secrets);
        if (!secrets_ok) {
            PQfinish(conn);
            return {false, 80, "failed to delete account secrets"};
        }

        PGresult* spns = PQexec(conn, ("delete from ad_service_principals where object_dn = " + object_dn + ";").c_str());
        const bool spns_ok = PQresultStatus(spns) == PGRES_COMMAND_OK;
        PQclear(spns);
        if (!spns_ok) {
            PQfinish(conn);
            return {false, 80, "failed to delete service principals"};
        }

        const std::string memberships_sql =
            "delete from ad_memberships where group_dn = " + object_dn + " or member_dn = " + object_dn + ";";
        PGresult* memberships = PQexec(conn, memberships_sql.c_str());
        const bool memberships_ok = PQresultStatus(memberships) == PGRES_COMMAND_OK;
        PQclear(memberships);
        if (!memberships_ok) {
            PQfinish(conn);
            return {false, 80, "failed to delete memberships"};
        }

        PGresult* ad_result = PQexec(conn, ("delete from ad_objects where dn = " + object_dn + ";").c_str());
        const bool ad_ok = PQresultStatus(ad_result) == PGRES_COMMAND_OK;
        const bool ad_deleted = ad_ok && std::string(PQcmdTuples(ad_result)) != "0";
        if (!ad_ok) {
            std::cerr << "[nexus-directory] failed to delete canonical LDAP object: "
                      << PQresultErrorMessage(ad_result) << '\n';
        }
        PQclear(ad_result);

        PGresult* result = PQexec(conn, ("delete from identity_objects where dn = " + object_dn + ";").c_str());
        const bool ok = PQresultStatus(result) == PGRES_COMMAND_OK;
        const bool projection_deleted = ok && std::string(PQcmdTuples(result)) != "0";
        if (!ok) {
            std::cerr << "[nexus-directory] failed to delete LDAP object: "
                      << PQresultErrorMessage(result) << '\n';
        }
        PQclear(result);
        PQfinish(conn);
        const bool deleted = ad_deleted || projection_deleted;
        return deleted ? nexus::protocol::LdapMutationResult{true, 0, ""}
                       : nexus::protocol::LdapMutationResult{false, 32, "LDAP object was not found"};
    }

    if (mutation.type == nexus::protocol::LdapMutationType::rename) {
        if (mutation.previous_dn.empty() || !nexus::protocol::is_valid_dn(mutation.previous_dn)) {
            PQfinish(conn);
            return {false, 34, "invalid previous distinguished name"};
        }
        if (!mutation.object.parent_dn.empty() && !nexus::protocol::is_valid_dn(mutation.object.parent_dn)) {
            PQfinish(conn);
            return {false, 34, "invalid parent distinguished name"};
        }

        const auto old_dn = sql_literal(conn, mutation.previous_dn);
        const auto new_dn = sql_literal(conn, mutation.object.dn);

        const std::string conflict_sql =
            "select 1 from ad_objects "
            "where dn = " + new_dn + " and dn <> " + old_dn + " "
            "limit 1";
        PGresult* conflict = PQexec(conn, conflict_sql.c_str());
        const bool conflict_ok = PQresultStatus(conflict) == PGRES_TUPLES_OK;
        const bool exists = conflict_ok && PQntuples(conflict) > 0;
        if (!conflict_ok) {
            std::cerr << "[nexus-directory] failed to check LDAP rename conflict: "
                      << PQresultErrorMessage(conflict) << '\n';
            PQclear(conflict);
            PQfinish(conn);
            return {false, 80, "failed to check LDAP rename conflict"};
        }
        PQclear(conflict);
        if (exists) {
            PQfinish(conn);
            return {false, 68, "LDAP target object already exists"};
        }

        auto previous_object = lookup_ldap_object_by_dn(conn, mutation.previous_dn);
        if (!previous_object.has_value()) {
            PQfinish(conn);
            return {false, 32, "LDAP object was not found"};
        }

        auto object = *previous_object;
        object.dn = mutation.object.dn;
        object.parent_dn = mutation.object.parent_dn;
        if (object.parent_dn.empty()) {
            const auto comma = object.dn.find(',');
            object.parent_dn = comma == std::string::npos ? "" : object.dn.substr(comma + 1);
        }
        for (const auto& [key, value] : mutation.attributes) {
            set_ad_attribute(object.attributes, key, value);
        }
        set_ad_attribute(object.attributes, "distinguishedName", object.dn);
        if (const auto rdn = rdn_attribute_from_dn(object.dn); rdn.has_value()) {
            set_ad_attribute(object.attributes, rdn->first, rdn->second);
            set_ad_attribute(object.attributes, "name", rdn->second);
        }
        enrich_ldap_ad_object(config, object);

        PGresult* begin = PQexec(conn, "begin");
        const bool begin_ok = PQresultStatus(begin) == PGRES_COMMAND_OK;
        PQclear(begin);
        if (!begin_ok) {
            PQfinish(conn);
            return {false, 80, "failed to start LDAP rename transaction"};
        }

        const std::string delete_old_spn_sql =
            "delete from ad_service_principals where object_dn = " + old_dn +
            " or object_dn = " + new_dn + ";";
        PGresult* delete_old_spn = PQexec(conn, delete_old_spn_sql.c_str());
        const bool delete_old_spn_ok = PQresultStatus(delete_old_spn) == PGRES_COMMAND_OK;
        if (!delete_old_spn_ok) {
            std::cerr << "[nexus-directory] failed to clear LDAP rename SPNs: "
                      << PQresultErrorMessage(delete_old_spn) << '\n';
        }
        PQclear(delete_old_spn);
        if (!delete_old_spn_ok) {
            PGresult* rollback = PQexec(conn, "rollback");
            PQclear(rollback);
            PQfinish(conn);
            return {false, 80, "failed to persist LDAP rename"};
        }

        PGresult* delete_identity = PQexec(conn, ("delete from identity_objects where dn = " + old_dn + ";").c_str());
        const bool delete_identity_ok = PQresultStatus(delete_identity) == PGRES_COMMAND_OK;
        PQclear(delete_identity);
        PGresult* delete_ad = PQexec(conn, ("delete from ad_objects where dn = " + old_dn + ";").c_str());
        const bool delete_ad_ok = PQresultStatus(delete_ad) == PGRES_COMMAND_OK;
        PQclear(delete_ad);
        if (!delete_identity_ok || !delete_ad_ok || !persist_ldap_object_to_connection(conn, config, object, false)) {
            PGresult* rollback = PQexec(conn, "rollback");
            PQclear(rollback);
            PQfinish(conn);
            return {false, 80, "failed to persist LDAP rename"};
        }

        const std::string secrets_sql =
            "update ad_account_secrets set "
            "object_dn = " + sql_literal(conn, object.dn) + ", "
            "updated_at = now() "
            "where object_dn = " + old_dn + ";";
        PGresult* secrets = PQexec(conn, secrets_sql.c_str());
        const bool secrets_ok = PQresultStatus(secrets) == PGRES_COMMAND_OK;
        if (!secrets_ok) {
            std::cerr << "[nexus-directory] failed to move LDAP rename secrets: "
                      << PQresultErrorMessage(secrets) << '\n';
            PQclear(secrets);
            PGresult* rollback = PQexec(conn, "rollback");
            PQclear(rollback);
            PQfinish(conn);
            return {false, 80, "failed to move LDAP account secrets"};
        }
        PQclear(secrets);

        const std::string memberships_group_sql =
            "update ad_memberships set group_dn = " + new_dn + " where group_dn = " + old_dn + ";";
        PGresult* memberships_group = PQexec(conn, memberships_group_sql.c_str());
        const bool memberships_group_ok = PQresultStatus(memberships_group) == PGRES_COMMAND_OK;
        PQclear(memberships_group);
        const std::string memberships_member_sql =
            "update ad_memberships set member_dn = " + new_dn + " where member_dn = " + old_dn + ";";
        PGresult* memberships_member = PQexec(conn, memberships_member_sql.c_str());
        const bool memberships_member_ok = PQresultStatus(memberships_member) == PGRES_COMMAND_OK;
        PQclear(memberships_member);
        if (!memberships_group_ok || !memberships_member_ok) {
            PGresult* rollback = PQexec(conn, "rollback");
            PQclear(rollback);
            PQfinish(conn);
            return {false, 80, "failed to move LDAP memberships"};
        }

        PGresult* commit = PQexec(conn, "commit");
        const bool commit_ok = PQresultStatus(commit) == PGRES_COMMAND_OK;
        PQclear(commit);
        PQfinish(conn);
        return commit_ok ? nexus::protocol::LdapMutationResult{true, 0, ""}
                         : nexus::protocol::LdapMutationResult{false, 80, "failed to commit LDAP rename"};
    }

    if (mutation.type == nexus::protocol::LdapMutationType::modify) {
        auto attributes = mutation.attributes;
        const auto new_password = remove_password_attribute(attributes);
        if (attributes.empty() && !new_password.has_value()) {
            PQfinish(conn);
            return {true, 0, ""};
        }

        auto object = lookup_ldap_object_by_dn(conn, mutation.object.dn);
        if (!object.has_value()) {
            PQfinish(conn);
            return {false, 32, "LDAP object was not found"};
        }
        const auto previous_member_dns = split_ldap_member_dns(find_ad_attribute(object->attributes, "member").value_or(""));
        const bool membership_touched = std::any_of(attributes.begin(), attributes.end(), [](const auto& entry) {
            return lowercase_ascii(entry.first) == "member";
        });

        if (!attributes.empty() || new_password.has_value()) {
            for (const auto& [key, value] : attributes) {
                const auto operation = mutation.attribute_operations.contains(key)
                    ? mutation.attribute_operations.at(key)
                    : 2;
                apply_ldap_attribute_modify(object->attributes, key, value, operation);
            }
            enrich_ldap_ad_object(config, *object);
            const auto sam_after_modify = find_ad_attribute(object->attributes, "sAMAccountName").value_or("");
            if (new_password.has_value()) {
                stamp_ad_password_metadata(object->attributes, sam_after_modify);
            }
            if (!persist_ldap_object_to_connection(conn, config, *object, false)) {
                PQfinish(conn);
                return {false, 80, "failed to persist LDAP modify"};
            }
            if (membership_touched && !sync_ldap_group_memberships(conn, config, *object, previous_member_dns)) {
                PQfinish(conn);
                return {false, 80, "failed to persist LDAP group memberships"};
            }
        }

        const auto sam = find_ad_attribute(object->attributes, "sAMAccountName").value_or("");
        if (new_password.has_value() &&
            !persist_ad_account_secret(conn, config, mutation.object.dn, sam, *new_password, "LDAP")) {
            PQfinish(conn);
            return {false, 80, "failed to persist LDAP password"};
        }

        PQfinish(conn);
        return {true, 0, ""};
    }

    auto object = mutation.object;
    for (const auto& [key, value] : mutation.attributes) {
        set_ad_attribute(object.attributes, key, value);
    }
    const auto new_password = remove_password_attribute(object.attributes);
    enrich_ldap_ad_object(config, object);
    if (new_password.has_value()) {
        const auto sam = find_ad_attribute(object.attributes, "sAMAccountName").value_or("");
        stamp_ad_password_metadata(object.attributes, sam);
    }

    const bool ok = persist_ldap_object_to_connection(conn, config, object, true);
    if (!ok) {
        std::cerr << "[nexus-directory] failed to persist LDAP add: " << object.dn << '\n';
    }
    if (ok && new_password.has_value()) {
        const auto sam = find_ad_attribute(object.attributes, "sAMAccountName").value_or("");
        if (!persist_ad_account_secret(conn, config, object.dn, sam, *new_password, "LDAP add")) {
            PQfinish(conn);
            return {false, 80, "failed to persist LDAP add password"};
        }
    }
    if (ok && find_ad_attribute(object.attributes, "member").has_value() &&
        !sync_ldap_group_memberships(conn, config, object, {})) {
        PQfinish(conn);
        return {false, 80, "failed to persist LDAP add memberships"};
    }
    PQfinish(conn);
    return ok ? nexus::protocol::LdapMutationResult{true, 0, ""}
              : nexus::protocol::LdapMutationResult{false, 80, "failed to persist LDAP object"};
}

std::vector<std::string> kpasswd_lookup_candidates(const nexus::protocol::KerberosPasswordChange& change) {
    std::vector<std::string> candidates;
    const auto add = [&](std::string value) {
        if (value.empty()) {
            return;
        }
        if (std::find(candidates.begin(), candidates.end(), value) == candidates.end()) {
            candidates.push_back(value);
        }
    };
    const auto add_principal = [&](const std::string& value) {
        add(value);
        if (const auto at = value.find('@'); at != std::string::npos) {
            add(value.substr(0, at));
        }
    };

    add_principal(change.target_principal);
    add_principal(change.principal);
    if (!change.principal.empty() && !change.realm.empty() && change.principal.find('@') == std::string::npos) {
        add(change.principal + "@" + lowercase_ascii(change.realm));
    }
    return candidates;
}

bool persist_kpasswd_password_change(
    const nexus::core::Config& config,
    const nexus::protocol::KerberosPasswordChange& change) {
    if (config.database_url.empty() || change.new_password.empty()) {
        return false;
    }

    const auto candidates = kpasswd_lookup_candidates(change);
    if (candidates.empty()) {
        return false;
    }

    PGconn* conn = PQconnectdb(config.database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "[nexus-directory] database unavailable; kpasswd password update was not persisted\n";
        PQfinish(conn);
        return false;
    }
    mirror_identity_objects_into_ad_objects(conn, config);

    std::string where = "(";
    bool first = true;
    for (const auto& candidate : candidates) {
        const auto normalized = sql_literal(conn, lowercase_ascii(candidate));
        if (!first) {
            where += " or ";
        }
        first = false;
        where += "lower(attributes->>'sAMAccountName') = " + normalized +
            " or lower(attributes->>'userPrincipalName') = " + normalized;
    }
    where += ")";

    auto object = lookup_ldap_object_where(conn, where);
    if (!object.has_value()) {
        std::cerr << "[nexus-directory] kpasswd password update ignored for unknown principal "
                  << change.principal << '\n';
        PQfinish(conn);
        return false;
    }

    const auto sam = find_ad_attribute(object->attributes, "sAMAccountName").value_or("");
    stamp_ad_password_metadata(object->attributes, sam);
    if (!persist_ldap_object_to_connection(conn, config, *object, false)) {
        std::cerr << "[nexus-directory] failed to persist kpasswd password metadata for "
                  << object->dn << '\n';
        PQfinish(conn);
        return false;
    }
    const bool ok = persist_ad_account_secret(conn, config, object->dn, sam, change.new_password, "kpasswd");
    PQfinish(conn);
    return ok;
}

bool persist_netlogon_machine_password(
    const nexus::core::Config& config,
    const nexus::protocol::NetlogonPasswordUpdate& update) {
    if (config.database_url.empty() || update.sam_account_name.empty() || update.new_password.empty()) {
        return false;
    }

    PGconn* conn = PQconnectdb(config.database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        std::cerr << "[nexus-directory] database unavailable; Netlogon password update was not persisted\n";
        PQfinish(conn);
        return false;
    }
    mirror_identity_objects_into_ad_objects(conn, config);

    auto object = lookup_ldap_object_where(
        conn,
        "lower(attributes->>'sAMAccountName') = lower(" + sql_literal(conn, update.sam_account_name) + ")");
    if (!object.has_value()) {
        std::cerr << "[nexus-directory] Netlogon password update ignored for unknown machine account "
                  << update.sam_account_name << '\n';
        PQfinish(conn);
        return false;
    }

    const std::string object_dn = object->dn;
    const std::string sam = find_ad_attribute(object->attributes, "sAMAccountName").value_or("");
    if (sam.empty()) {
        PQfinish(conn);
        return false;
    }

    stamp_ad_password_metadata(object->attributes, sam);
    if (!persist_ldap_object_to_connection(conn, config, *object, false)) {
        std::cerr << "[nexus-directory] failed to persist Netlogon password metadata for "
                  << object_dn << '\n';
        PQfinish(conn);
        return false;
    }
    const bool ok = persist_ad_account_secret(conn, config, object_dn, sam, update.new_password, "Netlogon");
    PQfinish(conn);
    return ok;
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
        synthetic_domain_sid(config.domain),
    };

    std::mutex ldap_sessions_mutex;
    std::map<std::string, nexus::protocol::LdapSessionInfo> ldap_sessions;
    auto ldap_handler = [config, directory, &ldap_sessions_mutex, &ldap_sessions](
                            const std::string& connection_label,
                            const nexus::core::UvPacket& packet) {
        const nexus::protocol::KerberosRealmInfo ldap_kerberos_realm{
            config.directory.realm,
            "krbtgt",
            load_kerberos_principals(config),
        };
        nexus::protocol::LdapSessionInfo session;
        {
            std::lock_guard<std::mutex> lock(ldap_sessions_mutex);
            const auto it = ldap_sessions.find(connection_label);
            if (it != ldap_sessions.end()) {
                session = it->second;
            }
        }

        auto response = nexus::protocol::ldap_ad_response(
            packet,
            directory,
            load_ldap_objects(config),
            [config](const nexus::protocol::LdapMutation& mutation) {
                return persist_ldap_mutation(config, mutation);
            },
            ldap_kerberos_realm,
            &session,
            [config](const std::string& bind_name, const std::string& password) {
                return verify_ldap_simple_bind(config, bind_name, password);
            });
        {
            std::lock_guard<std::mutex> lock(ldap_sessions_mutex);
            if (ldap_sessions.size() > 1024) {
                ldap_sessions.erase(ldap_sessions.begin());
            }
            ldap_sessions[connection_label] = std::move(session);
        }
        return response;
    };
    auto kerberos_realm = [config]() {
        return nexus::protocol::KerberosRealmInfo{
            config.directory.realm,
            "krbtgt",
            load_kerberos_principals(config),
        };
    };
    auto kerberos_udp_handler = [kerberos_realm](const std::string&, const nexus::core::UvPacket& packet) {
        return nexus::protocol::kerberos_error_response(packet, kerberos_realm());
    };
    auto kerberos_tcp_handler = [kerberos_realm](const std::string&, const nexus::core::UvPacket& packet) {
        return nexus::protocol::kerberos_tcp_error_response(packet, kerberos_realm());
    };
    auto kpasswd_udp_handler = [config, kerberos_realm](const std::string&, const nexus::core::UvPacket& packet) {
        return nexus::protocol::kerberos_kpasswd_response(
            packet,
            kerberos_realm(),
            [config](const nexus::protocol::KerberosPasswordChange& change) {
                return persist_kpasswd_password_change(config, change);
            });
    };
    auto kpasswd_tcp_handler = [config, kerberos_realm](const std::string&, const nexus::core::UvPacket& packet) {
        return nexus::protocol::kerberos_tcp_kpasswd_response(
            packet,
            kerberos_realm(),
            [config](const nexus::protocol::KerberosPasswordChange& change) {
                return persist_kpasswd_password_change(config, change);
            });
    };
    auto rpc_handler = [config](const std::string&, const nexus::core::UvPacket& packet) {
        return nexus::protocol::rpc_endpoint_mapper_response(packet, static_cast<std::uint16_t>(config.rpc.port));
    };
    auto smb_handler = [config, kerberos_realm](const std::string&, const nexus::core::UvPacket& packet) {
        nexus::protocol::RpcRuntimeInfo rpc_runtime{
            load_netlogon_account_secrets(config),
            [config](const nexus::protocol::NetlogonPasswordUpdate& update) {
                return persist_netlogon_machine_password(config, update);
            },
            [config](const nexus::protocol::SamrAccountRequest& request) {
                return handle_samr_account_request(config, request);
            },
            [config](const nexus::protocol::SamrAccountUpdate& update) {
                return handle_samr_account_update(config, update);
            },
            {},
            netbios_name_from_domain(config.domain),
            config.domain,
            synthetic_domain_sid(config.domain),
            config.directory.domain_controller_host,
            config.directory.domain_controller_address,
            config.directory.site_name,
        };
        rpc_runtime.samr_account_enumerator = [config]() {
            return load_samr_account_records(config);
        };
        rpc_runtime.samr_membership_update_handler = [config](const nexus::protocol::SamrMembershipUpdate& update) {
            return handle_samr_membership_update(config, update);
        };
        return nexus::protocol::smb2_response(packet, {
            rpc_runtime,
            kerberos_realm(),
            "cifs/" + lowercase_ascii(config.directory.domain_controller_host + "." + config.domain),
        });
    };

    return nexus::core::run_uv_daemon(
        "directory",
        std::vector<nexus::core::UvListener>{
            // Stream protocols (LDAP/Kerberos-TCP/kpasswd-TCP/RPC) keep the
            // connection open after each response: real LDAP/AD clients issue a
            // bind followed by many searches on a single connection, and DCE/RPC
            // multiplexes a bind plus several operations per connection. Closing
            // after the first reply (the default) makes ldapsearch and Windows
            // domain join hang on their second PDU.
            {"ldap", config.ldap.host, config.ldap.port, nexus::core::UvTransport::tcp, ldap_handler, false},
            {"cldap", config.ldap.host, config.ldap.port, nexus::core::UvTransport::udp, ldap_handler},
            {"ldaps", config.ldaps.host, config.ldaps.port, nexus::core::UvTransport::tcp, ldap_handler, false},
            {"global-catalog", config.gc.host, config.gc.port, nexus::core::UvTransport::tcp, ldap_handler, false},
            {"kerberos-tcp", config.kerberos.host, config.kerberos.port, nexus::core::UvTransport::tcp, kerberos_tcp_handler, false},
            {"kerberos-udp", config.kerberos.host, config.kerberos.port, nexus::core::UvTransport::udp, kerberos_udp_handler},
            {"kpasswd-tcp", config.kpasswd.host, config.kpasswd.port, nexus::core::UvTransport::tcp, kpasswd_tcp_handler, false},
            {"kpasswd-udp", config.kpasswd.host, config.kpasswd.port, nexus::core::UvTransport::udp, kpasswd_udp_handler},
            {"rpc-epmapper", config.rpc.host, config.rpc.port, nexus::core::UvTransport::tcp, rpc_handler, false},
            {"smb2", config.smb.host, config.smb.port, nexus::core::UvTransport::tcp, smb_handler, false},
        });
}
