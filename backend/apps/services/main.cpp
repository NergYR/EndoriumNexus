#include "nexus/core/config.hpp"

#include <json/json.h>
#include <libpq-fe.h>

#include <csignal>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <string>
#include <vector>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace {

struct ServiceSpec {
    std::string id;
    std::filesystem::path binary;
};

struct RunningService {
    pid_t pid{-1};
    std::filesystem::path binary;
};

std::string read_string(const Json::Value& body, const char* key, const std::string& fallback) {
    return body.isMember(key) ? body[key].asString() : fallback;
}

int read_port(const Json::Value& body, const char* key, int fallback) {
    if (!body.isMember(key)) {
        return fallback;
    }
    const int value = body[key].asInt();
    return value > 0 ? value : fallback;
}

nexus::core::Config config_from_json(const nexus::core::Config& current, const Json::Value& body) {
    nexus::core::Config updated = current;
    updated.environment = read_string(body, "environment", current.environment);
    updated.domain = read_string(body, "domain", current.domain);
    updated.ad_port_profile = read_string(body, "adPortProfile", current.ad_port_profile);
    if (updated.ad_port_profile != "standard") {
        updated.ad_port_profile = "dev";
    }
    updated.blob_root = read_string(body, "blobRoot", current.blob_root.string());
    updated.state_root = read_string(body, "stateRoot", current.state_root.string());
    updated.database_url = read_string(body, "databaseUrl", current.database_url);
    updated.admin_email = read_string(body, "adminEmail", current.admin_email);
    updated.admin_password_hash = read_string(body, "adminPasswordHash", current.admin_password_hash);
    updated.admin_totp_secret = read_string(body, "adminTotpSecret", current.admin_totp_secret);
    updated.http.port = read_port(body, "httpPort", current.http.port);
    updated.ldap.port = read_port(body, "ldapPort", current.ldap.port);
    updated.ldaps.port = read_port(body, "ldapsPort", current.ldaps.port);
    updated.gc.port = read_port(body, "gcPort", current.gc.port);
    updated.kerberos.port = read_port(body, "kerberosPort", current.kerberos.port);
    updated.kpasswd.port = read_port(body, "kpasswdPort", current.kpasswd.port);
    updated.rpc.port = read_port(body, "rpcPort", current.rpc.port);
    updated.smb.port = read_port(body, "smbPort", current.smb.port);
    updated.dns_tcp.port = read_port(body, "dnsTcpPort", current.dns_tcp.port);
    updated.dns_udp.port = read_port(body, "dnsUdpPort", current.dns_udp.port);
    updated.dhcp.port = read_port(body, "dhcpPort", current.dhcp.port);
    if (body.isMember("ports") && body["ports"].isObject()) {
        const auto& ports = body["ports"];
        if (ports.isMember("http")) updated.http.port = ports["http"].asInt();
        if (ports.isMember("ldap")) updated.ldap.port = ports["ldap"].asInt();
        if (ports.isMember("ldaps")) updated.ldaps.port = ports["ldaps"].asInt();
        if (ports.isMember("gc")) updated.gc.port = ports["gc"].asInt();
        if (ports.isMember("kerberos")) updated.kerberos.port = ports["kerberos"].asInt();
        if (ports.isMember("kpasswd")) updated.kpasswd.port = ports["kpasswd"].asInt();
        if (ports.isMember("rpc")) updated.rpc.port = ports["rpc"].asInt();
        if (ports.isMember("smb")) updated.smb.port = ports["smb"].asInt();
        if (ports.isMember("dnsTcp")) updated.dns_tcp.port = ports["dnsTcp"].asInt();
        if (ports.isMember("dnsUdp")) updated.dns_udp.port = ports["dnsUdp"].asInt();
        if (ports.isMember("dhcp")) updated.dhcp.port = ports["dhcp"].asInt();
    }
    updated.features.clear();
    if (body.isMember("features") && body["features"].isObject()) {
        const auto& features = body["features"];
        for (const auto& key : features.getMemberNames()) {
            updated.features[key] = features[key].asBool();
        }
    }
    return updated;
}

std::optional<nexus::core::Config> load_persisted_config(const nexus::core::Config& fallback) {
    const auto path = fallback.state_root / "settings.json";
    if (!std::filesystem::exists(path)) {
        return std::nullopt;
    }

    std::ifstream input(path);
    if (!input.is_open()) {
        return std::nullopt;
    }

    Json::CharReaderBuilder builder;
    builder["collectComments"] = false;
    Json::Value body;
    std::string errors;
    if (!Json::parseFromStream(builder, input, &body, &errors)) {
        std::cerr << "[nexus-services] failed to parse settings.json: " << errors << '\n';
        return std::nullopt;
    }

    return config_from_json(fallback, body);
}

void set_env(const std::string& key, const std::string& value) {
    ::setenv(key.c_str(), value.c_str(), 1);
}

void export_config_env(const nexus::core::Config& config) {
    set_env("NEXUS_ENV", config.environment);
    set_env("NEXUS_DOMAIN", config.domain);
    set_env("NEXUS_AD_PORT_PROFILE", config.ad_port_profile);
    set_env("NEXUS_HTTP_HOST", config.http.host);
    set_env("NEXUS_HTTP_PORT", std::to_string(config.http.port));
    set_env("NEXUS_LDAP_PORT", std::to_string(config.ldap.port));
    set_env("NEXUS_LDAPS_PORT", std::to_string(config.ldaps.port));
    set_env("NEXUS_GC_PORT", std::to_string(config.gc.port));
    set_env("NEXUS_KRB_PORT", std::to_string(config.kerberos.port));
    set_env("NEXUS_KPASSWD_PORT", std::to_string(config.kpasswd.port));
    set_env("NEXUS_RPC_PORT", std::to_string(config.rpc.port));
    set_env("NEXUS_SMB_PORT", std::to_string(config.smb.port));
    set_env("NEXUS_DNS_TCP_PORT", std::to_string(config.dns_tcp.port));
    set_env("NEXUS_DNS_UDP_PORT", std::to_string(config.dns_udp.port));
    set_env("NEXUS_DHCP_PORT", std::to_string(config.dhcp.port));
    set_env("NEXUS_DATABASE_URL", config.database_url);
    set_env("NEXUS_ADMIN_EMAIL", config.admin_email);
    set_env("NEXUS_ADMIN_PASSWORD_HASH", config.admin_password_hash);
    set_env("NEXUS_ADMIN_TOTP_SECRET", config.admin_totp_secret);
    set_env("NEXUS_UI_DIST_DIR", config.ui_dist_dir.string());
    set_env("NEXUS_BLOB_ROOT", config.blob_root.string());
    set_env("NEXUS_STATE_ROOT", config.state_root.string());
}

std::vector<ServiceSpec> make_services(const std::filesystem::path& bin_dir) {
    std::vector<ServiceSpec> services;
    for (const auto& definition : nexus::core::service_definitions()) {
        if (definition.binary_name.empty() || definition.id == "api") {
            continue;
        }
        services.push_back({definition.id, bin_dir / definition.binary_name});
    }
    return services;
}

std::optional<pid_t> spawn_service(const ServiceSpec& spec) {
    if (!std::filesystem::exists(spec.binary)) {
        std::cerr << "[nexus-services] missing binary: " << spec.binary << '\n';
        return std::nullopt;
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        std::cerr << "[nexus-services] fork failed for " << spec.id << '\n';
        return std::nullopt;
    }

    if (pid == 0) {
        std::string path = spec.binary.string();
        char* argv[] = {path.data(), nullptr};
        ::execv(path.c_str(), argv);
        std::perror("execv");
        _exit(127);
    }

    return pid;
}

void stop_service(RunningService& service) {
    if (service.pid <= 0) {
        return;
    }

    ::kill(service.pid, SIGTERM);
    for (int attempts = 0; attempts < 20; ++attempts) {
        int status = 0;
        const pid_t result = ::waitpid(service.pid, &status, WNOHANG);
        if (result == service.pid) {
            service.pid = -1;
            return;
        }
        std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    ::kill(service.pid, SIGKILL);
    ::waitpid(service.pid, nullptr, 0);
    service.pid = -1;
}

// Check if service has all required configuration (non-verbose)
// Returns: pair<can_start, reason>
std::pair<bool, std::string> can_start_service(const std::string& service_id, const std::string& database_url) {
    if (database_url.empty()) {
        return {false, "database not configured"};
    }

    PGconn* conn = PQconnectdb(database_url.c_str());
    if (PQstatus(conn) != CONNECTION_OK) {
        PQfinish(conn);
        return {false, "database connection failed"};
    }

    std::pair<bool, std::string> result = {false, "unknown reason"};

    if (service_id == "network") {
        // Network service needs at least one DNS zone and one DHCP pool
        PGresult* zones_result = PQexec(conn, "SELECT COUNT(*) FROM dns_zones");
        PGresult* pools_result = PQexec(conn, "SELECT COUNT(*) FROM dhcp_pools");

        if (PQresultStatus(zones_result) == PGRES_TUPLES_OK && PQresultStatus(pools_result) == PGRES_TUPLES_OK) {
            try {
                const int zone_count = std::stoi(PQgetvalue(zones_result, 0, 0));
                const int pool_count = std::stoi(PQgetvalue(pools_result, 0, 0));

                if (zone_count > 0 && pool_count > 0) {
                    result = {true, std::to_string(zone_count) + " zones, " + std::to_string(pool_count) + " pools"};
                } else {
                    result = {false, "needs ≥1 DNS zone and ≥1 DHCP pool (found " + std::to_string(zone_count) + " zones, " + std::to_string(pool_count) + " pools)"};
                }
            } catch (const std::exception& e) {
                result = {false, std::string("query parse error: ") + e.what()};
            }
        } else {
            result = {false, "dns/dhcp query failed"};
        }

        PQclear(zones_result);
        PQclear(pools_result);
    } else if (service_id == "directory") {
        // Directory service just needs database connectivity
        result = {true, "database connected"};
    } else if (service_id == "pki-repo") {
        // PKI repository needs at least one certificate authority
        PGresult* authorities_result = PQexec(conn, "SELECT COUNT(*) FROM pki_authorities");

        if (PQresultStatus(authorities_result) == PGRES_TUPLES_OK) {
            try {
                const int authority_count = std::stoi(PQgetvalue(authorities_result, 0, 0));

                if (authority_count > 0) {
                    result = {true, std::to_string(authority_count) + " authorities"};
                } else {
                    result = {false, "needs ≥1 PKI authority"};
                }
            } catch (const std::exception& e) {
                result = {false, std::string("query parse error: ") + e.what()};
            }
        } else {
            result = {false, "pki query failed"};
        }

        PQclear(authorities_result);
    } else {
        // Unknown service, allow it
        result = {true, "no prerequisites required"};
    }

    PQfinish(conn);
    return result;
}


}  // namespace

int main(int argc, char** argv) {
    const auto fallback = nexus::core::Config::from_env();
    auto config = load_persisted_config(fallback).value_or(fallback);
    export_config_env(config);

    const std::filesystem::path executable_path = std::filesystem::weakly_canonical(argv[0]);
    const auto bin_dir = executable_path.parent_path();
    const auto services = make_services(bin_dir);

    std::map<std::string, RunningService> running;
    std::map<std::string, bool> blocked_services;  // Track services waiting for prerequisites
    
    auto desired_enabled = [&](const std::string& id) {
        const auto it = config.features.find(id);
        return it != config.features.end() && it->second;
    };

    auto reconcile = [&]() {
        for (const auto& spec : services) {
            const bool should_run = desired_enabled(spec.id);
            const auto existing = running.find(spec.id);
            const auto blocked_it = blocked_services.find(spec.id);
            const bool was_blocked = blocked_it != blocked_services.end() && blocked_it->second;

            if (should_run && existing == running.end()) {
                // Check if service has all required configuration
                auto [can_start, reason] = can_start_service(spec.id, config.database_url);
                if (!can_start) {
                    if (!was_blocked) {
                        // First time blocking this service
                        blocked_services[spec.id] = true;
                        std::cerr << "[nexus-services] " << spec.id << " is blocked: " << reason << "\n";
                    }
                    continue;
                }

                // Prerequisites are now met
                if (was_blocked) {
                    blocked_services[spec.id] = false;
                    std::cout << "[nexus-services] " << spec.id << " prerequisites satisfied (" << reason << "), starting\n";
                }

                if (const auto pid = spawn_service(spec)) {
                    running.emplace(spec.id, RunningService{*pid, spec.binary});
                    std::cout << "[nexus-services] started " << spec.id << " (pid " << *pid << ")\n";
                }
                continue;
            }

            if (!should_run && existing != running.end()) {
                stop_service(existing->second);
                running.erase(existing);
                std::cout << "[nexus-services] stopped " << spec.id << "\n";
                if (was_blocked) {
                    blocked_services.erase(spec.id);
                }
            }
        }
    };

    auto restart_all = [&]() {
        for (auto& [id, service] : running) {
            stop_service(service);
        }
        running.clear();
        blocked_services.clear();
    };

    reconcile();
    auto last_settings_write = std::filesystem::exists(config.state_root / "settings.json")
        ? std::filesystem::last_write_time(config.state_root / "settings.json")
        : std::filesystem::file_time_type::min();

    while (true) {
        std::this_thread::sleep_for(std::chrono::seconds(2));

        for (auto it = running.begin(); it != running.end();) {
            int status = 0;
            const pid_t result = ::waitpid(it->second.pid, &status, WNOHANG);
            if (result == it->second.pid) {
                std::cerr << "[nexus-services] " << it->first << " exited unexpectedly\n";
                it = running.erase(it);
                continue;
            }
            ++it;
        }

        const auto settings_path = config.state_root / "settings.json";
        if (std::filesystem::exists(settings_path)) {
            const auto current_write = std::filesystem::last_write_time(settings_path);
            if (current_write != last_settings_write) {
                last_settings_write = current_write;
                if (auto updated = load_persisted_config(fallback)) {
                    config = *updated;
                    export_config_env(config);
                    restart_all();
                    std::cout << "[nexus-services] reloaded settings\n";
                }
            }
        }

        reconcile();
    }
}
