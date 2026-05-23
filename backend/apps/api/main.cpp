#include "platform_state.hpp"

#include "nexus/storage/database.hpp"

#include <drogon/drogon.h>
#include <json/json.h>
#include <trantor/net/EventLoop.h>

#include <cstdint>
#include <exception>
#include <filesystem>
#include <iostream>
#include <map>
#include <sstream>

namespace {

Json::Value to_json(const nexus::core::ServiceStatus& service) {
    Json::Value node(Json::objectValue);
    node["id"] = service.id;
    node["label"] = service.label;
    node["state"] = service.state;
    node["summary"] = service.summary;
    node["critical"] = service.critical;
    node["enabled"] = service.enabled;
    node["endpoints"] = Json::arrayValue;
    for (const auto& endpoint : service.endpoints) {
        node["endpoints"].append(endpoint);
    }
    node["capabilities"] = Json::arrayValue;
    for (const auto& capability : service.capabilities) {
        node["capabilities"].append(capability);
    }

    if (!service.blocking_reason.empty()) {
        node["blockingReason"] = service.blocking_reason;
    }
    return node;
}
Json::Value to_json(const nexus::core::DirectoryObject& object) {
    Json::Value node(Json::objectValue);
    node["dn"] = object.dn;
    node["parentDn"] = object.parent_dn;
    node["kind"] = object.kind;
    for (const auto& object_class : object.object_classes) {
        node["objectClasses"].append(object_class);
    }
    for (const auto& [key, value] : object.attributes) {
        node["attributes"][key] = value;
    }
    return node;
}

Json::Value to_json(const nexus::core::DnsRecord& record) {
    Json::Value node(Json::objectValue);
    node["name"] = record.name;
    node["type"] = record.type;
    node["value"] = record.value;
    node["class"] = record.dns_class;
    node["ttl"] = Json::UInt(record.ttl);
    node["priority"] = Json::UInt(record.priority);
    if (record.weight > 0) {
        node["weight"] = Json::UInt(record.weight);
    }
    if (record.port > 0) {
        node["port"] = Json::UInt(record.port);
    }
    if (!record.flags.empty()) {
        node["flags"] = record.flags;
    }
    return node;
}

Json::Value to_json(const nexus::core::DnsZone& zone) {
    Json::Value node(Json::objectValue);
    node["name"] = zone.name;
    node["serial"] = Json::UInt64(zone.serial);
    node["records"] = Json::arrayValue;
    for (const auto& record : zone.records) {
        node["records"].append(to_json(record));
    }
    return node;
}

Json::Value to_json(const nexus::core::DhcpLease& lease) {
    Json::Value node(Json::objectValue);
    node["ipAddress"] = lease.ip_address;
    node["clientId"] = lease.client_id;
    node["hostname"] = lease.hostname;
    node["state"] = lease.state;
    node["expiresAt"] = lease.expires_at;
    return node;
}

Json::Value to_json(const nexus::core::DhcpPool& pool) {
    Json::Value node(Json::objectValue);
    node["name"] = pool.name;
    node["subnet"] = pool.subnet;
    node["rangeStart"] = pool.range_start;
    node["rangeEnd"] = pool.range_end;
    node["options"] = Json::objectValue;
    for (const auto& [key, value] : pool.options) {
        node["options"][key] = value;
    }
    node["leases"] = Json::arrayValue;
    for (const auto& lease : pool.leases) {
        node["leases"].append(to_json(lease));
    }
    return node;
}

Json::Value to_json(const nexus::core::PkiRevocation& revocation) {
    Json::Value node(Json::objectValue);
    node["serial"] = revocation.serial;
    node["commonName"] = revocation.common_name;
    node["reason"] = revocation.reason;
    node["revokedAt"] = revocation.revoked_at;
    return node;
}

Json::Value to_json(const nexus::core::PkiInsight& insight) {
    Json::Value node(Json::objectValue);
    node["category"] = insight.category;
    node["title"] = insight.title;
    node["detail"] = insight.detail;
    node["severity"] = insight.severity;
    return node;
}

Json::Value to_json(const nexus::core::PkiAssistantSnapshot& assistant) {
    Json::Value node(Json::objectValue);
    node["recommendedMode"] = assistant.recommended_mode;
    node["recommendedProfileId"] = assistant.recommended_profile_id;
    node["headline"] = assistant.headline;
    node["authorityCount"] = Json::UInt64(assistant.authority_count);
    node["certificateCount"] = Json::UInt64(assistant.certificate_count);
    node["revocationCount"] = Json::UInt64(assistant.revocation_count);
    node["leafDaysValid"] = assistant.leaf_days_valid;
    node["insights"] = Json::arrayValue;
    for (const auto& insight : assistant.insights) {
        node["insights"].append(to_json(insight));
    }
    return node;
}

Json::Value to_json(const nexus::core::PkiAuthority& authority) {
    Json::Value node(Json::objectValue);
    node["name"] = authority.name;
    node["commonName"] = authority.common_name;
    node["organization"] = authority.organization;
    node["serial"] = authority.serial_hex;
    node["certificatePem"] = authority.certificate_pem;
    node["privateKeyPem"] = authority.private_key_pem;
    node["createdAt"] = authority.created_at;
    return node;
}

Json::Value to_json(const nexus::core::PkiCertificate& certificate) {
    Json::Value node(Json::objectValue);
    node["serial"] = certificate.serial_hex;
    node["authorityName"] = certificate.authority_name;
    node["commonName"] = certificate.common_name;
    node["organization"] = certificate.organization;
    node["sans"] = Json::arrayValue;
    for (const auto& san : certificate.dns_subject_alternative_names) {
        node["sans"].append(san);
    }
    node["certificatePem"] = certificate.certificate_pem;
    node["privateKeyPem"] = certificate.private_key_pem;
    node["revoked"] = certificate.revoked;
    node["createdAt"] = certificate.created_at;
    return node;
}

Json::Value to_json(const nexus::core::AptPackage& package) {
    Json::Value node(Json::objectValue);
    node["name"] = package.name;
    node["version"] = package.version;
    node["architecture"] = package.architecture;
    node["component"] = package.component;
    node["filename"] = package.filename;
    node["sha256"] = package.sha256;
    node["size"] = Json::UInt64(package.size);
    return node;
}

Json::Value to_json(const nexus::core::AptRepository& repository) {
    Json::Value node(Json::objectValue);
    node["distribution"] = repository.distribution;
    node["component"] = repository.component;
    node["packages"] = Json::arrayValue;
    for (const auto& package : repository.packages) {
        node["packages"].append(to_json(package));
    }
    return node;
}

Json::Value to_json(const nexus::core::AuditEvent& event) {
    Json::Value node(Json::objectValue);
    node["happenedAt"] = event.happened_at;
    node["actor"] = event.actor;
    node["domain"] = event.domain;
    node["action"] = event.action;
    node["detail"] = event.detail;
    return node;
}

Json::Value to_json(const nexus::core::Config& config) {
    Json::Value node(Json::objectValue);
    node["environment"] = config.environment;
    node["domain"] = config.domain;
    node["blobRoot"] = config.blob_root.string();
    node["stateRoot"] = config.state_root.string();
    node["databaseConfigured"] = !config.database_url.empty();
    node["databaseUrl"] = config.database_url;
    node["adminEmail"] = config.admin_email;
    node["adminPasswordHash"] = config.admin_password_hash;
    node["adminTotpSecret"] = config.admin_totp_secret;
    node["ports"]["http"] = config.http.port;
    node["ports"]["ldap"] = config.ldap.port;
    node["ports"]["ldaps"] = config.ldaps.port;
    node["ports"]["kerberos"] = config.kerberos.port;
    node["ports"]["dnsTcp"] = config.dns_tcp.port;
    node["ports"]["dnsUdp"] = config.dns_udp.port;
    node["ports"]["dhcp"] = config.dhcp.port;
    node["directory"]["baseDn"] = config.directory.base_dn;
    node["directory"]["organization"] = config.directory.organization;
    node["directory"]["realm"] = config.directory.realm;
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
    node["features"] = Json::objectValue;
    Json::Value features(Json::objectValue);
    for (const auto& [k, v] : config.features) {
        features[k] = v;
    }
    node["features"] = features;
    return node;
}

nexus::core::Config config_from_json(const nexus::core::Config& current, const Json::Value& body) {
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
    updated.dns_tcp.port = read_port("dnsTcpPort", current.dns_tcp.port);
    updated.dns_udp.port = read_port("dnsUdpPort", current.dns_udp.port);
    updated.dhcp.port = read_port("dhcpPort", current.dhcp.port);
    if (body.isMember("directory") && body["directory"].isObject()) {
        const auto& directory = body["directory"];
        if (directory.isMember("baseDn")) {
            updated.directory.base_dn = directory["baseDn"].asString();
        }
        if (directory.isMember("organization")) {
            updated.directory.organization = directory["organization"].asString();
        }
        if (directory.isMember("realm")) {
            updated.directory.realm = directory["realm"].asString();
        }
    }
    if (body.isMember("dns") && body["dns"].isObject()) {
        const auto& dns = body["dns"];
        if (dns.isMember("primaryNs")) {
            updated.dns.primary_ns = dns["primaryNs"].asString();
        }
        if (dns.isMember("adminMailbox")) {
            updated.dns.admin_mailbox = dns["adminMailbox"].asString();
        }
        if (dns.isMember("defaultTtl")) {
            const auto ttl = dns["defaultTtl"].asUInt();
            if (ttl > 0) {
                updated.dns.default_ttl = ttl;
            }
        }
    }
    if (body.isMember("dhcp") && body["dhcp"].isObject()) {
        const auto& dhcp = body["dhcp"];
        if (dhcp.isMember("subnet")) {
            updated.dhcp_service.subnet = dhcp["subnet"].asString();
        }
        if (dhcp.isMember("rangeStart")) {
            updated.dhcp_service.range_start = dhcp["rangeStart"].asString();
        }
        if (dhcp.isMember("rangeEnd")) {
            updated.dhcp_service.range_end = dhcp["rangeEnd"].asString();
        }
        if (dhcp.isMember("router")) {
            updated.dhcp_service.router = dhcp["router"].asString();
        }
    }
    if (body.isMember("pki") && body["pki"].isObject()) {
        const auto& pki = body["pki"];
        if (pki.isMember("organization")) {
            updated.pki.organization = pki["organization"].asString();
        }
        if (pki.isMember("commonName")) {
            updated.pki.common_name = pki["commonName"].asString();
        }
        if (pki.isMember("leafDaysValid")) {
            const auto days = pki["leafDaysValid"].asInt();
            if (days > 0) {
                updated.pki.leaf_days_valid = days;
            }
        }
    }
    if (body.isMember("repo") && body["repo"].isObject()) {
        const auto& repo = body["repo"];
        if (repo.isMember("origin")) {
            updated.repo.origin = repo["origin"].asString();
        }
        if (repo.isMember("distribution")) {
            updated.repo.distribution = repo["distribution"].asString();
        }
        if (repo.isMember("component")) {
            updated.repo.component = repo["component"].asString();
        }
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

Json::Value to_json(const nexus::core::JobSummary& job) {
    Json::Value node(Json::objectValue);
    node["id"] = job.id;
    node["domain"] = job.domain;
    node["status"] = job.status;
    node["description"] = job.description;
    node["submittedAt"] = job.submitted_at;
    return node;
}

Json::Value to_json(const nexus::core::DashboardSnapshot& snapshot) {
    Json::Value node(Json::objectValue);
    node["services"] = Json::arrayValue;
    for (const auto& service : snapshot.services) {
        node["services"].append(to_json(service));
    }
    node["directoryObjects"] = Json::UInt64(snapshot.directory_objects);
    node["dnsRecords"] = Json::UInt64(snapshot.dns_records);
    node["dhcpLeases"] = Json::UInt64(snapshot.dhcp_leases);
    node["pendingJobs"] = Json::UInt64(snapshot.pending_jobs);
    node["pkiRevocations"] = Json::UInt64(snapshot.pki_revocations);
    node["repoPackages"] = Json::UInt64(snapshot.repo_packages);
    node["jobs"] = Json::arrayValue;
    node["audit"] = Json::arrayValue;
    return node;
}

std::string session_cookie(const std::string& token, bool secure, bool clear = false) {
    std::ostringstream output;
    output << "nexus_session=" << (clear ? "" : token) << "; Path=/; HttpOnly; SameSite=Strict";
    if (secure) {
        output << "; Secure";
    }
    if (clear) {
        output << "; Max-Age=0";
    } else {
        output << "; Max-Age=43200";
    }
    return output.str();
}

Json::Value error_json(const std::string& message) {
    Json::Value node(Json::objectValue);
    node["error"] = message;
    return node;
}

nexus::core::DirectoryObject directory_object_from_json(const Json::Value& body) {
    nexus::core::DirectoryObject object;
    object.dn = body["dn"].asString();
    object.parent_dn = body.isMember("parentDn") ? body["parentDn"].asString() : "";
    object.kind = body["kind"].asString();
    if (body.isMember("objectClasses") && body["objectClasses"].isArray()) {
        for (const auto& entry : body["objectClasses"]) {
            object.object_classes.push_back(entry.asString());
        }
    }
    if (body.isMember("attributes") && body["attributes"].isObject()) {
        for (const auto& key : body["attributes"].getMemberNames()) {
            object.attributes[key] = body["attributes"][key].asString();
        }
    }
    return object;
}

nexus::security::CertificateSubject certificate_subject_from_json(const Json::Value& body) {
    nexus::security::CertificateSubject subject;
    subject.common_name = body["commonName"].asString();
    subject.organization = body.isMember("organization") ? body["organization"].asString() : "Endorium";
    if (body.isMember("sans") && body["sans"].isArray()) {
        for (const auto& entry : body["sans"]) {
            const auto san = entry.asString();
            if (!san.empty()) {
                subject.dns_subject_alternative_names.push_back(san);
            }
        }
    }
    return subject;
}

nexus::core::AptPackage apt_package_from_json(const Json::Value& body, const std::string& component) {
    nexus::core::AptPackage package;
    package.name = body["name"].asString();
    package.version = body["version"].asString();
    package.architecture = body["architecture"].asString();
    package.component = component;
    package.filename = body["filename"].asString();
    package.sha256 = body["sha256"].asString();
    package.size = body.isMember("size") ? static_cast<std::size_t>(body["size"].asUInt64()) : 0;
    return package;
}

std::string sse_event(const std::string& event_name, std::uint64_t revision) {
    Json::Value payload(Json::objectValue);
    payload["revision"] = Json::UInt64(revision);

    Json::StreamWriterBuilder builder;
    builder["indentation"] = "";

    return "event: " + event_name + "\ndata: " + Json::writeString(builder, payload) + "\n\n";
}

void respond_json(
    drogon::HttpStatusCode status,
    Json::Value payload,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
    auto response = drogon::HttpResponse::newHttpJsonResponse(payload);
    response->setStatusCode(status);
    callback(response);
}

}  // namespace

int main() {
    const auto config = nexus::core::Config::from_env();

    try {
        nexus::storage::Database database(config.database_url);
        if (database.configured()) {
            database.apply_migrations("backend/sql/migrations");
        }
    } catch (const std::exception& error) {
        std::cerr << "Failed to initialize database migrations: " << error.what() << '\n';
        return 1;
    }

    auto state = std::make_shared<nexus::api::PlatformState>(config);

    if (std::filesystem::exists(config.ui_dist_dir / "index.html")) {
        drogon::app().setDocumentRoot(config.ui_dist_dir.string());
        drogon::app().registerHandler(
            "/",
            [config](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
                callback(drogon::HttpResponse::newFileResponse((config.ui_dist_dir / "index.html").string()));
            },
            {drogon::Get});
    }

    drogon::app().registerHandler(
        "/api/v1/health",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            const auto& config = state->config();
            Json::Value payload(Json::objectValue);
            payload["status"] = "ok";
            payload["databaseConfigured"] = !config.database_url.empty();
            payload["databaseHealthy"] = config.database_url.empty() ? false : nexus::storage::Database(config.database_url).ping();
            payload["environment"] = config.environment;
            payload["domain"] = config.domain;
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/auth/login",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("email") || !body->isMember("password")) {
                respond_json(drogon::k400BadRequest, error_json("email and password are required"), std::move(callback));
                return;
            }

            const auto result = state->login(
                (*body)["email"].asString(),
                (*body)["password"].asString(),
                body->isMember("totp") ? (*body)["totp"].asString() : "");

            if (!result.ok) {
                respond_json(drogon::k401Unauthorized, error_json(result.error), std::move(callback));
                return;
            }

            Json::Value payload(Json::objectValue);
            payload["email"] = state->config().admin_email;
            payload["csrfToken"] = result.csrf_token;
            for (const auto& role : result.roles) {
                payload["roles"].append(role);
            }

            auto response = drogon::HttpResponse::newHttpJsonResponse(payload);
            response->setStatusCode(drogon::k200OK);
            response->addHeader("Set-Cookie", session_cookie(result.session_token, !state->config().is_development()));
            callback(response);
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/auth/logout",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            const auto session_token = request->getCookie("nexus_session");
            state->logout(session_token);
            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            auto response = drogon::HttpResponse::newHttpJsonResponse(payload);
            response->addHeader("Set-Cookie", session_cookie("", !state->config().is_development(), true));
            callback(response);
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/auth/me",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            std::vector<std::string> roles;
            if (!state->authenticate(request->getCookie("nexus_session"), &actor, &roles)) {
                respond_json(drogon::k401Unauthorized, error_json("not authenticated"), std::move(callback));
                return;
            }

            Json::Value payload(Json::objectValue);
            payload["email"] = actor;
            for (const auto& role : roles) {
                payload["roles"].append(role);
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/settings",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            respond_json(drogon::k200OK, to_json(state->config()), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/feature-flags",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value payload(Json::arrayValue);
            const auto flags = state->feature_flags();
            for (const auto& service : nexus::core::service_definitions()) {
                if (service.feature_flag.empty()) {
                    continue;
                }

                Json::Value node(Json::objectValue);
                node["serviceId"] = service.id;
                node["label"] = service.label;
                node["featureFlag"] = service.feature_flag;
                node["priority"] = service.priority;
                node["critical"] = service.critical;
                node["enabled"] = flags.contains(service.feature_flag) ? flags.at(service.feature_flag) : false;
                payload.append(node);
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/feature-flags",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }

            auto body = request->getJsonObject();
            if (body == nullptr) {
                respond_json(drogon::k400BadRequest, error_json("feature flags payload is required"), std::move(callback));
                return;
            }

            std::map<std::string, bool> features;
            const Json::Value* source = body.get();
            if (body->isMember("features") && (*body)["features"].isObject()) {
                source = &(*body)["features"];
            }

            for (const auto& key : source->getMemberNames()) {
                features[key] = (*source)[key].asBool();
            }

            if (!state->update_feature_flags(features, actor)) {
                respond_json(drogon::k500InternalServerError, error_json("failed to persist feature flags"), std::move(callback));
                return;
            }

            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            payload["features"] = Json::arrayValue;
            for (const auto& service : nexus::core::service_definitions()) {
                if (service.feature_flag.empty()) {
                    continue;
                }

                Json::Value node(Json::objectValue);
                node["serviceId"] = service.id;
                node["enabled"] = features.contains(service.feature_flag) ? features.at(service.feature_flag) : false;
                payload["features"].append(node);
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Put});

    drogon::app().registerHandler(
        "/api/v1/settings",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }

            auto body = request->getJsonObject();
            if (body == nullptr) {
                respond_json(drogon::k400BadRequest, error_json("settings payload is required"), std::move(callback));
                return;
            }

            const auto updated = config_from_json(state->config(), *body);
            if (!state->update_settings(updated, actor)) {
                respond_json(drogon::k500InternalServerError, error_json("failed to persist settings"), std::move(callback));
                return;
            }

            Json::Value payload = to_json(state->config());
            payload["ok"] = true;
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Put});

    drogon::app().registerHandler(
        "/api/v1/services",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value payload(Json::arrayValue);
            for (const auto& service : state->services()) {
                payload.append(to_json(service));
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/dashboard",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value payload = to_json(state->dashboard());
            for (const auto& job : state->jobs()) {
                payload["jobs"].append(to_json(job));
            }
            const auto audit = state->audit_events();
            for (std::size_t index = 0; index < std::min<std::size_t>(audit.size(), 8); ++index) {
                payload["audit"].append(to_json(audit[index]));
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/dashboard/stream",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            auto response = drogon::HttpResponse::newAsyncStreamResponse(
                [state](drogon::ResponseStreamPtr stream) {
                    auto* loop = trantor::EventLoop::getEventLoopOfCurrentThread();
                    if (loop == nullptr) {
                        loop = drogon::app().getLoop();
                    }

                    auto shared_stream = std::shared_ptr<drogon::ResponseStream>(std::move(stream));
                    auto timer_id = std::make_shared<trantor::TimerId>(trantor::InvalidTimerId);
                    auto last_revision = std::make_shared<std::uint64_t>(state->stream_revision());
                    auto idle_ticks = std::make_shared<std::uint8_t>(0);

                    if (!shared_stream->send("retry: 5000\n" + sse_event("state-changed", *last_revision))) {
                        shared_stream->close();
                        return;
                    }

                    *timer_id = loop->runEvery(
                        2.0,
                        [state, loop, shared_stream, timer_id, last_revision, idle_ticks]() {
                            const auto revision = state->stream_revision();
                            if (revision != *last_revision) {
                                *last_revision = revision;
                                *idle_ticks = 0;
                                if (!shared_stream->send(sse_event("state-changed", revision))) {
                                    loop->invalidateTimer(*timer_id);
                                    shared_stream->close();
                                }
                                return;
                            }

                            *idle_ticks += 1;
                            if (*idle_ticks < 5) {
                                return;
                            }

                            *idle_ticks = 0;
                            if (!shared_stream->send(": keepalive\n\n")) {
                                loop->invalidateTimer(*timer_id);
                                shared_stream->close();
                            }
                        });
                },
                true);
            response->setStatusCode(drogon::k200OK);
            response->setContentTypeString("text/event-stream");
            response->addHeader("Cache-Control", "no-cache");
            response->addHeader("X-Accel-Buffering", "no");
            callback(response);
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/directory/objects",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value payload(Json::arrayValue);
            for (const auto& object : state->directory_objects()) {
                payload.append(to_json(object));
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/directory/objects",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }
            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("dn") || !body->isMember("kind") || !body->isMember("objectClasses") || !body->isMember("attributes")) {
                respond_json(drogon::k400BadRequest, error_json("directory object payload is incomplete"), std::move(callback));
                return;
            }
            const auto object = directory_object_from_json(*body);
            const auto password = body->isMember("password") ? (*body)["password"].asString() : "";
            if (!state->create_directory_object(object, password, actor)) {
                respond_json(drogon::k409Conflict, error_json("invalid directory object or dn already exists"), std::move(callback));
                return;
            }
            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            payload["dn"] = object.dn;
            respond_json(drogon::k201Created, std::move(payload), std::move(callback));
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/directory/objects/{1}",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& dn) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }
            if (request->getMethod() == drogon::Delete) {
                if (!state->delete_directory_object(dn, actor)) {
                    respond_json(drogon::k404NotFound, error_json("directory object not found"), std::move(callback));
                    return;
                }
                Json::Value payload(Json::objectValue);
                payload["ok"] = true;
                respond_json(drogon::k200OK, std::move(payload), std::move(callback));
                return;
            }
            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("dn") || !body->isMember("kind") || !body->isMember("objectClasses") || !body->isMember("attributes")) {
                respond_json(drogon::k400BadRequest, error_json("directory object payload is incomplete"), std::move(callback));
                return;
            }
            const auto object = directory_object_from_json(*body);
            const auto password = body->isMember("password") ? (*body)["password"].asString() : "";
            if (!state->update_directory_object(dn, object, password, actor)) {
                respond_json(drogon::k404NotFound, error_json("directory object not found or dn already exists"), std::move(callback));
                return;
            }
            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            payload["dn"] = object.dn;
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Put, drogon::Delete});

    drogon::app().registerHandler(
        "/api/v1/dns/zones",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value payload(Json::arrayValue);
            for (const auto& zone : state->dns_zones()) {
                payload.append(to_json(zone));
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/dns/zones",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }

            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("name")) {
                respond_json(drogon::k400BadRequest, error_json("zone payload is incomplete"), std::move(callback));
                return;
            }

            const auto zone_name = (*body)["name"].asString();
            if (!state->create_dns_zone(zone_name, actor)) {
                respond_json(drogon::k409Conflict, error_json("invalid zone name or zone already exists"), std::move(callback));
                return;
            }

            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            payload["zone"] = zone_name;
            respond_json(drogon::k201Created, std::move(payload), std::move(callback));
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/dns/zones/{1}",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback, const std::string& zone_name) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }

            if (request->getMethod() == drogon::Delete) {
                if (!state->delete_dns_zone(zone_name, actor)) {
                    respond_json(drogon::k404NotFound, error_json("zone not found"), std::move(callback));
                    return;
                }
                Json::Value payload(Json::objectValue);
                payload["ok"] = true;
                respond_json(drogon::k200OK, std::move(payload), std::move(callback));
                return;
            }

            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("name")) {
                respond_json(drogon::k400BadRequest, error_json("zone payload is incomplete"), std::move(callback));
                return;
            }

            const auto new_name = (*body)["name"].asString();
            if (!state->update_dns_zone(zone_name, new_name, actor)) {
                respond_json(drogon::k409Conflict, error_json("invalid zone name or zone already exists"), std::move(callback));
                return;
            }

            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            payload["zone"] = new_name;
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Put, drogon::Delete});

    drogon::app().registerHandler(
        "/api/v1/dns/zones/{1}/render",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback, const std::string& zone_name) {
            const auto rendered = state->render_zone(zone_name);
            if (!rendered.has_value()) {
                respond_json(drogon::k404NotFound, error_json("zone not found"), std::move(callback));
                return;
            }

            Json::Value payload(Json::objectValue);
            payload["zone"] = zone_name;
            payload["text"] = *rendered;
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/dns/zones/{1}/records",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback, const std::string& zone_name) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }

            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("name") || !body->isMember("type") || !body->isMember("value")) {
                respond_json(drogon::k400BadRequest, error_json("record payload is incomplete"), std::move(callback));
                return;
            }

            const auto priority = body->isMember("priority")
                ? static_cast<std::uint16_t>((*body)["priority"].asUInt())
                : static_cast<std::uint16_t>(0);
            
            nexus::core::DnsRecord record;
            record.name = (*body)["name"].asString();
            record.type = (*body)["type"].asString();
            record.value = (*body)["value"].asString();
            record.dns_class = body->isMember("class") ? (*body)["class"].asString() : "IN";
            record.ttl = body->isMember("ttl") ? (*body)["ttl"].asUInt() : 3600U;
            record.priority = priority;
            record.weight = body->isMember("weight") ? static_cast<std::uint16_t>((*body)["weight"].asUInt()) : 0;
            record.port = body->isMember("port") ? static_cast<std::uint16_t>((*body)["port"].asUInt()) : 0;
            record.flags = body->isMember("flags") ? (*body)["flags"].asString() : "";

            if (!state->add_dns_record(zone_name, record, actor)) {
                respond_json(drogon::k404NotFound, error_json("zone not found"), std::move(callback));
                return;
            }

            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            payload["zone"] = zone_name;
            respond_json(drogon::k201Created, std::move(payload), std::move(callback));
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/dns/zones/{1}/records/{2}",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& zone_name,
                const std::string& record_index_text) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }

            std::size_t record_index = 0;
            try {
                record_index = static_cast<std::size_t>(std::stoul(record_index_text));
            } catch (...) {
                respond_json(drogon::k400BadRequest, error_json("invalid record index"), std::move(callback));
                return;
            }

            if (request->getMethod() == drogon::Delete) {
                if (!state->delete_dns_record(zone_name, record_index, actor)) {
                    respond_json(drogon::k404NotFound, error_json("zone or record not found"), std::move(callback));
                    return;
                }
                Json::Value payload(Json::objectValue);
                payload["ok"] = true;
                respond_json(drogon::k200OK, std::move(payload), std::move(callback));
                return;
            }

            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("name") || !body->isMember("type") || !body->isMember("value")) {
                respond_json(drogon::k400BadRequest, error_json("record payload is incomplete"), std::move(callback));
                return;
            }

            const auto priority = body->isMember("priority")
                ? static_cast<std::uint16_t>((*body)["priority"].asUInt())
                : static_cast<std::uint16_t>(0);
            
            nexus::core::DnsRecord record;
            record.name = (*body)["name"].asString();
            record.type = (*body)["type"].asString();
            record.value = (*body)["value"].asString();
            record.dns_class = body->isMember("class") ? (*body)["class"].asString() : "IN";
            record.ttl = body->isMember("ttl") ? (*body)["ttl"].asUInt() : 3600U;
            record.priority = priority;
            record.weight = body->isMember("weight") ? static_cast<std::uint16_t>((*body)["weight"].asUInt()) : 0;
            record.port = body->isMember("port") ? static_cast<std::uint16_t>((*body)["port"].asUInt()) : 0;
            record.flags = body->isMember("flags") ? (*body)["flags"].asString() : "";

            if (!state->update_dns_record(zone_name, record_index, record, actor)) {
                respond_json(drogon::k404NotFound, error_json("zone or record not found"), std::move(callback));
                return;
            }

            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            payload["zone"] = zone_name;
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Put, drogon::Delete});

    drogon::app().registerHandler(
        "/api/v1/dns/restart",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("restart requires a valid session and csrf token"), std::move(callback));
                return;
            }

            if (!state->restart_dns_service(actor)) {
                respond_json(drogon::k500InternalServerError, error_json("failed to restart DNS service"), std::move(callback));
                return;
            }

            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            payload["status"] = "restarting";
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/dhcp/pools",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value payload(Json::arrayValue);
            for (const auto& pool : state->dhcp_pools()) {
                payload.append(to_json(pool));
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/dhcp/pools",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }

            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("name") || !body->isMember("subnet") || !body->isMember("rangeStart") || !body->isMember("rangeEnd")) {
                respond_json(drogon::k400BadRequest, error_json("pool payload is incomplete"), std::move(callback));
                return;
            }

            nexus::core::DhcpPool pool;
            pool.name = (*body)["name"].asString();
            pool.subnet = (*body)["subnet"].asString();
            pool.range_start = (*body)["rangeStart"].asString();
            pool.range_end = (*body)["rangeEnd"].asString();
            if (body->isMember("options") && (*body)["options"].isObject()) {
                for (const auto& key : (*body)["options"].getMemberNames()) {
                    pool.options[key] = (*body)["options"][key].asString();
                }
            }

            if (!state->create_dhcp_pool(pool, actor)) {
                respond_json(drogon::k409Conflict, error_json("pool already exists or payload is invalid"), std::move(callback));
                return;
            }

            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            payload["pool"] = pool.name;
            respond_json(drogon::k201Created, std::move(payload), std::move(callback));
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/dhcp/pools/{1}",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& pool_name) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }

            if (request->getMethod() == drogon::Delete) {
                if (!state->delete_dhcp_pool(pool_name, actor)) {
                    respond_json(drogon::k404NotFound, error_json("pool not found"), std::move(callback));
                    return;
                }
                Json::Value payload(Json::objectValue);
                payload["ok"] = true;
                respond_json(drogon::k200OK, std::move(payload), std::move(callback));
                return;
            }

            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("name") || !body->isMember("subnet") || !body->isMember("rangeStart") || !body->isMember("rangeEnd")) {
                respond_json(drogon::k400BadRequest, error_json("pool payload is incomplete"), std::move(callback));
                return;
            }

            nexus::core::DhcpPool pool;
            pool.name = (*body)["name"].asString();
            pool.subnet = (*body)["subnet"].asString();
            pool.range_start = (*body)["rangeStart"].asString();
            pool.range_end = (*body)["rangeEnd"].asString();
            if (body->isMember("options") && (*body)["options"].isObject()) {
                for (const auto& key : (*body)["options"].getMemberNames()) {
                    pool.options[key] = (*body)["options"][key].asString();
                }
            }

            if (!state->update_dhcp_pool(pool_name, pool, actor)) {
                respond_json(drogon::k404NotFound, error_json("pool not found or name already exists"), std::move(callback));
                return;
            }

            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            payload["pool"] = pool.name;
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Put, drogon::Delete});

    drogon::app().registerHandler(
        "/api/v1/dhcp/restart",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("restart requires a valid session and csrf token"), std::move(callback));
                return;
            }

            if (!state->restart_dhcp_service(actor)) {
                respond_json(drogon::k500InternalServerError, error_json("failed to restart DHCP service"), std::move(callback));
                return;
            }

            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            payload["status"] = "restarting";
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/pki/authorities",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value payload(Json::arrayValue);
            for (const auto& authority : state->pki_authorities()) {
                payload.append(to_json(authority));
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/pki/authorities",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }
            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("name") || !body->isMember("commonName") || !body->isMember("organization")) {
                respond_json(drogon::k400BadRequest, error_json("authority payload is incomplete"), std::move(callback));
                return;
            }
            const auto subject = certificate_subject_from_json(*body);
            const auto days = body->isMember("daysValid") ? (*body)["daysValid"].asInt() : 3650;
            if (!state->create_pki_authority((*body)["name"].asString(), subject, days, actor)) {
                respond_json(drogon::k409Conflict, error_json("invalid authority or name already exists"), std::move(callback));
                return;
            }
            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            payload["authority"] = (*body)["name"].asString();
            respond_json(drogon::k201Created, std::move(payload), std::move(callback));
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/pki/certificates",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value payload(Json::arrayValue);
            for (const auto& certificate : state->pki_certificates()) {
                payload.append(to_json(certificate));
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/pki/certificates",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }
            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("authorityName") || !body->isMember("commonName") || !body->isMember("organization")) {
                respond_json(drogon::k400BadRequest, error_json("certificate payload is incomplete"), std::move(callback));
                return;
            }
            const auto subject = certificate_subject_from_json(*body);
            const auto days = body->isMember("daysValid") ? (*body)["daysValid"].asInt() : 365;
            if (!state->issue_pki_certificate((*body)["authorityName"].asString(), subject, days, actor)) {
                respond_json(drogon::k404NotFound, error_json("authority not found or certificate payload invalid"), std::move(callback));
                return;
            }
            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            respond_json(drogon::k201Created, std::move(payload), std::move(callback));
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/pki/revocations",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value payload(Json::arrayValue);
            for (const auto& revocation : state->pki_revocations()) {
                payload.append(to_json(revocation));
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/pki/revocations",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }

            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("serial") || !body->isMember("commonName") || !body->isMember("reason")) {
                respond_json(drogon::k400BadRequest, error_json("revocation payload is incomplete"), std::move(callback));
                return;
            }

            const bool revoked = state->revoke_certificate(
                (*body)["serial"].asString(),
                (*body)["commonName"].asString(),
                (*body)["reason"].asString(),
                actor);
            if (!revoked) {
                respond_json(drogon::k500InternalServerError, error_json("failed to store revocation"), std::move(callback));
                return;
            }
            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            respond_json(drogon::k201Created, std::move(payload), std::move(callback));
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/pki/assistant",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            respond_json(drogon::k200OK, to_json(state->pki_assistant()), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/repos",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value payload(Json::arrayValue);
            for (const auto& repository : state->apt_repositories()) {
                payload.append(to_json(repository));
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/repos",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }
            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("distribution") || !body->isMember("component")) {
                respond_json(drogon::k400BadRequest, error_json("repository payload is incomplete"), std::move(callback));
                return;
            }
            const auto distribution = (*body)["distribution"].asString();
            const auto component = (*body)["component"].asString();
            if (!state->create_apt_repository(distribution, component, actor)) {
                respond_json(drogon::k409Conflict, error_json("repository already exists or payload is invalid"), std::move(callback));
                return;
            }
            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            respond_json(drogon::k201Created, std::move(payload), std::move(callback));
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/repos/{1}/{2}",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& distribution,
                const std::string& component) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }
            if (!state->delete_apt_repository(distribution, component, actor)) {
                respond_json(drogon::k404NotFound, error_json("repository not found"), std::move(callback));
                return;
            }
            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Delete});

    drogon::app().registerHandler(
        "/api/v1/repos/{1}/{2}/packages",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& distribution,
                const std::string& component) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }
            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("name") || !body->isMember("version") || !body->isMember("architecture") || !body->isMember("filename") || !body->isMember("sha256") || !body->isMember("size")) {
                respond_json(drogon::k400BadRequest, error_json("package payload is incomplete"), std::move(callback));
                return;
            }
            const auto package = apt_package_from_json(*body, component);
            if (!state->add_apt_package(distribution, component, package, actor)) {
                respond_json(drogon::k404NotFound, error_json("repository not found or package payload invalid"), std::move(callback));
                return;
            }
            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            respond_json(drogon::k201Created, std::move(payload), std::move(callback));
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/repos/{1}/{2}/packages/{3}",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& distribution,
                const std::string& component,
                const std::string& package_index_text) {
            std::string actor;
            if (!state->authorize_mutation(request->getCookie("nexus_session"), request->getHeader("X-CSRF-Token"), &actor, nullptr)) {
                respond_json(drogon::k401Unauthorized, error_json("mutation requires a valid session and csrf token"), std::move(callback));
                return;
            }
            std::size_t package_index = 0;
            try {
                package_index = static_cast<std::size_t>(std::stoul(package_index_text));
            } catch (...) {
                respond_json(drogon::k400BadRequest, error_json("invalid package index"), std::move(callback));
                return;
            }
            if (request->getMethod() == drogon::Delete) {
                if (!state->delete_apt_package(distribution, component, package_index, actor)) {
                    respond_json(drogon::k404NotFound, error_json("repository or package not found"), std::move(callback));
                    return;
                }
                Json::Value payload(Json::objectValue);
                payload["ok"] = true;
                respond_json(drogon::k200OK, std::move(payload), std::move(callback));
                return;
            }
            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("name") || !body->isMember("version") || !body->isMember("architecture") || !body->isMember("filename") || !body->isMember("sha256") || !body->isMember("size")) {
                respond_json(drogon::k400BadRequest, error_json("package payload is incomplete"), std::move(callback));
                return;
            }
            const auto package = apt_package_from_json(*body, component);
            if (!state->update_apt_package(distribution, component, package_index, package, actor)) {
                respond_json(drogon::k404NotFound, error_json("repository or package not found"), std::move(callback));
                return;
            }
            Json::Value payload(Json::objectValue);
            payload["ok"] = true;
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Put, drogon::Delete});

    drogon::app().registerHandler(
        "/api/v1/repos/{1}/{2}/render/packages",
        [state](const drogon::HttpRequestPtr&,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& distribution,
                const std::string& component) {
            const auto rendered = state->render_apt_packages(distribution, component);
            if (!rendered.has_value()) {
                respond_json(drogon::k404NotFound, error_json("repository not found"), std::move(callback));
                return;
            }
            Json::Value payload(Json::objectValue);
            payload["text"] = *rendered;
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/repos/{1}/{2}/render/release",
        [state](const drogon::HttpRequestPtr&,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& distribution,
                const std::string& component) {
            const auto rendered = state->render_apt_release(distribution, component);
            if (!rendered.has_value()) {
                respond_json(drogon::k404NotFound, error_json("repository not found"), std::move(callback));
                return;
            }
            Json::Value payload(Json::objectValue);
            payload["text"] = *rendered;
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/audit",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value payload(Json::arrayValue);
            for (const auto& event : state->audit_events()) {
                payload.append(to_json(event));
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/jobs",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            Json::Value payload(Json::arrayValue);
            for (const auto& job : state->jobs()) {
                payload.append(to_json(job));
            }
            respond_json(drogon::k200OK, std::move(payload), std::move(callback));
        },
        {drogon::Get});

    drogon::app().setThreadNum(1);
    drogon::app().addListener(config.http.host, config.http.port);
    drogon::app().run();
}
