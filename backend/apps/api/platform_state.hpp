#pragma once

#include "nexus/core/config.hpp"
#include "nexus/core/models.hpp"
#include "nexus/jobs/queue.hpp"
#include "nexus/security/password_hasher.hpp"
#include "nexus/security/pki.hpp"
#include "nexus/security/totp.hpp"

#include <json/json.h>

#include <chrono>
#include <cstdint>
#include <filesystem>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace nexus::api {

class PlatformState {
  public:
    struct ActiveDirectoryReadinessItem {
        std::string id;
        std::string label;
        std::string category;
        std::string detail;
        bool ready{false};
        bool blocking{true};
    };

    struct ActiveDirectoryReadinessSnapshot {
        bool supported{false};
        std::string dns_name;
        std::string realm;
        std::string base_dn;
        std::vector<ActiveDirectoryReadinessItem> items;
    };

    struct ActiveDirectoryAttributeValue {
        std::string value;
        std::string encoding{"utf8"};
    };

    struct ActiveDirectoryAttribute {
        std::string name;
        std::string type{"string"};
        bool multi_valued{false};
        std::vector<ActiveDirectoryAttributeValue> values;
    };

    struct ActiveDirectoryObject {
        std::string object_guid;
        std::string domain_dns_name;
        std::string dn;
        std::string parent_dn;
        std::string rdn;
        std::string kind;
        std::string object_sid;
        std::uint64_t rid{0};
        std::uint64_t usn_created{0};
        std::uint64_t usn_changed{0};
        std::string when_created;
        std::string when_changed;
        std::vector<std::string> object_classes;
        std::vector<ActiveDirectoryAttribute> attributes;
    };

    struct LoginResult {
        bool ok{false};
        std::string error;
        std::string session_token;
        std::string csrf_token;
        std::vector<std::string> roles;
    };

    explicit PlatformState(nexus::core::Config config);

    [[nodiscard]] const nexus::core::Config& config() const;
    bool update_settings(const nexus::core::Config& config, const std::string& actor);
    [[nodiscard]] nexus::core::DashboardSnapshot dashboard() const;
    [[nodiscard]] std::vector<nexus::core::ServiceStatus> services() const;
    [[nodiscard]] std::vector<nexus::core::DirectoryObject> directory_objects() const;
    [[nodiscard]] std::vector<ActiveDirectoryObject> active_directory_objects() const;
    [[nodiscard]] ActiveDirectoryReadinessSnapshot active_directory_readiness() const;
    [[nodiscard]] std::vector<nexus::core::DnsZone> dns_zones() const;
    [[nodiscard]] std::vector<nexus::core::DhcpPool> dhcp_pools() const;
    [[nodiscard]] std::vector<nexus::core::PkiAuthority> pki_authorities() const;
    [[nodiscard]] std::vector<nexus::core::PkiCertificate> pki_certificates() const;
    [[nodiscard]] std::vector<nexus::core::PkiRevocation> pki_revocations() const;
    [[nodiscard]] nexus::core::PkiAssistantSnapshot pki_assistant() const;
    [[nodiscard]] std::vector<nexus::core::AptRepository> apt_repositories() const;
    [[nodiscard]] std::vector<nexus::core::AuditEvent> audit_events() const;
    [[nodiscard]] std::vector<nexus::core::JobSummary> jobs() const;
    void record_platform_audit(std::string actor, std::string domain, std::string action, std::string detail);
    [[nodiscard]] std::optional<nexus::core::DnsZone> find_zone(const std::string& zone_name) const;
    [[nodiscard]] std::optional<std::string> render_zone(const std::string& zone_name) const;
    [[nodiscard]] std::uint64_t stream_revision() const;

    LoginResult login(const std::string& email, const std::string& password, const std::string& totp_code);
    [[nodiscard]] bool authenticate(
        const std::string& session_token,
        std::string* actor_out = nullptr,
        std::vector<std::string>* roles_out = nullptr) const;
    [[nodiscard]] bool authorize_mutation(
        const std::string& session_token,
        const std::string& csrf_token,
        std::string* actor_out = nullptr,
        std::vector<std::string>* roles_out = nullptr) const;
    void logout(const std::string& session_token);

    [[nodiscard]] bool create_dns_zone(const std::string& zone_name, const std::string& actor);
    [[nodiscard]] bool update_dns_zone(const std::string& zone_name, const std::string& new_name, const std::string& actor);
    [[nodiscard]] bool delete_dns_zone(const std::string& zone_name, const std::string& actor);
    [[nodiscard]] bool add_dns_record(
        const std::string& zone_name,
        const nexus::core::DnsRecord& record,
        const std::string& actor);
    [[nodiscard]] bool update_dns_record(
        const std::string& zone_name,
        std::size_t record_index,
        const nexus::core::DnsRecord& record,
        const std::string& actor);
    [[nodiscard]] bool delete_dns_record(const std::string& zone_name, std::size_t record_index, const std::string& actor);
    [[nodiscard]] bool restart_dns_service(const std::string& actor);
    [[nodiscard]] bool restart_dhcp_service(const std::string& actor);
    [[nodiscard]] std::map<std::string, bool> feature_flags() const;
    [[nodiscard]] bool update_feature_flags(const std::map<std::string, bool>& features, const std::string& actor);
    [[nodiscard]] bool create_directory_object(
        nexus::core::DirectoryObject object,
        const std::string& password,
        const std::string& actor);
    [[nodiscard]] bool update_directory_object(
        const std::string& dn,
        nexus::core::DirectoryObject object,
        const std::string& password,
        const std::string& actor);
    [[nodiscard]] bool delete_directory_object(const std::string& dn, const std::string& actor);
    [[nodiscard]] bool create_dhcp_pool(const nexus::core::DhcpPool& pool, const std::string& actor);
    [[nodiscard]] bool update_dhcp_pool(const std::string& pool_name, const nexus::core::DhcpPool& pool, const std::string& actor);
    [[nodiscard]] bool delete_dhcp_pool(const std::string& pool_name, const std::string& actor);
    [[nodiscard]] bool create_pki_authority(
        const std::string& name,
        const nexus::security::CertificateSubject& subject,
        int days_valid,
        const std::string& actor);
    [[nodiscard]] bool issue_pki_certificate(
        const std::string& authority_name,
        const nexus::security::CertificateSubject& subject,
        int days_valid,
        const std::string& actor);
    [[nodiscard]] bool revoke_certificate(
        const std::string& serial,
        const std::string& common_name,
        const std::string& reason,
        const std::string& actor);
    [[nodiscard]] bool create_apt_repository(
        const std::string& distribution,
        const std::string& component,
        const std::string& actor);
    [[nodiscard]] bool delete_apt_repository(
        const std::string& distribution,
        const std::string& component,
        const std::string& actor);
    [[nodiscard]] bool add_apt_package(
        const std::string& distribution,
        const std::string& component,
        const nexus::core::AptPackage& package,
        const std::string& actor);
    [[nodiscard]] std::optional<nexus::core::AptPackage> upload_apt_package(
        const std::string& distribution,
        const std::string& component,
        const std::string& filename,
        std::string_view content,
        const std::string& actor);
    [[nodiscard]] bool update_apt_package(
        const std::string& distribution,
        const std::string& component,
        std::size_t package_index,
        const nexus::core::AptPackage& package,
        const std::string& actor);
    [[nodiscard]] bool delete_apt_package(
        const std::string& distribution,
        const std::string& component,
        std::size_t package_index,
        const std::string& actor);
    [[nodiscard]] std::optional<std::string> render_apt_packages(
        const std::string& distribution,
        const std::string& component) const;
    [[nodiscard]] std::optional<std::string> render_apt_release(
        const std::string& distribution,
        const std::string& component) const;

  private:
    struct Session {
        std::string email;
        std::string csrf_token;
        std::vector<std::string> roles;
        std::chrono::system_clock::time_point expires_at;
    };

    mutable std::mutex mutex_;
    nexus::core::Config config_;
    nexus::jobs::JobQueue jobs_;
    nexus::security::PasswordHasher password_hasher_;
    nexus::security::Totp totp_;
    std::vector<nexus::core::ServiceStatus> services_;
    std::vector<nexus::core::DirectoryObject> directory_;
    std::vector<nexus::core::DnsZone> zones_;
    std::vector<nexus::core::DhcpPool> pools_;
    std::vector<nexus::core::PkiAuthority> authorities_;
    std::vector<nexus::core::PkiCertificate> certificates_;
    std::vector<nexus::core::PkiRevocation> revocations_;
    std::vector<nexus::core::AptRepository> repositories_;
    std::vector<nexus::core::AuditEvent> audit_events_;
    std::unordered_map<std::string, Session> sessions_;
    std::uint64_t revision_{0};

    [[nodiscard]] bool sync_feature_flags_to_database(const nexus::core::Config& config) const;
    [[nodiscard]] bool load_feature_flags_from_database();
    void initialize_runtime_state();
    [[nodiscard]] std::filesystem::path settings_file_path() const;
    [[nodiscard]] bool load_persisted_settings();
    [[nodiscard]] bool persist_settings(const nexus::core::Config& config) const;
    void record_audit(std::string actor, std::string domain, std::string action, std::string detail);
    void record_audit_locked(std::string actor, std::string domain, std::string action, std::string detail);
    void expire_sessions_locked(std::chrono::system_clock::time_point now) const;
    [[nodiscard]] static std::string random_token(std::size_t bytes);
};

}  // namespace nexus::api
