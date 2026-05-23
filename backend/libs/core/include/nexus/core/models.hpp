#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <string>
#include <utility>
#include <vector>

namespace nexus::core {

struct ServiceStatus {
    std::string id;
    std::string label;
    std::string state;
    std::string summary;
    std::vector<std::string> endpoints;
    std::vector<std::string> capabilities;
    bool critical{true};
    bool enabled{false};

    std::string blocking_reason{};  // Reason if service is blocked, empty otherwise
};
struct DirectoryObject {
    std::string dn;
    std::string parent_dn;
    std::string kind;
    std::vector<std::string> object_classes;
    std::map<std::string, std::string> attributes;
};

struct DnsRecord {
    std::string name;
    std::string type;
    std::string value;
    std::string dns_class{"IN"};  // IN (Internet), CH (Chaos), HS (Hesiod)
    std::uint32_t ttl{3600};
    std::uint16_t priority{0};    // For MX, SRV records
    std::uint16_t weight{0};      // For SRV records
    std::uint16_t port{0};        // For SRV records
    std::string flags{};          // Optional flags field
};

struct DnsZone {
    std::string name;
    std::uint64_t serial{1};
    std::vector<DnsRecord> records;
};

struct DhcpLease {
    std::string ip_address;
    std::string client_id;
    std::string hostname;
    std::string state;
    std::string expires_at;
};

struct DhcpPool {
    std::string name;
    std::string subnet;
    std::string range_start;
    std::string range_end;
    std::map<std::string, std::string> options;
    std::vector<DhcpLease> leases;
};

struct PkiRevocation {
    std::string serial;
    std::string common_name;
    std::string reason;
    std::string revoked_at;
};

struct PkiInsight {
    std::string category;
    std::string title;
    std::string detail;
    std::string severity;
};

struct PkiAssistantSnapshot {
    std::string recommended_mode;
    std::string recommended_profile_id;
    std::string headline;
    std::vector<PkiInsight> insights;
    std::size_t authority_count{0};
    std::size_t certificate_count{0};
    std::size_t revocation_count{0};
    int leaf_days_valid{0};
};

struct PkiAuthority {
    std::string name;
    std::string common_name;
    std::string organization;
    std::string serial_hex;
    std::string certificate_pem;
    std::string private_key_pem;
    std::string created_at;
};

struct PkiCertificate {
    std::string serial_hex;
    std::string authority_name;
    std::string common_name;
    std::string organization;
    std::vector<std::string> dns_subject_alternative_names;
    std::string certificate_pem;
    std::string private_key_pem;
    bool revoked{false};
    std::string created_at;
};

struct AptPackage {
    std::string name;
    std::string version;
    std::string architecture;
    std::string component;
    std::string filename;
    std::string sha256;
    std::size_t size{0};
};

struct AptRepository {
    std::string distribution;
    std::string component;
    std::vector<AptPackage> packages;
};

struct AuditEvent {
    std::string happened_at;
    std::string actor;
    std::string domain;
    std::string action;
    std::string detail;
};

struct JobSummary {
    std::string id;
    std::string domain;
    std::string status;
    std::string description;
    std::string submitted_at;
};

struct DashboardSnapshot {
    std::vector<ServiceStatus> services;
    std::size_t directory_objects{0};
    std::size_t dns_records{0};
    std::size_t dhcp_leases{0};
    std::size_t pending_jobs{0};
    std::size_t pki_revocations{0};
    std::size_t repo_packages{0};
};

}  // namespace nexus::core
