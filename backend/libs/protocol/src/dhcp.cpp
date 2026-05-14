#include "nexus/protocol/dhcp.hpp"

#include "nexus/core/time.hpp"

#include <algorithm>
#include <chrono>
#include <array>
#include <cstdint>
#include <sstream>

namespace nexus::protocol {

namespace {

std::uint32_t ip_to_u32(const std::string& ip) {
    std::array<unsigned int, 4> octets{};
    char dot{};
    std::istringstream input(ip);
    input >> octets[0] >> dot >> octets[1] >> dot >> octets[2] >> dot >> octets[3];
    return (octets[0] << 24U) | (octets[1] << 16U) | (octets[2] << 8U) | octets[3];
}

std::string u32_to_ip(std::uint32_t value) {
    std::ostringstream output;
    output << ((value >> 24U) & 0xFF) << "."
           << ((value >> 16U) & 0xFF) << "."
           << ((value >> 8U) & 0xFF) << "."
           << (value & 0xFF);
    return output.str();
}

}  // namespace

std::optional<nexus::core::DhcpLease> allocate_next_lease(
    const nexus::core::DhcpPool& pool,
    const std::vector<nexus::core::DhcpLease>& existing_leases,
    const std::string& client_id,
    const std::string& hostname) {
    const auto start = ip_to_u32(pool.range_start);
    const auto end = ip_to_u32(pool.range_end);

    for (const auto& lease : existing_leases) {
        if (lease.client_id == client_id) {
            return lease;
        }
    }

    for (std::uint32_t candidate = start; candidate <= end; ++candidate) {
        const std::string ip = u32_to_ip(candidate);
        const bool taken = std::any_of(existing_leases.begin(), existing_leases.end(), [&](const auto& lease) {
            return lease.ip_address == ip && lease.state != "expired";
        });
        if (!taken) {
            return nexus::core::DhcpLease{
                ip,
                client_id,
                hostname,
                "active",
                nexus::core::utc_timestamp(std::chrono::system_clock::now() + std::chrono::hours(12))};
        }
    }

    return std::nullopt;
}

}  // namespace nexus::protocol
