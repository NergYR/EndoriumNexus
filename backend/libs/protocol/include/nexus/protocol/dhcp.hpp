#pragma once

#include "nexus/core/models.hpp"

#include <optional>
#include <string>
#include <vector>

namespace nexus::protocol {

[[nodiscard]] std::optional<nexus::core::DhcpLease> allocate_next_lease(
    const nexus::core::DhcpPool& pool,
    const std::vector<nexus::core::DhcpLease>& existing_leases,
    const std::string& client_id,
    const std::string& hostname);

}  // namespace nexus::protocol

