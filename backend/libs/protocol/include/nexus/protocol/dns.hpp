#pragma once

#include "nexus/core/models.hpp"

#include <string>

namespace nexus::protocol {

[[nodiscard]] std::string render_zone_file(const nexus::core::DnsZone& zone, const std::string& primary_ns, const std::string& admin_mailbox);

}  // namespace nexus::protocol

