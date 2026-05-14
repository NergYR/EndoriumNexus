#pragma once

#include <chrono>
#include <string>

namespace nexus::core {

[[nodiscard]] std::string utc_timestamp();
[[nodiscard]] std::string utc_timestamp(std::chrono::system_clock::time_point time_point);

}  // namespace nexus::core

