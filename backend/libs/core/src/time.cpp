#include "nexus/core/time.hpp"

#include <ctime>
#include <iomanip>
#include <sstream>

namespace nexus::core {

std::string utc_timestamp() {
    return utc_timestamp(std::chrono::system_clock::now());
}

std::string utc_timestamp(std::chrono::system_clock::time_point time_point) {
    const auto raw_time = std::chrono::system_clock::to_time_t(time_point);
    std::tm tm{};
    gmtime_r(&raw_time, &tm);

    std::ostringstream output;
    output << std::put_time(&tm, "%Y-%m-%dT%H:%M:%SZ");
    return output.str();
}

}  // namespace nexus::core

