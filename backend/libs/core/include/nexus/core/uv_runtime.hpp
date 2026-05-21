#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace nexus::core {

enum class UvTransport {
    tcp,
    udp,
};

using UvPacket = std::vector<std::uint8_t>;
using UvPacketHandler = std::function<UvPacket(const std::string& listener_label, const UvPacket& payload)>;

struct UvListener {
    std::string label;
    std::string host;
    int port;
    UvTransport transport;
    UvPacketHandler handler{};
};

int run_uv_daemon(const std::string& service_name, const std::vector<UvListener>& listeners);

}  // namespace nexus::core
