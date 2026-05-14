#pragma once

#include <string>
#include <vector>

namespace nexus::core {

enum class UvTransport {
    tcp,
    udp,
};

struct UvListener {
    std::string label;
    std::string host;
    int port;
    UvTransport transport;
};

int run_uv_daemon(const std::string& service_name, const std::vector<UvListener>& listeners);

}  // namespace nexus::core

