#include "nexus/core/config.hpp"
#include "nexus/core/uv_runtime.hpp"

int main() {
    const auto config = nexus::core::Config::from_env();
    return nexus::core::run_uv_daemon(
        "network",
        {
            {"dns-tcp", config.dns_tcp.host, config.dns_tcp.port, nexus::core::UvTransport::tcp},
            {"dns-udp", config.dns_udp.host, config.dns_udp.port, nexus::core::UvTransport::udp},
            {"dhcp-udp", config.dhcp.host, config.dhcp.port, nexus::core::UvTransport::udp},
        });
}

