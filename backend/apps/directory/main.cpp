#include "nexus/core/config.hpp"
#include "nexus/core/uv_runtime.hpp"

int main() {
    const auto config = nexus::core::Config::from_env();
    return nexus::core::run_uv_daemon(
        "directory",
        {
            {"ldap", config.ldap.host, config.ldap.port, nexus::core::UvTransport::tcp},
            {"ldaps", config.ldaps.host, config.ldaps.port, nexus::core::UvTransport::tcp},
            {"kerberos-tcp", config.kerberos.host, config.kerberos.port, nexus::core::UvTransport::tcp},
            {"kerberos-udp", config.kerberos.host, config.kerberos.port, nexus::core::UvTransport::udp},
        });
}

