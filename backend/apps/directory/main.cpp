#include "nexus/core/config.hpp"
#include "nexus/core/uv_runtime.hpp"
#include "nexus/protocol/ldap.hpp"

int main() {
    const auto config = nexus::core::Config::from_env();
    const nexus::protocol::LdapDirectoryInfo directory{
        config.domain,
        config.directory.base_dn,
        config.directory.realm,
        config.directory.site_name,
        config.directory.domain_controller_host,
    };

    auto ldap_handler = [directory](const std::string&, const nexus::core::UvPacket& packet) {
        return nexus::protocol::ldap_ad_response(packet, directory);
    };

    return nexus::core::run_uv_daemon(
        "directory",
        {
            {"ldap", config.ldap.host, config.ldap.port, nexus::core::UvTransport::tcp, ldap_handler},
            {"cldap", config.ldap.host, config.ldap.port, nexus::core::UvTransport::udp, ldap_handler},
            {"ldaps", config.ldaps.host, config.ldaps.port, nexus::core::UvTransport::tcp},
            {"global-catalog", config.global_catalog.host, config.global_catalog.port, nexus::core::UvTransport::tcp, ldap_handler},
            {"kerberos-tcp", config.kerberos.host, config.kerberos.port, nexus::core::UvTransport::tcp},
            {"kerberos-udp", config.kerberos.host, config.kerberos.port, nexus::core::UvTransport::udp},
            {"kpasswd-tcp", config.kpasswd.host, config.kpasswd.port, nexus::core::UvTransport::tcp},
            {"kpasswd-udp", config.kpasswd.host, config.kpasswd.port, nexus::core::UvTransport::udp},
            {"rpc-endpoint-mapper", config.rpc_endpoint_mapper.host, config.rpc_endpoint_mapper.port, nexus::core::UvTransport::tcp},
            {"smb", config.smb.host, config.smb.port, nexus::core::UvTransport::tcp},
        });
}
