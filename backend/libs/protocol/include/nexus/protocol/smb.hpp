#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "nexus/protocol/kerberos.hpp"
#include "nexus/protocol/rpc.hpp"

namespace nexus::protocol {

struct Smb2RequestInfo {
    bool valid{false};
    bool netbios_framed{false};
    bool smb1_multiprotocol_negotiate{false};
    std::uint16_t command{0};
    std::uint16_t selected_dialect{0};
    std::uint32_t tree_id{0};
    std::uint64_t session_id{0};
    std::uint64_t message_id{0};
    std::string tree_path;
    std::string create_name;
    std::uint32_t ioctl_ctl_code{0};
    std::uint64_t file_id_persistent{0};
    std::uint64_t file_id_volatile{0};
    std::uint64_t read_offset{0};
    std::uint32_t read_length{0};
    std::uint64_t write_offset{0};
    std::uint32_t query_output_length{0};
    std::uint8_t query_info_type{0};
    std::uint8_t query_file_info_class{0};
    std::uint8_t set_info_type{0};
    std::uint8_t set_file_info_class{0};
    std::uint32_t max_output_response{0};
    std::vector<std::uint8_t> security_blob;
    std::vector<std::uint8_t> ioctl_input;
    std::vector<std::uint8_t> write_data;
    std::vector<std::uint16_t> dialects;
};

struct Smb2RuntimeInfo {
    RpcRuntimeInfo rpc;
    std::optional<KerberosRealmInfo> kerberos_realm;
    std::string cifs_service_principal;
    std::vector<std::uint8_t> signing_key;
};

[[nodiscard]] Smb2RequestInfo parse_smb2_request(const std::vector<std::uint8_t>& packet);

[[nodiscard]] std::vector<std::uint8_t> smb2_response(const std::vector<std::uint8_t>& packet);

[[nodiscard]] std::vector<std::uint8_t> smb2_response(
    const std::vector<std::uint8_t>& packet,
    const Smb2RuntimeInfo& runtime);

}  // namespace nexus::protocol
