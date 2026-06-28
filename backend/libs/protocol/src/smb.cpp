#include "nexus/protocol/smb.hpp"
#include "nexus/protocol/rpc.hpp"

#include <openssl/evp.h>
#include <openssl/hmac.h>

#include <algorithm>
#include <array>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <cctype>
#include <map>
#include <mutex>
#include <optional>
#include <string>
#include <tuple>
#include <utility>
#include <vector>

namespace nexus::protocol {
namespace {

constexpr std::uint16_t smb2_command_negotiate = 0x0000;
constexpr std::uint16_t smb2_command_session_setup = 0x0001;
constexpr std::uint16_t smb2_command_logoff = 0x0002;
constexpr std::uint16_t smb2_command_tree_connect = 0x0003;
constexpr std::uint16_t smb2_command_tree_disconnect = 0x0004;
constexpr std::uint16_t smb2_command_create = 0x0005;
constexpr std::uint16_t smb2_command_close = 0x0006;
constexpr std::uint16_t smb2_command_flush = 0x0007;
constexpr std::uint16_t smb2_command_read = 0x0008;
constexpr std::uint16_t smb2_command_write = 0x0009;
constexpr std::uint16_t smb2_command_lock = 0x000a;
constexpr std::uint16_t smb2_command_ioctl = 0x000b;
constexpr std::uint16_t smb2_command_cancel = 0x000c;
constexpr std::uint16_t smb2_command_echo = 0x000d;
constexpr std::uint16_t smb2_command_query_directory = 0x000e;
constexpr std::uint16_t smb2_command_change_notify = 0x000f;
constexpr std::uint16_t smb2_command_query_info = 0x0010;
constexpr std::uint16_t smb2_command_set_info = 0x0011;
constexpr std::uint32_t smb2_status_success = 0x00000000U;
constexpr std::uint32_t smb2_status_end_of_file = 0xc0000011U;
constexpr std::uint32_t smb2_status_object_name_not_found = 0xc0000034U;
constexpr std::uint32_t smb2_status_pipe_empty = 0xc00000d9U;
constexpr std::uint32_t smb2_status_not_supported = 0xc00000bbU;
constexpr std::uint32_t smb2_status_bad_network_name = 0xc00000ccU;
constexpr std::uint32_t smb2_status_logon_failure = 0xc000006dU;
constexpr std::uint32_t smb2_status_no_more_files = 0x80000006U;
constexpr std::uint32_t smb2_header_flag_server_to_redir = 0x00000001U;
constexpr std::uint32_t smb2_header_flag_signed = 0x00000008U;
constexpr std::uint64_t nexus_smb_session_id = 0x400000000001ULL;
constexpr std::uint32_t nexus_smb_ipc_tree_id = 1;
constexpr std::uint32_t nexus_smb_sysvol_tree_id = 2;
constexpr std::uint32_t nexus_smb_netlogon_tree_id = 3;
constexpr std::uint32_t fsctl_pipe_transceive = 0x0011c017U;
constexpr std::uint32_t fsctl_validate_negotiate_info = 0x00140204U;
constexpr std::uint32_t fs_file_persistent_acls = 0x00000008U;
constexpr std::uint32_t fs_file_unicode_on_disk = 0x00000004U;
constexpr std::uint32_t fs_file_case_preserved_names = 0x00000002U;
constexpr std::uint32_t fs_file_case_sensitive_search = 0x00000001U;

using PipeCacheKey = std::tuple<std::uint64_t, std::uint64_t, std::uint64_t>;

std::mutex& pipe_cache_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::map<PipeCacheKey, std::vector<std::uint8_t>>& pipe_response_cache() {
    static std::map<PipeCacheKey, std::vector<std::uint8_t>> cache;
    return cache;
}

std::map<PipeCacheKey, std::vector<std::uint8_t>>& pipe_request_fragment_cache() {
    static std::map<PipeCacheKey, std::vector<std::uint8_t>> cache;
    return cache;
}

// Writable overlay for SYSVOL/NETLOGON policy files. Windows clients author
// Group Policy by writing gpt.ini/Registry.pol/GptTmpl.inf; the overlay makes
// those writes persist across stateless smb2_response() calls so a later READ
// returns the authored content instead of the read-only skeleton. Keyed by the
// normalized share path, guarded by its own mutex (mirrors the pipe cache).
std::mutex& sysvol_overlay_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::map<std::string, std::vector<std::uint8_t>>& sysvol_overlay() {
    static std::map<std::string, std::vector<std::uint8_t>> overlay;
    return overlay;
}

std::mutex& signing_key_mutex() {
    static std::mutex mutex;
    return mutex;
}

std::map<std::uint64_t, std::vector<std::uint8_t>>& signing_key_cache() {
    static std::map<std::uint64_t, std::vector<std::uint8_t>> cache;
    return cache;
}

PipeCacheKey pipe_cache_key(const Smb2RequestInfo& request) {
    return {request.session_id, request.file_id_persistent, request.file_id_volatile};
}

std::uint16_t read_u16(const std::vector<std::uint8_t>& input, std::size_t offset) {
    if (offset + 2 > input.size()) {
        return 0;
    }
    return static_cast<std::uint16_t>(input[offset]) |
           static_cast<std::uint16_t>(static_cast<std::uint16_t>(input[offset + 1]) << 8U);
}

std::uint32_t read_u32(const std::vector<std::uint8_t>& input, std::size_t offset) {
    if (offset + 4 > input.size()) {
        return 0;
    }
    return static_cast<std::uint32_t>(input[offset]) |
           (static_cast<std::uint32_t>(input[offset + 1]) << 8U) |
           (static_cast<std::uint32_t>(input[offset + 2]) << 16U) |
           (static_cast<std::uint32_t>(input[offset + 3]) << 24U);
}

std::uint64_t read_u64(const std::vector<std::uint8_t>& input, std::size_t offset) {
    std::uint64_t value = 0;
    for (std::size_t index = 0; index < 8 && offset + index < input.size(); ++index) {
        value |= static_cast<std::uint64_t>(input[offset + index]) << (index * 8U);
    }
    return value;
}

std::optional<std::size_t> dce_rpc_expected_fragment_size(const std::vector<std::uint8_t>& input) {
    if (input.empty()) {
        return std::nullopt;
    }
    if (input.size() < 16) {
        return input.front() == 5 ? std::nullopt : std::optional<std::size_t>{input.size()};
    }
    if (input[0] != 5) {
        return input.size();
    }

    constexpr std::size_t max_reasonable_fragment_size = 1024U * 1024U;
    const auto fragment_size = static_cast<std::size_t>(read_u16(input, 8));
    if (fragment_size < 16 || fragment_size > max_reasonable_fragment_size) {
        return input.size();
    }
    return fragment_size;
}

std::optional<std::vector<std::uint8_t>> complete_pipe_rpc_fragment(const Smb2RequestInfo& request) {
    std::lock_guard<std::mutex> lock(pipe_cache_mutex());
    auto& cache = pipe_request_fragment_cache();
    const auto key = pipe_cache_key(request);
    auto& pending = cache[key];
    pending.insert(pending.end(), request.write_data.begin(), request.write_data.end());

    const auto expected_size = dce_rpc_expected_fragment_size(pending);
    if (!expected_size.has_value() || pending.size() < *expected_size) {
        return std::nullopt;
    }

    std::vector<std::uint8_t> fragment(
        pending.begin(),
        pending.begin() + static_cast<std::ptrdiff_t>(*expected_size));
    if (pending.size() == *expected_size) {
        cache.erase(key);
    } else {
        pending.erase(pending.begin(), pending.begin() + static_cast<std::ptrdiff_t>(*expected_size));
    }
    return fragment;
}

void queue_pipe_response(PipeCacheKey key, std::vector<std::uint8_t> output) {
    if (output.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(pipe_cache_mutex());
    auto& cached = pipe_response_cache()[key];
    if (cached.empty()) {
        cached = std::move(output);
        return;
    }
    cached.insert(cached.end(), output.begin(), output.end());
}

std::vector<std::uint8_t> pipe_response_chunk(
    const Smb2RequestInfo& request,
    std::vector<std::uint8_t> output,
    bool cache_remainder) {
    if (request.max_output_response == 0 || output.size() <= request.max_output_response) {
        return output;
    }

    const auto limit = static_cast<std::size_t>(request.max_output_response);
    std::vector<std::uint8_t> remainder(
        output.begin() + static_cast<std::ptrdiff_t>(limit),
        output.end());
    output.resize(limit);
    if (cache_remainder) {
        queue_pipe_response(pipe_cache_key(request), std::move(remainder));
    }
    return output;
}

std::string lower_ascii(std::string value) {
    for (auto& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
    }
    return value;
}

std::uint64_t stable_hash64(const std::string& value) {
    std::uint64_t hash = 14695981039346656037ULL;
    for (const auto ch : value) {
        hash ^= static_cast<unsigned char>(ch);
        hash *= 1099511628211ULL;
    }
    return hash;
}

std::string read_utf16le_ascii(const std::vector<std::uint8_t>& input, std::size_t offset, std::size_t length) {
    std::string output;
    const auto end = std::min(input.size(), offset + length);
    for (std::size_t current = offset; current + 1 < end; current += 2) {
        const auto codepoint = static_cast<std::uint16_t>(input[current]) |
                               static_cast<std::uint16_t>(static_cast<std::uint16_t>(input[current + 1]) << 8U);
        output.push_back(codepoint >= 0x20 && codepoint <= 0x7e ? static_cast<char>(codepoint) : '?');
    }
    return output;
}

std::string trim_pipe_prefix(std::string value) {
    while (!value.empty() && (value.front() == '\\' || value.front() == '/')) {
        value.erase(value.begin());
    }
    return value;
}

std::string normalize_share_path(std::string value) {
    std::replace(value.begin(), value.end(), '/', '\\');
    while (!value.empty() && value.front() == '\\') {
        value.erase(value.begin());
    }
    while (!value.empty() && value.back() == '\\') {
        value.pop_back();
    }
    return lower_ascii(value);
}

std::vector<std::uint8_t> utf16le_ascii(const std::string& value) {
    std::vector<std::uint8_t> output;
    output.reserve(value.size() * 2U);
    for (const auto ch : value) {
        output.push_back(static_cast<std::uint8_t>(ch));
        output.push_back(0);
    }
    return output;
}

void write_u16(std::vector<std::uint8_t>& output, std::uint16_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
}

void write_u32(std::vector<std::uint8_t>& output, std::uint32_t value) {
    output.push_back(static_cast<std::uint8_t>(value & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 16U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>((value >> 24U) & 0xffU));
}

void write_u64(std::vector<std::uint8_t>& output, std::uint64_t value) {
    for (int index = 0; index < 8; ++index) {
        output.push_back(static_cast<std::uint8_t>((value >> (index * 8U)) & 0xffU));
    }
}

void write_u32_at(std::vector<std::uint8_t>& output, std::size_t offset, std::uint32_t value) {
    if (offset + 4 > output.size()) {
        return;
    }
    output[offset] = static_cast<std::uint8_t>(value & 0xffU);
    output[offset + 1] = static_cast<std::uint8_t>((value >> 8U) & 0xffU);
    output[offset + 2] = static_cast<std::uint8_t>((value >> 16U) & 0xffU);
    output[offset + 3] = static_cast<std::uint8_t>((value >> 24U) & 0xffU);
}

std::size_t smb2_offset(const std::vector<std::uint8_t>& packet, bool& netbios_framed) {
    netbios_framed = false;
    if (packet.size() >= 4 && packet[0] == 0x00) {
        const auto length = (static_cast<std::uint32_t>(packet[1]) << 16U) |
                            (static_cast<std::uint32_t>(packet[2]) << 8U) |
                            static_cast<std::uint32_t>(packet[3]);
        if (length == packet.size() - 4) {
            netbios_framed = true;
            return 4;
        }
    }
    return 0;
}

std::optional<std::vector<std::uint8_t>> hmac_sha256(
    const std::vector<std::uint8_t>& key,
    const std::vector<std::uint8_t>& message) {
    if (key.empty()) {
        return std::nullopt;
    }
    std::vector<std::uint8_t> digest(EVP_MAX_MD_SIZE);
    unsigned int digest_len = 0;
    if (HMAC(
            EVP_sha256(),
            key.data(),
            static_cast<int>(key.size()),
            message.data(),
            message.size(),
            digest.data(),
            &digest_len) == nullptr) {
        return std::nullopt;
    }
    digest.resize(digest_len);
    return digest;
}

std::uint64_t response_session_id(const Smb2RequestInfo& request, const std::vector<std::uint8_t>& packet) {
    bool framed = false;
    const auto offset = smb2_offset(packet, framed);
    if (packet.size() >= offset + 48) {
        const auto session_id = read_u64(packet, offset + 40);
        if (session_id != 0) {
            return session_id;
        }
    }
    return request.session_id;
}

std::optional<std::vector<std::uint8_t>> cached_signing_key(std::uint64_t session_id) {
    if (session_id == 0) {
        return std::nullopt;
    }
    std::lock_guard<std::mutex> lock(signing_key_mutex());
    const auto it = signing_key_cache().find(session_id);
    if (it == signing_key_cache().end()) {
        return std::nullopt;
    }
    return it->second;
}

void cache_signing_key(std::uint64_t session_id, const std::vector<std::uint8_t>& key) {
    if (session_id == 0 || key.empty()) {
        return;
    }
    std::lock_guard<std::mutex> lock(signing_key_mutex());
    signing_key_cache()[session_id] = key;
}

std::vector<std::uint8_t> signing_key_for_response(
    const Smb2RequestInfo& request,
    const Smb2RuntimeInfo& runtime,
    const std::vector<std::uint8_t>& packet) {
    if (!runtime.signing_key.empty()) {
        return runtime.signing_key;
    }
    const auto session_id = response_session_id(request, packet);
    if (auto key = cached_signing_key(session_id)) {
        return *key;
    }
    return {};
}

std::vector<std::uint8_t> sign_smb2_response(
    const Smb2RequestInfo& request,
    const Smb2RuntimeInfo& runtime,
    std::vector<std::uint8_t> packet) {
    auto signing_key = signing_key_for_response(request, runtime, packet);
    if (signing_key.empty()) {
        return packet;
    }

    bool netbios_framed = false;
    const auto offset = smb2_offset(packet, netbios_framed);
    if (packet.size() < offset + 64) {
        return packet;
    }

    const auto flags = read_u32(packet, offset + 16) | smb2_header_flag_signed;
    write_u32_at(packet, offset + 16, flags);
    std::fill(packet.begin() + static_cast<std::ptrdiff_t>(offset + 48),
              packet.begin() + static_cast<std::ptrdiff_t>(offset + 64),
              0);
    const std::vector<std::uint8_t> signed_region(
        packet.begin() + static_cast<std::ptrdiff_t>(offset),
        packet.end());
    auto signature = hmac_sha256(signing_key, signed_region);
    if (!signature.has_value() || signature->size() < 16) {
        return packet;
    }
    std::copy_n(
        signature->begin(),
        16,
        packet.begin() + static_cast<std::ptrdiff_t>(offset + 48));
    return packet;
}

std::vector<std::uint8_t> concat(std::initializer_list<std::vector<std::uint8_t>> chunks) {
    std::vector<std::uint8_t> output;
    for (const auto& chunk : chunks) {
        output.insert(output.end(), chunk.begin(), chunk.end());
    }
    return output;
}

void append_der_length(std::vector<std::uint8_t>& output, std::size_t length) {
    if (length < 0x80U) {
        output.push_back(static_cast<std::uint8_t>(length));
        return;
    }
    if (length <= 0xffU) {
        output.push_back(0x81);
        output.push_back(static_cast<std::uint8_t>(length));
        return;
    }
    output.push_back(0x82);
    output.push_back(static_cast<std::uint8_t>((length >> 8U) & 0xffU));
    output.push_back(static_cast<std::uint8_t>(length & 0xffU));
}

std::vector<std::uint8_t> der_tlv(std::uint8_t tag, const std::vector<std::uint8_t>& payload) {
    std::vector<std::uint8_t> output{tag};
    append_der_length(output, payload.size());
    output.insert(output.end(), payload.begin(), payload.end());
    return output;
}

std::vector<std::uint8_t> der_oid(std::initializer_list<std::uint32_t> parts_list) {
    const std::vector<std::uint32_t> parts(parts_list);
    std::vector<std::uint8_t> payload;
    if (parts.size() < 2) {
        return der_tlv(0x06, payload);
    }
    payload.push_back(static_cast<std::uint8_t>(parts[0] * 40U + parts[1]));
    for (std::size_t index = 2; index < parts.size(); ++index) {
        std::uint32_t value = parts[index];
        std::array<std::uint8_t, 5> encoded{};
        std::size_t count = 0;
        do {
            encoded[count++] = static_cast<std::uint8_t>(value & 0x7fU);
            value >>= 7U;
        } while (value != 0 && count < encoded.size());
        for (std::size_t reverse = count; reverse > 0; --reverse) {
            auto byte = encoded[reverse - 1];
            if (reverse != 1) {
                byte |= 0x80U;
            }
            payload.push_back(byte);
        }
    }
    return der_tlv(0x06, payload);
}

std::vector<std::uint8_t> spnego_security_blob() {
    const auto mech_types = der_tlv(0x30, concat({
        der_oid({1, 2, 840, 113554, 1, 2, 2}),
        der_oid({1, 2, 840, 48018, 1, 2, 2}),
        der_oid({1, 3, 6, 1, 4, 1, 311, 2, 2, 10}),
    }));
    const auto neg_token_init = der_tlv(0x30, der_tlv(0xa0, mech_types));
    return der_tlv(0x60, concat({
        der_oid({1, 3, 6, 1, 5, 5, 2}),
        der_tlv(0xa0, neg_token_init),
    }));
}

std::uint16_t choose_dialect(const std::vector<std::uint16_t>& dialects) {
    // Prefer SMB 2.1: SMB 3.x clients enforce "secure negotiate" by sending
    // FSCTL_VALIDATE_NEGOTIATE_INFO right after TREE_CONNECT, and Windows tears the
    // connection down when the server can't satisfy it (we answer STATUS_NOT_SUPPORTED).
    // That teardown aborts the domain join (surfacing as a bogus Int32 OverflowException
    // in Add-Computer). SMB 2.1 clients never send that IOCTL, and 2.1 still provides
    // everything the join needs (named pipes, RPC, signing).
    for (const auto preferred : {std::uint16_t{0x0210}, std::uint16_t{0x0202}, std::uint16_t{0x0302}, std::uint16_t{0x0300}, std::uint16_t{0x0311}}) {
        if (std::find(dialects.begin(), dialects.end(), preferred) != dialects.end()) {
            return preferred;
        }
    }
    return dialects.empty() ? 0 : dialects.front();
}

std::uint64_t windows_filetime_now() {
    constexpr std::uint64_t windows_to_unix_100ns = 116444736000000000ULL;
    const auto now = std::chrono::system_clock::now().time_since_epoch();
    const auto ticks = std::chrono::duration_cast<std::chrono::nanoseconds>(now).count() / 100;
    return windows_to_unix_100ns + static_cast<std::uint64_t>(ticks);
}

std::vector<std::uint8_t> smb2_header(
    const Smb2RequestInfo& request,
    std::uint32_t status,
    std::uint16_t command,
    std::uint32_t tree_id = 0,
    std::uint64_t session_id = 0) {
    std::vector<std::uint8_t> output{0xfe, 'S', 'M', 'B'};
    write_u16(output, 64);
    write_u16(output, 0);
    write_u32(output, status);
    write_u16(output, command);
    write_u16(output, 1);
    write_u32(output, smb2_header_flag_server_to_redir);
    write_u32(output, 0);
    write_u64(output, request.message_id);
    write_u32(output, 0);
    write_u32(output, tree_id);
    write_u64(output, session_id);
    output.insert(output.end(), 16, 0);
    return output;
}

std::vector<std::uint8_t> add_netbios_frame(const std::vector<std::uint8_t>& smb2_packet) {
    std::vector<std::uint8_t> output{
        0x00,
        static_cast<std::uint8_t>((smb2_packet.size() >> 16U) & 0xffU),
        static_cast<std::uint8_t>((smb2_packet.size() >> 8U) & 0xffU),
        static_cast<std::uint8_t>(smb2_packet.size() & 0xffU),
    };
    output.insert(output.end(), smb2_packet.begin(), smb2_packet.end());
    return output;
}

std::vector<std::uint8_t> error_response(const Smb2RequestInfo& request, std::uint32_t status);

std::vector<std::uint8_t> negotiate_response(const Smb2RequestInfo& request) {
    const auto security_blob = spnego_security_blob();
    const std::uint16_t security_offset = 64 + 64;

    auto packet = smb2_header(request, smb2_status_success, smb2_command_negotiate);
    write_u16(packet, 65);
    write_u16(packet, 1);
    write_u16(packet, request.selected_dialect);
    write_u16(packet, 0);
    packet.insert(packet.end(), {
        0x45, 0x4e, 0x44, 0x4f, 0x52, 0x49, 0x55, 0x4d,
        0x4e, 0x45, 0x58, 0x55, 0x53, 0x41, 0x44, 0x31,
    });
    write_u32(packet, 0);
    write_u32(packet, 65536);
    write_u32(packet, 1048576);
    write_u32(packet, 1048576);
    const auto now = windows_filetime_now();
    write_u64(packet, now);
    write_u64(packet, now);
    write_u16(packet, security_offset);
    write_u16(packet, static_cast<std::uint16_t>(security_blob.size()));
    write_u32(packet, 0);
    packet.insert(packet.end(), security_blob.begin(), security_blob.end());
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> session_setup_response(
    const Smb2RequestInfo& request,
    const std::vector<std::uint8_t>& security_blob = {}) {
    auto packet = smb2_header(
        request,
        smb2_status_success,
        smb2_command_session_setup,
        0,
        request.session_id == 0 ? nexus_smb_session_id : request.session_id);
    write_u16(packet, 9);
    write_u16(packet, 0);
    write_u16(packet, 64 + 8);
    write_u16(packet, static_cast<std::uint16_t>(security_blob.size()));
    packet.insert(packet.end(), security_blob.begin(), security_blob.end());
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> spnego_response_token(const std::vector<std::uint8_t>& response_token) {
    // A SPNEGO *response* (the acceptor's reply) is a bare NegTokenResp [1]. Only the
    // initiator's very first token carries the GSS InitialContextToken wrapper
    // ([APPLICATION 0] + SPNEGO OID). Wrapping the response in that header makes
    // Windows reject the SMB session-setup with STATUS_INVALID_PARAMETER (the domain
    // join then fails with "Paramètre incorrect"), so emit the NegTokenResp directly.
    const auto neg_state = der_tlv(0xa0, der_tlv(0x0a, {0}));
    const auto response = der_tlv(0xa2, der_tlv(0x04, response_token));
    return der_tlv(0xa1, der_tlv(0x30, concat({neg_state, response})));
}

std::vector<std::uint8_t> extract_kerberos_ap_req(const std::vector<std::uint8_t>& security_blob) {
    for (std::size_t offset = 0; offset < security_blob.size(); ++offset) {
        if (security_blob[offset] != 0x6e) {
            continue;
        }
        std::size_t length_offset = offset + 1;
        if (length_offset >= security_blob.size()) {
            continue;
        }
        std::size_t length = 0;
        const auto first_length = security_blob[length_offset++];
        if ((first_length & 0x80U) == 0) {
            length = first_length;
        } else {
            const auto count = first_length & 0x7fU;
            if (count == 0 || count > 4 || length_offset + count > security_blob.size()) {
                continue;
            }
            for (std::uint8_t index = 0; index < count; ++index) {
                length = (length << 8U) | security_blob[length_offset++];
            }
        }
        const auto next_offset = length_offset + length;
        if (next_offset <= security_blob.size()) {
            return {
                security_blob.begin() + static_cast<std::ptrdiff_t>(offset),
                security_blob.begin() + static_cast<std::ptrdiff_t>(next_offset),
            };
        }
    }
    return {};
}

std::vector<std::uint8_t> session_setup_response(const Smb2RequestInfo& request, const Smb2RuntimeInfo& runtime) {
    if (runtime.kerberos_realm.has_value() && !request.security_blob.empty()) {
        const auto ap_req = extract_kerberos_ap_req(request.security_blob);
        if (ap_req.empty()) {
            return error_response(request, smb2_status_logon_failure);
        }
        const auto validation = validate_kerberos_ap_req(
            ap_req,
            *runtime.kerberos_realm,
            runtime.cifs_service_principal.empty()
                ? std::optional<std::string>{}
                : std::optional<std::string>{runtime.cifs_service_principal});
        if (!validation.ok) {
            return error_response(request, smb2_status_logon_failure);
        }
        cache_signing_key(
            request.session_id == 0 ? nexus_smb_session_id : request.session_id,
            validation.session_key);
        if (!validation.response_token.empty()) {
            return session_setup_response(request, spnego_response_token(validation.response_token));
        }
    }
    return session_setup_response(request);
}

std::uint32_t tree_id_for_path(const std::string& path) {
    const auto lower = lower_ascii(path);
    if (lower.ends_with("\\ipc$") || lower == "ipc$") {
        return nexus_smb_ipc_tree_id;
    }
    if (lower.ends_with("\\sysvol") || lower == "sysvol") {
        return nexus_smb_sysvol_tree_id;
    }
    if (lower.ends_with("\\netlogon") || lower == "netlogon") {
        return nexus_smb_netlogon_tree_id;
    }
    return 0;
}

std::uint8_t share_type_for_tree_id(std::uint32_t tree_id) {
    return tree_id == nexus_smb_ipc_tree_id ? 0x02 : 0x01;
}

std::vector<std::uint8_t> tree_connect_response(const Smb2RequestInfo& request) {
    const auto tree_id = tree_id_for_path(request.tree_path);
    if (tree_id == 0) {
        return error_response(request, smb2_status_bad_network_name);
    }

    auto packet = smb2_header(
        request,
        smb2_status_success,
        smb2_command_tree_connect,
        tree_id,
        request.session_id == 0 ? nexus_smb_session_id : request.session_id);
    write_u16(packet, 16);
    packet.push_back(share_type_for_tree_id(tree_id));
    packet.push_back(0);
    write_u32(packet, 0x00000030U);
    write_u32(packet, 0);
    write_u32(packet, 0x001f01ffU);
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> fixed_empty_response(const Smb2RequestInfo& request, std::uint16_t command) {
    auto packet = smb2_header(
        request,
        smb2_status_success,
        command,
        command == smb2_command_tree_disconnect ? request.tree_id : 0,
        request.session_id);
    write_u16(packet, 4);
    write_u16(packet, 0);
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> close_response(const Smb2RequestInfo& request) {
    {
        std::lock_guard<std::mutex> lock(pipe_cache_mutex());
        pipe_response_cache().erase(pipe_cache_key(request));
        pipe_request_fragment_cache().erase(pipe_cache_key(request));
    }

    auto packet = smb2_header(request, smb2_status_success, smb2_command_close, request.tree_id, request.session_id);
    const auto now = windows_filetime_now();
    write_u16(packet, 60);
    write_u16(packet, 0);
    write_u32(packet, 0);
    write_u64(packet, now);
    write_u64(packet, now);
    write_u64(packet, now);
    write_u64(packet, now);
    write_u64(packet, 0);
    write_u64(packet, 0);
    write_u32(packet, 0x00000010U);
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> flush_response(const Smb2RequestInfo& request) {
    auto packet = smb2_header(request, smb2_status_success, smb2_command_flush, request.tree_id, request.session_id);
    write_u16(packet, 4);
    write_u16(packet, 0);
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> echo_response(const Smb2RequestInfo& request) {
    auto packet = smb2_header(request, smb2_status_success, smb2_command_echo, 0, request.session_id);
    write_u16(packet, 4);
    write_u16(packet, 0);
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

bool is_supported_ipc_pipe_name(const std::string& name) {
    const auto lower = lower_ascii(trim_pipe_prefix(name));
    return lower == "netlogon" ||
           lower == "epmapper" ||
           lower == "samr" ||
           lower == "lsarpc" ||
           lower == "srvsvc" ||
           lower == "wkssvc";
}

std::string pipe_name_for_file_id(std::uint64_t persistent, std::uint64_t volatile_id) {
    for (const auto* pipe : {"netlogon", "epmapper", "samr", "lsarpc", "srvsvc", "wkssvc"}) {
        const std::string name = pipe;
        if (stable_hash64(name + ":persistent") == persistent &&
            stable_hash64(name + ":volatile") == volatile_id) {
            return name;
        }
    }
    return "";
}

std::uint64_t file_id_part(const std::string& path, const std::string& suffix) {
    return stable_hash64(normalize_share_path(path) + suffix);
}

bool file_id_matches_path(
    std::uint64_t persistent,
    std::uint64_t volatile_id,
    const std::string& path) {
    const auto normalized = normalize_share_path(path);
    return file_id_part(normalized, ":persistent") == persistent &&
           file_id_part(normalized, ":volatile") == volatile_id;
}

std::string default_domain_name(const Smb2RuntimeInfo& runtime) {
    if (!runtime.rpc.domain_dns_name.empty()) {
        return lower_ascii(runtime.rpc.domain_dns_name);
    }
    return "endorium.local";
}

std::vector<std::string> policy_guids() {
    return {
        "{31b2f340-016d-11d2-945f-00c04fb984f9}",
        "{6ac1786c-016f-11d2-945f-00c04fb984f9}",
    };
}

std::vector<std::string> sysvol_known_paths(const std::string& domain) {
    std::vector<std::string> paths{
        "",
        domain,
        domain + "\\policies",
        domain + "\\scripts",
        domain + "\\scripts\\readme.txt",
        "readme.txt",
    };
    for (const auto& guid : policy_guids()) {
        const auto root = domain + "\\policies\\" + guid;
        for (const auto& suffix : {
                 "",
                 "\\gpt.ini",
                 "\\machine",
                 "\\machine\\registry.pol",
                 "\\machine\\microsoft",
                 "\\machine\\microsoft\\windows nt",
                 "\\machine\\microsoft\\windows nt\\secedit",
                 "\\machine\\microsoft\\windows nt\\secedit\\gpttmpl.inf",
                 "\\machine\\scripts",
                 "\\machine\\scripts\\startup",
                 "\\machine\\scripts\\shutdown",
                 "\\user",
                 "\\user\\registry.pol",
                 "\\user\\scripts",
                 "\\user\\scripts\\logon",
                 "\\user\\scripts\\logoff",
             }) {
            paths.push_back(root + suffix);
        }
    }
    return paths;
}

bool is_sysvol_directory_path(const std::string& path, const std::string& domain) {
    if (path.empty() || path == domain || path == domain + "\\policies" || path == domain + "\\scripts") {
        return true;
    }
    for (const auto& guid : policy_guids()) {
        const auto root = domain + "\\policies\\" + guid;
        if (path == root ||
            path == root + "\\machine" ||
            path == root + "\\machine\\microsoft" ||
            path == root + "\\machine\\microsoft\\windows nt" ||
            path == root + "\\machine\\microsoft\\windows nt\\secedit" ||
            path == root + "\\machine\\scripts" ||
            path == root + "\\machine\\scripts\\startup" ||
            path == root + "\\machine\\scripts\\shutdown" ||
            path == root + "\\user" ||
            path == root + "\\user\\scripts" ||
            path == root + "\\user\\scripts\\logon" ||
            path == root + "\\user\\scripts\\logoff") {
            return true;
        }
    }
    return false;
}

std::string known_share_path_for_file_id(const Smb2RequestInfo& request, const Smb2RuntimeInfo& runtime) {
    const auto domain = default_domain_name(runtime);
    auto candidates = sysvol_known_paths(domain);
    if (request.tree_id == nexus_smb_netlogon_tree_id) {
        candidates = {"", "readme.txt"};
    }
    for (const auto& path : candidates) {
        if (file_id_matches_path(request.file_id_persistent, request.file_id_volatile, path)) {
            return normalize_share_path(path);
        }
    }
    return "";
}

bool is_directory_share_path(const std::string& path, std::uint32_t tree_id, const Smb2RuntimeInfo& runtime) {
    const auto domain = default_domain_name(runtime);
    if (path.empty()) {
        return true;
    }
    if (tree_id == nexus_smb_sysvol_tree_id) {
        return is_sysvol_directory_path(path, domain);
    }
    return false;
}

bool known_share_path_exists(const std::string& path, std::uint32_t tree_id, const Smb2RuntimeInfo& runtime) {
    const auto normalized = normalize_share_path(path);
    if (tree_id == nexus_smb_ipc_tree_id) {
        return is_supported_ipc_pipe_name(normalized);
    }
    if (tree_id == nexus_smb_netlogon_tree_id) {
        return normalized.empty() || normalized == "readme.txt";
    }
    if (tree_id != nexus_smb_sysvol_tree_id) {
        return false;
    }
    const auto domain = default_domain_name(runtime);
    const auto known_paths = sysvol_known_paths(domain);
    return std::any_of(known_paths.begin(), known_paths.end(), [&](const auto& known) {
        return normalize_share_path(known) == normalized;
    });
}

std::vector<std::uint8_t> lock_response(const Smb2RequestInfo& request, const Smb2RuntimeInfo& runtime) {
    if (request.tree_id == nexus_smb_ipc_tree_id) {
        if (pipe_name_for_file_id(request.file_id_persistent, request.file_id_volatile).empty()) {
            return error_response(request, smb2_status_object_name_not_found);
        }
    } else if (request.tree_id == nexus_smb_sysvol_tree_id || request.tree_id == nexus_smb_netlogon_tree_id) {
        const auto path = known_share_path_for_file_id(request, runtime);
        if (path.empty() &&
            request.file_id_persistent != file_id_part("", ":persistent") &&
            request.file_id_volatile != file_id_part("", ":volatile")) {
            return error_response(request, smb2_status_object_name_not_found);
        }
    } else {
        return error_response(request, smb2_status_bad_network_name);
    }

    auto packet = smb2_header(request, smb2_status_success, smb2_command_lock, request.tree_id, request.session_id);
    write_u16(packet, 4);
    write_u16(packet, 0);
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::uint32_t file_attributes_for_create(const Smb2RequestInfo& request) {
    if (request.tree_id == nexus_smb_ipc_tree_id) {
        return 0;
    }
    const auto path = normalize_share_path(request.create_name);
    if (request.create_name.empty() || request.create_name.ends_with("\\") || request.create_name.ends_with("/") ||
        path.ends_with("policies") || path.ends_with("scripts") ||
        path.ends_with("machine") || path.ends_with("user") ||
        path.ends_with("microsoft") || path.ends_with("windows nt") || path.ends_with("secedit") ||
        path.ends_with("startup") || path.ends_with("shutdown") || path.ends_with("logon") || path.ends_with("logoff") ||
        path.ends_with("{31b2f340-016d-11d2-945f-00c04fb984f9}") ||
        path.ends_with("{6ac1786c-016f-11d2-945f-00c04fb984f9}")) {
        return 0x00000010U;
    }
    return 0x00000020U;
}

std::vector<std::uint8_t> create_response(const Smb2RequestInfo& request, const Smb2RuntimeInfo& runtime) {
    if (request.tree_id == nexus_smb_ipc_tree_id && !is_supported_ipc_pipe_name(request.create_name)) {
        return error_response(request, smb2_status_object_name_not_found);
    }
    if (request.tree_id != nexus_smb_ipc_tree_id &&
        request.tree_id != nexus_smb_sysvol_tree_id &&
        request.tree_id != nexus_smb_netlogon_tree_id) {
        return error_response(request, smb2_status_bad_network_name);
    }
    if (!known_share_path_exists(request.create_name, request.tree_id, runtime)) {
        return error_response(request, smb2_status_object_name_not_found);
    }

    auto packet = smb2_header(
        request,
        smb2_status_success,
        smb2_command_create,
        request.tree_id,
        request.session_id);
    const auto now = windows_filetime_now();
    write_u16(packet, 89);
    packet.push_back(0);
    packet.push_back(0);
    write_u32(packet, 1);
    write_u64(packet, now);
    write_u64(packet, now);
    write_u64(packet, now);
    write_u64(packet, now);
    write_u64(packet, 0);
    write_u64(packet, 0);
    write_u32(packet, file_attributes_for_create(request));
    write_u32(packet, 0);
    write_u64(packet, file_id_part(request.create_name, ":persistent"));
    write_u64(packet, file_id_part(request.create_name, ":volatile"));
    write_u32(packet, 0);
    write_u32(packet, 0);
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::string> directory_entries_for_path(
    const std::string& path,
    std::uint32_t tree_id,
    const Smb2RuntimeInfo& runtime) {
    const auto domain = default_domain_name(runtime);
    if (tree_id == nexus_smb_netlogon_tree_id) {
        return path.empty() ? std::vector<std::string>{"README.txt"} : std::vector<std::string>{};
    }
    if (tree_id != nexus_smb_sysvol_tree_id) {
        return {};
    }
    if (path.empty()) {
        return {domain};
    }
    if (path == domain) {
        return {"Policies", "scripts"};
    }
    if (path == domain + "\\policies") {
        return {
            "{31B2F340-016D-11D2-945F-00C04FB984F9}",
            "{6AC1786C-016F-11D2-945F-00C04FB984F9}",
        };
    }
    if (path == domain + "\\policies\\{31b2f340-016d-11d2-945f-00c04fb984f9}" ||
        path == domain + "\\policies\\{6ac1786c-016f-11d2-945f-00c04fb984f9}") {
        return {"gpt.ini", "Machine", "User"};
    }
    if (path.ends_with("\\machine")) {
        return {"Registry.pol", "Microsoft", "Scripts"};
    }
    if (path.ends_with("\\machine\\microsoft")) {
        return {"Windows NT"};
    }
    if (path.ends_with("\\machine\\microsoft\\windows nt")) {
        return {"SecEdit"};
    }
    if (path.ends_with("\\machine\\microsoft\\windows nt\\secedit")) {
        return {"GptTmpl.inf"};
    }
    if (path.ends_with("\\machine\\scripts")) {
        return {"Startup", "Shutdown"};
    }
    if (path.ends_with("\\machine\\scripts\\startup") || path.ends_with("\\machine\\scripts\\shutdown")) {
        return {};
    }
    if (path.ends_with("\\user")) {
        return {"Registry.pol", "Scripts"};
    }
    if (path.ends_with("\\user\\scripts")) {
        return {"Logon", "Logoff"};
    }
    if (path.ends_with("\\user\\scripts\\logon") || path.ends_with("\\user\\scripts\\logoff")) {
        return {};
    }
    if (path == domain + "\\scripts") {
        return {"README.txt"};
    }
    return {};
}

std::string file_content_for_path(
    const std::string& path,
    std::uint32_t tree_id,
    const Smb2RuntimeInfo& runtime) {
    const auto domain = default_domain_name(runtime);
    // Authored Group Policy content takes precedence over the read-only skeleton.
    {
        std::lock_guard<std::mutex> lock(sysvol_overlay_mutex());
        const auto& overlay = sysvol_overlay();
        const auto it = overlay.find(path);
        if (it != overlay.end()) {
            return std::string(it->second.begin(), it->second.end());
        }
    }
    if (tree_id == nexus_smb_netlogon_tree_id && path == "readme.txt") {
        return "Endorium Nexus NETLOGON share\r\n"
               "No logon scripts are configured for this domain.\r\n";
    }
    if (tree_id != nexus_smb_sysvol_tree_id) {
        return "";
    }
    if (path == domain + "\\scripts\\readme.txt") {
        return "Endorium Nexus SYSVOL scripts share\r\n"
               "No startup, shutdown, logon or logoff scripts are configured for this domain.\r\n";
    }
    if (path.ends_with("\\gpt.ini")) {
        const auto display_name = path.find("{6ac1786c-016f-11d2-945f-00c04fb984f9}") == std::string::npos
            ? "Default Domain Policy"
            : "Default Domain Controllers Policy";
        return "[General]\r\nVersion=0\r\ndisplayName=" + std::string(display_name) + "\r\n";
    }
    if (path.ends_with("\\registry.pol")) {
        return std::string("PReg\x01\x00\x00\x00", 8);
    }
    if (path.ends_with("\\gpttmpl.inf")) {
        return "[Unicode]\r\n"
               "Unicode=yes\r\n"
               "[System Access]\r\n"
               "MinimumPasswordAge = 0\r\n"
               "MaximumPasswordAge = 42\r\n"
               "MinimumPasswordLength = 0\r\n"
               "PasswordComplexity = 0\r\n"
               "ClearTextPassword = 0\r\n"
               "LockoutBadCount = 0\r\n"
               "RequireLogonToChangePassword = 0\r\n"
               "ForceLogoffWhenHourExpire = 0\r\n"
               "[Version]\r\n"
               "signature=\"$CHICAGO$\"\r\n"
               "Revision=1\r\n";
    }
    return "";
}

void append_directory_information_entry(
    std::vector<std::uint8_t>& output,
    const std::string& name,
    bool directory,
    bool last) {
    const auto start = output.size();
    const auto name_bytes = utf16le_ascii(name);
    write_u32(output, 0);
    write_u32(output, 0);
    const auto now = windows_filetime_now();
    write_u64(output, now);
    write_u64(output, now);
    write_u64(output, now);
    write_u64(output, now);
    write_u64(output, 0);
    write_u64(output, 0);
    write_u32(output, directory ? 0x00000010U : 0x00000020U);
    write_u32(output, static_cast<std::uint32_t>(name_bytes.size()));
    output.insert(output.end(), name_bytes.begin(), name_bytes.end());
    while (output.size() % 8 != 0) {
        output.push_back(0);
    }
    if (!last) {
        const auto next_offset = static_cast<std::uint32_t>(output.size() - start);
        output[start] = static_cast<std::uint8_t>(next_offset & 0xffU);
        output[start + 1] = static_cast<std::uint8_t>((next_offset >> 8U) & 0xffU);
        output[start + 2] = static_cast<std::uint8_t>((next_offset >> 16U) & 0xffU);
        output[start + 3] = static_cast<std::uint8_t>((next_offset >> 24U) & 0xffU);
    }
}

std::vector<std::uint8_t> directory_listing_buffer(
    const std::string& path,
    const Smb2RequestInfo& request,
    const Smb2RuntimeInfo& runtime) {
    const auto entries = directory_entries_for_path(path, request.tree_id, runtime);
    std::vector<std::uint8_t> output;
    for (std::size_t index = 0; index < entries.size(); ++index) {
        const auto child_path = path.empty() ? normalize_share_path(entries[index]) : path + "\\" + normalize_share_path(entries[index]);
        append_directory_information_entry(
            output,
            entries[index],
            is_directory_share_path(child_path, request.tree_id, runtime),
            index + 1 == entries.size());
    }
    return output;
}

std::vector<std::uint8_t> query_directory_response(
    const Smb2RequestInfo& request,
    const Smb2RuntimeInfo& runtime) {
    const auto path = known_share_path_for_file_id(request, runtime);
    const auto listing = directory_listing_buffer(path, request, runtime);
    if (listing.empty()) {
        return error_response(request, smb2_status_no_more_files);
    }
    const std::uint16_t buffer_offset = 64 + 8;
    auto packet = smb2_header(request, smb2_status_success, smb2_command_query_directory, request.tree_id, request.session_id);
    write_u16(packet, 9);
    write_u16(packet, buffer_offset);
    write_u32(packet, static_cast<std::uint32_t>(listing.size()));
    packet.insert(packet.end(), listing.begin(), listing.end());
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> change_notify_response(
    const Smb2RequestInfo& request,
    const Smb2RuntimeInfo& runtime) {
    const auto path = known_share_path_for_file_id(request, runtime);
    if (path.empty() &&
        request.file_id_persistent != file_id_part("", ":persistent") &&
        request.file_id_volatile != file_id_part("", ":volatile")) {
        return error_response(request, smb2_status_object_name_not_found);
    }
    if (!is_directory_share_path(path, request.tree_id, runtime)) {
        return error_response(request, smb2_status_object_name_not_found);
    }

    auto packet = smb2_header(
        request,
        smb2_status_success,
        smb2_command_change_notify,
        request.tree_id,
        request.session_id);
    write_u16(packet, 9);
    write_u16(packet, 0);
    write_u32(packet, 0);
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> file_standard_information(bool directory, std::uint64_t size) {
    std::vector<std::uint8_t> output;
    write_u64(output, size);
    write_u64(output, size);
    write_u32(output, 1);
    output.push_back(0);
    output.push_back(directory ? 1 : 0);
    write_u16(output, 0);
    return output;
}

std::vector<std::uint8_t> file_basic_information(bool directory) {
    std::vector<std::uint8_t> output;
    const auto now = windows_filetime_now();
    write_u64(output, now);
    write_u64(output, now);
    write_u64(output, now);
    write_u64(output, now);
    write_u32(output, directory ? 0x00000010U : 0x00000020U);
    write_u32(output, 0);
    return output;
}

std::uint32_t file_attributes_for_info(bool directory) {
    return directory ? 0x00000010U : 0x00000020U;
}

std::string file_name_for_information(const std::string& path) {
    if (path.empty()) {
        return "";
    }
    const auto separator = path.find_last_of('\\');
    if (separator == std::string::npos) {
        return path;
    }
    return path.substr(separator + 1);
}

std::vector<std::uint8_t> file_internal_information(const std::string& path) {
    std::vector<std::uint8_t> output;
    write_u64(output, stable_hash64(path.empty() ? std::string{"."} : path));
    return output;
}

std::vector<std::uint8_t> file_ea_information() {
    std::vector<std::uint8_t> output;
    write_u32(output, 0);
    return output;
}

std::vector<std::uint8_t> file_access_information() {
    std::vector<std::uint8_t> output;
    write_u32(output, 0x0012019fU);
    return output;
}

std::vector<std::uint8_t> file_position_information() {
    std::vector<std::uint8_t> output;
    write_u64(output, 0);
    return output;
}

std::vector<std::uint8_t> file_mode_information() {
    std::vector<std::uint8_t> output;
    write_u32(output, 0);
    return output;
}

std::vector<std::uint8_t> file_alignment_information() {
    std::vector<std::uint8_t> output;
    write_u32(output, 0);
    return output;
}

std::vector<std::uint8_t> file_name_information(const std::string& path) {
    std::vector<std::uint8_t> output;
    const auto name = utf16le_ascii(file_name_for_information(path));
    write_u32(output, static_cast<std::uint32_t>(name.size()));
    output.insert(output.end(), name.begin(), name.end());
    return output;
}

std::vector<std::uint8_t> file_network_open_information(bool directory, std::uint64_t size) {
    std::vector<std::uint8_t> output;
    const auto now = windows_filetime_now();
    write_u64(output, now);
    write_u64(output, now);
    write_u64(output, now);
    write_u64(output, now);
    write_u64(output, size);
    write_u64(output, size);
    write_u32(output, file_attributes_for_info(directory));
    write_u32(output, 0);
    return output;
}

std::vector<std::uint8_t> file_attribute_tag_information(bool directory) {
    std::vector<std::uint8_t> output;
    write_u32(output, file_attributes_for_info(directory));
    write_u32(output, 0);
    return output;
}

std::vector<std::uint8_t> file_all_information(const std::string& path, bool directory, std::uint64_t size) {
    std::vector<std::uint8_t> output;
    const auto basic = file_basic_information(directory);
    const auto standard = file_standard_information(directory, size);
    const auto internal = file_internal_information(path);
    const auto ea = file_ea_information();
    const auto access = file_access_information();
    const auto position = file_position_information();
    const auto mode = file_mode_information();
    const auto alignment = file_alignment_information();
    const auto name = file_name_information(path);
    output.insert(output.end(), basic.begin(), basic.end());
    output.insert(output.end(), standard.begin(), standard.end());
    output.insert(output.end(), internal.begin(), internal.end());
    output.insert(output.end(), ea.begin(), ea.end());
    output.insert(output.end(), access.begin(), access.end());
    output.insert(output.end(), position.begin(), position.end());
    output.insert(output.end(), mode.begin(), mode.end());
    output.insert(output.end(), alignment.begin(), alignment.end());
    output.insert(output.end(), name.begin(), name.end());
    return output;
}

std::vector<std::uint8_t> file_information(
    std::uint8_t info_class,
    const std::string& path,
    bool directory,
    std::uint64_t size) {
    switch (info_class) {
        case 4:
            return file_basic_information(directory);
        case 5:
            return file_standard_information(directory, size);
        case 6:
            return file_internal_information(path);
        case 7:
            return file_ea_information();
        case 8:
            return file_access_information();
        case 9:
            return file_name_information(path);
        case 14:
            return file_position_information();
        case 16:
            return file_mode_information();
        case 17:
            return file_alignment_information();
        case 18:
            return file_all_information(path, directory, size);
        case 34:
            return file_network_open_information(directory, size);
        case 35:
            return file_attribute_tag_information(directory);
        default:
            return file_standard_information(directory, size);
    }
}

bool parse_decimal_part(const std::string& value, std::size_t begin, std::size_t end, std::uint64_t& output) {
    if (begin >= end || end > value.size()) {
        return false;
    }
    std::uint64_t parsed = 0;
    for (std::size_t index = begin; index < end; ++index) {
        const auto ch = static_cast<unsigned char>(value[index]);
        if (!std::isdigit(ch)) {
            return false;
        }
        parsed = (parsed * 10U) + static_cast<std::uint64_t>(ch - static_cast<unsigned char>('0'));
    }
    output = parsed;
    return true;
}

std::vector<std::uint8_t> sid_bytes(const std::string& sid) {
    if (sid.size() < 5 || sid.rfind("S-", 0) != 0) {
        return {};
    }

    std::size_t cursor = 2;
    auto delimiter = sid.find('-', cursor);
    if (delimiter == std::string::npos) {
        return {};
    }
    std::uint64_t revision = 0;
    if (!parse_decimal_part(sid, cursor, delimiter, revision) || revision > 0xffU) {
        return {};
    }

    cursor = delimiter + 1;
    delimiter = sid.find('-', cursor);
    const auto authority_end = delimiter == std::string::npos ? sid.size() : delimiter;
    std::uint64_t authority = 0;
    if (!parse_decimal_part(sid, cursor, authority_end, authority) || authority > 0xffffffffffffULL) {
        return {};
    }

    std::vector<std::uint32_t> sub_authorities;
    cursor = authority_end;
    while (cursor != std::string::npos && cursor < sid.size()) {
        if (sid[cursor] != '-') {
            return {};
        }
        const auto next = sid.find('-', cursor + 1);
        const auto part_end = next == std::string::npos ? sid.size() : next;
        std::uint64_t sub_authority = 0;
        if (!parse_decimal_part(sid, cursor + 1, part_end, sub_authority) || sub_authority > 0xffffffffULL) {
            return {};
        }
        sub_authorities.push_back(static_cast<std::uint32_t>(sub_authority));
        cursor = next;
    }
    if (sub_authorities.size() > 0xffU) {
        return {};
    }

    std::vector<std::uint8_t> output;
    output.push_back(static_cast<std::uint8_t>(revision));
    output.push_back(static_cast<std::uint8_t>(sub_authorities.size()));
    for (int shift = 40; shift >= 0; shift -= 8) {
        output.push_back(static_cast<std::uint8_t>((authority >> static_cast<unsigned>(shift)) & 0xffU));
    }
    for (const auto sub_authority : sub_authorities) {
        write_u32(output, sub_authority);
    }
    return output;
}

std::vector<std::uint8_t> security_descriptor_ace(const std::string& sid, std::uint32_t access_mask) {
    const auto encoded_sid = sid_bytes(sid);
    if (encoded_sid.empty()) {
        return {};
    }
    std::vector<std::uint8_t> output;
    output.push_back(0);
    output.push_back(0);
    write_u16(output, static_cast<std::uint16_t>(8U + encoded_sid.size()));
    write_u32(output, access_mask);
    output.insert(output.end(), encoded_sid.begin(), encoded_sid.end());
    return output;
}

std::vector<std::uint8_t> security_descriptor_dacl(const std::vector<std::string>& allowed_sids) {
    std::vector<std::uint8_t> aces;
    std::uint16_t ace_count = 0;
    for (const auto& sid : allowed_sids) {
        const auto ace = security_descriptor_ace(sid, 0x001f01ffU);
        if (ace.empty()) {
            continue;
        }
        aces.insert(aces.end(), ace.begin(), ace.end());
        ++ace_count;
    }

    std::vector<std::uint8_t> output;
    output.push_back(2);
    output.push_back(0);
    write_u16(output, static_cast<std::uint16_t>(8U + aces.size()));
    write_u16(output, ace_count);
    write_u16(output, 0);
    output.insert(output.end(), aces.begin(), aces.end());
    return output;
}

std::vector<std::uint8_t> smb_security_descriptor(const Smb2RuntimeInfo& runtime) {
    const std::string builtin_administrators = "S-1-5-32-544";
    const std::string local_system = "S-1-5-18";
    const std::string authenticated_users = "S-1-5-11";
    const auto domain_admins = runtime.rpc.domain_sid.empty() ? std::string{} : runtime.rpc.domain_sid + "-512";

    const auto owner = sid_bytes(builtin_administrators);
    const auto group = sid_bytes(domain_admins.empty() ? builtin_administrators : domain_admins);
    std::vector<std::string> allowed_sids{local_system, builtin_administrators, authenticated_users};
    if (!domain_admins.empty()) {
        allowed_sids.push_back(domain_admins);
    }
    const auto dacl = security_descriptor_dacl(allowed_sids);

    constexpr std::uint32_t header_size = 20;
    const auto owner_offset = header_size;
    const auto group_offset = owner_offset + owner.size();
    const auto dacl_offset = group_offset + group.size();

    std::vector<std::uint8_t> output;
    output.push_back(1);
    output.push_back(0);
    write_u16(output, 0x8004U);
    write_u32(output, static_cast<std::uint32_t>(owner_offset));
    write_u32(output, static_cast<std::uint32_t>(group_offset));
    write_u32(output, 0);
    write_u32(output, static_cast<std::uint32_t>(dacl_offset));
    output.insert(output.end(), owner.begin(), owner.end());
    output.insert(output.end(), group.begin(), group.end());
    output.insert(output.end(), dacl.begin(), dacl.end());
    return output;
}

std::string filesystem_name_for_tree(std::uint32_t tree_id) {
    return tree_id == nexus_smb_ipc_tree_id ? "IPC" : "NTFS";
}

std::vector<std::uint8_t> filesystem_volume_information() {
    std::vector<std::uint8_t> output;
    const auto now = windows_filetime_now();
    const auto label = utf16le_ascii("Endorium Nexus");
    write_u64(output, now);
    write_u32(output, 0x454e5841U);
    write_u32(output, static_cast<std::uint32_t>(label.size()));
    output.push_back(0);
    output.insert(output.end(), label.begin(), label.end());
    return output;
}

std::vector<std::uint8_t> filesystem_size_information(bool full) {
    std::vector<std::uint8_t> output;
    constexpr std::uint64_t allocation_units = 262144;
    constexpr std::uint64_t available_units = 131072;
    write_u64(output, allocation_units);
    write_u64(output, available_units);
    if (full) {
        write_u64(output, available_units);
    }
    write_u32(output, 8);
    write_u32(output, 512);
    return output;
}

std::vector<std::uint8_t> filesystem_device_information(std::uint32_t tree_id) {
    std::vector<std::uint8_t> output;
    write_u32(output, tree_id == nexus_smb_ipc_tree_id ? 0x00000011U : 0x00000007U);
    write_u32(output, 0);
    return output;
}

std::vector<std::uint8_t> filesystem_attribute_information(std::uint32_t tree_id) {
    std::vector<std::uint8_t> output;
    const auto name = utf16le_ascii(filesystem_name_for_tree(tree_id));
    write_u32(output, fs_file_persistent_acls |
        fs_file_unicode_on_disk |
        fs_file_case_preserved_names |
        fs_file_case_sensitive_search);
    write_u32(output, 255);
    write_u32(output, static_cast<std::uint32_t>(name.size()));
    output.insert(output.end(), name.begin(), name.end());
    return output;
}

std::vector<std::uint8_t> filesystem_information(std::uint8_t info_class, std::uint32_t tree_id) {
    switch (info_class) {
        case 1:
            return filesystem_volume_information();
        case 3:
            return filesystem_size_information(false);
        case 4:
            return filesystem_device_information(tree_id);
        case 5:
            return filesystem_attribute_information(tree_id);
        case 7:
            return filesystem_size_information(true);
        default:
            return filesystem_attribute_information(tree_id);
    }
}

std::vector<std::uint8_t> query_info_response(
    const Smb2RequestInfo& request,
    const Smb2RuntimeInfo& runtime) {
    const auto path = known_share_path_for_file_id(request, runtime);
    const auto directory = is_directory_share_path(path, request.tree_id, runtime);
    const auto content = file_content_for_path(path, request.tree_id, runtime);
    std::vector<std::uint8_t> info;
    if (request.query_info_type == 3) {
        info = smb_security_descriptor(runtime);
    } else if (request.query_info_type == 2) {
        info = filesystem_information(request.query_file_info_class, request.tree_id);
    } else {
        info = file_information(
            request.query_file_info_class,
            path,
            directory,
            static_cast<std::uint64_t>(content.size()));
    }
    const std::uint16_t buffer_offset = 64 + 8;
    auto packet = smb2_header(request, smb2_status_success, smb2_command_query_info, request.tree_id, request.session_id);
    write_u16(packet, 9);
    write_u16(packet, buffer_offset);
    write_u32(packet, static_cast<std::uint32_t>(info.size()));
    packet.insert(packet.end(), info.begin(), info.end());
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> set_info_response(const Smb2RequestInfo& request, const Smb2RuntimeInfo& runtime) {
    const auto pipe_name = pipe_name_for_file_id(request.file_id_persistent, request.file_id_volatile);
    if (request.tree_id == nexus_smb_ipc_tree_id && pipe_name.empty()) {
        return error_response(request, smb2_status_object_name_not_found);
    }
    if (request.tree_id == nexus_smb_sysvol_tree_id || request.tree_id == nexus_smb_netlogon_tree_id) {
        const auto path = known_share_path_for_file_id(request, runtime);
        if (path.empty() &&
            request.file_id_persistent != file_id_part("", ":persistent") &&
            request.file_id_volatile != file_id_part("", ":volatile")) {
            return error_response(request, smb2_status_object_name_not_found);
        }
    } else if (request.tree_id != nexus_smb_ipc_tree_id) {
        return error_response(request, smb2_status_bad_network_name);
    }

    auto packet = smb2_header(request, smb2_status_success, smb2_command_set_info, request.tree_id, request.session_id);
    write_u16(packet, 2);
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> read_response(
    const Smb2RequestInfo& request,
    const Smb2RuntimeInfo& runtime) {
    if (request.tree_id == nexus_smb_ipc_tree_id &&
        !pipe_name_for_file_id(request.file_id_persistent, request.file_id_volatile).empty()) {
        std::vector<std::uint8_t> data;
        {
            std::lock_guard<std::mutex> lock(pipe_cache_mutex());
            auto& cache = pipe_response_cache();
            auto it = cache.find(pipe_cache_key(request));
            if (it == cache.end() || it->second.empty()) {
                return error_response(request, smb2_status_pipe_empty);
            }

            const auto count = std::min<std::size_t>(
                it->second.size(),
                request.read_length == 0 ? it->second.size() : request.read_length);
            data.assign(it->second.begin(), it->second.begin() + static_cast<std::ptrdiff_t>(count));
            if (count == it->second.size()) {
                cache.erase(it);
            } else {
                it->second.erase(it->second.begin(), it->second.begin() + static_cast<std::ptrdiff_t>(count));
            }
        }

        const std::uint8_t data_offset = 64 + 16;
        auto packet = smb2_header(request, smb2_status_success, smb2_command_read, request.tree_id, request.session_id);
        write_u16(packet, 17);
        packet.push_back(data_offset);
        packet.push_back(0);
        write_u32(packet, static_cast<std::uint32_t>(data.size()));
        write_u32(packet, 0);
        write_u32(packet, 0);
        packet.insert(packet.end(), data.begin(), data.end());
        return request.netbios_framed ? add_netbios_frame(packet) : packet;
    }

    const auto path = known_share_path_for_file_id(request, runtime);
    const auto content_text = file_content_for_path(path, request.tree_id, runtime);
    if (content_text.empty() || request.read_offset >= content_text.size()) {
        return error_response(request, smb2_status_end_of_file);
    }
    const auto available = content_text.size() - static_cast<std::size_t>(request.read_offset);
    const auto count = std::min<std::size_t>(available, request.read_length == 0 ? available : request.read_length);
    std::vector<std::uint8_t> data(
        content_text.begin() + static_cast<std::ptrdiff_t>(request.read_offset),
        content_text.begin() + static_cast<std::ptrdiff_t>(request.read_offset + count));
    const std::uint8_t data_offset = 64 + 16;
    auto packet = smb2_header(request, smb2_status_success, smb2_command_read, request.tree_id, request.session_id);
    write_u16(packet, 17);
    packet.push_back(data_offset);
    packet.push_back(0);
    write_u32(packet, static_cast<std::uint32_t>(data.size()));
    write_u32(packet, 0);
    write_u32(packet, 0);
    packet.insert(packet.end(), data.begin(), data.end());
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> write_response(const Smb2RequestInfo& request, const Smb2RuntimeInfo& runtime) {
    // SYSVOL/NETLOGON policy authoring: persist writes to known GPO/script files
    // into the overlay so subsequent reads return the authored content.
    if (request.tree_id == nexus_smb_sysvol_tree_id || request.tree_id == nexus_smb_netlogon_tree_id) {
        const auto path = known_share_path_for_file_id(request, runtime);
        if (path.empty() || is_directory_share_path(path, request.tree_id, runtime)) {
            return error_response(request, smb2_status_object_name_not_found);
        }
        {
            std::lock_guard<std::mutex> lock(sysvol_overlay_mutex());
            auto& buffer = sysvol_overlay()[path];
            const auto end = static_cast<std::size_t>(request.write_offset) + request.write_data.size();
            if (buffer.size() < end) {
                buffer.resize(end, 0);
            }
            std::copy(request.write_data.begin(), request.write_data.end(),
                      buffer.begin() + static_cast<std::ptrdiff_t>(request.write_offset));
        }
        auto packet = smb2_header(request, smb2_status_success, smb2_command_write, request.tree_id, request.session_id);
        write_u16(packet, 17);
        write_u16(packet, 0);
        write_u32(packet, static_cast<std::uint32_t>(request.write_data.size()));
        write_u32(packet, 0);
        write_u16(packet, 0);
        write_u16(packet, 0);
        return request.netbios_framed ? add_netbios_frame(packet) : packet;
    }

    if (request.tree_id != nexus_smb_ipc_tree_id) {
        return error_response(request, smb2_status_not_supported);
    }

    const auto pipe_name = pipe_name_for_file_id(request.file_id_persistent, request.file_id_volatile);
    if (pipe_name.empty()) {
        return error_response(request, smb2_status_object_name_not_found);
    }

    auto rpc_input = complete_pipe_rpc_fragment(request);
    if (rpc_input.has_value() && !rpc_input->empty()) {
        auto output = rpc_named_pipe_response(*rpc_input, pipe_name, runtime.rpc);
        queue_pipe_response(pipe_cache_key(request), std::move(output));
    }

    auto packet = smb2_header(request, smb2_status_success, smb2_command_write, request.tree_id, request.session_id);
    write_u16(packet, 17);
    write_u16(packet, 0);
    write_u32(packet, static_cast<std::uint32_t>(request.write_data.size()));
    write_u32(packet, 0);
    write_u16(packet, 0);
    write_u16(packet, 0);
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> validate_negotiate_response(const Smb2RequestInfo& request) {
    // FSCTL_VALIDATE_NEGOTIATE_INFO ("secure negotiate"): the client re-sends the
    // dialects/capabilities it offered and expects the server to echo back the
    // parameters it negotiated. If the server can't (we used to answer
    // STATUS_NOT_SUPPORTED), Windows tears the connection down — which aborts the
    // domain join (surfaced as a bogus Int32 OverflowException in Add-Computer). These
    // values must match negotiate_response(): Capabilities=0, the server GUID,
    // SecurityMode=signing-enabled, and the negotiated dialect.
    std::uint16_t dialect = 0x0210;
    if (request.ioctl_input.size() >= 24) {
        const auto dialect_count = read_u16(request.ioctl_input, 22);
        std::vector<std::uint16_t> offered;
        for (std::size_t index = 0; index < dialect_count && 24 + index * 2 + 1 < request.ioctl_input.size(); ++index) {
            offered.push_back(read_u16(request.ioctl_input, 24 + index * 2));
        }
        if (const auto chosen = choose_dialect(offered); chosen != 0) {
            dialect = chosen;
        }
    }

    std::vector<std::uint8_t> output;
    write_u32(output, 0);  // Capabilities (matches negotiate_response)
    output.insert(output.end(), {
        0x45, 0x4e, 0x44, 0x4f, 0x52, 0x49, 0x55, 0x4d,
        0x4e, 0x45, 0x58, 0x55, 0x53, 0x41, 0x44, 0x31,
    });                    // ServerGuid
    write_u16(output, 1);  // SecurityMode (signing enabled)
    write_u16(output, dialect);

    const std::uint32_t buffer_offset = 64 + 48;
    auto packet = smb2_header(
        request,
        smb2_status_success,
        smb2_command_ioctl,
        request.tree_id,
        request.session_id);
    write_u16(packet, 49);
    write_u16(packet, 0);
    write_u32(packet, request.ioctl_ctl_code);
    write_u64(packet, request.file_id_persistent);
    write_u64(packet, request.file_id_volatile);
    write_u32(packet, buffer_offset);  // InputOffset
    write_u32(packet, 0);              // InputCount
    write_u32(packet, buffer_offset);  // OutputOffset
    write_u32(packet, static_cast<std::uint32_t>(output.size()));
    write_u32(packet, 0);              // Flags
    write_u32(packet, 0);              // Reserved2
    packet.insert(packet.end(), output.begin(), output.end());
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> ioctl_response(const Smb2RequestInfo& request, const Smb2RuntimeInfo& runtime) {
    if (request.ioctl_ctl_code == fsctl_validate_negotiate_info) {
        return validate_negotiate_response(request);
    }
    if (request.ioctl_ctl_code != fsctl_pipe_transceive || request.tree_id != nexus_smb_ipc_tree_id) {
        return error_response(request, smb2_status_not_supported);
    }

    const auto pipe_name = pipe_name_for_file_id(request.file_id_persistent, request.file_id_volatile);
    auto output = pipe_name.empty()
        ? rpc_endpoint_mapper_response(request.ioctl_input, 135)
        : rpc_named_pipe_response(request.ioctl_input, pipe_name, runtime.rpc);
    output = pipe_response_chunk(request, std::move(output), !pipe_name.empty());

    const std::uint32_t buffer_offset = 64 + 48;
    auto packet = smb2_header(
        request,
        smb2_status_success,
        smb2_command_ioctl,
        request.tree_id,
        request.session_id);
    write_u16(packet, 49);
    write_u16(packet, 0);
    write_u32(packet, request.ioctl_ctl_code);
    write_u64(packet, request.file_id_persistent);
    write_u64(packet, request.file_id_volatile);
    write_u32(packet, buffer_offset);
    write_u32(packet, 0);
    write_u32(packet, output.empty() ? 0 : buffer_offset);
    write_u32(packet, static_cast<std::uint32_t>(output.size()));
    write_u32(packet, 0);
    write_u32(packet, 0);
    packet.insert(packet.end(), output.begin(), output.end());
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

std::vector<std::uint8_t> error_response(const Smb2RequestInfo& request, std::uint32_t status) {
    auto packet = smb2_header(request, status, request.command, request.tree_id, request.session_id);
    write_u16(packet, 9);
    packet.push_back(0);
    packet.push_back(0);
    write_u32(packet, 0);
    packet.push_back(0);
    return request.netbios_framed ? add_netbios_frame(packet) : packet;
}

}  // namespace

Smb2RequestInfo parse_smb2_request(const std::vector<std::uint8_t>& packet) {
    Smb2RequestInfo info;
    const auto offset = smb2_offset(packet, info.netbios_framed);
    // Real SMB clients (smbclient, Windows) open with an SMB1 multi-protocol
    // SMB_COM_NEGOTIATE (0xFF 'SMB', command 0x72) that advertises the "SMB
    // 2.???" dialect. Recognize it so we can answer with an SMB2 negotiate and
    // pull the client up to SMB2 instead of dropping the connection.
    if (packet.size() >= offset + 5 &&
        packet[offset] == 0xff &&
        packet[offset + 1] == 'S' &&
        packet[offset + 2] == 'M' &&
        packet[offset + 3] == 'B' &&
        packet[offset + 4] == 0x72) {
        info.valid = true;
        info.smb1_multiprotocol_negotiate = true;
        info.command = smb2_command_negotiate;
        info.message_id = 0;
        return info;
    }
    if (packet.size() < offset + 64 ||
        packet[offset] != 0xfe ||
        packet[offset + 1] != 'S' ||
        packet[offset + 2] != 'M' ||
        packet[offset + 3] != 'B') {
        return info;
    }
    if (read_u16(packet, offset + 4) != 64) {
        return info;
    }

    info.command = read_u16(packet, offset + 12);
    info.message_id = read_u64(packet, offset + 24);
    info.tree_id = read_u32(packet, offset + 36);
    info.session_id = read_u64(packet, offset + 40);
    if (info.command == smb2_command_negotiate && packet.size() >= offset + 64 + 36) {
        const auto body_offset = offset + 64;
        const auto dialect_count = read_u16(packet, body_offset + 2);
        const auto dialect_offset = body_offset + 36;
        for (std::uint16_t index = 0; index < dialect_count; ++index) {
            const auto current = dialect_offset + static_cast<std::size_t>(index) * 2U;
            if (current + 2 > packet.size()) {
                break;
            }
            info.dialects.push_back(read_u16(packet, current));
        }
        info.selected_dialect = choose_dialect(info.dialects);
    } else if (info.command == smb2_command_session_setup && packet.size() >= offset + 64 + 24) {
        const auto body_offset = offset + 64;
        const auto security_offset = read_u16(packet, body_offset + 12);
        const auto security_length = read_u16(packet, body_offset + 14);
        if (security_offset > 0 && security_length > 0 &&
            offset + security_offset + security_length <= packet.size()) {
            info.security_blob.assign(
                packet.begin() + static_cast<std::ptrdiff_t>(offset + security_offset),
                packet.begin() + static_cast<std::ptrdiff_t>(offset + security_offset + security_length));
        }
    } else if (info.command == smb2_command_tree_connect && packet.size() >= offset + 64 + 8) {
        const auto body_offset = offset + 64;
        const auto path_offset = read_u16(packet, body_offset + 4);
        const auto path_length = read_u16(packet, body_offset + 6);
        if (path_offset > 0 && path_length > 0 && offset + path_offset + path_length <= packet.size()) {
            info.tree_path = read_utf16le_ascii(packet, offset + path_offset, path_length);
        }
    } else if (info.command == smb2_command_create && packet.size() >= offset + 64 + 56) {
        const auto body_offset = offset + 64;
        const auto name_offset = read_u16(packet, body_offset + 44);
        const auto name_length = read_u16(packet, body_offset + 46);
        if (name_offset > 0 && name_length > 0 && offset + name_offset + name_length <= packet.size()) {
            info.create_name = read_utf16le_ascii(packet, offset + name_offset, name_length);
        }
    } else if ((info.command == smb2_command_close || info.command == smb2_command_flush) && packet.size() >= offset + 64 + 24) {
        const auto body_offset = offset + 64;
        info.file_id_persistent = read_u64(packet, body_offset + 8);
        info.file_id_volatile = read_u64(packet, body_offset + 16);
    } else if (info.command == smb2_command_read && packet.size() >= offset + 64 + 48) {
        const auto body_offset = offset + 64;
        info.read_length = read_u32(packet, body_offset + 4);
        info.read_offset = read_u64(packet, body_offset + 8);
        info.file_id_persistent = read_u64(packet, body_offset + 16);
        info.file_id_volatile = read_u64(packet, body_offset + 24);
    } else if (info.command == smb2_command_write && packet.size() >= offset + 64 + 48) {
        const auto body_offset = offset + 64;
        const auto data_offset = read_u16(packet, body_offset + 2);
        const auto data_length = read_u32(packet, body_offset + 4);
        info.write_offset = read_u64(packet, body_offset + 8);
        info.file_id_persistent = read_u64(packet, body_offset + 16);
        info.file_id_volatile = read_u64(packet, body_offset + 24);
        if (data_offset > 0 && data_length > 0 && offset + data_offset + data_length <= packet.size()) {
            info.write_data.assign(
                packet.begin() + static_cast<std::ptrdiff_t>(offset + data_offset),
                packet.begin() + static_cast<std::ptrdiff_t>(offset + data_offset + data_length));
        }
    } else if (info.command == smb2_command_lock && packet.size() >= offset + 64 + 48) {
        const auto body_offset = offset + 64;
        info.file_id_persistent = read_u64(packet, body_offset + 8);
        info.file_id_volatile = read_u64(packet, body_offset + 16);
    } else if (info.command == smb2_command_ioctl && packet.size() >= offset + 64 + 56) {
        const auto body_offset = offset + 64;
        info.ioctl_ctl_code = read_u32(packet, body_offset + 4);
        info.file_id_persistent = read_u64(packet, body_offset + 8);
        info.file_id_volatile = read_u64(packet, body_offset + 16);
        const auto input_offset = read_u32(packet, body_offset + 24);
        const auto input_count = read_u32(packet, body_offset + 28);
        info.max_output_response = read_u32(packet, body_offset + 44);
        if (input_offset > 0 && input_count > 0 && offset + input_offset + input_count <= packet.size()) {
            info.ioctl_input.assign(
                packet.begin() + static_cast<std::ptrdiff_t>(offset + input_offset),
                packet.begin() + static_cast<std::ptrdiff_t>(offset + input_offset + input_count));
        }
    } else if (info.command == smb2_command_query_directory && packet.size() >= offset + 64 + 32) {
        const auto body_offset = offset + 64;
        info.query_file_info_class = packet[body_offset + 2];
        info.file_id_persistent = read_u64(packet, body_offset + 8);
        info.file_id_volatile = read_u64(packet, body_offset + 16);
        info.query_output_length = read_u32(packet, body_offset + 28);
    } else if (info.command == smb2_command_change_notify && packet.size() >= offset + 64 + 32) {
        const auto body_offset = offset + 64;
        info.query_output_length = read_u32(packet, body_offset + 4);
        info.file_id_persistent = read_u64(packet, body_offset + 8);
        info.file_id_volatile = read_u64(packet, body_offset + 16);
    } else if (info.command == smb2_command_query_info && packet.size() >= offset + 64 + 40) {
        const auto body_offset = offset + 64;
        info.query_info_type = packet[body_offset + 2];
        info.query_file_info_class = packet[body_offset + 3];
        info.query_output_length = read_u32(packet, body_offset + 4);
        info.file_id_persistent = read_u64(packet, body_offset + 24);
        info.file_id_volatile = read_u64(packet, body_offset + 32);
    } else if (info.command == smb2_command_set_info && packet.size() >= offset + 64 + 32) {
        const auto body_offset = offset + 64;
        info.set_info_type = packet[body_offset + 2];
        info.set_file_info_class = packet[body_offset + 3];
        info.file_id_persistent = read_u64(packet, body_offset + 16);
        info.file_id_volatile = read_u64(packet, body_offset + 24);
    }
    info.valid = true;
    return info;
}

std::vector<std::uint8_t> smb2_response(const std::vector<std::uint8_t>& packet) {
    return smb2_response(packet, Smb2RuntimeInfo{});
}

std::vector<std::uint8_t> smb2_response(
    const std::vector<std::uint8_t>& packet,
    const Smb2RuntimeInfo& runtime) {
    const auto request = parse_smb2_request(packet);
    if (!request.valid) {
        return {};
    }
    // Answer an SMB1 multi-protocol negotiate with an SMB2 negotiate carrying the
    // 0x02FF wildcard revision; the client then re-negotiates over real SMB2.
    if (request.smb1_multiprotocol_negotiate) {
        Smb2RequestInfo upgrade = request;
        upgrade.selected_dialect = 0x02ff;
        return negotiate_response(upgrade);
    }
    std::vector<std::uint8_t> response;
    if (request.command == smb2_command_negotiate && request.selected_dialect != 0) {
        response = negotiate_response(request);
    } else if (request.command == smb2_command_session_setup) {
        response = session_setup_response(request, runtime);
    } else if (request.command == smb2_command_tree_connect) {
        response = tree_connect_response(request);
    } else if (request.command == smb2_command_tree_disconnect) {
        response = fixed_empty_response(request, smb2_command_tree_disconnect);
    } else if (request.command == smb2_command_logoff) {
        response = fixed_empty_response(request, smb2_command_logoff);
    } else if (request.command == smb2_command_create) {
        response = create_response(request, runtime);
    } else if (request.command == smb2_command_close) {
        response = close_response(request);
    } else if (request.command == smb2_command_flush) {
        response = flush_response(request);
    } else if (request.command == smb2_command_read) {
        response = read_response(request, runtime);
    } else if (request.command == smb2_command_write) {
        response = write_response(request, runtime);
    } else if (request.command == smb2_command_lock) {
        response = lock_response(request, runtime);
    } else if (request.command == smb2_command_ioctl) {
        response = ioctl_response(request, runtime);
    } else if (request.command == smb2_command_cancel) {
        return {};
    } else if (request.command == smb2_command_query_directory) {
        response = query_directory_response(request, runtime);
    } else if (request.command == smb2_command_change_notify) {
        response = change_notify_response(request, runtime);
    } else if (request.command == smb2_command_query_info) {
        response = query_info_response(request, runtime);
    } else if (request.command == smb2_command_set_info) {
        response = set_info_response(request, runtime);
    } else if (request.command == smb2_command_echo) {
        response = echo_response(request);
    } else {
        response = error_response(request, smb2_status_not_supported);
    }
    return sign_smb2_response(request, runtime, std::move(response));
}

}  // namespace nexus::protocol
