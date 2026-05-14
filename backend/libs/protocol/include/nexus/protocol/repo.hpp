#pragma once

#include "nexus/core/models.hpp"

#include <cstdint>
#include <string>
#include <vector>

namespace nexus::protocol {

[[nodiscard]] std::string render_packages_index(const nexus::core::AptRepository& repository);
[[nodiscard]] std::string render_release_file(
    const nexus::core::AptRepository& repository,
    const std::string& origin,
    const std::string& suite,
    const std::string& packages_sha256,
    std::size_t packages_size);
[[nodiscard]] std::vector<std::uint8_t> gzip_bytes(const std::string& payload);

}  // namespace nexus::protocol

