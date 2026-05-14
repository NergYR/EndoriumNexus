#pragma once

#include <string>
#include <vector>

namespace nexus::protocol {

[[nodiscard]] std::vector<std::string> split_dn(const std::string& distinguished_name);
[[nodiscard]] bool is_valid_dn(const std::string& distinguished_name);

}  // namespace nexus::protocol

