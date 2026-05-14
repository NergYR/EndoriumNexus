#pragma once

#include <chrono>
#include <string>

namespace nexus::security {

class Totp {
  public:
    [[nodiscard]] std::string generate_secret(std::size_t bytes = 20) const;
    [[nodiscard]] std::string provisioning_uri(
        const std::string& issuer,
        const std::string& account_name,
        const std::string& secret) const;
    [[nodiscard]] std::string code_at(
        const std::string& secret,
        std::chrono::system_clock::time_point time_point) const;
    [[nodiscard]] bool verify(
        const std::string& secret,
        const std::string& code,
        std::chrono::system_clock::time_point time_point,
        int window = 1) const;
};

}  // namespace nexus::security

