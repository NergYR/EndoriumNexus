#pragma once

#include <string>

namespace nexus::security {

class PasswordHasher {
  public:
    [[nodiscard]] std::string hash_password(const std::string& password) const;
    [[nodiscard]] bool verify_password(const std::string& password, const std::string& encoded_hash) const;
};

}  // namespace nexus::security

