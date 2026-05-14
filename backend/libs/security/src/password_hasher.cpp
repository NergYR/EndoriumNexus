#include "nexus/security/password_hasher.hpp"
#include "nexus/security/argon2_ffi.hpp"

#include <openssl/rand.h>

#include <array>
#include <stdexcept>

namespace nexus::security {

std::string PasswordHasher::hash_password(const std::string& password) const {
    std::array<char, 256> encoded{};
    std::array<std::uint8_t, 16> salt{};
    if (RAND_bytes(salt.data(), static_cast<int>(salt.size())) != 1) {
        throw std::runtime_error("RAND_bytes failed");
    }

    const int result = argon2id_hash_encoded(
        3,
        1 << 16,
        1,
        password.data(),
        password.size(),
        salt.data(),
        salt.size(),
        32,
        encoded.data(),
        encoded.size());

    if (result != ARGON2_OK) {
        throw std::runtime_error(argon2_error_message(result));
    }

    return encoded.data();
}

bool PasswordHasher::verify_password(const std::string& password, const std::string& encoded_hash) const {
    return argon2id_verify(encoded_hash.c_str(), password.data(), password.size()) == ARGON2_OK;
}

}  // namespace nexus::security
