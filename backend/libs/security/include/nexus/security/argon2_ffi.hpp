#pragma once

#include <cstddef>
#include <cstdint>

extern "C" {

int argon2id_hash_encoded(
    std::uint32_t t_cost,
    std::uint32_t m_cost,
    std::uint32_t parallelism,
    const void* pwd,
    std::size_t pwdlen,
    const void* salt,
    std::size_t saltlen,
    std::size_t hashlen,
    char* encoded,
    std::size_t encodedlen);

int argon2id_verify(const char* encoded, const void* pwd, std::size_t pwdlen);

const char* argon2_error_message(int error_code);

}

constexpr int ARGON2_OK = 0;

