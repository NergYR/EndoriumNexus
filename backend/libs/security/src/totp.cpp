#include "nexus/security/totp.hpp"

#include <openssl/hmac.h>
#include <openssl/rand.h>

#include <array>
#include <cmath>
#include <cstdint>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <vector>

namespace nexus::security {

namespace {

constexpr char kAlphabet[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

std::string base32_encode(const std::vector<unsigned char>& data) {
    std::string output;
    int buffer = 0;
    int bits_left = 0;

    for (unsigned char byte : data) {
        buffer = (buffer << 8) | byte;
        bits_left += 8;
        while (bits_left >= 5) {
            output.push_back(kAlphabet[(buffer >> (bits_left - 5)) & 0x1F]);
            bits_left -= 5;
        }
    }

    if (bits_left > 0) {
        output.push_back(kAlphabet[(buffer << (5 - bits_left)) & 0x1F]);
    }

    return output;
}

std::vector<unsigned char> base32_decode(const std::string& input) {
    std::vector<unsigned char> output;
    int buffer = 0;
    int bits_left = 0;

    for (char ch : input) {
        if (ch == '=') {
            break;
        }

        int value = -1;
        if (ch >= 'A' && ch <= 'Z') {
            value = ch - 'A';
        } else if (ch >= '2' && ch <= '7') {
            value = 26 + (ch - '2');
        }

        if (value < 0) {
            continue;
        }

        buffer = (buffer << 5) | value;
        bits_left += 5;

        if (bits_left >= 8) {
            output.push_back(static_cast<unsigned char>((buffer >> (bits_left - 8)) & 0xFF));
            bits_left -= 8;
        }
    }

    return output;
}

std::string format_code(std::uint32_t code) {
    std::ostringstream output;
    output << std::setw(6) << std::setfill('0') << code;
    return output.str();
}

}  // namespace

std::string Totp::generate_secret(std::size_t bytes) const {
    std::vector<unsigned char> buffer(bytes);
    if (RAND_bytes(buffer.data(), static_cast<int>(buffer.size())) != 1) {
        throw std::runtime_error("failed to generate TOTP secret");
    }
    return base32_encode(buffer);
}

std::string Totp::provisioning_uri(
    const std::string& issuer,
    const std::string& account_name,
    const std::string& secret) const {
    return "otpauth://totp/" + issuer + ":" + account_name + "?secret=" + secret + "&issuer=" + issuer;
}

std::string Totp::code_at(
    const std::string& secret,
    std::chrono::system_clock::time_point time_point) const {
    const auto counter = static_cast<std::uint64_t>(
        std::chrono::duration_cast<std::chrono::seconds>(time_point.time_since_epoch()).count() / 30);

    std::array<unsigned char, 8> message{};
    for (int index = 7; index >= 0; --index) {
        message[static_cast<std::size_t>(index)] = static_cast<unsigned char>((counter >> ((7 - index) * 8)) & 0xFF);
    }

    const auto secret_bytes = base32_decode(secret);
    unsigned int digest_length = 0;
    unsigned char digest[EVP_MAX_MD_SIZE];
    HMAC(
        EVP_sha1(),
        secret_bytes.data(),
        static_cast<int>(secret_bytes.size()),
        message.data(),
        static_cast<int>(message.size()),
        digest,
        &digest_length);

    const int offset = digest[digest_length - 1] & 0x0F;
    const std::uint32_t binary_code =
        ((digest[offset] & 0x7F) << 24) |
        ((digest[offset + 1] & 0xFF) << 16) |
        ((digest[offset + 2] & 0xFF) << 8) |
        (digest[offset + 3] & 0xFF);

    return format_code(binary_code % 1000000);
}

bool Totp::verify(
    const std::string& secret,
    const std::string& code,
    std::chrono::system_clock::time_point time_point,
    int window) const {
    for (int offset = -window; offset <= window; ++offset) {
        const auto candidate_time = time_point + std::chrono::seconds(offset * 30);
        if (code_at(secret, candidate_time) == code) {
            return true;
        }
    }
    return false;
}

}  // namespace nexus::security

