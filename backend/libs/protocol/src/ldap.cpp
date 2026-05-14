#include "nexus/protocol/ldap.hpp"

#include <algorithm>

namespace nexus::protocol {

std::vector<std::string> split_dn(const std::string& distinguished_name) {
    std::vector<std::string> parts;
    std::string current;
    bool escaped = false;

    for (char ch : distinguished_name) {
        if (escaped) {
            current.push_back(ch);
            escaped = false;
            continue;
        }

        if (ch == '\\') {
            escaped = true;
            current.push_back(ch);
            continue;
        }

        if (ch == ',') {
            if (!current.empty()) {
                parts.push_back(current);
                current.clear();
            }
            continue;
        }

        current.push_back(ch);
    }

    if (!current.empty()) {
        parts.push_back(current);
    }

    return parts;
}

bool is_valid_dn(const std::string& distinguished_name) {
    const auto parts = split_dn(distinguished_name);
    if (parts.empty()) {
        return false;
    }

    return std::all_of(parts.begin(), parts.end(), [](const auto& part) {
        const auto position = part.find('=');
        return position != std::string::npos && position > 0 && position < part.size() - 1;
    });
}

}  // namespace nexus::protocol

