#include "nexus/core/config.hpp"
#include "nexus/security/password_hasher.hpp"
#include "nexus/security/totp.hpp"
#include "nexus/storage/database.hpp"

#include <iostream>

namespace {

void print_help() {
    std::cout
        << "Usage: nexusctl <command>\n"
        << "  bootstrap-admin <password>\n"
        << "  migrate\n";
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        print_help();
        return 1;
    }

    const std::string command = argv[1];
    const auto config = nexus::core::Config::from_env();

    if (command == "bootstrap-admin") {
        if (argc < 3) {
            std::cerr << "bootstrap-admin requires a password\n";
            return 1;
        }

        nexus::security::PasswordHasher hasher;
        nexus::security::Totp totp;
        std::cout << "NEXUS_ADMIN_EMAIL=" << config.admin_email << "\n";
        std::cout << "NEXUS_ADMIN_PASSWORD_HASH=" << hasher.hash_password(argv[2]) << "\n";
        std::cout << "NEXUS_ADMIN_TOTP_SECRET=" << totp.generate_secret() << "\n";
        return 0;
    }

    if (command == "migrate") {
        nexus::storage::Database database(config.database_url);
        // Honour NEXUS_SQL_MIGRATIONS_DIR (config.sql_migrations_dir) so migrations
        // work outside the repo root — e.g. from the container's /opt/nexus.
        database.apply_migrations(config.sql_migrations_dir);
        std::cout << "Migrations applied from " << config.sql_migrations_dir << ".\n";
        return 0;
    }

    print_help();
    return 1;
}
