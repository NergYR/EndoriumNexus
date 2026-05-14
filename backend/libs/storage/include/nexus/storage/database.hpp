#pragma once

#include <filesystem>
#include <string>
#include <vector>

namespace nexus::storage {

class Database {
  public:
    explicit Database(std::string connection_string);

    [[nodiscard]] bool configured() const;
    [[nodiscard]] bool ping() const;
    void apply_migrations(const std::filesystem::path& migrations_dir) const;

  private:
    std::string connection_string_;

    [[nodiscard]] std::vector<std::filesystem::path> pending_migrations(const std::filesystem::path& migrations_dir) const;
};

}  // namespace nexus::storage

