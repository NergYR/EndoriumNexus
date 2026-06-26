#pragma once

#include "nexus/core/models.hpp"

#include <filesystem>
#include <cstdint>
#include <map>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::apt {

enum class RepositoryError {
    invalid_repository,
    invalid_package,
    not_found,
    database_not_configured,
    database_unavailable,
    database_error,
    filesystem_error,
    tool_failed,
};

class RepositoryException : public std::runtime_error {
  public:
    RepositoryException(RepositoryError code, std::string message);

    [[nodiscard]] RepositoryError code() const noexcept;

  private:
    RepositoryError code_;
};

[[nodiscard]] bool is_valid_debian_name(std::string_view value);
[[nodiscard]] std::map<std::string, std::string> parse_control_fields(std::string_view control);
[[nodiscard]] std::map<std::string, std::string> extract_deb_control_fields(const std::filesystem::path& deb_path);
[[nodiscard]] std::string render_packages_index(const std::vector<nexus::core::AptPackage>& packages);

class RepositoryService {
  public:
    RepositoryService(
        std::string database_url,
        std::filesystem::path blob_root,
        std::filesystem::path state_root,
        std::string origin);

    [[nodiscard]] std::filesystem::path apt_root() const;
    [[nodiscard]] std::vector<nexus::core::AptRepository> list() const;
    void create_repository(const std::string& distribution, const std::string& component) const;
    bool delete_repository(const std::string& distribution, const std::string& component) const;

    nexus::core::AptPackage upload_package(
        const std::string& distribution,
        const std::string& component,
        const std::string& original_filename,
        std::string_view content,
        const std::string& actor) const;

    bool delete_package(
        const std::string& distribution,
        const std::string& component,
        const nexus::core::AptPackage& package) const;

    [[nodiscard]] std::optional<std::string> packages_index(
        const std::string& distribution,
        const std::string& component,
        const std::string& architecture) const;
    [[nodiscard]] std::optional<std::vector<std::uint8_t>> packages_index_gzip(
        const std::string& distribution,
        const std::string& component,
        const std::string& architecture) const;
    [[nodiscard]] std::optional<std::string> release_file(const std::string& distribution) const;
    [[nodiscard]] std::optional<std::string> in_release(const std::string& distribution) const;
    [[nodiscard]] std::optional<std::string> release_gpg(const std::string& distribution) const;
    [[nodiscard]] std::string public_key() const;
    [[nodiscard]] std::optional<std::filesystem::path> artifact_path(std::string_view storage_path) const;

  private:
    std::string database_url_;
    std::filesystem::path blob_root_;
    std::filesystem::path state_root_;
    std::string origin_;
};

}  // namespace nexus::apt
