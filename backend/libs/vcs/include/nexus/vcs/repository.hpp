#pragma once

#include <filesystem>
#include <cstdint>
#include <optional>
#include <stdexcept>
#include <string>
#include <string_view>
#include <vector>

namespace nexus::vcs {

struct Repository {
    std::string id;
    std::string name;
    std::string description;
    bool is_private{true};
    bool http_push_enabled{true};
    std::string default_branch{"main"};
    std::string created_at;
    std::string updated_at;
    bool storage_exists{false};
    std::string head_target;
};

struct RepositoryCreateRequest {
    std::string name;
    std::string description;
    bool is_private{true};
    bool http_push_enabled{true};
    std::string default_branch{"main"};
};

struct RepositoryUpdateRequest {
    std::optional<std::string> description;
    std::optional<bool> is_private;
    std::optional<bool> http_push_enabled;
    std::optional<std::string> default_branch;
};

struct RepositoryRef {
    std::string name;
    std::string short_name;
    std::string type;
    std::string object_id;
};

struct AccessToken {
    std::string id;
    std::string repository_id;
    std::string repository_name;
    std::string name;
    std::string scope;
    std::string token_prefix;
    std::string created_at;
    std::string expires_at;
    std::string last_used_at;
    bool revoked{false};
};

struct AccessTokenCreateRequest {
    std::string repository_id;
    std::string name;
    std::string scope{"read"};
    std::optional<std::string> expires_at;
};

struct AccessTokenCreateResult {
    AccessToken token;
    std::string secret;
};

struct TokenAuthentication {
    std::string repository_id;
    std::string repository_name;
    std::string token_id;
    std::string actor;
    std::string scope;
    bool can_read{false};
    bool can_write{false};
};

struct RepositoryEvent {
    std::int64_t id{0};
    std::string repository_id;
    std::string repository_name;
    std::string actor;
    std::string action;
    std::string detail;
    std::string ref_name;
    std::string old_oid;
    std::string new_oid;
    std::string happened_at;
};

enum class RepositoryError {
    invalid_name,
    invalid_branch,
    database_not_configured,
    database_unavailable,
    database_error,
    already_exists,
    not_found,
    storage_conflict,
    filesystem_error,
    git_failed,
};

class RepositoryException : public std::runtime_error {
  public:
    RepositoryException(RepositoryError code, std::string message);

    [[nodiscard]] RepositoryError code() const noexcept;

  private:
    RepositoryError code_;
};

[[nodiscard]] bool is_valid_repository_name(std::string_view name);
[[nodiscard]] bool is_valid_branch_name(std::string_view name);
[[nodiscard]] bool token_scope_allows(std::string_view scope, bool require_write);
[[nodiscard]] std::filesystem::path repository_path(
    const std::filesystem::path& git_root,
    std::string_view repository_name);
[[nodiscard]] std::vector<RepositoryRef> list_repository_refs(const std::filesystem::path& repo_path);

class RepositoryService {
  public:
    RepositoryService(std::string database_url, std::filesystem::path blob_root);

    [[nodiscard]] std::filesystem::path git_root() const;
    [[nodiscard]] std::vector<Repository> list() const;
    [[nodiscard]] std::optional<Repository> find_by_id(const std::string& id) const;
    [[nodiscard]] std::optional<Repository> find_by_name(const std::string& name) const;

    Repository create(const RepositoryCreateRequest& request) const;
    std::optional<Repository> update(const std::string& id, const RepositoryUpdateRequest& request) const;
    std::optional<Repository> repair_storage(const std::string& id) const;
    bool remove(const std::string& id) const;
    [[nodiscard]] std::vector<RepositoryRef> refs(const std::string& id) const;

    [[nodiscard]] std::vector<AccessToken> access_tokens(const std::string& repository_id) const;
    AccessTokenCreateResult create_access_token(const AccessTokenCreateRequest& request) const;
    bool revoke_access_token(const std::string& repository_id, const std::string& token_id) const;
    [[nodiscard]] std::optional<TokenAuthentication> authenticate_token(
        const std::string& repository_name,
        std::string_view secret,
        bool require_write) const;

    void record_event(
        const std::string& repository_id,
        const std::string& actor,
        const std::string& action,
        const std::string& detail = {},
        const std::string& ref_name = {},
        const std::string& old_oid = {},
        const std::string& new_oid = {}) const;
    [[nodiscard]] std::vector<RepositoryEvent> events(const std::string& repository_id, std::size_t limit = 100) const;

  private:
    std::string database_url_;
    std::filesystem::path blob_root_;
};

}  // namespace nexus::vcs
