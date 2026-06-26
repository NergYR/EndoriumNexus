#include "nexus/vcs/repository.hpp"

#include <openssl/rand.h>
#include <openssl/sha.h>

#include <libpq-fe.h>

#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <limits>
#include <optional>
#include <sstream>
#include <system_error>
#include <thread>
#include <utility>

namespace nexus::vcs {

namespace {

class PgConnection {
  public:
    explicit PgConnection(const std::string& connection_string) {
        if (connection_string.empty()) {
            throw RepositoryException(
                RepositoryError::database_not_configured,
                "database url is not configured");
        }

        connection_ = PQconnectdb(connection_string.c_str());
        if (PQstatus(connection_) != CONNECTION_OK) {
            const std::string error = PQerrorMessage(connection_);
            PQfinish(connection_);
            connection_ = nullptr;
            throw RepositoryException(
                RepositoryError::database_unavailable,
                error.empty() ? "database connection failed" : error);
        }
    }

    PgConnection(const PgConnection&) = delete;
    PgConnection& operator=(const PgConnection&) = delete;

    ~PgConnection() {
        if (connection_ != nullptr) {
            PQfinish(connection_);
        }
    }

    [[nodiscard]] PGconn* get() const {
        return connection_;
    }

  private:
    PGconn* connection_{nullptr};
};

class PgResult {
  public:
    explicit PgResult(PGresult* result)
        : result_(result) {}

    PgResult(const PgResult&) = delete;
    PgResult& operator=(const PgResult&) = delete;

    PgResult(PgResult&& other) noexcept
        : result_(std::exchange(other.result_, nullptr)) {}

    PgResult& operator=(PgResult&& other) noexcept {
        if (this != &other) {
            if (result_ != nullptr) {
                PQclear(result_);
            }
            result_ = std::exchange(other.result_, nullptr);
        }
        return *this;
    }

    ~PgResult() {
        if (result_ != nullptr) {
            PQclear(result_);
        }
    }

    [[nodiscard]] PGresult* get() const {
        return result_;
    }

  private:
    PGresult* result_{nullptr};
};

[[nodiscard]] std::string pg_error(PGconn* connection, PGresult* result) {
    const char* result_error = result != nullptr ? PQresultErrorMessage(result) : nullptr;
    if (result_error != nullptr && std::strlen(result_error) > 0) {
        return result_error;
    }

    const char* connection_error = connection != nullptr ? PQerrorMessage(connection) : nullptr;
    if (connection_error != nullptr && std::strlen(connection_error) > 0) {
        return connection_error;
    }

    return "database operation failed";
}

[[nodiscard]] bool is_unique_violation(PGresult* result) {
    const char* state = PQresultErrorField(result, PG_DIAG_SQLSTATE);
    return state != nullptr && std::string_view(state) == "23505";
}

[[nodiscard]] std::string field(PGresult* result, int row, int column) {
    if (PQgetisnull(result, row, column) != 0) {
        return {};
    }
    return PQgetvalue(result, row, column);
}

[[nodiscard]] bool bool_field(PGresult* result, int row, int column) {
    return !PQgetisnull(result, row, column) && std::string_view(PQgetvalue(result, row, column)) == "t";
}

[[nodiscard]] AccessToken map_access_token(PGresult* result, int row) {
    AccessToken token;
    token.id = field(result, row, 0);
    token.repository_id = field(result, row, 1);
    token.repository_name = field(result, row, 2);
    token.name = field(result, row, 3);
    token.scope = field(result, row, 4);
    token.token_prefix = field(result, row, 5);
    token.created_at = field(result, row, 6);
    token.expires_at = field(result, row, 7);
    token.last_used_at = field(result, row, 8);
    token.revoked = bool_field(result, row, 9);
    return token;
}

[[nodiscard]] RepositoryEvent map_event(PGresult* result, int row) {
    RepositoryEvent event;
    try {
        event.id = static_cast<std::int64_t>(std::stoll(field(result, row, 0)));
    } catch (...) {
        event.id = 0;
    }
    event.repository_id = field(result, row, 1);
    event.repository_name = field(result, row, 2);
    event.actor = field(result, row, 3);
    event.action = field(result, row, 4);
    event.detail = field(result, row, 5);
    event.ref_name = field(result, row, 6);
    event.old_oid = field(result, row, 7);
    event.new_oid = field(result, row, 8);
    event.happened_at = field(result, row, 9);
    return event;
}

[[nodiscard]] Repository map_repository(PGresult* result, int row, const std::filesystem::path& git_root) {
    Repository repository;
    repository.id = field(result, row, 0);
    repository.name = field(result, row, 1);
    repository.description = field(result, row, 2);
    repository.is_private = bool_field(result, row, 3);
    repository.http_push_enabled = bool_field(result, row, 4);
    repository.default_branch = field(result, row, 5);
    repository.created_at = field(result, row, 6);
    repository.updated_at = field(result, row, 7);

    const auto path = repository_path(git_root, repository.name);
    repository.storage_exists = std::filesystem::is_directory(path) &&
        std::filesystem::exists(path / "HEAD") &&
        std::filesystem::is_directory(path / "objects") &&
        std::filesystem::is_directory(path / "refs");

    std::ifstream head(path / "HEAD");
    if (head.is_open()) {
        std::getline(head, repository.head_target);
    }

    return repository;
}

[[nodiscard]] const char* select_sql() {
    return R"SQL(
        select
            id::text,
            name,
            coalesce(description, ''),
            is_private,
            http_push_enabled,
            default_branch,
            created_at::text,
            updated_at::text
        from vcs_repositories
    )SQL";
}

[[nodiscard]] bool is_word_character(char value) {
    const auto character = static_cast<unsigned char>(value);
    return std::isalnum(character) != 0 || value == '-' || value == '_' || value == '.';
}

[[nodiscard]] bool has_suffix(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size() &&
        value.substr(value.size() - suffix.size()) == suffix;
}

[[nodiscard]] bool contains(std::string_view value, std::string_view needle) {
    return value.find(needle) != std::string_view::npos;
}

[[nodiscard]] std::string hex_bytes(const unsigned char* data, std::size_t size) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');
    for (std::size_t index = 0; index < size; ++index) {
        output << std::setw(2) << static_cast<unsigned int>(data[index]);
    }
    return output.str();
}

[[nodiscard]] std::string sha256_hex(std::string_view value) {
    unsigned char digest[SHA256_DIGEST_LENGTH]{};
    SHA256(
        reinterpret_cast<const unsigned char*>(value.data()),
        value.size(),
        digest);
    return hex_bytes(digest, sizeof(digest));
}

[[nodiscard]] std::string generate_secret_token() {
    std::array<unsigned char, 32> random{};
    if (RAND_bytes(random.data(), static_cast<int>(random.size())) != 1) {
        throw RepositoryException(RepositoryError::database_error, "unable to generate access token");
    }
    return "nxgit_" + hex_bytes(random.data(), random.size());
}

[[nodiscard]] std::string shell_quote(const std::string& value) {
    std::string output = "'";
    for (const char character : value) {
        if (character == '\'') {
            output += "'\\''";
        } else {
            output.push_back(character);
        }
    }
    output.push_back('\'');
    return output;
}

[[nodiscard]] std::string read_all_fd(int fd) {
    std::string output;
    std::array<char, 8192> buffer{};
    while (true) {
        const ssize_t count = ::read(fd, buffer.data(), buffer.size());
        if (count > 0) {
            output.append(buffer.data(), static_cast<std::size_t>(count));
            continue;
        }
        if (count == 0) {
            break;
        }
        if (errno == EINTR) {
            continue;
        }
        break;
    }
    return output;
}

void run_git_execvp(const std::vector<std::string>& args, bool allow_failure = false) {
    std::vector<std::string> storage;
    storage.reserve(args.size() + 1);
    storage.push_back("git");
    // Operate on the bare repositories Nexus owns even when the host hardens git
    // with safe.bareRepository=explicit (otherwise ref/clone operations fail).
    storage.push_back("-c");
    storage.push_back("safe.bareRepository=all");
    storage.insert(storage.end(), args.begin(), args.end());

    std::vector<char*> argv;
    argv.reserve(storage.size() + 1);
    for (auto& item : storage) {
        argv.push_back(item.data());
    }
    argv.push_back(nullptr);

    const pid_t pid = ::fork();
    if (pid < 0) {
        throw RepositoryException(
            RepositoryError::git_failed,
            std::string("fork failed: ") + std::strerror(errno));
    }

    if (pid == 0) {
        ::execvp("git", argv.data());
        _exit(127);
    }

    int status = 0;
    if (::waitpid(pid, &status, 0) != pid) {
        throw RepositoryException(
            RepositoryError::git_failed,
            std::string("waitpid failed: ") + std::strerror(errno));
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return;
    }

    if (allow_failure) {
        return;
    }

    throw RepositoryException(RepositoryError::git_failed, "git command failed");
}

[[nodiscard]] std::string run_git_capture(const std::vector<std::string>& args, bool allow_failure = false) {
    std::vector<std::string> storage;
    storage.reserve(args.size() + 1);
    storage.push_back("git");
    // Operate on the bare repositories Nexus owns even when the host hardens git
    // with safe.bareRepository=explicit (otherwise ref/clone operations fail).
    storage.push_back("-c");
    storage.push_back("safe.bareRepository=all");
    storage.insert(storage.end(), args.begin(), args.end());

    std::vector<char*> argv;
    argv.reserve(storage.size() + 1);
    for (auto& item : storage) {
        argv.push_back(item.data());
    }
    argv.push_back(nullptr);

    int stdout_pipe[2]{-1, -1};
    int stderr_pipe[2]{-1, -1};
    if (::pipe(stdout_pipe) != 0 || ::pipe(stderr_pipe) != 0) {
        if (stdout_pipe[0] >= 0) {
            ::close(stdout_pipe[0]);
        }
        if (stdout_pipe[1] >= 0) {
            ::close(stdout_pipe[1]);
        }
        if (stderr_pipe[0] >= 0) {
            ::close(stderr_pipe[0]);
        }
        if (stderr_pipe[1] >= 0) {
            ::close(stderr_pipe[1]);
        }
        throw RepositoryException(RepositoryError::git_failed, "unable to create git pipes");
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(stdout_pipe[0]);
        ::close(stdout_pipe[1]);
        ::close(stderr_pipe[0]);
        ::close(stderr_pipe[1]);
        throw RepositoryException(
            RepositoryError::git_failed,
            std::string("fork failed: ") + std::strerror(errno));
    }

    if (pid == 0) {
        ::dup2(stdout_pipe[1], STDOUT_FILENO);
        ::dup2(stderr_pipe[1], STDERR_FILENO);
        ::close(stdout_pipe[0]);
        ::close(stdout_pipe[1]);
        ::close(stderr_pipe[0]);
        ::close(stderr_pipe[1]);
        ::execvp("git", argv.data());
        _exit(127);
    }

    ::close(stdout_pipe[1]);
    ::close(stderr_pipe[1]);
    std::string stderr_text;
    std::thread stderr_reader([&]() {
        stderr_text = read_all_fd(stderr_pipe[0]);
    });
    const std::string stdout_text = read_all_fd(stdout_pipe[0]);
    ::close(stdout_pipe[0]);
    stderr_reader.join();
    ::close(stderr_pipe[0]);

    int status = 0;
    if (::waitpid(pid, &status, 0) != pid) {
        throw RepositoryException(
            RepositoryError::git_failed,
            std::string("waitpid failed: ") + std::strerror(errno));
    }

    if (WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        return stdout_text;
    }

    if (allow_failure) {
        return stdout_text;
    }

    throw RepositoryException(
        RepositoryError::git_failed,
        stderr_text.empty() ? "git command failed" : stderr_text);
}

void write_description(const std::filesystem::path& repo_path, const std::string& description) {
    std::ofstream output(repo_path / "description", std::ios::trunc);
    if (!output.is_open()) {
        throw RepositoryException(
            RepositoryError::filesystem_error,
            "unable to write git repository description");
    }
    output << (description.empty() ? "Endorium Nexus Git repository" : description) << '\n';
}

void install_post_receive_hook(const std::filesystem::path& repo_path) {
    const auto hooks_dir = repo_path / "hooks";
    std::error_code error_code;
    std::filesystem::create_directories(hooks_dir, error_code);
    if (error_code) {
        throw RepositoryException(
            RepositoryError::filesystem_error,
            "unable to create git hooks directory: " + error_code.message());
    }

    const auto hook_path = hooks_dir / "post-receive";
    const auto log_path = (repo_path / "nexus-events.log").string();
    std::ofstream output(hook_path, std::ios::trunc);
    if (!output.is_open()) {
        throw RepositoryException(
            RepositoryError::filesystem_error,
            "unable to write git post-receive hook");
    }

    output << "#!/usr/bin/env sh\n";
    output << "log=" << shell_quote(log_path) << "\n";
    output << "while read old new ref; do\n";
    output << "  printf '%s\\t%s\\t%s\\t%s\\n' \"$(date -u +%Y-%m-%dT%H:%M:%SZ)\" \"$old\" \"$new\" \"$ref\" >> \"$log\"\n";
    output << "done\n";
    output.close();

    std::filesystem::permissions(
        hook_path,
        std::filesystem::perms::owner_exec | std::filesystem::perms::group_exec |
            std::filesystem::perms::others_exec,
        std::filesystem::perm_options::add,
        error_code);
    if (error_code) {
        throw RepositoryException(
            RepositoryError::filesystem_error,
            "unable to mark git post-receive hook executable: " + error_code.message());
    }
}

void configure_repository_storage(
    const std::filesystem::path& repo_path,
    const std::string& default_branch,
    bool http_push_enabled,
    const std::string& description) {
    run_git_execvp({"-C", repo_path.string(), "symbolic-ref", "HEAD", "refs/heads/" + default_branch});
    run_git_execvp({"-C", repo_path.string(), "config", "--unset-all", "http.receivepack"}, true);
    if (!http_push_enabled) {
        run_git_execvp({"-C", repo_path.string(), "config", "http.receivepack", "false"});
    }
    write_description(repo_path, description);
    install_post_receive_hook(repo_path);
}

void create_repository_storage(
    const std::filesystem::path& repo_path,
    const std::string& default_branch,
    bool http_push_enabled,
    const std::string& description) {
    std::error_code error_code;
    std::filesystem::create_directories(repo_path.parent_path(), error_code);
    if (error_code) {
        throw RepositoryException(
            RepositoryError::filesystem_error,
            "unable to create git root: " + error_code.message());
    }

    if (std::filesystem::exists(repo_path)) {
        throw RepositoryException(
            RepositoryError::storage_conflict,
            "git repository storage already exists");
    }

    run_git_execvp({"init", "--quiet", "--bare", "--initial-branch", default_branch, repo_path.string()});
    configure_repository_storage(repo_path, default_branch, http_push_enabled, description);
}

[[nodiscard]] PgResult exec_params(
    PGconn* connection,
    const std::string& sql,
    const std::vector<const char*>& values) {
    return PgResult(PQexecParams(
        connection,
        sql.c_str(),
        static_cast<int>(values.size()),
        nullptr,
        values.empty() ? nullptr : values.data(),
        nullptr,
        nullptr,
        0));
}

}  // namespace

RepositoryException::RepositoryException(RepositoryError code, std::string message)
    : std::runtime_error(std::move(message)),
      code_(code) {}

RepositoryError RepositoryException::code() const noexcept {
    return code_;
}

bool is_valid_repository_name(std::string_view name) {
    if (name.empty() || name.size() > 96) {
        return false;
    }

    if (!std::isalnum(static_cast<unsigned char>(name.front())) ||
        !std::isalnum(static_cast<unsigned char>(name.back()))) {
        return false;
    }

    if (contains(name, "..") || contains(name, ".git") || has_suffix(name, ".lock")) {
        return false;
    }

    return std::all_of(name.begin(), name.end(), is_word_character);
}

bool is_valid_branch_name(std::string_view name) {
    if (name.empty() || name.size() > 128) {
        return false;
    }

    if (name.front() == '/' || name.back() == '/' || name.back() == '.') {
        return false;
    }

    if (contains(name, "..") || contains(name, "@{") || contains(name, "//") || has_suffix(name, ".lock")) {
        return false;
    }

    for (const char character : name) {
        const auto byte = static_cast<unsigned char>(character);
        if (byte < 33 || character == '~' || character == '^' || character == ':' ||
            character == '?' || character == '*' || character == '[' || character == '\\') {
            return false;
        }
    }

    return true;
}

bool token_scope_allows(std::string_view scope, bool require_write) {
    if (require_write) {
        return scope == "write";
    }
    return scope == "read" || scope == "write";
}

std::filesystem::path repository_path(
    const std::filesystem::path& git_root,
    std::string_view repository_name) {
    return git_root / (std::string(repository_name) + ".git");
}

std::vector<RepositoryRef> list_repository_refs(const std::filesystem::path& repo_path) {
    const auto output = run_git_capture({
        "-C",
        repo_path.string(),
        "for-each-ref",
        "--format=%(objectname)%09%(refname)%09%(refname:short)",
        "refs/heads",
        "refs/tags",
    });

    std::vector<RepositoryRef> refs;
    std::istringstream stream(output);
    std::string line;
    while (std::getline(stream, line)) {
        if (line.empty()) {
            continue;
        }
        std::vector<std::string> columns;
        std::size_t cursor = 0;
        while (cursor <= line.size()) {
            const auto next = line.find('\t', cursor);
            if (next == std::string::npos) {
                columns.push_back(line.substr(cursor));
                break;
            }
            columns.push_back(line.substr(cursor, next - cursor));
            cursor = next + 1;
        }
        if (columns.size() < 3) {
            continue;
        }

        RepositoryRef ref;
        ref.object_id = columns[0];
        ref.name = columns[1];
        ref.short_name = columns[2];
        if (ref.name.rfind("refs/heads/", 0) == 0) {
            ref.type = "branch";
        } else if (ref.name.rfind("refs/tags/", 0) == 0) {
            ref.type = "tag";
        } else {
            ref.type = "ref";
        }
        refs.push_back(std::move(ref));
    }
    return refs;
}

RepositoryService::RepositoryService(std::string database_url, std::filesystem::path blob_root)
    : database_url_(std::move(database_url)),
      blob_root_(std::move(blob_root)) {}

std::filesystem::path RepositoryService::git_root() const {
    return blob_root_ / "git";
}

std::vector<Repository> RepositoryService::list() const {
    PgConnection connection(database_url_);
    const std::string sql = std::string(select_sql()) + " order by created_at desc";
    PgResult result(PQexec(connection.get(), sql.c_str()));
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(
            RepositoryError::database_error,
            pg_error(connection.get(), result.get()));
    }

    std::vector<Repository> repositories;
    repositories.reserve(static_cast<std::size_t>(PQntuples(result.get())));
    for (int row = 0; row < PQntuples(result.get()); ++row) {
        repositories.push_back(map_repository(result.get(), row, git_root()));
    }
    return repositories;
}

std::optional<Repository> RepositoryService::find_by_id(const std::string& id) const {
    PgConnection connection(database_url_);
    const std::string sql = std::string(select_sql()) + " where id = $1";
    const char* values[] = {id.c_str()};
    PgResult result(PQexecParams(connection.get(), sql.c_str(), 1, nullptr, values, nullptr, nullptr, 0));
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(
            RepositoryError::database_error,
            pg_error(connection.get(), result.get()));
    }

    if (PQntuples(result.get()) == 0) {
        return std::nullopt;
    }
    return map_repository(result.get(), 0, git_root());
}

std::optional<Repository> RepositoryService::find_by_name(const std::string& name) const {
    PgConnection connection(database_url_);
    const std::string sql = std::string(select_sql()) + " where name = $1";
    const char* values[] = {name.c_str()};
    PgResult result(PQexecParams(connection.get(), sql.c_str(), 1, nullptr, values, nullptr, nullptr, 0));
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(
            RepositoryError::database_error,
            pg_error(connection.get(), result.get()));
    }

    if (PQntuples(result.get()) == 0) {
        return std::nullopt;
    }
    return map_repository(result.get(), 0, git_root());
}

Repository RepositoryService::create(const RepositoryCreateRequest& request) const {
    if (!is_valid_repository_name(request.name)) {
        throw RepositoryException(
            RepositoryError::invalid_name,
            "repository name must use letters, digits, dot, dash or underscore and omit .git");
    }

    if (!is_valid_branch_name(request.default_branch)) {
        throw RepositoryException(RepositoryError::invalid_branch, "default branch name is invalid");
    }

    const auto repo_path = repository_path(git_root(), request.name);
    if (std::filesystem::exists(repo_path)) {
        throw RepositoryException(
            RepositoryError::storage_conflict,
            "git repository storage already exists");
    }

    PgConnection connection(database_url_);
    const char* values[] = {
        request.name.c_str(),
        request.description.c_str(),
        request.is_private ? "true" : "false",
        request.http_push_enabled ? "true" : "false",
        request.default_branch.c_str(),
    };

    const std::string sql = R"SQL(
        insert into vcs_repositories (name, description, is_private, http_push_enabled, default_branch)
        values ($1, $2, $3, $4, $5)
        returning id::text, name, coalesce(description, ''), is_private, http_push_enabled, default_branch, created_at::text, updated_at::text
    )SQL";
    PgResult result(PQexecParams(connection.get(), sql.c_str(), 5, nullptr, values, nullptr, nullptr, 0));
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        if (is_unique_violation(result.get())) {
            throw RepositoryException(RepositoryError::already_exists, "repository already exists");
        }
        throw RepositoryException(
            RepositoryError::database_error,
            pg_error(connection.get(), result.get()));
    }

    try {
        create_repository_storage(
            repo_path,
            request.default_branch,
            request.http_push_enabled,
            request.description);
    } catch (...) {
        const std::string cleanup_id = field(result.get(), 0, 0);
        const char* cleanup_values[] = {cleanup_id.c_str()};
        PgResult cleanup(PQexecParams(
            connection.get(),
            "delete from vcs_repositories where id = $1",
            1,
            nullptr,
            cleanup_values,
            nullptr,
            nullptr,
            0));
        std::error_code ignored;
        std::filesystem::remove_all(repo_path, ignored);
        throw;
    }

    return map_repository(result.get(), 0, git_root());
}

std::optional<Repository> RepositoryService::update(
    const std::string& id,
    const RepositoryUpdateRequest& request) const {
    if (request.default_branch.has_value() && !is_valid_branch_name(*request.default_branch)) {
        throw RepositoryException(RepositoryError::invalid_branch, "default branch name is invalid");
    }

    const std::string private_value = request.is_private.has_value()
        ? (*request.is_private ? "true" : "false")
        : "";
    const std::string push_value = request.http_push_enabled.has_value()
        ? (*request.http_push_enabled ? "true" : "false")
        : "";

    const char* values[] = {
        id.c_str(),
        request.description.has_value() ? request.description->c_str() : nullptr,
        request.is_private.has_value() ? private_value.c_str() : nullptr,
        request.http_push_enabled.has_value() ? push_value.c_str() : nullptr,
        request.default_branch.has_value() ? request.default_branch->c_str() : nullptr,
    };

    PgConnection connection(database_url_);
    const std::string sql = R"SQL(
        update vcs_repositories
        set
            description = coalesce($2, description),
            is_private = coalesce($3::boolean, is_private),
            http_push_enabled = coalesce($4::boolean, http_push_enabled),
            default_branch = coalesce($5, default_branch),
            updated_at = now()
        where id = $1
        returning id::text, name, coalesce(description, ''), is_private, http_push_enabled, default_branch, created_at::text, updated_at::text
    )SQL";
    PgResult result(PQexecParams(connection.get(), sql.c_str(), 5, nullptr, values, nullptr, nullptr, 0));
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(
            RepositoryError::database_error,
            pg_error(connection.get(), result.get()));
    }

    if (PQntuples(result.get()) == 0) {
        return std::nullopt;
    }

    Repository repository = map_repository(result.get(), 0, git_root());
    const auto path = repository_path(git_root(), repository.name);
    if (repository.storage_exists) {
        configure_repository_storage(
            path,
            repository.default_branch,
            repository.http_push_enabled,
            repository.description);
        repository = map_repository(result.get(), 0, git_root());
    }
    return repository;
}

std::optional<Repository> RepositoryService::repair_storage(const std::string& id) const {
    auto repository = find_by_id(id);
    if (!repository.has_value()) {
        return std::nullopt;
    }

    const auto path = repository_path(git_root(), repository->name);
    if (repository->storage_exists) {
        configure_repository_storage(
            path,
            repository->default_branch,
            repository->http_push_enabled,
            repository->description);
        return find_by_id(id);
    }

    create_repository_storage(
        path,
        repository->default_branch,
        repository->http_push_enabled,
        repository->description);
    return find_by_id(id);
}

bool RepositoryService::remove(const std::string& id) const {
    const auto repository = find_by_id(id);
    if (!repository.has_value()) {
        return false;
    }

    const auto path = repository_path(git_root(), repository->name);
    std::error_code error_code;
    std::filesystem::remove_all(path, error_code);
    if (error_code) {
        throw RepositoryException(
            RepositoryError::filesystem_error,
            "unable to remove git repository storage: " + error_code.message());
    }

    PgConnection connection(database_url_);
    const char* values[] = {id.c_str()};
    PgResult result(PQexecParams(
        connection.get(),
        "delete from vcs_repositories where id = $1",
        1,
        nullptr,
        values,
        nullptr,
        nullptr,
        0));
    if (PQresultStatus(result.get()) != PGRES_COMMAND_OK) {
        throw RepositoryException(
            RepositoryError::database_error,
            pg_error(connection.get(), result.get()));
    }

    return true;
}

std::vector<RepositoryRef> RepositoryService::refs(const std::string& id) const {
    auto repository = find_by_id(id);
    if (!repository.has_value()) {
        throw RepositoryException(RepositoryError::not_found, "repository not found");
    }
    if (!repository->storage_exists) {
        repository = repair_storage(id);
        if (!repository.has_value() || !repository->storage_exists) {
            throw RepositoryException(RepositoryError::filesystem_error, "repository storage is unavailable");
        }
    }

    return list_repository_refs(repository_path(git_root(), repository->name));
}

std::vector<AccessToken> RepositoryService::access_tokens(const std::string& repository_id) const {
    PgConnection connection(database_url_);
    const char* values[] = {repository_id.c_str()};
    const std::string sql = R"SQL(
        select
            t.id::text,
            t.repository_id::text,
            r.name,
            t.name,
            t.scope,
            t.token_prefix,
            t.created_at::text,
            coalesce(t.expires_at::text, ''),
            coalesce(t.last_used_at::text, ''),
            t.revoked
        from vcs_access_tokens t
        join vcs_repositories r on r.id = t.repository_id
        where t.repository_id = $1
        order by t.created_at desc
    )SQL";
    PgResult result(PQexecParams(connection.get(), sql.c_str(), 1, nullptr, values, nullptr, nullptr, 0));
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), result.get()));
    }

    std::vector<AccessToken> tokens;
    tokens.reserve(static_cast<std::size_t>(PQntuples(result.get())));
    for (int row = 0; row < PQntuples(result.get()); ++row) {
        tokens.push_back(map_access_token(result.get(), row));
    }
    return tokens;
}

AccessTokenCreateResult RepositoryService::create_access_token(const AccessTokenCreateRequest& request) const {
    if (request.repository_id.empty()) {
        throw RepositoryException(RepositoryError::not_found, "repository not found");
    }
    if (request.name.empty() || request.name.size() > 96 || !token_scope_allows(request.scope, false)) {
        throw RepositoryException(RepositoryError::invalid_name, "token name or scope is invalid");
    }

    const auto repository = find_by_id(request.repository_id);
    if (!repository.has_value()) {
        throw RepositoryException(RepositoryError::not_found, "repository not found");
    }

    const auto secret = generate_secret_token();
    const auto token_hash = sha256_hex(secret);
    const auto token_prefix = secret.substr(0, std::min<std::size_t>(18, secret.size()));

    PgConnection connection(database_url_);
    const char* values[] = {
        request.repository_id.c_str(),
        request.name.c_str(),
        token_hash.c_str(),
        token_prefix.c_str(),
        request.scope.c_str(),
        request.expires_at.has_value() && !request.expires_at->empty() ? request.expires_at->c_str() : nullptr,
    };
    const std::string sql = R"SQL(
        insert into vcs_access_tokens(repository_id, name, token_hash, token_prefix, scope, expires_at)
        values ($1, $2, $3, $4, $5, nullif($6, '')::timestamptz)
        returning
            id::text,
            repository_id::text,
            (select name from vcs_repositories where id = vcs_access_tokens.repository_id),
            name,
            scope,
            token_prefix,
            created_at::text,
            coalesce(expires_at::text, ''),
            coalesce(last_used_at::text, ''),
            revoked
    )SQL";
    PgResult result(PQexecParams(connection.get(), sql.c_str(), 6, nullptr, values, nullptr, nullptr, 0));
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), result.get()));
    }

    AccessTokenCreateResult created;
    created.token = map_access_token(result.get(), 0);
    created.secret = secret;
    return created;
}

bool RepositoryService::revoke_access_token(const std::string& repository_id, const std::string& token_id) const {
    PgConnection connection(database_url_);
    const char* values[] = {repository_id.c_str(), token_id.c_str()};
    PgResult result(PQexecParams(
        connection.get(),
        "update vcs_access_tokens set revoked = true where repository_id = $1 and id = $2",
        2,
        nullptr,
        values,
        nullptr,
        nullptr,
        0));
    if (PQresultStatus(result.get()) != PGRES_COMMAND_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), result.get()));
    }
    return std::string_view(PQcmdTuples(result.get())) != "0";
}

std::optional<TokenAuthentication> RepositoryService::authenticate_token(
    const std::string& repository_name,
    std::string_view secret,
    bool require_write) const {
    if (secret.empty() || !is_valid_repository_name(repository_name)) {
        return std::nullopt;
    }

    const auto token_hash = sha256_hex(secret);
    PgConnection connection(database_url_);
    const char* values[] = {
        repository_name.c_str(),
        token_hash.c_str(),
        require_write ? "write" : "read",
    };
    const std::string sql = R"SQL(
        select
            r.id::text,
            r.name,
            t.id::text,
            t.name,
            t.scope
        from vcs_access_tokens t
        join vcs_repositories r on r.id = t.repository_id
        where r.name = $1
          and t.token_hash = $2
          and t.revoked = false
          and (t.expires_at is null or t.expires_at > now())
          and (case when $3 = 'write' then t.scope = 'write' else t.scope in ('read', 'write') end)
        limit 1
    )SQL";
    PgResult result(PQexecParams(connection.get(), sql.c_str(), 3, nullptr, values, nullptr, nullptr, 0));
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), result.get()));
    }
    if (PQntuples(result.get()) == 0) {
        return std::nullopt;
    }

    TokenAuthentication authentication;
    authentication.repository_id = field(result.get(), 0, 0);
    authentication.repository_name = field(result.get(), 0, 1);
    authentication.token_id = field(result.get(), 0, 2);
    authentication.actor = "git:" + field(result.get(), 0, 3);
    authentication.scope = field(result.get(), 0, 4);
    authentication.can_read = true;
    authentication.can_write = authentication.scope == "write";

    const char* update_values[] = {authentication.token_id.c_str()};
    PgResult update(PQexecParams(
        connection.get(),
        "update vcs_access_tokens set last_used_at = now() where id = $1",
        1,
        nullptr,
        update_values,
        nullptr,
        nullptr,
        0));
    if (PQresultStatus(update.get()) != PGRES_COMMAND_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), update.get()));
    }

    return authentication;
}

void RepositoryService::record_event(
    const std::string& repository_id,
    const std::string& actor,
    const std::string& action,
    const std::string& detail,
    const std::string& ref_name,
    const std::string& old_oid,
    const std::string& new_oid) const {
    if (repository_id.empty() || actor.empty() || action.empty()) {
        return;
    }

    PgConnection connection(database_url_);
    const char* values[] = {
        repository_id.c_str(),
        actor.c_str(),
        action.c_str(),
        detail.c_str(),
        ref_name.c_str(),
        old_oid.c_str(),
        new_oid.c_str(),
    };
    const std::string sql = R"SQL(
        insert into vcs_events(repository_id, actor, action, detail, ref_name, old_oid, new_oid)
        values ($1, $2, $3, $4, $5, $6, $7)
    )SQL";
    PgResult result(PQexecParams(connection.get(), sql.c_str(), 7, nullptr, values, nullptr, nullptr, 0));
    if (PQresultStatus(result.get()) != PGRES_COMMAND_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), result.get()));
    }
}

std::vector<RepositoryEvent> RepositoryService::events(const std::string& repository_id, std::size_t limit) const {
    const auto repository = find_by_id(repository_id);
    if (!repository.has_value()) {
        throw RepositoryException(RepositoryError::not_found, "repository not found");
    }

    const auto bounded_limit = std::min<std::size_t>(limit == 0 ? 100 : limit, 500);
    const auto limit_text = std::to_string(bounded_limit);
    PgConnection connection(database_url_);
    const char* values[] = {repository_id.c_str(), limit_text.c_str()};
    const std::string sql = R"SQL(
        select
            e.id::text,
            e.repository_id::text,
            r.name,
            e.actor,
            e.action,
            e.detail,
            e.ref_name,
            e.old_oid,
            e.new_oid,
            e.happened_at::text
        from vcs_events e
        join vcs_repositories r on r.id = e.repository_id
        where e.repository_id = $1
        order by e.happened_at desc, e.id desc
        limit $2::int
    )SQL";
    PgResult result(PQexecParams(connection.get(), sql.c_str(), 2, nullptr, values, nullptr, nullptr, 0));
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), result.get()));
    }

    std::vector<RepositoryEvent> output;
    output.reserve(static_cast<std::size_t>(PQntuples(result.get())));
    for (int row = 0; row < PQntuples(result.get()); ++row) {
        output.push_back(map_event(result.get(), row));
    }

    const auto hook_log = repository_path(git_root(), repository->name) / "nexus-events.log";
    std::ifstream input(hook_log);
    if (input.is_open()) {
        std::vector<RepositoryEvent> hook_events;
        std::string line;
        while (std::getline(input, line)) {
            if (line.empty()) {
                continue;
            }
            std::array<std::string, 4> columns{};
            std::size_t cursor = 0;
            for (std::size_t index = 0; index < columns.size(); ++index) {
                const auto next = line.find('\t', cursor);
                if (next == std::string::npos) {
                    columns[index] = line.substr(cursor);
                    break;
                }
                columns[index] = line.substr(cursor, next - cursor);
                cursor = next + 1;
            }

            RepositoryEvent event;
            event.repository_id = repository->id;
            event.repository_name = repository->name;
            event.actor = "git-hook";
            event.action = "push.ref";
            event.detail = "post-receive";
            event.happened_at = columns[0];
            event.old_oid = columns[1];
            event.new_oid = columns[2];
            event.ref_name = columns[3];
            hook_events.push_back(std::move(event));
        }
        std::reverse(hook_events.begin(), hook_events.end());
        for (auto& event : hook_events) {
            if (output.size() >= bounded_limit) {
                break;
            }
            output.push_back(std::move(event));
        }
    }

    return output;
}

}  // namespace nexus::vcs
