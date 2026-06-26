#include "nexus/apt/repository.hpp"

#include "nexus/protocol/repo.hpp"

#include <json/json.h>
#include <openssl/sha.h>

#include <libpq-fe.h>

#include <sys/wait.h>
#include <unistd.h>

#include <algorithm>
#include <array>
#include <cerrno>
#include <cctype>
#include <chrono>
#include <cstring>
#include <fstream>
#include <iomanip>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <sstream>
#include <system_error>
#include <thread>
#include <utility>

namespace nexus::apt {

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

struct ProcessResult {
    int exit_code{0};
    std::string stdout_text;
    std::string stderr_text;
};

struct SigningKey {
    std::string fingerprint;
    std::string public_key;
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

[[nodiscard]] std::string field(PGresult* result, int row, int column) {
    if (PQgetisnull(result, row, column) != 0) {
        return {};
    }
    return PQgetvalue(result, row, column);
}

[[nodiscard]] nexus::core::AptPackage map_package(PGresult* result, int row) {
    nexus::core::AptPackage package;
    package.id = field(result, row, 0);
    package.component = field(result, row, 2);
    package.name = field(result, row, 3);
    package.version = field(result, row, 4);
    package.architecture = field(result, row, 5);
    package.filename = field(result, row, 6);
    package.storage_path = field(result, row, 7);
    package.sha256 = field(result, row, 8);
    try {
        package.size = static_cast<std::size_t>(std::stoull(field(result, row, 9)));
    } catch (...) {
        package.size = 0;
    }
    package.control_json = field(result, row, 10);
    package.uploaded_by = field(result, row, 11);
    package.uploaded_at = field(result, row, 12);
    package.download_url = "/apt/" + (package.storage_path.empty() ? package.filename : package.storage_path);
    return package;
}

[[nodiscard]] const char* package_select_sql() {
    return R"SQL(
        select
            id::text,
            distribution,
            component,
            name,
            version,
            architecture,
            filename,
            coalesce(storage_path, filename),
            sha256,
            size::text,
            coalesce(control_json, '{}'::jsonb)::text,
            coalesce(uploaded_by, 'system'),
            coalesce(uploaded_at, now())::text
        from repo_packages
    )SQL";
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

[[nodiscard]] ProcessResult run_process(const std::vector<std::string>& args, bool allow_failure = false) {
    if (args.empty()) {
        throw RepositoryException(RepositoryError::tool_failed, "empty process command");
    }

    std::vector<std::string> storage(args.begin(), args.end());
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
        throw RepositoryException(RepositoryError::tool_failed, "unable to create process pipes");
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        ::close(stdout_pipe[0]);
        ::close(stdout_pipe[1]);
        ::close(stderr_pipe[0]);
        ::close(stderr_pipe[1]);
        throw RepositoryException(
            RepositoryError::tool_failed,
            std::string("fork failed: ") + std::strerror(errno));
    }

    if (pid == 0) {
        ::dup2(stdout_pipe[1], STDOUT_FILENO);
        ::dup2(stderr_pipe[1], STDERR_FILENO);
        ::close(stdout_pipe[0]);
        ::close(stdout_pipe[1]);
        ::close(stderr_pipe[0]);
        ::close(stderr_pipe[1]);
        ::execvp(argv[0], argv.data());
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
            RepositoryError::tool_failed,
            std::string("waitpid failed: ") + std::strerror(errno));
    }

    ProcessResult result;
    result.stdout_text = stdout_text;
    result.stderr_text = stderr_text;
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;

    if (result.exit_code != 0 && !allow_failure) {
        throw RepositoryException(
            RepositoryError::tool_failed,
            result.stderr_text.empty() ? args.front() + " failed" : result.stderr_text);
    }
    return result;
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

[[nodiscard]] std::string sha256_hex(const std::vector<std::uint8_t>& value) {
    unsigned char digest[SHA256_DIGEST_LENGTH]{};
    SHA256(value.data(), value.size(), digest);
    return hex_bytes(digest, sizeof(digest));
}

[[nodiscard]] bool has_suffix(std::string_view value, std::string_view suffix) {
    return value.size() >= suffix.size() &&
        value.substr(value.size() - suffix.size()) == suffix;
}

[[nodiscard]] std::string lowercase_ascii(std::string value) {
    for (char& character : value) {
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
    }
    return value;
}

[[nodiscard]] std::string trim(std::string value) {
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.front())) != 0) {
        value.erase(value.begin());
    }
    while (!value.empty() && std::isspace(static_cast<unsigned char>(value.back())) != 0) {
        value.pop_back();
    }
    return value;
}

[[nodiscard]] std::string json_escape(std::string_view value) {
    std::ostringstream output;
    for (const char character : value) {
        switch (character) {
            case '\\':
                output << "\\\\";
                break;
            case '"':
                output << "\\\"";
                break;
            case '\n':
                output << "\\n";
                break;
            case '\r':
                output << "\\r";
                break;
            case '\t':
                output << "\\t";
                break;
            default:
                output << character;
                break;
        }
    }
    return output.str();
}

[[nodiscard]] std::string fields_to_json(const std::map<std::string, std::string>& fields) {
    std::ostringstream output;
    output << "{";
    bool first = true;
    for (const auto& [key, value] : fields) {
        if (!first) {
            output << ",";
        }
        first = false;
        output << "\"" << json_escape(key) << "\":\"" << json_escape(value) << "\"";
    }
    output << "}";
    return output.str();
}

[[nodiscard]] std::map<std::string, std::string> fields_from_json(std::string_view json) {
    std::map<std::string, std::string> fields;
    if (json.empty()) {
        return fields;
    }

    Json::CharReaderBuilder builder;
    Json::Value root;
    std::string errors;
    std::istringstream input{std::string(json)};
    if (!Json::parseFromStream(builder, input, &root, &errors) || !root.isObject()) {
        return fields;
    }

    for (const auto& key : root.getMemberNames()) {
        if (root[key].isString()) {
            fields[key] = root[key].asString();
        }
    }
    return fields;
}

void write_control_field(std::ostringstream& output, const std::string& key, const std::string& value) {
    if (value.empty()) {
        return;
    }

    output << key << ": ";
    std::istringstream lines(value);
    std::string line;
    if (std::getline(lines, line)) {
        output << line << "\n";
    } else {
        output << "\n";
        return;
    }
    while (std::getline(lines, line)) {
        output << " " << line << "\n";
    }
}

[[nodiscard]] std::string control_value(
    const std::map<std::string, std::string>& fields,
    const std::string& key,
    std::string fallback = {}) {
    const auto item = fields.find(key);
    if (item != fields.end() && !item->second.empty()) {
        return item->second;
    }
    return fallback;
}

[[nodiscard]] bool synthetic_package_field(std::string_view key) {
    return key == "Package" || key == "Version" || key == "Architecture" ||
        key == "Filename" || key == "Size" || key == "SHA256" || key == "SHA1" ||
        key == "MD5sum" || key == "Section" || key == "Priority" || key == "Description" ||
        key == "Maintainer" || key == "Installed-Size" || key == "Depends" ||
        key == "Pre-Depends" || key == "Recommends" || key == "Suggests" ||
        key == "Conflicts" || key == "Breaks" || key == "Replaces" ||
        key == "Provides" || key == "Homepage";
}

[[nodiscard]] std::string sanitize_path_segment(std::string_view value) {
    std::string output;
    output.reserve(value.size());
    for (const char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if (std::isalnum(byte) != 0 || character == '.' || character == '_' ||
            character == '+' || character == '-' || character == '~' || character == ':') {
            output.push_back(character);
        } else {
            output.push_back('_');
        }
    }
    if (output.empty() || output == "." || output == "..") {
        return "pkg";
    }
    return output;
}

[[nodiscard]] std::string storage_path_for(
    const std::string& component,
    const std::string& name,
    const std::string& version,
    const std::string& architecture) {
    const auto safe_component = sanitize_path_segment(component);
    const auto safe_name = sanitize_path_segment(name);
    const auto safe_version = sanitize_path_segment(version);
    const auto safe_arch = sanitize_path_segment(architecture);
    const auto first = safe_name.empty() ? std::string{"_"} : lowercase_ascii(std::string(1, safe_name.front()));
    return "pool/" + safe_component + "/" + first + "/" + safe_name + "/" +
        safe_name + "_" + safe_version + "_" + safe_arch + ".deb";
}

[[nodiscard]] std::filesystem::path unique_temp_path(const std::filesystem::path& root, const std::string& suffix) {
    const auto now = std::chrono::steady_clock::now().time_since_epoch().count();
    return root / "tmp" / ("nexus-" + std::to_string(::getpid()) + "-" + std::to_string(now) + suffix);
}

void write_file(const std::filesystem::path& path, std::string_view content) {
    std::error_code error_code;
    std::filesystem::create_directories(path.parent_path(), error_code);
    if (error_code) {
        throw RepositoryException(
            RepositoryError::filesystem_error,
            "unable to create directory: " + error_code.message());
    }

    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output.is_open()) {
        throw RepositoryException(RepositoryError::filesystem_error, "unable to write file");
    }
    output.write(content.data(), static_cast<std::streamsize>(content.size()));
}

[[nodiscard]] std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path, std::ios::binary);
    if (!input.is_open()) {
        throw RepositoryException(RepositoryError::filesystem_error, "unable to read file");
    }
    std::ostringstream output;
    output << input.rdbuf();
    return output.str();
}

void ensure_gpg_home(const std::filesystem::path& home) {
    std::error_code error_code;
    std::filesystem::create_directories(home, error_code);
    if (error_code) {
        throw RepositoryException(
            RepositoryError::filesystem_error,
            "unable to create gpg home: " + error_code.message());
    }
    std::filesystem::permissions(
        home,
        std::filesystem::perms::owner_all,
        std::filesystem::perm_options::replace,
        error_code);
}

[[nodiscard]] std::string first_gpg_fingerprint(const std::filesystem::path& home) {
    const auto result = run_process({
        "gpg",
        "--batch",
        "--homedir",
        home.string(),
        "--with-colons",
        "--list-secret-keys",
    }, true);

    std::istringstream input(result.stdout_text);
    std::string line;
    while (std::getline(input, line)) {
        if (line.rfind("fpr:", 0) != 0) {
            continue;
        }
        std::vector<std::string> fields;
        std::size_t cursor = 0;
        while (cursor <= line.size()) {
            const auto next = line.find(':', cursor);
            if (next == std::string::npos) {
                fields.push_back(line.substr(cursor));
                break;
            }
            fields.push_back(line.substr(cursor, next - cursor));
            cursor = next + 1;
        }
        if (fields.size() > 9 && !fields[9].empty()) {
            return fields[9];
        }
    }
    return {};
}

[[nodiscard]] SigningKey ensure_signing_key(
    const std::string& database_url,
    const std::filesystem::path& state_root) {
    std::optional<SigningKey> database_key;
    {
        PgConnection connection(database_url);
        PgResult result(PQexec(
            connection.get(),
            "select fingerprint, public_key from repo_signing_keys where active = true order by created_at desc limit 1"));
        if (PQresultStatus(result.get()) == PGRES_TUPLES_OK && PQntuples(result.get()) > 0) {
            database_key = SigningKey{field(result.get(), 0, 0), field(result.get(), 0, 1)};
        }
        if (PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
            throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), result.get()));
        }
    }

    const auto home = state_root / "repo" / "gpg";
    ensure_gpg_home(home);

    auto fingerprint = first_gpg_fingerprint(home);
    if (database_key.has_value() && fingerprint == database_key->fingerprint) {
        return *database_key;
    }

    if (fingerprint.empty()) {
        const auto generated = run_process({
            "gpg",
            "--batch",
            "--homedir",
            home.string(),
            "--pinentry-mode",
            "loopback",
            "--passphrase",
            "",
            "--quick-generate-key",
            "Endorium Nexus APT <repo@endorium.local>",
            "rsa3072",
            "sign",
            "0",
        });
        (void)generated;
        fingerprint = first_gpg_fingerprint(home);
    }

    if (fingerprint.empty()) {
        throw RepositoryException(RepositoryError::tool_failed, "unable to create apt signing key");
    }

    const auto exported = run_process({
        "gpg",
        "--batch",
        "--homedir",
        home.string(),
        "--armor",
        "--export",
        fingerprint,
    }).stdout_text;

    PgConnection connection(database_url);
    const char* values[] = {fingerprint.c_str(), exported.c_str()};
    PgResult deactivate(PQexecParams(
        connection.get(),
        "update repo_signing_keys set active = false where fingerprint <> $1",
        1,
        nullptr,
        values,
        nullptr,
        nullptr,
        0));
    if (PQresultStatus(deactivate.get()) != PGRES_COMMAND_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), deactivate.get()));
    }
    PgResult result(PQexecParams(
        connection.get(),
        R"SQL(
            insert into repo_signing_keys(fingerprint, public_key, active)
            values ($1, $2, true)
            on conflict (fingerprint) do update set public_key = excluded.public_key, active = true
        )SQL",
        2,
        nullptr,
        values,
        nullptr,
        nullptr,
        0));
    if (PQresultStatus(result.get()) != PGRES_COMMAND_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), result.get()));
    }

    return {fingerprint, exported};
}

[[nodiscard]] std::string sign_release(
    const std::string& database_url,
    const std::filesystem::path& state_root,
    std::string_view release,
    bool clear_sign) {
    const auto key = ensure_signing_key(database_url, state_root);
    const auto home = state_root / "repo" / "gpg";
    const auto release_path = unique_temp_path(state_root / "repo", ".Release");
    const auto output_path = unique_temp_path(state_root / "repo", clear_sign ? ".InRelease" : ".Release.gpg");
    write_file(release_path, release);

    std::vector<std::string> args = {
        "gpg",
        "--batch",
        "--yes",
        "--homedir",
        home.string(),
        "--local-user",
        key.fingerprint,
        "--digest-algo",
        "SHA256",
        "--output",
        output_path.string(),
    };
    if (clear_sign) {
        args.push_back("--clearsign");
    } else {
        args.push_back("--armor");
        args.push_back("--detach-sign");
    }
    args.push_back(release_path.string());
    const auto signed_result = run_process(args);
    (void)signed_result;
    const auto signed_payload = read_file(output_path);

    std::error_code ignored;
    std::filesystem::remove(release_path, ignored);
    std::filesystem::remove(output_path, ignored);
    return signed_payload;
}

[[nodiscard]] bool repository_exists(
    PGconn* connection,
    const std::string& distribution,
    const std::string& component) {
    const char* values[] = {distribution.c_str(), component.c_str()};
    PgResult result(PQexecParams(
        connection,
        "select 1 from repo_repositories where distribution = $1 and component = $2 limit 1",
        2,
        nullptr,
        values,
        nullptr,
        nullptr,
        0));
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection, result.get()));
    }
    return PQntuples(result.get()) > 0;
}

}  // namespace

RepositoryException::RepositoryException(RepositoryError code, std::string message)
    : std::runtime_error(std::move(message)),
      code_(code) {}

RepositoryError RepositoryException::code() const noexcept {
    return code_;
}

bool is_valid_debian_name(std::string_view value) {
    if (value.empty() || value.size() > 128 || value.front() == '.' || value.front() == '-') {
        return false;
    }
    for (const char character : value) {
        const auto byte = static_cast<unsigned char>(character);
        if (std::isalnum(byte) == 0 && character != '.' && character != '_' &&
            character != '+' && character != '-' && character != '~') {
            return false;
        }
    }
    return true;
}

std::map<std::string, std::string> parse_control_fields(std::string_view control) {
    std::map<std::string, std::string> fields;
    std::string current_key;
    std::istringstream input{std::string(control)};
    std::string line;
    while (std::getline(input, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        if (line.empty()) {
            continue;
        }
        if ((line.front() == ' ' || line.front() == '\t') && !current_key.empty()) {
            fields[current_key] += "\n" + trim(line);
            continue;
        }
        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }
        current_key = line.substr(0, colon);
        fields[current_key] = trim(line.substr(colon + 1));
    }
    return fields;
}

std::map<std::string, std::string> extract_deb_control_fields(const std::filesystem::path& deb_path) {
    return parse_control_fields(run_process({"dpkg-deb", "--field", deb_path.string()}).stdout_text);
}

std::string render_packages_index(const std::vector<nexus::core::AptPackage>& packages) {
    std::ostringstream output;
    for (const auto& package : packages) {
        const auto control = fields_from_json(package.control_json);
        write_control_field(output, "Package", package.name);
        write_control_field(output, "Version", package.version);
        write_control_field(output, "Architecture", package.architecture);
        write_control_field(output, "Maintainer", control_value(control, "Maintainer"));
        write_control_field(output, "Installed-Size", control_value(control, "Installed-Size"));
        write_control_field(output, "Depends", control_value(control, "Depends"));
        write_control_field(output, "Pre-Depends", control_value(control, "Pre-Depends"));
        write_control_field(output, "Recommends", control_value(control, "Recommends"));
        write_control_field(output, "Suggests", control_value(control, "Suggests"));
        write_control_field(output, "Conflicts", control_value(control, "Conflicts"));
        write_control_field(output, "Breaks", control_value(control, "Breaks"));
        write_control_field(output, "Replaces", control_value(control, "Replaces"));
        write_control_field(output, "Provides", control_value(control, "Provides"));
        write_control_field(output, "Homepage", control_value(control, "Homepage"));
        write_control_field(output, "Filename", package.storage_path.empty() ? package.filename : package.storage_path);
        write_control_field(output, "Size", std::to_string(package.size));
        write_control_field(output, "SHA256", package.sha256);
        write_control_field(output, "Section", control_value(
            control,
            "Section",
            package.component.empty() ? std::string{"main"} : package.component));
        write_control_field(output, "Priority", control_value(control, "Priority", "optional"));
        write_control_field(output, "Description", control_value(
            control,
            "Description",
            package.name.empty() ? std::string{"Endorium Nexus package"} : package.name));
        for (const auto& [key, value] : control) {
            if (!synthetic_package_field(key)) {
                write_control_field(output, key, value);
            }
        }
        output << "\n";
    }
    return output.str();
}

RepositoryService::RepositoryService(
    std::string database_url,
    std::filesystem::path blob_root,
    std::filesystem::path state_root,
    std::string origin)
    : database_url_(std::move(database_url)),
      blob_root_(std::move(blob_root)),
      state_root_(std::move(state_root)),
      origin_(std::move(origin)) {}

std::filesystem::path RepositoryService::apt_root() const {
    return blob_root_ / "apt";
}

std::vector<nexus::core::AptRepository> RepositoryService::list() const {
    PgConnection connection(database_url_);
    PgResult repo_result(PQexec(
        connection.get(),
        "select distribution, component from repo_repositories order by distribution, component"));
    if (PQresultStatus(repo_result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), repo_result.get()));
    }

    std::vector<nexus::core::AptRepository> repositories;
    repositories.reserve(static_cast<std::size_t>(PQntuples(repo_result.get())));
    for (int row = 0; row < PQntuples(repo_result.get()); ++row) {
        repositories.push_back({field(repo_result.get(), row, 0), field(repo_result.get(), row, 1), {}});
    }

    const std::string package_sql = std::string(package_select_sql()) +
        " order by distribution, component, name, version";
    PgResult pkg_result(PQexec(connection.get(), package_sql.c_str()));
    if (PQresultStatus(pkg_result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), pkg_result.get()));
    }

    for (int row = 0; row < PQntuples(pkg_result.get()); ++row) {
        const auto distribution = field(pkg_result.get(), row, 1);
        const auto component = field(pkg_result.get(), row, 2);
        auto repo = std::find_if(repositories.begin(), repositories.end(), [&](const auto& current) {
            return current.distribution == distribution && current.component == component;
        });
        if (repo == repositories.end()) {
            repositories.push_back({distribution, component, {}});
            repo = std::prev(repositories.end());
        }
        repo->packages.push_back(map_package(pkg_result.get(), row));
    }

    return repositories;
}

void RepositoryService::create_repository(const std::string& distribution, const std::string& component) const {
    if (!is_valid_debian_name(distribution) || !is_valid_debian_name(component)) {
        throw RepositoryException(RepositoryError::invalid_repository, "repository distribution or component is invalid");
    }

    PgConnection connection(database_url_);
    const char* values[] = {distribution.c_str(), component.c_str()};
    PgResult result(PQexecParams(
        connection.get(),
        "insert into repo_repositories(distribution, component) values ($1, $2) on conflict do nothing",
        2,
        nullptr,
        values,
        nullptr,
        nullptr,
        0));
    if (PQresultStatus(result.get()) != PGRES_COMMAND_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), result.get()));
    }
}

bool RepositoryService::delete_repository(const std::string& distribution, const std::string& component) const {
    PgConnection connection(database_url_);
    const char* values[] = {distribution.c_str(), component.c_str()};
    PgResult paths(PQexecParams(
        connection.get(),
        "select coalesce(storage_path, filename) from repo_packages where distribution = $1 and component = $2",
        2,
        nullptr,
        values,
        nullptr,
        nullptr,
        0));
    if (PQresultStatus(paths.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), paths.get()));
    }
    std::vector<std::string> storage_paths;
    storage_paths.reserve(static_cast<std::size_t>(PQntuples(paths.get())));
    for (int row = 0; row < PQntuples(paths.get()); ++row) {
        storage_paths.push_back(field(paths.get(), row, 0));
    }

    PgResult packages(PQexecParams(
        connection.get(),
        "delete from repo_packages where distribution = $1 and component = $2",
        2,
        nullptr,
        values,
        nullptr,
        nullptr,
        0));
    if (PQresultStatus(packages.get()) != PGRES_COMMAND_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), packages.get()));
    }
    PgResult repo(PQexecParams(
        connection.get(),
        "delete from repo_repositories where distribution = $1 and component = $2",
        2,
        nullptr,
        values,
        nullptr,
        nullptr,
        0));
    if (PQresultStatus(repo.get()) != PGRES_COMMAND_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), repo.get()));
    }
    const auto removed = std::string_view(PQcmdTuples(repo.get())) != "0";
    if (removed) {
        const auto pool_root = (apt_root() / "pool").lexically_normal();
        for (const auto& storage_path : storage_paths) {
            const auto artifact = artifact_path(storage_path);
            if (!artifact.has_value()) {
                continue;
            }
            std::error_code ignored;
            std::filesystem::remove(*artifact, ignored);
            auto parent = artifact->parent_path().lexically_normal();
            while (parent != pool_root && parent.string().rfind(pool_root.string(), 0) == 0) {
                if (!std::filesystem::is_empty(parent, ignored)) {
                    break;
                }
                std::filesystem::remove(parent, ignored);
                parent = parent.parent_path().lexically_normal();
            }
        }
    }
    return removed;
}

nexus::core::AptPackage RepositoryService::upload_package(
    const std::string& distribution,
    const std::string& component,
    const std::string& original_filename,
    std::string_view content,
    const std::string& actor) const {
    if (!is_valid_debian_name(distribution) || !is_valid_debian_name(component)) {
        throw RepositoryException(RepositoryError::invalid_repository, "repository distribution or component is invalid");
    }
    if (content.empty() || !has_suffix(lowercase_ascii(original_filename), ".deb")) {
        throw RepositoryException(RepositoryError::invalid_package, "upload must be a non-empty .deb file");
    }

    PgConnection connection(database_url_);
    if (!repository_exists(connection.get(), distribution, component)) {
        throw RepositoryException(RepositoryError::not_found, "repository not found");
    }

    const auto temp_path = unique_temp_path(apt_root(), ".deb");
    write_file(temp_path, content);

    const auto fields = extract_deb_control_fields(temp_path);
    const auto package_name = fields.contains("Package") ? fields.at("Package") : std::string{};
    const auto version = fields.contains("Version") ? fields.at("Version") : std::string{};
    const auto architecture = fields.contains("Architecture") ? fields.at("Architecture") : std::string{};
    if (!is_valid_debian_name(package_name) || version.empty() || architecture.empty()) {
        std::error_code ignored;
        std::filesystem::remove(temp_path, ignored);
        throw RepositoryException(RepositoryError::invalid_package, "deb control metadata is incomplete");
    }

    const auto storage_path = storage_path_for(component, package_name, version, architecture);
    const auto final_path = apt_root() / storage_path;
    std::error_code error_code;
    std::filesystem::create_directories(final_path.parent_path(), error_code);
    if (error_code) {
        std::filesystem::remove(temp_path, error_code);
        throw RepositoryException(
            RepositoryError::filesystem_error,
            "unable to create apt pool directory: " + error_code.message());
    }
    std::filesystem::remove(final_path, error_code);
    std::filesystem::rename(temp_path, final_path, error_code);
    if (error_code) {
        std::error_code copy_error;
        std::filesystem::copy_file(temp_path, final_path, std::filesystem::copy_options::overwrite_existing, copy_error);
        std::filesystem::remove(temp_path, error_code);
        if (copy_error) {
            throw RepositoryException(
                RepositoryError::filesystem_error,
                "unable to store deb artifact: " + copy_error.message());
        }
    }

    const auto sha256 = sha256_hex(content);
    const auto size = std::to_string(content.size());
    const auto control_json = fields_to_json(fields);
    const auto uploader = actor.empty() ? std::string{"system"} : actor;

    const char* values[] = {
        distribution.c_str(),
        component.c_str(),
        package_name.c_str(),
        version.c_str(),
        architecture.c_str(),
        storage_path.c_str(),
        sha256.c_str(),
        size.c_str(),
        storage_path.c_str(),
        control_json.c_str(),
        uploader.c_str(),
    };
    const std::string sql = R"SQL(
        insert into repo_packages(
            distribution,
            component,
            name,
            version,
            architecture,
            filename,
            sha256,
            size,
            storage_path,
            control_json,
            uploaded_by
        )
        values ($1, $2, $3, $4, $5, $6, $7, $8::bigint, $9, $10::jsonb, $11)
        on conflict (distribution, component, name, version, architecture) do update set
            filename = excluded.filename,
            sha256 = excluded.sha256,
            size = excluded.size,
            storage_path = excluded.storage_path,
            control_json = excluded.control_json,
            uploaded_by = excluded.uploaded_by,
            uploaded_at = now()
        returning
            id::text,
            distribution,
            component,
            name,
            version,
            architecture,
            filename,
            coalesce(storage_path, filename),
            sha256,
            size::text,
            coalesce(control_json, '{}'::jsonb)::text,
            coalesce(uploaded_by, 'system'),
            coalesce(uploaded_at, now())::text
    )SQL";

    PgResult result(PQexecParams(connection.get(), sql.c_str(), 11, nullptr, values, nullptr, nullptr, 0));
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), result.get()));
    }

    return map_package(result.get(), 0);
}

bool RepositoryService::delete_package(
    const std::string& distribution,
    const std::string& component,
    const nexus::core::AptPackage& package) const {
    PgConnection connection(database_url_);
    std::string sql;
    std::vector<const char*> values;
    if (!package.id.empty()) {
        sql = "delete from repo_packages where id = $1";
        values.push_back(package.id.c_str());
    } else {
        sql = "delete from repo_packages where distribution = $1 and component = $2 and filename = $3";
        values.push_back(distribution.c_str());
        values.push_back(component.c_str());
        values.push_back(package.filename.c_str());
    }

    PgResult result(PQexecParams(
        connection.get(),
        sql.c_str(),
        static_cast<int>(values.size()),
        nullptr,
        values.data(),
        nullptr,
        nullptr,
        0));
    if (PQresultStatus(result.get()) != PGRES_COMMAND_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), result.get()));
    }

    const auto removed = std::string_view(PQcmdTuples(result.get())) != "0";
    if (removed) {
        const auto storage_path = package.storage_path.empty() ? package.filename : package.storage_path;
        if (!storage_path.empty()) {
            std::error_code ignored;
            std::filesystem::remove(apt_root() / storage_path, ignored);
        }
    }
    return removed;
}

std::optional<std::string> RepositoryService::packages_index(
    const std::string& distribution,
    const std::string& component,
    const std::string& architecture) const {
    PgConnection connection(database_url_);
    if (!repository_exists(connection.get(), distribution, component)) {
        return std::nullopt;
    }

    const char* values[] = {distribution.c_str(), component.c_str(), architecture.c_str()};
    const std::string sql = std::string(package_select_sql()) + R"SQL(
        where distribution = $1
          and component = $2
          and (architecture = $3 or architecture = 'all')
        order by name, version
    )SQL";
    PgResult result(PQexecParams(connection.get(), sql.c_str(), 3, nullptr, values, nullptr, nullptr, 0));
    if (PQresultStatus(result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), result.get()));
    }

    std::vector<nexus::core::AptPackage> packages;
    packages.reserve(static_cast<std::size_t>(PQntuples(result.get())));
    for (int row = 0; row < PQntuples(result.get()); ++row) {
        packages.push_back(map_package(result.get(), row));
    }
    return render_packages_index(packages);
}

std::optional<std::vector<std::uint8_t>> RepositoryService::packages_index_gzip(
    const std::string& distribution,
    const std::string& component,
    const std::string& architecture) const {
    const auto packages = packages_index(distribution, component, architecture);
    if (!packages.has_value()) {
        return std::nullopt;
    }
    return nexus::protocol::gzip_bytes(*packages);
}

std::optional<std::string> RepositoryService::release_file(const std::string& distribution) const {
    PgConnection connection(database_url_);
    const char* values[] = {distribution.c_str()};
    PgResult components_result(PQexecParams(
        connection.get(),
        "select component from repo_repositories where distribution = $1 order by component",
        1,
        nullptr,
        values,
        nullptr,
        nullptr,
        0));
    if (PQresultStatus(components_result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), components_result.get()));
    }
    if (PQntuples(components_result.get()) == 0) {
        return std::nullopt;
    }

    std::vector<std::string> components;
    for (int row = 0; row < PQntuples(components_result.get()); ++row) {
        components.push_back(field(components_result.get(), row, 0));
    }

    PgResult arch_result(PQexecParams(
        connection.get(),
        "select distinct architecture from repo_packages where distribution = $1 order by architecture",
        1,
        nullptr,
        values,
        nullptr,
        nullptr,
        0));
    if (PQresultStatus(arch_result.get()) != PGRES_TUPLES_OK) {
        throw RepositoryException(RepositoryError::database_error, pg_error(connection.get(), arch_result.get()));
    }

    std::set<std::string> architectures{"amd64"};
    for (int row = 0; row < PQntuples(arch_result.get()); ++row) {
        const auto architecture = field(arch_result.get(), row, 0);
        if (!architecture.empty() && architecture != "all") {
            architectures.insert(architecture);
        }
    }

    struct ReleaseIndex {
        std::string path;
        std::string sha256;
        std::size_t size{0};
    };
    std::vector<ReleaseIndex> indexes;
    for (const auto& component : components) {
        for (const auto& architecture : architectures) {
            const auto packages = packages_index(distribution, component, architecture).value_or("");
            const auto gzipped = nexus::protocol::gzip_bytes(packages);
            const auto base = component + "/binary-" + architecture + "/";
            indexes.push_back({base + "Packages", sha256_hex(packages), packages.size()});
            indexes.push_back({base + "Packages.gz", sha256_hex(gzipped), gzipped.size()});
        }
    }

    std::ostringstream output;
    output << "Origin: " << (origin_.empty() ? "Endorium Nexus" : origin_) << "\n";
    output << "Label: Endorium Nexus\n";
    output << "Suite: " << distribution << "\n";
    output << "Codename: " << distribution << "\n";
    output << "Components:";
    for (const auto& component : components) {
        output << " " << component;
    }
    output << "\n";
    output << "Architectures:";
    for (const auto& architecture : architectures) {
        output << " " << architecture;
    }
    output << "\n";
    output << "Acquire-By-Hash: no\n";
    output << "SHA256:\n";
    for (const auto& index : indexes) {
        output << " " << index.sha256 << " " << index.size << " " << index.path << "\n";
    }
    return output.str();
}

std::optional<std::string> RepositoryService::in_release(const std::string& distribution) const {
    const auto release = release_file(distribution);
    if (!release.has_value()) {
        return std::nullopt;
    }
    return sign_release(database_url_, state_root_, *release, true);
}

std::optional<std::string> RepositoryService::release_gpg(const std::string& distribution) const {
    const auto release = release_file(distribution);
    if (!release.has_value()) {
        return std::nullopt;
    }
    return sign_release(database_url_, state_root_, *release, false);
}

std::string RepositoryService::public_key() const {
    return ensure_signing_key(database_url_, state_root_).public_key;
}

std::optional<std::filesystem::path> RepositoryService::artifact_path(std::string_view storage_path) const {
    if (storage_path.empty() || storage_path.front() == '/' ||
        storage_path.find("..") != std::string_view::npos ||
        storage_path.find('\\') != std::string_view::npos) {
        return std::nullopt;
    }

    const auto root = apt_root().lexically_normal();
    const auto path = (root / std::filesystem::path(std::string(storage_path))).lexically_normal();
    const auto root_text = root.string();
    const auto path_text = path.string();
    if (path_text.rfind(root_text, 0) != 0 || !std::filesystem::is_regular_file(path)) {
        return std::nullopt;
    }
    return path;
}

}  // namespace nexus::apt
