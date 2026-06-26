#include "nexus/vcs/git_http.hpp"

#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <cerrno>
#include <csignal>
#include <cstring>
#include <sstream>
#include <string_view>
#include <thread>
#include <utility>

namespace nexus::vcs {

namespace {

struct ProcessResult {
    int exit_code{0};
    std::string stdout_text;
    std::string stderr_text;
};

[[nodiscard]] bool is_write_request(const GitHttpRequest& request) {
    return request.path_info.find("git-receive-pack") != std::string::npos ||
        request.query_string.find("service=git-receive-pack") != std::string::npos;
}

[[nodiscard]] GitHttpResponse text_response(
    int status,
    std::string body,
    std::vector<std::pair<std::string, std::string>> headers = {}) {
    GitHttpResponse response;
    response.status_code = status;
    response.headers = std::move(headers);
    response.headers.emplace_back("Content-Type", "text/plain; charset=utf-8");
    response.body = std::move(body);
    return response;
}

[[nodiscard]] GitHttpResponse auth_required() {
    return text_response(
        401,
        "authentication required\n",
        {{"WWW-Authenticate", R"(Basic realm="Endorium Nexus Git")"}});
}

void record_event_best_effort(
    const RepositoryService& repositories,
    const Repository& repository,
    const GitHttpRequest& request,
    const std::string& action,
    const std::string& detail = {}) {
    try {
        const auto actor = request.remote_user.empty() ? std::string{"anonymous"} : request.remote_user;
        repositories.record_event(repository.id, actor, action, detail);
    } catch (...) {
    }
}

void close_fd(int& fd) {
    if (fd >= 0) {
        ::close(fd);
        fd = -1;
    }
}

[[nodiscard]] std::string read_all(int fd) {
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

void write_all_and_close(int fd, std::string_view body) {
    const char* cursor = body.data();
    std::size_t remaining = body.size();
    while (remaining > 0) {
        const ssize_t written = ::write(fd, cursor, remaining);
        if (written > 0) {
            cursor += written;
            remaining -= static_cast<std::size_t>(written);
            continue;
        }
        if (written < 0 && errno == EINTR) {
            continue;
        }
        break;
    }
    ::close(fd);
}

void set_child_env(const std::string& key, const std::string& value) {
    ::setenv(key.c_str(), value.c_str(), 1);
}

[[nodiscard]] ProcessResult run_git_http_backend(
    const GitHttpRequest& request,
    const std::filesystem::path& git_root) {
    std::signal(SIGPIPE, SIG_IGN);

    int stdin_pipe[2]{-1, -1};
    int stdout_pipe[2]{-1, -1};
    int stderr_pipe[2]{-1, -1};
    if (::pipe(stdin_pipe) != 0 || ::pipe(stdout_pipe) != 0 || ::pipe(stderr_pipe) != 0) {
        close_fd(stdin_pipe[0]);
        close_fd(stdin_pipe[1]);
        close_fd(stdout_pipe[0]);
        close_fd(stdout_pipe[1]);
        close_fd(stderr_pipe[0]);
        close_fd(stderr_pipe[1]);
        throw RepositoryException(RepositoryError::git_failed, "unable to create git http pipes");
    }

    const pid_t pid = ::fork();
    if (pid < 0) {
        close_fd(stdin_pipe[0]);
        close_fd(stdin_pipe[1]);
        
        close_fd(stdout_pipe[0]);
        close_fd(stdout_pipe[1]);
        close_fd(stderr_pipe[0]);
        close_fd(stderr_pipe[1]);
        throw RepositoryException(
            RepositoryError::git_failed,
            std::string("fork failed: ") + std::strerror(errno));
    }

    if (pid == 0) {
        ::dup2(stdin_pipe[0], STDIN_FILENO);
        ::dup2(stdout_pipe[1], STDOUT_FILENO);
        ::dup2(stderr_pipe[1], STDERR_FILENO);

        close_fd(stdin_pipe[0]);
        close_fd(stdin_pipe[1]);
        close_fd(stdout_pipe[0]);
        close_fd(stdout_pipe[1]);
        close_fd(stderr_pipe[0]);
        close_fd(stderr_pipe[1]);

        set_child_env("GIT_PROJECT_ROOT", git_root.string());
        set_child_env("GIT_HTTP_EXPORT_ALL", "1");
        set_child_env("PATH_INFO", request.path_info);
        set_child_env("REQUEST_METHOD", request.method == GitHttpMethod::post ? "POST" : "GET");
        set_child_env("QUERY_STRING", request.query_string);
        set_child_env("CONTENT_LENGTH", std::to_string(request.body.size()));
        if (!request.content_type.empty()) {
            set_child_env("CONTENT_TYPE", request.content_type);
        }
        if (request.authenticated && !request.remote_user.empty()) {
            set_child_env("REMOTE_USER", request.remote_user);
        }

        char git[] = "git";
        char backend[] = "http-backend";
        char* argv[] = {git, backend, nullptr};
        ::execvp("git", argv);
        _exit(127);
    }

    close_fd(stdin_pipe[0]);
    close_fd(stdout_pipe[1]);
    close_fd(stderr_pipe[1]);

    std::thread stdin_writer([fd = stdin_pipe[1], body = request.body]() {
        write_all_and_close(fd, body);
    });
    stdin_pipe[1] = -1;

    std::string stderr_text;
    std::thread stderr_reader([&]() {
        stderr_text = read_all(stderr_pipe[0]);
    });

    const std::string stdout_text = read_all(stdout_pipe[0]);
    close_fd(stdout_pipe[0]);

    stdin_writer.join();
    stderr_reader.join();
    close_fd(stderr_pipe[0]);

    int status = 0;
    if (::waitpid(pid, &status, 0) != pid) {
        throw RepositoryException(
            RepositoryError::git_failed,
            std::string("waitpid failed: ") + std::strerror(errno));
    }

    ProcessResult result;
    result.stdout_text = stdout_text;
    result.stderr_text = stderr_text;
    result.exit_code = WIFEXITED(status) ? WEXITSTATUS(status) : 128;
    return result;
}

void strip_trailing_cr(std::string& value) {
    if (!value.empty() && value.back() == '\r') {
        value.pop_back();
    }
}

[[nodiscard]] std::string trim_left(std::string value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t')) {
        value.erase(value.begin());
    }
    return value;
}

[[nodiscard]] GitHttpResponse parse_cgi_response(const ProcessResult& process) {
    if (process.stdout_text.empty() && process.exit_code != 0) {
        return text_response(500, process.stderr_text.empty() ? "git http-backend failed\n" : process.stderr_text);
    }

    std::size_t separator = process.stdout_text.find("\r\n\r\n");
    std::size_t separator_size = 4;
    if (separator == std::string::npos) {
        separator = process.stdout_text.find("\n\n");
        separator_size = 2;
    }

    if (separator == std::string::npos) {
        GitHttpResponse response;
        response.status_code = process.exit_code == 0 ? 200 : 500;
        response.body = process.stdout_text;
        return response;
    }

    GitHttpResponse response;
    response.status_code = 200;
    response.body = process.stdout_text.substr(separator + separator_size);

    std::istringstream input(process.stdout_text.substr(0, separator));
    std::string line;
    while (std::getline(input, line)) {
        strip_trailing_cr(line);
        if (line.empty()) {
            continue;
        }

        const auto colon = line.find(':');
        if (colon == std::string::npos) {
            continue;
        }

        const auto key = line.substr(0, colon);
        const auto value = trim_left(line.substr(colon + 1));
        if (key == "Status") {
            try {
                response.status_code = std::stoi(value);
            } catch (...) {
                response.status_code = 500;
            }
            continue;
        }

        response.headers.emplace_back(key, value);
    }

    return response;
}

}  // namespace

GitSmartHttpService::GitSmartHttpService(RepositoryService repositories)
    : repositories_(std::move(repositories)) {}

GitHttpResponse GitSmartHttpService::handle(const GitHttpRequest& request) const {
    if (!is_valid_repository_name(request.repository_name)) {
        return text_response(404, "repository not found\n");
    }

    auto repository = repositories_.find_by_name(request.repository_name);
    if (!repository.has_value()) {
        return text_response(404, "repository not found\n");
    }

    if (!repository->storage_exists) {
        repository = repositories_.repair_storage(repository->id);
        if (!repository.has_value() || !repository->storage_exists) {
            return text_response(500, "repository storage is unavailable\n");
        }
    }

    const bool write = is_write_request(request);
    const bool can_read = request.can_read;
    const bool can_write = request.can_write;

    if (repository->is_private && !can_read) {
        record_event_best_effort(repositories_, *repository, request, "fetch.denied", request.path_info);
        return auth_required();
    }

    if (write && !repository->http_push_enabled) {
        record_event_best_effort(repositories_, *repository, request, "push.denied", "http push disabled");
        return text_response(403, "git push is disabled for this repository\n");
    }

    if (write && !can_write) {
        record_event_best_effort(repositories_, *repository, request, "push.denied", "write token required");
        return request.authenticated || can_read
            ? text_response(403, "git write token required\n")
            : auth_required();
    }

    auto response = parse_cgi_response(run_git_http_backend(request, repositories_.git_root()));
    const bool success = response.status_code >= 200 && response.status_code < 400;
    record_event_best_effort(
        repositories_,
        *repository,
        request,
        success ? (write ? "push" : "fetch") : (write ? "push.failed" : "fetch.failed"),
        request.query_string.empty() ? request.path_info : request.path_info + "?" + request.query_string);
    return response;
}

}  // namespace nexus::vcs
