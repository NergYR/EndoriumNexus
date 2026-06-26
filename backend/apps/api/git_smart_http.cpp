#include "git_smart_http.hpp"

#include "platform_state.hpp"

#include "nexus/security/password_hasher.hpp"
#include "nexus/security/totp.hpp"
#include "nexus/vcs/git_http.hpp"

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>
#include <drogon/utils/Utilities.h>

#include <chrono>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <thread>
#include <utility>

namespace nexus::api {

namespace {

struct GitActor {
    bool authenticated{false};
    bool can_read{false};
    bool can_write{false};
    std::string email;
    std::string token_id;
};

struct BasicCredentials {
    std::string username;
    std::string password;
    std::string totp;
};

std::optional<BasicCredentials> parse_basic_credentials(const std::string& authorization, bool mfa_required) {
    constexpr std::string_view prefix = "Basic ";
    if (authorization.size() <= prefix.size() || authorization.compare(0, prefix.size(), prefix) != 0) {
        return std::nullopt;
    }

    const auto decoded = drogon::utils::base64Decode(std::string_view(authorization).substr(prefix.size()));
    const auto separator = decoded.find(':');
    if (separator == std::string::npos) {
        return std::nullopt;
    }

    BasicCredentials credentials;
    credentials.username = decoded.substr(0, separator);
    auto secret = decoded.substr(separator + 1);
    if (mfa_required) {
        const auto mfa_separator = secret.rfind(':');
        if (mfa_separator != std::string::npos) {
            credentials.password = secret.substr(0, mfa_separator);
            credentials.totp = secret.substr(mfa_separator + 1);
        } else {
            credentials.password = std::move(secret);
        }
    } else {
        credentials.password = std::move(secret);
    }
    return credentials;
}

GitActor git_actor(
    const std::shared_ptr<PlatformState>& state,
    const drogon::HttpRequestPtr& request,
    const std::string& repository_name) {
    GitActor actor;
    if (state->authenticate(request->getCookie("nexus_session"), &actor.email, nullptr)) {
        actor.authenticated = true;
        actor.can_read = true;
        actor.can_write = true;
        return actor;
    }

    const auto& config = state->config();
    const auto credentials = parse_basic_credentials(
        request->getHeader("Authorization"),
        !config.admin_totp_secret.empty());
    if (!credentials.has_value()) {
        return actor;
    }

    if (credentials->username == "git") {
        try {
            nexus::vcs::RepositoryService repositories(config.database_url, config.blob_root);
            const auto token = repositories.authenticate_token(repository_name, credentials->password, false);
            if (!token.has_value()) {
                return actor;
            }
            actor.authenticated = true;
            actor.can_read = token->can_read;
            actor.can_write = token->can_write;
            actor.email = token->actor;
            actor.token_id = token->token_id;
        } catch (...) {
            return actor;
        }
        return actor;
    }

    if (config.admin_password_hash.empty() || credentials->username != config.admin_email) {
        return actor;
    }

    nexus::security::PasswordHasher password_hasher;
    if (!password_hasher.verify_password(credentials->password, config.admin_password_hash)) {
        return actor;
    }

    if (!config.admin_totp_secret.empty()) {
        nexus::security::Totp totp;
        if (credentials->totp.empty() ||
            !totp.verify(config.admin_totp_secret, credentials->totp, std::chrono::system_clock::now())) {
            return actor;
        }
    }

    actor.authenticated = true;
    actor.can_read = true;
    actor.can_write = true;
    actor.email = credentials->username;
    return actor;
}

drogon::HttpResponsePtr to_drogon_response(const nexus::vcs::GitHttpResponse& response) {
    auto output = drogon::HttpResponse::newHttpResponse();
    output->setStatusCode(static_cast<drogon::HttpStatusCode>(response.status_code));
    for (const auto& [key, value] : response.headers) {
        output->addHeader(key, value);
    }
    output->setBody(response.body);
    return output;
}

nexus::vcs::GitHttpMethod method_from_request(const drogon::HttpRequestPtr& request) {
    return request->getMethod() == drogon::Post
        ? nexus::vcs::GitHttpMethod::post
        : nexus::vcs::GitHttpMethod::get;
}

drogon::HttpResponsePtr exception_response(const std::exception& error) {
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(drogon::k500InternalServerError);
    response->setContentTypeString("text/plain; charset=utf-8");
    response->setBody(std::string("git backend failed: ") + error.what() + "\n");
    return response;
}

}  // namespace

void register_git_smart_http(std::shared_ptr<PlatformState> state) {
    drogon::app().registerHandlerViaRegex(
        "/git/([^/]+)\\.git/(.*)",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& repository_name,
                const std::string& path_info) {
            std::thread(
                [state,
                 request,
                 callback = std::move(callback),
                 repository_name,
                 path_info]() mutable {
                    try {
                        const auto actor = git_actor(state, request, repository_name);
                        nexus::vcs::GitHttpRequest git_request;
                        git_request.method = method_from_request(request);
                        git_request.repository_name = repository_name;
                        git_request.path_info = "/" + repository_name + ".git/" + path_info;
                        git_request.query_string = request->getQuery();
                        git_request.content_type = request->getHeader("Content-Type");
                        git_request.body = std::string(request->getBody());
                        git_request.authenticated = actor.authenticated;
                        git_request.can_read = actor.can_read;
                        git_request.can_write = actor.can_write;
                        git_request.remote_user = actor.email;
                        git_request.token_id = actor.token_id;

                        nexus::vcs::GitSmartHttpService service(nexus::vcs::RepositoryService(
                            state->config().database_url,
                            state->config().blob_root));
                        callback(to_drogon_response(service.handle(git_request)));
                    } catch (const std::exception& error) {
                        callback(exception_response(error));
                    }
                })
                .detach();
        },
        {drogon::Get, drogon::Post});
}

}  // namespace nexus::api
