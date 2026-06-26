#include "apt_handlers.hpp"

#include "platform_state.hpp"

#include "nexus/apt/repository.hpp"

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>
#include <drogon/MultiPart.h>
#include <json/json.h>

#include <functional>
#include <memory>
#include <string>
#include <string_view>

namespace nexus::api {

namespace {

Json::Value error_json(const std::string& message) {
    Json::Value node(Json::objectValue);
    node["error"] = message;
    return node;
}

Json::Value to_json(const nexus::core::AptPackage& package) {
    Json::Value node(Json::objectValue);
    node["id"] = package.id;
    node["name"] = package.name;
    node["version"] = package.version;
    node["architecture"] = package.architecture;
    node["component"] = package.component;
    node["filename"] = package.filename;
    node["storagePath"] = package.storage_path;
    node["sha256"] = package.sha256;
    node["size"] = Json::UInt64(package.size);
    node["controlJson"] = package.control_json;
    node["uploadedBy"] = package.uploaded_by;
    node["uploadedAt"] = package.uploaded_at;
    node["downloadUrl"] = package.download_url;
    return node;
}

void respond_json(
    drogon::HttpStatusCode status,
    Json::Value payload,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
    auto response = drogon::HttpResponse::newHttpJsonResponse(payload);
    response->setStatusCode(status);
    callback(response);
}

drogon::HttpStatusCode status_for(nexus::apt::RepositoryError error) {
    switch (error) {
        case nexus::apt::RepositoryError::invalid_repository:
        case nexus::apt::RepositoryError::invalid_package:
            return drogon::k400BadRequest;
        case nexus::apt::RepositoryError::not_found:
            return drogon::k404NotFound;
        case nexus::apt::RepositoryError::database_not_configured:
        case nexus::apt::RepositoryError::database_unavailable:
        case nexus::apt::RepositoryError::database_error:
        case nexus::apt::RepositoryError::filesystem_error:
        case nexus::apt::RepositoryError::tool_failed:
            return drogon::k500InternalServerError;
    }
    return drogon::k500InternalServerError;
}

void respond_apt_error(
    const nexus::apt::RepositoryException& error,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
    respond_json(status_for(error.code()), error_json(error.what()), std::move(callback));
}

nexus::apt::RepositoryService repository_service(const PlatformState& state) {
    return nexus::apt::RepositoryService(
        state.config().database_url,
        state.config().blob_root,
        state.config().state_root,
        state.config().repo.origin);
}

drogon::HttpResponsePtr text_response(
    drogon::HttpStatusCode status,
    std::string body,
    std::string content_type = "text/plain; charset=utf-8") {
    auto response = drogon::HttpResponse::newHttpResponse();
    response->setStatusCode(status);
    response->setContentTypeString(content_type);
    response->setBody(std::move(body));
    return response;
}

}  // namespace

void register_apt_handlers(std::shared_ptr<PlatformState> state) {
    drogon::app().registerHandler(
        "/api/v1/repos/{1}/{2}/packages/upload",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& distribution,
                const std::string& component) {
            std::string actor;
            if (!state->authorize_mutation(
                    request->getCookie("nexus_session"),
                    request->getHeader("X-CSRF-Token"),
                    &actor,
                    nullptr)) {
                respond_json(
                    drogon::k401Unauthorized,
                    error_json("mutation requires a valid session and csrf token"),
                    std::move(callback));
                return;
            }

            drogon::MultiPartParser parser;
            if (parser.parse(request) != 0 || parser.getFiles().empty()) {
                respond_json(drogon::k400BadRequest, error_json("multipart file is required"), std::move(callback));
                return;
            }

            const auto& file = parser.getFiles().front();
            try {
                const auto content = file.fileContent();
                const auto package = state->upload_apt_package(
                    distribution,
                    component,
                    file.getFileName(),
                    content,
                    actor);
                if (!package.has_value()) {
                    respond_json(drogon::k404NotFound, error_json("repository not found"), std::move(callback));
                    return;
                }
                respond_json(drogon::k201Created, to_json(*package), std::move(callback));
            } catch (const nexus::apt::RepositoryException& error) {
                respond_apt_error(error, std::move(callback));
            } catch (const std::exception& error) {
                respond_json(drogon::k500InternalServerError, error_json(error.what()), std::move(callback));
            }
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/apt/key.gpg",
        [state](const drogon::HttpRequestPtr&, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            try {
                callback(text_response(drogon::k200OK, repository_service(*state).public_key(), "application/pgp-keys"));
            } catch (const std::exception& error) {
                callback(text_response(drogon::k500InternalServerError, std::string(error.what()) + "\n"));
            }
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/apt/dists/{1}/Release",
        [state](const drogon::HttpRequestPtr&,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& distribution) {
            try {
                const auto release = repository_service(*state).release_file(distribution);
                if (!release.has_value()) {
                    callback(text_response(drogon::k404NotFound, "repository not found\n"));
                    return;
                }
                callback(text_response(drogon::k200OK, *release));
            } catch (const std::exception& error) {
                callback(text_response(drogon::k500InternalServerError, std::string(error.what()) + "\n"));
            }
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/apt/dists/{1}/InRelease",
        [state](const drogon::HttpRequestPtr&,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& distribution) {
            try {
                const auto release = repository_service(*state).in_release(distribution);
                if (!release.has_value()) {
                    callback(text_response(drogon::k404NotFound, "repository not found\n"));
                    return;
                }
                callback(text_response(drogon::k200OK, *release));
            } catch (const std::exception& error) {
                callback(text_response(drogon::k500InternalServerError, std::string(error.what()) + "\n"));
            }
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/apt/dists/{1}/Release.gpg",
        [state](const drogon::HttpRequestPtr&,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& distribution) {
            try {
                const auto signature = repository_service(*state).release_gpg(distribution);
                if (!signature.has_value()) {
                    callback(text_response(drogon::k404NotFound, "repository not found\n"));
                    return;
                }
                callback(text_response(drogon::k200OK, *signature, "application/pgp-signature"));
            } catch (const std::exception& error) {
                callback(text_response(drogon::k500InternalServerError, std::string(error.what()) + "\n"));
            }
        },
        {drogon::Get});

    drogon::app().registerHandlerViaRegex(
        R"(/apt/dists/([^/]+)/([^/]+)/binary-([^/]+)/Packages\.gz)",
        [state](const drogon::HttpRequestPtr&,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& distribution,
                const std::string& component,
                const std::string& architecture) {
            try {
                auto service = repository_service(*state);
                const auto payload = service.packages_index_gzip(distribution, component, architecture);
                if (!payload.has_value()) {
                    callback(text_response(drogon::k404NotFound, "repository not found\n"));
                    return;
                }
                auto response = drogon::HttpResponse::newHttpResponse();
                response->setStatusCode(drogon::k200OK);
                response->setContentTypeString("application/gzip");
                response->setBody(std::string(
                    reinterpret_cast<const char*>(payload->data()),
                    payload->size()));
                callback(response);
            } catch (const std::exception& error) {
                callback(text_response(drogon::k500InternalServerError, std::string(error.what()) + "\n"));
            }
        },
        {drogon::Get});

    drogon::app().registerHandlerViaRegex(
        R"(/apt/dists/([^/]+)/([^/]+)/binary-([^/]+)/Packages)",
        [state](const drogon::HttpRequestPtr&,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& distribution,
                const std::string& component,
                const std::string& architecture) {
            try {
                auto service = repository_service(*state);
                const auto payload = service.packages_index(distribution, component, architecture);
                if (!payload.has_value()) {
                    callback(text_response(drogon::k404NotFound, "repository not found\n"));
                    return;
                }
                callback(text_response(drogon::k200OK, *payload));
            } catch (const std::exception& error) {
                callback(text_response(drogon::k500InternalServerError, std::string(error.what()) + "\n"));
            }
        },
        {drogon::Get});

    drogon::app().registerHandlerViaRegex(
        R"(/apt/(pool/.+\.deb))",
        [state](const drogon::HttpRequestPtr&,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& storage_path) {
            try {
                const auto path = repository_service(*state).artifact_path(storage_path);
                if (!path.has_value()) {
                    callback(text_response(drogon::k404NotFound, "package not found\n"));
                    return;
                }
                auto response = drogon::HttpResponse::newFileResponse(path->string());
                response->setContentTypeString("application/vnd.debian.binary-package");
                callback(response);
            } catch (const std::exception& error) {
                callback(text_response(drogon::k500InternalServerError, std::string(error.what()) + "\n"));
            }
        },
        {drogon::Get});
}

}  // namespace nexus::api
