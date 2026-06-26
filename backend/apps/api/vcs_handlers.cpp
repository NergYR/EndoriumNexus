#include "vcs_handlers.hpp"

#include "platform_state.hpp"

#include "nexus/vcs/repository.hpp"

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>
#include <json/json.h>

#include <functional>
#include <memory>
#include <optional>
#include <string>

namespace nexus::api {

namespace {

Json::Value error_json(const std::string& message) {
    Json::Value node(Json::objectValue);
    node["error"] = message;
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

drogon::HttpStatusCode status_for(nexus::vcs::RepositoryError error) {
    switch (error) {
        case nexus::vcs::RepositoryError::invalid_name:
        case nexus::vcs::RepositoryError::invalid_branch:
            return drogon::k400BadRequest;
        case nexus::vcs::RepositoryError::already_exists:
        case nexus::vcs::RepositoryError::storage_conflict:
            return drogon::k409Conflict;
        case nexus::vcs::RepositoryError::not_found:
            return drogon::k404NotFound;
        case nexus::vcs::RepositoryError::database_not_configured:
        case nexus::vcs::RepositoryError::database_unavailable:
        case nexus::vcs::RepositoryError::database_error:
        case nexus::vcs::RepositoryError::filesystem_error:
        case nexus::vcs::RepositoryError::git_failed:
            return drogon::k500InternalServerError;
    }
    return drogon::k500InternalServerError;
}

Json::Value to_json(const nexus::vcs::Repository& repository) {
    Json::Value node(Json::objectValue);
    node["id"] = repository.id;
    node["name"] = repository.name;
    node["description"] = repository.description;
    node["isPrivate"] = repository.is_private;
    node["is_private"] = repository.is_private;
    node["httpPushEnabled"] = repository.http_push_enabled;
    node["defaultBranch"] = repository.default_branch;
    node["createdAt"] = repository.created_at;
    node["created_at"] = repository.created_at;
    node["updatedAt"] = repository.updated_at;
    node["storageReady"] = repository.storage_exists;
    node["headTarget"] = repository.head_target;
    node["cloneUrl"] = "/git/" + repository.name + ".git";
    node["pushUrl"] = "/git/" + repository.name + ".git";
    return node;
}

Json::Value to_json(const nexus::vcs::RepositoryRef& ref) {
    Json::Value node(Json::objectValue);
    node["name"] = ref.name;
    node["shortName"] = ref.short_name;
    node["type"] = ref.type;
    node["objectId"] = ref.object_id;
    return node;
}

Json::Value to_json(const nexus::vcs::AccessToken& token) {
    Json::Value node(Json::objectValue);
    node["id"] = token.id;
    node["repositoryId"] = token.repository_id;
    node["repositoryName"] = token.repository_name;
    node["name"] = token.name;
    node["scope"] = token.scope;
    node["tokenPrefix"] = token.token_prefix;
    node["createdAt"] = token.created_at;
    node["expiresAt"] = token.expires_at;
    node["lastUsedAt"] = token.last_used_at;
    node["revoked"] = token.revoked;
    return node;
}

Json::Value to_json(const nexus::vcs::RepositoryEvent& event) {
    Json::Value node(Json::objectValue);
    node["id"] = Json::Int64(event.id);
    node["repositoryId"] = event.repository_id;
    node["repositoryName"] = event.repository_name;
    node["actor"] = event.actor;
    node["action"] = event.action;
    node["detail"] = event.detail;
    node["refName"] = event.ref_name;
    node["oldOid"] = event.old_oid;
    node["newOid"] = event.new_oid;
    node["happenedAt"] = event.happened_at;
    return node;
}

bool json_bool(const Json::Value& body, const char* camel_key, const char* snake_key, bool fallback) {
    if (body.isMember(camel_key)) {
        return body[camel_key].asBool();
    }
    if (body.isMember(snake_key)) {
        return body[snake_key].asBool();
    }
    return fallback;
}

std::optional<bool> json_optional_bool(const Json::Value& body, const char* camel_key, const char* snake_key) {
    if (body.isMember(camel_key)) {
        return body[camel_key].asBool();
    }
    if (body.isMember(snake_key)) {
        return body[snake_key].asBool();
    }
    return std::nullopt;
}

nexus::vcs::RepositoryService repository_service(const PlatformState& state) {
    return nexus::vcs::RepositoryService(state.config().database_url, state.config().blob_root);
}

bool require_session(
    const std::shared_ptr<PlatformState>& state,
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback,
    std::string* actor) {
    if (state->authenticate(request->getCookie("nexus_session"), actor, nullptr)) {
        return true;
    }
    respond_json(drogon::k401Unauthorized, error_json("authentication required"), std::move(callback));
    return false;
}

bool require_mutation(
    const std::shared_ptr<PlatformState>& state,
    const drogon::HttpRequestPtr& request,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback,
    std::string* actor) {
    if (state->authorize_mutation(
            request->getCookie("nexus_session"),
            request->getHeader("X-CSRF-Token"),
            actor,
            nullptr)) {
        return true;
    }
    respond_json(
        drogon::k401Unauthorized,
        error_json("mutation requires a valid session and csrf token"),
        std::move(callback));
    return false;
}

void respond_repository_error(
    const nexus::vcs::RepositoryException& error,
    std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
    respond_json(status_for(error.code()), error_json(error.what()), std::move(callback));
}

}  // namespace

void register_vcs_handlers(std::shared_ptr<PlatformState> state) {
    drogon::app().registerHandler(
        "/api/v1/vcs",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            if (!require_session(state, request, std::move(callback), &actor)) {
                return;
            }

            try {
                Json::Value payload(Json::arrayValue);
                for (const auto& repository : repository_service(*state).list()) {
                    payload.append(to_json(repository));
                }
                respond_json(drogon::k200OK, std::move(payload), std::move(callback));
            } catch (const nexus::vcs::RepositoryException& error) {
                respond_repository_error(error, std::move(callback));
            }
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/vcs",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            std::string actor;
            if (!require_mutation(state, request, std::move(callback), &actor)) {
                return;
            }

            auto body = request->getJsonObject();
            if (body == nullptr || !body->isMember("name")) {
                respond_json(drogon::k400BadRequest, error_json("repository name is required"), std::move(callback));
                return;
            }

            nexus::vcs::RepositoryCreateRequest create;
            create.name = (*body)["name"].asString();
            create.description = body->isMember("description") ? (*body)["description"].asString() : "";
            create.is_private = json_bool(*body, "isPrivate", "is_private", true);
            create.http_push_enabled = json_bool(*body, "httpPushEnabled", "http_push_enabled", true);
            create.default_branch = body->isMember("defaultBranch") ? (*body)["defaultBranch"].asString() : "main";

            try {
                auto repository = repository_service(*state).create(create);
                state->record_platform_audit(actor, "vcs", "repository.created", repository.name);
                respond_json(drogon::k201Created, to_json(repository), std::move(callback));
            } catch (const nexus::vcs::RepositoryException& error) {
                respond_repository_error(error, std::move(callback));
            }
        },
        {drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/vcs/{1}",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& id) {
            std::string actor;
            if (request->getMethod() == drogon::Get) {
                if (!require_session(state, request, std::move(callback), &actor)) {
                    return;
                }
            } else if (!require_mutation(state, request, std::move(callback), &actor)) {
                return;
            }

            try {
                auto service = repository_service(*state);
                if (request->getMethod() == drogon::Get) {
                    const auto repository = service.find_by_id(id);
                    if (!repository.has_value()) {
                        respond_json(drogon::k404NotFound, error_json("repository not found"), std::move(callback));
                        return;
                    }
                    respond_json(drogon::k200OK, to_json(*repository), std::move(callback));
                    return;
                }

                if (request->getMethod() == drogon::Delete) {
                    const auto before_delete = service.find_by_id(id);
                    if (!service.remove(id)) {
                        respond_json(drogon::k404NotFound, error_json("repository not found"), std::move(callback));
                        return;
                    }
                    state->record_platform_audit(
                        actor,
                        "vcs",
                        "repository.deleted",
                        before_delete.has_value() ? before_delete->name : id);
                    Json::Value payload(Json::objectValue);
                    payload["ok"] = true;
                    respond_json(drogon::k200OK, std::move(payload), std::move(callback));
                    return;
                }

                auto body = request->getJsonObject();
                if (body == nullptr) {
                    respond_json(drogon::k400BadRequest, error_json("repository update payload is required"), std::move(callback));
                    return;
                }

                nexus::vcs::RepositoryUpdateRequest update;
                if (body->isMember("description")) {
                    update.description = (*body)["description"].asString();
                }
                update.is_private = json_optional_bool(*body, "isPrivate", "is_private");
                update.http_push_enabled = json_optional_bool(*body, "httpPushEnabled", "http_push_enabled");
                if (body->isMember("defaultBranch")) {
                    update.default_branch = (*body)["defaultBranch"].asString();
                }

                auto repository = service.update(id, update);
                if (!repository.has_value()) {
                    respond_json(drogon::k404NotFound, error_json("repository not found"), std::move(callback));
                    return;
                }
                state->record_platform_audit(actor, "vcs", "repository.updated", repository->name);
                respond_json(drogon::k200OK, to_json(*repository), std::move(callback));
            } catch (const nexus::vcs::RepositoryException& error) {
                respond_repository_error(error, std::move(callback));
            }
        },
        {drogon::Get, drogon::Put, drogon::Delete});

    drogon::app().registerHandler(
        "/api/v1/vcs/{1}/refs",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& id) {
            std::string actor;
            if (!require_session(state, request, std::move(callback), &actor)) {
                return;
            }

            try {
                Json::Value payload(Json::arrayValue);
                for (const auto& ref : repository_service(*state).refs(id)) {
                    payload.append(to_json(ref));
                }
                respond_json(drogon::k200OK, std::move(payload), std::move(callback));
            } catch (const nexus::vcs::RepositoryException& error) {
                respond_repository_error(error, std::move(callback));
            }
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/vcs/{1}/tokens",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& id) {
            std::string actor;
            if (request->getMethod() == drogon::Get) {
                if (!require_session(state, request, std::move(callback), &actor)) {
                    return;
                }
            } else if (!require_mutation(state, request, std::move(callback), &actor)) {
                return;
            }

            try {
                auto service = repository_service(*state);
                if (request->getMethod() == drogon::Get) {
                    Json::Value payload(Json::arrayValue);
                    for (const auto& token : service.access_tokens(id)) {
                        payload.append(to_json(token));
                    }
                    respond_json(drogon::k200OK, std::move(payload), std::move(callback));
                    return;
                }

                auto body = request->getJsonObject();
                if (body == nullptr || !body->isMember("name")) {
                    respond_json(drogon::k400BadRequest, error_json("token name is required"), std::move(callback));
                    return;
                }
                nexus::vcs::AccessTokenCreateRequest create;
                create.repository_id = id;
                create.name = (*body)["name"].asString();
                create.scope = body->isMember("scope") ? (*body)["scope"].asString() : "read";
                if (body->isMember("expiresAt") && !(*body)["expiresAt"].asString().empty()) {
                    create.expires_at = (*body)["expiresAt"].asString();
                }

                const auto created = service.create_access_token(create);
                Json::Value payload(Json::objectValue);
                payload["token"] = to_json(created.token);
                payload["secret"] = created.secret;
                state->record_platform_audit(actor, "vcs", "token.created", created.token.repository_name + ":" + created.token.name);
                respond_json(drogon::k201Created, std::move(payload), std::move(callback));
            } catch (const nexus::vcs::RepositoryException& error) {
                respond_repository_error(error, std::move(callback));
            }
        },
        {drogon::Get, drogon::Post});

    drogon::app().registerHandler(
        "/api/v1/vcs/{1}/tokens/{2}",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& repository_id,
                const std::string& token_id) {
            std::string actor;
            if (!require_mutation(state, request, std::move(callback), &actor)) {
                return;
            }

            try {
                if (!repository_service(*state).revoke_access_token(repository_id, token_id)) {
                    respond_json(drogon::k404NotFound, error_json("token not found"), std::move(callback));
                    return;
                }
                state->record_platform_audit(actor, "vcs", "token.revoked", token_id);
                Json::Value payload(Json::objectValue);
                payload["ok"] = true;
                respond_json(drogon::k200OK, std::move(payload), std::move(callback));
            } catch (const nexus::vcs::RepositoryException& error) {
                respond_repository_error(error, std::move(callback));
            }
        },
        {drogon::Delete});

    drogon::app().registerHandler(
        "/api/v1/vcs/{1}/activity",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& id) {
            std::string actor;
            if (!require_session(state, request, std::move(callback), &actor)) {
                return;
            }

            try {
                Json::Value payload(Json::arrayValue);
                for (const auto& event : repository_service(*state).events(id)) {
                    payload.append(to_json(event));
                }
                respond_json(drogon::k200OK, std::move(payload), std::move(callback));
            } catch (const nexus::vcs::RepositoryException& error) {
                respond_repository_error(error, std::move(callback));
            }
        },
        {drogon::Get});

    drogon::app().registerHandler(
        "/api/v1/vcs/{1}/repair",
        [state](const drogon::HttpRequestPtr& request,
                std::function<void(const drogon::HttpResponsePtr&)>&& callback,
                const std::string& id) {
            std::string actor;
            if (!require_mutation(state, request, std::move(callback), &actor)) {
                return;
            }

            try {
                auto repository = repository_service(*state).repair_storage(id);
                if (!repository.has_value()) {
                    respond_json(drogon::k404NotFound, error_json("repository not found"), std::move(callback));
                    return;
                }
                state->record_platform_audit(actor, "vcs", "repository.repaired", repository->name);
                respond_json(drogon::k200OK, to_json(*repository), std::move(callback));
            } catch (const nexus::vcs::RepositoryException& error) {
                respond_repository_error(error, std::move(callback));
            }
        },
        {drogon::Post});
}

}  // namespace nexus::api
