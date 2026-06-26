#pragma once

#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>
#include <json/json.h>
#include <libpq-fe.h>
#include <memory>
#include <cstdlib>
#include <filesystem>
#include "platform_state.hpp"

using namespace nexus::api;

inline void register_vcs_handlers(std::shared_ptr<PlatformState> state) {
    drogon::app().registerHandler(
        "/api/v1/vcs",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            PGconn* conn = PQconnectdb(state->config().database_url.c_str());
            if (PQstatus(conn) != CONNECTION_OK) {
                PQfinish(conn);
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k500InternalServerError);
                callback(resp);
                return;
            }
 
            auto* res = PQexec(conn, "SELECT id, name, description, is_private, created_at FROM vcs_repositories ORDER BY created_at DESC");

            Json::Value payload(Json::arrayValue);
            if (PQresultStatus(res) == PGRES_TUPLES_OK) {
                int rows = PQntuples(res);
                for (int i = 0; i < rows; ++i) {
                    Json::Value repo;
                    repo["id"] = PQgetvalue(res, i, 0);
                    repo["name"] = PQgetvalue(res, i, 1);
                    repo["description"] = PQgetvalue(res, i, 2);
                    repo["is_private"] = std::string(PQgetvalue(res, i, 3)) == "t";
                    repo["created_at"] = PQgetvalue(res, i, 4);
                    payload.append(repo);
                }
            }
            PQclear(res);
            PQfinish(conn);

            auto resp = drogon::HttpResponse::newHttpJsonResponse(payload);
            callback(resp);
        },
        {drogon::Get, "nexus::RequireAuth"});

    drogon::app().registerHandler(
        "/api/v1/vcs",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback) {
            auto body = request->getJsonObject();
            if (!body || !body->isMember("name")) {
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k400BadRequest);
                callback(resp);
                return;
            }

            std::string name = (*body)["name"].asString();
            std::string desc = body->isMember("description") ? (*body)["description"].asString() : "";
            bool is_private = body->isMember("is_private") ? (*body)["is_private"].asBool() : true;

            PGconn* conn = PQconnectdb(state->config().database_url.c_str());
            if (PQstatus(conn) != CONNECTION_OK) {
                PQfinish(conn);
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k500InternalServerError);
                callback(resp);
                return;
            }

            const char* paramValues[3];
            paramValues[0] = name.c_str();
            paramValues[1] = desc.c_str();
            paramValues[2] = is_private ? "true" : "false";

            auto* res = PQexecParams(conn,
                                     "INSERT INTO vcs_repositories (name, description, is_private) VALUES ($1, $2, $3) RETURNING id",
                                     3, nullptr, paramValues, nullptr, nullptr, 0);

            if (PQresultStatus(res) != PGRES_TUPLES_OK) {
                PQclear(res);
                PQfinish(conn);
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k500InternalServerError);
                callback(resp);
                return;
            }
            PQclear(res);
            PQfinish(conn);

            // Create bare git repo
            std::filesystem::path git_root = state->config().blob_root / "git";
            std::filesystem::create_directories(git_root);
            std::string repo_path = (git_root / (name + ".git")).string();
            std::string cmd = "git init --bare " + repo_path;
            std::system(cmd.c_str());

            Json::Value payload;
            payload["status"] = "ok";
            auto resp = drogon::HttpResponse::newHttpJsonResponse(payload);
            callback(resp);
        },
        {drogon::Post, "nexus::RequireAuth"});

    drogon::app().registerHandler(
        "/api/v1/vcs/{id}",
        [state](const drogon::HttpRequestPtr& request, std::function<void(const drogon::HttpResponsePtr&)>&& callback, const std::string& id) {
            PGconn* conn = PQconnectdb(state->config().database_url.c_str());
            if (PQstatus(conn) != CONNECTION_OK) {
                PQfinish(conn);
                auto resp = drogon::HttpResponse::newHttpResponse();
                resp->setStatusCode(drogon::k500InternalServerError);
                callback(resp);
                return;
            }

            const char* paramValues[1] = { id.c_str() };

            // Find name to delete dir
            auto* check_res = PQexecParams(conn, "SELECT name FROM vcs_repositories WHERE id = $1", 1, nullptr, paramValues, nullptr, nullptr, 0);
            if (PQresultStatus(check_res) == PGRES_TUPLES_OK && PQntuples(check_res) > 0) {
                std::string name = PQgetvalue(check_res, 0, 0);
                std::filesystem::path repo_path = state->config().blob_root / "git" / (name + ".git");
                std::filesystem::remove_all(repo_path);
            }
            PQclear(check_res);

            auto* res = PQexecParams(conn, "DELETE FROM vcs_repositories WHERE id = $1", 1, nullptr, paramValues, nullptr, nullptr, 0);
            PQclear(res);
            PQfinish(conn);

            auto resp = drogon::HttpResponse::newHttpResponse();
            resp->setStatusCode(drogon::k200OK);
            callback(resp);
        },
        {drogon::Delete, "nexus::RequireAuth"});
}
