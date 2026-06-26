#include "nexus/storage/database.hpp"

#include <libpq-fe.h>

#include <algorithm>
#include <cstring>
#include <fstream>
#include <set>
#include <sstream>
#include <stdexcept>

namespace nexus::storage {

namespace {

std::string read_file(const std::filesystem::path& path) {
    std::ifstream input(path);
    if (!input.is_open()) {
        throw std::runtime_error("unable to open migration: " + path.string());
    }
    std::ostringstream buffer;
    buffer << input.rdbuf();
    return buffer.str();
}

std::string pq_error(PGconn* connection, PGresult* result, const std::string& fallback) {
    const char* result_error = result != nullptr ? PQresultErrorMessage(result) : nullptr;
    if (result_error != nullptr && std::strlen(result_error) > 0) {
        return result_error;
    }

    const char* connection_error = connection != nullptr ? PQerrorMessage(connection) : nullptr;
    if (connection_error != nullptr && std::strlen(connection_error) > 0) {
        return connection_error;
    }

    return fallback;
}

}  // namespace

Database::Database(std::string connection_string)
    : connection_string_(std::move(connection_string)) {}

bool Database::configured() const {
    return !connection_string_.empty();
}

bool Database::ping() const {
    if (!configured()) {
        return false;
    }

    PGconn* connection = PQconnectdb(connection_string_.c_str());
    if (PQstatus(connection) != CONNECTION_OK) {
        PQfinish(connection);
        return false;
    }

    PGresult* result = PQexec(connection, "select 1");
    const bool ok = PQresultStatus(result) == PGRES_TUPLES_OK;
    PQclear(result);
    PQfinish(connection);
    return ok;
}

std::vector<std::filesystem::path> Database::pending_migrations(const std::filesystem::path& migrations_dir) const {
    std::vector<std::filesystem::path> migration_files;
    std::set<std::string> applied;

    PGconn* connection = PQconnectdb(connection_string_.c_str());
    if (PQstatus(connection) != CONNECTION_OK) {
        const std::string error = pq_error(connection, nullptr, "database connection failed");
        PQfinish(connection);
        throw std::runtime_error(error);
    }

    auto* create_result = PQexec(connection, R"SQL(
        create table if not exists schema_migrations (
            version text primary key,
            applied_at timestamptz not null default now()
        )
    )SQL");
    if (PQresultStatus(create_result) != PGRES_COMMAND_OK) {
        const std::string error = pq_error(connection, create_result, "unable to create schema_migrations");
        PQclear(create_result);
        PQfinish(connection);
        throw std::runtime_error(error);
    }
    PQclear(create_result);

    auto* select_result = PQexec(connection, "select version from schema_migrations");
    if (PQresultStatus(select_result) != PGRES_TUPLES_OK) {
        const std::string error = pq_error(connection, select_result, "unable to load applied migrations");
        PQclear(select_result);
        PQfinish(connection);
        throw std::runtime_error(error);
    }

    const int rows = PQntuples(select_result);
    for (int index = 0; index < rows; ++index) {
        applied.insert(PQgetvalue(select_result, index, 0));
    }
    PQclear(select_result);
    PQfinish(connection);

    for (const auto& entry : std::filesystem::directory_iterator(migrations_dir)) {
        if (entry.is_regular_file() && entry.path().extension() == ".sql") {
            if (!applied.contains(entry.path().filename().string())) {
                migration_files.push_back(entry.path());
            }
        }
    }

    std::sort(migration_files.begin(), migration_files.end());
    return migration_files;
}

void Database::apply_migrations(const std::filesystem::path& migrations_dir) const {
    if (!configured()) {
        throw std::runtime_error("database url not configured");
    }

    for (const auto& path : pending_migrations(migrations_dir)) {
        PGconn* connection = PQconnectdb(connection_string_.c_str());
        if (PQstatus(connection) != CONNECTION_OK) {
            const std::string error = pq_error(connection, nullptr, "database connection failed");
            PQfinish(connection);
            throw std::runtime_error(error);
        }

        auto* begin_result = PQexec(connection, "begin");
        if (PQresultStatus(begin_result) != PGRES_COMMAND_OK) {
            const std::string error = pq_error(connection, begin_result, "unable to begin migration transaction");
            PQclear(begin_result);
            PQfinish(connection);
            throw std::runtime_error(error);
        }
        PQclear(begin_result);

        auto* migration_result = PQexec(connection, read_file(path).c_str());
        if (PQresultStatus(migration_result) != PGRES_COMMAND_OK) {
            const std::string error = pq_error(connection, migration_result, "migration failed: " + path.filename().string());
            PQclear(migration_result);
            PQfinish(connection);
            throw std::runtime_error(error);
        }
        PQclear(migration_result);

        const std::string insert_sql = "insert into schema_migrations(version) values('" + path.filename().string() + "')";
        auto* insert_result = PQexec(connection, insert_sql.c_str());
        if (PQresultStatus(insert_result) != PGRES_COMMAND_OK) {
            const std::string error = pq_error(connection, insert_result, "unable to record migration: " + path.filename().string());
            PQclear(insert_result);
            PQfinish(connection);
            throw std::runtime_error(error);
        }
        PQclear(insert_result);

        auto* commit_result = PQexec(connection, "commit");
        if (PQresultStatus(commit_result) != PGRES_COMMAND_OK) {
            const std::string error = pq_error(connection, commit_result, "unable to commit migration transaction");
            PQclear(commit_result);
            PQfinish(connection);
            throw std::runtime_error(error);
        }
        PQclear(commit_result);
        PQfinish(connection);
    }
}

}  // namespace nexus::storage
