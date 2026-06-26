# syntax=docker/dockerfile:1.7
# Endorium Nexus — multi-stage image containing every nexus-* binary plus the
# built frontend. One image, several roles: the orchestrator picks the role with
# the container `command` (nexus-api, entrypoint-dc.sh, nexus-pki-repo, ...).

# ---- Stage 1: frontend (static SPA served by nexus-api) --------------------
FROM node:20-bookworm-slim AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build   # -> /app/frontend/dist

# ---- Stage 2: backend build (C++ daemons) ---------------------------------
# kali-rolling matches the development host: Drogon 1.9.12 (whose streaming API
# nexus-api uses) and CMake modules compatible with the current CMake. (Debian
# bookworm has no drogon; trixie only has Drogon 1.9.0, missing that API.)
FROM kalilinux/kali-rolling AS backend
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build pkg-config \
        libargon2-dev libdrogon-dev libpqxx-dev libssl-dev libuv1-dev \
        nlohmann-json3-dev zlib1g-dev \
        # find_package(Drogon) requires the -dev package of every backend Drogon
        # was built with, even though Nexus itself only talks to libpq.
        libjsoncpp-dev uuid-dev libsqlite3-dev libmariadb-dev libhiredis-dev \
        libbrotli-dev libc-ares-dev libyaml-cpp-dev \
    && rm -rf /var/lib/apt/lists/*
WORKDIR /src
COPY CMakeLists.txt CMakePresets.json ./
COPY backend/ ./backend/
RUN cmake --preset release -DNEXUS_BUILD_TESTS=OFF \
    && cmake --build --preset release -j"$(nproc)"

# ---- Stage 3: runtime ------------------------------------------------------
# Same base as the build stage so the runtime .so versions match. The runtime
# libraries are pulled by installing the same -dev metapackages the build used
# (name-stable across rolling lib renames). git + dpkg-dev are needed at runtime
# by the VCS and APT-repository features. (Can be slimmed to runtime-only libs.)
FROM kalilinux/kali-rolling AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        libargon2-dev libdrogon-dev libpqxx-dev libssl-dev libuv1-dev zlib1g-dev \
        ca-certificates git dpkg-dev gnupg tini \
    && rm -rf /var/lib/apt/lists/*

COPY --from=backend /src/build/release/backend/nexus-api \
                    /src/build/release/backend/nexus-directory \
                    /src/build/release/backend/nexus-network \
                    /src/build/release/backend/nexus-pki-repo \
                    /src/build/release/backend/nexus-services \
                    /src/build/release/backend/nexusctl \
                    /usr/local/bin/
COPY --from=frontend /app/frontend/dist /opt/nexus/frontend/dist
COPY backend/sql /opt/nexus/sql
COPY docker/entrypoint-dc.sh docker/entrypoint-api.sh /usr/local/bin/
RUN chmod +x /usr/local/bin/entrypoint-dc.sh /usr/local/bin/entrypoint-api.sh \
    && mkdir -p /var/lib/nexus/state /var/lib/nexus/blob

WORKDIR /opt/nexus
ENV NEXUS_ENV=production \
    NEXUS_UI_DIST_DIR=/opt/nexus/frontend/dist \
    NEXUS_SQL_MIGRATIONS_DIR=/opt/nexus/sql/migrations \
    NEXUS_STATE_ROOT=/var/lib/nexus/state \
    NEXUS_BLOB_ROOT=/var/lib/nexus/blob

# tini = PID 1: forwards signals and reaps the daemons the DC entrypoint forks.
ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["nexus-api"]
