# syntax=docker/dockerfile:1.7
# Endorium Nexus — slim multi-stage image. Drogon is built from source (no distro
# packages it at the version Nexus needs) with the ORM disabled, so the runtime
# only carries libpq + a handful of libraries. One image, several roles: the
# orchestrator picks the role via the container `command`.

# ---- Stage 1: frontend (static SPA served by nexus-api) --------------------
FROM node:20-bookworm-slim AS frontend
WORKDIR /app/frontend
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build   # -> /app/frontend/dist

# ---- Stage 2: build Drogon (from source) + the C++ daemons -----------------
FROM debian:trixie AS backend
RUN apt-get update && apt-get install -y --no-install-recommends \
        build-essential cmake ninja-build pkg-config git ca-certificates \
        # Drogon's own dependencies (ORM/backends disabled below):
        libjsoncpp-dev uuid-dev libssl-dev zlib1g-dev \
        # Nexus dependencies:
        libpq-dev libuv1-dev libargon2-dev nlohmann-json3-dev \
    && rm -rf /var/lib/apt/lists/*

# Drogon ≥ 1.9.4 (Nexus uses newAsyncStreamResponse). ORM/examples/ctl off keeps
# the dependency surface — and the runtime image — minimal.
ARG DROGON_VERSION=v1.9.13
RUN git clone --depth 1 --branch "${DROGON_VERSION}" --recurse-submodules \
        https://github.com/drogonframework/drogon /tmp/drogon \
    && cmake -S /tmp/drogon -B /tmp/drogon/build -G Ninja \
        -DCMAKE_BUILD_TYPE=Release -DCMAKE_INSTALL_PREFIX=/usr/local \
        -DBUILD_ORM=OFF -DBUILD_EXAMPLES=OFF -DBUILD_CTL=OFF -DBUILD_TESTING=OFF \
    && cmake --build /tmp/drogon/build -j"$(nproc)" \
    && cmake --install /tmp/drogon/build \
    && rm -rf /tmp/drogon

WORKDIR /src
COPY CMakeLists.txt CMakePresets.json ./
COPY backend/ ./backend/
RUN cmake --preset release -DNEXUS_BUILD_TESTS=OFF \
    && cmake --build --preset release -j"$(nproc)"

# ---- Stage 3: runtime ------------------------------------------------------
# debian:trixie-slim (same release as the build stage → matching glibc/.so).
# git + dpkg-dev are needed at runtime by the VCS and APT-repository features.
FROM debian:trixie-slim AS runtime
RUN apt-get update && apt-get install -y --no-install-recommends \
        libjsoncpp26 libssl3t64 libuuid1 zlib1g libpq5 libargon2-1 libuv1t64 \
        libgssapi-krb5-2 ca-certificates git dpkg-dev gnupg tini \
    && rm -rf /var/lib/apt/lists/*

# Drogon/Trantor are built as static libraries and linked into the binaries, so
# no Drogon shared object is needed at runtime.
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
