#!/usr/bin/env bash
set -euo pipefail

sudo apt install -y \
  build-essential \
  cmake \
  ninja-build \
  pkg-config \
  libargon2-dev \
  libdrogon-dev \
  libpqxx-dev \
  libssl-dev \
  libuv1-dev \
  nlohmann-json3-dev \
  zlib1g-dev \
  npm

echo "System dependencies installed."

