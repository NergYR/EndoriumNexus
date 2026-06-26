#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
BUILD_DIR="${ROOT_DIR}/build/dev"
API_BIN="${BUILD_DIR}/backend/nexus-api"
SERVICES_BIN="${BUILD_DIR}/backend/nexus-services"

if [[ ! -x "${API_BIN}" || ! -x "${SERVICES_BIN}" ]]; then
  echo "Missing backend binary: ${API_BIN}" >&2
  echo "Run 'make build' first." >&2
  exit 1
fi

mkdir -p "${ROOT_DIR}/var/blob" "${ROOT_DIR}/var/state"

if [[ -z "${NEXUS_ADMIN_PASSWORD_HASH:-}" ]] && [[ -f "${ROOT_DIR}/.env.local" ]]; then
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.env.local"
fi

if [[ -z "${NEXUS_ADMIN_PASSWORD_HASH:-}" ]]; then
  echo "Missing NEXUS_ADMIN_PASSWORD_HASH." >&2
  echo "Generate with: ./build/dev/backend/nexusctl bootstrap-admin \"<strong-password>\"" >&2
  exit 1
fi

cleanup() {
  if [[ -n "${API_PID:-}" ]] && kill -0 "${API_PID}" 2>/dev/null; then
    kill "${API_PID}"
  fi
}

trap cleanup EXIT INT TERM

(
  cd "${ROOT_DIR}"
  export NEXUS_ENV=development
  export NEXUS_HTTP_HOST="${NEXUS_HTTP_HOST:-127.0.0.1}"
  export NEXUS_HTTP_PORT="${NEXUS_HTTP_PORT:-18080}"
  export NEXUS_BLOB_ROOT="${NEXUS_BLOB_ROOT:-var/blob}"
  export NEXUS_STATE_ROOT="${NEXUS_STATE_ROOT:-var/state}"
  "${API_BIN}"
) &
API_PID=$!

(
  cd "${ROOT_DIR}"
  export NEXUS_ENV=development
  export NEXUS_HTTP_HOST="${NEXUS_HTTP_HOST:-127.0.0.1}"
  export NEXUS_HTTP_PORT="${NEXUS_HTTP_PORT:-18080}"
  export NEXUS_BLOB_ROOT="${NEXUS_BLOB_ROOT:-var/blob}"
  export NEXUS_STATE_ROOT="${NEXUS_STATE_ROOT:-var/state}"
  "${SERVICES_BIN}"
) &
SERVICES_PID=$!

cd "${ROOT_DIR}/frontend"
npm run dev -- --host 0.0.0.0
