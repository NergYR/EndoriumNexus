#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BUILD_PRESET="${BUILD_PRESET:-dev}"
NPM="${NPM:-npm}"

usage() {
  cat <<'EOF'
Usage: ./run.sh [--preset <name>]

Environment variables:
  BUILD_PRESET     CMake preset to use (default: dev)
  NPM              npm binary to use (default: npm)
  NEXUS_UI_HOST    Frontend dev server host (default: 0.0.0.0)
  NEXUS_UI_PORT    Frontend dev server port (default: 5173)
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --preset)
      BUILD_PRESET="$2"
      shift 2
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown argument: $1" >&2
      usage >&2
      exit 1
      ;;
  esac
done

if [[ -f "${ROOT_DIR}/.env.local" ]]; then
  # Auto-export env vars loaded from .env.local so child services inherit them.
  set -a
  # shellcheck disable=SC1091
  source "${ROOT_DIR}/.env.local"
  set +a
fi

export NEXUS_ENV="${NEXUS_ENV:-development}"
export NEXUS_HTTP_HOST="${NEXUS_HTTP_HOST:-127.0.0.1}"
export NEXUS_HTTP_PORT="${NEXUS_HTTP_PORT:-8080}"
export NEXUS_BLOB_ROOT="${NEXUS_BLOB_ROOT:-var/blob}"
export NEXUS_STATE_ROOT="${NEXUS_STATE_ROOT:-var/state}"

if [[ -z "${NEXUS_ADMIN_PASSWORD_HASH:-}" ]]; then
  echo "[run] missing NEXUS_ADMIN_PASSWORD_HASH in environment/.env.local" >&2
  echo "[run] bootstrap with: ./build/dev/backend/nexusctl bootstrap-admin \"<strong-password>\"" >&2
  exit 1
fi

BUILD_DIR="${ROOT_DIR}/build/${BUILD_PRESET}/backend"
API_BIN="${BUILD_DIR}/nexus-api"
SERVICES_BIN="${BUILD_DIR}/nexus-services"

if [[ ! -x "${API_BIN}" || ! -x "${SERVICES_BIN}" ]]; then
  echo "[run] missing build artifacts for preset '${BUILD_PRESET}', starting full build"
  "${ROOT_DIR}/build.sh" --preset "${BUILD_PRESET}"
fi

if [[ ! -d "${ROOT_DIR}/frontend/node_modules" ]]; then
  echo "[run] missing frontend dependencies, installing"
  (
    cd "${ROOT_DIR}/frontend"
    "${NPM}" ci
  )
fi

mkdir -p "${ROOT_DIR}/${NEXUS_BLOB_ROOT}" "${ROOT_DIR}/${NEXUS_STATE_ROOT}"

declare -a PIDS=()

cleanup() {
  local pid
  for pid in "${PIDS[@]}"; do
    if kill -0 "${pid}" 2>/dev/null; then
      kill "${pid}" 2>/dev/null || true
    fi
  done
}

trap cleanup EXIT INT TERM

start_service() {
  local name="$1"
  local binary="$2"

  "${binary}" \
    > >(sed -u "s/^/[${name}] /") \
    2> >(sed -u "s/^/[${name}] /" >&2) &
  local pid=$!
  PIDS+=("${pid}")
  echo "[run] started ${name} (pid ${pid})"
}

echo "[run] starting backend services with preset '${BUILD_PRESET}'"
start_service "api" "${API_BIN}"
start_service "services" "${SERVICES_BIN}"

sleep 1
for pid in "${PIDS[@]}"; do
  if ! kill -0 "${pid}" 2>/dev/null; then
    echo "[run] one backend service stopped unexpectedly during startup" >&2
    exit 1
  fi
done

echo "[run] starting frontend dev server"
cd "${ROOT_DIR}/frontend"
"${NPM}" run dev -- --host "${NEXUS_UI_HOST:-0.0.0.0}" --port "${NEXUS_UI_PORT:-5173}"
