#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

BUILD_PRESET="${BUILD_PRESET:-dev}"
NPM="${NPM:-npm}"
CMAKE="${CMAKE:-cmake}"

usage() {
  cat <<'EOF'
Usage: ./build.sh [--preset <name>]

Environment variables:
  BUILD_PRESET   CMake preset to use (default: dev)
  NPM            npm binary to use (default: npm)
  CMAKE          cmake binary to use (default: cmake)
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

echo "[build] using preset: ${BUILD_PRESET}"

cd "${ROOT_DIR}/frontend"
echo "[build] installing frontend dependencies"
"${NPM}" ci

cd "${ROOT_DIR}"
echo "[build] configuring cmake"
"${CMAKE}" --preset "${BUILD_PRESET}"

echo "[build] building backend targets"
"${CMAKE}" --build --preset "${BUILD_PRESET}"

cd "${ROOT_DIR}/frontend"
echo "[build] building frontend bundle"
"${NPM}" run build

echo "[build] done"
