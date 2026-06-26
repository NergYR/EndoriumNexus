#!/usr/bin/env bash
# Launch the Nexus AD daemons on the STANDARD AD ports bound to all interfaces so
# a real Windows client (e.g. a bridged VM) can join the domain.
#
# Must run as root: the AD ports (53/88/135/389/445/464/636/3268) are privileged.
#   sudo ./scripts/dev/run-ad-standard.sh
#
# The Windows client must use this host (192.168.1.111) as its PRIMARY DNS and
# join the realm ENDORIUM.LOCAL / domain endorium.local.
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "${ROOT_DIR}"

if [[ "${EUID}" -ne 0 ]]; then
  echo "[ad] must run as root (privileged ports). Use: sudo $0" >&2
  exit 1
fi

DC_ADDRESS="${NEXUS_AD_DC_ADDRESS:-192.168.1.111}"

# --- environment -----------------------------------------------------------
export NEXUS_ENV="${NEXUS_ENV:-development}"
export NEXUS_DATABASE_URL="${NEXUS_DATABASE_URL:-postgresql://endorium:endorium@127.0.0.1:5432/endorium_nexus}"
export NEXUS_DOMAIN="${NEXUS_DOMAIN:-endorium.local}"
export NEXUS_DIRECTORY_REALM="${NEXUS_DIRECTORY_REALM:-ENDORIUM.LOCAL}"
export NEXUS_STATE_ROOT="${NEXUS_STATE_ROOT:-var/state}"
export NEXUS_BLOB_ROOT="${NEXUS_BLOB_ROOT:-var/blob}"
export NEXUS_SQL_MIGRATIONS_DIR="${NEXUS_SQL_MIGRATIONS_DIR:-${ROOT_DIR}/backend/sql/migrations}"
# Standard AD ports, bound to the LAN IP specifically. Binding the exact host IP
# (not 0.0.0.0) avoids colliding with the WSL mirrored-mode DNS tunneling resolver
# that already holds 10.255.255.254:53, so our DNS can own <LAN_IP>:53.
export NEXUS_AD_PORT_PROFILE="standard"
export NEXUS_HTTP_HOST="${DC_ADDRESS}"
export NEXUS_AD_DC_HOST="${NEXUS_AD_DC_HOST:-dc1}"
export NEXUS_AD_DC_ADDRESS="${DC_ADDRESS}"

BIN="${ROOT_DIR}/build/dev/backend"
LOG_DIR="${ROOT_DIR}/var/log"
mkdir -p "${LOG_DIR}"

echo "[ad] stopping any running directory/network daemons"
pkill -f "${BIN}/nexus-directory" 2>/dev/null || true
pkill -f "${BIN}/nexus-network" 2>/dev/null || true
sleep 1

echo "[ad] DC advertised at ${NEXUS_AD_DC_HOST}.${NEXUS_DOMAIN} -> ${DC_ADDRESS} (standard ports, bind 0.0.0.0)"

"${BIN}/nexus-network"   > "${LOG_DIR}/network.log"   2>&1 &
echo "[ad] nexus-network (DNS/DHCP) pid $!"
"${BIN}/nexus-directory" > "${LOG_DIR}/directory.log" 2>&1 &
echo "[ad] nexus-directory (LDAP/Kerberos/SMB/RPC) pid $!"

sleep 2
echo "[ad] listening sockets:"
ss -tlnp 2>/dev/null | grep -E ":53 |:88 |:135 |:389 |:445 |:464 |:636 |:3268 " || true
ss -ulnp 2>/dev/null | grep -E ":53 |:88 |:389 |:464 " || true
echo "[ad] logs: ${LOG_DIR}/{network,directory}.log   (Ctrl-C does NOT stop the daemons; use: sudo pkill -f nexus-directory nexus-network)"
