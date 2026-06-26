#!/usr/bin/env bash
# Domain-controller container: run the two daemons that must share one network
# identity — nexus-network (DNS/DHCP) and nexus-directory (LDAP/Kerberos/SMB/RPC)
# — and supervise them so the container exits (and the orchestrator restarts it)
# if either dies.
set -euo pipefail

net_pid=0
dir_pid=0

shutdown() {
    kill -TERM "${net_pid}" "${dir_pid}" 2>/dev/null || true
    wait "${net_pid}" "${dir_pid}" 2>/dev/null || true
}
trap shutdown TERM INT

nexus-network &
net_pid=$!
nexus-directory &
dir_pid=$!

echo "[dc] nexus-network pid ${net_pid}, nexus-directory pid ${dir_pid}"

# Exit as soon as either daemon stops; restart:unless-stopped brings us back.
wait -n "${net_pid}" "${dir_pid}"
echo "[dc] a DC daemon exited; shutting the container down for restart" >&2
shutdown
exit 1
