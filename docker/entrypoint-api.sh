#!/usr/bin/env bash
# Control-plane container: apply database migrations (idempotent) before the API
# starts, then exec the API. On boot nexus-api also seeds the default AD objects
# and bootstraps the krbtgt / DC service-account secrets the DC daemons rely on.
set -euo pipefail

echo "[api] applying database migrations"
for attempt in $(seq 1 30); do
    if nexusctl migrate; then
        break
    fi
    echo "[api] database not ready yet (attempt ${attempt}/30), retrying in 2s" >&2
    sleep 2
done

echo "[api] starting nexus-api"
exec nexus-api
