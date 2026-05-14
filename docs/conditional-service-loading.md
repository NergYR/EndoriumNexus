# Conditional Service Loading

## Overview

The **nexus-services** supervisor now implements conditional service loading, which prevents services from starting until their configuration dependencies are satisfied. This ensures services only run when they have the necessary prerequisites to function properly.

## Service Prerequisites

### Network Service
- **Requirements**: 
  - At least 1 DNS zone configured
  - At least 1 DHCP pool configured
- **Why**: Network services need zone data and pools to serve DNS and DHCP requests
- **Database checks**:
  ```sql
  SELECT COUNT(*) FROM dns_zones;     -- Must be > 0
  SELECT COUNT(*) FROM dhcp_pools;    -- Must be > 0
  ```

### Directory Service  
- **Requirements**:
  - Database connection available
- **Why**: Directory service provides LDAP/Kerberos authentication infrastructure
- **Note**: Future enhancements could add LDAP configuration validation

### PKI Repository Service
- **Requirements**:
  - At least 1 certificate authority configured
- **Why**: PKI services need at least one CA to issue certificates
- **Database checks**:
  ```sql
  SELECT COUNT(*) FROM pki_authorities;  -- Must be > 0
  ```

## Activation Flow

```
User enables service flag in UI
         ↓
Feature flag saved to database
         ↓
Supervisor reconciliation loop (every 2s)
         ↓
Check: Is service flag enabled? ──NO──→ Stop service if running
         ↓ YES
Check: Are prerequisites met?
         ↓ NO
  Mark as BLOCKED (logged once)
  Skip startup attempt
         ↓ YES
  Check: Was previously blocked?
         ↓ YES
  Log "prerequisites now satisfied"
         ↓
  Spawn service process
  Add to running services map
```

## Logging

The supervisor provides clear logging at each stage:

```
[nexus-services] network is blocked (waiting for prerequisites)
[nexus-services] network cannot start: needs at least 1 DNS zone and 1 DHCP pool (found 0 zones, 1 pools)

... (user configures DNS zone in UI)

[nexus-services] network prerequisites now satisfied, attempting start
[nexus-services] network prerequisites met: 1 zones, 1 pools
[nexus-services] started network (pid 12345)
```

## State Tracking

The supervisor maintains a `blocked_services` map to track which services are waiting:

- When a service cannot start, it's marked as blocked
- The blocked state persists until prerequisites are met
- Log messages are printed only on **state transitions** to avoid log spam
- When settings are reloaded, the blocked_services map is cleared

## Integration with Feature Flags

1. **API** (`/api/v1/feature-flags`):
   - Persists flags in PostgreSQL `feature_flags` table
   - Syncs with `settings.json` as fallback

2. **Supervisor** (`nexus-services`):
   - Reads feature flags from `settings.json` every 2 seconds
   - Watches file modification time for changes
   - Applies conditional startup logic before spawning

3. **Frontend** (Settings page):
   - Shows module activation toggles
   - Disabled if prerequisites cannot be met
   - User creates DNS zones/DHCP pools via dedicated tabs

## Database Schema

The supervisor queries these tables to verify prerequisites:

```sql
-- DNS zones (network service prerequisite)
SELECT COUNT(*) FROM dns_zones;

-- DHCP pools (network service prerequisite)
SELECT COUNT(*) FROM dhcp_pools;

-- PKI authorities (pki-repo service prerequisite)
SELECT COUNT(*) FROM pki_authorities;
```

## Future Enhancements

1. **Health checks**: Add endpoint to verify service health after startup
2. **Dependency chain**: Model service dependencies (e.g., network requires DNS)
3. **Auto-disable**: Automatically disable services if critical resources are removed
4. **SSE updates**: Push service state changes to UI in real-time
5. **Readiness probes**: Check service ports are listening before marking as healthy
6. **Graceful degradation**: Allow services to start in degraded mode and become ready asynchronously

## Testing

To test conditional startup:

1. Enable network service flag (should be blocked)
2. Create a DNS zone via `/api/v1/dns/zones`
3. Create a DHCP pool via `/api/v1/dhcp/pools`
4. Observe supervisor logs showing "prerequisites now satisfied"
5. Verify network service process starts

## Troubleshooting

**Service won't start**:
- Check supervisor logs: `docker logs nexus-services`
- Verify database connection: `psql <database_url>`
- Confirm prerequisites exist:
  - Network: `SELECT * FROM dns_zones; SELECT * FROM dhcp_pools;`
  - PKI-repo: `SELECT * FROM pki_authorities;`

**Logs spammed with "cannot start"**:
- This shouldn't happen with the state-tracking mechanism
- If it does, check database connection stability
- Verify no concurrent supervisor instances are running

**Service still runs after flag disabled**:
- Supervisor checks every 2 seconds
- Service receives SIGTERM with 2-second grace period
- If not responding, receives SIGKILL after 2 seconds
