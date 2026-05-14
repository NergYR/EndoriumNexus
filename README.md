# Endorium Nexus

Endorium Nexus is a production-oriented infrastructure suite built around a C++20 backend and a React administration console. This repository initializes the platform as a single codebase with dedicated runtime daemons for API, directory/Kerberos, DNS/DHCP, and PKI/APT repository services.

## Topology

- `backend/`: C++20 workspace with shared libraries, daemons, a REST API, and the `nexusctl` operator CLI.
- `frontend/`: React + TypeScript + Tailwind admin console for operations teams.
- `ops/`: systemd units and deployment-oriented assets for Debian 12 hosts.
- `docs/adr/`: architecture decisions that explain the service split and production assumptions.
- `scripts/dev/`: local development helpers that do not depend on Docker Compose.

## Quick Start

1. Install system dependencies with `./scripts/dev/bootstrap-debian.sh`.
2. Copy `.env.example` to `.env.local` and adjust ports, database URL, and blob paths.
3. Install frontend dependencies with `make bootstrap`.
4. Build everything with `make build`.
5. Generate admin secrets with `./build/dev/backend/nexusctl bootstrap-admin "<strong-password>"` and set the resulting values in `.env.local`.
6. Run the development stack with `make run-dev`.

The API defaults to `http://127.0.0.1:8080` in development. The frontend runs on `http://127.0.0.1:5173` and proxies `/api` traffic to the backend.

## Root Scripts

If you prefer direct root-level scripts instead of `make`:

- `./build.sh`: complete build (frontend deps, CMake configure/build, frontend bundle).
- `./run.sh`: full runtime stack in dev mode (API + daemons + frontend dev server).

Both scripts support `--preset <name>` and default to `dev`.

## Current State

This initialization lays down the production repo shape, build system, CI, systemd units, seed migrations, core crypto/protocol libraries, a working Drogon API with SSE dashboards, and a React operations UI. The native LDAP/Kerberos, DNS/DHCP, PKI, and APT server listeners are scaffolded as dedicated daemons with shared runtime plumbing; protocol-complete implementations remain the next delivery slices.

## Service Activation

The control API stays available as the configuration surface, while the directory, network, and PKI/repository daemons are managed by `nexus-services`.

- Service activation flags are stored in `var/state/settings.json` and exposed in the Settings UI.
- New installations start with the module flags disabled.
- After configuring ports, domains, and secrets, enable the desired modules from the Settings page and save.
- The service supervisor reloads persisted settings and restarts managed daemons when configuration changes.
