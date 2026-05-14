# Repository Guidelines

## Project Structure & Module Organization
The repo is split by runtime concern. `backend/` contains the C++20 workspace: shared libraries under `backend/libs/` (`core`, `security`, `storage`, `jobs`, `protocol`) feed the Drogon API in `backend/apps/api/` plus the dedicated daemons in `backend/apps/directory/`, `backend/apps/network/`, `backend/apps/pki_repo/`, and the operator CLI in `backend/apps/nexusctl/`. SQL migrations live in `backend/sql/migrations/`. `frontend/` hosts the React + Vite admin console with route-oriented feature folders. Production assets such as systemd units live in `ops/`, while architectural decisions belong in `docs/adr/`.

## Build, Test, and Development Commands
Run `./scripts/dev/bootstrap-debian.sh` once on Debian 12 to install native dependencies. Use `make bootstrap` to install frontend packages and configure CMake, `make build` to compile backend targets and build the frontend, `make test` for backend unit tests plus frontend Vitest runs, `make lint` for TypeScript checks and frontend linting, `make package` for the CPack Debian package, and `make run-dev` to launch the API and Vite dev server together. To run only backend tests, use `ctest --test-dir build/dev --output-on-failure`.

## Coding Style & Naming Conventions
C++ targets use C++20, four-space indentation, and headers under `nexus/<domain>/...` matching library boundaries. Prefer small, composable domain structs over inheritance-heavy designs. TypeScript, CSS, JSON, YAML, and Markdown use two-space indentation. Keep Tailwind styling close to components, but put shared UI primitives in `frontend/src/components/`. Environment-driven behavior should be expressed through `.env` variables and `core::Config`, not scattered `std::getenv` calls.

## Testing Guidelines
Backend tests live in `backend/tests/` and should focus on deterministic protocol, crypto, and domain logic. Frontend tests belong next to the UI features they cover or under `frontend/src/test/` when shared. Any new mutation endpoint should have an audit-path test, and any new protocol helper should gain at least one unit test plus a negative-path case.

## Commit & Pull Request Guidelines
The repository was initialized empty, so no house commit convention exists yet. Use short imperative commit titles scoped by area, for example `backend: add DNS zone renderer` or `frontend: build dashboard cards`. Pull requests should summarize the user-visible capability, operational impact, new environment variables, and verification steps.

