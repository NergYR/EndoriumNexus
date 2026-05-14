# ADR 0002: Postgres is the source of truth

The platform stores authoritative state in PostgreSQL and keeps certificates, repository blobs, package payloads, and backup artifacts on disk under a controlled blob root. Daemons observe state changes through domain revisions and refresh their in-memory views without requiring internal RPC between services.

