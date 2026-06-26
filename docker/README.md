# Running Endorium Nexus in containers

Topology (**DC + control plane**):

```
            ┌──────────────── nexus-dc ────────────────┐
 LAN  ──────┤ nexus-network (DNS/DHCP)                  │  macvlan IP 192.168.1.50
 (Windows   │ nexus-directory (LDAP/Kerberos/SMB/RPC)   │  (own MAC, no host conflicts)
  client)   └───────────────────────────────────────────┘
                         │ backend bridge
   ┌─────────────┐  ┌─────────────────┐  ┌──────────────┐
   │ nexus-api   │  │ nexus-pki-repo  │  │ postgres:16  │
   │ + Web UI    │  └─────────────────┘  └──────────────┘
   └─────────────┘
```

The DC daemons share **one network identity** because Active Directory requires it
(SRV records resolve `dc1` → one A record → one IP serving DNS *and* LDAP/Kerberos/SMB).
A `macvlan` network gives that container its own LAN IP+MAC, so a Windows VM reaches
it on the standard AD ports with **no conflict** against the host's own DNS/SMB.

## 1. Configure

```bash
cp .env.docker.example .env.docker
# Edit .env.docker: set NEXUS_DC_IP (free LAN IP), MACVLAN_PARENT (host NIC),
# LAN_SUBNET/LAN_GATEWAY, and the DB password.
ip -o link            # find the bridged NIC name for MACVLAN_PARENT (e.g. eth0)
```

Generate the Web-UI admin hash and paste it into `.env.docker` as `NEXUS_ADMIN_PASSWORD_HASH`:

```bash
docker compose --env-file .env.docker run --rm --no-deps nexus-api \
  nexusctl bootstrap-admin 'YourStrongPassword'
```

## 2. Build & start

```bash
docker compose --env-file .env.docker build
docker compose --env-file .env.docker up -d
docker compose --env-file .env.docker ps
docker compose --env-file .env.docker logs -f nexus-dc nexus-api
```

The Web UI is on `http://<docker-host>:8080`. The DC is reachable on the LAN at
`NEXUS_DC_IP` on ports 53/88/135/389/445/464/636/3268.

## 3. Verify the DC (from any LAN host)

```bash
nslookup -type=SRV _ldap._tcp.dc._msdcs.endorium.local 192.168.1.50
ldapsearch -x -H ldap://192.168.1.50:389 -s base -b "" dnsHostName
```

## 4. Join a Windows client

1. Set the client's **primary DNS** to `NEXUS_DC_IP` (e.g. 192.168.1.50).
2. Set the AD `Administrator` password first (Web UI → Directory, or the setup
   wizard) so the KDC has its key material.
3. Join: `Add-Computer -DomainName endorium.local -Credential ENDORIUM\Administrator`.

## Publishing the image (GitHub Actions → Docker Hub)

`.github/workflows/docker-publish.yml` builds and pushes the image to Docker Hub
on every push to `main`/`master`, on `v*` tags, and on manual dispatch.

One-time setup in the GitHub repo (Settings → Secrets and variables → Actions):

| Name                 | Where                                  | Value                                    |
| -------------------- | -------------------------------------- | ---------------------------------------- |
| `DOCKERHUB_USERNAME` | **Variable** (recommended) *or* Secret | your Docker Hub namespace                |
| `DOCKERHUB_TOKEN`    | Secret                                 | a Docker Hub access token (Read & Write) |

`DOCKERHUB_USERNAME` works either as a repository **Variable** or a **Secret** (the
workflow falls back to the secret). A Variable is preferable so the username stays
readable in the build logs instead of being masked as `***`.

Create the access token at Docker Hub → Account Settings → Personal access tokens.
The image is published as `<DOCKERHUB_USERNAME>/endorium-nexus` with tags:
`latest` (default branch), the branch name, semver tags from `vX.Y.Z`, and the
short commit SHA. Then point `NEXUS_IMAGE` in `.env.docker` at it (and drop the
`build:` block from `docker-compose.yml`) to deploy the published image directly.

## Requirements & notes

- **macvlan needs a real/bridged L2 interface.** Run the Docker host as a Linux VM
  **bridged** to the LAN (not NAT), with the parent NIC allowed in promiscuous mode.
  macvlan is not supported reliably under WSL2 — use a dedicated Linux VM/host.
- By macvlan design the **Docker host itself cannot talk to the DC container** over
  the macvlan IP; that's fine here — other containers reach it via the `backend`
  bridge, and LAN clients reach it via the macvlan IP.
- State (the KEK that seals secrets) lives in the shared `nexus-state` volume so the
  API and the DC agree on the wrapped krbtgt/DC/account secrets.
- The image is built on `debian:trixie-slim` (~223 MB). Drogon is compiled from
  source (no distro packages the version Nexus needs) with the ORM disabled and
  linked statically, so the runtime only carries libpq + a few libraries.
```
