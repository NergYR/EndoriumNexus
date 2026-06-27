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

## Deploying on an AlmaLinux host

AlmaLinux is a real Linux host (not WSL2), so `macvlan` works and a Windows client
can actually join the domain. The host must sit on the same LAN the clients use.

### 0a. Install Docker Engine

AlmaLinux ships Podman, not Docker — install Docker CE from the official repo:

```bash
sudo dnf -y install dnf-plugins-core
sudo dnf config-manager --add-repo https://download.docker.com/linux/centos/docker-ce.repo
sudo dnf -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"      # log out/in so the group applies
docker compose version               # sanity check
```

### 0b. AlmaLinux specifics

- **SELinux** (enforcing by default): the stack uses *named volumes* only, which
  Docker labels automatically — nothing to do. (If you switch to bind mounts, add
  `:Z` to them.)
- **firewalld**: open the Web-UI port on the host. The DC's AD ports live on the
  container's own macvlan IP, *not* the host, so they need no firewall rule:
  ```bash
  sudo firewall-cmd --permanent --add-port=8080/tcp
  sudo firewall-cmd --reload
  ```
- **macvlan parent NIC**: find the LAN interface and put it in `MACVLAN_PARENT`:
  ```bash
  ip -o -4 addr show          # e.g. ens18 / eth0 with the host's LAN IP
  ```
  If the AlmaLinux host is itself a VM, enable **promiscuous mode / MAC spoofing**
  on its virtual NIC at the hypervisor, otherwise the macvlan IP is unreachable.

### 0c. Get the project on the host

```bash
git clone <your-repo-url> EndoriumNexus && cd EndoriumNexus
```
(Or just copy `docker-compose.yml` and `.env.docker.example` — everything else is
baked into the image.)

To deploy the **published image** instead of building locally, set `NEXUS_IMAGE`
in `.env.docker` to `<dockerhub-namespace>/endorium-nexus:latest` and run
`docker compose --env-file .env.docker pull` before `up` (see step 2).

Then follow steps 1–4 below.

## 1. Configure

```bash
cp .env.docker.example .env.docker
# Edit .env.docker: set NEXUS_DC_IP (free LAN IP), MACVLAN_PARENT (host NIC),
# LAN_SUBNET/LAN_GATEWAY, and the DB password.
ip -o link            # find the bridged NIC name for MACVLAN_PARENT (e.g. ens18)
```

Generate the Web-UI admin hash and paste it into `.env.docker` as `NEXUS_ADMIN_PASSWORD_HASH`
(the first run builds or pulls the image, so it may take a few minutes):

```bash
docker compose --env-file .env.docker run --rm --no-deps nexus-api \
  nexusctl bootstrap-admin 'YourStrongPassword'
```

Copy the printed `NEXUS_ADMIN_PASSWORD_HASH=...` line into `.env.docker`.

## 2. Build (or pull) & start

```bash
# Either build the image on the host…
docker compose --env-file .env.docker build
# …or, if NEXUS_IMAGE points at a published image, pull it instead:
# docker compose --env-file .env.docker pull

docker compose --env-file .env.docker up -d
docker compose --env-file .env.docker ps
docker compose --env-file .env.docker logs -f nexus-dc nexus-api
```

The Web UI is on `http://<host-lan-ip>:8080`. The DC is reachable on the LAN at
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

## 5. Operations

```bash
# Update to a newer image (when NEXUS_IMAGE points at Docker Hub)
docker compose --env-file .env.docker pull
docker compose --env-file .env.docker up -d

# Logs / status / restart
docker compose --env-file .env.docker logs -f nexus-dc
docker compose --env-file .env.docker restart nexus-dc
docker compose --env-file .env.docker ps

# Back up the database and the secret-sealing key (KEK)
docker compose --env-file .env.docker exec -T postgres \
  pg_dump -U endorium endorium_nexus | gzip > nexus-db-$(date +%F).sql.gz
docker run --rm -v endorium-nexus_nexus-state:/state -v "$PWD":/out alpine \
  tar czf /out/nexus-state-$(date +%F).tgz -C /state .
```

> The `nexus-state` volume holds the KEK that seals krbtgt/DC/account secrets —
> back it up together with the database, and never recreate it independently.

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
