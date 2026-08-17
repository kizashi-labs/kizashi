# Getting started

Server running, first endpoint reporting. About 30 minutes, most of it waiting
for images to build.

This is the English path through
[`サーバーインストール手順.md`](../サーバーインストール手順.md) and
[`エージェントインストール手順.md`](../エージェントインストール手順.md). Where
this page and those disagree, this page was checked against the code.

## 1. What you need

**Server host**

| Endpoints | CPU | RAM | Disk |
|---|---|---|---|
| up to 50 | 2 cores | 4 GB | 100 GB SSD |
| up to 500 | 4 cores | 8 GB | 500 GB SSD |
| 500+ | 8+ cores | 16+ GB | 1 TB+ SSD |

Docker 24.0+ and Docker Compose 2.20+. Linux is the tested platform
(Ubuntu 22.04 LTS / Debian 12).

**Ports the server listens on**

| Port | Purpose |
|---|---|
| 3000 | Web console |
| 8080 | REST API |
| 9090 | gRPC — agent enrolment |
| 9091 | gRPC — event ingestion |

Endpoints need **outbound** access to 8080 and 9091 only. They never need to
reach the console.

## 2. Bring the stack up

```bash
git clone https://github.com/kizashi-labs/kizashi.git
cd kizashi
cp .env.example .env
```

Set three values in `.env`:

| Variable | Rule |
|---|---|
| `POSTGRES_PASSWORD` | anything, but not empty |
| `JWT_SECRET` | 32+ characters. `openssl rand -base64 48` |
| `ADMIN_PASSWORD` | `openssl rand -base64 24`. Weak values are rejected — see below |

`ADMIN_PASSWORD` is checked against a deny-list (`changeme`, `admin`,
`password`, `admin123`, `123456`, `edrplatform`, case-insensitive). If it
matches one of those, or is unset, **login returns HTTP 503** with a message
telling you to set it. This is deliberate: there is no default password to
forget to change.

```bash
docker compose up -d
```

The first run builds images locally and takes several minutes. Database
migrations run automatically when the `api` service starts
(`RUN_MIGRATIONS=true` in `docker-compose.yml`).

Check it came up:

```bash
docker compose ps            # everything healthy or running
curl http://localhost:8080/healthz
# {"status":"ok","time":"..."}
```

## 3. Log in

Open `http://localhost:3000`.

| Field | Value |
|---|---|
| Email | `admin@example.com` (`admin` and `admin@localhost` also work) |
| Password | whatever you set as `ADMIN_PASSWORD` |

There is no fixed default password. On first startup, if the `users` table is
empty, an `admin@example.com` row is seeded with the `ADMIN_PASSWORD` you set.
The same value also backs an environment-based fallback login, so you can get in
before any database user exists.

> The console's text is Japanese. Screen paths in this guide (`/endpoints`,
> `/alerts`) are stable and in English — navigate by URL if the labels don't
> help you.

## 4. Get an enrolment token

Open `/agents/deploy` (or `/admin/agent-deployment`) and generate a token. It is
issued by `POST /api/v1/settings/enrollment-token`, so you can also do it from
the API:

```bash
TOKEN=$(curl -s -X POST http://localhost:8080/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"admin@example.com","password":"'"$ADMIN_PASSWORD"'"}' | jq -r .token)

curl -s -X POST http://localhost:8080/api/v1/settings/enrollment-token \
  -H "Authorization: Bearer $TOKEN" | jq -r .enrollment_token
```

Regenerating invalidates the previous token. Agents already enrolled keep
working — the token is only used at first contact.

## 5. Install an agent

The installers take **environment variables**, not flags.

**Linux / macOS**

```bash
sudo SERVER_URL=https://edr.example.com ENROLLMENT_TOKEN=<token> \
  ./deploy/install/install.sh
```

**Windows (PowerShell as Administrator)**

```powershell
$env:SERVER_URL = 'https://edr.example.com'
$env:ENROLLMENT_TOKEN = '<token>'
.\deploy\install\install.ps1
```

The installer downloads `edr-agent` and `edr-watchdog` from your server,
verifies their SHA-256, writes `/etc/edr/agent.toml`, and registers the
**watchdog** as the service. The watchdog starts and supervises the agent, and
rolls back a binary update that crashes within 60 seconds of start.

Full reference — install layout, manual install, updating, uninstalling:
[`deploy/install/README.md`](../../deploy/install/README.md).

### Binaries you have to build yourself

No pre-built binaries ship in this repository; the server builds them into
`/downloads` at image build time. Two targets are missing from that build:

| Target | Why | How |
|---|---|---|
| `darwin/arm64` | the image builds `darwin/amd64` only | `cd agent && make build-darwin-arm64`, rename to `edr-agent-darwin-arm64` |
| Linux **with eBPF** | the build stage has no clang, so Linux is compiled *without* `-tags ebpf` | generate CO-RE bindings with `agent/ebpf/Makefile`, then `go build -tags ebpf -o edr-agent-linux-amd64 ./cmd/agent` |

The default Linux agent therefore uses **procfs polling**, not eBPF. It works,
but it misses short-lived processes.

## 6. Confirm it worked

```bash
# Linux
sudo systemctl status edr-agent
sudo journalctl -u edr-agent -f

# macOS
sudo launchctl list | grep edr-agent
tail -f /var/log/edr-agent/agent.log
```

In the console, `/endpoints` should show the host as `online` within a minute or
two. If it doesn't, start at
[Troubleshooting → agent not appearing](troubleshooting.md#an-agent-never-appears).

## 7. Before you rely on it

- **Auto-isolation is gated behind `AUTO_ISOLATE_MIN_SEVERITY` (default `9`).**
  Read [`自動隔離・SOAR設定ガイド.md`](../自動隔離・SOAR設定ガイド.md) before
  lowering it. An over-eager threshold isolates hosts on false positives, and
  recovering an isolated host takes longer than you expect.
- **Two Sigma engines exist** — built-in rules compiled into the API service,
  and database rules you can edit at runtime. Editing one does not change the
  other. [`検知ルールの二重管理とデプロイ.md`](../検知ルールの二重管理とデプロイ.md)
  explains which is which; you will need it the first time an edited rule
  doesn't fire.
- **Kernel-level prevention is an unvalidated proof of concept.** Detection and
  response are the supported paths. See the warning in the top-level
  [`README.md`](../../README.md).
- **Check what talks to the internet.** A default install fetches public IOC
  blocklists and CVE data. The complete list, with off switches, is in
  [Outbound traffic](../../README.md#outbound-traffic).
