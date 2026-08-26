# Troubleshooting

The failures people actually hit, in the order they hit them. Commands here were
checked against the compose file and the code; the fuller Japanese guide is
[`トラブルシューティング.md`](../トラブルシューティング.md) (1,600 lines, 24 sections).

Container names, for reference:

```
kizashi-postgres  kizashi-nats-1/2/3  kizashi-api
kizashi-ingestion kizashi-detection   edr-frontend
```

## First moves

```bash
docker compose ps                        # who is unhealthy
curl -s http://localhost:8080/healthz    # {"status":"ok",...}
docker compose logs -f api               # the service that runs migrations
```

`/healthz` is at the **root**, not under `/api/v1`. So is `/metrics`.

---

## Login returns 503

The response body says a default admin password is set.

`ADMIN_PASSWORD` is unset, or matches the deny-list: `changeme`, `admin`,
`password`, `admin123`, `123456`, `edrplatform` (case-insensitive). Set a real
one in `.env` and restart `api`:

```bash
docker compose up -d --force-recreate api
```

There is no fixed default password to fall back on — this is by design.

## Login returns 401 with a password you are sure about

The environment-based fallback only accepts the emails `admin`,
`admin@localhost`, and `admin@example.com`. If a database user with your address
exists, its stored password wins and the fallback is never reached.

## An agent never appears

`/endpoints` stays empty, or the host shows `offline`.

**1. Can the endpoint reach the server?** Agents need outbound 8080 (API) and
9091 (gRPC ingestion). They do **not** need 3000 or 4222 — NATS is internal to
the server stack.

```bash
# from the endpoint
curl -v http://<server>:8080/healthz
nc -zv <server> 9091
```

**2. Is the service running?**

```bash
# Linux
sudo systemctl status edr-agent
sudo journalctl -u edr-agent -n 100 --no-pager

# macOS
sudo launchctl list | grep edr-agent
tail -n 100 /var/log/edr-agent/agent.log

# Windows
Get-Service -Name EDRAgent
```

Note the service the OS starts is the **watchdog**; it starts `edr-agent`. If
the agent keeps dying, the watchdog log (`/var/log/edr/watchdog.log`) is the one
that says why, and after a failed update it will have rolled the binary back.

**3. Common errors**

| Message | Cause | Fix |
|---|---|---|
| `agent token invalid` | enrolment token regenerated or never valid | issue a new one at `/agents/deploy`, reinstall |
| `TLS certificate verify failed` | server certificate changed or expired | redistribute the CA, or reinstall the agent |
| `heartbeat timeout` | network loss, or the agent process is wedged | restart the agent service |
| `connection refused: 9091` | ingestion service down or port blocked | `docker compose ps ingestion`, then check the firewall |

**4. Check what the agent thinks it should talk to**

```bash
cat /etc/edr/agent.toml                              # Linux / macOS
type C:\ProgramData\EDRAgent\agent.toml              # Windows
```

## Events arrive but no alerts fire

**Check the detection service is consuming.**

```bash
docker compose logs -f detection
```

**Check which engine owns the rule you edited.** There are two, and they are
independent:

| Engine | Where it lives | How you change it |
|---|---|---|
| Built-in Sigma | compiled into the API service | code change + rebuild |
| Database Sigma | `rules` table | edit in the console, reloads automatically |

Editing a database rule does nothing to its built-in namesake, and vice versa.
This is the single most common "my rule doesn't fire" cause.
[`検知ルールの二重管理とデプロイ.md`](../検知ルールの二重管理とデプロイ.md) has the
detail.

**Duplicate alerts across engines are merged by MITRE technique**, so a rule
firing in both places produces one alert — which can look like the one you
edited never ran.

## Screens are empty everywhere

Expected on a fresh install with no agents. If you have agents reporting and
screens are still blank, check the browser console for failed `/api/v1/...`
calls and the `api` logs for the matching error.

If screens show **plausible-looking data you never generated** — CVEs for
software you don't run, assignees with names you don't recognise, a threat model
named "EDRプラットフォーム脅威モデル v2.1" — then `NEXT_PUBLIC_USE_MOCK=true`
is set. Unset it and rebuild the frontend. That flag renders built-in sample
data and is for local development only.

## Postgres: "sorry, too many clients already"

The three app services each hold a connection pool; `api` alone keeps ~29 mostly
idle connections. The compose file raises `max_connections` to 100 via a CLI
flag on the `postgres` command, which outranks `postgresql.conf`. If you run
Postgres yourself, set it there too — the image default of 50 is not enough.

## Migrations failed on startup

`api` runs migrations on boot. A failure there stops the API and everything
downstream stalls. Read the actual error:

```bash
docker compose logs api | grep -i migrat
```

The most common cause is `api` racing a Postgres that is up but not yet
accepting connections; compose already gates on `service_healthy`, so if you
removed that condition, put it back.

## Dark-web monitoring screen is empty

It is **off by default** — it is opt-in because it reaches out to ransomwatch
and ransomware.live. Enable it with the overlay:

```bash
docker compose -f docker-compose.yml -f docker-compose.darkweb.yml up -d
```

With it on, `docker compose logs api | grep DarkWebScheduler` shows
`DarkWebScheduler: 開始`. Without it, you get
`DarkWebScheduler: 無効です`.

## A rule/screen references an endpoint that 404s

`docs/openapi.yaml` is the source of truth for what exists. Operations marked
`x-generated: true` are verified to exist (path, method, auth, path parameters)
but have no documented request/response shape. Everything in it is checked
against `router.go` in CI, so if the spec says an endpoint exists, it does.

## Getting more detail

```bash
docker compose logs -f              # everything
docker compose logs -f api          # REST/gRPC API, migrations, schedulers
docker compose logs -f ingestion    # agent event intake
docker compose logs -f detection    # rule evaluation
docker compose logs -f frontend
```

Log level is `LOG_LEVEL` (default `info`) in `docker-compose.yml`.
