# Configuration reference

Everything is configured through environment variables read from `.env` by
`docker-compose.yml`. `.env.example` is the annotated template (its comments are
Japanese); this page is the English version, organised by "what breaks if you
leave it alone".

Variables are listed with the default that applies when the variable is **unset**.

## Must be set

The stack refuses to be useful without these.

| Variable | Default | What happens if you skip it |
|---|---|---|
| `POSTGRES_PASSWORD` | `edr_dev_password` | Works, but the database password is the one printed in a public repository |
| `JWT_SECRET` | — | `docker compose up` fails immediately; compose requires it |
| `ADMIN_PASSWORD` | — | Login returns **HTTP 503**. Also rejected if it matches `changeme`, `admin`, `password`, `admin123`, `123456`, `edrplatform` (case-insensitive) |

`JWT_SECRET` must be 32+ characters. Generate both with
`openssl rand -base64 48` / `openssl rand -base64 24`.

## Set these before exposing the server

| Variable | Default | Notes |
|---|---|---|
| `EDR_BASE_URL` | `http://localhost:8080` | Used in generated links. `http://` logs a warning at startup |
| `ALLOWED_ORIGINS` | empty | WebSocket CORS allow-list, comma-separated. **Empty means all origins are allowed** — fine for development, not for anything reachable |
| `TLS_CERT_FILE` / `TLS_KEY_FILE` | unset | Terminate TLS at the API instead of in front of it |
| `FRONTEND_URL` | `http://localhost:3000` | Where the console is reachable |

## Ports

| Variable | Default |
|---|---|
| `API_PORT` | 8080 |
| `GRPC_PORT` | 9090 |
| `INGESTION_PORT` | 9091 |
| `FRONTEND_PORT` | 3000 |
| `POSTGRES_PORT` | 5432 |
| `NATS_PORT` | 4222 |

## Database

| Variable | Default | Notes |
|---|---|---|
| `DATABASE_URL` | built from `POSTGRES_PASSWORD` | Owner role `edr`. Runs migrations (DDL) |
| `APP_DATABASE_URL` | falls back to `DATABASE_URL` | Runtime connection as the non-superuser `edr_app`. **Required to actually enforce row-level tenant isolation** — with the fallback, RLS is not in effect. Setup is in [`security/マルチテナント分離ハードニング.md`](../security/マルチテナント分離ハードニング.md) |
| `RUN_MIGRATIONS` | `true` in compose | Migrations run on `api` startup |

## Response and automation

| Variable | Default | Notes |
|---|---|---|
| `AUTO_RESPONSE_ENABLED` | `true` | Master switch for rule-driven automatic response |
| `AUTO_ISOLATE_MIN_SEVERITY` | `9` | Severity (1–10) at which a host is isolated automatically. Lowering this without tuning will isolate hosts on false positives |

## Outbound integrations

All optional. See [Outbound traffic](../../README.md#outbound-traffic) for what a
default install already reaches out to.

| Variable | Default | Enables |
|---|---|---|
| `DARKWEB_MONITOR_ENABLED` | `false` | Ransomware leak-site monitoring (ransomwatch, ransomware.live) |
| `TOR_PROXY_URL` | empty | SOCKS5 proxy for `.onion` reachability checks. Empty skips them |
| `DARKWEB_ALERT_SLACK_WEBHOOK_URL`, `DARKWEB_ALERT_WEBHOOK_URL`, `DARKWEB_ALERT_EMAIL_TO` | empty | Immediate notification on a dark-web hit |
| `VIRUSTOTAL_API_KEY` | empty | File/hash reputation lookups |
| `ABUSEIPDB_API_KEY`, `OTX_API_KEY` | empty | IP and IOC reputation lookups |
| `NVD_API_KEY` | empty | Raises the NVD CVE API rate limit from 5 to 50 requests / 30 s. The lookup happens either way |
| `SIGMAHQ_SYNC_ENABLED` | `false` | SigmaHQ community rule sync (also enabled by setting `GITHUB_TOKEN`) |
| `ES_URL`, `ES_USERNAME`, `ES_PASSWORD`, `ES_INDEX` | empty | Elasticsearch log shipping |
| `SMTP_HOST`, `SMTP_PORT`, `SMTP_USER`, `SMTP_PASS`, `SMTP_FROM` | example values | Mail delivery. `DIGEST_RECIPIENTS` for the alert digest |
| `OTEL_EXPORTER_OTLP_ENDPOINT`, `OTEL_SERVICE_NAME`, `OTEL_SAMPLE_RATIO` | empty / `edr-api` | Tracing |

To turn the ransomware leak-site monitor on, layer the overlay rather than
setting the variable by hand — it also brings up the Tor container the
reachability check needs:

```bash
docker compose -f docker-compose.yml -f docker-compose.darkweb.yml up -d
```

## Detection scaling

The detection consumers scale horizontally. Every replica binds the **same**
JetStream durable, so NATS load-balances events across them.

| Variable | Notes |
|---|---|
| `DETECTION_CONCURRENCY` | Must be identical on every replica |
| `DETECTION_MAX_ACK_PENDING` | Total in-flight cap **across all replicas**, not per replica |
| `DETECTION_ACK_WAIT_SEC` | Redelivery timeout |

`docker-compose.scale.yml` is the worked example.

## Agent distribution

| Variable | Default | Notes |
|---|---|---|
| `SERVER_URL` | `http://localhost:8080` | Baked into what agents are told to connect to |
| `AGENT_BIN_DIR` | `/downloads` | Where the server serves agent binaries from |
| `AGENT_LATEST_VERSION`, `AGENT_LATEST_URL`, `AGENT_LATEST_CHECKSUM` | empty | Advertised for agent self-update. Leave empty to disable update checks |

The agent's own configuration file (`/etc/edr/agent.toml`) is documented in
[`deploy/install/README.md`](../../deploy/install/README.md#configuration-reference).

## Development only

| Variable | Default | Notes |
|---|---|---|
| `NEXT_PUBLIC_USE_MOCK` | `false` | Console renders built-in sample data where the API returns nothing. **Never set this in production** — the sample data is fabricated (invented CVEs, made-up assignees, fictional metrics) and is indistinguishable from real data on screen |
| `ENABLE_PPROF` | `false` | Exposes pprof endpoints |
| `SEED_E2E_MFA_USER` | unset | Seeds an MFA test user. Gated so production never creates it |
