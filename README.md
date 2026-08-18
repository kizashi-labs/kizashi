# Kizashi

**兆し** — *the first sign, before anything has happened.*

A self-hostable, open source Endpoint Detection and Response (EDR) platform.
Cross-platform agent, real-time detection engine, and a SOC console — in one repository.

[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.25%2B-00ADD8?logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/agent-Windows%20%7C%20Linux%20%7C%20macOS-lightgrey)](#agent)

---

## What it is

Kizashi collects endpoint telemetry — process, network, file, DNS, and OS-specific
events — streams it to a self-hosted server over mTLS gRPC, evaluates it against
Sigma rules, YARA rules, IOC feeds, statistical baselines and stateful behavioural
detectors, and escalates correlated alerts into incidents you can work in the
included web console.

Everything runs on infrastructure you control. **No endpoint telemetry ever leaves
your network** — events, alerts and incidents stay in your Postgres. A default
install does make a small number of outbound *fetches* (public threat-intel
blocklists, CVE lookups); every one of them is listed and switchable in
[Outbound traffic](#outbound-traffic) below.

| Component | Stack |
|---|---|
| Agent | Go. Linux eBPF (CO-RE), Windows ETW, macOS ESF / process polling |
| Server | Go. REST + gRPC API, separate ingestion and detection services |
| Storage | PostgreSQL / TimescaleDB, NATS JetStream |
| Console | Next.js 14 (App Router), React 18, TypeScript, Tailwind |

**Event flow:** agent → gRPC ingestion → Postgres + NATS → detection pipeline
(Sigma / YARA / IOC / anomaly) → correlation → incidents → pushed to the console
over WebSocket.

## Quick start

```bash
git clone https://github.com/kizashi-labs/kizashi.git && cd kizashi
cp .env.example .env
```

Edit `.env` and set `POSTGRES_PASSWORD`, `JWT_SECRET` (32+ characters) and
`ADMIN_PASSWORD`. Weak values such as `changeme` are rejected at startup on purpose.

```bash
docker compose up -d
```

The console is at `http://localhost:3000`. Other ports: API `8080` (REST) / `9090`
(gRPC), ingestion `9091`, detection `8083`, PostgreSQL `5432`, NATS `4222`.

Database migrations are applied automatically on API startup.

Agent installation: [`deploy/install/README.md`](deploy/install/README.md) (English)
or [`docs/エージェントインストール手順.md`](docs/エージェントインストール手順.md) (Japanese).
Where the binaries come from — and the two targets you have to build yourself — is
covered under [Agent](#getting-the-agent-binaries).

A longer walkthrough, a configuration reference and a troubleshooting guide are in
**[`docs/en/`](docs/en/README.md)**. That page also indexes the Japanese-only
documents, so you can see what exists even if you cannot read it.

## Detection

Three independent evaluation paths run against the same event stream:

1. **Built-in Sigma rules** (Go, compiled into the API service) — MITRE ATT&CK mapped
2. **Database Sigma rules** (`rules` table, seeded by migrations) — editable at runtime,
   reloaded automatically or on demand
3. **Stateful detectors** — port scanning, DNS tunnelling and beaconing, credential
   access, lateral movement, ransomware file-burst correlation, kill-chain
   correlation. These are fed flattened events directly and are neither Sigma nor
   YARA based

Plus YARA scanning (pure Go, no cgo), IOC matching against IP / domain / hash / URL,
an Isolation Forest anomaly model, and process ancestry analysis.

Duplicate alerts across paths are merged by MITRE technique. See
[`docs/検知ルールの二重管理とデプロイ.md`](docs/検知ルールの二重管理とデプロイ.md) for how the two engines differ —
this matters when a rule you edited does not fire.

## Response

- **Network isolation** — iptables / nftables / pfctl / netsh, applied from the console
- **File quarantine** — `O_NOFOLLOW`, TOCTOU-hardened
- **Process termination** — dispatched to the agent over NATS JetStream
- **Playbooks** — conditional multi-step automation
- **Live response** — interactive command sessions over SSE

Rule-driven automatic isolation is available and gated behind
`AUTO_ISOLATE_MIN_SEVERITY` (default `9`). **Read the tuning notes before enabling it
in production** — an over-eager threshold will isolate hosts on false positives, and
recovering an isolated host takes longer than you expect.

## Outbound traffic

Nothing you collect is ever uploaded — no telemetry, no alerts, no file contents,
no usage analytics. What follows is the complete list of connections the server
opens *outwards*, and what each one is on by default.

**On out of the box:**

| What | Where to | When | Turn it off with |
|---|---|---|---|
| Public IOC blocklists | `*.abuse.ch` (URLhaus, MalwareBazaar, Feodo, ThreatFox), `reputation.alienvault.com`, `cinsscore.com`, `lists.blocklist.de`, `raw.githubusercontent.com` (IPsum) | every 6–24 h per feed | `THREAT_FEED_SYNC_ENABLED=false` stops all of them. To drop one feed, disable it in **Threat Intelligence → Feeds** or `UPDATE threat_feeds SET is_active = FALSE WHERE …;` |
| CVE lookups | `services.nvd.nist.gov` | every 6 h, and only for software your agents actually report | `NVD_LOOKUP_ENABLED=false` (falls back to a small built-in CVE table) |

These send a query, not your data: a blocklist fetch is a plain GET, and the CVE
lookup sends a software product name (e.g. `openssl`). Neither carries hostnames,
users, event contents or hashes from your estate. If even that is unacceptable in
your environment, turn both off — detection continues to run against the built-in
Sigma, YARA and behavioural paths, though IOC matching and CVE detection lose most
of their input.

They are on by default because they *are* the input to IOC matching and
vulnerability detection; shipping them off would mean a fresh install detects far
less than it appears to. That is a deliberate choice, not an oversight — and both
switches above turn it off in one line.

**Off unless you turn it on:**

| What | Where to | Enable with |
|---|---|---|
| Dark web / ransomware leak-site monitoring | `raw.githubusercontent.com` (ransomwatch), `api.ransomware.live`, Tor SOCKS5 for `.onion` reachability | `docker compose -f docker-compose.yml -f docker-compose.darkweb.yml up -d` (`DARKWEB_MONITOR_ENABLED=true`) |
| File / hash reputation | `virustotal.com`, `abuseipdb.com`, `otx.alienvault.com` | `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` / `OTX_API_KEY` |
| SigmaHQ community rule sync | `github.com` | `SIGMAHQ_SYNC_ENABLED=true` |
| SIEM / log forwarding | your Elasticsearch | `ES_URL` |
| Mail, Slack, generic webhooks | your SMTP server / the webhook URLs you supply | `SMTP_HOST`, `*_SLACK_WEBHOOK_URL`, `*_WEBHOOK_URL` |
| Tracing | your OTLP collector | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| Cloud posture (CSPM) polling | AWS / Azure / GCP APIs | cloud credentials configured in the console |
| Agent update checks | wherever you host the binaries | `AGENT_LATEST_URL` |

The dark web monitor used to be **on** by default and synced on startup. It is
opt-in as of this change, and the Tor container has moved out of the base compose
file into `docker-compose.darkweb.yml` so the default stack no longer ships it.

## Agent

| OS | Sensor | Status |
|---|---|---|
| Linux | eBPF CO-RE — process, network, file, fileless exec, shared-object load | Production |
| Windows | ETW — process, network, registry, WMI, named pipes, PowerShell | Production |
| macOS | Endpoint Security Framework (build tag) or process polling | ESF requires an Apple entitlement |

A watchdog process supervises the agent and is registered with systemd, Windows
Service Manager, or launchd. The agent ring-buffers events while offline and
reconnects with exponential backoff.

**Shared-object (`image_load`) telemetry on Linux covers `dlopen` only.** The
collector is a uprobe on libc's `dlopen`
(`internal/platform/linux/library_loader.go`), so it reports what an
already-running process pulls in — plugins, PAM/NSS modules, anything loaded at
runtime. Libraries resolved by `ld.so` when a program starts are **not** reported,
which makes this narrower than the Windows ETW image-load stream. Rule the two
apart: the Windows side-loading rule keys on an unsigned/invalid signature, which
does not exist on Linux, so Linux has its own rule keyed on shared objects loaded
from world-writable paths (`/tmp`, `/var/tmp`, `/dev/shm`, `/run/shm`).

The LSM-based sensors below are a different matter — those genuinely ship nothing.

### Getting the agent binaries

No pre-built binaries are shipped in this repository. They do not need to be:
building the API image cross-compiles the agent and the watchdog and bakes them
into the image at `AGENT_BIN_DIR` (`/downloads`), so `docker compose up -d` leaves
you with a server that can already hand out agents. The installer endpoints and the
console's installer page serve them from there, together with `.sha256` sidecars.

**The binaries are not code signed.** Windows SmartScreen and macOS Gatekeeper will
say so. Sign them yourself if you are deploying beyond a lab —
[`docs/エージェントコード署名.md`](docs/エージェントコード署名.md) describes the procedure.

Two targets are deliberately *not* in the image, and both fall back to a `404` with
manual instructions. Build them yourself and drop them into `AGENT_BIN_DIR` if you
need them:

| Target | Why it is missing | How to build |
|---|---|---|
| `darwin/arm64` (Apple Silicon) | the image builds `darwin/amd64` only | `cd agent && make build-darwin-arm64`, then rename to `edr-agent-darwin-arm64` |
| Linux **with eBPF** | the image build stage has no clang, so the Linux agent is compiled *without* `-tags ebpf` | generate the CO-RE bindings with `agent/ebpf/Makefile`, then `go build -tags ebpf -o edr-agent-linux-amd64 ./cmd/agent` |

> **The Linux agent served out of the box has no eBPF sensors.** It falls back to
> procfs polling, which sees fewer short-lived processes and none of the eBPF-only
> file, library and LSM telemetry. If you want the Linux coverage described in the
> table above, you have to supply the `-tags ebpf` build yourself.

Filenames matter: the download endpoint looks for exactly
`edr-agent-<os>-<arch>` (`.exe` on Windows) inside `AGENT_BIN_DIR`.

> ### ⚠️ Kernel-level prevention is an unverified proof of concept
>
> This repository contains a Windows WDK kernel driver
> (`agent/driver/windows/prevention/`) and Linux eBPF LSM hooks
> (`agent/ebpf/prevention_lsm.bpf.c`, `tamper_lsm.bpf.c`, `credaccess_lsm.bpf.c`)
> intended for pre-execution blocking and agent self-protection.
>
> **Neither is wired into production builds, and neither has been validated on real
> workloads.** They are published as research artifacts so the approach can be
> reviewed and built upon. Do not deploy them to machines you care about, and do not
> assume prevention is active because the code is present. Detection and response
> are the supported paths.

## What is not included

Kizashi is the open source core. The following are developed separately and are not
part of this repository:

enterprise SSO (SAML / OIDC / LDAP) · mobile device management (MDM) and mobile
threat detection · AI-assisted triage and investigation · automatic SigmaHQ
community rule synchronisation · managed update delivery · billing and license
management · commercial support

Compliance evaluation, scorecards, CSPM, cloud runtime security, XDR, SIEM
connectors and deception **are** included here.

If you need any of these, or you want to use Kizashi without the obligations of the
AGPL, a commercial license is available — see below.

## Running the checks locally

`scripts/verify.sh` runs the same gates CI does, so you can get the same answer
before pushing — and keep working if Actions is unavailable.

```sh
scripts/verify.sh              # only the areas you changed, fast checks
scripts/verify.sh --full       # adds builds, govulncheck, Semgrep, image scans
scripts/verify.sh --all        # every area, ignoring what changed
scripts/verify.sh --list       # show what would run, without running it
scripts/verify.sh server       # one area (agent/server/frontend/sdk/rules/security)
```

Checks whose prerequisites are missing are reported as **SKIP with a reason**,
never silently dropped — "it passed" and "it never ran" must not look alike.
Optional prerequisites:

| Check | Needs |
|---|---|
| `server` tests, coverage gate, migrations, synthetic-injection E2E | `DATABASE_URL` pointing at a reachable Postgres |
| NATS-dependent ingestion/scheduler tests | `NATS_URL` pointing at a reachable NATS |
| golangci-lint (`--new-from-merge-base`) | `golangci-lint` v2.12.2 — CI's version, built with a Go at least as new as `server/go.mod` |
| Detection rule validation | `yara` CLI |
| `ebpf prevention` build, staticcheck, binding-drift check | `clang`, `/sys/kernel/btf/vmlinux`, `bpftool` |
| Python SDK tests | `pip install -r sdk/python/requirements-dev.txt` |
| Secret scanning | `gitleaks` CLI |
| Dependency / SAST scanning | `trivy`, `semgrep` (image scans also need a running Docker daemon) |

The backup/restore integrity test creates and drops its own throwaway database, so
it never touches the schema `DATABASE_URL` points at.

What stays CI-only: the collision radar's sweep over *other people's* open PRs (needs
the GitHub API — your own branch's migration numbers are checked locally), the macOS
ESF native build, the nightly Playwright E2E, and the reporting paths (SARIF upload,
Codecov, the coverage PR comment).

## Contributing

Contributions are welcome. Please read [`CLA.md`](CLA.md) first: a one-time
contributor license agreement is required before a pull request can be merged. It
does not transfer your copyright — you keep ownership of your work — but it does
allow the project to be offered under both open source and commercial licenses.

Security issues should **not** be filed as public issues. See [`SECURITY.md`](SECURITY.md).

## License

Kizashi is licensed under the **GNU Affero General Public License v3.0 or later**
(see [`LICENSE`](LICENSE)).

In short: you may use, modify and redistribute it freely, including commercially.
If you run a modified version as a network service, you must make your modified
source available to the users of that service.

**A commercial license is available** for organisations that cannot accept the AGPL's
source disclosure requirement — for example, when embedding Kizashi in a closed
product or offering it as a hosted service. The same applies to the enterprise
features listed above. To start a conversation,
[open an issue](https://github.com/kizashi-labs/kizashi/issues/new) with the
`licensing` label; no need to disclose commercial details in public — say what you
need and we will take it from there.

Third-party components and detection content, including SigmaHQ community rules used
under the Detection Rule License 1.1, are attributed in [`NOTICE`](NOTICE).

## Disclaimer

Kizashi is provided without warranty of any kind. It is a detection and response
tool, not a guarantee of security, and it has not been certified against any
anti-malware or regulatory testing standard. You are responsible for validating it
in your own environment before relying on it. Deploying an endpoint agent with
kernel-level or eBPF components carries operational risk — test on
non-critical hosts first.

## Language

Most of `docs/` and all of the console's UI text is Japanese.

English versions of the documents you need to run the thing are in
[`docs/en/`](docs/en/README.md) — getting started, configuration reference,
troubleshooting — along with an index of what the Japanese-only documents cover.
The agent installer guide ([`deploy/install/README.md`](deploy/install/README.md)),
the agent's own logs and `agent.toml` are English already.

The **console has no English mode**. The strings are inline in the components and
there is no i18n layer to add one to. This is the largest remaining barrier for
non-Japanese operators and is a known gap, not an oversight. Screen paths
(`/alerts`, `/endpoints`, `/incidents`) are in English and stable, so the English
docs can send you to the right screen even when its labels don't help.

---

# Kizashi（日本語）

**兆し** — 何かが起きる前の、最初のしるし。

セルフホスト可能なオープンソースの EDR（エンドポイント検知・対応）プラットフォームです。
クロスプラットフォームのエージェント、リアルタイム検知エンジン、SOC コンソールを
1つのリポジトリに収めています。

## 特徴

- **すべて自分の環境で動く。** 収集したテレメトリ（イベント・アラート・インシデント）が
  外部に出ることはありません。ただし既定構成でも、公開ブロックリストと CVE の
  **取得**のために数本の外向き通信が出ます。全件を[外部通信](#外部通信)に列挙しています
- **Linux は eBPF、Windows は ETW、macOS は ESF またはプロセスポーリング**による
  OS ネイティブな収集（ESF の利用には Apple のエンタイトルメント申請が必要です）。
  Linux の共有ライブラリのロード（`image_load`）は **`dlopen` のみ**を捉えます。
  プログラム起動時に `ld.so` が解決する分は含まれません
- **3系統の検知**（ビルトイン Sigma / DB 上の Sigma ルール / 状態を持つ振る舞い検知）に
  加え、YARA・IOC 照合・Isolation Forest による異常検知・プロセス系譜分析
- **対応機能** — ネットワーク隔離、ファイル検疫、プロセス停止、プレイブック、ライブレスポンス

## 起動

```bash
git clone https://github.com/kizashi-labs/kizashi.git
```

```bash
cd kizashi
```

```bash
cp .env.example .env
```

`.env` に `POSTGRES_PASSWORD` / `JWT_SECRET`（32文字以上）/ `ADMIN_PASSWORD` を設定します。
`changeme` のような値は起動時に意図的に拒否されます。

```bash
docker compose up -d
```

初回はイメージをローカルでビルドするため、数分かかります（公開版はビルド済みイメージを
配布していません）。

コンソールは `http://localhost:3000`。マイグレーションは API 起動時に自動適用されます。

## 外部通信

収集したものを送信することはありません（テレメトリ・アラート・ファイル内容・
利用統計、いずれも送りません）。サーバーが**外向き**に張る接続は以下がすべてです。

**既定で有効:**

| 内容 | 接続先 | 頻度 | 止め方 |
|---|---|---|---|
| 公開 IOC ブロックリスト | `*.abuse.ch`（URLhaus / MalwareBazaar / Feodo / ThreatFox）、`reputation.alienvault.com`、`cinsscore.com`、`lists.blocklist.de`、`raw.githubusercontent.com`（IPsum） | フィードごとに 6〜24 時間おき | `THREAT_FEED_SYNC_ENABLED=false` で全停止。個別に止めるなら**脅威インテリジェンス → フィード**、または `UPDATE threat_feeds SET is_active = FALSE WHERE …;` |
| CVE 照会 | `services.nvd.nist.gov` | 6 時間おき。エージェントがソフトウェア資産を報告している場合のみ | `NVD_LOOKUP_ENABLED=false`（内蔵の小さな CVE 表にフォールバック） |

送っているのは問い合わせだけです。ブロックリストの取得は素の GET で、CVE 照会は
ソフトウェア名（例: `openssl`）だけを送ります。ホスト名・ユーザー名・イベント内容・
ハッシュは含みません。それも許容できない環境では両方を無効化してください。
ビルトイン Sigma / YARA / 振る舞い検知はそのまま動きますが、IOC 照合と脆弱性検出は
入力の大半を失います。

既定で有効にしているのは、これらが IOC 照合と脆弱性検出の**入力そのもの**だからです。
止めた状態で配ると、入れたのに検知しない状態になり、しかもそれが分かりません。
意図した既定であって、放置ではありません。上記のスイッチで 1 行で止められます。

**明示的に有効化したときだけ:**

| 内容 | 接続先 | 有効化 |
|---|---|---|
| ダークウェブ / リークサイト監視 | `raw.githubusercontent.com`（ransomwatch）、`api.ransomware.live`、`.onion` 到達性チェック用 Tor SOCKS5 | `docker compose -f docker-compose.yml -f docker-compose.darkweb.yml up -d`（`DARKWEB_MONITOR_ENABLED=true`） |
| ファイル / ハッシュ評価 | `virustotal.com`、`abuseipdb.com`、`otx.alienvault.com` | `VIRUSTOTAL_API_KEY` / `ABUSEIPDB_API_KEY` / `OTX_API_KEY` |
| SigmaHQ ルール同期 | `github.com` | `SIGMAHQ_SYNC_ENABLED=true` |
| SIEM / ログ転送 | 自組織の Elasticsearch | `ES_URL` |
| メール・Slack・Webhook | 自組織の SMTP / 指定した Webhook | `SMTP_HOST`、`*_SLACK_WEBHOOK_URL`、`*_WEBHOOK_URL` |
| トレーシング | 自組織の OTLP コレクタ | `OTEL_EXPORTER_OTLP_ENDPOINT` |
| クラウド構成監査（CSPM） | AWS / Azure / GCP API | コンソールで設定したクラウド認証情報 |
| エージェント更新確認 | バイナリの配布元 | `AGENT_LATEST_URL` |

ダークウェブ監視は以前**既定で有効**で、起動直後に同期していました。本変更で
オプトインに倒し、Tor コンテナもベースの compose から `docker-compose.darkweb.yml`
へ切り出しています。

## エージェントの配布

ビルド済みバイナリは同梱していませんが、**用意する必要はありません**。API イメージの
ビルド時にエージェントと watchdog をクロスコンパイルしてイメージ内の `AGENT_BIN_DIR`
（`/downloads`）に格納するため、`docker compose up -d` の時点で配布可能な状態になります。
コンソールのインストーラ画面とインストーラ API が、`.sha256` とあわせてここから配ります。

**バイナリはコード署名されていません。** Windows の SmartScreen や macOS の Gatekeeper が
警告します。検証環境を超えて配る場合はご自身で署名してください
（[`docs/エージェントコード署名.md`](docs/エージェントコード署名.md)）。

イメージに含めていないターゲットが2つあります。いずれも 404 と手動手順が返るので、
必要なら自分でビルドして `AGENT_BIN_DIR` に置いてください。

| ターゲット | 理由 | ビルド方法 |
|---|---|---|
| `darwin/arm64`（Apple Silicon） | イメージは `darwin/amd64` のみビルドする | `cd agent && make build-darwin-arm64` の後 `edr-agent-darwin-arm64` にリネーム |
| **eBPF 有効な Linux** | イメージのビルドステージに clang が無く、Linux 版は `-tags ebpf` **なし**でコンパイルされる | `agent/ebpf/Makefile` で CO-RE バインディングを生成し、`go build -tags ebpf -o edr-agent-linux-amd64 ./cmd/agent` |

> **既定で配られる Linux エージェントに eBPF センサーはありません。** procfs ポーリングに
> フォールバックするため、短命プロセスの取りこぼしが増え、eBPF でしか取れないファイル・
> ライブラリ・LSM のテレメトリは取得できません。上記の Linux 検知能力が必要な場合は、
> `-tags ebpf` でビルドしたものを自分で配置する必要があります。

ファイル名は固定です。ダウンロード API は `AGENT_BIN_DIR` 内の
`edr-agent-<os>-<arch>`（Windows は `.exe` 付き）をそのまま探します。

## ⚠️ カーネル防御は未検証の PoC です

Windows のカーネルドライバと Linux の eBPF LSM フックが含まれていますが、
**どちらも製品ビルドに結線されておらず、実環境での検証も行われていません。**
研究成果物として公開しているものです。**大事なマシンには入れないでください。**
サポート対象は検知と対応の機能です。

## 含まれないもの

企業向け SSO（SAML/OIDC/LDAP）、MDM・モバイル脅威検知、AI 支援トリアージ／調査、
SigmaHQ ルールの自動同期、アップデート配信、課金・ライセンス管理、商用サポート。
これらは商用版で提供します。

コンプライアンス自動評価・スコアカード、CSPM・クラウドランタイム、XDR、SIEM 連携、
デセプションは**この公開版に含まれています**。

## ライセンス

**AGPL-3.0 or later**。自由に利用・改変・再配布できます（商用利用を含む）。
ただし改変版をネットワークサービスとして提供する場合、その利用者に対して
改変ソースを提供する義務があります。

AGPL のソース開示義務を受け入れられない組織向けに、**商用ライセンスを用意しています**。
上記「含まれないもの」の機能についても同様です。ご相談は
[Issue](https://github.com/kizashi-labs/kizashi/issues/new)（`licensing` ラベル）から。
公開の場に商談の詳細を書く必要はありません。必要なものだけ書いていただければ、こちらから対応します。

## ローカルでの検証

`scripts/verify.sh` は CI と同じゲートを手元で流します。push する前に同じ
結論を得られますし、Actions が使えないときでも作業を止めずに済みます。

```sh
scripts/verify.sh              # 変更した領域だけを高速に
scripts/verify.sh --full       # ビルド・govulncheck・Semgrep・イメージ走査まで
scripts/verify.sh --all        # 変更に関係なく全領域
scripts/verify.sh --list       # 実行せず、何が走るかだけ表示
scripts/verify.sh server       # 領域を指定（agent/server/frontend/sdk/rules/security）
```

前提が足りない検査は**理由つきの SKIP として必ず表示**し、黙って飛ばしません。
「通った」と「そもそも走っていない」が同じに見えてはいけないためです。
任意の前提:

| 検査 | 必要なもの |
|---|---|
| server のテスト・カバレッジ下限・migration 適用・synthetic injection E2E | 到達可能な Postgres を指す `DATABASE_URL` |
| NATS 依存の ingestion / scheduler テスト | 到達可能な NATS を指す `NATS_URL` |
| golangci-lint（`--new-from-merge-base`） | CI と同じ `golangci-lint` v2.12.2。`server/go.mod` 以上の Go でビルドされたもの |
| 検知ルール検証 | `yara` CLI |
| `ebpf prevention` のビルド・staticcheck・バインディング鮮度検査 | `clang`、`/sys/kernel/btf/vmlinux`、`bpftool` |
| Python SDK テスト | `pip install -r sdk/python/requirements-dev.txt` |
| シークレット走査 | `gitleaks` CLI |
| 依存脆弱性 / SAST 走査 | `trivy`、`semgrep`（イメージ走査は起動中の Docker デーモンも要る） |

バックアップ復元テストは使い捨ての DB を自分で作って自分で消します。
`DATABASE_URL` が指すスキーマには触れません。

CI 専用のまま残るもの: collision radar のうち**他人の開いている PR**を見る部分
（GitHub API が要る。自分の枝が追加した番号はローカルで検査します）、macOS ESF の
ネイティブビルド、夜間の Playwright E2E、そして報告経路（SARIF アップロード、
Codecov、カバレッジの PR コメント）。

## 貢献

プルリクエストの前に [`CLA.md`](CLA.md) をご確認ください。
**貢献したコードの著作権は、書いた本人が持ち続けます**（維持者に譲渡されません）。
そのうえで、オープンソース版と商用版の二本立てを可能にするためのライセンス付与に
同意していただく必要があります。

脆弱性の報告は公開 issue ではなく [`SECURITY.md`](SECURITY.md) の手順でお願いします。

## 免責

本ソフトウェアは無保証で提供されます。検知・対応のためのツールであり、
セキュリティを保証するものではありません。いかなるアンチマルウェア認証・規制基準の
試験も受けていません。実運用の前に、ご自身の環境で検証してください。

## 言語

`docs/` のほとんどとコンソールの UI 文言は日本語です。導入に必要な範囲
（導入手順・設定リファレンス・トラブルシュート）の英語版を
[`docs/en/`](docs/en/README.md) に置いています。日本語のみのドキュメントも、
何が書いてあるかを一覧にしてあります。

コンソール自体には英語モードがありません。文言がコンポーネントに直書きされて
おり、i18n の層が無いためです。非日本語話者にとって最大の障壁として残っています。
