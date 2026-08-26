# Kizashi

**兆し** — *the first sign, before anything has happened.*

A self-hostable, open source Endpoint Detection and Response (EDR) for Windows
endpoints. Agent, real-time detection engine, and a web console — in one repository.

[![License: AGPL v3](https://img.shields.io/badge/license-AGPL--3.0-blue)](LICENSE)
[![Go](https://img.shields.io/badge/go-1.26%2B-00ADD8?logo=go)](https://go.dev/)
[![Platform](https://img.shields.io/badge/agent-Windows-lightgrey)](#agent)

---

## What it is

Kizashi collects Windows endpoint telemetry — process, network, file, registry,
DNS and authentication events over ETW — streams it to a self-hosted server over
mTLS gRPC, evaluates it against Sigma rules, IOC indicators and statistical
baselines, and shows the resulting alerts in the included web console.

Everything runs on infrastructure you control, and **this edition opens no outbound
connections at all** unless you configure your own SMTP server or OTLP collector —
see [Outbound traffic](#outbound-traffic).

| Component | Stack |
|---|---|
| Agent | Go. Windows ETW (process, network, registry, DNS, auth, PowerShell) |
| Server | Go. REST + gRPC API, separate ingestion and detection services |
| Storage | PostgreSQL / TimescaleDB, NATS JetStream |
| Console | Next.js 14 (App Router), React 18, TypeScript, Tailwind |

**Event flow:** agent → gRPC ingestion → Postgres + NATS → detection pipeline
(Sigma / IOC / anomaly) → alerts → pushed to the console over WebSocket.

**Scope, stated plainly:** this repository is the free core of a larger commercial
product. It is complete and genuinely useful — real-time Sigma detection with a
working console beats an agent-less log pile — but the advanced detection layers,
the multi-OS agents and the operations tooling are not here. The full list is in
[What is not included](#what-is-not-included).

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

A getting-started guide, a configuration reference and a troubleshooting guide are
in **[`docs/en/`](docs/en/README.md)**. That page also indexes the Japanese-only
documents, so you can see what exists even if you cannot read it.

## Detection

Two evaluation paths run against the same event stream:

1. **Built-in Sigma rules** (Go, compiled into the API service) — MITRE ATT&CK mapped
2. **Database Sigma rules** (`rules` table, loaded from `rulepacks/`) — editable at
   runtime, reloaded automatically or on demand

Plus IOC matching against a built-in indicator set, a statistical anomaly model,
per-agent behavioural baselines (unknown-process detection) and process ancestry
resolution for parent-image rules.

### What ships in `rulepacks/`

This edition includes **`baseline.json`** — the same detections that are compiled
into the API binary, in the form the detection engine reads. Both matter: the API
service evaluates the compiled copies, while `server-detect` only ever reads the
`rules` table, so without the pack that engine would evaluate nothing at all.

Packs are loaded at startup from `EDR_RULEPACK_DIR` and upserted into the `rules`
table, where they behave like any other rule: editable and disableable through the
database. You can add your own — the format is documented in
[`server/internal/rulepack`](server/internal/rulepack), and it is standard Sigma.

**Not included:** the curated rule packs, the stateful behavioural detectors
(port-scan, DNS tunnelling, C2 correlation, ransomware burst correlation,
kill-chain scoring), YARA scanning, and the automatic SigmaHQ synchronisation.
Those are part of the commercial edition.

## Response

- **Network isolation** — isolate / release an endpoint from the console
  (`POST /agents/:id/isolate`), dispatched to the agent over NATS JetStream
- **Rule-driven auto-remediation** — available and gated behind
  `AUTO_ISOLATE_MIN_SEVERITY` (default `9`). **Read the tuning notes before
  enabling it** — an over-eager threshold will isolate hosts on false positives,
  and recovering an isolated host takes longer than you expect

File quarantine, process termination, playbooks and interactive live response are
part of the commercial edition.

## Outbound traffic

Nothing you collect is ever uploaded — no telemetry, no alerts, no file contents,
no usage analytics. **This edition makes no outbound connections by default.**

The only connections it can open outwards are ones you configure yourself:

| What | Where to | Enable with |
|---|---|---|
| Mail (password reset, email MFA) | your SMTP server | `SMTP_HOST` |
| Tracing | your OTLP collector | `OTEL_EXPORTER_OTLP_ENDPOINT` |

Threat-intel feed subscriptions, CVE lookups, file-reputation services and other
external enrichment are part of the commercial edition.

## Agent

| OS | Sensor | Status |
|---|---|---|
| Windows | ETW — process, network, registry, DNS, auth, WMI, named pipes, PowerShell | Production |

A watchdog process supervises the agent and is registered with the Windows Service
Manager. The agent ring-buffers events while offline and reconnects with
exponential backoff. Linux and macOS agents are part of the commercial edition.

### Getting the agent binaries

No pre-built binaries are shipped in this repository. They do not need to be:
building the API image cross-compiles the Windows agent and the watchdog and bakes
them into the image at `AGENT_BIN_DIR` (`/downloads`), so `docker compose up -d`
leaves you with a server that can already hand out agents. The installer endpoints
and the console's deploy page serve them from there, together with `.sha256`
sidecars.

**The binaries are not code signed.** Windows SmartScreen will say so. Sign them
yourself if you are deploying beyond a lab —
[`docs/エージェントコード署名.md`](docs/エージェントコード署名.md) describes the procedure.

Filenames matter: the download endpoint looks for exactly
`edr-agent-windows-amd64.exe` inside `AGENT_BIN_DIR`.

## What is not included

Kizashi is the free core of a commercial product. The following are developed
separately and are not part of this repository:

Linux / macOS agents · stateful behavioural detectors and kill-chain correlation ·
YARA scanning · threat-intel feeds and enrichment · incident management ·
reports · compliance · vulnerability management · threat hunting · forensics ·
live response · playbooks / SOAR · SIEM connectors · UEBA · CSPM / cloud / XDR ·
multi-tenancy · RBAC · enterprise SSO (SAML / OIDC / LDAP) · MDM · AI-assisted
triage · SigmaHQ rule synchronisation · managed update delivery · API clients
(SDKs) · commercial support

If you need any of these, or you want to use Kizashi without the obligations of
the AGPL, a commercial license is available — see below.

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

**A commercial license is available** for organisations that cannot accept the
AGPL's source disclosure requirement, and the commercial edition carries the
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
in your own environment before relying on it.

## Language

Most of `docs/` and all of the console's UI text is Japanese.

English versions of the documents you need to run the thing are in
[`docs/en/`](docs/en/README.md) — getting started, configuration reference,
troubleshooting. The agent installer guide
([`deploy/install/README.md`](deploy/install/README.md)), the agent's own logs and
`agent.toml` are English already.

The **console has no English mode**. The strings are inline in the components and
there is no i18n layer to add one to. Screen paths (`/alerts`, `/endpoints`) are in
English and stable, so the English docs can send you to the right screen even when
its labels don't help.

---

# Kizashi（日本語）

**兆し** — 何かが起きる前の、最初のしるし。

セルフホスト可能なオープンソースの Windows 向け EDR（エンドポイント検知・対応）です。
エージェント、リアルタイム検知エンジン、Web コンソールを 1 つのリポジトリに収めています。

## 特徴

- **すべて自分の環境で動く。** 収集したテレメトリ（イベント・アラート）が外部に出る
  ことはありません。しかもこの版は、**既定で外向き通信を一切開きません**
  （[外部通信](#外部通信)参照）
- **Windows ETW によるネイティブ収集** — プロセス・ネットワーク・レジストリ・DNS・
  認証・WMI・名前付きパイプ・PowerShell
- **2系統の Sigma 検知**（ビルトイン / DB 上のルール）＋ IOC 照合・統計的異常検知・
  エージェント別の行動ベースライン（未知プロセス検知）
- **対応機能** — コンソールからのネットワーク隔離と、しきい値ゲート付きの自動隔離

**位置づけをはっきり書いておきます:** このリポジトリは商用製品の無料コアです。
リアルタイム Sigma 検知と動くコンソールが揃った、それ自体で使い物になる EDR ですが、
高度な検知レイヤ・マルチ OS エージェント・運用系の機能は含まれていません。
一覧は[含まれないもの](#含まれないもの)にあります。

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
利用統計、いずれも送りません）。**この版は既定で外向きの接続を一切開きません。**

開き得るのは、自分で設定した次の 2 つだけです。

| 内容 | 接続先 | 有効化 |
|---|---|---|
| メール（パスワードリセット・メール MFA） | 自組織の SMTP | `SMTP_HOST` |
| トレーシング | 自組織の OTLP コレクタ | `OTEL_EXPORTER_OTLP_ENDPOINT` |

脅威インテリジェンスフィードの購読、CVE 照会、ファイル評価サービスなどの外部
エンリッチメントは商用版の機能です。

## エージェントの配布

ビルド済みバイナリは同梱していませんが、**用意する必要はありません**。API イメージの
ビルド時に Windows エージェントと watchdog をクロスコンパイルしてイメージ内の
`AGENT_BIN_DIR`（`/downloads`）に格納するため、`docker compose up -d` の時点で
配布可能な状態になります。コンソールの配布画面とインストーラ API が、`.sha256` と
あわせてここから配ります。

**バイナリはコード署名されていません。** Windows の SmartScreen が警告します。
検証環境を超えて配る場合はご自身で署名してください
（[`docs/エージェントコード署名.md`](docs/エージェントコード署名.md)）。

ファイル名は固定です。ダウンロード API は `AGENT_BIN_DIR` 内の
`edr-agent-windows-amd64.exe` をそのまま探します。

## 含まれないもの

この公開版は商用製品の無料コアです。以下は別に開発しており、このリポジトリには
含まれません:

Linux / macOS エージェント、状態を持つ振る舞い検知器とキルチェーン相関、YARA、
脅威インテリジェンスフィードとエンリッチメント、インシデント管理、レポート、
コンプライアンス、脆弱性管理、脅威ハンティング、フォレンジック、ライブレスポンス、
プレイブック / SOAR、SIEM 連携、UEBA、CSPM / クラウド / XDR、マルチテナント、
RBAC、企業向け SSO（SAML/OIDC/LDAP）、MDM、AI 支援トリアージ、SigmaHQ ルール自動同期、
アップデート配信、API クライアント（SDK）、商用サポート。

**エンジンは完全なので、独自 Sigma ルールの作成も取り込みも自分でできます** ——
形式は標準の Sigma です。

## ライセンス

**AGPL-3.0 or later**。自由に利用・改変・再配布できます（商用利用を含む）。
ただし改変版をネットワークサービスとして提供する場合、その利用者に対して
改変ソースを提供する義務があります。

AGPL のソース開示義務を受け入れられない組織向けに、**商用ライセンスを用意しています**。
上記「含まれないもの」の機能についても同様です。ご相談は
[Issue](https://github.com/kizashi-labs/kizashi/issues/new)（`licensing` ラベル）から。
公開の場に商談の詳細を書く必要はありません。必要なものだけ書いていただければ、こちらから対応します。

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
[`docs/en/`](docs/en/README.md) に置いています。

コンソール自体には英語モードがありません。文言がコンポーネントに直書きされて
おり、i18n の層が無いためです。非日本語話者にとって最大の障壁として残っています。
