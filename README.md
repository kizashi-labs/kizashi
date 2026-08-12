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

Everything runs on infrastructure you control. **By default nothing leaves your
network** — the only outbound traffic is what you configure yourself (VirusTotal
lookups, SIEM/Elasticsearch forwarding, threat intelligence feeds, cloud provider
polling). None of it is on unless you turn it on.

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

Agent installation is documented in [`docs/エージェントインストール手順.md`](docs/エージェントインストール手順.md).

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

## Agent

| OS | Sensor | Status |
|---|---|---|
| Linux | eBPF CO-RE — process, network, file, library, LSM hooks | Production |
| Windows | ETW — process, network, registry, WMI, named pipes, PowerShell | Production |
| macOS | Endpoint Security Framework (build tag) or process polling | ESF requires an Apple entitlement |

A watchdog process supervises the agent and is registered with systemd, Windows
Service Manager, or launchd. The agent ring-buffers events while offline and
reconnects with exponential backoff.

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

Most of the documentation under `docs/` and much of the console copy is written in
Japanese.

---

# Kizashi（日本語）

**兆し** — 何かが起きる前の、最初のしるし。

セルフホスト可能なオープンソースの EDR（エンドポイント検知・対応）プラットフォームです。
クロスプラットフォームのエージェント、リアルタイム検知エンジン、SOC コンソールを
1つのリポジトリに収めています。

## 特徴

- **すべて自分の環境で動く。** 既定では、収集したデータが外部に出ることはありません。
  外部通信が発生するのは、利用者自身が設定した場合だけです（VirusTotal 照会、
  SIEM / Elasticsearch への転送、脅威インテルフィードの取得、クラウド事業者の API 監視）
- **Linux は eBPF、Windows は ETW、macOS は ESF またはプロセスポーリング**による
  OS ネイティブな収集（ESF の利用には Apple のエンタイトルメント申請が必要です）
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
