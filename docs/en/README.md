# Kizashi — English documentation

Most of `docs/` is written in Japanese. This directory holds English versions of
the documents you need to **get a server running, enrol your first endpoint, and
work out why something is broken**. Everything else is listed below with a short
description, so you know what exists even when you cannot read it.

If a page here disagrees with the Japanese original, the code is the tiebreaker —
please open an issue.

## Start here

| | |
|---|---|
| [Getting started](getting-started.md) | Server install → first login → first endpoint. ~30 minutes. |
| [Configuration reference](configuration.md) | Every environment variable that matters, and what happens if you leave it unset. |
| [Troubleshooting](troubleshooting.md) | The failures people actually hit, and how to tell them apart. |
| [`deploy/install/README.md`](../../deploy/install/README.md) | Agent installer reference — already written in English. Layout, one-liners, update, uninstall. |
| [`docs/openapi.yaml`](../openapi.yaml) | The REST API. 1,117 paths. See [OpenAPI coverage](../OpenAPI網羅率と同期ゲート.md) for what is verified and what is only a stub. |

## What is only in Japanese

These have no English version. The table says what each one is for, so you can
decide whether machine translation is worth it.

### Operating the product

| Document | What it covers |
|---|---|
| [`ユーザーガイド.md`](../ユーザーガイド.md) | Console walkthrough, screen by screen (915 lines) |
| [`管理者運用ガイド.md`](../管理者運用ガイド.md) | Day-to-day administration: users, tenants, retention, backups |
| [`製品取扱説明書.md`](../製品取扱説明書.md) | Full product manual |
| [`運用ランブック.md`](../運用ランブック.md) | On-call runbook: what to do when a component fails |
| [`インシデント対応SOP.md`](../インシデント対応SOP.md) | Incident response standard operating procedure |
| [`SOC規模別運用ガイド.md`](../SOC規模別運用ガイド.md) | Staffing and process by SOC size |
| [`自動隔離・SOAR設定ガイド.md`](../自動隔離・SOAR設定ガイド.md) | Automatic isolation and playbook tuning — **read before enabling auto-isolation** |
| [`状況別画面確認ガイド.md`](../状況別画面確認ガイド.md) | "Something happened — which screen do I open?" |

### Detection engineering

| Document | What it covers |
|---|---|
| [`検知ルールの二重管理とデプロイ.md`](../検知ルールの二重管理とデプロイ.md) | **Important.** Built-in Sigma rules and database Sigma rules are two separate engines. Read this when a rule you edited does not fire |
| [`ATT&CK検知カバレッジ監査.md`](../ATT&CK検知カバレッジ監査.md) | Which ATT&CK techniques are covered |
| [`ATT&CK検知率測定計画.md`](../ATT&CK検知率測定計画.md) | How detection rate is measured |
| `検知率向上_*.md` (30+ files) | Per-investigation write-ups of detection gaps and their fixes |
| [`マルウェア対応シナリオ.md`](../マルウェア対応シナリオ.md) | Worked malware response scenarios |

### Platform and security

| Document | What it covers |
|---|---|
| [`セキュリティ強化ガイド.md`](../セキュリティ強化ガイド.md) | Hardening the deployment |
| [`security/マルチテナント分離ハードニング.md`](../security/マルチテナント分離ハードニング.md) | Row-level security and tenant isolation |
| [`security/RLS-fail-closed設計.md`](../security/RLS-fail-closed設計.md) | Why RLS fails closed and what that costs |
| [`エージェントコード署名.md`](../エージェントコード署名.md) | Signing agent binaries |
| [`アンインストール保護.md`](../アンインストール保護.md) | Tamper protection |
| [`CI・デプロイ運用とコスト最適化.md`](../CI・デプロイ運用とコスト最適化.md) | CI and deployment |
| [`SDK開発者ガイド.md`](../SDK開発者ガイド.md) | Python and TypeScript client SDKs |

Design documents live under [`docs/design/`](../design/), and are Japanese-only.

## The console is Japanese

The web console's UI text is Japanese, with no language switcher. There is no
i18n layer to add English to today — the strings are inline in the components.
This is the largest remaining barrier for non-Japanese operators, and it is a
known gap rather than an oversight.

What that means in practice:

- **Server-side**: fully usable in English. Logs are mixed Japanese/English,
  the REST API is language-neutral, and error responses are Japanese strings.
- **Agent-side**: English. Installer scripts, agent logs and `agent.toml`
  comments are all English.
- **Console**: Japanese. Screen paths (`/alerts`, `/endpoints`, `/incidents`)
  are in English and stable, so the troubleshooting page can point you at the
  right screen even if the text on it is not readable to you.

If you want to work on this, the console is Next.js App Router under
`frontend/app/`; a dictionary-based i18n layer would be the natural first step.
