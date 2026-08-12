# Kizashi — 自動隔離・SOAR 設定ガイド

**対象読者:** セキュリティ管理者・SOCチームリード  
**最終更新:** 2026-06-03  
**関連バージョン:** v1.3.50+（`AUTO_ISOLATE_MIN_SEVERITY` 対応）

---

## 概要

Kizashi の SOAR（Security Orchestration, Automation and Response）機能では、検知ルールにマッチしたアラートに対して自動的に対応アクションを実行できます。本ガイドでは自動隔離を中心に設定方法・推奨値・運用上の注意点を説明します。

---

## 目次

1. [自動隔離の仕組み](#1-自動隔離の仕組み)
2. [AUTO_ISOLATE_MIN_SEVERITY の設定](#2-auto_isolate_min_severity-の設定)
3. [検知ルールの auto_isolate 設定](#3-検知ルールの-auto_isolate-設定)
4. [除外リスト（重要インフラ保護）](#4-除外リストの設定重要インフラ保護)
5. [自動ロールバック（タイムアウト隔離）](#5-自動ロールバック)
6. [自動隔離イベントの確認・承認](#6-自動隔離イベントの確認と承認)
7. [プレイブックによる高度な自動化](#7-プレイブックによる高度な自動化)
8. [推奨設定パターン](#8-推奨設定パターン)
9. [注意事項とベストプラクティス](#9-注意事項とベストプラクティス)

---

## 1. 自動隔離の仕組み

```
イベント受信
    │
    ▼
検知エンジン（Detection Engine）
    │  ルールマッチ
    ▼
アラート生成
    │  auto_isolate=true かつ severity >= AUTO_ISOLATE_MIN_SEVERITY?
    ▼
自動隔離コマンド発行
    │  NATS JetStream 経由
    ▼
エージェント（iptables / nftables / pfctl / netsh）
    │
    ▼
エンドポイント ネットワーク遮断
```

自動隔離は以下の **2つの条件がともに満たされた場合** に発動します：

1. マッチした検知ルールの `auto_isolate` が `true` に設定されている
2. アラートの `severity`（重大度）が `AUTO_ISOLATE_MIN_SEVERITY` 以上である

どちらか一方の条件でも欠けた場合、自動隔離は実行されません。

---

## 2. AUTO_ISOLATE_MIN_SEVERITY の設定

### 環境変数

```env
AUTO_ISOLATE_MIN_SEVERITY=9
```

| 値 | 意味 |
|----|------|
| `9`（デフォルト） | 重大度 9〜10（Critical）のみ自動隔離 |
| `7` | 重大度 7〜10（High以上）で自動隔離 |
| `5` | 重大度 5〜10（Medium以上）で自動隔離 |
| `1` | すべてのルールマッチで自動隔離（推奨しない） |

### Docker Compose での設定

`docker-compose.yml` または `deploy/.env.prod.example` の `detection` サービスに追加：

```yaml
services:
  detection:
    environment:
      - AUTO_ISOLATE_MIN_SEVERITY=9   # デフォルト値。本番では 9 を推奨
```

### Kubernetes（Helm）での設定

`helm/values.yaml` または上書き用 `values.override.yaml`：

```yaml
detection:
  env:
    AUTO_ISOLATE_MIN_SEVERITY: "9"
```

### 設定変更の反映

`detection` サービスの再起動が必要です：

```bash
# Docker Compose
docker compose restart detection

# Kubernetes
kubectl rollout restart deployment/edr-detection -n edr
```

---

## 3. 検知ルールの auto_isolate 設定

### GUI からの設定

1. **検知 → 検知ルール** を開く
2. 対象ルールの行をクリックして詳細を開く
3. **自動対応** セクションで **ネットワーク隔離** のトグルを有効化
4. **保存**

### API からの設定

```http
PUT /api/v1/rules/{rule_id}
Authorization: Bearer <APIキー>
Content-Type: application/json

{
  "auto_isolate": true
}
```

### デフォルトで auto_isolate=true のルール

以下のビルトインルールは、特に危険度が高いためデフォルトで自動隔離が有効になっています：

| ルール名 | MITRE | 重大度 |
|---------|-------|--------|
| Ransomware Shadow Copy Deletion | T1490 | 10 |
| Mimikatz LSASS Access | T1003 | 9 |
| WMIC Remote Process Creation | T1047 | 9 |

> Linuxの「Linux Reverse Shell via Bash」ルールは `auto_isolate=false` です。リバースシェルは正規の管理作業でも発生し得るため、誤検知時の影響を避けるよう設計されています。

---

## 4. 除外リストの設定（重要インフラ保護）

ドメインコントローラー・本番DBサーバーなど、隔離されると業務影響が大きいホストは **除外リスト** に登録してください。

> 除外リスト登録済みのホストへは自動隔離・プロセス終了・ファイル検疫が一切発動しません。

### API での除外追加

```http
POST /api/v1/admin/remediation/exclusions
Authorization: Bearer <管理者APIキー>
Content-Type: application/json

{
  "hostname_pattern": "dc-*",
  "reason": "Active Directoryドメインコントローラー"
}
```

`hostname_pattern` は glob パターンで指定します：

| パターン例 | マッチするホスト名 |
|----------|----------------|
| `dc-*` | `dc-01`, `dc-02`, ... |
| `prod-db-??` | `prod-db-01`, `prod-db-02`, ... |
| `*.critical.local` | `sqlserver.critical.local` など |

### 除外リストの確認

```http
GET /api/v1/admin/remediation/exclusions
Authorization: Bearer <管理者APIキー>
```

### 管理画面からの確認

**管理 → 対応 → 自動修復ルール → 除外リスト** タブ

---

## 5. 自動ロールバック

自動隔離のアクションに `rollback_timeout_seconds` を設定すると、指定時間後に隔離が自動解除されます。アナリストが確認して承認する場合はキャンセルできます。

### ロールバック設定付きルールの例（API）

```http
POST /api/v1/admin/remediation/rules
Content-Type: application/json

{
  "name": "Ransomware - Timed Isolation",
  "trigger": {"alert_rule_id": "<rule_id>"},
  "action": {
    "type": "isolate",
    "rollback_timeout_seconds": 3600
  }
}
```

### 保留中ロールバックの確認と承認

```http
# 保留一覧
GET /api/v1/admin/remediation/pending-rollbacks

# 承認（自動解除をキャンセル）
POST /api/v1/admin/remediation/executions/{execution_id}/approve
```

---

## 6. 自動隔離イベントの確認と承認

### Web UI での確認

1. **エンドポイント → エンドポイント一覧** を開く
2. ステータス列が **「隔離中」**（オレンジ）のエンドポイントを確認
3. ホスト名をクリックして詳細を開く
4. **隔離解除** ボタンで手動解除（調査完了・誤検知の場合）

### 自動隔離の監査証跡

すべての自動隔離操作は監査ログに記録されます：

**管理 → レポート & コンプライアンス → 監査ログ** → アクション種別 `auto_isolate` でフィルター

### 自動隔離後の標準対応フロー

1. **確認**（〜5分）: アラート詳細でAI分析結果を確認
2. **調査**（〜30分）: ライブレスポンス / フォレンジクスで詳細調査
3. **判断**: 脅威が確認された → 証拠収集・除去後に隔離解除 / 誤検知 → 即時解除・抑制ルール追加
4. **記録**: インシデントをクローズし対応内容をコメントに記録

---

## 7. プレイブックによる高度な自動化

自動隔離だけでなく、複数のアクションを順番に実行するプレイブックを定義できます。

### プレイブック例：ランサムウェア自動封じ込め

```yaml
name: Ransomware Auto-Containment
trigger:
  severity_min: 9
  rule_pattern: "*ransomware*"
steps:
  - action: isolate_endpoint
    delay: 0
  - action: send_notification
    channel: slack
    message: "⚠️ ランサムウェア自動隔離実行: {endpoint}"
    delay: 0
  - action: create_incident
    severity: critical
    title: "ランサムウェア疑い: {endpoint}"
    delay: 0
  - action: collect_forensics
    targets: [processes, network, files]
    delay: 30
```

### GUI でのプレイブック設定

**管理 → 自動化 → プレイブック作成** → テンプレートから選択または新規作成

---

## 8. 推奨設定パターン

### パターン A: 保守的（製造業・医療・金融）

ビジネス継続性を最優先し、誤検知による業務影響を最小化します。

```env
AUTO_ISOLATE_MIN_SEVERITY=10
```

- Critical（重大度 10）のみ自動隔離
- プレイブックで通知とインシデント作成のみ自動実行
- 隔離はアナリストが手動で承認

### パターン B: 標準（一般企業）

デフォルト設定。Critical アラートのみ自動隔離します。

```env
AUTO_ISOLATE_MIN_SEVERITY=9   # デフォルト
```

### パターン C: 積極的（SOC専業・セキュリティ企業）

High以上で自動隔離。誤検知時の解除フローを整備した上で使用します。

```env
AUTO_ISOLATE_MIN_SEVERITY=7
```

- 除外リストに重要インフラを必ず登録すること
- ロールバックタイムアウト（30〜60分）を設定すること
- 24時間対応のSOCアナリストが常駐していること

---

## 9. 注意事項とベストプラクティス

### 必須：除外リストの事前登録

自動隔離を有効化する前に、以下のホストを除外リストに登録してください：

- ドメインコントローラー（`dc-*`）
- Active Directory サーバー
- 本番データベースサーバー
- バックアップサーバー
- 監視サーバー（Wazuh など）
- VPN / ゲートウェイサーバー

### 誤検知率を下げてから有効化する

`auto_isolate=true` を設定する前に、そのルールの誤検知率が許容範囲内かを確認してください。

1. **検知 → アラート一覧** でルールごとの `false_positive` 率を確認
2. 誤検知が多いルールは先にチューニング（抑制ルールの追加など）を行う
3. 十分なチューニング後に `auto_isolate=true` を設定

### 変更は段階的に行う

```
テスト環境で検証
    ↓
本番の一部ホスト（低重要度）で試行
    ↓
全ホストに適用
```

### 自動隔離後の業務影響を把握する

本番適用前に「このエンドポイントが隔離されたら何が止まるか」を確認してください。VDI環境・共有端末など隔離の影響が大きい端末は除外リストへ。

### 定期的なレビュー

月次で以下を確認することを推奨します：

- 自動隔離の発動件数と誤検知件数の比率
- 除外リストが適切に維持されているか
- `auto_isolate=true` のルールが過剰になっていないか

---

## 関連ドキュメント

- [管理者運用ガイド § 8-5](管理者運用ガイド.md#8-5-自動リメディエーション管理) — 自動リメディエーション管理
- [マルウェア対応シナリオ](マルウェア対応シナリオ.md) — 隔離後の調査・対応手順
- [トラブルシューティング](トラブルシューティング.md) — 自動隔離が期待通り動作しない場合
- [運用ランブック](運用ランブック.md) — インシデント発生時の対応手順
