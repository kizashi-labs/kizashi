# ローカルで稼働サーバに接続する — 起動ランブック

curate ソークや attack-scorer の実測など、**稼働中のサーバに接続して操作する**ための最小構成の
立ち上げ手順。2経路を用意する:

| 経路 | 用途 | 前提 |
|---|---|---|
| **A. docker compose**（推奨・永続） | VM/クラウド/ノートPC など**通常の環境**。curate の数日ソークもこれ | Docker が動き、イメージ pull ができる |
| **B. ネイティブ**（`run-native.sh`） | Docker が使えない/イメージ pull が制限された隔離環境。**即時の実地検証**向け | PostgreSQL16 バイナリ・Go 1.25+ |

> ⚠️ どちらも `.env` の `JWT_SECRET` / `POSTGRES_PASSWORD` / `ADMIN_PASSWORD` を設定すること
> （`ADMIN_PASSWORD` が `changeme`/`admin`/`password` 等だと起動時に拒否される）。`.env` はコミット禁止。

---

## A. docker compose（推奨）

```bash
cp .env.example .env
# .env を編集: JWT_SECRET(32文字以上) / POSTGRES_PASSWORD / ADMIN_PASSWORD(openssl rand -base64 24)

# コア一式(postgres + nats 3ノード + api + detection + ingestion + frontend)を起動
docker compose up -d --build

# 健全性
curl -fsS http://localhost:8080/healthz && echo OK
# UI: http://localhost:3000  /  API: http://localhost:8080
```

最小(API + 検知 + DB + NATS 1ノードだけ)なら:

```bash
docker compose up -d --build postgres nats-1 api detection
```

SigmaHQ 公開ルールの自動同期(curate の対象を DB に投入)を有効化するには `.env` に:

```
SIGMAHQ_SYNC_ENABLED=true
```

を設定して `api` を再起動する（外部ネットワークが `api.github.com` に到達できること）。

---

## B. ネイティブ（Docker 不要）

Docker デーモンが無い/イメージ pull が 403 になる隔離環境向け。`postgres`(ネイティブ) +
`nats-server`(go install) + `go build` した `api` を起動する。

```bash
sudo deploy/local/run-native.sh                 # api のみ
sudo deploy/local/run-native.sh --with-detection # 検知パイプラインも
sudo deploy/local/run-native.sh --stop          # 停止
```

`.env` が無ければ安全な秘密情報で自動生成する。起動後、接続情報(URL・ログイン・DB・ログ位置)を表示する。

> **制約(隔離環境)**: ①使い捨てで**セッション終了時に消える**(数日のソークには A を使う)。
> ②timescaledb 拡張が無い場合、events は通常テーブルとして作られる(検知検証には十分)。
> ③外部フィード/SigmaHQ 同期はネットワーク制限下では 403 になる(コア機能は動作、curate 対象は空になる)。

---

## 接続して操作する（両経路共通）

```bash
set -a; source .env; set +a
BASE=http://localhost:8080

# 1) 管理者ログイン → JWT トークン
TOKEN=$(curl -s -X POST $BASE/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d "{\"email\":\"admin@localhost\",\"password\":\"$ADMIN_PASSWORD\"}" | jq -r .token)

# 2) curate 状態(カテゴリ別 total/supported/enabled/deferred/pending/quarantined)
curl -s -H "Authorization: Bearer $TOKEN" $BASE/api/v1/admin/detection/curate/status | jq

# 3) curate ラウンド実行(field-supported なルールを cap 件まで段階有効化)
curl -s -X POST -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d '{"cap":20}' $BASE/api/v1/admin/detection/curate/run | jq
```

### curate ソークの運用ループ（本命）

`SIGMAHQ_SYNC_ENABLED=true` で同期した SigmaHQ ルールが DB(`rules` の `source='sigmahq'`)に
入った状態で、以下を回す:

1. `GET .../curate/status` で field-supported な pending/deferred を確認
2. `POST .../curate/run {"categories":["registry_set"],"cap":20}` で1カテゴリを段階有効化
3. 実トラフィック下で 24h、FP を観測（`CurateScheduler.MonitorFP` が閾値超ルールを自動隔離）
4. 問題なければ次カテゴリ/次バッチへ

CI からの状態スナップショット/自動前進は [`.github/workflows/curate-ops.yml`](../../.github/workflows/curate-ops.yml)
（`EDR_ADMIN_SERVER`/`EDR_ADMIN_TOKEN` を上記 `$BASE`/`$TOKEN` に設定）。効果測定は
`agent/cmd/scorecard-trend` と `attack-scorer`。

### attack-scorer で検知率を実測

```bash
cd agent && go build -o /tmp/attack-scorer ./cmd/attack-scorer
# オフライン(決定的・インフラ非依存)
/tmp/attack-scorer -runlog ../docs/results/fixtures/intrusion_runlog.csv \
  -alerts ../docs/results/fixtures/intrusion_alerts.json -out /tmp/sc.csv
# ライブ(稼働サーバ + 実エンドポイントの runlog)
/tmp/attack-scorer -server $BASE -token "$TOKEN" -runlog run.csv -agent <agent-id> -out /tmp/live.csv
```

---

## トラブルシュート
- `healthz` が 200 にならない → `api` ログ（A: `docker compose logs api` / B: `/tmp/edr-local/api.log`）を確認。多くは `.env` 未設定(JWT_SECRET/ADMIN_PASSWORD)。
- curate `status` が空 → SigmaHQ 同期未実行。`SIGMAHQ_SYNC_ENABLED=true`＋外部到達性が必要（seeded builtin は `source` が `sigmahq` でないため curate 対象外）。
- ポート競合 → `.env` の `API_PORT`/`FRONTEND_PORT` 等、または B は `API_PORT=... PGPORT=... deploy/local/run-native.sh`。
