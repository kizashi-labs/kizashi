# FPソーク用 良性テレメトリ・プロファイル

`agent/cmd/fleet-sim` が読み込む良性エンドポイントの定義。1ファイル = 1ホストクラス。

**運用手順は [docs/ops/FPソーク運用.md](../../docs/ops/FPソーク運用.md) を参照。**

## 設計原則

1. **全イベントは良性である。** これが測定のグラウンドトゥルースそのもの。
   ここに攻撃的な挙動を混ぜた瞬間、「ソーク中のアラートは全て誤検知」という
   前提が壊れ、自動ラベリングが成立しなくなる。

2. **「攻撃と見分けがつかない正規操作」を意図的に含める。** 静かなデスクトップの
   ノイズだけで組んだフリートは誤検知ゼロを報告し、何も測ったことにならない。
   管理者の探索コマンド連打、バックアップの世代一括削除、外部クラウドへの
   大容量転送、`curl | sh`、`authorized_keys` の更新 — これらが本体。

3. **`fleet_weight` は実フリートの構成比に合わせる。** 均等配分すると
   ノイジーなホストクラスが過大評価され、誤検知率が数倍に膨らむ。
   ただし `AllocateFleet` が各プロファイルに最低1台を保証するので、
   小規模実行でも管理端末・バックアップ機は必ず含まれる。

## プロファイル

| ファイル | OS | fleet_weight | 役割 |
|---|---|---:|---|
| `office-pc.toml` | Windows | 60 | 一般事務PC。低頻度・高台数側の誤検知 |
| `dev-machine.toml` | Linux | 20 | 開発者マシン。コマンドライン系ルールの誤爆源 |
| `file-server.toml` | Windows | 8 | 大量ファイルI/O。ランサム検知の閾値近傍 |
| `it-admin.toml` | Windows | 8 | 情シス管理端末。**FPフロンティアの本丸** |
| `macbook.toml` | macOS | 15 | Jamf 管理下の Mac。macOS 専用ルールの唯一の測定対象 |
| `backup-server.toml` | Linux | 4 | 世代削除＋外部大容量転送 |

> **`macbook.toml` が無いと macOS 専用ルールは「静かなルール」と区別がつかない。**
> `platform` 列を持つ DB Sigma ルールは `rules.PlatformMatchesEvent` が
> **評価前に**落とすので、darwin ホストが 0 台のフリートでは macOS ルールが
> 一律 0 件になる。スコアカード上、それは「精度が高いルール」と同じ見え方をする。
> 実際 migration 386 で macOS 専用 9 件を入れた直後のソークは全件 0 件を報告し、
> それを「誤検知が少ない」と読みかけた（負債台帳 P4-12）。
> `TestRealProfilesLoad` が windows/linux/**darwin** の 3 つ揃いを要求するのは
> この穴を再び開けないためである。

## スキーマ

```toml
name = "profile-name"       # 一意。ホスト名にも使われる
os = "windows"              # windows|linux|darwin
os_version = "..."          # 登録時に申告する
host_prefix = "wks"         # ホスト名: <global>-<host_prefix>-<NNNN>
fleet_weight = 60           # フリート構成比 (省略時 1)
subnet = "10.20.0.0/16"     # 自ホストのアドレスを引く CIDR。必ず RFC1918
users = ["sato", "..."]     # {{user}} に束縛される。ホストごとに固定

[rates]                     # 1台あたり 1シミュレート時間 のイベント数
process = 120
file = 900
network = 700
dns = 250
registry = 150              # windows のみ
auth = 4
image_load = 300

[[processes]]               # rates で 0 でない種別は必ず1つ以上定義すること
weight = 30                 # 種別内での相対頻度
name = "chrome.exe"
path = 'C:\...\chrome.exe'
parent = "explorer.exe"
cmdlines = ["...", "..."]   # 必須
user = 'CORP\{{user}}'
integrity = "Medium"        # Sigma IntegrityLevel
company = "Google LLC"      # PE VERSIONINFO 系フィールド
product = "Google Chrome"
original_file_name = "chrome.exe"
file_description = "..."
```

`[[files]]` `[[network]]` `[[dns]]` `[[registry]]` `[[auth]]` `[[image_loads]]` も
同様に `weight` 必須。全フィールドは `agent/cmd/fleet-sim/profile.go` を参照。

### プレースホルダ

| 記法 | 展開先 |
|---|---|
| `{{user}}` | そのホストに束縛されたユーザ名 |
| `{{host}}` | シミュレートホスト名 |
| `{{srcip}}` | シミュレートホストのIP |
| `{{rand}}` | 8桁の16進乱数 (出現ごとに別値) |
| `{{randint}}` | 1〜99999 の整数 (出現ごとに別値) |
| `{{date}}` | 実行日 `YYYYMMDD` |

## 検証

プロファイルを編集したら必ず実行すること。

```bash
cd agent && go test ./cmd/fleet-sim/
```

- `TestRealProfilesLoad` — 全ファイルがパース・検証を通るか
- `TestRealProfilesCoverFPFrontier` — 上記の設計原則2が維持されているか
  (探索バースト / 横展開ファンアウト / 大量削除 / 外部大容量送信 / 内部対照)
- `TestMacProfileMakesWave3RulesMeasurable` — macOS プロファイルが migration 386 の
  各ルールのセレクタに実際に届いているか。加えて**禁止側**（SIP 無効化・リバース
  シェル・匿名アップローダ・VNC）が入り込んでいないことも見る。カバレッジ欲しさに
  攻撃相当の挙動を書くと、それは FP を測ったことにならず真陽性を誤ラベルするだけ
- `TestGeneratorEmitsEveryRatedKind` — `rates` に対して実際にイベントが出るか

**`rates` に値を入れたのに対応する `[[...]]` を書き忘れると、その種別は無音になる。**
`Profile.Validate` がこれを起動時に弾く — 無音のまま「誤検知ゼロ」という
誤った合格が出るのを防ぐため。

---

## ソークの実行

CI は `.github/workflows/fp-soak.yml`、docker compose を使うローカル実行は
[`docs/ops/FPソーク運用.md`](../../docs/ops/FPソーク運用.md) §3。

**`local-soak.sh`** は docker を使わずに素の PostgreSQL 16 + `nats-server` で
スタックを立てる。用途は 2 つある。

```bash
tests/fpsoak/local-soak.sh setup
tests/fpsoak/local-soak.sh run before EDR_SIGMA_DB_RULES=0
tests/fpsoak/local-soak.sh run after  EDR_SIGMA_DB_RULES=1
tests/fpsoak/local-soak.sh teardown
```

1. **docker が無い環境**（CI コンテナ内、権限のないホスト）。TimescaleDB も要らない
   —— migration は `|| true` で適用され、CI も同じである。
2. **A/B 比較**。CI の待機列は 1 本しか無く、別ブランチの PR が走っているだけで
   自分の計測が押し出される。同一マシン・同一 seed で環境変数だけを変えれば、
   差分は変更に帰属できる。

⚠️ **アームの比較は `OPEN` 件数で行うこと。** `run` の出力が両方を並べて表示する。
`fpsoak-report` の見出し数字は窓内の**全行**で、重複排除は行を resolved にして
残すため、統合がどれだけ効いてもその数字は動かない。詳細は
[FPソーク運用.md §4](../../docs/ops/FPソーク運用.md) と負債台帳 P5-30。
