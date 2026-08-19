# CI・デプロイ運用と GitHub Actions コスト最適化

**最終更新:** 2026-06-15（PR #113, #114, #133）

このリポジトリは**プライベート**（商用EDRソースのため公開不可）です。GitHub Actions は
パブリックリポジトリでは無料無制限ですが、**プライベートは Free プランで月2,000分の無料枠**
（請求サイクルごとに**毎月リセット**）で、超過分は従量課金（Linux ランナー $0.008/分）に
なります。本書はその課金を抑えるための運用と設定をまとめます。

---

## 1. 課金の仕組み（要点）

- 無料枠 **2,000分/月**（毎月リセット）。超過分のみ課金。
- 課金されるのは **Actions の実行時間**（と一部ストレージ）だけ。EC2 上で稼働中の
  プラットフォーム費用は **AWS 側**で、GitHub とは別物。
- 課金は**設定した予算（Settings → Billing → Budgets）の上限まで**。予算を $0/Stop に
  すると課金されない代わりに Actions が止まる（＝デプロイもブロックされる）。
- 使用量・課金額は **Settings → Billing and plans → Plans and usage** で確認。

> 2026-06-12、1日に約20PRを連続マージしたことで無料枠を使い切り課金が発生
> （途中で「Actions budget is preventing further use」が出た）。下記の最適化を導入。

---

## 2. 導入済みの最適化

### 2-1. docs/Markdown のみの変更で CI スキップ（PR #113）
`ci.yml` / `coverage.yml` / `security.yml` の `push`・`pull_request` に `paths-ignore` を追加:

```yaml
paths-ignore:
  - 'docs/**'
  - '**/*.md'
  - 'LICENSE'
  - '.gitignore'
```

- ドキュメントのみのコミットは **CI を起動しない**。
- `ci.yml` が起動しないと、それを `workflow_run` の起点とする `docker.yml` も連鎖しない
  → docs変更は**実質0 Actions分**。
- **コードとdocsの混在PRは従来どおりCIが走る**（path filter は全ファイルが対象パターンに
  一致したときだけスキップ）。
- 運用上の注意: **docs専用PRはCIチェックが付かない**ので、緑待ちせず直接マージしてよい。

### 2-2. デプロイを手動/タグのみに（PR #114）
`docker.yml`（api/ingestion/detect/frontend の**4イメージビルド＋EC2デプロイ**＝最大の
コスト源）のトリガーを変更:

- 旧: `workflow_run`（ci.yml 完了で**毎マージ自動**）
- 新: `workflow_dispatch`（手動）＋ `push: tags v*.*.*`（リリース）

**コードPRをマージしても自動デプロイされません。** デプロイは複数PRをまとめて任意の
タイミングで実行します。

`ci.yml`（テスト＋エージェントバイナリ配信）は緑チェックとバイナリ配布のため毎マージ継続。

### 2-3. security.yml の週次 cron 停止（PR #133）
`security.yml` は `push(main)`・`pull_request` に加えて **`schedule: cron '0 2 * * 1'`（毎週月曜 02:00 UTC）** を持ち、**コミットが無くても毎週 Trivy/Semgrep/Gitleaks が走って課金**していた。この cron を削除し `workflow_dispatch`（手動）に置換:

```yaml
# 旧
  schedule:
    - cron: '0 2 * * 1'
# 新
  workflow_dispatch: {}
```

- **無活動時（push/PR が無い期間）の Actions 課金がゼロ**になる。
- 定期スキャンが必要なときは手動実行: `gh workflow run security.yml --ref main`。
- push(main)/PR 時のセキュリティスキャンは従来どおり継続。

> **★ paths-ignore の副作用（2026-08-03 発見）**: 上記 2-1 の `paths-ignore` は正しい判断だが、
> **「docs にしか関係しない検査」まで一緒にスキップする**。PR #639 で入れた負債台帳の整合性ゲート
> （`server/internal/store/debt_ledger_test.go`）は `Server Tests (Go)` の中にあったため、
> **台帳を編集する PR（＝定義上ほぼ常に docs-only）では一度も走らなかった**。PR #641 でチェックが
> 1 つも付かなかったことで発覚した。`.github/workflows/docs-gate.yml` を追加し、`docs/**` と
> `**/*.md` を対象にその 4 検査だけを 1 ジョブで走らせるようにした（`paths-ignore` を外すと
> docs の typo 修正で E2E や Trivy まで走り、2-1 が消したコストが戻るため）。
> **CI にゲートを足したら、そのゲートが守る変更を含む PR で実際に走ったかを一度確認すること。**
> ジョブが緑なのと、ジョブが実行されたのは違う。

> 補足: 残る課金源は push/PR で走る `ci.yml`/`coverage.yml`/`security.yml`。**開発で push/PR しなければ Actions はほぼ動かない**。Actions 課金はアカウント単位の共通プール（リポジトリ別請求ではない）で、本リポジトリの重い CI（E2E Playwright・Trivy 4イメージ等）がアカウントの分数をほぼ独占している（他リポジトリは workflow がほぼ無く無消費）。

### 2-4. 解析ツールのバージョン固定と FP soak の直列化（PR #609 / #637, 2026-08-03）

**問題**: `go install ...@latest` で入れるツールは、**コードを変えていないのに突然赤くなる**。
§5 に govulncheck での実例が 2 件記録されているが、同じことが lint 側でも起こりうる状態だった。

固定した対象:

| ツール | 変更前 | 変更後 |
|---|---|---|
| golangci-lint | `go install ...@latest` | `golangci/golangci-lint-action@v8` + `version: v2.12.2` |
| staticcheck（server / agent 両方） | `@latest` | `@v0.7.0` |
| govulncheck（server / agent 両方） | `@latest` | `@v1.6.0` |

#### ★ govulncheck の固定は staticcheck とは意味が違う

ここは誤解したまま運用されると危険なので明記する。

| | staticcheck / golangci-lint | govulncheck |
|---|---|---|
| 赤くなる原因 | ツールに新しい検査が増える | **実行時に取得する脆弱性 DB** |
| 版を固定すると | 新しい検査が入らなくなる | **何も減らない** |

govulncheck が報告する脆弱性は解析エンジンの版ではなく、実行時に `vuln.go.dev` から取得する DB に
由来する。**DB は毎回取り直されるので、版を固定しても新規 CVE の検知力は一切落ちない。**
§5 の「コードを変えていないのに突然赤くなる」性質は固定後も変わらない（それが正しい挙動である）。

固定して防げるのは解析エンジン側の事故だけである——新リリースが `go.mod` より新しい Go
ツールチェインを要求して `go install` が失敗する、出力形式や終了コードが変わる、到達可能性解析の
リグレッションで既知の脆弱性を見落とす。いずれもコード無変更で CI の色が変わる事象なので pin する
価値はある。固定時点で `@latest` は v1.6.0 に解決されたため、挙動は変わっていない。

> **注意（手動更新が要る）**: Dependabot の `github-actions` エコシステムは `uses:` しか見ないため、
> `run:` の中の `go install ...@vX.Y.Z` は**自動更新されない**。上記の pin はすべて手動で上げる
> 必要がある。放置すると解析エンジンだけが古びる。

#### FP soak の直列化

`fp-soak.yml` に `concurrency: { group: fp-soak, cancel-in-progress: false }` を追加した。

FP soak は 20 エージェントの良性フリートを 600 秒走らせて誤検知を数える定点観測なので、**複数の
run が同時に走ると互いのアラートを数え合って測定が汚染される**。実際に #604 の初回測定が並行実行で
使いものにならなくなった。`push` が main 限定なのは 2 つある入口の 1 つを塞いだだけで、より頻度の
高い**複数 PR の並行実行**が残っていた。

留意点が 2 つある。

- `cancel-in-progress: false` でも**キューに保持される run は 1 つだけ**である。待機中の run が
  ある状態でさらに新しい run が来ると、待機中の方が置き換えられる（キャンセル扱いになる）。
- concurrency 設定は**ワークフロー・ファイル自体に書かれている**ため、この変更を含まないブランチの
  run は直列化の対象外になる。古い定義のブランチが並行して走る可能性は残る。


---

## 3. デプロイ手順（バッチデプロイ）

複数のコードPRをマージしたあと、まとめて1回デプロイする:

```bash
# 認証トークン（GCM経由）
TOKEN=$(printf 'protocol=https\nhost=github.com\n\n' | git credential fill | awk -F= '/^password=/{print $2}')

# main を手動デプロイ（4イメージビルド＋EC2デプロイ）
GH_TOKEN="$TOKEN" gh api -X POST \
  repos/kizashi-labs/kizashi/actions/workflows/docker.yml/dispatches -f ref=main

# 実行を監視（成功まで）
GH_TOKEN="$TOKEN" gh api \
  "repos/kizashi-labs/kizashi/actions/workflows/docker.yml/runs?per_page=1&event=workflow_dispatch" \
  --jq '.workflow_runs[0] | "\(.status)/\(.conclusion) id=\(.id)"'
```

- リリース時は `v*.*.*` タグを push すれば自動でビルド＋デプロイ。
- `.github/` やドキュメントのみのマージはプラットフォーム本体に影響しないので手動デプロイ不要。
- デプロイ後は EC2 でリビジョン（`docker inspect ... org.opencontainers.image.revision`）と
  対象機能を実機検証する。

---

## 4. 採用しなかった選択肢と理由

### セルフホストランナー（検証EC2への設置）— 非推奨
Actions 分を実質無料化できるが、**検証EC2（2 vCPU / 7.6GB / load≈1.9 / disk 78%）に
載せると、CIビルド（Next.js・4イメージビルド・Goコンパイル）が稼働中のプラットフォームと
資源競合し、OOM・不安定化のリスクが高い**ため見送り。導入するなら専用インスタンスだが、
超過課金 $0.008/分 に対し別EC2代（月$30前後）が割高になりがちで、平常運用なら §2 の
2対策＋無料枠で足りる見込み。CI頻度が恒常的に無料枠を大きく超える場合に専用インスタンスで
再検討する。

### 変更イメージのみビルド — 保留
`docker.yml` が常に4イメージをビルドするのを「変更があったイメージだけ」に絞れば中〜大の
削減になるが、`workflow_dispatch`/binary-commit 下での変更検出が不安定でデプロイ経路の
リスクが高いため保留。

---

## 5. トラブルシュート

- **全チェックが数秒で同時に failure** になったら、コードではなく**Actions 予算の枯渇**を
  まず疑う（annotation に "Actions budget is preventing further use"）。予算を引き上げるか
  翌月の無料枠リセットを待つ。
- **手動デプロイが反映されない**: `workflow_dispatch` は `ref=main` を指定（checkout は
  dispatch ref を使う）。docker/deploy ジョブの `if` は `workflow_dispatch`/`push` を許可済み。
- **deploy ジョブが `error from registry: denied`（GHCR pull 不可）**（2026-06-15）:
  - GHCR パッケージ4種（server-api/detect/ingest, frontend）は `private` だが `edr-platform`
    リポジトリに**紐付け済み**で、workflow の `GITHUB_TOKEN(packages:read)` で pull できる正しい状態
    （`gh api user/packages/container/<name>` で確認。要 `read:packages` スコープ）。**GHCR設定の修正は不要。**
  - EC2 上で**手動** `docker compose pull` すると denied になるのは、EC2 に残った**期限切れの古い
    `docker login`**が原因。docker.yml の deploy ジョブは毎回 `GITHUB_TOKEN` で `docker login` し直す
    （docker.yml:170）ため、ワークフロー経由なら本来 pull できる。
  - **GHCR を介さない緊急反映（方式A・実績あり）**: EC2 にソースがあるので frontend をソースビルドして
    差し替えられる。git は SSH リモートで認証が通る。
    ```bash
    # EC2 上
    cd /home/ubuntu/edr-platform && git pull --ff-only origin main
    # ★ビルド引数必須: NEXT_PUBLIC_API_URL=/api/v1（既定の localhost:8080 だとブラウザが壊れる）
    export IMAGE_TAG=main NEXT_PUBLIC_API_URL=/api/v1
    nohup docker compose -f docker-compose.yml build frontend > /tmp/fe-build.log 2>&1 &   # 長時間→nohup必須(SSH切断対策)
    docker compose -f docker-compose.yml -f docker-compose.prod.yml up -d --no-deps frontend  # pullはdeniedだがローカル:mainを使い recreate
    docker restart edr-caddy   # frontend 再作成で IP が変わるため Caddy の DNS キャッシュを更新
    ```
    ロールバック用に事前に `docker tag ...frontend:main edr-frontend-backup:pre<x>`。
- **deploy ジョブが skipped / 全ビルドが 1秒・0ステップで失敗**: §5 冒頭の通り **Actions 予算枯渇**。
  GHCR とは無関係。Billing で上限を上げるか翌月リセットを待つ。
- **frontend 再作成後にサイトが 502**: frontend コンテナの IP が変わり Caddy が旧 IP をキャッシュ。
  `docker restart edr-caddy` で解消。`up -d` が api 依存で frontend を `Created` のまま止めた場合は
  `docker start edr-frontend` してから Caddy 再起動。
- **`Deploy Agent Binaries` が `! [rejected] main -> main (fetch first)` で失敗**（2026-07-20 是正）:
  checkout から `git push` までに main の tip が動くと、リトライ無しの素の push が弾かれる（複数セッションの
  同時マージ・coverage badge コミット・agent-ebpf のバイナリコミットが並行するため頻発）。**失敗するだけでなく
  配布バイナリが陳腐化する**（`downloads/` が 18 日間更新されず、新規インストールが古い agent を掴んでいた）。
  → [PR #500](https://github.com/kizashi-labs/kizashi/pull/500)/[#501](https://github.com/kizashi-labs/kizashi/pull/501) で 5 回リトライを追加。
  **`git pull --rebase` ではなく「リモート tip へ reset して成果物を再適用」**する方式（ci.yml/agent-ebpf.yml/coverage.yml で統一）。
  理由: 2 つの run が同じ `downloads/` や `badges/coverage.json` を再生成する**同一ファイル競合**では rebase が
  `CONFLICT (content)` で未解決停止しループが詰まる。ビルド成果物/計測値の正しい意味論は「最後のビルドが勝つ」で、
  reset+再適用がそれを表現する。
- **`Load Test (k6 smoke)` が `exit code 124`（タイムアウト）**（2026-07-20 是正）: `go run ./cmd/api/ &` +
  `timeout 30` の構成で、`go run` が**コンパイルごとバックグラウンド化**するため、ビルドキャッシュが冷えていると
  API がまだリンク中に 30 秒枠を使い切る。**コンパイルエラーでも同じ 124** になり原因が判別できなかった。
  → [PR #505](https://github.com/kizashi-labs/kizashi/pull/505) で先に `go build` してから起動し、待ちを「起動のみ」に限定。`/health` を
  1 秒間隔で最大 60 秒ポーリングし、プロセスが先に死んだら API のログを出して即失敗させる（コンパイル失敗/起動失敗/
  未応答が別々のエラーになる）。E2E Playwright ジョブも同型の欠陥（ヘルスチェック無しの `sleep 5`）だったので揃えた。
- **`Install k6` が `gpg: can't connect to the dirmngr` で失敗**（2026-07-20 是正）: k6 apt リポジトリの署名鍵を
  keyserver から取得していたが、ランナーイメージに `dirmngr` が無く `/root/.gnupg` も存在しないため失敗。
  → [PR #516](https://github.com/kizashi-labs/kizashi/pull/516) で keyserver/apt/GPG 依存を捨て、GitHub Releases のピン留めバイナリ（v2.1.0）を
  `checksums.txt` で **sha256 検証してから**インストールする方式へ変更（上流リポジトリ/keyserver の障害に左右されない）。
  > k6 の失敗は **API 起動タイムアウト → k6 インストール → E2E 同型欠陥** の 3 層が積み重なっており、1 つ直すたびに
  > 次が露出した。表面的には「同じジョブがずっと赤い」ようにしか見えないため、失敗が原因ごとに別エラーとして出る形へ
  > 直すことが切り分けの前提だった。
- **`Server Tests (Go)` の `govulncheck` が突然 failure に**（2026-07-25 是正）: コード変更なしに
  `govulncheck` が赤くなった場合は**新規公開された脆弱性アドバイザリ**を疑う。今回は
  `go.opentelemetry.io/otel/sdk@v1.42.0`（GO-2026-5426、BSD kenv コマンドの絶対パス未使用）が
  該当。`go.mod`/`go.sum` は base ブランチと完全一致しており PR の変更が原因ではなかったが、
  マージには CI を通す必要があるため otel ファミリー一式（`otel`/`metric`/`sdk`/`trace`/
  `otlptracegrpc`）を修正版 v1.43.0 系へ更新して対応（[PR #537](https://github.com/kizashi-labs/kizashi/pull/537)）。
- **`Agent Vulnerability Check (govulncheck)` が failure**（2026-08-01 是正）: 上と同型の再発。
  `google.golang.org/grpc`（GO-2026-6061、xDS RBAC 認可エンジンと HTTP/2 トランスポートサーバの脆弱性）
  が新規公開され、**agent(v1.79.3)・server(v1.80.0) の両モジュール**が該当した。どちらも `go.mod` は
  base ブランチと完全一致＝main 側にも存在する既存問題（実際に main の CI も赤）だが、PR をマージする
  には CI を通す必要があるため両モジュールを修正版 v1.82.1 へ更新して対応
  （[PR #537](https://github.com/kizashi-labs/kizashi/pull/537)）。
  > **教訓**: govulncheck は「コードを変えていないのに突然赤くなる」ジョブである（アドバイザリDBが
  > 日々更新されるため）。長命な PR ほど遭遇しやすい。切り分けの第一手は
  > `git diff origin/main -- <module>/go.mod` で **base と差分があるか**を見ること。差分ゼロなら
  > PR 起因ではなく、base 側にも同じ問題がある。
- **`golangci-lint` が新規追加ファイルの `gosec`(G304/G204) で failure**（2026-07-25 是正）: 新規
  `server/cmd/validate-rules/main.go`（検知ルール構文検証CLI）の `os.ReadFile`/`exec.CommandContext`
  が「変数由来パス/コマンド」として検出。パスは `globRecursive()` が固定の `rules/sigma`・`rules/yara`
  ディレクトリを走査した結果のみで外部入力ではないため、`internal/scheduler/backup_scheduler.go` の
  既存パターンと同じ `#nosec G304 -- 理由` 形式で注釈して解消（[PR #537](https://github.com/kizashi-labs/kizashi/pull/537)）。
- **CI 構成に3ジョブを追加**（2026-07-25）: `sdk-test`（Python/TypeScript 両SDKのテスト実行。従来
  どちらもCIで一度も実行されていなかった）、`rules-validate`（Sigma/YARA ルール構文検証）、
  `agent-test` へのカバレッジ計測・閾値ゲート（30%）追加。いずれもテストカバレッジ監査を受けた
  対応で、Actions 分は増えるが「壊れたルール/脆弱な依存/未実行のテストが本番まで気づかれない」
  リスクの方が大きいと判断（詳細は `docs/技術的負債と改善計画.md` の P2-1、CHANGELOG
  `[Unreleased]`、[PR #537](https://github.com/kizashi-labs/kizashi/pull/537)）。
- **PR のカバレッジコメントが常に「❌ Fail」と表示される**（2026-08-01 是正）: `coverage.yml` の
  PR コメントが**自前で `Threshold: 40%` をハードコード**しており、実際にビルドをブロックする
  ゲート（`ci.yml` の `Check coverage threshold`、当時 35%）と乖離していた。結果、実ゲートを
  クリアして**全チェックが緑の PR でも赤い「❌ Fail」が出続け**、レビュー中に3度「CI が落ちている」
  と誤読される原因になった（`Go Coverage Report` ジョブ自体は success）。
  → `coverage.yml` が `ci.yml` の `server-test` ジョブから実ゲート値を読み取る方式に変更し、
  表示を `Gate (enforced in ci.yml)` に改名、「このジョブは計測・報告のみでゲートではない」旨も
  コメント末尾に明記した。パースに失敗した場合は**誤った判定を出さず合否行を省略**する。
  抽出は `server-test` ジョブブロックに限定している（`agent-test` にも同名ステップ（30%）が
  あり、素朴な `grep | head -1` ではジョブ順が変わった際に静かに別の値を拾うため＝本件と同種の
  事故になる）。（[PR #537](https://github.com/kizashi-labs/kizashi/pull/537)）

---

## 6. 予算枯渇中でも前進する方法（2026-06-19 実証）

Actions 予算が枯渇すると全ジョブが2秒で失敗する（annotations が
`The job was not started because an Actions budget is preventing further use.`）。翌月リセット
（請求サイクル＝多くは毎月1日 UTC）か予算引き上げまで GitHub-hosted CI は止まるが、以下で**待たず・課金せず**開発を続けられる。

### 6-1. ローカル検証根拠マージ（main 無保護を活用）

main はブランチ保護なしなので、CI 赤でも `gh pr merge --squash` で統合できる。**CI と同等のチェックを
ローカルで回し、それを根拠にマージ**する:
- Go: `go build ./...` / `go test ./...` / `go vet ./...` / `gofmt -l`
- 低リスク変更（特に **CI が一切コンパイルしない部分**＝build タグ付きコード・`.bpf.c` 等）は安全度が高い。
- Linux 実行前防御 Ph1〜Ph6（`prevention` タグ＋`.bpf.c`、ci.yml はタグ無しビルドのため非コンパイル）は
  この方式で全マージ（PR #226〜#233）。実機検証は EC2 ローカルビルドで予算非依存に実施。

### 6-2. EC2 ローカルビルドで実機検証（Actions 不要）

エージェント機能の検証は検証 EC2 上で `go build` して直接動かせば Actions を消費しない。
Linux eBPF/prevention は RHEL EC2 で `bpf2go` 生成＋`go build -tags "ebpf prevention"`（手順は
[Linuxカーネル防御検証ランブック.md](Linuxカーネル防御検証ランブック.md)）。ci.yml のバイナリ自動配信に依存しない。

### 6-3. 予算が必須なのはどこか

- **必須**: `ci.yml` のエージェントバイナリ**本番配信**、`docker.yml` の **server イメージ＋migration 反映**。
- **不要**: 上記ローカル方式での実装・検証・マージ。

→ 開発・検証は予算ゼロで進め、**本番配布（Ph6 等）だけ予算復旧後にまとめて回す**のが最適。

### 6-4. 「枯渇の瞬間」を挟んだ判定の作法（2026-07-25/26 実証）

予算は**run の途中で尽きる**ことがある。RLS 分離 PR #541 では次の時系列になった:

- 初回 run: **正常に走り切り**、`Server Tests (Go)` が 10分2秒で **PASS**（＝変更本体は検証済み）。
- その run が残予算を消費 → **以降の全 run（rerun ×2 / 新規 push / 翌日の workflow_dispatch）が全ジョブ 2 秒 fail**。
- 31 時間後も同症状 ＝ 一時障害ではなく予算枯渇と確定（annotations で確証）。

この状態で「CI 緑後マージ」を機械的に適用すると永久に進めない。**初回 run の結果を証拠として使える**ようにするのが要点:

```bash
# CI が実際に検証した sha と、マージしようとしている HEAD のツリーが同一かを実証する
git diff <CIが走ったsha> <HEAD> --stat     # 空 = 同一ツリー = 初回 run の緑がそのまま効く
# 落ちたジョブが当該変更と無関係であることも実証する（例: agent ファイルを1つも触っていない）
git diff --name-only origin/main..HEAD | grep -c '^agent/'   # 0
```

rebase や `--amend` を挟んでもツリーが変わっていなければ、初回 run の結果は有効な証拠になる。

**罠: 予算枯渇下では「再実行」は判定に使えない**

- `gh run rerun --failed`（部分再実行）は `needs:` 依存が満たされず即失敗する（例: `E2E` は `needs: [frontend-build]`）。
- 予算枯渇下では**全ジョブが 2 秒 fail** になるため、フルの `gh run rerun` も無意味。
- したがって**再実行を繰り返さない**。判定は「初回 run の結果 ＋ ツリー同一性 ＋ ローカル検証」で行う。

**判別の決め手**（コードや YAML を先に触らないこと）:

```bash
jid=$(gh run view <run_id> --json jobs --jq '.jobs[0].databaseId')
gh api repos/<owner>/<repo>/check-runs/$jid/annotations --jq '.[].message'
# → "The job was not started because an Actions budget is preventing further use."
```

`steps: []` かつ数秒で failure、`log not found` も同じサインである。

---

## 7. 断続的な CI の赤を切り分ける（フレーク vs 恒久回帰・2026-07-23 実証）

このリポジトリは**複数セッションが高頻度で main にマージ**するため、CI の赤が「自分の変更の回帰」とは限らない。
実際に 2026-07-23 の調査では、run ごとに**別のジョブ**が落ちていた（07-22 は Server Tests、07-23 は E2E/k6）。
これは単一の恒久回帰ではなく**フレーク／個別の一過性要因**のシグネチャである。以下の順で切り分ける。
（run が数秒で全ジョブ fail する「予算枯渇」パターンの見分け方と、その状況での判定の作法は §6-4 を参照。）

### 7-1. run 全体の conclusion を信用しない — ジョブ単位で見る

`gh run list` の `failure` は「どれか1ジョブが落ちた」に過ぎない。`k6`/`E2E` は `continue-on-error: true` の
ものもあり、run が `failure` でも当該ジョブは `success` のことがある。必ずジョブ単位で確認する。

```bash
gh run view <run-id> --json jobs -q '.jobs[] | "\(.conclusion // .status)  \(.name)"'
# 落ちたジョブだけ:
gh run view <run-id> --json jobs -q '.jobs[] | select(.conclusion=="failure") | .name'
```

### 7-2. `cancelled` は失敗ではない — `concurrency: cancel-in-progress` の副作用

ci.yml は `concurrency: { group: CI-<ref>, cancel-in-progress: true }`。**新しい main push が走ると、実行中の
run の残りジョブが打ち切られる**。E2E/Playwright や k6 は**依存関係の後段にある長時間ジョブ**だったため、マージ頻度が
高い時間帯は完走前に `cancelled` になりやすかった。`cancelled` を「失敗」と誤読しないこと。

> **是正済み（2026-07-27）**: この2ジョブ（E2E Playwright / k6 smoke）を ci.yml から `integration.yml`
> （`schedule: '0 18 * * *'`＝毎日 03:00 JST ＋ `workflow_dispatch`）へ移設した。**push/PR では走らず**、
> 夜間に1回だけ確実に完走させて安定した信号を得る。両ジョブは API/frontend を自前でビルドする自己完結型なので
> 移設で `needs` は不要。per-push の frontend 挙動チェックは frontend-build の Vitest が担う。オンデマンドで
> 回したいときは `gh workflow run integration.yml --ref main`。

### 7-3. ログは早く失効する — 疑ったら即取得、無ければ再現

失敗ジョブのログは短期間で `BlobNotFound`（HTTP 404）になる。赤を見たら**その場で**取得する。

```bash
gh run view <run-id> --log-failed | tail -40                       # 失効前ならこれで足りる
gh api repos/<owner>/<repo>/actions/jobs/<job-id>/logs | tail -40  # ジョブ単位
```

失効済みなら、**フレークか恒久かを1 run で確定**する（コストは1 run）:

```bash
gh workflow run ci.yml --ref main         # 現 main で再実行
```

- 当該ジョブが**緑になればフレーク**（2026-07-23 の k6 はこれで green に戻り、フレーク確定）。
- **同じジョブが同じ理由で再度落ちれば恒久回帰** → 緑だった最後の sha との差分を `git log <green>..<red>` で絞る。

> 注意: 再実行してもすぐ別 push に `cancel-in-progress` で打ち切られることがある。その場合は**自分を打ち切った
> 後続 push の run に相乗り**して結果を見れば、追加コストなしで判定できる。

### 7-4. アプリ起動失敗と CI インフラ問題を分ける

E2E と k6 が**同時に**落ちたら、両者が依存する **API 起動**を疑う。§5 の health-gate 化（#505）以降、API が
起動に失敗すると API 自身のログが出て明示的に落ちるので、`gh run view --log-failed` で
`::error::API exited before becoming healthy` とスタックが読める。ここに Go の panic やマイグレーション失敗が
出ていればアプリ回帰（別セッションのコード変更由来のことが多い）、出ていなければ CI インフラ側（ランナー枯渇・
ネットワーク）のフレーク。
