# OpenAPI の網羅率と同期ゲート

**対象:** `docs/openapi.yaml` / `server/docs/openapi.yaml` / `server/cmd/openapi-sync`
**関連:** [APIドキュメント実装乖離監査_20260804.md](APIドキュメント実装乖離監査_20260804.md)（`admin/api-docs` 画面側の同種の作業）

---

## 1. 何が問題だったか

### 1-1. 網羅率 8%

`router.go` に登録されている操作は **1,459**（メソッド × パス）。対して
`docs/openapi.yaml` の記載は **171 操作**。しかも後述のとおり、そのうち 52 は
実装に存在しない。実在する記載は **119 操作 = 8.2%** だった。

つまり、この仕様書だけを見て API を叩こうとすると、**9 割以上のエンドポイントは
存在すら分からない**。

### 1-2. 書いてある分の 3 割が嘘

手書き 171 操作のうち **59**（移植分を含む）が `router.go` に無かった。内訳の型は
[APIドキュメント実装乖離監査](APIドキュメント実装乖離監査_20260804.md) と同じ。

| 型 | 例 | 件数 |
|---|---|---|
| パスが違う | `GET /api/v1/auth/me` → 実際は `/api/v1/users/me` | 多数 |
| メソッドが違う | `PUT /api/v1/alerts/{id}/status` → 実際は `POST` | 8 |
| 経路そのものが無い | `/api/v1/billing/*`、`/api/v1/admin/system-updates/*` | 10 |
| ルート直下なのに `/api/v1` 配下として記載 | `/api/v1/health`、`/api/v1/metrics`、`/api/v1/ws/alerts` | 4 |

`billing` と `system-updates` は README の「含まれないもの」に挙がっている
機能で、OSS 版のルータには最初から無い。仕様書だけが残っていた。

### 1-3. 仕様書が 2 つあり、内容が食い違っていた

- `docs/openapi.yaml` — 119 パス。`servers: http://localhost:8080`、パスは `/api/v1/...`
- `server/docs/openapi.yaml` — 64 パス。`servers: /api/v1`、パスは `/alerts` のような相対

後者が `go:embed` で取り込まれ、**API が実際に配信していた**のはこちら。
両方が別々に手書きされ、片方にしか無い記述が 26 パス分あった。
`GET /api/v1/docs/openapi.yaml` を叩いて得られる仕様と、リポジトリの
`docs/openapi.yaml` が別物、という状態だった。

## 2. どう直したか

### 2-1. 正本を 1 つにした

`docs/openapi.yaml` を正本とし、配信側にしか無かった 26 パス（と、それが参照する
5 つのコンポーネント定義）を移植した。`server/docs/openapi.yaml` は正本の
**バイト単位のコピー**にした。`go:embed` はパッケージディレクトリの外を参照
できないので、ファイル自体は 2 つ残るが、内容が一致することを CI で固定する。

### 2-2. 乖離 59 件を是正した

38 件は実装のパス/メソッドへ付け替え、21 件は削除した。削除したのは、対応する
実装がそもそも無いもの（billing / system-updates / 未実装の PATCH など）。

### 2-3. 残りを自動生成で埋めた

`server/cmd/openapi-sync` が `router.go` を読み、記載の無い操作を
**自動生成スタブ**として書き出す。スタブが保証するのは 4 つだけ:

- パス
- メソッド
- 認証要否（`security: []` の有無）
- パスパラメータ

**要求/応答の形状は書かない。** これは手抜きではなく設計判断で、実装から
機械的に導けないものを埋めると、このファイルが以前そうだったように「静かに
嘘になる」。スタブは `x-generated: true` を持ち、応答は
`#/components/responses/Undocumented` を指す。

結果、**1,117 パス / 1,459 操作**（＝実装の 100%）が仕様書から辿れるようになった。

## 3. 「網羅率」の数え方

自動生成スタブは網羅率に**数えない**。

> **網羅率 = 要求/応答の形状まで手書きされた操作 ÷ 実装の全操作**

導入時点で **178 / 1,459 = 12.2%**。スタブを数えれば 100% になるが、それは
「存在すること」しか言っていない数字で、実態より良く見えてしまう。

## 4. CI ゲート

`server/cmd/openapi-sync` のテスト（`go test ./cmd/openapi-sync/`）と、
CI の `OpenAPI sync check` ステップ（`go run ./cmd/openapi-sync -check`）が
次を落とす。

| 検査 | 落ちる条件 |
|---|---|
| `TestOpenAPIHasNoDrift` | 手書き記述が `router.go` に存在しない |
| `TestOpenAPIIsSynced` | ルートを足した/消したのに再生成していない |
| `TestEmbeddedSpecMatchesCanonical` | `server/docs/openapi.yaml` が正本と違う |
| `TestOpenAPICoverageDoesNotRegress` | 手書き網羅率が下限 12.0% を割った |
| `TestGeneratedStubsStayMinimal` | 自動生成ブロックに形状が書き足された |

## 5. 運用

**ルートを追加/変更したら:**

```bash
cd server && go run ./cmd/openapi-sync
```

`docs/openapi.yaml` と `server/docs/openapi.yaml` の両方が更新される。差分を
コミットする。

**スタブに中身を書きたくなったら:** そのブロックを自動生成セクションから
上の手書きセクションへ移し、`x-generated: true` を消してから書く。移した時点で
再生成の対象から外れ、以降は `TestOpenAPIHasNoDrift` が実装との一致を見張る。
網羅率も上がるので、`coverageFloorPercent` を引き上げる。

**手書き記述が `TestOpenAPIHasNoDrift` で落ちたら:** ルートを消した/リネームした
ということ。仕様書側を実装に合わせる。自動修正はしない — 「どのパスに移ったのか」
は実装からは決められないため。

## 6. 検証しないもの

- **要求/応答の形状** — 手書き分も、記載が実装と一致するかは機械検証していない。
  `admin/api-docs` 側では一部（成功レスポンスが単一の `gin.H` リテラルの場合）を
  静的に突合している（`internal/api/apidocs_routes_test.go`）。同じ手法をここへ
  広げる余地はある
- **パラメータ名の意味・クエリパラメータ** — パスパラメータの名前だけは
  `router.go` から取れるが、クエリは取れない
- **認証以外のミドルウェア** — 権限（admin 限定など）・レート制限・
  フィーチャーゲートは仕様書に出ていない
