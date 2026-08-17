package handlers

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/store"
)

// dbErrMsg returns a generic Japanese error message for database failures.
// Use this instead of err.Error() in HTTP responses to prevent raw SQL error
// messages (table names, column names, SQLSTATE codes) from leaking to clients.
//
// Usage:
//
//	c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
func dbErrMsg(err error) string {
	if err != nil {
		// Log the real error server-side so it's not lost.
		slog.Warn("db error (sanitized for client)", "error", err)
	}
	return "データベース操作に失敗しました"
}

// isConstraintViolation reports whether err is a PostgreSQL integrity-constraint
// error (class 23: check / not-null / foreign-key / unique) or a data-exception
// (class 22: invalid text representation, etc.). These mean the client sent
// invalid data and warrant a 400 — not a 500 or a misleading "not found".
func isConstraintViolation(err error) bool {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && len(pgErr.Code) >= 2 {
		switch pgErr.Code[:2] {
		case "22", "23":
			return true
		}
	}
	return false
}

// isValidUUID returns true if s is a valid UUID (any version).
func isValidUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, c := range s {
		if i == 8 || i == 13 || i == 18 || i == 23 {
			if c != '-' {
				return false
			}
		} else if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F')) {
			return false
		}
	}
	return true
}

// tableMissing reports whether err is PostgreSQL 42P01 (undefined_table).
//
// It is the one read failure that genuinely means "there is nothing here": a
// feature whose migration has not run yet has no rows and never had any. Every
// other failure — the database is unreachable, the role lacks SELECT, the
// statement timed out — means we could not find out, which is a different
// answer and must not be dressed up as the first one.
func tableMissing(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "42P01"
}

// readFailure writes the response for a read that could not be performed.
//
// これらのハンドラは以前、読み取りに失敗すると 200 と空のリストを返して
// いました。コンソールには「該当なし」と表示されます — 脆弱性0件、
// 未対応アラート0件、期限切れ間近の証明書0件。SOC にとってその画面は
// 「見るべきものが無い」という答えであって、「答えられなかった」ではありません。
// 空の一覧は、読んだ人にとって最も安心できる形をした嘘です。
//
// 「本当に無い」場合だけ、従来どおり空の形（あるいは既定値）を返します。
// それは2つ — マイグレーション未適用のテーブル (42P01) と、行が無いこと
// (pgx.ErrNoRows) — で、どちらも「まだ設定されていない」という事実です。
// それ以外は 500 です。
func ReadFailure(c *gin.Context, err error, empty any) {
	if absent(err) {
		c.JSON(http.StatusOK, empty)
		return
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
}

// ReadOK reports whether a single-row read can be used, and writes the response
// when it cannot.
//
// **`ReadFailure` の1行読み版です。** あちらは一覧の読み取りに入れた答えで、
// `_ = pool.QueryRow(…).Scan(&n)` は手つかずでした。実測 (2026-08-12):
// `internal/api/handlers` に 248 か所、**うち 223 は読んだ値が応答に
// 入ります** —— 数えられなかった 0 が「ブロック 0件」「未対応の重大な
// 脆弱性 0件」として画面に出ます。
//
// **「本当に無い」ときの形は変えません。** テーブル未作成 (42P01) と
// 行なし (`pgx.ErrNoRows`) は、どちらも「まだ設定されていない」という
// 事実なので、既定値のまま続けます（`absent` の判断は `ReadFailure` と
// 同じものです）。それ以外は 500 です。
//
// 呼び方:
//
//	if !ReadOK(c, h.Pool.QueryRow(ctx, q).Scan(&n)) {
//		return
//	}
func ReadOK(c *gin.Context, err error) bool {
	if err == nil || absent(err) {
		return true
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
	return false
}

// WriteOK reports whether a write succeeded, and writes the response when it
// did not.
//
// **`ReadOK` と違って、「まだ無い」を通しません。** 読み取りなら
// 「テーブルがまだ無い＝まだ設定されていない」は事実ですが、**書き込みで
// それが起きたら、書けていない**のに「保存しました」と答えることに
// なります。
//
// 実測 (2026-08-12): `_, _ = pool.Exec(…)` は 122 か所。**うち 55 は、
// そのあと 200/201 で答える関数の中**にあります —— 状態を変えたと
// 答えながら、1行も書いていないことがあります:
//
//	software_vulnerability  UPDATE を捨てて `{"status": 変更後}` を返す
//	dns_security            DELETE を捨てて `{"message": "entry removed"}`
//	recovery_code           **利用者が控える復旧コード**を、保存を確かめずに返す
//
// 呼び方:
//
//	if _, err := h.pool.Exec(ctx, q, args...); !WriteOK(c, err) {
//		return
//	}
func WriteOK(c *gin.Context, err error) bool {
	if err == nil {
		return true
	}
	c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
	return false
}

// absent reports whether err means "it is not there" rather than "we could not
// look".
func absent(err error) bool {
	return errors.Is(err, pgx.ErrNoRows) || tableMissing(err)
}

// TenantOrAbort returns the request's tenant, or writes 400 and returns false.
//
// これらのハンドラは `c.GetString("tenant_id")` を
// `WHERE tenant_id = $1::uuid` にそのまま渡します。テナントが空文字だと
// PostgreSQL は `invalid input syntax for type uuid: ""` を返すので、
// **そのリクエストは1件も読めません。**
//
// 空になる経路は2つ、どちらも実在します:
//
//   - **APIキー認証**。router.go は `c.Set("tenant_id", "")` を無条件で
//     置きます。**SDK からの読み取りは全部これです。**
//   - tenant_id クレームの無い JWT（単一テナント構成、組み込みの admin）
//
// 直前まではもっと悪い形でした。rows.Err() を見ていなかったので、
// クエリが失敗しても `rows.Next()` が false を返すだけで
// **200 と空のリストが返っていました** ——「カオス実験は0件です」と
// 読める応答です。同じキャンペーンで rows.Err() を足したところ、
// 隠れていた失敗が 500 として出てきました。テストが緑だったのは、
// 握り潰された失敗に対して 200 を期待していたからです。
//
// 500 と「データベース操作に失敗しました」では、呼び出し側は何をすれば
// よいのか分かりません。**答えられない理由は、こちら側にあります。**
// 400 で、テナントが特定できないと書きます。
//
// APIキーにテナントを持たせるかどうかは別の判断です（`api_keys` に
// tenant_id はありませんが、`users` にはあるので `user_id` から辿れます）。
// 判断待ちの一覧に記録しました。
func TenantOrAbort(c *gin.Context) (string, bool) {
	tenantID := c.GetString("tenant_id")
	if tenantID == "" {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "テナントを特定できないため、この一覧は返せません。" +
				"APIキーではなくユーザートークンでお試しください",
			"tenant_missing": true,
		})
		return "", false
	}
	return tenantID, true
}

// NotImplemented reports that a feature has no implementation behind it, as
// distinct from a read that failed.
//
// この2つを同じ形で返すと、運用担当は再試行します。データを作る処理が
// どこにも無いものを再試行しても、いつまでも同じ空が返るだけです。
// 501 は「まだ実装されていません」を意味する唯一のステータスで、
// missing にはそれを満たすために何が要るかを書きます。
func NotImplemented(c *gin.Context, feature, missing string) {
	c.JSON(http.StatusNotImplemented, gin.H{
		"error":           feature + "はまだ実装されていません",
		"not_implemented": true,
		"feature":         feature,
		"missing":         missing,
	})
}

// OptionalBody binds a request body that the caller is allowed to omit.
//
// いくつかのハンドラはこう書かれていました:
//
//	var req struct{ Reason string `json:"reason"` }
//	if err := c.ShouldBindJSON(&req); err != nil {
//		req.Reason = "手動隔離"
//	}
//
// 本文が無いときの既定値としては正しい書き方です。ただし ShouldBindJSON は
// 「本文が無い」(io.EOF) と「本文が壊れている」を同じ err で返します。
// つまり送信側の不具合で本文が壊れていても、既定値を入れて処理を続けます。
// 隔離の理由が実際には「手動隔離」ではないのに、記録にはそう残ります。
// おとりへのアクセス記録に至っては、送信元IPが 192.168.1.100 で作られていました。
//
// OptionalBody は本文が無いときだけ既定値を通し、壊れているときは 400 を
// 返して false を返します。呼び出し側は false ならそのまま return します。
func OptionalBody(c *gin.Context, req any) bool {
	err := c.ShouldBindJSON(req)
	if err == nil || errors.Is(err, io.EOF) {
		return true
	}
	c.JSON(http.StatusBadRequest, gin.H{
		"error": "リクエストの本文を読めませんでした。既定値では続けません: " + err.Error(),
	})
	return false
}

// tableIsThere は、そのテーブルが在るかを返します。
//
// **確認そのものに失敗したら true を返します。**
//
// この確認は、まだマイグレーションが当たっていない機能の画面を 500 に
// しないために置かれています。ところが 49 個すべてが、**確認の失敗を
// 「無い」と同じに扱っていました**:
//
//	return err == nil && exists   // 24 個
//	return exists                 // 18 個（err はログだけ、あるいは捨てる）
//	return ok                     // 7 個（`_ =` で捨てる）
//
// 呼び出し側 193 箇所は、それを受けて 200 の空（76）・404（62）・
// 503（54）を返します。**DB に届かないだけで「その機能は使われて
// いません」と同じ姿になります。**
//
// 実測 (2026-08-12): `statement_timeout` を 1ms にして
// `/api/v1/admin/bas/scenarios` を叩くと、`bas_scenarios` に 400 行
// あるのに **200 の空**が返りました。
//
// true を返すのは、**本物のクエリに答えさせる**ためです:
//
//   - DB が落ちている → 本物のクエリが失敗 → そのハンドラ自身の
//     失敗時の答え方（前回 146 箇所を揃えたもの）が答えます
//   - テーブルが本当に無い → 本物のクエリが 42P01 → `absent()` が
//     それを「無い」と見分け、従来どおり空を返します
//
// **どちらに転んでも、正しい方の答えが出ます。** 確認の失敗だけを
// 理由に「無い」と答えるのをやめます。
//
// なお `information_schema` は必ず在るので、この確認が 42P01 を返す
// ことはありません。ここでの err は「見に行けなかった」だけです。
func tableIsThere(ctx context.Context, pool *pgxpool.Pool, name string) bool {
	return store.TableIsThere(ctx, pool, name)
}

// probeAnswer は `store.ProbeAnswer` そのものです。
//
// **この package の検査（`table_probe_test.go`）と理由の一覧が、この名前を
// 指しています。** 本体は `internal/store` に移しました —— scheduler や
// reports など、handlers の外にも同じ確認が 24 個あり、そちらからも
// 使えないと「片方だけ直った」状態が続きます。
func probeAnswer(exists bool, err error) bool {
	return store.ProbeAnswer(exists, err)
}

// FeatureNotInstalled は、**やっていない作業を「やった」と答えない**ための
// 応答です。
//
// 変更系のハンドラに、テーブルが無いときそのまま成功を返すものが 8 つ
// ありました。実測 (2026-08-12):
//
//	POST /api/v1/campaigns              200 {"id":"<でっち上げ>","message":"created"}
//	DELETE /admin/edr-policies/:id      200 {"message":"削除しました"}
//	POST /api/v1/fim/ignore-rules       200 {"message":"ignore rule added"}
//	PUT  /admin/rbac/permissions        200 {"message":"Permissions saved"}
//
// **どれも1行も書いていません。** `campaigns` は存在しない id まで返すので、
// 画面はそれを「作成済みの1件」として持ちます。`rbac` のコメントには
// 「Accept but silently discard」と書いてありました —— 権限表を保存した
// つもりの管理者に、保存していないことは伝わりません。
//
// 503 なのは、**呼び出し側の誤りではない**からです（4xx にすると、正しい
// 要求を送った人が自分の要求を疑いに行きます）。この配備にその機能が
// 用意されていない、という事実そのものを返します。読み取り側が同じ状況で
// 503 を返している 54 箇所と揃えます。
func FeatureNotInstalled(c *gin.Context, what string) {
	c.JSON(http.StatusServiceUnavailable, gin.H{
		"error": what + "はこの配備では利用できません（データベースの用意ができていません）。保存していません。",
	})
}
