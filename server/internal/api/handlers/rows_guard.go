package handlers

import (
	"log/slog"
	"net/http"

	"github.com/gin-gonic/gin"
)

// rowsErrer is the only part of a result set this guard needs. Taking the
// narrow interface rather than pgx.Rows lets it accept the package's own
// narrowed row types (e.g. pgxRows in ai_usage_handler.go) as well.
type rowsErrer interface{ Err() error }

// abortOnRowsErr reports a fatal row-iteration failure and aborts the request,
// returning true when the caller must stop.
//
// Why this exists: handlers iterate with
//
//	for rows.Next() {
//	    if err := rows.Scan(...); err != nil { continue }
//	    out = append(out, x)
//	}
//	c.JSON(http.StatusOK, out)
//
// pgx v5 marks a Rows fatal and CLOSES it when Scan fails, so that `continue`
// does not skip one row — the next Next() returns false and every remaining row
// is dropped. The handler then answers 200 with a short list and nothing says so.
// Live on 2026-08-03 this cost 38 of 56 alerts on GET /api/v1/alerts (which also
// kept reporting `total: 56` from a separate COUNT(*)), and made an ATT&CK
// detection-rate measurement read 13.6% against an actual 86.4%.
//
// A truncated list from a security console is worse than an error: the analyst
// cannot tell that anything is missing. So this answers 500 rather than serving
// partial data, and logs the cause server-side instead of leaking it to the client.
//
// what names the data being listed and only reaches the server log.
func abortOnRowsErr(c *gin.Context, rows rowsErrer, what string) bool {
	if err := rows.Err(); err != nil {
		slog.Error("行の走査に失敗しました（部分結果は返しません）", "対象", what, "error", err)
		c.AbortWithStatusJSON(http.StatusInternalServerError,
			gin.H{"error": "データの取得に失敗しました"})
		return true
	}
	return false
}
