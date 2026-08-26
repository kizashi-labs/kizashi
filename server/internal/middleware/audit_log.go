package middleware

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditLogger logs all mutating API requests to the audit_logs table.
type AuditLogger struct {
	pool *pgxpool.Pool

	// logFn overrides where entries go. nil means "write to the DB" (a.log).
	// テストから差し替えるためだけの口です —— この middleware は長いあいだ
	// **未配線のまま「直された」**経歴があるので、配線とエントリの中身を
	// 通常の go test で押さえておかないと、また黙って死にます。
	logFn func(context.Context, AuditEntry)
}

// NewAuditLogger creates a new AuditLogger.
func NewAuditLogger(pool *pgxpool.Pool) *AuditLogger {
	return &AuditLogger{pool: pool}
}

// Middleware returns a Gin middleware that logs mutations to the audit log.
func (a *AuditLogger) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Only log mutating requests
		method := c.Request.Method
		if method == "GET" || method == "HEAD" || method == "OPTIONS" {
			c.Next()
			return
		}

		// Read request body (up to 4KB)
		//
		// **認証・パスワード系の経路では本文を保存しない。** /auth/login の本文は
		// 平文のパスワードそのもので、監査ログに写すとログが資格情報の保管庫になる。
		var bodySnippet string
		if sensitiveAuditPath(c.Request.URL.Path) {
			bodySnippet = "[redacted]"
		} else if c.Request.Body != nil {
			bodyBytes, _ := io.ReadAll(io.LimitReader(c.Request.Body, 4096))
			c.Request.Body = io.NopCloser(bytes.NewBuffer(bodyBytes))
			if len(bodyBytes) > 0 {
				bodySnippet = string(bodyBytes)
				if len(bodySnippet) > 500 {
					bodySnippet = bodySnippet[:500] + "..."
				}
			}
		}

		start := time.Now()
		c.Next()
		duration := time.Since(start)

		// Extract user from context
		//
		// 鍵は "user_role"。authMiddleware が置くのはこの名前で、"role" ではない
		// （"role" を読んでいた間、user_role 列は常に空になるはずだった —— 実際は
		// この middleware 自体が未配線で、どちらにせよ書かれていなかった）。
		userID, _ := c.Get("user_id")
		role, _ := c.Get("user_role")
		userIDStr, _ := userID.(string)
		roleStr, _ := role.(string)

		// Log to DB asynchronously
		logFn := a.logFn
		if logFn == nil {
			logFn = a.log
		}
		go logFn(context.Background(), AuditEntry{
			UserID:      userIDStr,
			UserRole:    roleStr,
			Method:      method,
			Path:        c.FullPath(),
			RequestURI:  c.Request.RequestURI,
			StatusCode:  c.Writer.Status(),
			SourceIP:    c.ClientIP(),
			UserAgent:   c.Request.UserAgent(),
			RequestBody: bodySnippet,
			DurationMs:  duration.Milliseconds(),
		})
	}
}

// sensitiveAuditPath reports whether the request body on this path may carry
// credentials and must not be copied into the audit log.
func sensitiveAuditPath(path string) bool {
	p := strings.ToLower(path)
	return strings.Contains(p, "/auth/") || strings.Contains(p, "password")
}

// AuditEntry holds data for one audit log record.
type AuditEntry struct {
	UserID      string
	UserRole    string
	Method      string
	Path        string
	RequestURI  string
	StatusCode  int
	SourceIP    string
	UserAgent   string
	RequestBody string
	DurationMs  int64
}

// log writes an audit entry to the database.
func (a *AuditLogger) log(ctx context.Context, entry AuditEntry) {
	if a.pool == nil {
		return
	}
	// audit_logs carries two generations of column names and this INSERT has to
	// satisfy both. Migration 006 created it with action/ip_address (action is
	// NOT NULL with no default); 173 re-declared the table with method/path/
	// source_ip, but CREATE TABLE IF NOT EXISTS is a no-op on an existing table,
	// so 006's shape is what actually lives in the database and 173 only
	// contributed its ALTERs.
	//
	// Writing only the 173 names therefore violated action's NOT NULL and every
	// row was rejected — this middleware runs on every API request, so the
	// ordinary operation history was never recorded at all. The failure was
	// invisible: ON CONFLICT DO NOTHING makes a rejected row look like a
	// duplicate, and the error went to Debug.
	//
	// The readers are split across both generations too (password_policy_handler
	// and audit_sign_handler select action/ip_address; insider_threat_detector
	// groups by action), so dropping the NOT NULL instead would keep the write
	// succeeding while leaving those views empty — the same bug with a green light.
	action := strings.TrimSpace(entry.Method + " " + entry.Path)
	_, err := a.pool.Exec(ctx, `
		INSERT INTO audit_logs (action, ip_address,
		                        user_id, user_role, method, path, request_uri, status_code,
		                        source_ip, user_agent, request_body, duration_ms)
		VALUES ($11::text, $7::text,
		        $1,$2,$3,$4,$5,$6,$7::text,$8,$9,$10)
		ON CONFLICT DO NOTHING
	`, entry.UserID, entry.UserRole, entry.Method, entry.Path, entry.RequestURI,
		entry.StatusCode, entry.SourceIP, entry.UserAgent, entry.RequestBody, entry.DurationMs,
		action)
	if err != nil {
		// Warn, not Debug. Reaching here means an audit record was dropped, and
		// nothing else reports it. Debug is what kept this invisible.
		slog.Warn("audit_logs への書き込みに失敗しました（監査記録が欠落します）",
			"error", err, "action", action)
	}
}
