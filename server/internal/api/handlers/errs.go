package handlers

import (
	"errors"
	"log/slog"

	"github.com/jackc/pgx/v5/pgconn"
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
