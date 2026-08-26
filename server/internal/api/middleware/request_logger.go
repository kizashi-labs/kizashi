package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// StructuredLogger logs HTTP requests with structured fields.
func StructuredLogger() gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		path := c.Request.URL.Path
		query := c.Request.URL.RawQuery

		c.Next()

		latency := time.Since(start)
		status := c.Writer.Status()
		requestID, _ := c.Get(RequestIDKey)

		attrs := []slog.Attr{
			slog.Int("status", status),
			slog.String("method", c.Request.Method),
			slog.String("path", path),
			slog.Duration("latency", latency),
			slog.String("ip", c.ClientIP()),
			slog.String("request_id", requestID.(string)),
		}
		if query != "" {
			attrs = append(attrs, slog.String("query", query))
		}
		if len(c.Errors) > 0 {
			attrs = append(attrs, slog.String("errors", c.Errors.String()))
		}

		level := slog.LevelInfo
		if status >= 500 {
			level = slog.LevelError
		} else if status >= 400 {
			level = slog.LevelWarn
		}

		slog.LogAttrs(c.Request.Context(), level, "HTTP request", attrs...)
	}
}
