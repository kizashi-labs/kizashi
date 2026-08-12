package middleware

import (
	"log/slog"
	"time"

	"github.com/gin-gonic/gin"
)

// SlowQueryLogger logs requests that take longer than the given threshold.
func SlowQueryLogger(threshold time.Duration) gin.HandlerFunc {
	return func(c *gin.Context) {
		start := time.Now()
		c.Next()
		elapsed := time.Since(start)
		if elapsed > threshold {
			requestID, _ := c.Get(RequestIDKey)
			slog.Warn("スロークエリ検出",
				"path", c.Request.URL.Path,
				"method", c.Request.Method,
				"duration", elapsed,
				"status", c.Writer.Status(),
				"request_id", requestID,
				"threshold", threshold,
			)
		}
	}
}
