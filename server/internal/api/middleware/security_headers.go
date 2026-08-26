package middleware

import (
	"github.com/gin-gonic/gin"
)

// SecurityHeaders adds standard HTTP security headers to every response.
// These headers harden the API against common web vulnerabilities.
func SecurityHeaders() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Prevent MIME type sniffing
		c.Header("X-Content-Type-Options", "nosniff")
		// Prevent clickjacking
		c.Header("X-Frame-Options", "DENY")
		// Block XSS in older browsers
		c.Header("X-XSS-Protection", "1; mode=block")
		// Enforce HTTPS for 1 year (only sent over HTTPS)
		c.Header("Strict-Transport-Security", "max-age=31536000; includeSubDomains; preload")
		// Control referrer information
		c.Header("Referrer-Policy", "strict-origin-when-cross-origin")
		// Disable dangerous browser features
		c.Header("Permissions-Policy", "geolocation=(), microphone=(), camera=(), payment=()")
		// Content Security Policy for API responses
		c.Header("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
		// Remove server fingerprinting header
		c.Header("Server", "")
		// Cache control for API responses
		if c.Request.Method != "GET" {
			c.Header("Cache-Control", "no-store")
		}
		c.Next()
	}
}
