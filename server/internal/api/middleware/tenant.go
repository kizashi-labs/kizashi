package middleware

import (
	"context"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/store"
)

// TenantMiddleware propagates tenant_id from the JWT context into the HTTP
// request context using store.TenantContextKey. The pgxpool PrepareConn
// hook in store.Connect reads this value and calls set_config('app.tenant_id')
// on every connection acquired during the request, enabling PostgreSQL RLS
// without modifying individual query handlers.
//
// If tenant_id is not set (single-tenant deployment), the middleware is a no-op.
func TenantMiddleware(_ *pgxpool.Pool) gin.HandlerFunc {
	return func(c *gin.Context) {
		tenantID, exists := c.Get("tenant_id")
		if !exists || tenantID == "" {
			c.Next()
			return
		}

		tid, ok := tenantID.(string)
		if !ok || tid == "" {
			c.Next()
			return
		}

		ctx := context.WithValue(c.Request.Context(), store.TenantContextKey{}, tid)
		c.Request = c.Request.WithContext(ctx)
		c.Next()
	}
}
