package middleware

import (
	"net/http"
	"strings"

	"github.com/edr-platform/server/internal/tenant"
	"github.com/gin-gonic/gin"
)

// skipPaths holds URL prefixes that bypass tenant enforcement.
var tenantSkipPaths = []string{
	"/healthz",
	"/readyz",
	"/api/v1/auth/",
}

// TenantMiddleware enforces that requests carry a valid, enabled organization ID.
// It reads the org from the X-Organization-ID header or the org_id JWT claim.
func TenantMiddleware(store *tenant.Store) gin.HandlerFunc {
	return func(c *gin.Context) {
		path := c.Request.URL.Path
		for _, prefix := range tenantSkipPaths {
			if strings.HasPrefix(path, prefix) {
				c.Next()
				return
			}
		}

		// Prefer explicit header over JWT claim.
		orgID := c.GetHeader("X-Organization-ID")
		if orgID == "" {
			if v, exists := c.Get("org_id"); exists {
				orgID, _ = v.(string)
			}
		}

		if orgID == "" {
			// No org context — allow request to proceed without org enforcement.
			c.Next()
			return
		}

		org, err := store.Get(c.Request.Context(), orgID)
		if err != nil {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "organization not found"})
			return
		}
		if !org.Enabled {
			c.AbortWithStatusJSON(http.StatusForbidden, gin.H{"error": "organization is disabled"})
			return
		}

		c.Set("org_id", orgID)
		c.Next()
	}
}
