package handlers

import (
	"net/http"

	"github.com/edr-platform/server/docs"
	"github.com/gin-gonic/gin"
)

// RegisterDocsRoutes adds /api/docs and /api/docs/openapi.yaml routes.
// No authentication required — spec is public.
func RegisterDocsRoutes(r *gin.Engine) {
	r.GET("/api/docs", swaggerUIHandler)
	r.GET("/api/docs/openapi.yaml", func(c *gin.Context) {
		c.Data(http.StatusOK, "application/yaml", docs.Spec)
	})
}

func swaggerUIHandler(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, swaggerHTML)
}

const swaggerHTML = `<!DOCTYPE html>
<html lang="ja">
<head>
  <meta charset="UTF-8">
  <title>Kizashi — API Docs</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
<div id="swagger-ui"></div>
<script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
<script>
  SwaggerUIBundle({
    url: "/api/docs/openapi.yaml",
    dom_id: "#swagger-ui",
    presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
    layout: "BaseLayout",
    deepLinking: true,
    displayRequestDuration: true,
    filter: true,
  });
</script>
</body>
</html>`

// DocsHandler serves Swagger UI and the OpenAPI spec.
// Kept for backward compatibility with existing router wiring at /api/v1/docs.
type DocsHandler struct{}

// NewDocsHandler creates a new DocsHandler.
// The specPath argument is ignored; the spec is embedded at compile time.
func NewDocsHandler(_ string) *DocsHandler {
	return &DocsHandler{}
}

// ServeSpec handles GET /api/v1/docs/openapi.yaml
func (h *DocsHandler) ServeSpec(c *gin.Context) {
	c.Data(http.StatusOK, "application/yaml; charset=utf-8", docs.Spec)
}

// ServeUI handles GET /api/v1/docs — returns HTML with embedded Swagger UI CDN
func (h *DocsHandler) ServeUI(c *gin.Context) {
	c.Header("Content-Type", "text/html; charset=utf-8")
	c.String(http.StatusOK, swaggerHTML)
}
