package handlers

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// LogIngestionHandler handles multi-format log ingestion (JSON, Syslog, CEF).
type LogIngestionHandler struct {
	pool *pgxpool.Pool
}

// NewLogIngestionHandler constructs a LogIngestionHandler.
func NewLogIngestionHandler(pool *pgxpool.Pool) *LogIngestionHandler {
	return &LogIngestionHandler{pool: pool}
}

// parsedLog holds the result of parsing a raw log body.
type parsedLog struct {
	format     string
	parsedData map[string]interface{}
	errMsg     string
}

// parseBody auto-detects and parses a log body.
func parseBody(body string) parsedLog {
	body = strings.TrimSpace(body)

	// Syslog: starts with "<priority>"
	if strings.HasPrefix(body, "<") {
		return parseSyslog(body)
	}

	// CEF: starts with "CEF:"
	if strings.HasPrefix(body, "CEF:") {
		return parseCEF(body)
	}

	// Fallback: JSON
	return parseJSON(body)
}

// parseSyslog extracts priority, hostname, and message from a syslog line.
// Supports RFC 3164 style: <PRI>TIMESTAMP HOSTNAME MESSAGE
func parseSyslog(body string) parsedLog {
	result := parsedLog{format: "syslog", parsedData: map[string]interface{}{}}

	// Extract priority
	end := strings.Index(body, ">")
	if end < 1 {
		result.errMsg = "invalid syslog: missing closing >"
		result.parsedData["raw"] = body
		return result
	}

	priStr := body[1:end]
	pri, err := strconv.Atoi(priStr)
	if err == nil {
		facility := pri / 8
		severity := pri % 8
		result.parsedData["priority"] = pri
		result.parsedData["facility"] = facility
		result.parsedData["severity"] = severity
	}

	rest := strings.TrimSpace(body[end+1:])

	// Try to extract timestamp (first token) + hostname (second token) + message (rest)
	parts := strings.SplitN(rest, " ", 3)
	switch len(parts) {
	case 1:
		result.parsedData["message"] = parts[0]
	case 2:
		result.parsedData["timestamp"] = parts[0]
		result.parsedData["message"] = parts[1]
	default:
		result.parsedData["timestamp"] = parts[0]
		result.parsedData["hostname"] = parts[1]
		result.parsedData["message"] = parts[2]
	}

	result.parsedData["raw"] = body
	return result
}

// parseCEF extracts vendor, product, severity and extension fields from a CEF log.
// CEF:Version|DeviceVendor|DeviceProduct|DeviceVersion|SignatureID|Name|Severity|Extension
func parseCEF(body string) parsedLog {
	result := parsedLog{format: "cef", parsedData: map[string]interface{}{}}

	// Split header portion (first 8 pipe-delimited fields)
	parts := strings.SplitN(body, "|", 8)
	if len(parts) < 7 {
		result.errMsg = "invalid CEF: expected at least 7 pipe-delimited fields"
		result.parsedData["raw"] = body
		return result
	}

	// parts[0] = "CEF:0"
	versionPart := parts[0]
	if idx := strings.Index(versionPart, ":"); idx >= 0 {
		result.parsedData["cef_version"] = versionPart[idx+1:]
	}

	result.parsedData["device_vendor"] = parts[1]
	result.parsedData["device_product"] = parts[2]
	result.parsedData["device_version"] = parts[3]
	result.parsedData["signature_id"] = parts[4]
	result.parsedData["name"] = parts[5]
	result.parsedData["severity"] = parts[6]

	// Parse extension key=value pairs if present
	if len(parts) == 8 {
		ext := parts[7]
		extMap := map[string]string{}
		// Simple key=value parser (does not handle escaped values)
		tokens := strings.Fields(ext)
		for _, tok := range tokens {
			kv := strings.SplitN(tok, "=", 2)
			if len(kv) == 2 {
				extMap[kv[0]] = kv[1]
			}
		}
		if len(extMap) > 0 {
			result.parsedData["extension"] = extMap
		}
	}

	result.parsedData["raw"] = body
	return result
}

// parseJSON attempts to unmarshal body as JSON.
func parseJSON(body string) parsedLog {
	result := parsedLog{format: "json", parsedData: map[string]interface{}{}}

	if err := json.Unmarshal([]byte(body), &result.parsedData); err != nil {
		result.errMsg = "invalid JSON: " + err.Error()
		result.parsedData = map[string]interface{}{"raw": body}
	}

	return result
}

// Ingest handles POST /api/v1/ingest/:source_name
// Authentication is token-based via X-Ingest-Token header.
func (h *LogIngestionHandler) Ingest(c *gin.Context) {
	sourceName := c.Param("source_name")
	if sourceName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "source_name is required"})
		return
	}

	// Look up source and validate token
	ctx := c.Request.Context()
	var sourceID string
	var enabled bool
	var expectedToken string

	err := h.pool.QueryRow(ctx,
		`SELECT id, enabled, token FROM log_sources WHERE name = $1`,
		sourceName,
	).Scan(&sourceID, &enabled, &expectedToken)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "unknown log source"})
		return
	}

	if !enabled {
		c.JSON(http.StatusForbidden, gin.H{"error": "log source is disabled"})
		return
	}

	// Validate token
	token := c.GetHeader("X-Ingest-Token")
	if token == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "X-Ingest-Token header required"})
		return
	}
	if token != expectedToken {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "invalid ingest token"})
		return
	}

	// Read body
	bodyBytes, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "failed to read request body"})
		return
	}
	rawData := string(bodyBytes)
	if rawData == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "request body is empty"})
		return
	}

	// Parse the log body
	parsed := parseBody(rawData)

	// Serialize parsed data to JSON for storage
	parsedJSON, _ := json.Marshal(parsed.parsedData)

	// Determine source IP
	sourceIP := c.ClientIP()

	// Insert into ingested_logs
	var logID string
	now := time.Now().UTC()
	err = h.pool.QueryRow(ctx,
		`INSERT INTO ingested_logs
			(source_name, source_ip, format, raw_data, parsed_data, event_time, processed, error_msg)
		VALUES ($1, $2::inet, $3, $4, $5, $6, false, $7)
		RETURNING id`,
		sourceName,
		sourceIP,
		parsed.format,
		rawData,
		parsedJSON,
		now,
		nullableString(parsed.errMsg),
	).Scan(&logID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	// Update log_sources stats
	if _, err := h.pool.Exec(ctx,
		`UPDATE log_sources
			SET total_ingested = total_ingested + 1,
			    last_received_at = $1
			WHERE name = $2`,
		now, sourceName,
	); !WriteOK(c, err) {
		return
	}

	c.JSON(http.StatusAccepted, gin.H{
		"id":     logID,
		"format": parsed.format,
	})
}

// nullableString converts an empty string to nil (for nullable DB columns).
func nullableString(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}

// logSourceRow is used for list/create responses.
type logSourceRow struct {
	ID             string     `json:"id"`
	Name           string     `json:"name"`
	Description    string     `json:"description"`
	Format         string     `json:"format"`
	Token          string     `json:"token"`
	Enabled        bool       `json:"enabled"`
	TotalIngested  int64      `json:"total_ingested"`
	LastReceivedAt *time.Time `json:"last_received_at"`
	CreatedAt      time.Time  `json:"created_at"`
}

// ListSources handles GET /api/v1/admin/log-sources
func (h *LogIngestionHandler) ListSources(c *gin.Context) {
	ctx := c.Request.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT id, name, description, format, token, enabled, total_ingested, last_received_at, created_at
		FROM log_sources ORDER BY created_at DESC`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list log sources"})
		return
	}
	defer rows.Close()

	sources := []logSourceRow{}
	for rows.Next() {
		var s logSourceRow
		if err := rows.Scan(&s.ID, &s.Name, &s.Description, &s.Format, &s.Token,
			&s.Enabled, &s.TotalIngested, &s.LastReceivedAt, &s.CreatedAt); err != nil {
			continue
		}
		sources = append(sources, s)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list log sources"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"sources": sources, "total": len(sources)})
}

// CreateSource handles POST /api/v1/admin/log-sources
func (h *LogIngestionHandler) CreateSource(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
		Format      string `json:"format"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Format == "" {
		req.Format = "json"
	}
	validFormats := map[string]bool{"json": true, "syslog": true, "cef": true}
	if !validFormats[req.Format] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "format must be json, syslog, or cef"})
		return
	}

	ctx := c.Request.Context()
	var s logSourceRow
	err := h.pool.QueryRow(ctx,
		`INSERT INTO log_sources (name, description, format)
		VALUES ($1, $2, $3)
		RETURNING id, name, description, format, token, enabled, total_ingested, last_received_at, created_at`,
		req.Name, req.Description, req.Format,
	).Scan(&s.ID, &s.Name, &s.Description, &s.Format, &s.Token,
		&s.Enabled, &s.TotalIngested, &s.LastReceivedAt, &s.CreatedAt)
	if err != nil {
		if strings.Contains(err.Error(), "unique") || strings.Contains(err.Error(), "duplicate") {
			c.JSON(http.StatusConflict, gin.H{"error": "log source name already exists"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusCreated, s)
}

// DeleteSource handles DELETE /api/v1/admin/log-sources/:id
func (h *LogIngestionHandler) DeleteSource(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	result, err := h.pool.Exec(ctx, `DELETE FROM log_sources WHERE id = $1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete log source"})
		return
	}
	if result.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "log source not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"deleted": true})
}

// GetSourceStats handles GET /api/v1/admin/log-sources/:id/stats
// Returns total log count, last 24h volume, and recent error count.
func (h *LogIngestionHandler) GetSourceStats(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	// Confirm source exists
	var sourceName string
	var totalIngested int64
	var lastReceived *time.Time
	err := h.pool.QueryRow(ctx,
		`SELECT name, total_ingested, last_received_at FROM log_sources WHERE id = $1`, id,
	).Scan(&sourceName, &totalIngested, &lastReceived)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "log source not found"})
		return
	}

	// Count logs in last 24 hours
	var last24hCount int64
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM ingested_logs
			WHERE source_name = $1 AND event_time >= NOW() - INTERVAL '24 hours'`,
		sourceName,
	).Scan(&last24hCount)) {
		return
	}

	// Count errors in last 24 hours
	var errorCount int64
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM ingested_logs
			WHERE source_name = $1 AND error_msg IS NOT NULL AND event_time >= NOW() - INTERVAL '24 hours'`,
		sourceName,
	).Scan(&errorCount)) {
		return
	}

	// Count unprocessed logs
	var unprocessedCount int64
	if !ReadOK(c, h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM ingested_logs
			WHERE source_name = $1 AND processed = false`,
		sourceName,
	).Scan(&unprocessedCount)) {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"source_name":      sourceName,
		"total_ingested":   totalIngested,
		"last_received_at": lastReceived,
		"last_24h_count":   last24hCount,
		"error_count_24h":  errorCount,
		"unprocessed":      unprocessedCount,
	})
}
