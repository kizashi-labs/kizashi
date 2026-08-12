package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditExportHandler streams audit log exports in CEF, LEEF, or JSON format.
type AuditExportHandler struct {
	pool *pgxpool.Pool
}

// NewAuditExportHandler creates a new AuditExportHandler.
func NewAuditExportHandler(pool *pgxpool.Pool) *AuditExportHandler {
	return &AuditExportHandler{pool: pool}
}

// auditRow holds a single audit log entry for export.
type auditRow struct {
	ID           string
	UserID       string
	Action       string
	ResourceType string
	ResourceID   string
	Details      string
	CreatedAt    time.Time
	TenantID     string
	IPAddress    string
}

// Export streams audit logs in the requested format.
// GET /api/v1/audit-logs/export?format=cef|leef|json&since=RFC3339&until=RFC3339&limit=10000
func (h *AuditExportHandler) Export(c *gin.Context) {
	format := strings.ToLower(c.DefaultQuery("format", "json"))
	sinceStr := c.Query("since")
	untilStr := c.Query("until")
	limitStr := c.DefaultQuery("limit", "10000")

	since := time.Time{}
	until := time.Now()
	var err error
	if sinceStr != "" {
		since, err = time.Parse(time.RFC3339, sinceStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "since パラメータが無効です"})
			return
		}
	}
	if untilStr != "" {
		until, err = time.Parse(time.RFC3339, untilStr)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "until パラメータが無効です"})
			return
		}
	}

	var limit int
	fmt.Sscanf(limitStr, "%d", &limit)
	if limit <= 0 || limit > 5000 {
		limit = 5000
	}

	args := []interface{}{}
	idx := 1
	where := "WHERE 1=1"
	if !since.IsZero() {
		where += fmt.Sprintf(" AND timestamp >= $%d", idx)
		args = append(args, since)
		idx++
	}
	where += fmt.Sprintf(" AND timestamp <= $%d", idx)
	args = append(args, until)
	idx++
	args = append(args, limit)

	rows, err := h.pool.Query(c.Request.Context(), fmt.Sprintf(`
		SELECT COALESCE(id,''), COALESCE(user_id,''), COALESCE(action,''),
		       '', COALESCE(resource_id,''),
		       COALESCE(details::text,'{}'),
		       timestamp,
		       '', COALESCE(ip_address,'')
		FROM audit_logs
		%s
		ORDER BY timestamp DESC
		LIMIT $%d`, where, idx),
		args...,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "監査ログの取得に失敗しました"})
		return
	}
	defer rows.Close()

	var entries []auditRow
	for rows.Next() {
		var r auditRow
		if err := rows.Scan(
			&r.ID, &r.UserID, &r.Action, &r.ResourceType, &r.ResourceID,
			&r.Details, &r.CreatedAt, &r.TenantID, &r.IPAddress,
		); err != nil {
			continue
		}
		entries = append(entries, r)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	filename := fmt.Sprintf("audit_logs_%s", time.Now().Format("20060102_150405"))

	switch format {
	case "cef":
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.cef", filename))
		for _, e := range entries {
			line := fmt.Sprintf(
				"CEF:0|EDR Platform|EDR|1.0|%s|%s|5|src=%s suser=%s cs1=%s cs1Label=ResourceType cs2=%s cs2Label=ResourceID\n",
				escapeCEF(e.Action), escapeCEF(e.Action),
				e.IPAddress, e.UserID, e.ResourceType, e.ResourceID,
			)
			_, _ = c.Writer.WriteString(line)
		}

	case "leef":
		c.Header("Content-Type", "text/plain; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.leef", filename))
		for _, e := range entries {
			line := fmt.Sprintf(
				"LEEF:2.0|EDR Platform|EDR|1.0|%s|\tsrc=%s\tusrName=%s\tresourceType=%s\n",
				e.Action, e.IPAddress, e.UserID, e.ResourceType,
			)
			_, _ = c.Writer.WriteString(line)
		}

	default: // json
		c.Header("Content-Type", "application/json; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s.json", filename))

		type jsonRow struct {
			ID           string          `json:"id"`
			UserID       string          `json:"user_id"`
			Action       string          `json:"action"`
			ResourceType string          `json:"resource_type"`
			ResourceID   string          `json:"resource_id"`
			Details      json.RawMessage `json:"details"`
			CreatedAt    time.Time       `json:"created_at"`
			TenantID     string          `json:"tenant_id"`
			IPAddress    string          `json:"ip_address"`
		}

		out := make([]jsonRow, 0, len(entries))
		for _, e := range entries {
			row := jsonRow{
				ID:           e.ID,
				UserID:       e.UserID,
				Action:       e.Action,
				ResourceType: e.ResourceType,
				ResourceID:   e.ResourceID,
				CreatedAt:    e.CreatedAt,
				TenantID:     e.TenantID,
				IPAddress:    e.IPAddress,
			}
			if e.Details != "" {
				row.Details = json.RawMessage(e.Details)
			} else {
				row.Details = json.RawMessage("{}")
			}
			out = append(out, row)
		}
		data, _ := json.Marshal(out)
		_, _ = c.Writer.Write(data)
	}
}

// escapeCEF escapes special characters in CEF field values.
func escapeCEF(s string) string {
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "|", "\\|")
	return s
}
