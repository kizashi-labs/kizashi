package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ExportHandler provides a unified export endpoint for all data types.
type ExportHandler struct {
	pool *pgxpool.Pool
}

// NewExportHandler creates a new ExportHandler.
func NewExportHandler(pool *pgxpool.Pool) *ExportHandler {
	return &ExportHandler{pool: pool}
}

// exportRequest is the request body for POST /api/v1/export.
type exportRequest struct {
	Type    string            `json:"type" binding:"required"`
	Format  string            `json:"format"`
	Columns []string          `json:"columns"`
	From    time.Time         `json:"from"`
	To      time.Time         `json:"to"`
	Filters map[string]string `json:"filters"`
	Limit   int               `json:"limit"`
}

// exportTypeMeta holds per-type metadata for query building.
type exportTypeMeta struct {
	table      string
	timeColumn string
	allColumns []string
}

var exportTypes = map[string]exportTypeMeta{
	"alerts": {
		table:      "alerts",
		timeColumn: "created_at",
		allColumns: []string{"id", "title", "severity", "status", "agent_id", "created_at", "updated_at"},
	},
	// 以下の列名は実スキーマ (migration 001 / 002 / 016) に合わせてある。
	// 誤った列名を並べると SELECT が実行時に落ち、該当タイプのエクスポートが
	// まるごと 500 になる（テーブル存在チェックは通ってしまうため気づきにくい）。
	"events": {
		table:      "events",
		timeColumn: "time",
		allColumns: []string{"event_id", "event_type", "agent_id", "time", "raw_data"},
	},
	"agents": {
		table:      "agents",
		timeColumn: "last_seen",
		allColumns: []string{"id", "hostname", "os_type", "agent_version", "status", "last_seen", "ip_addresses"},
	},
	"audit_logs": {
		table:      "audit_logs",
		timeColumn: "created_at",
		allColumns: []string{"id", "user_id", "action", "resource_id", "details", "created_at"},
	},
	"network_connections": {
		// network_connections には id 列が無く、時刻列は time。
		table:      "network_connections",
		timeColumn: "time",
		allColumns: []string{"agent_id", "src_ip", "dst_ip", "dst_port", "protocol", "bytes_sent", "bytes_recv", "time"},
	},
	"processes": {
		table:      "process_events",
		timeColumn: "timestamp",
		allColumns: []string{"id", "agent_id", "process_name", "pid", "ppid", "cmdline", "timestamp"},
	},
}

// tableExists checks whether a table exists in the public schema.
func (h *ExportHandler) tableExists(c *gin.Context, table string) (bool, error) {
	var exists bool
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT EXISTS(SELECT 1 FROM pg_tables WHERE schemaname='public' AND tablename=$1)`,
		table,
	).Scan(&exists)
	return exists, err
}

// Export handles POST /api/v1/export — unified multi-type data export.
func (h *ExportHandler) Export(c *gin.Context) {
	var req exportRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストボディが無効です: " + err.Error()})
		return
	}

	// Validate type
	meta, ok := exportTypes[req.Type]
	if !ok {
		validTypes := make([]string, 0, len(exportTypes))
		for k := range exportTypes {
			validTypes = append(validTypes, k)
		}
		c.JSON(http.StatusBadRequest, gin.H{
			"error": fmt.Sprintf("type が無効です。有効な値: %s", strings.Join(validTypes, ", ")),
		})
		return
	}

	// Validate format
	format := strings.ToLower(req.Format)
	if format == "" {
		format = "json"
	}
	if format != "csv" && format != "json" && format != "ndjson" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "format は csv, json, ndjson のいずれかである必要があります"})
		return
	}

	// Cap limit
	limit := req.Limit
	if limit <= 0 || limit > 50000 {
		limit = 10000
	}

	// Resolve columns
	columns := req.Columns
	if len(columns) == 0 {
		columns = meta.allColumns
	} else {
		// Validate requested columns against allowed set
		allowed := make(map[string]bool, len(meta.allColumns))
		for _, c := range meta.allColumns {
			allowed[c] = true
		}
		sanitized := make([]string, 0, len(columns))
		for _, col := range columns {
			if allowed[col] {
				sanitized = append(sanitized, col)
			}
		}
		if len(sanitized) == 0 {
			sanitized = meta.allColumns
		}
		columns = sanitized
	}

	// Check table existence
	exists, err := h.tableExists(c, meta.table)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブル確認中にエラーが発生しました"})
		return
	}
	if !exists {
		// Return empty export gracefully
		h.writeEmptyExport(c, req.Type, format, columns)
		return
	}

	// Build query
	args := []interface{}{}
	argIdx := 1

	// Column list — every column is cast to text so CSV/JSON writing is uniform.
	colExprs := make([]string, len(columns))
	for i, col := range columns {
		colExprs[i] = fmt.Sprintf("COALESCE(%s::text, '')", col)
	}
	selectCols := strings.Join(colExprs, ", ")

	where := "WHERE 1=1"

	// Date range filter
	if !req.From.IsZero() {
		where += fmt.Sprintf(" AND %s >= $%d", meta.timeColumn, argIdx)
		args = append(args, req.From)
		argIdx++
	}
	if !req.To.IsZero() {
		where += fmt.Sprintf(" AND %s <= $%d", meta.timeColumn, argIdx)
		args = append(args, req.To)
		argIdx++
	}

	// Optional filters
	for key, val := range req.Filters {
		// Whitelist filter keys against the allowed columns to prevent injection
		allowed := false
		for _, c := range meta.allColumns {
			if c == key {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		where += fmt.Sprintf(" AND %s = $%d", key, argIdx)
		args = append(args, val)
		argIdx++
	}

	// Limit arg
	args = append(args, limit)

	query := fmt.Sprintf(
		`SELECT %s FROM %s %s ORDER BY %s DESC LIMIT $%d`,
		selectCols, meta.table, where, meta.timeColumn, argIdx,
	)

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	// Collect rows as [][]string (all values are text-cast)
	var records [][]string
	for rows.Next() {
		vals := make([]interface{}, len(columns))
		ptrs := make([]interface{}, len(columns))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if err := rows.Scan(ptrs...); err != nil {
			continue
		}
		row := make([]string, len(columns))
		for i, v := range vals {
			if v == nil {
				row[i] = ""
			} else if s, ok := v.(string); ok {
				row[i] = s
			} else {
				row[i] = fmt.Sprintf("%v", v)
			}
		}
		records = append(records, row)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}

	ts := time.Now().UTC().Format("20060102_150405")

	switch format {
	case "csv":
		filename := fmt.Sprintf("export_%s_%s.csv", req.Type, ts)
		c.Header("Content-Type", "text/csv; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		w := csv.NewWriter(c.Writer)
		_ = w.Write(columns)
		for _, rec := range records {
			_ = w.Write(rec)
		}
		w.Flush()

	case "ndjson":
		c.Header("Content-Type", "application/x-ndjson; charset=utf-8")
		enc := json.NewEncoder(c.Writer)
		for _, rec := range records {
			obj := make(map[string]string, len(columns))
			for i, col := range columns {
				obj[col] = rec[i]
			}
			_ = enc.Encode(obj)
		}

	default: // json
		c.Header("Content-Type", "application/json; charset=utf-8")
		data := make([]map[string]string, 0, len(records))
		for _, rec := range records {
			obj := make(map[string]string, len(columns))
			for i, col := range columns {
				obj[col] = rec[i]
			}
			data = append(data, obj)
		}
		c.JSON(http.StatusOK, gin.H{
			"data":        data,
			"count":       len(data),
			"exported_at": time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// writeEmptyExport sends a graceful empty response when the table does not exist.
func (h *ExportHandler) writeEmptyExport(c *gin.Context, dataType, format string, columns []string) {
	ts := time.Now().UTC().Format("20060102_150405")
	switch format {
	case "csv":
		filename := fmt.Sprintf("export_%s_%s.csv", dataType, ts)
		c.Header("Content-Type", "text/csv; charset=utf-8")
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%s", filename))
		w := csv.NewWriter(c.Writer)
		_ = w.Write(columns)
		w.Flush()
	case "ndjson":
		c.Header("Content-Type", "application/x-ndjson; charset=utf-8")
		// empty — nothing to write
	default:
		c.JSON(http.StatusOK, gin.H{
			"data":        []interface{}{},
			"count":       0,
			"exported_at": time.Now().UTC().Format(time.RFC3339),
		})
	}
}

// exportStatusItem describes an available export type.
type exportStatusItem struct {
	Type        string `json:"type"`
	Table       string `json:"table"`
	Available   bool   `json:"available"`
	RecordCount int64  `json:"record_count"`
}

// GetExportStatus handles GET /api/v1/export/status — returns available export types and their record counts.
func (h *ExportHandler) GetExportStatus(c *gin.Context) {
	items := make([]exportStatusItem, 0, len(exportTypes))

	for typeName, meta := range exportTypes {
		item := exportStatusItem{
			Type:  typeName,
			Table: meta.table,
		}

		exists, err := h.tableExists(c, meta.table)
		if err != nil || !exists {
			item.Available = false
			items = append(items, item)
			continue
		}
		item.Available = true

		var count int64
		_ = h.pool.QueryRow(c.Request.Context(),
			fmt.Sprintf("SELECT COUNT(*) FROM %s", meta.table),
		).Scan(&count)
		item.RecordCount = count
		items = append(items, item)
	}

	c.JSON(http.StatusOK, gin.H{
		"export_types": items,
		"max_limit":    50000,
		"formats":      []string{"csv", "json", "ndjson"},
		"checked_at":   time.Now().UTC().Format(time.RFC3339),
	})
}
