package handlers

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	tenantcrypto "github.com/edr-platform/server/internal/crypto"
	"github.com/edr-platform/server/internal/store"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// ExportHandler provides a unified export endpoint for all data types.
type ExportHandler struct {
	pool      *pgxpool.Pool
	encryptor *tenantcrypto.Encryptor
}

// WithEncryptor attaches the tenant Encryptor so encrypted raw_event values can
// be decrypted on the way out.
//
// 付けないと、暗号化を有効にした瞬間に CSV へ ciphertext が出ます。
// 空にするのも同じくらい悪いので（「生データが無かった」に見えます）、
// 復号できないときは、そうと分かる印を書きます。
func (h *ExportHandler) WithEncryptor(enc *tenantcrypto.Encryptor) *ExportHandler {
	h.encryptor = enc
	return h
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
	// where is an extra predicate ANDed into every query for this type. It
	// exists because process and network telemetry are rows of `events`
	// distinguished by event_type, not tables of their own.
	where string
	// joins is appended after the FROM table. It exists so a column the export
	// centre offers can come from a related table — an agent hostname is what
	// an operator recognises, and it lives on agents, not on the row itself.
	joins string
	// columnExpr maps an exported column name to the SQL that produces it.
	// A name absent here is qualified with the table name. Values here are
	// trusted SQL fragments written in this file — never anything from a
	// request. Request columns are whitelisted against allColumns before being
	// looked up.
	columnExpr map[string]string
}

// exprFor returns the SQL producing one exported column.
//
// Unmapped names are qualified with the table, because once a type carries a
// join a bare `id` or `created_at` is ambiguous and Postgres rejects it.
func (m exportTypeMeta) exprFor(column string) string {
	if e, ok := m.columnExpr[column]; ok {
		return e
	}
	return m.table + "." + column
}

// exportTypes is the server's view of what can be exported.
//
// The export centre offers a column list per type and the server drops any key
// it does not recognise — silently, because an unknown key is skipped rather
// than refused. 29 of the columns the page offered were not in these lists, so
// ticking those boxes produced a file without them and no indication why. The
// names below cover what the page offers; each maps to where the data actually
// lives, which is often a differently-named column or a joined table.
var exportTypes = map[string]exportTypeMeta{
	"alerts": {
		table:      "alerts",
		timeColumn: "created_at",
		joins: "LEFT JOIN agents ag ON ag.id = alerts.agent_id " +
			"LEFT JOIN rules r ON r.id = alerts.rule_id " +
			"LEFT JOIN users u ON u.id = alerts.assigned_to",
		allColumns: []string{
			"id", "title", "severity", "status", "agent_id", "agent_hostname",
			"rule_name", "description", "mitre_attack", "assignee",
			"resolved_at", "raw_data", "created_at", "updated_at",
		},
		columnExpr: map[string]string{
			"agent_hostname": "ag.hostname",
			// Most alerts carry no rule_id — the pipeline that raises them does
			// not set one — so this is empty far more often than not. A LEFT
			// JOIN says that honestly rather than dropping those rows.
			"rule_name":    "r.name",
			"mitre_attack": "alerts.mitre_technique",
			// assigned_to is a users.id. Exporting the uuid would satisfy the
			// column name and tell the reader nothing, so the email is what
			// leaves the building — the same reason agent_hostname is joined
			// rather than exporting agent_id twice.
			"assignee": "u.email",
			"raw_data": "alerts.raw_event",
		},
	},
	// 以下の列名は実スキーマ (migration 001 / 002 / 016) に合わせてある。
	// 誤った列名を並べると SELECT が実行時に落ち、該当タイプのエクスポートが
	// まるごと 500 になる（テーブル存在チェックは通ってしまうため気づきにくい）。
	"events": {
		table:      "events",
		timeColumn: "time",
		joins:      "LEFT JOIN agents ag ON ag.id = events.agent_id",
		allColumns: []string{
			"id", "event_id", "event_type", "agent_id", "agent_hostname",
			"severity", "process_name", "process_path", "pid", "user",
			"details", "time", "timestamp", "raw_data",
		},
		columnExpr: map[string]string{
			"id":             "events.event_id",
			"timestamp":      "events.time",
			"agent_hostname": "ag.hostname",
			"process_name":   "events.raw_data->>'process_name'",
			"process_path":   "events.raw_data->>'image_path'",
			"pid":            "events.raw_data->>'pid'",
			"user":           "events.raw_data->>'username'",
			"details":        "events.raw_data",
		},
	},
	"agents": {
		table:      "agents",
		timeColumn: "last_seen",
		joins:      "LEFT JOIN agent_groups g ON g.id = agents.group_id",
		allColumns: []string{
			"id", "hostname", "os", "os_type", "os_version", "version",
			"agent_version", "status", "ip_address", "ip_addresses", "groups",
			"tags", "enrolled_at", "last_seen",
		},
		columnExpr: map[string]string{
			"os":         "agents.os_type",
			"version":    "agents.agent_version",
			"ip_address": "agents.ip_addresses",
			"groups":     "g.name",
		},
	},
	"audit_logs": {
		table:      "audit_logs",
		timeColumn: "created_at",
		allColumns: []string{
			"id", "user_id", "user", "action", "resource_id", "status",
			"ip_address", "user_agent", "details", "timestamp", "created_at",
		},
		columnExpr: map[string]string{
			"user":   "audit_logs.user_email",
			"status": "audit_logs.status_code",
		},
	},
	// network と processes は events の行であってテーブルではない。
	//
	// This used to name a process_events table, which no migration creates, and
	// a network_connections table which does exist but which no code in this
	// repository ever inserts into — the only writer is a test fixture. Both
	// exports were therefore incapable of producing a row: one failed its
	// existence probe and wrote an empty file, the other passed the probe and
	// queried an empty table, which looks the same to whoever asked for it.
	//
	// The telemetry is in `events`, written by the ingestion path, keyed by
	// event_type with the payload in raw_data. The field names below are the
	// ones internal/ingestion actually writes — see normalizeEvent.
	"network_connections": {
		table:      "events",
		timeColumn: "time",
		where:      "event_type = 'network'",
		joins:      "LEFT JOIN agents ag ON ag.id = events.agent_id",
		allColumns: []string{
			"agent_id", "agent_hostname", "src_ip", "src_port", "dst_ip", "dst_port",
			"protocol", "direction", "process_name", "bytes_sent", "bytes_recv", "time",
		},
		columnExpr: map[string]string{
			"agent_hostname": "ag.hostname",
			"src_ip":         "events.raw_data->>'src_ip'",
			"src_port":       "events.raw_data->>'src_port'",
			"dst_ip":         "events.raw_data->>'dst_ip'",
			"dst_port":       "events.raw_data->>'dst_port'",
			"protocol":       "events.raw_data->>'protocol'",
			"direction":      "events.raw_data->>'direction'",
			"process_name":   "events.raw_data->>'process_name'",
			"bytes_sent":     "events.raw_data->>'bytes_sent'",
			"bytes_recv":     "events.raw_data->>'bytes_recv'",
		},
	},
	"processes": {
		table:      "events",
		timeColumn: "time",
		where:      "event_type = 'process'",
		joins:      "LEFT JOIN agents ag ON ag.id = events.agent_id",
		allColumns: []string{
			"agent_id", "agent_hostname", "process_name", "image_path", "pid", "ppid",
			"username", "command_line", "action", "sha256", "md5", "time",
		},
		columnExpr: map[string]string{
			"agent_hostname": "ag.hostname",
			"process_name":   "events.raw_data->>'process_name'",
			"image_path":     "events.raw_data->>'image_path'",
			"pid":            "events.raw_data->>'pid'",
			"ppid":           "events.raw_data->>'ppid'",
			"username":       "events.raw_data->>'username'",
			"command_line":   "events.raw_data->>'command_line'",
			"action":         "events.raw_data->>'action'",
			"sha256":         "events.raw_data->>'sha256'",
			"md5":            "events.raw_data->>'md5'",
		},
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

	query, args := buildExportQuery(meta, columns, req.From, req.To, req.Filters, limit)

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
				row[i] = h.exportValue(c, s)
			} else {
				row[i] = fmt.Sprintf("%v", v)
			}
		}
		records = append(records, row)
	}
	if err := rows.Err(); err != nil {
		// **利用者が明示的に「書き出す」と押した経路です。**
		// 途中までのファイルを 200 で渡すと、それが全件だと読まれます。
		slog.Error("export: rows.Err", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "読み出しが途中で失敗しました。書き出しは中止します"})
		return
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

// exportValue turns a stored cell into what leaves the building.
//
// 暗号化された raw_event は、そのまま出すと ciphertext が CSV に載ります。
// 空にすると「生データが無かった」に見えます。**どちらも嘘なので、
// 復号するか、復号できなかったと書くかのどちらかにします。**
func (h *ExportHandler) exportValue(c *gin.Context, v string) string {
	if !store.IsEncryptedRawEvent(v) {
		return v
	}
	tenantID, _ := c.Get("tenant_id")
	tenant, _ := tenantID.(string)
	plain, err := store.DecodeRawEvent(c.Request.Context(), h.encryptor, tenant, &v)
	if err != nil {
		slog.Error("export: raw_event を復号できませんでした。"+
			"この行の生データは出力されません", "tenant", tenant, "error", err)
		return "[復号できませんでした]"
	}
	return string(plain)
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
		if !ReadOK(c, h.pool.QueryRow(c.Request.Context(),
			fmt.Sprintf("SELECT COUNT(*) FROM %s", meta.table),
		).Scan(&count)) {
			return
		}
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

// buildExportQuery assembles the SELECT for one export request.
//
// It is a function rather than inline handler code so the contract test can
// execute the query this actually builds. When the test built its own copy, a
// handler that stopped applying meta.where still passed.
func buildExportQuery(
	meta exportTypeMeta,
	columns []string,
	from, to time.Time,
	filters map[string]string,
	limit int,
) (string, []interface{}) {
	args := []interface{}{}
	argIdx := 1

	// Column list — every column is cast to text so CSV/JSON writing is uniform.
	colExprs := make([]string, len(columns))
	for i, col := range columns {
		colExprs[i] = fmt.Sprintf("COALESCE((%s)::text, '')", meta.exprFor(col))
	}
	selectCols := strings.Join(colExprs, ", ")

	where := "WHERE 1=1"
	// Types that are rows of `events` rather than tables of their own carry
	// their event_type predicate here.
	if meta.where != "" {
		where += " AND " + meta.where
	}

	// Date range filter. The time column goes through exprFor like any other,
	// so it stays unambiguous once a type carries a join.
	timeExpr := meta.exprFor(meta.timeColumn)
	if !from.IsZero() {
		where += fmt.Sprintf(" AND %s >= $%d", timeExpr, argIdx)
		args = append(args, from)
		argIdx++
	}
	if !to.IsZero() {
		where += fmt.Sprintf(" AND %s <= $%d", timeExpr, argIdx)
		args = append(args, to)
		argIdx++
	}

	// Optional filters
	for key, val := range filters {
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
		where += fmt.Sprintf(" AND (%s) = $%d", meta.exprFor(key), argIdx)
		args = append(args, val)
		argIdx++
	}

	args = append(args, limit)
	return fmt.Sprintf(
		`SELECT %s FROM %s %s %s ORDER BY %s DESC LIMIT $%d`,
		selectCols, meta.table, meta.joins, where, timeExpr, argIdx,
	), args
}
