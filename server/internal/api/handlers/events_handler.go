package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// EventHandler provides event query endpoints.
type EventHandler struct {
	Pool *pgxpool.Pool
}

// maxCountedEvents はページネーション表示用に数える行数の上限。
//
// events は hypertable で、90 日保持 × 日次 30 万件規模になると数千万行に達する。
// 素の `SELECT COUNT(*) FROM events` は全 chunk を走査するため数十秒かかり、
// ブラウザ側が先に諦めて接続を切る → PostgreSQL に
// `canceling statement due to user request` が残り、一覧が空のまま返っていた。
// (検証EC2 2026-07-30 のログで実測)
const maxCountedEvents = 10000

// countEventsCapped は条件に一致する events の件数を maxCountedEvents 件で
// 打ち切って数える。走査量が LIMIT 件までに抑えられるため、行数に関係なく
// 一定時間で返る。2 つ目の戻り値は上限に達したか (= UI で「10,000+」と
// 表示すべきか) を示す。
func countEventsCapped(ctx context.Context, pool *pgxpool.Pool, where string, args ...interface{}) (int, bool) {
	var n int
	q := fmt.Sprintf(
		"SELECT COUNT(*) FROM (SELECT 1 FROM events %s LIMIT %d) t",
		where, maxCountedEvents+1)
	if err := pool.QueryRow(ctx, q, args...).Scan(&n); err != nil {
		slog.Warn("イベント件数の取得に失敗", "error", err)
		return 0, false
	}
	if n > maxCountedEvents {
		return maxCountedEvents, true
	}
	return n, false
}

// NewEventHandler creates a new EventHandler.
func NewEventHandler(pool *pgxpool.Pool) *EventHandler {
	return &EventHandler{Pool: pool}
}

// List returns a paginated list of events.
// GET /api/v1/events?agent_id=xxx&type=process&search=powershell&from=2024-01-01T00:00:00Z&to=...&page=1&per_page=50
func (h *EventHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "0"))
	if perPage <= 0 {
		perPage, _ = strconv.Atoi(c.DefaultQuery("limit", "50"))
	}
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 500 {
		perPage = 50
	}

	agentID := c.Query("agent_id")
	eventType := c.Query("type")
	search := c.Query("search")
	fromStr := c.Query("from")
	toStr := c.Query("to")
	limit := perPage
	offset := (page - 1) * perPage

	var conditions []string
	var args []interface{}
	i := 1

	if agentID != "" {
		conditions = append(conditions, fmt.Sprintf("agent_id = $%d", i))
		args = append(args, agentID)
		i++
	}
	if eventType != "" {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", i))
		args = append(args, eventType)
		i++
	}
	if search != "" {
		conditions = append(conditions, fmt.Sprintf("raw_data::text ILIKE $%d", i))
		args = append(args, "%"+search+"%")
		i++
	}
	if fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			conditions = append(conditions, fmt.Sprintf("time >= $%d", i))
			args = append(args, t)
			i++
		}
	}
	if toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			conditions = append(conditions, fmt.Sprintf("time <= $%d", i))
			args = append(args, t)
			i++
		}
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + conditions[0]
		for _, cond := range conditions[1:] {
			where += " AND " + cond
		}
	}

	ctx := c.Request.Context()

	total, totalCapped := countEventsCapped(ctx, h.Pool, where, args...)

	query := `SELECT event_id, agent_id, event_type, raw_data, time
		FROM events ` + where + `
		ORDER BY time DESC
		LIMIT $` + fmt.Sprintf("%d", i) + ` OFFSET $` + fmt.Sprintf("%d", i+1)

	args = append(args, limit, offset)
	rows, err := h.Pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "イベント一覧の取得に失敗しました"})
		return
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var id, agentIDVal, eventTypeVal string
		var rawData []byte
		var ts time.Time
		if err := rows.Scan(&id, &agentIDVal, &eventTypeVal, &rawData, &ts); err != nil {
			continue
		}
		events = append(events, map[string]interface{}{
			"id":         id,
			"agent_id":   agentIDVal,
			"event_type": eventTypeVal,
			"raw_data":   json.RawMessage(rawData),
			"timestamp":  ts,
		})
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	if events == nil {
		events = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     events,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		// total は maxCountedEvents で打ち切られる。true なら「total 件以上」の意味。
		"total_capped": totalCapped,
		"has_more":     totalCapped || (page*perPage) < total,
	})
}

// Get returns a single event by ID.
// GET /api/v1/events/:id
func (h *EventHandler) Get(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	var agentID, eventType string
	var rawData []byte
	var ts time.Time

	err := h.Pool.QueryRow(ctx,
		"SELECT event_id, agent_id, event_type, raw_data, time FROM events WHERE event_id = $1",
		id,
	).Scan(&id, &agentID, &eventType, &rawData, &ts)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "イベントが見つかりません"})
		return
	}

	c.JSON(http.StatusOK, map[string]interface{}{
		"id":         id,
		"agent_id":   agentID,
		"event_type": eventType,
		"raw_data":   rawData,
		"timestamp":  ts,
	})
}

// Search searches events by criteria.
// POST /api/v1/events/search
func (h *EventHandler) Search(c *gin.Context) {
	var req struct {
		AgentID   string     `json:"agent_id"`
		EventType string     `json:"event_type"`
		Query     string     `json:"query"`
		From      *time.Time `json:"from"`
		To        *time.Time `json:"to"`
		Page      int        `json:"page"`
		PerPage   int        `json:"per_page"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}

	if req.Page < 1 {
		req.Page = 1
	}
	if req.PerPage < 1 || req.PerPage > 200 {
		req.PerPage = 50
	}

	var conditions []string
	var args []interface{}
	i := 1

	if req.AgentID != "" {
		conditions = append(conditions, fmt.Sprintf("agent_id = $%d", i))
		args = append(args, req.AgentID)
		i++
	}
	if req.EventType != "" {
		conditions = append(conditions, fmt.Sprintf("event_type = $%d", i))
		args = append(args, req.EventType)
		i++
	}
	if req.From != nil {
		conditions = append(conditions, fmt.Sprintf("time >= $%d", i))
		args = append(args, *req.From)
		i++
	}
	if req.To != nil {
		conditions = append(conditions, fmt.Sprintf("time <= $%d", i))
		args = append(args, *req.To)
		i++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE "
		for j, cond := range conditions {
			if j > 0 {
				where += " AND "
			}
			where += cond
		}
	}

	ctx := c.Request.Context()

	total, totalCapped := countEventsCapped(ctx, h.Pool, where, args...)

	query := `SELECT event_id, agent_id, event_type, raw_data, time
		FROM events ` + where + `
		ORDER BY time DESC
		LIMIT $` + fmt.Sprintf("%d", i) + ` OFFSET $` + fmt.Sprintf("%d", i+1)

	args = append(args, req.PerPage, (req.Page-1)*req.PerPage)
	rows, err := h.Pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "イベント検索に失敗しました"})
		return
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var id, agentID, eventType string
		var rawData []byte
		var ts time.Time
		if err := rows.Scan(&id, &agentID, &eventType, &rawData, &ts); err != nil {
			continue
		}
		events = append(events, map[string]interface{}{
			"id":         id,
			"agent_id":   agentID,
			"event_type": eventType,
			"raw_data":   json.RawMessage(rawData),
			"timestamp":  ts,
		})
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	if events == nil {
		events = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     events,
		"total":    total,
		"page":     req.Page,
		"per_page": req.PerPage,
		// total は maxCountedEvents で打ち切られる。true なら「total 件以上」の意味。
		"total_capped": totalCapped,
		"has_more":     totalCapped || (req.Page*req.PerPage) < total,
	})
}

// Timeline returns time-bucketed event counts.
// GET /api/v1/events/timeline?agent_id=xxx&interval=1h&from=...&to=...
func (h *EventHandler) Timeline(c *gin.Context) {
	agentID := c.Query("agent_id")
	interval := c.DefaultQuery("interval", "1h")

	ctx := c.Request.Context()

	var where string
	var args []interface{}
	if agentID != "" {
		where = "WHERE agent_id = $1"
		args = append(args, agentID)
	}

	// Map interval string to PostgreSQL interval
	pgInterval := "1 hour"
	switch interval {
	case "5m":
		pgInterval = "5 minutes"
	case "15m":
		pgInterval = "15 minutes"
	case "1h":
		pgInterval = "1 hour"
	case "6h":
		pgInterval = "6 hours"
	case "1d":
		pgInterval = "1 day"
	}

	query := `
		SELECT
			time_bucket($` + fmt.Sprintf("%d", len(args)+1) + `::interval, time) AS bucket,
			COUNT(*) AS count,
			event_type
		FROM events ` + where + `
		GROUP BY bucket, event_type
		ORDER BY bucket DESC
		LIMIT 100`

	args = append(args, pgInterval)
	rows, err := h.Pool.Query(ctx, query, args...)
	if err != nil {
		// Fallback for non-TimescaleDB environments
		c.JSON(http.StatusOK, gin.H{
			"data":     []interface{}{},
			"interval": interval,
		})
		return
	}
	defer rows.Close()

	var buckets []map[string]interface{}
	for rows.Next() {
		var bucket time.Time
		var count int64
		var evType string
		if err := rows.Scan(&bucket, &count, &evType); err != nil {
			continue
		}
		buckets = append(buckets, map[string]interface{}{
			"bucket":     bucket,
			"count":      count,
			"event_type": evType,
		})
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	if buckets == nil {
		buckets = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     buckets,
		"interval": interval,
	})
}

// ListDNS returns paginated DNS query events.
// GET /api/v1/events/dns?q=domain&suspicious=true&limit=50&offset=0
func (h *EventHandler) ListDNS(c *gin.Context) {
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit < 1 || limit > 500 {
		limit = 50
	}
	if offset < 0 {
		offset = 0
	}

	search := c.Query("q")
	suspicious := c.Query("suspicious") == "true"

	var conditions []string
	var args []interface{}
	i := 1

	conditions = append(conditions, "event_type = 'dns'")

	if search != "" {
		conditions = append(conditions, fmt.Sprintf("raw_data->>'query' ILIKE $%d", i))
		args = append(args, "%"+search+"%")
		i++
	}
	if suspicious {
		conditions = append(conditions, "(raw_data->>'is_suspicious')::boolean = true")
	}

	where := "WHERE " + conditions[0]
	for _, cond := range conditions[1:] {
		where += " AND " + cond
	}

	ctx := c.Request.Context()

	total, _ := countEventsCapped(ctx, h.Pool, where, args...)

	query := `
		SELECT e.event_id, e.agent_id, e.time,
		       e.raw_data->>'query'        AS query,
		       e.raw_data->>'query_type'   AS query_type,
		       e.raw_data->'answers'       AS answers,
		       (e.raw_data->>'pid')::int   AS pid,
		       e.raw_data->>'process_name' AS process_name,
		       COALESCE(a.hostname, '')    AS hostname,
		       COALESCE((e.raw_data->>'is_suspicious')::boolean, false) AS is_suspicious
		FROM events e
		LEFT JOIN agents a ON a.id = e.agent_id
		` + where + `
		ORDER BY e.time DESC
		LIMIT $` + fmt.Sprintf("%d", i) + ` OFFSET $` + fmt.Sprintf("%d", i+1)

	args = append(args, limit, offset)
	rows, err := h.Pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "DNSイベントの取得に失敗しました"})
		return
	}
	defer rows.Close()

	type DNSRecord struct {
		ID           string    `json:"id"`
		AgentID      string    `json:"agent_id"`
		Timestamp    time.Time `json:"timestamp"`
		Query        string    `json:"query"`
		QueryType    string    `json:"query_type"`
		Answers      []string  `json:"answers"`
		PID          int       `json:"pid"`
		ProcessName  string    `json:"process_name"`
		Hostname     string    `json:"hostname"`
		IsSuspicious bool      `json:"is_suspicious"`
	}

	var records []DNSRecord
	for rows.Next() {
		var r DNSRecord
		var answersJSON []byte
		if err := rows.Scan(
			&r.ID, &r.AgentID, &r.Timestamp,
			&r.Query, &r.QueryType, &answersJSON,
			&r.PID, &r.ProcessName, &r.Hostname, &r.IsSuspicious,
		); err != nil {
			continue
		}
		// Parse answers JSON array
		if len(answersJSON) > 0 {
			_ = json.Unmarshal(answersJSON, &r.Answers)
		}
		if r.Answers == nil {
			r.Answers = []string{}
		}
		records = append(records, r)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	if records == nil {
		records = []DNSRecord{}
	}

	c.JSON(http.StatusOK, gin.H{
		"records": records,
		"total":   total,
	})
}

// ListByAgent returns events for a specific agent.
// GET /api/v1/agents/:id/events
func (h *EventHandler) ListByAgent(c *gin.Context) {
	agentID := c.Param("id")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	if page < 1 {
		page = 1
	}
	if perPage < 1 || perPage > 200 {
		perPage = 50
	}

	ctx := c.Request.Context()
	limit := perPage
	offset := (page - 1) * perPage

	total, totalCapped := countEventsCapped(ctx, h.Pool, "WHERE agent_id = $1", agentID)

	rows, err := h.Pool.Query(ctx,
		`SELECT event_id, agent_id, event_type, raw_data, time
		 FROM events
		 WHERE agent_id = $1
		 ORDER BY time DESC
		 LIMIT $2 OFFSET $3`,
		agentID, limit, offset,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エージェントイベントの取得に失敗しました"})
		return
	}
	defer rows.Close()

	var events []map[string]interface{}
	for rows.Next() {
		var id, agentIDVal, eventType string
		var rawData []byte
		var ts time.Time
		if err := rows.Scan(&id, &agentIDVal, &eventType, &rawData, &ts); err != nil {
			continue
		}
		events = append(events, map[string]interface{}{
			"id":         id,
			"agent_id":   agentIDVal,
			"event_type": eventType,
			"raw_data":   json.RawMessage(rawData),
			"timestamp":  ts,
		})
	}

	if events == nil {
		events = []map[string]interface{}{}
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     events,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		// total は maxCountedEvents で打ち切られる。true なら「total 件以上」の意味。
		"total_capped": totalCapped,
		"has_more":     totalCapped || (page*perPage) < total,
	})
}

// NetworkStats returns aggregated network connection statistics.
// GET /api/v1/events/network-stats?hours=24&agent_id=xxx
func (h *EventHandler) NetworkStats(c *gin.Context) {
	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"top_destinations": []interface{}{}, "top_ports": []interface{}{}, "top_agents": []interface{}{}, "total": 0})
		return
	}

	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours < 1 || hours > 720 {
		hours = 24
	}
	agentID := c.Query("agent_id")

	// テレメトリの実表は `events`、時刻列は `time`。`agent_events` という
	// テーブルも `created_at` 列も存在しない。
	//
	// 期間は $1 で渡す。以前は hours を Sprintf で SQL に埋めながら args にも
	// 積んでいたため、$1 を参照しないクエリに 1 引数を渡すことになり、
	// エージェント指定なしでは
	// `bind message supplies 1 parameters, but prepared statement requires 0`
	// でも失敗していた。
	args := []interface{}{hours}
	agentFilter := ""
	if agentID != "" {
		agentFilter = fmt.Sprintf(" AND agent_id = $%d", len(args)+1)
		args = append(args, agentID)
	}

	baseWhere := `event_type='network' AND "time" >= NOW() - ($1 * INTERVAL '1 hour')` + agentFilter

	// Total count
	var total int
	_ = h.Pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM events WHERE "+baseWhere, args...).Scan(&total)

	// Top destination IPs
	type ipRow struct {
		IP    string `json:"ip"`
		Count int    `json:"count"`
	}
	var topDst []ipRow
	rows, err := h.Pool.Query(c.Request.Context(),
		"SELECT raw_data->>'dst_ip' AS ip, COUNT(*) AS cnt FROM events WHERE "+baseWhere+
			" AND raw_data->>'dst_ip' IS NOT NULL AND raw_data->>'dst_ip' != ''"+
			" GROUP BY ip ORDER BY cnt DESC LIMIT 15", args...)
	if err == nil {
		for rows.Next() {
			var r ipRow
			if err := rows.Scan(&r.IP, &r.Count); err == nil {
				topDst = append(topDst, r)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("events row iteration failed", "error", err)
		}
		rows.Close()
	}

	// Top destination ports
	type portRow struct {
		Port     string `json:"port"`
		Protocol string `json:"protocol"`
		Count    int    `json:"count"`
	}
	var topPorts []portRow
	rows2, err := h.Pool.Query(c.Request.Context(),
		"SELECT COALESCE(raw_data->>'dst_port','?') AS port, COALESCE(raw_data->>'protocol','?') AS proto, COUNT(*) AS cnt"+
			" FROM events WHERE "+baseWhere+
			" GROUP BY port, proto ORDER BY cnt DESC LIMIT 15", args...)
	if err == nil {
		for rows2.Next() {
			var r portRow
			if err := rows2.Scan(&r.Port, &r.Protocol, &r.Count); err == nil {
				topPorts = append(topPorts, r)
			}
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("events row iteration failed", "error", err)
		}
		rows2.Close()
	}

	// Top agents by connection count (only if no agent filter)
	type agentRow struct {
		AgentID  string `json:"agent_id"`
		Hostname string `json:"hostname"`
		Count    int    `json:"count"`
	}
	var topAgents []agentRow
	if agentID == "" {
		rows3, err := h.Pool.Query(c.Request.Context(),
			"SELECT e.agent_id::text, COALESCE(a.hostname,'unknown'), COUNT(*) AS cnt"+
				" FROM events e LEFT JOIN agents a ON a.id = e.agent_id"+
				" WHERE e.event_type='network' AND e.\"time\" >= NOW() - ($1 * INTERVAL '1 hour')"+
				" GROUP BY e.agent_id, a.hostname ORDER BY cnt DESC LIMIT 10", hours)
		if err == nil {
			for rows3.Next() {
				var r agentRow
				if err := rows3.Scan(&r.AgentID, &r.Hostname, &r.Count); err == nil {
					topAgents = append(topAgents, r)
				}
			}
			if err := rows3.Err(); err != nil {
				slog.Warn("events row iteration failed", "error", err)
			}
			rows3.Close()
		}
	}

	if topDst == nil {
		topDst = []ipRow{}
	}
	if topPorts == nil {
		topPorts = []portRow{}
	}
	if topAgents == nil {
		topAgents = []agentRow{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":            total,
		"top_destinations": topDst,
		"top_ports":        topPorts,
		"top_agents":       topAgents,
	})
}

// FileStats returns aggregated file event statistics.
// GET /api/v1/events/file-stats?hours=24&agent_id=xxx
func (h *EventHandler) FileStats(c *gin.Context) {
	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"top_paths": []interface{}{}, "top_agents": []interface{}{}, "operations": map[string]int{}, "total": 0})
		return
	}

	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours < 1 || hours > 720 {
		hours = 24
	}
	agentID := c.Query("agent_id")

	agentFilter := ""
	baseArgs := []interface{}{hours}
	if agentID != "" {
		agentFilter = fmt.Sprintf(" AND agent_id = $%d", len(baseArgs)+1)
		baseArgs = append(baseArgs, agentID)
	}

	baseWhere := `event_type='file' AND "time" >= NOW() - ($1 * INTERVAL '1 hour')` + agentFilter

	var total int
	_ = h.Pool.QueryRow(c.Request.Context(), "SELECT COUNT(*) FROM events WHERE "+baseWhere, baseArgs...).Scan(&total)

	// Top file paths by modification count
	type pathRow struct {
		Path  string `json:"path"`
		Count int    `json:"count"`
		Ops   string `json:"operations"`
	}
	var topPaths []pathRow
	rows, err := h.Pool.Query(c.Request.Context(), `
		SELECT
		  COALESCE(raw_data->>'path', raw_data->>'target_path', 'unknown') AS path,
		  COUNT(*) AS cnt,
		  STRING_AGG(DISTINCT COALESCE(raw_data->>'operation','?'), ',') AS ops
		FROM events
		WHERE `+baseWhere+`
		  AND (raw_data->>'path' IS NOT NULL OR raw_data->>'target_path' IS NOT NULL)
		GROUP BY path
		ORDER BY cnt DESC
		LIMIT 15`, baseArgs...)
	if err == nil {
		for rows.Next() {
			var r pathRow
			if err := rows.Scan(&r.Path, &r.Count, &r.Ops); err == nil {
				topPaths = append(topPaths, r)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("events row iteration failed", "error", err)
		}
		rows.Close()
	}

	// Operation type breakdown
	ops := map[string]int{}
	rows2, err := h.Pool.Query(c.Request.Context(), `
		SELECT COALESCE(raw_data->>'operation','unknown') AS op, COUNT(*) AS cnt
		FROM events
		WHERE `+baseWhere+`
		GROUP BY op
		ORDER BY cnt DESC`, baseArgs...)
	if err == nil {
		for rows2.Next() {
			var op string
			var cnt int
			if err := rows2.Scan(&op, &cnt); err == nil {
				ops[op] = cnt
			}
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("events row iteration failed", "error", err)
		}
		rows2.Close()
	}

	// Top agents by file event count
	type agentRow struct {
		AgentID  string `json:"agent_id"`
		Hostname string `json:"hostname"`
		Count    int    `json:"count"`
	}
	var topAgents []agentRow
	if agentID == "" {
		rows3, err := h.Pool.Query(c.Request.Context(), `
			SELECT e.agent_id::text, COALESCE(a.hostname,'unknown'), COUNT(*) AS cnt
			FROM events e LEFT JOIN agents a ON a.id = e.agent_id
			WHERE e.event_type='file' AND e."time" >= NOW() - ($1 * INTERVAL '1 hour')
			GROUP BY e.agent_id, a.hostname ORDER BY cnt DESC LIMIT 10`, hours)
		if err == nil {
			for rows3.Next() {
				var r agentRow
				if err := rows3.Scan(&r.AgentID, &r.Hostname, &r.Count); err == nil {
					topAgents = append(topAgents, r)
				}
			}
			if err := rows3.Err(); err != nil {
				slog.Warn("events row iteration failed", "error", err)
			}
			rows3.Close()
		}
	}

	if topPaths == nil {
		topPaths = []pathRow{}
	}
	if topAgents == nil {
		topAgents = []agentRow{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":      total,
		"top_paths":  topPaths,
		"operations": ops,
		"top_agents": topAgents,
	})
}

// AuthStats returns authentication event statistics.
// GET /api/v1/events/auth-stats?hours=24
func (h *EventHandler) AuthStats(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours < 1 || hours > 720 {
		hours = 24
	}
	ctx := c.Request.Context()

	type userRow struct {
		Username string `json:"username"`
		Count    int    `json:"count"`
		Failures int    `json:"failures"`
	}
	type agentRow2 struct {
		AgentID  string `json:"agent_id"`
		Hostname string `json:"hostname"`
		Count    int    `json:"count"`
	}
	type hourlyRow struct {
		Hour    string `json:"hour"`
		Success int    `json:"success"`
		Failure int    `json:"failure"`
	}
	type eventRow struct {
		ID        string `json:"id"`
		Timestamp string `json:"timestamp"`
		AgentID   string `json:"agent_id"`
		Hostname  string `json:"hostname"`
		Username  string `json:"username"`
		Outcome   string `json:"outcome"`
		LogonType string `json:"logon_type"`
	}

	var total, success, failure int
	var topUsers []userRow
	var topAgents []agentRow2
	var hourly []hourlyRow
	var recent []eventRow

	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{
			"total": 0, "success": 0, "failure": 0,
			"top_users": []userRow{}, "top_agents": []agentRow2{},
			"hourly": []hourlyRow{}, "recent": []eventRow{},
		})
		return
	}

	// Summary counts
	row := h.Pool.QueryRow(ctx, fmt.Sprintf(`
		SELECT
			COUNT(*) FILTER (WHERE raw_data->>'outcome' = 'success') AS success,
			COUNT(*) FILTER (WHERE raw_data->>'outcome' = 'failure') AS failure,
			COUNT(*) AS total
		FROM events
		WHERE event_type = 'auth'
		  AND "time" >= NOW() - INTERVAL '%d hours'`, hours))
	if err := row.Scan(&success, &failure, &total); err != nil {
		slog.Warn("events: 認証統計のスキャンに失敗しました", "error", err)
	}

	// Top users
	rows, err := h.Pool.Query(ctx, fmt.Sprintf(`
		SELECT
			COALESCE(raw_data->>'username', 'unknown') AS username,
			COUNT(*) AS cnt,
			COUNT(*) FILTER (WHERE raw_data->>'outcome' = 'failure') AS failures
		FROM events
		WHERE event_type = 'auth'
		  AND "time" >= NOW() - INTERVAL '%d hours'
		GROUP BY username ORDER BY cnt DESC LIMIT 10`, hours))
	if err == nil {
		for rows.Next() {
			var r userRow
			if err := rows.Scan(&r.Username, &r.Count, &r.Failures); err == nil {
				topUsers = append(topUsers, r)
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("events row iteration failed", "error", err)
		}
		rows.Close()
	}

	// Top agents
	rows2, err := h.Pool.Query(ctx, fmt.Sprintf(`
		SELECT e.agent_id::text, COALESCE(a.hostname, e.agent_id::text), COUNT(*) AS cnt
		FROM events e
		LEFT JOIN agents a ON a.id = e.agent_id
		WHERE e.event_type = 'auth'
		  AND e."time" >= NOW() - INTERVAL '%d hours'
		GROUP BY e.agent_id, a.hostname ORDER BY cnt DESC LIMIT 10`, hours))
	if err == nil {
		for rows2.Next() {
			var r agentRow2
			if err := rows2.Scan(&r.AgentID, &r.Hostname, &r.Count); err == nil {
				topAgents = append(topAgents, r)
			}
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("events row iteration failed", "error", err)
		}
		rows2.Close()
	}

	// Hourly breakdown (last 24h only makes sense bucketed hourly, for longer use daily)
	bucketSQL := ""
	if hours <= 48 {
		bucketSQL = fmt.Sprintf(`
			SELECT to_char(date_trunc('hour', "time"), 'YYYY-MM-DD"T"HH24:00') AS hour,
				COUNT(*) FILTER (WHERE raw_data->>'outcome' = 'success') AS success,
				COUNT(*) FILTER (WHERE raw_data->>'outcome' = 'failure') AS failure
			FROM events
			WHERE event_type = 'auth'
			  AND "time" >= NOW() - INTERVAL '%d hours'
			GROUP BY 1 ORDER BY 1`, hours)
	} else {
		bucketSQL = fmt.Sprintf(`
			SELECT to_char(date_trunc('day', "time"), 'YYYY-MM-DD"T"00:00') AS hour,
				COUNT(*) FILTER (WHERE raw_data->>'outcome' = 'success') AS success,
				COUNT(*) FILTER (WHERE raw_data->>'outcome' = 'failure') AS failure
			FROM events
			WHERE event_type = 'auth'
			  AND "time" >= NOW() - INTERVAL '%d hours'
			GROUP BY 1 ORDER BY 1`, hours)
	}
	rows3, err := h.Pool.Query(ctx, bucketSQL)
	if err == nil {
		for rows3.Next() {
			var r hourlyRow
			if err := rows3.Scan(&r.Hour, &r.Success, &r.Failure); err == nil {
				hourly = append(hourly, r)
			}
		}
		if err := rows3.Err(); err != nil {
			slog.Warn("events row iteration failed", "error", err)
		}
		rows3.Close()
	}

	// Recent auth events
	rows4, err := h.Pool.Query(ctx, fmt.Sprintf(`
		SELECT e.event_id::text, e."time"::text,
			e.agent_id::text, COALESCE(a.hostname, ''),
			COALESCE(e.raw_data->>'username', 'unknown'),
			COALESCE(e.raw_data->>'outcome', ''),
			COALESCE(e.raw_data->>'logon_type', '')
		FROM events e
		LEFT JOIN agents a ON a.id = e.agent_id
		WHERE e.event_type = 'auth'
		  AND e."time" >= NOW() - INTERVAL '%d hours'
		ORDER BY e."time" DESC LIMIT 100`, hours))
	if err == nil {
		for rows4.Next() {
			var r eventRow
			if err := rows4.Scan(&r.ID, &r.Timestamp, &r.AgentID, &r.Hostname, &r.Username, &r.Outcome, &r.LogonType); err == nil {
				recent = append(recent, r)
			}
		}
		if err := rows4.Err(); err != nil {
			slog.Warn("events row iteration failed", "error", err)
		}
		rows4.Close()
	}

	if topUsers == nil {
		topUsers = []userRow{}
	}
	if topAgents == nil {
		topAgents = []agentRow2{}
	}
	if hourly == nil {
		hourly = []hourlyRow{}
	}
	if recent == nil {
		recent = []eventRow{}
	}

	c.JSON(http.StatusOK, gin.H{
		"total":      total,
		"success":    success,
		"failure":    failure,
		"top_users":  topUsers,
		"top_agents": topAgents,
		"hourly":     hourly,
		"recent":     recent,
	})
}

// AgentTimeline returns a unified chronological activity timeline for a single agent.
// GET /api/v1/agents/:id/timeline?hours=24&types=alert,process,network,file,auth
func (h *EventHandler) AgentTimeline(c *gin.Context) {
	agentID := c.Param("id")
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "24"))
	if hours < 1 || hours > 168 {
		hours = 24
	}
	typesParam := c.DefaultQuery("types", "")
	ctx := c.Request.Context()

	type TimelineItem struct {
		ID        string          `json:"id"`
		Timestamp string          `json:"timestamp"`
		Category  string          `json:"category"` // alert, process, network, file, auth, dns
		Title     string          `json:"title"`
		Detail    string          `json:"detail,omitempty"`
		Severity  int             `json:"severity,omitempty"`
		Status    string          `json:"status,omitempty"`
		Raw       json.RawMessage `json:"raw,omitempty"`
	}

	var items []TimelineItem

	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"items": []TimelineItem{}, "total": 0})
		return
	}

	wantType := func(t string) bool {
		if typesParam == "" {
			return true
		}
		// simple contains check
		return len(typesParam) > 0 && (typesParam == t ||
			len(typesParam) > len(t) && (typesParam[:len(t)+1] == t+"," ||
				typesParam[len(typesParam)-len(t)-1:] == ","+t ||
				containsSubstr(typesParam, ","+t+",")))
	}

	// Alerts
	if wantType("alert") {
		// alerts に rule_name 列は無い。ルール名は rules から JOIN で引く。
		// ここは Title の下に出す副題なので、ルールに紐付かないアラート
		// (組み込み検知器は rule_id を埋めない) では空にする — title で
		// 埋めると同じ文字列が 2 行並ぶだけになる。
		rows, err := h.Pool.Query(ctx, fmt.Sprintf(`
			SELECT al.id::text, al.created_at::text, al.title,
			       COALESCE(r.name,''), al.severity, al.status
			FROM alerts al
			LEFT JOIN rules r ON r.id = al.rule_id
			WHERE al.agent_id = $1 AND al.created_at >= NOW() - INTERVAL '%d hours'
			ORDER BY al.created_at DESC LIMIT 200`, hours), agentID)
		if err != nil {
			slog.Warn("timeline: alerts query failed", "error", err)
		}
		if err == nil {
			for rows.Next() {
				var it TimelineItem
				it.Category = "alert"
				var detail string
				if err := rows.Scan(&it.ID, &it.Timestamp, &it.Title, &detail, &it.Severity, &it.Status); err == nil {
					it.Detail = detail
					items = append(items, it)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("events row iteration failed", "error", err)
			}
			rows.Close()
		}
	}

	// Agent events (process, network, file, auth, dns)
	eventTypes := []string{"process", "network", "file", "auth", "dns"}
	var wantedEventTypes []string
	for _, et := range eventTypes {
		if wantType(et) {
			wantedEventTypes = append(wantedEventTypes, et)
		}
	}

	if len(wantedEventTypes) > 0 {
		inClause := ""
		for i, et := range wantedEventTypes {
			if i > 0 {
				inClause += ","
			}
			inClause += "'" + et + "'"
		}
		rows, err := h.Pool.Query(ctx, fmt.Sprintf(`
			SELECT event_id::text, time::text, event_type,
				COALESCE(raw_data->>'image_path', raw_data->>'process_name',
						 raw_data->>'destination_ip', raw_data->>'path',
						 raw_data->>'username', raw_data->>'query', 'Event') AS title,
				COALESCE(raw_data->>'command_line', raw_data->>'cmdline', raw_data->>'port',
						 raw_data->>'operation', raw_data->>'outcome',
						 raw_data->>'answer', '') AS detail,
				raw_data
			FROM events
			WHERE agent_id = $1
			  AND event_type IN (%s)
			  AND time >= NOW() - INTERVAL '%d hours'
			ORDER BY time DESC LIMIT 500`, inClause, hours), agentID)
		if err == nil {
			for rows.Next() {
				var it TimelineItem
				var raw []byte
				if err := rows.Scan(&it.ID, &it.Timestamp, &it.Category, &it.Title, &it.Detail, &raw); err == nil {
					it.Raw = json.RawMessage(raw)
					items = append(items, it)
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("events row iteration failed", "error", err)
			}
			rows.Close()
		}
	}

	if items == nil {
		items = []TimelineItem{}
	}
	// Sort all items chronologically (newest first)
	sort.Slice(items, func(i, j int) bool {
		return items[i].Timestamp > items[j].Timestamp
	})
	c.JSON(http.StatusOK, gin.H{"items": items, "total": len(items)})
}

func containsSubstr(s, sub string) bool {
	return len(s) >= len(sub) && func() bool {
		for i := 0; i <= len(s)-len(sub); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	}()
}
