package handlers

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/detection"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// parseTimeParam reads an RFC3339 ?from / ?to bound.
//
// 読めない値は error にします。以前は nil を返していて、nil は「指定なし」
// と同じ意味なので、期間の絞り込みだけが黙って消えます。聞かれたのとは
// 違う質問に答えることになり、しかも広い方に外れます。CSV 書き出しでも
// 同じ関数を使っているので、「3月17日から18日のアラート」として渡された
// ファイルに、全期間の1万件が入ります。
func parseTimeParam(s string) (*time.Time, error) {
	if s == "" {
		return nil, nil
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return nil, fmt.Errorf("日時は RFC3339 形式で指定してください (例: 2026-03-17T10:00:00Z): %q", s)
	}
	return &t, nil
}

// timeRangeParams reads ?from and ?to, answering 400 and reporting false when
// either is unreadable.
func timeRangeParams(c *gin.Context) (from, to *time.Time, ok bool) {
	from, err := parseTimeParam(c.Query("from"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return nil, nil, false
	}
	to, err = parseTimeParam(c.Query("to"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return nil, nil, false
	}
	return from, to, true
}

// AlertHandler provides alert management endpoints.
type AlertHandler struct {
	Store      *store.AlertStore
	AgentStore *store.AgentStore
	Pool       *pgxpool.Pool // for cross-table event timeline queries
}

// NewAlertHandler creates a new AlertHandler.
func NewAlertHandler(s *store.AlertStore, agentStore *store.AgentStore) *AlertHandler {
	return &AlertHandler{Store: s, AgentStore: agentStore}
}

// List returns a paginated list of alerts with optional filtering.
// GET /api/v1/alerts?status=open&severity=7&agent_id=xxx&page=1&per_page=20
func (h *AlertHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))
	page, perPage, offset := clampPageParams(page, perPage, 20, 100)

	severityStr := c.Query("severity")
	var severity int
	if severityStr != "" {
		var err error
		severity, err = strconv.Atoi(severityStr)
		// Minimum is 1: the store uses Severity==0 as "no filter" sentinel.
		if err != nil || severity < 1 || severity > 10 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "severityは1〜10の整数で指定してください"})
			return
		}
	}
	severityMaxStr := c.Query("severity_max")
	var severityMax int
	if severityMaxStr != "" {
		var err error
		severityMax, err = strconv.Atoi(severityMaxStr)
		if err != nil || severityMax < 1 || severityMax > 10 {
			c.JSON(http.StatusBadRequest, gin.H{"error": "severity_maxは1〜10の整数で指定してください"})
			return
		}
	}

	fromTime, toTime, ok := timeRangeParams(c)
	if !ok {
		return
	}
	filter := store.AlertFilter{
		Status:         c.Query("status"),
		AgentID:        c.Query("agent_id"),
		RuleID:         c.Query("rule_id"),
		Severity:       severity,
		SeverityMax:    severityMax,
		Search:         c.Query("search"),
		MITRETech:      c.Query("mitre_technique"),
		FromTime:       fromTime,
		ToTime:         toTime,
		AIInvestigated: c.Query("ai_investigated") == "true",
		Limit:          perPage,
		Offset:         offset,
	}

	alerts, total, err := h.Store.ListAlerts(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アラート一覧の取得に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     alerts,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"has_more": (page * perPage) < total,
	})
}

// Stats returns aggregated alert statistics.
// GET /api/v1/alerts/stats
func (h *AlertHandler) Stats(c *gin.Context) {
	stats, err := h.Store.AlertStats(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "統計情報の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, stats)
}

// Get returns a single alert by ID.
// GET /api/v1/alerts/:id
func (h *AlertHandler) Get(c *gin.Context) {
	id := c.Param("id")
	alert, err := h.Store.GetAlert(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "アラートが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, alert)
}

// Update updates the status and/or assignment of an alert.
// PUT /api/v1/alerts/:id
func (h *AlertHandler) Update(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		Status     *string `json:"status"`
		AssignedTo *string `json:"assigned_to"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}

	if err := h.Store.UpdateAlert(c.Request.Context(), id, req.Status, nil, req.AssignedTo); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アラートの更新に失敗しました"})
		return
	}

	alert, err := h.Store.GetAlert(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "アラートを更新しました", "id": id})
		return
	}
	c.JSON(http.StatusOK, alert)
}

// AddComment persists a comment on an alert.
// POST /api/v1/alerts/:id/comments
func (h *AlertHandler) AddComment(c *gin.Context) {
	alertID := c.Param("id")

	var req struct {
		Content string `json:"content" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "コメントの内容が必要です"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	commentID, createdAt, err := h.Store.AddComment(c.Request.Context(), alertID, userIDStr, req.Content)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コメントの保存に失敗しました"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":         commentID,
		"alert_id":   alertID,
		"content":    req.Content,
		"user_id":    userIDStr,
		"created_at": createdAt,
	})
}

// Graph returns the attack graph for an alert: processes → network/file nodes.
// GET /api/v1/alerts/:id/graph
func (h *AlertHandler) Graph(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	// ── Types ──────────────────────────────────────────────────
	type GraphNode struct {
		ID         string            `json:"id"`
		Type       string            `json:"type"` // alert|process|network|file|registry|dns
		Label      string            `json:"label"`
		Detail     map[string]string `json:"detail"`
		Suspicious bool              `json:"suspicious"`
		Timestamp  string            `json:"timestamp"`
		Severity   int               `json:"severity"`
	}
	type GraphEdge struct {
		Source string `json:"source"`
		Target string `json:"target"`
		Type   string `json:"type"` // spawned|connected|wrote|read|queried
		Label  string `json:"label"`
	}

	// ── Load alert ─────────────────────────────────────────────
	alert, err := h.Store.GetAlert(ctx, id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "アラートが見つかりません"})
		return
	}

	var nodes []GraphNode
	var edges []GraphEdge

	// ── Root node (Alert) ──────────────────────────────────────
	rootID := "alert-" + alert.ID
	mitre := ""
	if alert.MITRETech != nil {
		mitre = *alert.MITRETech
	}
	ruleName := ""
	if alert.RuleName != nil {
		ruleName = *alert.RuleName
	}
	rootDetail := map[string]string{
		"rule":   ruleName,
		"mitre":  mitre,
		"host":   alert.Hostname,
		"os":     alert.OS,
		"status": alert.Status,
	}
	nodes = append(nodes, GraphNode{
		ID: rootID, Type: "alert",
		Label: alert.Title, Detail: rootDetail,
		Suspicious: true, Severity: alert.Severity,
		Timestamp: alert.CreatedAt.Format(time.RFC3339),
	})

	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"nodes": nodes, "edges": edges, "alert_id": id})
		return
	}

	// ── Process events ± 2 h around alert ─────────────────────
	procRows, err := h.Pool.Query(ctx, `
		SELECT
			event_id::text,
			COALESCE(raw_data->>'pid',''),
			COALESCE(raw_data->>'ppid',''),
			COALESCE(raw_data->>'image_path',''),
			COALESCE(raw_data->>'command_line',''),
			COALESCE(raw_data->>'username',''),
			COALESCE(raw_data->>'parent_image',''),
			-- プロセスイベントに疑わしさの判定はありません。is_suspicious は
			-- dns イベント専用 (DnsEvent の DGA/homograph 判定) で、ここでは
			-- 常に NULL でした。無い判定を読むより、判定が無いことを
			-- 明示します — 相関グラフのプロセスノードは文脈であり、
			-- 強調表示の対象はアラート自身のノードです。
			false,
			"time"::text
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'process'
		  AND "time" BETWEEN $2::timestamptz - INTERVAL '2 hours'
		                 AND $2::timestamptz + INTERVAL '2 hours'
		ORDER BY "time" ASC
		LIMIT 150`,
		alert.AgentID, alert.CreatedAt)
	if err != nil {
		slog.Warn("alert graph: process events query failed", "error", err)
	}
	if err == nil {
		defer procRows.Close()
		pidToNodeID := map[string]string{}
		for procRows.Next() {
			var evID, pid, ppid, image, cmdline, username, parentImage string
			var suspicious bool
			var ts string
			if err := procRows.Scan(&evID, &pid, &ppid, &image, &cmdline,
				&username, &parentImage, &suspicious, &ts); err != nil {
				continue
			}
			// Basename of image path as label
			label := image
			if idx := strings.LastIndexAny(image, `/\`); idx >= 0 {
				label = image[idx+1:]
			}
			if label == "" {
				label = fmt.Sprintf("PID:%s", pid)
			}
			nodeID := "proc-" + evID
			pidToNodeID[pid] = nodeID

			detail := map[string]string{
				"pid":    pid,
				"ppid":   ppid,
				"image":  image,
				"cmd":    cmdline,
				"user":   username,
				"parent": parentImage,
			}
			nodes = append(nodes, GraphNode{
				ID: nodeID, Type: "process",
				Label: label, Detail: detail,
				Suspicious: suspicious, Timestamp: ts,
			})

			// Edge: parent → this process
			if ppid != "" && ppid != "0" {
				if parentNodeID, ok := pidToNodeID[ppid]; ok {
					edges = append(edges, GraphEdge{
						Source: parentNodeID, Target: nodeID,
						Type: "spawned", Label: "spawned",
					})
				} else {
					// Parent not in window — link to alert root
					edges = append(edges, GraphEdge{
						Source: rootID, Target: nodeID,
						Type: "spawned", Label: "process",
					})
				}
			} else {
				edges = append(edges, GraphEdge{
					Source: rootID, Target: nodeID,
					Type: "spawned", Label: "process",
				})
			}
		}
		if err := procRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	// ── Network events ─────────────────────────────────────────
	netRows, err := h.Pool.Query(ctx, `
		SELECT
			event_id::text,
			COALESCE(raw_data->>'dst_ip',''),
			COALESCE(raw_data->>'dst_port',''),
			COALESCE(raw_data->>'protocol','tcp'),
			COALESCE(raw_data->>'pid',''),
			COALESCE(raw_data->>'process_name',''),
			-- ネットワークイベントでの「疑わしい」は threat_intel_matched です
			-- (is_suspicious は dns 専用で、ここでは常に NULL でした)。
			COALESCE((raw_data->>'threat_intel_matched')::boolean, false),
			"time"::text
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'network'
		  AND "time" BETWEEN $2::timestamptz - INTERVAL '2 hours'
		                 AND $2::timestamptz + INTERVAL '2 hours'
		  AND raw_data->>'dst_ip' IS NOT NULL
		ORDER BY "time" ASC
		LIMIT 80`,
		alert.AgentID, alert.CreatedAt)
	if err != nil {
		slog.Warn("alert graph: network events query failed", "error", err)
	}
	if err == nil {
		defer netRows.Close()
		seenNet := map[string]string{} // dstIP:port → nodeID
		for netRows.Next() {
			var evID, dstIP, dstPort, proto, pid, procName string
			var suspicious bool
			var ts string
			if err := netRows.Scan(&evID, &dstIP, &dstPort, &proto, &pid, &procName, &suspicious, &ts); err != nil {
				continue
			}
			key := dstIP + ":" + dstPort
			netNodeID, exists := seenNet[key]
			if !exists {
				netNodeID = "net-" + evID
				seenNet[key] = netNodeID
				label := dstIP
				if dstPort != "" && dstPort != "0" {
					label += ":" + dstPort
				}
				nodes = append(nodes, GraphNode{
					ID: netNodeID, Type: "network",
					Label: label, Suspicious: suspicious, Timestamp: ts,
					Detail: map[string]string{
						"dst_ip":   dstIP,
						"port":     dstPort,
						"protocol": proto,
						"process":  procName,
					},
				})
			}
			// Edge from process (by PID) or root
			sourceID := rootID
			for _, n := range nodes {
				if n.Type == "process" && n.Detail["pid"] == pid {
					sourceID = n.ID
					break
				}
			}
			if !exists {
				edges = append(edges, GraphEdge{
					Source: sourceID, Target: netNodeID,
					Type: "connected", Label: proto,
				})
			}
		}
		if err := netRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	// ── File events ────────────────────────────────────────────
	fileRows, err := h.Pool.Query(ctx, `
		SELECT
			event_id::text,
			COALESCE(raw_data->>'path', raw_data->>'target_path',''),
			COALESCE(raw_data->>'operation','write'),
			COALESCE(raw_data->>'pid',''),
			-- ファイルイベントでの「疑わしい」は yara_matched です
			-- (is_suspicious は dns 専用で、ここでは常に NULL でした)。
			COALESCE((raw_data->>'yara_matched')::boolean, false),
			"time"::text
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'file'
		  AND "time" BETWEEN $2::timestamptz - INTERVAL '2 hours'
		                 AND $2::timestamptz + INTERVAL '2 hours'
		  AND (raw_data->>'path' IS NOT NULL OR raw_data->>'target_path' IS NOT NULL)
		ORDER BY "time" ASC
		LIMIT 50`,
		alert.AgentID, alert.CreatedAt)
	if err != nil {
		slog.Warn("alert graph: file events query failed", "error", err)
	}
	if err == nil {
		defer fileRows.Close()
		seenFile := map[string]string{}
		for fileRows.Next() {
			var evID, path, op, pid string
			var suspicious bool
			var ts string
			if err := fileRows.Scan(&evID, &path, &op, &pid, &suspicious, &ts); err != nil {
				continue
			}
			if path == "" {
				continue
			}
			fileNodeID, exists := seenFile[path]
			if !exists {
				fileNodeID = "file-" + evID
				seenFile[path] = fileNodeID
				label := path
				if idx := strings.LastIndexAny(path, `/\`); idx >= 0 {
					label = path[idx+1:]
				}
				nodes = append(nodes, GraphNode{
					ID: fileNodeID, Type: "file",
					Label: label, Suspicious: suspicious, Timestamp: ts,
					Detail: map[string]string{"path": path, "op": op},
				})
			}
			if !exists {
				sourceID := rootID
				for _, n := range nodes {
					if n.Type == "process" && n.Detail["pid"] == pid {
						sourceID = n.ID
						break
					}
				}
				edges = append(edges, GraphEdge{
					Source: sourceID, Target: fileNodeID,
					Type: "wrote", Label: op,
				})
			}
		}
		if err := fileRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	// ── DNS events ─────────────────────────────────────────────
	dnsRows, err := h.Pool.Query(ctx, `
		SELECT
			event_id::text,
			COALESCE(raw_data->>'query',''),
			COALESCE(raw_data->>'process_name',''),
			COALESCE((raw_data->>'is_suspicious')::boolean, false),
			"time"::text
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'dns'
		  AND "time" BETWEEN $2::timestamptz - INTERVAL '2 hours'
		                 AND $2::timestamptz + INTERVAL '2 hours'
		  AND raw_data->>'query' IS NOT NULL
		ORDER BY "time" ASC
		LIMIT 40`,
		alert.AgentID, alert.CreatedAt)
	if err != nil {
		slog.Warn("alert graph: dns events query failed", "error", err)
	}
	if err == nil {
		defer dnsRows.Close()
		seenDNS := map[string]string{}
		for dnsRows.Next() {
			var evID, query, procName string
			var suspicious bool
			var ts string
			if err := dnsRows.Scan(&evID, &query, &procName, &suspicious, &ts); err != nil {
				continue
			}
			if query == "" {
				continue
			}
			_, exists := seenDNS[query]
			if !exists {
				dnsNodeID := "dns-" + evID
				seenDNS[query] = dnsNodeID
				nodes = append(nodes, GraphNode{
					ID: dnsNodeID, Type: "dns",
					Label: query, Suspicious: suspicious, Timestamp: ts,
					Detail: map[string]string{"query": query, "process": procName},
				})
				sourceID := rootID
				edges = append(edges, GraphEdge{
					Source: sourceID, Target: dnsNodeID,
					Type: "queried", Label: "DNS",
				})
			}
		}
		if err := dnsRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}

	if nodes == nil {
		nodes = []GraphNode{}
	}
	if edges == nil {
		edges = []GraphEdge{}
	}

	c.JSON(http.StatusOK, gin.H{
		"alert_id": id,
		"nodes":    nodes,
		"edges":    edges,
	})
}

// StatusHistory returns the status change timeline for an alert.
// GET /api/v1/alerts/:id/history
func (h *AlertHandler) StatusHistory(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	type HistoryEntry struct {
		ID         string  `json:"id"`
		FromStatus *string `json:"from_status"`
		ToStatus   string  `json:"to_status"`
		ChangedBy  string  `json:"changed_by"`
		ChangedAt  string  `json:"changed_at"`
	}

	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"data": []HistoryEntry{}, "total": 0})
		return
	}

	rows, err := h.Pool.Query(ctx, `
		SELECT id::text, from_status, to_status, changed_by, changed_at::text
		FROM alert_status_changes
		WHERE alert_id = $1::uuid
		ORDER BY changed_at ASC`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ステータス履歴の取得に失敗しました"})
		return
	}
	defer rows.Close()

	var entries []HistoryEntry
	for rows.Next() {
		var e HistoryEntry
		if err := rows.Scan(&e.ID, &e.FromStatus, &e.ToStatus, &e.ChangedBy, &e.ChangedAt); err == nil {
			entries = append(entries, e)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ステータス履歴の取得に失敗しました"})
		return
	}
	if entries == nil {
		entries = []HistoryEntry{}
	}
	c.JSON(http.StatusOK, gin.H{"data": entries, "total": len(entries)})
}

// Related returns correlated alerts (same host / rule / MITRE technique within 7 days).
// GET /api/v1/alerts/:id/related
func (h *AlertHandler) Related(c *gin.Context) {
	id := c.Param("id")
	related, err := h.Store.GetRelated(c.Request.Context(), id, 20)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "関連アラートの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": related, "total": len(related)})
}

// ListComments returns comments for a given alert.
// GET /api/v1/alerts/:id/comments
func (h *AlertHandler) ListComments(c *gin.Context) {
	alertID := c.Param("id")
	comments, err := h.Store.ListComments(c.Request.Context(), alertID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "コメントの取得に失敗しました"})
		return
	}
	if comments == nil {
		comments = []store.AlertComment{}
	}
	c.JSON(http.StatusOK, gin.H{"data": comments, "total": len(comments)})
}

// Assign sets the assigned_to field on an alert.
// PUT /api/v1/alerts/:id/assign
func (h *AlertHandler) Assign(c *gin.Context) {
	id := c.Param("id")

	var req struct {
		AssignedTo *string `json:"assigned_to"` // null to unassign
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}

	// Use direct SQL so that assigned_to = NULL (unassign) is handled correctly.
	// UpdateAlert skips nil assigned_to, so we need a dedicated query here.
	var assignErr error
	if req.AssignedTo == nil {
		_, assignErr = h.Store.Pool().Exec(c.Request.Context(),
			`UPDATE alerts SET assigned_to = NULL, updated_at = NOW() WHERE id = $1`, id)
	} else {
		assignErr = h.Store.UpdateAlert(c.Request.Context(), id, nil, nil, req.AssignedTo)
	}
	if assignErr != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "担当者の割り当てに失敗しました"})
		return
	}

	alert, err := h.Store.GetAlert(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"message": "担当者を割り当てました", "id": id})
		return
	}
	c.JSON(http.StatusOK, alert)
}

// BulkUpdate performs a bulk status and/or assignment update on multiple alerts.
// POST /api/v1/alerts/bulk-update
func (h *AlertHandler) BulkUpdate(c *gin.Context) {
	var req struct {
		IDs        []string `json:"ids" binding:"required"`
		Status     *string  `json:"status"`
		AssignedTo *string  `json:"assigned_to"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "IDが必要です"})
		return
	}
	if req.Status == nil && req.AssignedTo == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "status または assigned_to が必要です"})
		return
	}

	ctx := c.Request.Context()
	updated := 0
	var failed []string

	for _, id := range req.IDs {
		if err := h.Store.UpdateAlert(ctx, id, req.Status, nil, req.AssignedTo); err != nil {
			failed = append(failed, id)
			continue
		}
		updated++
	}

	c.JSON(http.StatusOK, gin.H{
		"updated": updated,
		"failed":  failed,
		"total":   len(req.IDs),
	})
}

// Dashboard returns combined dashboard data matching the DashboardSummary frontend type.
// GET /api/v1/dashboard
func (h *AlertHandler) Dashboard(c *gin.Context) {
	ctx := c.Request.Context()

	// Alert statistics
	stats, err := h.Store.AlertStats(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "ダッシュボードデータの取得に失敗しました"})
		return
	}

	// Recent alerts
	recentAlerts, _, err := h.Store.ListAlerts(ctx, store.AlertFilter{Limit: 5, Offset: 0})
	if !ReadOK(c, err) {
		return
	}
	if recentAlerts == nil {
		recentAlerts = []*store.StoredAlert{}
	}

	// Agent summary
	// 'inactive'（30日以上未確認）にもバケットを与える。省くと total だけが増えて
	// online+offline+isolated と一致しなくなり、退役ホストがどの内訳にも現れない。
	agentSummary := map[string]int{"total": 0, "online": 0, "offline": 0, "isolated": 0, "inactive": 0}
	if h.AgentStore != nil {
		if all, total, err := h.AgentStore.ListAgents(ctx, store.AgentFilter{Limit: 9999}); err == nil {
			agentSummary["total"] = total
			for _, a := range all {
				switch a.Status {
				case "online":
					agentSummary["online"]++
				case "offline":
					agentSummary["offline"]++
				case "isolated":
					agentSummary["isolated"]++
				case "inactive":
					agentSummary["inactive"]++
				}
			}
		}
	}

	// Trend: compare last 24h vs previous 24h
	yesterdayCount, err2 := h.Store.AlertCountInWindow(ctx, 48, 24)
	if err2 != nil {
		slog.Warn("AlertStats: failed to fetch previous window count", "error", err2)
	}
	trend := 0
	if yesterdayCount > 0 {
		trend = ((stats.TodayCount - yesterdayCount) * 100) / yesterdayCount
	} else if stats.TodayCount > 0 {
		trend = 100
	}

	// Top threatened agents (past 7 days)
	topAgents, err := h.Store.TopThreatenedAgents(ctx, 5)
	if !ReadOK(c, err) {
		return
	}
	if topAgents == nil {
		topAgents = []store.TopAgent{}
	}

	// Build AlertStats response (matching frontend AlertStats type)
	bySeverity := make(map[string]int)
	for k, v := range stats.BySeverity {
		bySeverity[strconv.Itoa(k)] = v
	}
	alertsResp := map[string]any{
		"total":          stats.Total,
		"open":           stats.Open,
		"investigating":  stats.Investigating,
		"resolved":       stats.Resolved,
		"false_positive": stats.FalsePositive,
		"by_severity":    bySeverity,
		"today_count":    stats.TodayCount,
		"trend_24h":      trend,
	}

	// Event timeline: hourly buckets for past 24h
	eventTimeline, err := h.buildEventTimeline(ctx)
	if !ReadOK(c, err) {
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"agents":                agentSummary,
		"alerts":                alertsResp,
		"top_threatened_agents": topAgents,
		"recent_alerts":         recentAlerts,
		"event_timeline":        eventTimeline,
	})
}

// buildEventTimeline merges hourly event and alert counts for the past 24 hours.
// **失敗を空の時系列で返さないこと。**
//
// アラート件数の読み出しは `_` で捨てられていて、失敗すると
// **「この24時間、アラートは0件」と同じグラフ**になりました。
// 呼び出し側が答えられるよう、error を返します。
func (h *AlertHandler) buildEventTimeline(ctx context.Context) ([]map[string]any, error) {
	type point struct {
		ProcessEvents int
		FileEvents    int
		NetworkEvents int
		AlertCount    int
	}
	byBucket := make(map[string]*point)

	// Query event counts from pool if available
	if h.Pool != nil {
		// events の時刻列は `time` (migration 002 の hypertable パーティションキー)。
		// `timestamp` という列は存在せず、以前はこのクエリが毎回
		// `column "timestamp" does not exist` で失敗し、エラーが握りつぶされて
		// ダッシュボードのイベントタイムラインが常に 0 件表示になっていた。
		rows, err := h.Pool.Query(ctx, `
			SELECT date_trunc('hour', time) AS bucket,
			       COUNT(*) FILTER (WHERE event_type = 'process') AS process_events,
			       COUNT(*) FILTER (WHERE event_type = 'file')    AS file_events,
			       COUNT(*) FILTER (WHERE event_type = 'network') AS network_events
			FROM events
			WHERE time >= NOW() - INTERVAL '24 hours'
			GROUP BY bucket
			ORDER BY bucket ASC`)
		if err != nil {
			slog.Warn("buildEventTimeline: イベント件数の集計に失敗", "error", err)
		}
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var bucket time.Time
				var pe, fe, ne int
				if err := rows.Scan(&bucket, &pe, &fe, &ne); err != nil {
					continue
				}
				key := bucket.UTC().Format(time.RFC3339)
				if byBucket[key] == nil {
					byBucket[key] = &point{}
				}
				byBucket[key].ProcessEvents = pe
				byBucket[key].FileEvents = fe
				byBucket[key].NetworkEvents = ne
			}
			if err := rows.Err(); err != nil {
				slog.Warn("buildEventTimeline: row iteration error", "error", err)
			}
		}
	}

	// Merge in alert counts
	alertBuckets, err := h.Store.AlertTimeline(ctx, 24)
	if err != nil && !absent(err) {
		return nil, err
	}
	for _, b := range alertBuckets {
		key := b.Bucket.UTC().Format(time.RFC3339)
		if byBucket[key] == nil {
			byBucket[key] = &point{}
		}
		byBucket[key].AlertCount = b.Count
	}

	if len(byBucket) == 0 {
		return []map[string]any{}, nil
	}

	// Sort and build response
	keys := make([]string, 0, len(byBucket))
	for k := range byBucket {
		keys = append(keys, k)
	}
	// Simple sort
	for i := 0; i < len(keys); i++ {
		for j := i + 1; j < len(keys); j++ {
			if keys[i] > keys[j] {
				keys[i], keys[j] = keys[j], keys[i]
			}
		}
	}

	result := make([]map[string]any, 0, len(keys))
	for _, k := range keys {
		p := byBucket[k]
		result = append(result, map[string]any{
			"bucket":         k,
			"process_events": p.ProcessEvents,
			"file_events":    p.FileEvents,
			"network_events": p.NetworkEvents,
			"alert_count":    p.AlertCount,
		})
	}
	return result, nil
}

// Export streams filtered alerts as a UTF-8 CSV file.
// GET /api/v1/alerts/export
func (h *AlertHandler) Export(c *gin.Context) {
	severityStr := c.Query("severity")
	severity, _ := strconv.Atoi(severityStr)

	fromTime, toTime, ok := timeRangeParams(c)
	if !ok {
		return
	}
	filter := store.AlertFilter{
		Status:   c.Query("status"),
		AgentID:  c.Query("agent_id"),
		Severity: severity,
		Search:   c.Query("search"),
		FromTime: fromTime,
		ToTime:   toTime,
		Limit:    10000,
		Offset:   0,
	}

	alerts, _, err := h.Store.ListAlerts(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エクスポートに失敗しました"})
		return
	}

	fname := fmt.Sprintf("alerts_%s.csv", time.Now().Format("20060102_150405"))
	c.Header("Content-Type", "text/csv; charset=utf-8")
	c.Header("Content-Disposition", fmt.Sprintf(`attachment; filename="%s"`, fname))

	w := c.Writer
	// BOM for Excel UTF-8 compatibility
	w.Write([]byte("\xef\xbb\xbf"))                                             //nolint
	w.WriteString("ID,タイトル,重大度,ステータス,エンドポイント,OS,MITRE手法,担当者,コメント数,作成日時,更新日時\n") //nolint

	for _, a := range alerts {
		mitre := ""
		if a.MITRETech != nil {
			mitre = *a.MITRETech
		}
		assignee := ""
		if a.AssignedToName != nil {
			assignee = *a.AssignedToName
		}
		row := strings.Join([]string{
			csvField(a.ID),
			csvField(a.Title),
			strconv.Itoa(a.Severity),
			csvField(a.Status),
			csvField(a.Hostname),
			csvField(a.OS),
			csvField(mitre),
			csvField(assignee),
			strconv.Itoa(a.CommentCount),
			a.CreatedAt.Format(time.RFC3339),
			a.UpdatedAt.Format(time.RFC3339),
		}, ",") + "\n"
		w.WriteString(row) //nolint
	}
}

func csvField(s string) string {
	if strings.ContainsAny(s, ",\"\n\r") {
		return `"` + strings.ReplaceAll(s, `"`, `""`) + `"`
	}
	return s
}

// MITREStats returns top MITRE ATT&CK techniques observed in alerts.
// GET /api/v1/alerts/mitre-stats
// GeoStats returns alert counts grouped by source country for threat map visualization.
// GET /api/v1/alerts/geo-stats
func (h *AlertHandler) GeoStats(c *gin.Context) {
	// alerts に src_country 列はありません。どのマイグレーションも作らず、
	// エージェントも設定せず、サーバ側の GeoIP 付与はどこでも動いていません。
	// この問い合わせは必ず 42703 で失敗します。
	//
	// 失敗として返すと、運用担当は復旧するものだと考えて再試行します。
	// 実際には「まだ作られていない」ので、そう言います。
	//
	// ダッシュボードはこの失敗を受けて FALLBACK_GEO_THREATS — 中国142件、
	// ロシア89件、北朝鮮54件 — を表示していました。発明された攻撃元です。
	NotImplemented(c, "攻撃元の国別分布",
		"alerts に国コードの列が無く、サーバ側の GeoIP 付与も未実装です")
}

// killChainStages はサイバーキルチェーンの段階を攻撃の進行順に並べたもの。
// 表示順を固定するために使う。
var killChainStages = []string{
	"recon", "weaponize", "delivery", "exploit", "install", "c2", "actions",
}

// killChainStage は ATT&CK タクティクをキルチェーンの段階へ写す。
//
// ATT&CK は 14 タクティク、キルチェーンは 7 段階なので多対一になる。
// 対応が付かないもの (タクティク不明を含む) は最終段階の "actions"
// (Actions on Objectives) にまとめる — 元の SQL の ELSE と同じ扱い。
func killChainStage(tactic string) string {
	switch tactic {
	case "reconnaissance":
		return "recon"
	case "resource-development":
		return "weaponize"
	case "initial-access":
		return "delivery"
	case "execution", "privilege-escalation":
		return "exploit"
	case "persistence", "defense-evasion":
		return "install"
	case "command-and-control":
		return "c2"
	default:
		// discovery / credential-access / lateral-movement / collection /
		// exfiltration / impact / 不明
		return "actions"
	}
}

// KillChainStats returns alert counts mapped to Cyber Kill Chain stages.
// GET /api/v1/alerts/kill-chain-stats
func (h *AlertHandler) KillChainStats(c *gin.Context) {
	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"data": []any{}})
		return
	}

	// alerts に category / mitre_tactic 列は無い。実在するのは
	// mitre_technique (T1059 のようなテクニック ID) だけで、以前の
	// クエリは毎回 `column "category" does not exist` で失敗し、
	// キルチェーン図は常に空だった。
	//
	// SQL ではテクニック単位で数え、タクティクへの写像は Go 側の
	// detection.TacticForTechnique に任せる (kill-chain 相関・
	// コンプライアンススコアと同じ表)。
	rows, err := h.Pool.Query(c.Request.Context(), `
		SELECT mitre_technique, COUNT(*) AS cnt
		FROM alerts
		WHERE created_at >= NOW() - INTERVAL '30 days'
		  AND mitre_technique IS NOT NULL AND mitre_technique != ''
		GROUP BY mitre_technique`)
	if err != nil {
		slog.Warn("alerts: kill-chain stats query failed", "error", err)
		ReadFailure(c, err, gin.H{"data": []any{}})
		return
	}
	defer rows.Close()

	type stageRow struct {
		Stage string `json:"stage"`
		Count int    `json:"count"`
	}

	byStage := map[string]int{}
	for rows.Next() {
		var technique string
		var cnt int
		if err := rows.Scan(&technique, &cnt); err != nil {
			continue
		}
		byStage[killChainStage(detection.TacticForTechnique(technique))] += cnt
	}
	if err := rows.Err(); err != nil {
		slog.Warn("alerts: kill-chain stats query failed", "error", err)
		ReadFailure(c, err, gin.H{"data": []any{}})
		return
	}

	// 段階は固定順で返す。件数順にすると図の並びが日によって変わる。
	results := make([]stageRow, 0, len(killChainStages))
	for _, stage := range killChainStages {
		if cnt := byStage[stage]; cnt > 0 {
			results = append(results, stageRow{Stage: stage, Count: cnt})
		}
	}
	c.JSON(http.StatusOK, gin.H{"data": results})
}

func (h *AlertHandler) MITREStats(c *gin.Context) {
	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"techniques": []any{}})
		return
	}

	// hours パラメータで集計期間を指定（デフォルト720h=30日、0=全期間）
	hours := 720
	if v := c.Query("hours"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			hours = n
		}
	}

	var timeFilter string
	if hours > 0 {
		timeFilter = fmt.Sprintf("AND created_at >= NOW() - INTERVAL '%d hours'", hours)
	}

	q := fmt.Sprintf(`
		SELECT tech, COUNT(DISTINCT id) AS cnt, MAX(severity) AS max_sev
		FROM (
			SELECT id, severity, mitre_technique AS tech
			FROM alerts
			WHERE mitre_technique IS NOT NULL AND mitre_technique != ''
			  %s
			UNION ALL
			SELECT id, severity, unnest(ai_mitre_tags) AS tech
			FROM alerts
			WHERE ai_mitre_tags IS NOT NULL
			  AND array_length(ai_mitre_tags, 1) > 0
			  %s
		) t
		GROUP BY tech
		ORDER BY cnt DESC`, timeFilter, timeFilter)

	rows, err := h.Pool.Query(c.Request.Context(), q)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MITRE統計の取得に失敗しました"})
		return
	}
	defer rows.Close()

	type techRow struct {
		Technique string `json:"technique"`
		Count     int    `json:"count"`
		MaxSev    int    `json:"max_severity"`
	}
	var techs []techRow
	for rows.Next() {
		var t techRow
		if err := rows.Scan(&t.Technique, &t.Count, &t.MaxSev); err != nil {
			continue
		}
		techs = append(techs, t)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "MITRE統計の取得に失敗しました"})
		return
	}
	if techs == nil {
		techs = []techRow{}
	}
	c.JSON(http.StatusOK, gin.H{"techniques": techs})
}
