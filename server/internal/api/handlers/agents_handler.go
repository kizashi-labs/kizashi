package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/edr-platform/server/internal/isolation"
	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AgentHandler provides endpoint management handlers.
type AgentHandler struct {
	Store           *store.AgentStore
	Commander       agentCommander
	ResponseActions responseAuditor
	// Isolator is the only way this handler may isolate or release an endpoint.
	//
	// nil のときは 200 を返さず 503 で断る。「押せたのに何も起きない」は、
	// この一連の変更が潰している「実行していないのに成功と報告する」形そのもの
	// なので、結線漏れが成功に見えてはいけない。
	Isolator   endpointIsolator
	Alerts     *store.AlertStore
	Quarantine *store.QuarantineStore
	Pool       *pgxpool.Pool // for cross-table queries (processes)
	// UninstallGuardProvider supplies the tenant's uninstall-password material
	// to attach to heartbeat responses, or nil when none is configured.
	//
	// A function rather than a store handle so this handler keeps no dependency
	// on uninstall protection and stays constructible without it — the
	// registration test builds every handler with zero values, and a nil store
	// here would turn a heartbeat into a panic. Nil provider simply means the
	// field is omitted and agents keep whatever guard they already hold.
	UninstallGuardProvider func(*gin.Context) map[string]any
}

// agentCommander is the subset of store.CommandStore this handler dispatches
// through. It is an interface so a DISPATCH FAILURE can be exercised in a test:
// the defect this guards against is a containment command that fails to reach the
// endpoint while the database, the audit trail and the HTTP response all report
// success. That path had no coverage because the field was a concrete type and a
// failing commander could not be injected.
//
// 隔離と隔離解除はここに無い。それだけは isolation.Gatekeeper を通す
// （internal/isolation の冒頭を参照）。
type agentCommander interface {
	Scan(ctx context.Context, agentID, scanType, triggeredBy, commandID string) error
	ScanCancel(ctx context.Context, agentID, triggeredBy, commandID string) error
	KillProcess(ctx context.Context, agentID string, pid uint32, reason, commandID string) error
	QuarantineFile(ctx context.Context, agentID, path, alertID, commandID string) error
	RestoreFile(ctx context.Context, agentID, quarantineID, restorePath, commandID string) error
}

// endpointIsolator is the subset of isolation.Gatekeeper the handlers use.
//
// 手動隔離もここを通す。経路ごとに記録の作法が違うと、結局どの経路が
// 何を残すのかを人が覚えることになる。実際それで、実隔離が
// response_actions に一行も残らない経路が生き残っていた。
type endpointIsolator interface {
	Isolate(ctx context.Context, req isolation.Request) (isolation.Result, error)
	Unisolate(ctx context.Context, req isolation.Request) (isolation.Result, error)
}

// responseAuditor records what was attempted and whether it was dispatched.
type responseAuditor interface {
	// Record returns the new row's id so a later result notification can move it
	// to a terminal state via Complete.
	Record(ctx context.Context, agentID, actionType, status, triggeredBy string, details interface{}) (string, error)
	RecordFailure(ctx context.Context, agentID, actionType, triggeredBy, errMsg string, details interface{}) error
	Complete(ctx context.Context, id, status, errMsg string) error
	List(ctx context.Context, agentID string, limit, offset int) ([]*store.ResponseAction, int, error)
}

// NewAgentHandler creates a new AgentHandler.
func NewAgentHandler(s *store.AgentStore, cmd *store.CommandStore) *AgentHandler {
	h := &AgentHandler{Store: s}
	// Assign only when non-nil: storing a typed nil pointer in an interface makes
	// every `h.Commander != nil` guard true and the next call panics.
	if cmd != nil {
		h.Commander = cmd
	}
	return h
}

// List returns a paginated list of agents with optional filtering.
// GET /api/v1/agents?os=windows&status=online&page=1&per_page=20
// Also accepts "limit" as an alias for "per_page".
func (h *AgentHandler) List(c *gin.Context) {
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "0"))
	if perPage <= 0 {
		perPage, _ = strconv.Atoi(c.DefaultQuery("limit", "20"))
	}
	page, perPage, _ = clampPageParams(page, perPage, 20, 1000)

	filter := store.AgentFilter{
		OSType:  c.Query("os"),
		Status:  c.Query("status"),
		GroupID: c.Query("group_id"),
		Search:  c.Query("search"),
		Limit:   perPage,
		Offset:  (page - 1) * perPage,
	}

	agents, total, err := h.Store.ListAgents(c.Request.Context(), filter)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エージェント一覧の取得に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     agents,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"has_more": (page * perPage) < total,
	})
}

// Get returns a single agent by ID.
// GET /api/v1/agents/:id
func (h *AgentHandler) Get(c *gin.Context) {
	id := c.Param("id")
	agent, err := h.Store.GetAgentByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "エージェントが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, agent)
}

// Update updates agent metadata (PUT replaces, PATCH merges).
// PUT /api/v1/agents/:id  — replaces tags and group_id
// PATCH /api/v1/agents/:id — updates only provided fields
func (h *AgentHandler) Update(c *gin.Context) {
	id := c.Param("id")

	var raw map[string]json.RawMessage
	if err := c.ShouldBindJSON(&raw); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}

	// For PATCH, fetch current values and only override provided fields.
	current, err := h.Store.GetAgentByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "エージェントが見つかりません"})
		return
	}

	tags := current.Tags
	groupID := current.GroupID

	if v, ok := raw["tags"]; ok {
		var t []string
		if err := json.Unmarshal(v, &t); err == nil {
			tags = t
		}
	}
	if v, ok := raw["group_id"]; ok {
		var g *string
		if err := json.Unmarshal(v, &g); err == nil {
			groupID = g
		}
	}

	if err := h.Store.UpdateAgentMeta(c.Request.Context(), id, tags, groupID); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エージェントの更新に失敗しました"})
		return
	}

	agent, err := h.Store.GetAgentByID(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "エージェントが見つかりません"})
		return
	}

	c.JSON(http.StatusOK, agent)
}

// Delete removes an agent record from the database.
// DELETE /api/v1/agents/:id
func (h *AgentHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.DeleteAgent(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "エージェントが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "エージェントを削除しました", "id": id})
}

// ensureAgentInTenant is an application-layer defense-in-depth check for
// response-action endpoints that issue a command to an endpoint by :id. It
// writes the response and returns false when the caller must not proceed, so
// the command is never issued. It closes cross-tenant BOLA even when
// PostgreSQL RLS is not enforcing (e.g. the app still connects as a superuser
// role) and for command paths that never touch the RLS-protected agents row.
//
// **以前は「リクエストにテナントが無ければ素通し」でした**
// （`if tid == "" { return true }`、コメントは「single-tenant mode」）。
// その読みは、APIキー認証では成り立ちません —— `router.go` は構成に
// 関係なく `c.Set("tenant_id", "")` を無条件に置きます。ログインは必ず
// テナントを載せる（既定値に倒してでも）ので、**空になるのは実質
// APIキーだけです。**
//
// 下の層も止めませんでした。`AgentBelongsToTenant` は呼ばれず、RLS の
// 方針は `app.tenant_id` が空文字なら全テナント可として扱い、
// `TenantMiddleware` は空のときに ctx へ入れないのでそれが設定された
// ままになります。**塞ぐために書かれた関数を、いちばん通り抜けるのが
// APIキーでした。** 実測で、テナントを名乗らないリクエストが他テナントの
// 端末を隔離できました（agent_tenant_guard_test.go）。
//
// いまは端末の側に持ち主を訊きます。**構成の話（この配備にテナントが
// あるか）と認証の話（この呼び出し元が名乗れるか）を混ぜません。**
// 行にテナントが書かれていなければ、本当にテナント分離の無い配備なので
// 素通しします。書かれていて呼び出し元が名乗れないなら、通しません。
func (h *AgentHandler) ensureAgentInTenant(c *gin.Context, agentID string) bool {
	agentTenant, found, err := h.Store.AgentTenant(c.Request.Context(), agentID)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エージェントの確認に失敗しました"})
		return false
	}
	if !found {
		c.JSON(http.StatusNotFound, gin.H{"error": "エージェントが見つかりません"})
		return false
	}
	if agentTenant == "" {
		return true // 行に持ち主が書かれていない ＝ テナント分離の無い配備
	}

	tenantID, _ := c.Get("tenant_id")
	tid, _ := tenantID.(string)
	if tid == "" {
		// 誰として操作しているのか分かりません。**分からないことを
		// 「全テナントとして」と読み替えない**のがここの要点です。
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "テナントを特定できないため、この操作は実行できません。" +
				"APIキーではなくユーザートークンでお試しください",
			"tenant_missing": true,
		})
		return false
	}
	if tid != agentTenant {
		c.JSON(http.StatusNotFound, gin.H{"error": "エージェントが見つかりません"})
		return false
	}
	return true
}

// Isolate sends an isolation command to the agent.
// POST /api/v1/agents/:id/isolate
func (h *AgentHandler) Isolate(c *gin.Context) {
	id := c.Param("id")
	// 送れないと分かっているなら、DB を隔離状態に書き換える前に断る。
	// 書いてから断ると「記録は隔離、実態は接続中」を自分で作ることになる。
	if h.Isolator == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "隔離の実行経路が構成されていません。端末はネットワークに接続されたままです",
			"id":    id,
		})
		return
	}

	if !h.ensureAgentInTenant(c, id) {
		return
	}

	var req struct {
		Reason string `json:"reason"`
	}
	if !OptionalBody(c, &req) {
		return
	}
	if req.Reason == "" {
		req.Reason = "手動隔離"
	}

	userID, _ := c.Get("user_id")
	by, _ := userID.(string)

	if err := h.Store.IsolateAgent(c.Request.Context(), id, req.Reason, by); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エージェントの隔離に失敗しました"})
		return
	}

	// The dispatch error used to be discarded. When it failed, the database still
	// said "isolated", the audit trail still said "success", and the operator still
	// got 200 "エージェントを隔離しました" — while the endpoint was never told and
	// stayed on the network. A containment action that reports success without
	// happening is the most dangerous failure this API can have.
	// 記録・送出・結果の反映はすべて Gatekeeper が行う。手動隔離は
	// isolation.OriginManual なので、冷却期間・時間あたり上限・ドライランは
	// 適用されない（それらは誤検知が勝手に端末を止めることへの対策であって、
	// 押した人の判断を止めるためのものではない）。
	if _, err := h.Isolator.Isolate(c.Request.Context(), isolation.Request{
		AgentID:     id,
		Reason:      req.Reason,
		Origin:      isolation.OriginManual,
		TriggeredBy: by,
		Label:       "手動隔離",
	}); err != nil {
		slog.Error("隔離コマンドの送信に失敗しました", "agent", id, "error", err)
		// The agents row keeps isolated=true on purpose: it records the operator's
		// INTENT, and the heartbeat/self-healing path uses it to re-deliver. Rolling
		// it back here would discard the intent and leave nothing to retry from.
		// Say plainly that the two are out of step so nobody reads this as done.
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "隔離を記録しましたが、エンドポイントへの指示に失敗しました。端末はまだネットワークに接続されています",
			"id":    id,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "エージェントを隔離しました", "id": id})
}

// Unisolate restores normal network access for the agent.
// POST /api/v1/agents/:id/unisolate
func (h *AgentHandler) Unisolate(c *gin.Context) {
	id := c.Param("id")
	// 解除側も同じ。送れないなら DB を先に書き換えない。書いてしまうと
	// 「記録は解除済み、実態は隔離のまま」= 孤児化した隔離そのものになる。
	if h.Isolator == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{
			"error": "隔離解除の実行経路が構成されていません。端末は隔離されたままの可能性があります",
			"id":    id,
		})
		return
	}

	if !h.ensureAgentInTenant(c, id) {
		return
	}

	if err := h.Store.UnisolateAgent(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "エージェントの隔離解除に失敗しました"})
		return
	}

	userID, _ := c.Get("user_id")
	by, _ := userID.(string)

	// Same discarded error as Isolate, and the inverse hazard: the database says the
	// endpoint is released while its firewall rules are still in place. That is the
	// orphaned-isolation shape — the host is unreachable and every console says it
	// is fine.
	if _, err := h.Isolator.Unisolate(c.Request.Context(), isolation.Request{
		AgentID:     id,
		Reason:      "手動隔離解除",
		Origin:      isolation.OriginManual,
		TriggeredBy: by,
		Label:       "手動隔離解除",
	}); err != nil {
		slog.Error("隔離解除コマンドの送信に失敗しました", "agent", id, "error", err)
		c.JSON(http.StatusBadGateway, gin.H{
			"error": "隔離解除を記録しましたが、エンドポイントへの指示に失敗しました。端末はまだ隔離されたままの可能性があります",
			"id":    id,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "エージェントの隔離を解除しました", "id": id})
}

// GetProcesses returns process events for an agent (from the events table).
// GET /api/v1/agents/:id/processes
func (h *AgentHandler) GetProcesses(c *gin.Context) {
	id := c.Param("id")

	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"data": []interface{}{}, "total": 0})
		return
	}

	ctx := c.Request.Context()
	rows, err := h.Pool.Query(ctx, `
		SELECT event_id, time,
		       COALESCE(raw_data->>'pid', '')                                       AS pid,
		       COALESCE(raw_data->>'image_path', raw_data->>'process_name', '')    AS image,
		       COALESCE(raw_data->>'command_line', raw_data->>'cmdline', '')        AS cmdline,
		       COALESCE(raw_data->>'parent_image', '')                              AS parent_image,
		       COALESCE(raw_data->>'username', raw_data->>'user', '')               AS username,
		       -- ハッシュは sha256 / sha1 / md5 の個別キーで入ります。hashes という
		       -- まとめたキーは無く、この列は常に空でした。強い順に1つ選びます。
		       COALESCE(NULLIF(raw_data->>'sha256', ''),
		                NULLIF(raw_data->>'sha1', ''),
		                NULLIF(raw_data->>'md5', ''), '')                           AS hashes
		FROM events
		WHERE agent_id = $1 AND event_type = 'process'
		ORDER BY time DESC
		LIMIT 200`,
		id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プロセス情報の取得に失敗しました"})
		return
	}
	defer rows.Close()

	type Process struct {
		ID          string    `json:"id"`
		Timestamp   time.Time `json:"timestamp"`
		PID         string    `json:"pid"`
		Image       string    `json:"image"`
		Cmdline     string    `json:"cmdline"`
		ParentImage string    `json:"parent_image"`
		Username    string    `json:"user"`
		Hashes      string    `json:"hashes"`
	}

	var processes []Process
	for rows.Next() {
		var p Process
		if err := rows.Scan(
			&p.ID, &p.Timestamp, &p.PID, &p.Image,
			&p.Cmdline, &p.ParentImage, &p.Username, &p.Hashes,
		); err != nil {
			continue
		}
		processes = append(processes, p)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プロセス情報の取得に失敗しました"})
		return
	}

	if processes == nil {
		processes = []Process{}
	}

	c.JSON(http.StatusOK, gin.H{"data": processes, "total": len(processes)})
}

// GetProcessStats returns the latest per-process CPU/memory snapshot for an agent.
// GET /api/v1/agents/:id/process-stats
func (h *AgentHandler) GetProcessStats(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"data": []interface{}{}, "updated_at": nil})
		return
	}

	var rawData []byte
	var updatedAt time.Time
	err := h.Pool.QueryRow(ctx, `
		SELECT raw_data, time
		FROM events
		WHERE agent_id = $1::uuid AND event_type = 'process_stats'
		ORDER BY time DESC
		LIMIT 1`, id).Scan(&rawData, &updatedAt)
	if err != nil {
		ReadFailure(c, err, gin.H{"data": []interface{}{}, "updated_at": nil})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":       json.RawMessage(rawData),
		"updated_at": updatedAt,
	})
}

// TriggerScan dispatches a scan command to the agent.
// POST /api/v1/agents/:id/scan
func (h *AgentHandler) TriggerScan(c *gin.Context) {
	id := c.Param("id")
	if !h.ensureAgentInTenant(c, id) {
		return
	}

	var req struct {
		ScanType string `json:"scan_type"`
	}
	if !OptionalBody(c, &req) {
		return
	}
	if req.ScanType == "" {
		req.ScanType = "full"
	}

	userID, _ := c.Get("user_id")
	by, _ := userID.(string)

	if h.Commander != nil {
		if err := h.Commander.Scan(c.Request.Context(), id, req.ScanType, by, ""); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "スキャンコマンドの送信に失敗しました"})
			return
		}
	}

	h.noteResponseAction(c, id, "scan", store.StatusDispatched, by,
		map[string]string{"scan_type": req.ScanType})

	c.JSON(http.StatusAccepted, gin.H{
		"message":   "スキャンコマンドを送信しました",
		"id":        id,
		"scan_type": req.ScanType,
		"queued_at": time.Now(),
	})
}

// TriggerScanCancel asks the agent to stop the in-flight scan.
// POST /api/v1/agents/:id/scan/cancel
func (h *AgentHandler) TriggerScanCancel(c *gin.Context) {
	id := c.Param("id")
	if !h.ensureAgentInTenant(c, id) {
		return
	}

	userID, _ := c.Get("user_id")
	by, _ := userID.(string)

	if h.Commander != nil {
		if err := h.Commander.ScanCancel(c.Request.Context(), id, by, ""); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "スキャン停止コマンドの送信に失敗しました"})
			return
		}
	}

	h.noteResponseAction(c, id, "scan_cancel", store.StatusDispatched, by, nil)

	c.JSON(http.StatusAccepted, gin.H{
		"message":   "スキャン停止コマンドを送信しました",
		"id":        id,
		"queued_at": time.Now(),
	})
}

// severityForRule maps a YARA rule name to an alert severity (1-10 scale).
// Higher values indicate higher confidence / risk. Unknown rules fall back
// to 6 (medium-high). Add new entries here as the rule catalogue grows.
func severityForRule(rule string) int {
	switch rule {
	case "EICAR_Test":
		// EICAR is the industry-standard antivirus test string. A match is a
		// near-zero false-positive signal that something deliberately
		// triggered the detector — score it HIGH per the validation plan.
		return 8
	case "Malware_Test_Content":
		// Built-in placeholder rule that fires on any file containing the
		// literal string "malware_test_content" — useful for development /
		// pipeline testing but high false-positive risk on real binaries.
		return 6
	default:
		return 6
	}
}

// ReportScanResults receives YARA scan results from the agent (no JWT required).
// POST /api/v1/agents/:id/scan-results
func (h *AgentHandler) ReportScanResults(c *gin.Context) {
	agentID := c.Param("id")

	var req struct {
		Target  string `json:"target"`
		Scanned int    `json:"scanned"`
		Matched int    `json:"matched"`
		Matches []struct {
			File string `json:"file"`
			Rule string `json:"rule"`
			// Optional: agent ≥ v1.3.10 attaches the file's SHA-256 and size.
			// Older agents leave these empty/zero — the server still records
			// the bare match, just without IOC fingerprinting.
			SHA256 string `json:"sha256,omitempty"`
			Size   int64  `json:"size,omitempty"`
		} `json:"matches"`
		Cancelled bool `json:"cancelled,omitempty"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}

	status := "success"
	if req.Matched > 0 {
		status = "warning"
	}
	if req.Cancelled {
		status = "cancelled"
	}

	details := map[string]interface{}{
		"target":    req.Target,
		"scanned":   req.Scanned,
		"matched":   req.Matched,
		"cancelled": req.Cancelled,
		"matches":   req.Matches,
	}

	h.noteResponseAction(c, agentID, "scan_result", status, "agent", details)

	// Generate an alert when YARA matches were found, so the detection appears
	// in /alerts and the dashboard counters (not just the agent's response history).
	if req.Matched > 0 && h.Alerts != nil {
		rawEvent, _ := json.Marshal(details)
		title := fmt.Sprintf("YARAスキャン検知: %d件の一致 (%s)", req.Matched, req.Target)
		desc := fmt.Sprintf("対象: %s, スキャン数: %d, 一致数: %d", req.Target, req.Scanned, req.Matched)
		if len(req.Matches) > 0 {
			desc += fmt.Sprintf(" — 例: %s [%s]", req.Matches[0].File, req.Matches[0].Rule)
		}
		// Severity is driven by which YARA rule(s) matched. The validation plan
		// (docs/malware-validation-plan.md §10) requires EICAR detections to be
		// at least HIGH (>= 7) so they pass the "100% PASS" criterion.
		severity := 6 // medium baseline for generic test rules
		for _, m := range req.Matches {
			if s := severityForRule(m.Rule); s > severity {
				severity = s
			}
		}
		now := time.Now()
		alert := &store.StoredAlert{
			ID:          uuid.NewString(),
			AgentID:     agentID,
			Severity:    severity,
			Status:      "open",
			Title:       title,
			Description: &desc,
			RawEvent:    rawEvent,
			CreatedAt:   now,
			UpdatedAt:   now,
		}
		if err := h.Alerts.SaveAlert(c.Request.Context(), alert); err != nil {
			slog.Warn("scan_resultからalert作成に失敗しました", "agent", agentID, "error", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{"message": "スキャン結果を受信しました"})
}

// ReportQuarantineResult receives a quarantine completion report from the
// agent (no JWT required — same pattern as ReportScanResults). Persists to
// the quarantined_files table so the /quarantine UI can list and Restore.
// POST /api/v1/agents/:id/quarantine-result
func (h *AgentHandler) ReportQuarantineResult(c *gin.Context) {
	agentID := c.Param("id")

	var req struct {
		AlertID           string `json:"alert_id"`
		Path              string `json:"path" binding:"required"`
		FileSize          *int64 `json:"file_size"`
		MD5               string `json:"hash_md5"`
		SHA256            string `json:"hash_sha256"`
		AgentQuarantineID string `json:"quarantine_id"` // agent-local ID, needed for future Restore
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "pathが必要です"})
		return
	}

	if h.Quarantine == nil {
		c.JSON(http.StatusOK, gin.H{"message": "受信しました (永続化未構成)"})
		return
	}

	f, err := h.Quarantine.Record(c.Request.Context(), agentID, req.AlertID, req.Path, req.FileSize, req.MD5, req.SHA256, req.AgentQuarantineID)
	if err != nil {
		slog.Warn("agent検疫結果の保存に失敗しました", "agent", agentID, "path", req.Path, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "検疫レコードの保存に失敗しました"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": f.ID, "message": "検疫結果を記録しました"})
}

// GetResponseHistory returns response actions for an agent.
// GET /api/v1/agents/:id/response-history
func (h *AgentHandler) GetResponseHistory(c *gin.Context) {
	id := c.Param("id")
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	perPage, _ := strconv.Atoi(c.DefaultQuery("per_page", "20"))
	page, perPage, _ = clampPageParams(page, perPage, 20, 100)

	if h.ResponseActions == nil {
		c.JSON(http.StatusOK, gin.H{
			"data": []interface{}{}, "total": 0,
			"page": page, "per_page": perPage, "has_more": false,
		})
		return
	}

	actions, total, err := h.ResponseActions.List(c.Request.Context(), id, perPage, (page-1)*perPage)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "対応履歴の取得に失敗しました"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"data":     actions,
		"total":    total,
		"page":     page,
		"per_page": perPage,
		"has_more": (page * perPage) < total,
	})
}

// KillProcess sends a process termination command to an agent.
// POST /api/v1/agents/:id/kill-process
func (h *AgentHandler) KillProcess(c *gin.Context) {
	agentID := c.Param("id")
	if !h.ensureAgentInTenant(c, agentID) {
		return
	}

	var req struct {
		PID    uint32 `json:"pid" binding:"required"`
		Reason string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "PIDが必要です"})
		return
	}
	if req.Reason == "" {
		req.Reason = "手動によるプロセス終了"
	}

	userID, _ := c.Get("user_id")
	by, _ := userID.(string)

	if h.Commander != nil {
		if err := h.Commander.KillProcess(c.Request.Context(), agentID, req.PID, req.Reason, ""); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "プロセス終了コマンドの送信に失敗しました"})
			return
		}
	}

	h.noteResponseAction(c, agentID, "kill_process", store.StatusDispatched, by,
		map[string]string{"pid": strconv.Itoa(int(req.PID)), "reason": req.Reason})

	c.JSON(http.StatusAccepted, gin.H{
		"message": "プロセス終了コマンドを送信しました",
		"pid":     req.PID,
	})
}

// QuarantineFile sends a file quarantine command to an agent.
// POST /api/v1/agents/:id/quarantine-file
func (h *AgentHandler) QuarantineFile(c *gin.Context) {
	agentID := c.Param("id")
	if !h.ensureAgentInTenant(c, agentID) {
		return
	}

	var req struct {
		Path    string `json:"path" binding:"required"`
		AlertID string `json:"alert_id"`
		Reason  string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ファイルパスが必要です"})
		return
	}

	userID, _ := c.Get("user_id")
	by, _ := userID.(string)

	if h.Commander != nil {
		if err := h.Commander.QuarantineFile(c.Request.Context(), agentID, req.Path, req.AlertID, ""); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ファイル隔離コマンドの送信に失敗しました"})
			return
		}
	}

	h.noteResponseAction(c, agentID, "quarantine_file", store.StatusDispatched, by,
		map[string]string{"path": req.Path, "alert_id": req.AlertID})

	c.JSON(http.StatusAccepted, gin.H{
		"message": "ファイル隔離コマンドを送信しました",
		"path":    req.Path,
	})
}

// RestoreFile sends a file restore command to an agent.
// POST /api/v1/agents/:id/restore-file
func (h *AgentHandler) RestoreFile(c *gin.Context) {
	agentID := c.Param("id")
	if !h.ensureAgentInTenant(c, agentID) {
		return
	}

	var req struct {
		QuarantineID string `json:"quarantine_id" binding:"required"`
		RestorePath  string `json:"restore_path"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "quarantine_id が必要です"})
		return
	}

	userID, _ := c.Get("user_id")
	by, _ := userID.(string)

	if h.Commander != nil {
		if err := h.Commander.RestoreFile(c.Request.Context(), agentID, req.QuarantineID, req.RestorePath, ""); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "ファイル復元コマンドの送信に失敗しました"})
			return
		}
	}

	h.noteResponseAction(c, agentID, "restore_file", store.StatusDispatched, by,
		map[string]string{"quarantine_id": req.QuarantineID, "restore_path": req.RestorePath})

	c.JSON(http.StatusAccepted, gin.H{
		"message":       "ファイル復元コマンドを送信しました",
		"quarantine_id": req.QuarantineID,
	})
}

// ListGroups returns all agent groups.
// GET /api/v1/groups
func (h *AgentHandler) ListGroups(c *gin.Context) {
	groups, err := h.Store.ListGroups(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "グループ一覧の取得に失敗しました"})
		return
	}
	if groups == nil {
		groups = []*store.AgentGroup{}
	}
	c.JSON(http.StatusOK, gin.H{"data": groups, "total": len(groups)})
}

// GetGroup returns a single group with its member agents.
// GET /api/v1/groups/:id
func (h *AgentHandler) GetGroup(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()

	groups, err := h.Store.ListGroups(ctx)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "グループの取得に失敗しました"})
		return
	}
	var grp interface{}
	for _, g := range groups {
		if g.ID == id {
			grp = g
			break
		}
	}
	if grp == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "グループが見つかりません"})
		return
	}

	members, _, err := h.Store.ListAgents(ctx, store.AgentFilter{GroupID: id, Limit: 1000})
	if err != nil {
		// 以前は members = nil で先へ進んでいました。グループ詳細が
		// 「所属端末なし」に見えます。空のグループと区別が付きません。
		slog.Error("agents: グループの所属端末を取得できませんでした", "group", id, "error", err)
		ReadFailure(c, err, gin.H{"group": grp, "members": []any{}})
		return
	}

	type memberRow struct {
		AgentID   string `json:"agent_id"`
		Hostname  string `json:"hostname"`
		IPAddress string `json:"ip_address"`
		OS        string `json:"os"`
		Status    string `json:"status"`
	}
	rows := make([]memberRow, 0, len(members))
	for _, a := range members {
		ip := ""
		if len(a.IPAddresses) > 0 {
			ip = a.IPAddresses[0]
		}
		rows = append(rows, memberRow{
			AgentID:   a.ID,
			Hostname:  a.Hostname,
			IPAddress: ip,
			OS:        a.OSType + " " + a.OSVersion,
			Status:    a.Status,
		})
	}

	c.JSON(http.StatusOK, gin.H{
		"id":       id,
		"members":  rows,
		"policies": []struct{}{},
		"alerts":   []struct{}{},
		"stats":    gin.H{"alert_trend": []int{0, 0, 0, 0, 0, 0, 0}, "online_count": 0, "offline_count": 0},
	})
}

// CreateGroup creates a new agent group.
// POST /api/v1/groups
func (h *AgentHandler) CreateGroup(c *gin.Context) {
	var req struct {
		Name        string `json:"name" binding:"required"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "グループ名が必要です"})
		return
	}

	group, err := h.Store.CreateGroup(c.Request.Context(), req.Name, req.Description)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "グループの作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, group)
}

// UpdateGroup updates an agent group.
// PUT /api/v1/groups/:id
func (h *AgentHandler) UpdateGroup(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name        string `json:"name"`
		Description string `json:"description"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}
	if err := h.Store.UpdateGroup(c.Request.Context(), id, req.Name, req.Description); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": err.Error()})
		return
	}
	c.JSON(http.StatusOK, gin.H{"id": id, "name": req.Name, "description": req.Description})
}

// DeleteGroup deletes an agent group.
// DELETE /api/v1/groups/:id
func (h *AgentHandler) DeleteGroup(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.DeleteGroup(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "グループの削除に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "グループを削除しました", "id": id})
}

// RiskScore calculates a risk score for an endpoint based on open alerts and vulnerabilities.
// GET /api/v1/agents/:id/risk-score
func (h *AgentHandler) RiskScore(c *gin.Context) {
	agentID := c.Param("id")
	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"score": 0, "level": "unknown"})
		return
	}
	ctx := c.Request.Context()

	type riskData struct {
		AlertCritical int
		AlertHigh     int
		AlertMedium   int
		VulnCritical  int
		VulnHigh      int
		IsIsolated    bool
	}
	var rd riskData

	// Alert counts (open/investigating)
	rows, err := h.Pool.Query(ctx, `
		SELECT
		  COUNT(*) FILTER (WHERE severity >= 9)                  AS crit_alerts,
		  COUNT(*) FILTER (WHERE severity >= 7 AND severity < 9) AS high_alerts,
		  COUNT(*) FILTER (WHERE severity >= 4 AND severity < 7) AS med_alerts
		FROM alerts
		WHERE agent_id = $1::uuid
		  AND status IN ('open','investigating')`, agentID)
	// **読めなかった 0 は、この端末のリスクスコアを静かに下げます。**
	// 片方は `slog.Warn` 止まり、片方は `_ =` でした —— どちらも
	// 「危険なものは無い」と読める画面になります。
	var alertScanErr error
	if err == nil {
		if rows.Next() {
			alertScanErr = rows.Scan(&rd.AlertCritical, &rd.AlertHigh, &rd.AlertMedium)
		}
		rows.Close()
	}
	if !ReadOK(c, alertScanErr) {
		return
	}

	// Vulnerability counts (open)
	rows2, err := h.Pool.Query(ctx, `
		SELECT
		  COUNT(*) FILTER (WHERE severity='critical') AS crit_vulns,
		  COUNT(*) FILTER (WHERE severity='high')     AS high_vulns
		FROM vulnerabilities
		WHERE agent_id = $1::uuid AND status='open'`, agentID)
	var vulnScanErr error
	if err == nil {
		if rows2.Next() {
			vulnScanErr = rows2.Scan(&rd.VulnCritical, &rd.VulnHigh)
		}
		rows2.Close()
	}
	if !ReadOK(c, vulnScanErr) {
		return
	}

	// Isolation status
	if !ReadOK(c, h.Pool.QueryRow(ctx,
		"SELECT isolation_status='isolated' FROM agents WHERE id=$1::uuid", agentID,
	).Scan(&rd.IsIsolated)) {
		return
	}

	// Score calculation (max 100)
	score := 0
	score += rd.AlertCritical * 25
	score += rd.AlertHigh * 15
	score += rd.AlertMedium * 5
	score += rd.VulnCritical * 20
	score += rd.VulnHigh * 10
	if score > 100 {
		score = 100
	}

	level := "low"
	switch {
	case score >= 75:
		level = "critical"
	case score >= 50:
		level = "high"
	case score >= 25:
		level = "medium"
	}

	c.JSON(http.StatusOK, gin.H{
		"score":          score,
		"level":          level,
		"alert_critical": rd.AlertCritical,
		"alert_high":     rd.AlertHigh,
		"alert_medium":   rd.AlertMedium,
		"vuln_critical":  rd.VulnCritical,
		"vuln_high":      rd.VulnHigh,
		"is_isolated":    rd.IsIsolated,
	})
}

// RiskScores returns risk scores for all agents (used by dashboard/list views).
// GET /api/v1/agents/risk-scores
func (h *AgentHandler) RiskScores(c *gin.Context) {
	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"data": []interface{}{}})
		return
	}
	rows, err := h.Pool.Query(c.Request.Context(), `
		SELECT
		  a.id::text,
		  a.hostname,
		  COUNT(al.id) FILTER (WHERE al.severity >= 9 AND al.status IN ('open','investigating'))  AS crit,
		  COUNT(al.id) FILTER (WHERE al.severity >= 7 AND al.severity < 9 AND al.status IN ('open','investigating')) AS high,
		  COUNT(v.id)  FILTER (WHERE v.severity = 'critical' AND v.status = 'open')  AS vcrit,
		  COUNT(v.id)  FILTER (WHERE v.severity = 'high'     AND v.status = 'open')  AS vhigh
		FROM agents a
		LEFT JOIN alerts al ON al.agent_id = a.id
		LEFT JOIN vulnerabilities v ON v.agent_id = a.id
		GROUP BY a.id, a.hostname
		HAVING
		  COUNT(al.id) FILTER (WHERE al.severity >= 7 AND al.status IN ('open','investigating')) > 0
		  OR COUNT(v.id) FILTER (WHERE v.severity IN ('critical','high') AND v.status='open') > 0
		ORDER BY (COUNT(al.id) FILTER (WHERE al.severity >= 9 AND al.status IN ('open','investigating')) * 25 +
		          COUNT(al.id) FILTER (WHERE al.severity >= 7 AND al.severity < 9 AND al.status IN ('open','investigating')) * 15 +
		          COUNT(v.id)  FILTER (WHERE v.severity='critical' AND v.status='open') * 20 +
		          COUNT(v.id)  FILTER (WHERE v.severity='high' AND v.status='open') * 10) DESC
		LIMIT 20`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "リスクスコアの取得に失敗しました"})
		return
	}
	defer rows.Close()

	type agentRisk struct {
		ID       string `json:"id"`
		Hostname string `json:"hostname"`
		Score    int    `json:"score"`
		Level    string `json:"level"`
	}
	var result []agentRisk
	for rows.Next() {
		var r agentRisk
		var crit, high, vcrit, vhigh int
		if err := rows.Scan(&r.ID, &r.Hostname, &crit, &high, &vcrit, &vhigh); err != nil {
			continue
		}
		score := crit*25 + high*15 + vcrit*20 + vhigh*10
		if score > 100 {
			score = 100
		}
		r.Score = score
		switch {
		case score >= 75:
			r.Level = "critical"
		case score >= 50:
			r.Level = "high"
		case score >= 25:
			r.Level = "medium"
		default:
			r.Level = "low"
		}
		result = append(result, r)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "リスクスコアの取得に失敗しました"})
		return
	}
	if result == nil {
		result = []agentRisk{}
	}
	c.JSON(http.StatusOK, gin.H{"data": result})
}

// ProcessTree returns historical process events for an agent to build a process tree.
// GET /api/v1/agents/:id/process-tree?hours=4
func (h *AgentHandler) ProcessTree(c *gin.Context) {
	agentID := c.Param("id")
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "4"))
	if hours < 1 || hours > 168 {
		hours = 4
	}

	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"processes": []interface{}{}})
		return
	}

	rows, err := h.Pool.Query(c.Request.Context(), `
		SELECT
		  event_id::text,
		  COALESCE(raw_data->>'pid','0')                                         AS pid,
		  COALESCE(raw_data->>'ppid','0')                                        AS ppid,
		  COALESCE(raw_data->>'image_path', raw_data->>'process_name', '')       AS image,
		  COALESCE(raw_data->>'command_line', raw_data->>'cmdline', '')           AS cmdline,
		  COALESCE(raw_data->>'username', raw_data->>'user', '')                  AS username,
		  COALESCE(raw_data->>'parent_image','')                                  AS parent_image,
		  time
		FROM events
		WHERE agent_id = $1::uuid
		  AND event_type = 'process'
		  AND time >= NOW() - ($2 * INTERVAL '1 hour')
		ORDER BY time ASC
		LIMIT 500`,
		agentID, hours)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プロセスツリーの取得に失敗しました"})
		return
	}
	defer rows.Close()

	type ProcessNode struct {
		ID          string    `json:"id"`
		PID         string    `json:"pid"`
		PPID        string    `json:"ppid"`
		Image       string    `json:"image"`
		Cmdline     string    `json:"cmdline"`
		Username    string    `json:"username"`
		ParentImage string    `json:"parent_image"`
		Timestamp   time.Time `json:"timestamp"`
	}
	var processes []ProcessNode
	for rows.Next() {
		var p ProcessNode
		if err := rows.Scan(
			&p.ID, &p.PID, &p.PPID, &p.Image,
			&p.Cmdline, &p.Username, &p.ParentImage, &p.Timestamp,
		); err == nil {
			processes = append(processes, p)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "プロセスツリーの取得に失敗しました"})
		return
	}
	if processes == nil {
		processes = []ProcessNode{}
	}
	c.JSON(http.StatusOK, gin.H{"processes": processes, "total": len(processes)})
}

// ProtectionSummary returns the fleet's kernel-protection (eBPF LSM) readiness
// breakdown by reported protection_mode (enforce/observe/poll/unreported).
// GET /api/v1/agents-protection-summary
func (h *AgentHandler) ProtectionSummary(c *gin.Context) {
	// One GROUP BY (os, mode) scan; the fleet-wide by_mode totals are the per-OS
	// breakdown folded down — no need for a second ProtectionModeSummary scan.
	byOS, err := h.Store.ProtectionModeByOS(c.Request.Context())
	if err != nil {
		slog.Warn("protection summary failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "保護モード集計の取得に失敗しました"})
		return
	}
	summary := map[string]int{}
	total := 0
	for _, modes := range byOS {
		for mode, n := range modes {
			summary[mode] += n
			total += n
		}
	}
	enforcePct := 0
	if total > 0 {
		enforcePct = summary["enforce"] * 100 / total
	}

	// Effective collection mode alongside capability. Reported best-effort: a
	// failure here must not blank the protection summary, which is the primary
	// payload, so the telemetry fields are simply omitted on error.
	telemetryByOS, err := h.Store.TelemetryModeByOS(c.Request.Context())
	if err != nil {
		slog.Warn("telemetry summary failed", "error", err)
		c.JSON(http.StatusOK, gin.H{
			"by_mode":           summary,
			"by_os":             byOS,
			"total":             total,
			"enforce_ready_pct": enforcePct,
		})
		return
	}
	telemetrySummary := map[string]int{}
	telemetryTotal := 0
	for _, modes := range telemetryByOS {
		for mode, n := range modes {
			telemetrySummary[mode] += n
			telemetryTotal += n
		}
	}
	// Denominator is agents that actually reported a mode: Windows/macOS agents
	// do not, and counting them as "not on eBPF" would understate the Linux fleet
	// it is measuring.
	ebpfReported := telemetryTotal - telemetrySummary["unreported"]
	ebpfPct := 0
	if ebpfReported > 0 {
		ebpfPct = telemetrySummary["ebpf"] * 100 / ebpfReported
	}

	c.JSON(http.StatusOK, gin.H{
		"by_mode":           summary, // {enforce, observe, poll, unreported}
		"by_os":             byOS,    // {os_type: {mode: count}} (Linux/Windows/darwin)
		"total":             total,
		"enforce_ready_pct": enforcePct, // % of fleet doing in-kernel prevention

		// Effective collection mechanism — what agents are actually running on, as
		// opposed to what their hosts are capable of above.
		"telemetry_by_mode":  telemetrySummary, // {ebpf, poll, off, unreported}
		"telemetry_by_os":    telemetryByOS,    // {os_type: {mode: count}}
		"ebpf_effective_pct": ebpfPct,          // % of reporting agents actually on eBPF
	})
}

// AnomalyBoard returns the most behaviorally-anomalous agents by UEBA/Isolation-
// Forest score (alerts.anomaly_score, last 7 days). GET /api/v1/agents-anomaly-board
func (h *AgentHandler) AnomalyBoard(c *gin.Context) {
	board, err := h.Store.AnomalousAgentsBoard(c.Request.Context(), 10)
	if err != nil {
		slog.Warn("anomaly board failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "異常スコアボードの取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"agents": board, "total": len(board)})
}

// Heartbeat receives an HTTP heartbeat from an agent, updating last_seen and
// resolving any open offline/health alerts for that agent.
// POST /api/v1/agents/:id/heartbeat
//
// Body (optional JSON):
//
//	{ "hostname": "DESKTOP-SQB1AJO", "ip_addresses": ["192.168.1.10"] }
func (h *AgentHandler) Heartbeat(c *gin.Context) {
	agentID := c.Param("id")
	ctx := c.Request.Context()

	var body struct {
		Hostname       string   `json:"hostname"`
		IPAddresses    []string `json:"ip_addresses"`
		AgentVersion   string   `json:"agent_version"`
		OSVersion      string   `json:"os_version"`
		OSType         string   `json:"os_type"`
		Status         string   `json:"status"`          // "online"|"isolated"|"error" reported by agent
		ProtectionMode string   `json:"protection_mode"` // "enforce"|"observe"|"poll" kernel-protection tier (host capability)
		TelemetryMode  string   `json:"telemetry_mode"`  // "ebpf"|"poll"|"off" mechanism actually collecting
		// TelemetryDetail explains the mode per sensor, e.g.
		// "file=poll(eBPF非対応) network=ebpf process=ebpf".
		TelemetryDetail string `json:"telemetry_detail"`
	}
	// Body is optional — ignore parse errors.
	_ = c.ShouldBindJSON(&body)

	// Update last_seen, status = online, hostname, IP addresses, versions.
	if err := h.Store.UpdateLastSeen(ctx, agentID, body.Hostname, body.IPAddresses, body.AgentVersion, body.OSVersion, body.OSType); err != nil {
		slog.Warn("HTTP heartbeat: UpdateLastSeen failed", "agent_id", agentID, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "heartbeat update failed"})
		return
	}

	// Record the reported kernel-protection tier (best-effort; non-fatal).
	if err := h.Store.UpdateProtectionMode(ctx, agentID, body.ProtectionMode); err != nil {
		slog.Warn("HTTP heartbeat: UpdateProtectionMode failed", "agent_id", agentID, "error", err)
	}

	// Record the effective collection mechanism (best-effort; non-fatal). Separate
	// from protection mode so a capable-but-degraded endpoint is visible.
	if err := h.Store.UpdateTelemetryMode(ctx, agentID, body.TelemetryMode, body.TelemetryDetail); err != nil {
		slog.Warn("HTTP heartbeat: UpdateTelemetryMode failed", "agent_id", agentID, "error", err)
	}

	// Resolve open offline / health alerts for this agent.
	//
	// **落ちると、戻ってきた端末のオフラインアラートが開いたまま
	// 残ります** —— 対応する人には「まだ落ちている」に見えます。
	// ハートビートの応答に載せるものではないので、件数に出します。
	if err := h.Store.ResolveAgentOfflineAlerts(ctx, agentID); err != nil {
		metrics.BackgroundFailed("agent_heartbeat", err,
			"復帰した端末のオフラインアラートを解決できませんでした",
			"agent_id", agentID)
	}

	// Reconcile isolation state in **both** directions.
	//
	// 巻き戻しは片側しかありませんでした —— 端末が「まだ隔離中」で DB が
	// 解除済みなら解除させる、その一方向だけです。**逆が無いので、
	// 隔離コマンドが端末に届かなかったとき、その端末は二度と隔離
	// されませんでした**（DB も画面も「隔離済み」のまま）。
	//
	// 対称にすると、**DB が唯一の真実**になります。指示の送信は速い経路で、
	// 届かなければ次のハートビート（30 秒）が直します。
	shouldIsolate, shouldUnisolate := false, false
	if agent, err := h.Store.GetAgentByID(ctx, agentID); err == nil {
		shouldIsolate, shouldUnisolate = reconcileIsolation(agent.Status, body.Status)
		if shouldIsolate {
			slog.Warn("ハートビート経由の隔離指示を送信", "agent_id", agentID)
		}
		if shouldUnisolate {
			slog.Info("ハートビート経由の隔離解除指示を送信", "agent_id", agentID)
		}
	}

	resp := gin.H{
		"ok":               true,
		"should_isolate":   shouldIsolate,
		"should_unisolate": shouldUnisolate,
	}

	// Uninstall-password material rides the heartbeat because it has to be on
	// the endpoint *before* it is needed: the agent verifies an uninstall with
	// the network plausibly cut, so there is no chance to fetch it then.
	if h.UninstallGuardProvider != nil {
		if guard := h.UninstallGuardProvider(c); guard != nil {
			resp["uninstall_guard"] = guard
		}
	}

	c.JSON(http.StatusOK, resp)
}

// noteResponseAction records a dispatched response action and reports if it
// could not be written.
//
// **操作は済んでいて、残るのは記録だけです。** 応答は「送信しました」
// を答えていて、その記録が書けたかどうかは別の話です —— 各所とも
// `_ =` で捨てていました。落ちると、**インシデントの時系列から封じ込めの
// 操作が抜けます**（誰がいつ何をしたかの唯一の記録です）。
//
// 隔離／隔離解除は `Record` の返す id を ack の突き合わせに使うため、
// ここは通さず個別に扱います。こちらは id を必要としない片道の操作用です。
func (h *AgentHandler) noteResponseAction(c *gin.Context, agentID, action, status, by string, details any) {
	if h.ResponseActions == nil {
		return
	}
	if _, err := h.ResponseActions.Record(c.Request.Context(), agentID, action, status, by, details); err != nil {
		metrics.BackgroundFailed("response_action_record", err,
			"対応操作を記録できませんでした。インシデントの時系列から抜けます",
			"agent_id", agentID, "action", action, "status", status)
	}
}

// reconcileIsolation decides what to tell an agent whose reported isolation
// state disagrees with the database.
//
// **判定を切り出してあります。** 元は片方向だけで、`should_unisolate` の
// 分岐しかありませんでした —— 隔離コマンドが端末に届かなかったとき、
// **DB も画面も「隔離済み」、端末は繋がったまま、それを直すものが
// 何もありません**でした。
//
// `dbStatus` が真実です。指示の送信は速い経路で、届かなければ次の
// ハートビート（30 秒）がここで直します。
func reconcileIsolation(dbStatus, reportedStatus string) (shouldIsolate, shouldUnisolate bool) {
	dbIsolated := dbStatus == "isolated"
	reportedIsolated := reportedStatus == "isolated"
	switch {
	case dbIsolated && !reportedIsolated:
		return true, false
	case !dbIsolated && reportedIsolated:
		return false, true
	}
	return false, false
}
