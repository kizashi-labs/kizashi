package handlers

import (
	"context"
	"net/http"
	"time"

	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

// ReportHandler provides report generation endpoints backed by DB-persisted jobs.
type ReportHandler struct {
	Store       *store.AlertStore
	AgentStore  *store.AgentStore
	ReportStore *store.ReportStore
}

// NewReportHandler creates a new ReportHandler.
func NewReportHandler(s *store.AlertStore) *ReportHandler {
	return &ReportHandler{Store: s}
}

// NewReportHandlerWithAgents creates a ReportHandler with both stores.
func NewReportHandlerWithAgents(s *store.AlertStore, ag *store.AgentStore, rs *store.ReportStore) *ReportHandler {
	return &ReportHandler{Store: s, AgentStore: ag, ReportStore: rs}
}

// List returns all report jobs (from DB if available, empty list otherwise).
// GET /api/v1/reports
func (h *ReportHandler) List(c *gin.Context) {
	if h.ReportStore == nil {
		c.JSON(http.StatusOK, gin.H{"reports": []interface{}{}, "total": 0})
		return
	}
	jobs, err := h.ReportStore.List(c.Request.Context())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "レポート一覧の取得に失敗しました"})
		return
	}
	result := make([]map[string]interface{}, 0, len(jobs))
	for _, j := range jobs {
		result = append(result, jobToMap(j))
	}
	c.JSON(http.StatusOK, gin.H{"reports": result, "total": len(result)})
}

// Generate creates and enqueues a new report generation job.
// POST /api/v1/reports
func (h *ReportHandler) Generate(c *gin.Context) {
	var req struct {
		Type   string      `json:"type" binding:"required"`
		From   *time.Time  `json:"from"`
		To     *time.Time  `json:"to"`
		Params interface{} `json:"params"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "レポートタイプが必要です"})
		return
	}

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	to := time.Now()
	from := to.AddDate(0, 0, -7)
	if req.To != nil {
		to = *req.To
	}
	if req.From != nil {
		from = *req.From
	}

	jobID := uuid.New().String()

	if h.ReportStore != nil {
		if err := h.ReportStore.Insert(c.Request.Context(), &store.ReportJobRow{
			ID:          jobID,
			Type:        req.Type,
			RequestedBy: userIDStr,
			FromTime:    &from,
			ToTime:      &to,
		}); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "レポートジョブの作成に失敗しました"})
			return
		}
	}

	go h.generateReport(jobID, req.Type, from, to)

	c.JSON(http.StatusAccepted, gin.H{
		"id":           jobID,
		"type":         req.Type,
		"status":       "pending",
		"requested_by": userIDStr,
		"requested_at": time.Now(),
	})
}

func (h *ReportHandler) generateReport(jobID, reportType string, from, to time.Time) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// **この goroutine の3つの書き込みが、ジョブの状態のすべてです。**
	// 呼び出し側はもう 202 を返しています。落ちると:
	//
	//	SetRunning  ジョブは `pending` のまま —— 動いていません、に見える
	//	Fail        失敗したジョブが `running` のまま **永久に**
	//	Complete    出来上がったレポートが `running` のまま、取り出せない
	if h.ReportStore != nil {
		if err := h.ReportStore.SetRunning(ctx, jobID); err != nil {
			metrics.BackgroundFailed("report_job", err,
				"レポートジョブを実行中にできませんでした。pending のまま見えます",
				"job_id", jobID, "type", reportType)
		}
	}

	var content interface{}
	var genErr string

	switch reportType {
	case "alert_summary":
		v, err := h.buildAlertSummary(ctx, from, to)
		if err != nil {
			genErr = err.Error()
		} else {
			content = v
		}
	case "agent_status":
		v, err := h.buildAgentStatus(ctx)
		if err != nil {
			genErr = err.Error()
		} else {
			content = v
		}
	case "threat_report":
		v, err := h.buildThreatReport(ctx, from, to)
		if err != nil {
			genErr = err.Error()
		} else {
			content = v
		}
	default:
		genErr = "不明なレポートタイプ: " + reportType
	}

	if h.ReportStore == nil {
		return
	}
	if genErr != "" {
		if err := h.ReportStore.Fail(ctx, jobID, genErr); err != nil {
			metrics.BackgroundFailed("report_job", err,
				"レポートジョブの失敗を記録できませんでした。running のまま残ります",
				"job_id", jobID, "type", reportType)
		}
	} else {
		payload := map[string]interface{}{
			"generated_at": time.Now(),
			"period":       map[string]interface{}{"from": from, "to": to},
			"summary":      content,
		}
		if err := h.ReportStore.Complete(ctx, jobID, payload); err != nil {
			metrics.BackgroundFailed("report_job", err,
				"出来上がったレポートを保存できませんでした。running のまま取り出せません",
				"job_id", jobID, "type", reportType)
		}
	}
}

// Download fetches a completed report by job ID.
// GET /api/v1/reports/:id
func (h *ReportHandler) Download(c *gin.Context) {
	id := c.Param("id")

	if h.ReportStore == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "レポートストアが設定されていません"})
		return
	}

	job, err := h.ReportStore.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "レポートが見つかりません"})
		return
	}

	if job.Status != "completed" {
		c.JSON(http.StatusAccepted, gin.H{
			"message": "レポートはまだ生成中です",
			"status":  job.Status,
			"id":      id,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"id":           job.ID,
		"type":         job.Type,
		"status":       job.Status,
		"requested_at": job.RequestedAt,
		"completed_at": job.CompletedAt,
		"content":      job.Content,
	})
}

// Delete removes a report job.
// DELETE /api/v1/reports/:id
func (h *ReportHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if h.ReportStore == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "レポートストアが設定されていません"})
		return
	}
	if err := h.ReportStore.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "レポートが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "レポートを削除しました", "id": id})
}

// JobStatus checks the status of a report generation job.
// GET /api/v1/reports/jobs/:id
func (h *ReportHandler) JobStatus(c *gin.Context) {
	id := c.Param("id")

	if h.ReportStore == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "レポートストアが設定されていません"})
		return
	}

	job, err := h.ReportStore.Get(c.Request.Context(), id)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "レポートジョブが見つかりません"})
		return
	}

	c.JSON(http.StatusOK, jobToMap(job))
}

func jobToMap(j *store.ReportJobRow) map[string]interface{} {
	m := map[string]interface{}{
		"id":                j.ID,
		"type":              j.Type,
		"status":            j.Status,
		"requested_by":      j.RequestedBy,
		"requested_by_name": j.RequestedByName,
		"requested_at":      j.RequestedAt,
	}
	if j.CompletedAt != nil {
		m["completed_at"] = j.CompletedAt
	}
	if j.Error != "" {
		m["error"] = j.Error
	}
	if j.Status == "completed" {
		m["download_url"] = "/api/v1/reports/" + j.ID
	}
	return m
}

// ─── Report builders ─────────────────────────────────────────

func (h *ReportHandler) buildAlertSummary(ctx context.Context, from, to time.Time) (interface{}, error) {
	stats, err := h.Store.AlertStats(ctx)
	if err != nil {
		return nil, err
	}

	alerts, _, err := h.Store.ListAlerts(ctx, store.AlertFilter{
		FromTime: &from,
		ToTime:   &to,
		Limit:    100,
		Offset:   0,
	})
	if err != nil {
		return nil, err
	}

	type item struct {
		ID       string    `json:"id"`
		Title    string    `json:"title"`
		Severity int       `json:"severity"`
		Status   string    `json:"status"`
		AgentID  string    `json:"agent_id"`
		Created  time.Time `json:"created_at"`
	}
	items := make([]item, 0, len(alerts))
	for _, a := range alerts {
		items = append(items, item{
			ID: a.ID, Title: a.Title, Severity: a.Severity,
			Status: a.Status, AgentID: a.AgentID, Created: a.CreatedAt,
		})
	}
	return map[string]interface{}{"stats": stats, "alerts": items, "count": len(items)}, nil
}

func (h *ReportHandler) buildAgentStatus(ctx context.Context) (interface{}, error) {
	if h.AgentStore == nil {
		return map[string]interface{}{"message": "AgentStore not configured"}, nil
	}
	agents, total, err := h.AgentStore.ListAgents(ctx, store.AgentFilter{Limit: 1000, Offset: 0})
	if err != nil {
		return nil, err
	}

	type item struct {
		ID       string     `json:"id"`
		Hostname string     `json:"hostname"`
		OSType   string     `json:"os_type"`
		Status   string     `json:"status"`
		LastSeen *time.Time `json:"last_seen"`
	}
	items := make([]item, 0, len(agents))
	statusCounts := make(map[string]int)
	for _, a := range agents {
		items = append(items, item{
			ID: a.ID, Hostname: a.Hostname, OSType: a.OSType,
			Status: a.Status, LastSeen: a.LastSeen,
		})
		statusCounts[a.Status]++
	}
	return map[string]interface{}{"total": total, "status_counts": statusCounts, "agents": items}, nil
}

func (h *ReportHandler) buildThreatReport(ctx context.Context, from, to time.Time) (interface{}, error) {
	alerts, total, err := h.Store.ListAlerts(ctx, store.AlertFilter{
		Status:   "open",
		Severity: 7,
		FromTime: &from,
		ToTime:   &to,
		Limit:    100,
		Offset:   0,
	})
	if err != nil {
		return nil, err
	}

	type threat struct {
		ID           string    `json:"id"`
		Title        string    `json:"title"`
		Severity     int       `json:"severity"`
		AgentID      string    `json:"agent_id"`
		Hostname     string    `json:"hostname"`
		MITRETech    *string   `json:"mitre_technique,omitempty"`
		AIThreatName *string   `json:"ai_threat_name,omitempty"`
		Created      time.Time `json:"created_at"`
	}
	items := make([]threat, 0, len(alerts))
	for _, a := range alerts {
		items = append(items, threat{
			ID: a.ID, Title: a.Title, Severity: a.Severity,
			AgentID: a.AgentID, Hostname: a.Hostname,
			MITRETech: a.MITRETech, AIThreatName: a.AIThreatName,
			Created: a.CreatedAt,
		})
	}
	return map[string]interface{}{"total": total, "threats": items}, nil
}
