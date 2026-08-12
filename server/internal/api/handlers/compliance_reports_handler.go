package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

type ComplianceReportHandler struct {
	pool *pgxpool.Pool
}

func NewComplianceReportHandler(pool *pgxpool.Pool) *ComplianceReportHandler {
	return &ComplianceReportHandler{pool: pool}
}

type ComplianceFrameworkInfo struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	Version     string `json:"version"`
	Description string `json:"description"`
}

type ComplianceControlInfo struct {
	ID          string `json:"id"`
	FrameworkID string `json:"framework_id"`
	ControlID   string `json:"control_id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Category    string `json:"category"`
	Severity    string `json:"severity"`
	PassCount   int    `json:"pass_count"`
	FailCount   int    `json:"fail_count"`
	Status      string `json:"status"` // pass | fail | partial | not_evaluated
}

type ComplianceScore struct {
	FrameworkID    string                  `json:"framework_id"`
	FrameworkName  string                  `json:"framework_name"`
	Score          float64                 `json:"score"`
	TotalControls  int                     `json:"total_controls"`
	PassedControls int                     `json:"passed_controls"`
	FailedControls int                     `json:"failed_controls"`
	Controls       []ComplianceControlInfo `json:"controls"`
	GeneratedAt    time.Time               `json:"generated_at"`
}

// GET /api/v1/compliance/frameworks
func (h *ComplianceReportHandler) ListFrameworks(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, name, version, COALESCE(description,'') FROM compliance_frameworks ORDER BY name`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()
	var frameworks []ComplianceFrameworkInfo
	for rows.Next() {
		var f ComplianceFrameworkInfo
		if err := rows.Scan(&f.ID, &f.Name, &f.Version, &f.Description); err != nil {
			slog.Warn("compliance: frameworks scan error", "error", err)
			continue
		}
		frameworks = append(frameworks, f)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if frameworks == nil {
		frameworks = []ComplianceFrameworkInfo{}
	}
	c.JSON(http.StatusOK, frameworks)
}

// GET /api/v1/compliance/score/:framework_id
func (h *ComplianceReportHandler) GetScore(c *gin.Context) {
	frameworkID := c.Param("framework_id")

	var fw ComplianceFrameworkInfo
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT id, name, version, COALESCE(description,'') FROM compliance_frameworks WHERE id=$1`,
		frameworkID,
	).Scan(&fw.ID, &fw.Name, &fw.Version, &fw.Description)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "framework not found"})
		return
	}

	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT cc.id, cc.control_id, cc.title, COALESCE(cc.description,''), cc.category, cc.severity,
		        COUNT(CASE WHEN ce.status='pass' THEN 1 END) as pass_count,
		        COUNT(CASE WHEN ce.status='fail' THEN 1 END) as fail_count
		 FROM compliance_controls cc
		 LEFT JOIN compliance_evidence ce ON ce.control_id = cc.id
		   AND ce.collected_at > NOW() - INTERVAL '30 days'
		 WHERE cc.framework_id=$1
		 GROUP BY cc.id, cc.control_id, cc.title, cc.description, cc.category, cc.severity
		 ORDER BY cc.control_id`,
		frameworkID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	var controls []ComplianceControlInfo
	for rows.Next() {
		var ctrl ComplianceControlInfo
		ctrl.FrameworkID = frameworkID
		if err := rows.Scan(&ctrl.ID, &ctrl.ControlID, &ctrl.Title, &ctrl.Description,
			&ctrl.Category, &ctrl.Severity, &ctrl.PassCount, &ctrl.FailCount); err != nil {
			slog.Warn("compliance: controls scan error", "error", err)
			continue
		}
		if ctrl.PassCount == 0 && ctrl.FailCount == 0 {
			ctrl.Status = "not_evaluated"
		} else if ctrl.FailCount == 0 {
			ctrl.Status = "pass"
		} else if ctrl.PassCount == 0 {
			ctrl.Status = "fail"
		} else {
			ctrl.Status = "partial"
		}
		controls = append(controls, ctrl)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if controls == nil {
		controls = []ComplianceControlInfo{}
	}

	passed := 0
	failed := 0
	for _, ctrl := range controls {
		if ctrl.Status == "pass" {
			passed++
		} else if ctrl.Status == "fail" {
			failed++
		}
	}
	total := len(controls)
	score := 0.0
	if total > 0 {
		score = float64(passed) / float64(total) * 100
	}

	c.JSON(http.StatusOK, ComplianceScore{
		FrameworkID:    fw.ID,
		FrameworkName:  fw.Name,
		Score:          score,
		TotalControls:  total,
		PassedControls: passed,
		FailedControls: failed,
		Controls:       controls,
		GeneratedAt:    time.Now(),
	})
}

// POST /api/v1/compliance/evidence
func (h *ComplianceReportHandler) AddEvidence(c *gin.Context) {
	var req struct {
		ControlID    string `json:"control_id" binding:"required"`
		AgentID      string `json:"agent_id"`
		EventID      string `json:"event_id"`
		AlertID      string `json:"alert_id"`
		EvidenceType string `json:"evidence_type" binding:"required"`
		Summary      string `json:"summary" binding:"required"`
		Status       string `json:"status" binding:"required"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var agentID, eventID, alertID interface{}
	if req.AgentID != "" {
		agentID = req.AgentID
	}
	if req.EventID != "" {
		eventID = req.EventID
	}
	if req.AlertID != "" {
		alertID = req.AlertID
	}

	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO compliance_evidence
		 (control_id, agent_id, event_id, alert_id, evidence_type, summary, status)
		 VALUES ($1,$2,$3,$4,$5,$6,$7) RETURNING id`,
		req.ControlID, agentID, eventID, alertID, req.EvidenceType, req.Summary, req.Status,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("insert failed: %v", err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}

// GET /api/v1/compliance/evidence/:control_id
func (h *ComplianceReportHandler) GetEvidence(c *gin.Context) {
	controlID := c.Param("control_id")
	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, control_id, agent_id, event_id, alert_id, evidence_type, summary, status, collected_at
		 FROM compliance_evidence WHERE control_id=$1
		 ORDER BY collected_at DESC LIMIT 50`,
		controlID,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "query failed"})
		return
	}
	defer rows.Close()

	type Evidence struct {
		ID           string    `json:"id"`
		ControlID    string    `json:"control_id"`
		AgentID      *string   `json:"agent_id"`
		EventID      *string   `json:"event_id"`
		AlertID      *string   `json:"alert_id"`
		EvidenceType string    `json:"evidence_type"`
		Summary      string    `json:"summary"`
		Status       string    `json:"status"`
		CollectedAt  time.Time `json:"collected_at"`
	}
	var evidence []Evidence
	for rows.Next() {
		var e Evidence
		if err := rows.Scan(&e.ID, &e.ControlID, &e.AgentID, &e.EventID, &e.AlertID,
			&e.EvidenceType, &e.Summary, &e.Status, &e.CollectedAt); err != nil {
			slog.Warn("compliance: evidence scan error", "error", err)
			continue
		}
		evidence = append(evidence, e)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if evidence == nil {
		evidence = []Evidence{}
	}
	c.JSON(http.StatusOK, evidence)
}
