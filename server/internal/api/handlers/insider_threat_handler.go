package handlers

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// InsiderThreatHandler serves insider threat data.
// GET  /api/v1/insider-threat/users
// GET  /api/v1/insider-threat/events
// GET  /api/v1/insider-threat/investigations
// POST /api/v1/insider-threat/investigations
// GET  /api/v1/insider-threats/stats  (summary stats, plural path)
type InsiderThreatHandler struct {
	pool *pgxpool.Pool
}

func NewInsiderThreatHandler(pool *pgxpool.Pool) *InsiderThreatHandler {
	return &InsiderThreatHandler{pool: pool}
}

func (h *InsiderThreatHandler) tableExists(ctx *gin.Context, name string) bool {
	var ok bool
	_ = h.pool.QueryRow(ctx.Request.Context(),
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=$1)`, name).Scan(&ok)
	return ok
}

// ── Types ─────────────────────────────────────────────────────────────────────

type itRiskUser struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Email            string   `json:"email"`
	Department       string   `json:"department"`
	Title            string   `json:"title"`
	RiskScore        float64  `json:"risk_score"`
	RiskIndicators   []string `json:"risk_indicators"`
	AnomalyCountWeek int      `json:"anomaly_count_week"`
	LastAnomaly      string   `json:"last_anomaly"`
	Watchlist        bool     `json:"watchlist"`
	Trend            string   `json:"trend"`
}

type itBehaviorEvent struct {
	ID          string `json:"id"`
	UserID      string `json:"user_id"`
	UserName    string `json:"user_name"`
	Department  string `json:"department"`
	EventType   string `json:"event_type"`
	Timestamp   string `json:"timestamp"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Details     string `json:"details"`
}

type itInvestigation struct {
	ID             string          `json:"id"`
	CaseID         string          `json:"case_id"`
	SubjectUser    string          `json:"subject_user"`
	Department     string          `json:"department"`
	Investigator   string          `json:"investigator"`
	OpenedDate     string          `json:"opened_date"`
	ClosedDate     *string         `json:"closed_date"`
	Status         string          `json:"status"`
	RiskLevel      string          `json:"risk_level"`
	Notes          string          `json:"notes"`
	RiskIndicators json.RawMessage `json:"risk_indicators"`
	Outcome        *string         `json:"outcome"`
	Priority       string          `json:"priority"`
}

// ── Handlers ──────────────────────────────────────────────────────────────────

// ListUsers derives risk users from UEBA anomalies + users table.
// GET /api/v1/insider-threat/users
func (h *InsiderThreatHandler) ListUsers(c *gin.Context) {
	ctx := c.Request.Context()

	// Derive users with risk scores from ueba_anomalies
	rows, err := h.pool.Query(ctx, `
		SELECT
			COALESCE(u.id::text, ua.username) AS id,
			ua.username AS name,
			COALESCE(u.email, '') AS email,
			'Unknown' AS department,
			COALESCE(u.role, 'user') AS title,
			LEAST(COALESCE(SUM(ua.score), 0), 100) AS risk_score,
			COUNT(*) FILTER (WHERE ua.created_at >= NOW() - INTERVAL '7 days') AS anomaly_count_week,
			MAX(ua.created_at) AS last_anomaly
		FROM ueba_anomalies ua
		LEFT JOIN users u ON u.email = ua.username
		WHERE ua.status != 'false_positive'
		GROUP BY ua.username, u.id, u.email, u.role
		ORDER BY risk_score DESC
		LIMIT 100
	`)
	if err != nil {
		c.JSON(http.StatusOK, []itRiskUser{})
		return
	}
	defer rows.Close()

	var users []itRiskUser
	for rows.Next() {
		var u itRiskUser
		var lastAnomaly time.Time
		if err := rows.Scan(
			&u.ID, &u.Name, &u.Email, &u.Department, &u.Title,
			&u.RiskScore, &u.AnomalyCountWeek, &lastAnomaly,
		); err != nil {
			continue
		}
		u.LastAnomaly = lastAnomaly.Format(time.RFC3339)
		u.RiskIndicators = []string{}
		u.Trend = "stable"
		users = append(users, u)
	}
	if users == nil {
		users = []itRiskUser{}
	}
	c.JSON(http.StatusOK, users)
}

// ListEvents returns insider threat behavior events.
// GET /api/v1/insider-threat/events
func (h *InsiderThreatHandler) ListEvents(c *gin.Context) {
	ctx := c.Request.Context()

	if !h.tableExists(c, "insider_threat_events") {
		// Derive from ueba_anomalies
		rows, err := h.pool.Query(ctx, `
			SELECT id::text, COALESCE(username,''), anomaly_type, created_at, score, description
			FROM ueba_anomalies
			WHERE status != 'false_positive'
			ORDER BY created_at DESC LIMIT 100
		`)
		if err != nil {
			c.JSON(http.StatusOK, []itBehaviorEvent{})
			return
		}
		defer rows.Close()
		var events []itBehaviorEvent
		for rows.Next() {
			var e itBehaviorEvent
			var ts time.Time
			var score float64
			if rows.Scan(&e.ID, &e.UserName, &e.EventType, &ts, &score, &e.Description) != nil {
				continue
			}
			e.UserID = e.UserName
			e.Timestamp = ts.Format(time.RFC3339)
			switch {
			case score >= 80:
				e.Severity = "critical"
			case score >= 60:
				e.Severity = "high"
			case score >= 40:
				e.Severity = "medium"
			default:
				e.Severity = "low"
			}
			e.Details = e.Description
			events = append(events, e)
		}
		if events == nil {
			events = []itBehaviorEvent{}
		}
		c.JSON(http.StatusOK, events)
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, user_id, user_name, department, event_type, timestamp, severity, description, details
		FROM insider_threat_events ORDER BY timestamp DESC LIMIT 200
	`)
	if err != nil {
		c.JSON(http.StatusOK, []itBehaviorEvent{})
		return
	}
	defer rows.Close()
	var events []itBehaviorEvent
	for rows.Next() {
		var e itBehaviorEvent
		var ts time.Time
		if rows.Scan(&e.ID, &e.UserID, &e.UserName, &e.Department, &e.EventType,
			&ts, &e.Severity, &e.Description, &e.Details) != nil {
			continue
		}
		e.Timestamp = ts.Format(time.RFC3339)
		events = append(events, e)
	}
	if events == nil {
		events = []itBehaviorEvent{}
	}
	c.JSON(http.StatusOK, events)
}

// ListInvestigations returns insider threat investigations.
// GET /api/v1/insider-threat/investigations
func (h *InsiderThreatHandler) ListInvestigations(c *gin.Context) {
	ctx := c.Request.Context()

	if !h.tableExists(c, "insider_threat_investigations") {
		c.JSON(http.StatusOK, []itInvestigation{})
		return
	}

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, case_id, subject_user, department, investigator,
		       opened_date, closed_date, status, risk_level, notes,
		       risk_indicators, outcome, priority
		FROM insider_threat_investigations ORDER BY created_at DESC
	`)
	if err != nil {
		c.JSON(http.StatusOK, []itInvestigation{})
		return
	}
	defer rows.Close()

	var list []itInvestigation
	for rows.Next() {
		var inv itInvestigation
		var openedDate time.Time
		var closedDate *time.Time
		if rows.Scan(
			&inv.ID, &inv.CaseID, &inv.SubjectUser, &inv.Department, &inv.Investigator,
			&openedDate, &closedDate, &inv.Status, &inv.RiskLevel, &inv.Notes,
			&inv.RiskIndicators, &inv.Outcome, &inv.Priority,
		) != nil {
			continue
		}
		inv.OpenedDate = openedDate.Format("2006-01-02")
		if closedDate != nil {
			s := closedDate.Format("2006-01-02")
			inv.ClosedDate = &s
		}
		if inv.RiskIndicators == nil {
			inv.RiskIndicators = json.RawMessage(`[]`)
		}
		list = append(list, inv)
	}
	if list == nil {
		list = []itInvestigation{}
	}
	c.JSON(http.StatusOK, list)
}

// CreateInvestigation creates a new investigation case.
// POST /api/v1/insider-threat/investigations
func (h *InsiderThreatHandler) CreateInvestigation(c *gin.Context) {
	if !h.tableExists(c, "insider_threat_investigations") {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Insider threat tables not available"})
		return
	}
	var body struct {
		SubjectUser  string   `json:"subject_user" binding:"required"`
		Department   string   `json:"department"`
		Investigator string   `json:"investigator"`
		RiskLevel    string   `json:"risk_level"`
		Notes        string   `json:"notes"`
		Indicators   []string `json:"risk_indicators"`
		Priority     string   `json:"priority"`
	}
	if err := c.ShouldBindJSON(&body); err != nil || body.SubjectUser == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "subject_user is required"})
		return
	}
	if body.RiskLevel == "" {
		body.RiskLevel = "medium"
	}
	if body.Priority == "" {
		body.Priority = "medium"
	}
	if body.Indicators == nil {
		body.Indicators = []string{}
	}
	indicatorsJSON, _ := json.Marshal(body.Indicators)
	caseID := "INV-" + time.Now().Format("2006-01") + "-" + generateShortID()

	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx, `
		INSERT INTO insider_threat_investigations
		(case_id, subject_user, department, investigator, risk_level, notes, risk_indicators, priority)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		caseID, body.SubjectUser, body.Department, body.Investigator,
		body.RiskLevel, body.Notes, indicatorsJSON, body.Priority,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create investigation"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "case_id": caseID, "message": "Investigation created"})
}

// GetStats returns aggregate insider threat statistics.
// GET /api/v1/insider-threats/stats
func (h *InsiderThreatHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()
	stats := gin.H{
		"high_risk_users":     0,
		"total_alerts":        0,
		"open_cases":          0,
		"data_exfil_attempts": 0,
		"avg_risk_score":      0.0,
		"watchlist_count":     0,
	}

	// high risk users (risk score >= 70) from ueba_anomalies
	var highRisk int
	_ = h.pool.QueryRow(ctx, `
		SELECT COUNT(DISTINCT username) FROM ueba_anomalies
		WHERE status != 'false_positive' AND created_at >= NOW() - INTERVAL '30 days'
		GROUP BY username HAVING LEAST(SUM(score), 100) >= 70
	`).Scan(&highRisk)
	stats["high_risk_users"] = highRisk

	// total insider-threat-related alerts
	var totalAlerts int
	_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts WHERE source='insider_threat_detector'`).Scan(&totalAlerts)
	stats["total_alerts"] = totalAlerts

	// open cases
	if h.tableExists(c, "insider_threat_investigations") {
		var openCases int
		_ = h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM insider_threat_investigations WHERE status IN ('open','in_progress')`).Scan(&openCases)
		stats["open_cases"] = openCases
	}

	c.JSON(http.StatusOK, stats)
}

// ListIndicators returns BehaviorIndicator items for the admin/insider-threat page.
// Derives from ueba_anomalies, mapping anomaly_type → ThreatCategory.
// GET /api/v1/insider-threat/indicators
func (h *InsiderThreatHandler) ListIndicators(c *gin.Context) {
	ctx := c.Request.Context()

	type BehaviorIndicator struct {
		ID          string `json:"id"`
		User        string `json:"user"`
		Type        string `json:"type"`
		Description string `json:"description"`
		Severity    string `json:"severity"`
		Timestamp   string `json:"timestamp"`
	}

	// Map UEBA anomaly_type to ThreatCategory
	mapType := func(t string) string {
		switch {
		case itContains(t, "exfil", "upload", "send"):
			return "data_exfil"
		case itContains(t, "download", "mass"):
			return "mass_download"
		case itContains(t, "privilege", "escalat", "admin", "sudo"):
			return "privilege_abuse"
		case itContains(t, "lateral", "movement", "pivot"):
			return "lateral_movement"
		case itContains(t, "hour", "after", "night", "weekend", "login"):
			return "unusual_hours"
		default:
			return "policy_violation"
		}
	}

	rows, err := h.pool.Query(ctx, `
		SELECT id::text, COALESCE(username,'不明'), anomaly_type, description, score, created_at
		FROM ueba_anomalies
		WHERE status != 'false_positive'
		ORDER BY created_at DESC LIMIT 50
	`)
	if err != nil {
		c.JSON(http.StatusOK, []BehaviorIndicator{})
		return
	}
	defer rows.Close()

	var indicators []BehaviorIndicator
	for rows.Next() {
		var ind BehaviorIndicator
		var score float64
		var ts time.Time
		var anomalyType string
		if rows.Scan(&ind.ID, &ind.User, &anomalyType, &ind.Description, &score, &ts) != nil {
			continue
		}
		ind.Type = mapType(anomalyType)
		ind.Timestamp = ts.Format(time.RFC3339)
		switch {
		case score >= 80:
			ind.Severity = "critical"
		case score >= 60:
			ind.Severity = "high"
		case score >= 40:
			ind.Severity = "medium"
		default:
			ind.Severity = "low"
		}
		indicators = append(indicators, ind)
	}
	if indicators == nil {
		indicators = []BehaviorIndicator{}
	}
	c.JSON(http.StatusOK, indicators)
}

// itContains checks if s contains any of the substrs (case-insensitive).
func itContains(s string, substrs ...string) bool {
	sl := strings.ToLower(s)
	for _, sub := range substrs {
		if strings.Contains(sl, sub) {
			return true
		}
	}
	return false
}
