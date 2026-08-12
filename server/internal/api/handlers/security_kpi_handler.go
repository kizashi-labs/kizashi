package handlers

import (
	"log/slog"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SecurityKPIHandler manages security KPI definitions and measurements.
type SecurityKPIHandler struct {
	pool *pgxpool.Pool
}

// NewSecurityKPIHandler creates a new SecurityKPIHandler.
func NewSecurityKPIHandler(pool *pgxpool.Pool) *SecurityKPIHandler {
	return &SecurityKPIHandler{pool: pool}
}

func (h *SecurityKPIHandler) kpiTableExists(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='security_kpi_definitions')`).Scan(&exists)
	return err == nil && exists
}

func (h *SecurityKPIHandler) measurementsTableExists(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='security_kpi_measurements')`).Scan(&exists)
	return err == nil && exists
}

type kpiDefinition struct {
	ID               string   `json:"id"`
	Name             string   `json:"name"`
	Description      *string  `json:"description"`
	Category         string   `json:"category"`
	Unit             string   `json:"unit"`
	TargetValue      float64  `json:"target_value"`
	WarningThreshold *float64 `json:"warning_threshold"`
	Direction        string   `json:"direction"`
	IsActive         bool     `json:"is_active"`
	CreatedAt        string   `json:"created_at"`
	LatestValue      *float64 `json:"latest_value,omitempty"`
	// Computed from the latest measurements so the dashboard can render without a
	// second request. CurrentValue is nil when the KPI has no measurements yet.
	CurrentValue   *float64 `json:"current_value"`
	AchievementPct float64  `json:"achievement_pct"`
	Status         string   `json:"status"` // on_track, warning, off_track, no_data
	Trend          string   `json:"trend"`  // up, down, flat
}

// kpiStatus classifies a KPI against its target/warning thresholds.
func kpiStatus(current, target float64, warning *float64, direction string) string {
	if direction == "higher" {
		switch {
		case current >= target:
			return "on_track"
		case warning != nil && current >= *warning:
			return "warning"
		default:
			return "off_track"
		}
	}
	switch { // lower is better
	case current <= target:
		return "on_track"
	case warning != nil && current <= *warning:
		return "warning"
	default:
		return "off_track"
	}
}

// kpiAchievement returns the percentage of target achieved (0–100).
func kpiAchievement(current, target float64, warning *float64, direction string) float64 {
	clamp := func(p float64) float64 {
		if p < 0 {
			return 0
		}
		if p > 100 {
			return 100
		}
		return math.Round(p)
	}
	if direction == "higher" {
		if target <= 0 {
			if current > 0 {
				return 100
			}
			return 0
		}
		return clamp(current / target * 100)
	}
	// lower is better
	if current <= target {
		return 100
	}
	if warning != nil && *warning > target {
		if current >= *warning {
			return 0
		}
		return math.Round(100 * (*warning - current) / (*warning - target))
	}
	if current > 0 {
		return clamp(target / current * 100)
	}
	return 100
}

// kpiTrend compares the latest value to the previous one.
func kpiTrend(current, previous float64) string {
	switch {
	case current > previous:
		return "up"
	case current < previous:
		return "down"
	default:
		return "flat"
	}
}

type kpiMeasurement struct {
	ID        string  `json:"id"`
	KPIId     string  `json:"kpi_id"`
	Value     float64 `json:"value"`
	Period    string  `json:"period"`
	Notes     *string `json:"notes"`
	CreatedAt string  `json:"created_at"`
}

// ListKPIs returns all KPI definitions with latest measurement joined.
// GET /api/v1/admin/kpi
func (h *SecurityKPIHandler) ListKPIs(c *gin.Context) {
	if !h.kpiTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"kpis": []interface{}{}})
		return
	}
	ctx := c.Request.Context()

	rows, err := h.pool.Query(ctx,
		`SELECT k.id, k.name, k.description, k.category, k.unit,
		        k.target_value, k.warning_threshold, k.direction, k.is_active, k.created_at
		 FROM security_kpi_definitions k
		 ORDER BY k.category, k.name`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list KPIs"})
		return
	}
	defer rows.Close()

	var result []kpiDefinition
	for rows.Next() {
		var k kpiDefinition
		var createdAt time.Time
		if err := rows.Scan(
			&k.ID, &k.Name, &k.Description, &k.Category, &k.Unit,
			&k.TargetValue, &k.WarningThreshold, &k.Direction, &k.IsActive, &createdAt,
		); err != nil {
			continue
		}
		k.CreatedAt = createdAt.Format(time.RFC3339)
		k.Status = "no_data"
		k.Trend = "flat"
		result = append(result, k)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	rows.Close()

	// Enrich each KPI with current value, trend, achievement and status derived
	// from its latest measurements, so the dashboard renders real numbers in one
	// request. A KPI with no measurements stays current_value=null / status=no_data.
	for i := range result {
		mRows, err := h.pool.Query(ctx,
			`SELECT value FROM security_kpi_measurements
			 WHERE kpi_id=$1 ORDER BY period DESC LIMIT 2`, result[i].ID)
		if err != nil {
			continue
		}
		var vals []float64
		for mRows.Next() {
			var v float64
			if err := mRows.Scan(&v); err == nil {
				vals = append(vals, v)
			}
		}
		mRows.Close()
		if len(vals) == 0 {
			continue
		}
		cur := vals[0]
		result[i].CurrentValue = &cur
		result[i].LatestValue = &cur
		if len(vals) >= 2 {
			result[i].Trend = kpiTrend(cur, vals[1])
		}
		result[i].AchievementPct = kpiAchievement(cur, result[i].TargetValue, result[i].WarningThreshold, result[i].Direction)
		result[i].Status = kpiStatus(cur, result[i].TargetValue, result[i].WarningThreshold, result[i].Direction)
	}
	if result == nil {
		result = []kpiDefinition{}
	}
	c.JSON(http.StatusOK, gin.H{"kpis": result})
}

// CreateKPI creates a new KPI definition.
// POST /api/v1/admin/kpi
func (h *SecurityKPIHandler) CreateKPI(c *gin.Context) {
	if !h.kpiTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Table not available"})
		return
	}
	var body struct {
		Name             string   `json:"name" binding:"required"`
		Description      *string  `json:"description"`
		Category         string   `json:"category"`
		Unit             string   `json:"unit"`
		TargetValue      float64  `json:"target_value"`
		WarningThreshold *float64 `json:"warning_threshold"`
		Direction        string   `json:"direction"`
		IsActive         *bool    `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if body.Category == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "category is required"})
		return
	}
	if body.Unit == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unit is required"})
		return
	}
	if body.Direction == "" {
		body.Direction = "higher"
	}
	isActive := true
	if body.IsActive != nil {
		isActive = *body.IsActive
	}
	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO security_kpi_definitions
		 (name, description, category, unit, target_value, warning_threshold, direction, is_active)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		body.Name, body.Description, body.Category, body.Unit,
		body.TargetValue, body.WarningThreshold, body.Direction, isActive,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create KPI"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "KPI created"})
}

// UpdateKPI updates a KPI definition.
// PUT /api/v1/admin/kpi/:id
func (h *SecurityKPIHandler) UpdateKPI(c *gin.Context) {
	if !h.kpiTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	if !isValidUUID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
		return
	}
	var body struct {
		Name             string   `json:"name"`
		Description      *string  `json:"description"`
		Category         string   `json:"category"`
		Unit             string   `json:"unit"`
		TargetValue      float64  `json:"target_value"`
		WarningThreshold *float64 `json:"warning_threshold"`
		Direction        string   `json:"direction"`
		IsActive         *bool    `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE security_kpi_definitions
		 SET name=$1, description=$2, category=$3, unit=$4, target_value=$5,
		     warning_threshold=$6, direction=$7, is_active=$8
		 WHERE id=$9`,
		body.Name, body.Description, body.Category, body.Unit, body.TargetValue,
		body.WarningThreshold, body.Direction, body.IsActive, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update KPI"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "KPI not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "KPI updated"})
}

// DeleteKPI deletes a KPI definition (cascades to measurements).
// DELETE /api/v1/admin/kpi/:id
func (h *SecurityKPIHandler) DeleteKPI(c *gin.Context) {
	if !h.kpiTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	if !isValidUUID(id) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
		return
	}
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx, `DELETE FROM security_kpi_definitions WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete KPI"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "KPI deleted"})
}

// RecordMeasurement inserts a measurement for a KPI period.
// POST /api/v1/admin/kpi/:id/measurements
func (h *SecurityKPIHandler) RecordMeasurement(c *gin.Context) {
	if !h.measurementsTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Table not available"})
		return
	}
	kpiID := c.Param("id")
	if !isValidUUID(kpiID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
		return
	}
	var body struct {
		Value  float64 `json:"value"`
		Period string  `json:"period"` // YYYY-MM-DD
		Notes  *string `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if body.Period == "" {
		body.Period = time.Now().Format("2006-01-02")
	}
	ctx := c.Request.Context()

	// Verify KPI exists
	var kpiName string
	err := h.pool.QueryRow(ctx,
		`SELECT name FROM security_kpi_definitions WHERE id=$1`, kpiID).Scan(&kpiName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "KPI not found"})
		return
	}

	var id string
	err = h.pool.QueryRow(ctx,
		`INSERT INTO security_kpi_measurements (kpi_id, value, period, notes)
		 VALUES ($1,$2,$3,$4) RETURNING id`,
		kpiID, body.Value, body.Period, body.Notes,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to record measurement"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Measurement recorded"})
}

// GetMeasurements returns historical measurements for a KPI.
// GET /api/v1/admin/kpi/:id/measurements?months=6
func (h *SecurityKPIHandler) GetMeasurements(c *gin.Context) {
	if !h.measurementsTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"measurements": []interface{}{}})
		return
	}
	kpiID := c.Param("id")
	if !isValidUUID(kpiID) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid id format"})
		return
	}
	months, _ := strconv.Atoi(c.DefaultQuery("months", "6"))
	if months <= 0 || months > 60 {
		months = 6
	}

	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, kpi_id, value, period, notes, created_at
		 FROM security_kpi_measurements
		 WHERE kpi_id=$1 AND period >= (NOW() - ($2 || ' months')::interval)::date
		 ORDER BY period DESC`,
		kpiID, strconv.Itoa(months))
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list measurements"})
		return
	}
	defer rows.Close()

	var result []kpiMeasurement
	for rows.Next() {
		var m kpiMeasurement
		var period time.Time
		var createdAt time.Time
		if err := rows.Scan(&m.ID, &m.KPIId, &m.Value, &period, &m.Notes, &createdAt); err != nil {
			continue
		}
		m.Period = period.Format("2006-01-02")
		m.CreatedAt = createdAt.Format(time.RFC3339)
		result = append(result, m)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if result == nil {
		result = []kpiMeasurement{}
	}
	c.JSON(http.StatusOK, gin.H{"measurements": result})
}

// GetDashboard returns all KPIs with current value, target, status, and trend.
// GET /api/v1/admin/kpi/dashboard
func (h *SecurityKPIHandler) GetDashboard(c *gin.Context) {
	if !h.kpiTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"kpis": []interface{}{}})
		return
	}
	ctx := c.Request.Context()

	type dashboardKPI struct {
		ID               string    `json:"id"`
		Name             string    `json:"name"`
		Category         string    `json:"category"`
		Unit             string    `json:"unit"`
		TargetValue      float64   `json:"target_value"`
		WarningThreshold *float64  `json:"warning_threshold"`
		Direction        string    `json:"direction"`
		CurrentValue     *float64  `json:"current_value"`
		Status           string    `json:"status"` // on_track, warning, off_track, no_data
		Trend            []float64 `json:"trend"`  // last 3 period values (oldest first)
	}

	rows, err := h.pool.Query(ctx,
		`SELECT id, name, category, unit, target_value, warning_threshold, direction
		 FROM security_kpi_definitions WHERE is_active=true ORDER BY category, name`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to load KPIs"})
		return
	}
	defer rows.Close()

	var kpis []dashboardKPI
	for rows.Next() {
		var k dashboardKPI
		if err := rows.Scan(&k.ID, &k.Name, &k.Category, &k.Unit, &k.TargetValue,
			&k.WarningThreshold, &k.Direction); err != nil {
			continue
		}
		k.Status = "no_data"
		k.Trend = []float64{}
		kpis = append(kpis, k)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	rows.Close()

	// For each KPI, fetch the last 3 measurements to determine current value and trend
	for i := range kpis {
		mRows, err := h.pool.Query(ctx,
			`SELECT value FROM security_kpi_measurements
			 WHERE kpi_id=$1 ORDER BY period DESC LIMIT 3`,
			kpis[i].ID)
		if err != nil {
			continue
		}
		var vals []float64
		for mRows.Next() {
			var v float64
			if err := mRows.Scan(&v); err == nil {
				vals = append(vals, v)
			}
		}
		if err := mRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		mRows.Close()

		if len(vals) == 0 {
			continue
		}

		currentVal := vals[0]
		kpis[i].CurrentValue = &currentVal

		// Reverse to get oldest-first for trend
		for left, right := 0, len(vals)-1; left < right; left, right = left+1, right-1 {
			vals[left], vals[right] = vals[right], vals[left]
		}
		kpis[i].Trend = vals

		// Determine status
		target := kpis[i].TargetValue
		warning := kpis[i].WarningThreshold
		direction := kpis[i].Direction

		if direction == "higher" {
			if currentVal >= target {
				kpis[i].Status = "on_track"
			} else if warning != nil && currentVal >= *warning {
				kpis[i].Status = "warning"
			} else {
				kpis[i].Status = "off_track"
			}
		} else { // lower is better
			if currentVal <= target {
				kpis[i].Status = "on_track"
			} else if warning != nil && currentVal <= *warning {
				kpis[i].Status = "warning"
			} else {
				kpis[i].Status = "off_track"
			}
		}
	}

	if kpis == nil {
		kpis = []dashboardKPI{}
	}
	c.JSON(http.StatusOK, gin.H{"kpis": kpis})
}
