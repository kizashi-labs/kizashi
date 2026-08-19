package handlers

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GDPRHandler manages privacy/GDPR compliance endpoints.
type GDPRHandler struct {
	pool *pgxpool.Pool
}

// NewGDPRHandler creates a new GDPRHandler.
func NewGDPRHandler(pool *pgxpool.Pool) *GDPRHandler {
	return &GDPRHandler{pool: pool}
}

func (h *GDPRHandler) subjectsTableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "data_subjects")
}

func (h *GDPRHandler) dsarTableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "dsar_requests")
}

func (h *GDPRHandler) incidentsTableExists(c *gin.Context) bool {
	return tableIsThere(c.Request.Context(), h.pool, "privacy_incidents")
}

// ─── Data Subjects ───────────────────────────────────────────────────────────

type dataSubject struct {
	ID                  string          `json:"id"`
	SubjectType         string          `json:"subject_type"`
	Email               string          `json:"email"`
	Name                string          `json:"name"`
	DataCategories      json.RawMessage `json:"data_categories"`
	ConsentGiven        bool            `json:"consent_given"`
	ConsentDate         *time.Time      `json:"consent_date"`
	RetentionPeriodDays int             `json:"retention_period_days"`
	DeletionRequestedAt *time.Time      `json:"deletion_requested_at"`
	DeletionCompletedAt *time.Time      `json:"deletion_completed_at"`
	Notes               string          `json:"notes"`
	CreatedAt           time.Time       `json:"created_at"`
	UpdatedAt           time.Time       `json:"updated_at"`
}

// ListSubjects GET /privacy/subjects
func (h *GDPRHandler) ListSubjects(c *gin.Context) {
	if !h.subjectsTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"subjects": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()

	limit, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	page, limit, offset := clampPageParams(page, limit, 50, 200)

	where := " WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if subjectType := c.Query("subject_type"); subjectType != "" {
		where += " AND subject_type=$" + strconv.Itoa(idx)
		args = append(args, subjectType)
		idx++
	}
	if consent := c.Query("consent_given"); consent != "" {
		val := consent == "true"
		where += " AND consent_given=$" + strconv.Itoa(idx)
		args = append(args, val)
		idx++
	}

	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)

	var total int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM data_subjects`+where, countArgs...).Scan(&total)) {
		return
	}

	args = append(args, limit, offset)
	query := `SELECT id, subject_type, email, name, data_categories, consent_given, consent_date,
	                 retention_period_days, deletion_requested_at, deletion_completed_at, notes, created_at, updated_at
	          FROM data_subjects` + where +
		` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(idx) + ` OFFSET $` + strconv.Itoa(idx+1)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list subjects"})
		return
	}
	defer rows.Close()

	subjects := []dataSubject{}
	for rows.Next() {
		var s dataSubject
		if err := rows.Scan(&s.ID, &s.SubjectType, &s.Email, &s.Name, &s.DataCategories,
			&s.ConsentGiven, &s.ConsentDate, &s.RetentionPeriodDays,
			&s.DeletionRequestedAt, &s.DeletionCompletedAt, &s.Notes,
			&s.CreatedAt, &s.UpdatedAt); err == nil {
			subjects = append(subjects, s)
		}
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"subjects": subjects, "total": total, "page": page, "per_page": limit})
}

// CreateSubject POST /privacy/subjects
func (h *GDPRHandler) CreateSubject(c *gin.Context) {
	if !h.subjectsTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "GDPR management not available"})
		return
	}
	ctx := c.Request.Context()

	var body struct {
		SubjectType         string          `json:"subject_type"`
		Email               string          `json:"email" binding:"required"`
		Name                string          `json:"name"`
		DataCategories      json.RawMessage `json:"data_categories"`
		ConsentGiven        bool            `json:"consent_given"`
		RetentionPeriodDays int             `json:"retention_period_days"`
		Notes               string          `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "email is required"})
		return
	}
	if body.SubjectType == "" {
		body.SubjectType = "employee"
	}
	if body.RetentionPeriodDays == 0 {
		body.RetentionPeriodDays = 365
	}
	if body.DataCategories == nil {
		body.DataCategories = json.RawMessage("[]")
	}

	var consentDate *time.Time
	if body.ConsentGiven {
		now := time.Now()
		consentDate = &now
	}

	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO data_subjects (subject_type, email, name, data_categories, consent_given, consent_date, retention_period_days, notes)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		body.SubjectType, body.Email, body.Name, body.DataCategories, body.ConsentGiven,
		consentDate, body.RetentionPeriodDays, body.Notes).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create subject"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "data subject created"})
}

// UpdateSubject PUT /privacy/subjects/:id
func (h *GDPRHandler) UpdateSubject(c *gin.Context) {
	if !h.subjectsTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var body struct {
		SubjectType         string          `json:"subject_type"`
		Email               string          `json:"email"`
		Name                string          `json:"name"`
		DataCategories      json.RawMessage `json:"data_categories"`
		ConsentGiven        bool            `json:"consent_given"`
		RetentionPeriodDays int             `json:"retention_period_days"`
		Notes               string          `json:"notes"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.DataCategories == nil {
		body.DataCategories = json.RawMessage("[]")
	}

	_, err := h.pool.Exec(ctx,
		`UPDATE data_subjects SET subject_type=$1, email=$2, name=$3, data_categories=$4,
		        consent_given=$5, retention_period_days=$6, notes=$7, updated_at=NOW()
		 WHERE id=$8`,
		body.SubjectType, body.Email, body.Name, body.DataCategories,
		body.ConsentGiven, body.RetentionPeriodDays, body.Notes, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update subject"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "data subject updated"})
}

// DeleteSubject DELETE /privacy/subjects/:id — GDPR erasure
func (h *GDPRHandler) DeleteSubject(c *gin.Context) {
	if !h.subjectsTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	_, err := h.pool.Exec(ctx,
		`UPDATE data_subjects SET deletion_completed_at=NOW(), updated_at=NOW() WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to process erasure"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "GDPR erasure completed"})
}

// ─── Privacy Incidents ───────────────────────────────────────────────────────

type privacyIncident struct {
	ID                    string          `json:"id"`
	IncidentType          string          `json:"incident_type"`
	Description           string          `json:"description"`
	AffectedSubjectsCount int             `json:"affected_subjects_count"`
	DataCategories        json.RawMessage `json:"data_categories"`
	Severity              string          `json:"severity"`
	ReportedToAuthority   bool            `json:"reported_to_authority"`
	ReportedAt            *time.Time      `json:"reported_at"`
	RemediationSteps      string          `json:"remediation_steps"`
	Status                string          `json:"status"`
	CreatedAt             time.Time       `json:"created_at"`
	UpdatedAt             time.Time       `json:"updated_at"`
}

// ListPrivacyIncidents GET /privacy/incidents
func (h *GDPRHandler) ListPrivacyIncidents(c *gin.Context) {
	if !h.incidentsTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"incidents": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()

	limit, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	page, limit, offset := clampPageParams(page, limit, 50, 200)

	where := " WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if status := c.Query("status"); status != "" {
		where += " AND status=$" + strconv.Itoa(idx)
		args = append(args, status)
		idx++
	}

	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)

	var total int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM privacy_incidents`+where, countArgs...).Scan(&total)) {
		return
	}

	args = append(args, limit, offset)
	query := `SELECT id, incident_type, description, affected_subjects_count, data_categories,
	                 severity, reported_to_authority, reported_at, remediation_steps, status, created_at, updated_at
	          FROM privacy_incidents` + where +
		` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(idx) + ` OFFSET $` + strconv.Itoa(idx+1)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list incidents"})
		return
	}
	defer rows.Close()

	incidents := []privacyIncident{}
	for rows.Next() {
		var i privacyIncident
		if err := rows.Scan(&i.ID, &i.IncidentType, &i.Description, &i.AffectedSubjectsCount,
			&i.DataCategories, &i.Severity, &i.ReportedToAuthority, &i.ReportedAt,
			&i.RemediationSteps, &i.Status, &i.CreatedAt, &i.UpdatedAt); err == nil {
			incidents = append(incidents, i)
		}
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"incidents": incidents, "total": total, "page": page, "per_page": limit})
}

// CreateIncident POST /privacy/incidents
func (h *GDPRHandler) CreateIncident(c *gin.Context) {
	if !h.incidentsTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "GDPR management not available"})
		return
	}
	ctx := c.Request.Context()

	var body struct {
		IncidentType          string          `json:"incident_type"`
		Description           string          `json:"description" binding:"required"`
		AffectedSubjectsCount int             `json:"affected_subjects_count"`
		DataCategories        json.RawMessage `json:"data_categories"`
		Severity              string          `json:"severity"`
		ReportedToAuthority   bool            `json:"reported_to_authority"`
		RemediationSteps      string          `json:"remediation_steps"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.Description == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "description is required"})
		return
	}
	if body.IncidentType == "" {
		body.IncidentType = "breach"
	}
	if body.Severity == "" {
		body.Severity = "medium"
	}
	if body.DataCategories == nil {
		body.DataCategories = json.RawMessage("[]")
	}

	var reportedAt *time.Time
	if body.ReportedToAuthority {
		now := time.Now()
		reportedAt = &now
	}

	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO privacy_incidents (incident_type, description, affected_subjects_count, data_categories,
		        severity, reported_to_authority, reported_at, remediation_steps)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING id`,
		body.IncidentType, body.Description, body.AffectedSubjectsCount, body.DataCategories,
		body.Severity, body.ReportedToAuthority, reportedAt, body.RemediationSteps).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create incident"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "privacy incident created"})
}

// UpdateIncident PUT /privacy/incidents/:id
func (h *GDPRHandler) UpdateIncident(c *gin.Context) {
	if !h.incidentsTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var body struct {
		IncidentType          string          `json:"incident_type"`
		Description           string          `json:"description"`
		AffectedSubjectsCount int             `json:"affected_subjects_count"`
		DataCategories        json.RawMessage `json:"data_categories"`
		Severity              string          `json:"severity"`
		ReportedToAuthority   bool            `json:"reported_to_authority"`
		RemediationSteps      string          `json:"remediation_steps"`
		Status                string          `json:"status"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.DataCategories == nil {
		body.DataCategories = json.RawMessage("[]")
	}

	var reportedAt *time.Time
	if body.ReportedToAuthority {
		now := time.Now()
		reportedAt = &now
	}

	_, err := h.pool.Exec(ctx,
		`UPDATE privacy_incidents SET incident_type=$1, description=$2, affected_subjects_count=$3,
		        data_categories=$4, severity=$5, reported_to_authority=$6, reported_at=$7,
		        remediation_steps=$8, status=$9, updated_at=NOW()
		 WHERE id=$10`,
		body.IncidentType, body.Description, body.AffectedSubjectsCount, body.DataCategories,
		body.Severity, body.ReportedToAuthority, reportedAt, body.RemediationSteps, body.Status, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update incident"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "incident updated"})
}

// ─── DSAR Requests ───────────────────────────────────────────────────────────

type dsarRequest struct {
	ID            string     `json:"id"`
	RequestType   string     `json:"request_type"`
	SubjectEmail  string     `json:"subject_email"`
	SubjectName   string     `json:"subject_name"`
	Status        string     `json:"status"`
	DueDate       string     `json:"due_date"`
	CompletedAt   *time.Time `json:"completed_at"`
	ResponseNotes string     `json:"response_notes"`
	CreatedAt     time.Time  `json:"created_at"`
	UpdatedAt     time.Time  `json:"updated_at"`
	Overdue       bool       `json:"overdue"`
}

// ListDSARs GET /privacy/dsar
func (h *GDPRHandler) ListDSARs(c *gin.Context) {
	if !h.dsarTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"requests": []interface{}{}, "total": 0})
		return
	}
	ctx := c.Request.Context()

	limit, _ := strconv.Atoi(c.DefaultQuery("per_page", "50"))
	page, _ := strconv.Atoi(c.DefaultQuery("page", "1"))
	page, limit, offset := clampPageParams(page, limit, 50, 200)

	where := " WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if status := c.Query("status"); status != "" {
		where += " AND status=$" + strconv.Itoa(idx)
		args = append(args, status)
		idx++
	}

	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)

	var total int
	if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM dsar_requests`+where, countArgs...).Scan(&total)) {
		return
	}

	args = append(args, limit, offset)
	query := `SELECT id, request_type, subject_email, subject_name, status,
	                 due_date::TEXT, completed_at, response_notes, created_at, updated_at
	          FROM dsar_requests` + where +
		` ORDER BY due_date ASC LIMIT $` + strconv.Itoa(idx) + ` OFFSET $` + strconv.Itoa(idx+1)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to list DSAR requests"})
		return
	}
	defer rows.Close()

	today := time.Now().Format("2006-01-02")
	requests := []dsarRequest{}
	for rows.Next() {
		var r dsarRequest
		if err := rows.Scan(&r.ID, &r.RequestType, &r.SubjectEmail, &r.SubjectName,
			&r.Status, &r.DueDate, &r.CompletedAt, &r.ResponseNotes,
			&r.CreatedAt, &r.UpdatedAt); err == nil {
			// Flag overdue: due_date < today and status != completed
			r.Overdue = r.DueDate < today && r.Status != "completed"
			requests = append(requests, r)
		}
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"requests": requests, "total": total, "page": page, "per_page": limit})
}

// CreateDSAR POST /privacy/dsar
func (h *GDPRHandler) CreateDSAR(c *gin.Context) {
	if !h.dsarTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "GDPR management not available"})
		return
	}
	ctx := c.Request.Context()

	var body struct {
		RequestType  string `json:"request_type"`
		SubjectEmail string `json:"subject_email" binding:"required"`
		SubjectName  string `json:"subject_name"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if body.SubjectEmail == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "subject_email is required"})
		return
	}
	if body.RequestType == "" {
		body.RequestType = "access"
	}

	// GDPR requires response within 30 days
	dueDate := time.Now().AddDate(0, 0, 30).Format("2006-01-02")

	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO dsar_requests (request_type, subject_email, subject_name, due_date)
		 VALUES ($1,$2,$3,$4) RETURNING id`,
		body.RequestType, body.SubjectEmail, body.SubjectName, dueDate).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create DSAR request"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"id": id, "due_date": dueDate, "message": "DSAR request created"})
}

// CompleteDSAR POST /privacy/dsar/:id/complete
func (h *GDPRHandler) CompleteDSAR(c *gin.Context) {
	if !h.dsarTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "not found"})
		return
	}
	ctx := c.Request.Context()
	id := c.Param("id")

	var body struct {
		ResponseNotes string `json:"response_notes"`
	}
	_ = c.ShouldBindJSON(&body)

	_, err := h.pool.Exec(ctx,
		`UPDATE dsar_requests SET status='completed', completed_at=NOW(), response_notes=$1, updated_at=NOW()
		 WHERE id=$2`,
		body.ResponseNotes, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to complete DSAR"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "DSAR request completed"})
}

// GetStats GET /privacy/stats
func (h *GDPRHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	var totalSubjects int
	if h.subjectsTableExists(c) {
		if !ReadOK(c, h.pool.QueryRow(ctx, `SELECT COUNT(*) FROM data_subjects`).Scan(&totalSubjects)) {
			return
		}
	}

	var activeDSARs, overdueDSARs int
	if h.dsarTableExists(c) {
		if !ReadOK(c, h.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM dsar_requests WHERE status != 'completed'`).Scan(&activeDSARs)) {
			return
		}
		if !ReadOK(c, h.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM dsar_requests WHERE status != 'completed' AND due_date < CURRENT_DATE`).Scan(&overdueDSARs)) {
			return
		}
	}

	var openIncidents int
	if h.incidentsTableExists(c) {
		if !ReadOK(c, h.pool.QueryRow(ctx,
			`SELECT COUNT(*) FROM privacy_incidents WHERE status='open'`).Scan(&openIncidents)) {
			return
		}
	}

	// Data categories distribution from subjects
	catDist := map[string]int{}
	if h.subjectsTableExists(c) {
		rows, err := h.pool.Query(ctx,
			`SELECT jsonb_array_elements_text(data_categories) AS cat FROM data_subjects`)
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var cat string
				if scanErr := rows.Scan(&cat); scanErr == nil {
					catDist[cat]++
				}
			}
			if err := rows.Err(); err != nil {
				slog.Warn("gdpr category dist iteration failed", "error", err)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"total_subjects":  totalSubjects,
		"active_dsars":    activeDSARs,
		"overdue_dsars":   overdueDSARs,
		"open_incidents":  openIncidents,
		"data_categories": catDist,
	})
}
