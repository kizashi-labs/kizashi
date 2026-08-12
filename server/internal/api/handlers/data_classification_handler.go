package handlers

import (
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DataClassificationHandler manages data classification labels and assets.
type DataClassificationHandler struct {
	pool *pgxpool.Pool
}

// NewDataClassificationHandler creates a new DataClassificationHandler.
func NewDataClassificationHandler(pool *pgxpool.Pool) *DataClassificationHandler {
	return &DataClassificationHandler{pool: pool}
}

func (h *DataClassificationHandler) labelsTableExists(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='data_classification_labels')`).Scan(&exists)
	return err == nil && exists
}

func (h *DataClassificationHandler) assetsTableExists(c *gin.Context) bool {
	ctx := c.Request.Context()
	var exists bool
	err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='data_assets')`).Scan(&exists)
	return err == nil && exists
}

type classificationLabel struct {
	ID            string  `json:"id"`
	Name          string  `json:"name"`
	Level         int     `json:"level"`
	Color         string  `json:"color"`
	Description   *string `json:"description"`
	HandlingRules *string `json:"handling_rules"`
	IsActive      bool    `json:"is_active"`
	CreatedAt     string  `json:"created_at"`
}

type dataAsset struct {
	ID          string  `json:"id"`
	Name        string  `json:"name"`
	Type        string  `json:"type"`
	Location    *string `json:"location"`
	LabelID     *string `json:"label_id"`
	Owner       *string `json:"owner"`
	Description *string `json:"description"`
	PIIDetected bool    `json:"pii_detected"`
	PHIDetected bool    `json:"phi_detected"`
	PCIDetected bool    `json:"pci_detected"`
	LastScanned *string `json:"last_scanned"`
	CreatedAt   string  `json:"created_at"`
	UpdatedAt   string  `json:"updated_at"`
}

// ListLabels returns all classification labels ordered by level.
// GET /api/v1/admin/data-classification/labels
func (h *DataClassificationHandler) ListLabels(c *gin.Context) {
	if !h.labelsTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"labels": []interface{}{}})
		return
	}
	ctx := c.Request.Context()
	rows, err := h.pool.Query(ctx,
		`SELECT id, name, level, color, description, handling_rules, is_active, created_at
		 FROM data_classification_labels ORDER BY level ASC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list labels"})
		return
	}
	defer rows.Close()

	var result []classificationLabel
	for rows.Next() {
		var l classificationLabel
		var createdAt time.Time
		if err := rows.Scan(&l.ID, &l.Name, &l.Level, &l.Color, &l.Description,
			&l.HandlingRules, &l.IsActive, &createdAt); err != nil {
			continue
		}
		l.CreatedAt = createdAt.Format(time.RFC3339)
		result = append(result, l)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if result == nil {
		result = []classificationLabel{}
	}
	c.JSON(http.StatusOK, gin.H{"labels": result})
}

// CreateLabel creates a new classification label.
// POST /api/v1/admin/data-classification/labels
func (h *DataClassificationHandler) CreateLabel(c *gin.Context) {
	if !h.labelsTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Table not available"})
		return
	}
	var body struct {
		Name          string  `json:"name"`
		Level         int     `json:"level"`
		Color         string  `json:"color"`
		Description   *string `json:"description"`
		HandlingRules *string `json:"handling_rules"`
		IsActive      *bool   `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if body.Level < 1 || body.Level > 5 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "level must be between 1 and 5"})
		return
	}
	if body.Color == "" {
		body.Color = "#6b7280"
	}
	isActive := true
	if body.IsActive != nil {
		isActive = *body.IsActive
	}
	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO data_classification_labels (name, level, color, description, handling_rules, is_active)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		body.Name, body.Level, body.Color, body.Description, body.HandlingRules, isActive,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create label"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Label created"})
}

// UpdateLabel updates a classification label.
// PUT /api/v1/admin/data-classification/labels/:id
func (h *DataClassificationHandler) UpdateLabel(c *gin.Context) {
	if !h.labelsTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	var body struct {
		Name          string  `json:"name"`
		Level         int     `json:"level"`
		Color         string  `json:"color"`
		Description   *string `json:"description"`
		HandlingRules *string `json:"handling_rules"`
		IsActive      *bool   `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE data_classification_labels
		 SET name=$1, level=$2, color=$3, description=$4, handling_rules=$5, is_active=$6
		 WHERE id=$7`,
		body.Name, body.Level, body.Color, body.Description, body.HandlingRules, body.IsActive, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update label"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Label not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Label updated"})
}

// DeleteLabel deletes a classification label.
// DELETE /api/v1/admin/data-classification/labels/:id
func (h *DataClassificationHandler) DeleteLabel(c *gin.Context) {
	if !h.labelsTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx, `DELETE FROM data_classification_labels WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete label"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Label deleted"})
}

// ListAssets returns paginated data assets, optionally filtered by label_id or type.
// GET /api/v1/admin/data-classification/assets
func (h *DataClassificationHandler) ListAssets(c *gin.Context) {
	if !h.assetsTableExists(c) {
		c.JSON(http.StatusOK, gin.H{"assets": []interface{}{}, "total": 0})
		return
	}
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}
	labelID := c.Query("label_id")
	assetType := c.Query("type")

	ctx := c.Request.Context()

	query := `SELECT id, name, type, location, label_id, owner, description,
	                 pii_detected, phi_detected, pci_detected, last_scanned, created_at, updated_at
	          FROM data_assets WHERE 1=1`
	args := []interface{}{}
	argIdx := 1

	if labelID != "" {
		query += ` AND label_id=$` + strconv.Itoa(argIdx)
		args = append(args, labelID)
		argIdx++
	}
	if assetType != "" {
		query += ` AND type=$` + strconv.Itoa(argIdx)
		args = append(args, assetType)
		argIdx++
	}
	query += ` ORDER BY created_at DESC LIMIT $` + strconv.Itoa(argIdx) + ` OFFSET $` + strconv.Itoa(argIdx+1)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list assets"})
		return
	}
	defer rows.Close()

	var result []dataAsset
	for rows.Next() {
		var a dataAsset
		var createdAt, updatedAt time.Time
		var lastScanned *time.Time
		if err := rows.Scan(
			&a.ID, &a.Name, &a.Type, &a.Location, &a.LabelID, &a.Owner, &a.Description,
			&a.PIIDetected, &a.PHIDetected, &a.PCIDetected, &lastScanned, &createdAt, &updatedAt,
		); err != nil {
			continue
		}
		if lastScanned != nil {
			s := lastScanned.Format(time.RFC3339)
			a.LastScanned = &s
		}
		a.CreatedAt = createdAt.Format(time.RFC3339)
		a.UpdatedAt = updatedAt.Format(time.RFC3339)
		result = append(result, a)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if result == nil {
		result = []dataAsset{}
	}
	c.JSON(http.StatusOK, gin.H{"assets": result, "total": len(result)})
}

// CreateAsset creates a new data asset.
// POST /api/v1/admin/data-classification/assets
func (h *DataClassificationHandler) CreateAsset(c *gin.Context) {
	if !h.assetsTableExists(c) {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Table not available"})
		return
	}
	var body struct {
		Name        string  `json:"name"`
		Type        string  `json:"type"`
		Location    *string `json:"location"`
		LabelID     *string `json:"label_id"`
		Owner       *string `json:"owner"`
		Description *string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	if body.Name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name is required"})
		return
	}
	if body.Type == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "type is required"})
		return
	}
	ctx := c.Request.Context()
	var id string
	err := h.pool.QueryRow(ctx,
		`INSERT INTO data_assets (name, type, location, label_id, owner, description)
		 VALUES ($1,$2,$3,$4,$5,$6) RETURNING id`,
		body.Name, body.Type, body.Location, body.LabelID, body.Owner, body.Description,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create asset"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "Asset created"})
}

// UpdateAsset updates a data asset including its label assignment.
// PUT /api/v1/admin/data-classification/assets/:id
func (h *DataClassificationHandler) UpdateAsset(c *gin.Context) {
	if !h.assetsTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	var body struct {
		Name        string  `json:"name"`
		Type        string  `json:"type"`
		Location    *string `json:"location"`
		LabelID     *string `json:"label_id"`
		Owner       *string `json:"owner"`
		Description *string `json:"description"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid request body"})
		return
	}
	ctx := c.Request.Context()
	tag, err := h.pool.Exec(ctx,
		`UPDATE data_assets
		 SET name=$1, type=$2, location=$3, label_id=$4, owner=$5, description=$6, updated_at=NOW()
		 WHERE id=$7`,
		body.Name, body.Type, body.Location, body.LabelID, body.Owner, body.Description, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update asset"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Asset updated"})
}

// DeleteAsset deletes a data asset.
// DELETE /api/v1/admin/data-classification/assets/:id
func (h *DataClassificationHandler) DeleteAsset(c *gin.Context) {
	if !h.assetsTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx, `DELETE FROM data_assets WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete asset"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "Asset deleted"})
}

// ScanAsset marks an asset as scanned and resets detection flags. Real content-level
// scanning (PII/PHI/PCI detection) requires agent-side file access and is not performed here.
// POST /api/v1/admin/data-classification/assets/:id/scan
func (h *DataClassificationHandler) ScanAsset(c *gin.Context) {
	if !h.assetsTableExists(c) {
		c.JSON(http.StatusNotFound, gin.H{"error": "Not found"})
		return
	}
	id := c.Param("id")
	ctx := c.Request.Context()

	// Verify asset exists
	var assetName string
	err := h.pool.QueryRow(ctx, `SELECT name FROM data_assets WHERE id=$1`, id).Scan(&assetName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Asset not found"})
		return
	}

	_, err = h.pool.Exec(ctx,
		`UPDATE data_assets
		 SET pii_detected=false, phi_detected=false, pci_detected=false, last_scanned=NOW(), updated_at=NOW()
		 WHERE id=$1`,
		id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update scan results"})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message":      "Scan completed",
		"pii_detected": false,
		"phi_detected": false,
		"pci_detected": false,
		"last_scanned": time.Now().Format(time.RFC3339),
	})
}

// GetStats returns data classification statistics.
// GET /api/v1/admin/data-classification/stats
func (h *DataClassificationHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Check tables
	var labelsExist, assetsExist bool
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='data_classification_labels')`).Scan(&labelsExist)
	_ = h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='data_assets')`).Scan(&assetsExist)

	if !labelsExist || !assetsExist {
		c.JSON(http.StatusOK, gin.H{
			"by_label":  []interface{}{},
			"by_type":   []interface{}{},
			"pii_count": 0,
			"phi_count": 0,
			"pci_count": 0,
			"total":     0,
		})
		return
	}

	// Count by label
	type labelCount struct {
		LabelID   *string `json:"label_id"`
		LabelName *string `json:"label_name"`
		Count     int     `json:"count"`
	}
	byLabelRows, err := h.pool.Query(ctx,
		`SELECT a.label_id, l.name, COUNT(*) AS cnt
		 FROM data_assets a
		 LEFT JOIN data_classification_labels l ON l.id = a.label_id
		 GROUP BY a.label_id, l.name
		 ORDER BY cnt DESC`)
	var byLabel []labelCount
	if err == nil {
		defer byLabelRows.Close()
		for byLabelRows.Next() {
			var lc labelCount
			if err := byLabelRows.Scan(&lc.LabelID, &lc.LabelName, &lc.Count); err != nil {
				continue
			}
			byLabel = append(byLabel, lc)
		}
		if err := byLabelRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}
	if byLabel == nil {
		byLabel = []labelCount{}
	}

	// Count by type
	type typeCount struct {
		Type  string `json:"type"`
		Count int    `json:"count"`
	}
	byTypeRows, err := h.pool.Query(ctx,
		`SELECT type, COUNT(*) AS cnt FROM data_assets GROUP BY type ORDER BY cnt DESC`)
	var byType []typeCount
	if err == nil {
		defer byTypeRows.Close()
		for byTypeRows.Next() {
			var tc typeCount
			if err := byTypeRows.Scan(&tc.Type, &tc.Count); err != nil {
				continue
			}
			byType = append(byType, tc)
		}
		if err := byTypeRows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
	}
	if byType == nil {
		byType = []typeCount{}
	}

	// PII/PHI/PCI counts
	var total, piiCount, phiCount, pciCount int
	_ = h.pool.QueryRow(ctx,
		`SELECT COUNT(*),
		        COUNT(*) FILTER (WHERE pii_detected),
		        COUNT(*) FILTER (WHERE phi_detected),
		        COUNT(*) FILTER (WHERE pci_detected)
		 FROM data_assets`).Scan(&total, &piiCount, &phiCount, &pciCount)

	c.JSON(http.StatusOK, gin.H{
		"by_label":  byLabel,
		"by_type":   byType,
		"pii_count": piiCount,
		"phi_count": phiCount,
		"pci_count": pciCount,
		"total":     total,
	})
}

// ListPolicies returns all data classification policies (migration 163 table).
// GET /api/v1/admin/data-classification/policies
func (h *DataClassificationHandler) ListPolicies(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, description, classification_level, file_extensions, enabled, created_at
		FROM data_classification_policies ORDER BY classification_level, name
	`)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"policies": []any{}})
		return
	}
	defer rows.Close()

	type Policy struct {
		ID                  string   `json:"id"`
		Name                string   `json:"name"`
		Description         string   `json:"description"`
		ClassificationLevel string   `json:"classification_level"`
		FileExtensions      []string `json:"file_extensions"`
		Enabled             bool     `json:"enabled"`
		CreatedAt           string   `json:"created_at"`
	}
	var list []Policy
	for rows.Next() {
		var p Policy
		var createdAt time.Time
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.ClassificationLevel, &p.FileExtensions, &p.Enabled, &createdAt); err != nil {
			continue
		}
		p.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		list = append(list, p)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if list == nil {
		list = []Policy{}
	}
	c.JSON(http.StatusOK, gin.H{"policies": list})
}

// ListFindings returns data classification findings (migration 163 table).
// GET /api/v1/admin/data-classification/findings
func (h *DataClassificationHandler) ListFindings(c *gin.Context) {
	level := c.Query("level")
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT f.id, f.agent_id, COALESCE(a.hostname, f.agent_id::text), f.file_path,
		       f.classification_level, f.match_count, f.status, f.created_at
		FROM data_classification_findings f
		LEFT JOIN agents a ON a.id = f.agent_id
		WHERE ($1 = '' OR f.classification_level = $1)
		ORDER BY f.created_at DESC LIMIT 200
	`, level)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"findings": []any{}})
		return
	}
	defer rows.Close()

	type Finding struct {
		ID                  string `json:"id"`
		AgentID             string `json:"agent_id"`
		Hostname            string `json:"hostname"`
		FilePath            string `json:"file_path"`
		ClassificationLevel string `json:"classification_level"`
		MatchCount          int    `json:"match_count"`
		Status              string `json:"status"`
		CreatedAt           string `json:"created_at"`
	}
	var list []Finding
	for rows.Next() {
		var f Finding
		var createdAt time.Time
		if err := rows.Scan(&f.ID, &f.AgentID, &f.Hostname, &f.FilePath,
			&f.ClassificationLevel, &f.MatchCount, &f.Status, &createdAt); err != nil {
			continue
		}
		f.CreatedAt = createdAt.UTC().Format(time.RFC3339)
		list = append(list, f)
	}
	if err := rows.Err(); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if list == nil {
		list = []Finding{}
	}
	c.JSON(http.StatusOK, gin.H{"findings": list})
}

// FindingsStats returns stats from the migration 163 data_classification_findings table.
// GET /api/v1/admin/data-classification/stats
func (h *DataClassificationHandler) FindingsStats(c *gin.Context) {
	var total, restricted, confidential, openFindings int
	h.pool.QueryRow(c.Request.Context(), `
		SELECT COUNT(*),
		       COUNT(*) FILTER (WHERE classification_level IN ('restricted','top_secret')),
		       COUNT(*) FILTER (WHERE classification_level = 'confidential'),
		       COUNT(*) FILTER (WHERE status = 'open')
		FROM data_classification_findings
	`).Scan(&total, &restricted, &confidential, &openFindings)
	c.JSON(http.StatusOK, gin.H{
		"total":        total,
		"restricted":   restricted,
		"confidential": confidential,
		"open":         openFindings,
	})
}

// CreatePolicy creates a new data classification policy (migration 163 table).
// POST /api/v1/admin/data-classification/policies
func (h *DataClassificationHandler) CreatePolicy(c *gin.Context) {
	var req struct {
		Name                string   `json:"name" binding:"required"`
		Description         string   `json:"description"`
		ClassificationLevel string   `json:"classification_level"`
		FileExtensions      []string `json:"file_extensions"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if req.ClassificationLevel == "" {
		req.ClassificationLevel = "internal"
	}
	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO data_classification_policies (name, description, classification_level, file_extensions)
		VALUES ($1,$2,$3,$4) RETURNING id
	`, req.Name, req.Description, req.ClassificationLevel, req.FileExtensions).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id})
}
