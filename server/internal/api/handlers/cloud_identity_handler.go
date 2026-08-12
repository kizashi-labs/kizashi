package handlers

import (
	"fmt"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// CloudIdentityHandler manages cloud identity providers and federated identities.
type CloudIdentityHandler struct {
	pool *pgxpool.Pool
}

// NewCloudIdentityHandler creates a new CloudIdentityHandler.
func NewCloudIdentityHandler(pool *pgxpool.Pool) *CloudIdentityHandler {
	return &CloudIdentityHandler{pool: pool}
}

// ListProviders GET /providers
func (h *CloudIdentityHandler) ListProviders(c *gin.Context) {
	rows, err := h.pool.Query(c.Request.Context(), `
		SELECT id, name, provider_type, COALESCE(tenant_id,''), config,
		       is_active, sync_status, last_sync, user_count, group_count,
		       COALESCE(error_msg,''), created_at, updated_at
		FROM cloud_identity_providers
		ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Provider struct {
		ID           string     `json:"id"`
		Name         string     `json:"name"`
		ProviderType string     `json:"provider_type"`
		TenantID     string     `json:"tenant_id"`
		Config       []byte     `json:"config"`
		IsActive     bool       `json:"is_active"`
		SyncStatus   string     `json:"sync_status"`
		LastSync     *time.Time `json:"last_sync"`
		UserCount    int        `json:"user_count"`
		GroupCount   int        `json:"group_count"`
		ErrorMsg     string     `json:"error_msg"`
		CreatedAt    time.Time  `json:"created_at"`
		UpdatedAt    time.Time  `json:"updated_at"`
	}

	var providers []Provider
	for rows.Next() {
		var p Provider
		if err := rows.Scan(&p.ID, &p.Name, &p.ProviderType, &p.TenantID, &p.Config,
			&p.IsActive, &p.SyncStatus, &p.LastSync, &p.UserCount, &p.GroupCount,
			&p.ErrorMsg, &p.CreatedAt, &p.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		providers = append(providers, p)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if providers == nil {
		providers = []Provider{}
	}
	c.JSON(http.StatusOK, gin.H{"providers": providers})
}

// CreateProvider POST /providers
func (h *CloudIdentityHandler) CreateProvider(c *gin.Context) {
	var body struct {
		Name         string         `json:"name" binding:"required"`
		ProviderType string         `json:"provider_type" binding:"required"`
		TenantID     string         `json:"tenant_id"`
		Config       map[string]any `json:"config"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	configJSON := toJSON(body.Config, "{}")

	var id string
	err := h.pool.QueryRow(c.Request.Context(), `
		INSERT INTO cloud_identity_providers (name, provider_type, tenant_id, config)
		VALUES ($1,$2,$3,$4::jsonb)
		RETURNING id`,
		body.Name, body.ProviderType, body.TenantID, configJSON,
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "プロバイダーを作成しました"})
}

// UpdateProvider PUT /providers/:id
func (h *CloudIdentityHandler) UpdateProvider(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		Name         string         `json:"name"`
		ProviderType string         `json:"provider_type"`
		TenantID     string         `json:"tenant_id"`
		Config       map[string]any `json:"config"`
		IsActive     *bool          `json:"is_active"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	configJSON := toJSON(body.Config, "{}")

	tag, err := h.pool.Exec(c.Request.Context(), `
		UPDATE cloud_identity_providers SET
		  name=COALESCE(NULLIF($1,''), name),
		  provider_type=COALESCE(NULLIF($2,''), provider_type),
		  tenant_id=COALESCE(NULLIF($3,''), tenant_id),
		  config=$4::jsonb,
		  is_active=COALESCE($5, is_active),
		  updated_at=NOW()
		WHERE id=$6`,
		body.Name, body.ProviderType, body.TenantID, configJSON, body.IsActive, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "プロバイダーが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "プロバイダーを更新しました"})
}

// DeleteProvider DELETE /providers/:id
func (h *CloudIdentityHandler) DeleteProvider(c *gin.Context) {
	id := c.Param("id")
	tag, err := h.pool.Exec(c.Request.Context(), `DELETE FROM cloud_identity_providers WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "プロバイダーが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "プロバイダーを削除しました"})
}

// SyncProvider POST /providers/:id/sync
func (h *CloudIdentityHandler) SyncProvider(c *gin.Context) {
	id := c.Param("id")

	tag, err := h.pool.Exec(c.Request.Context(), `
		UPDATE cloud_identity_providers
		SET sync_status='syncing', updated_at=NOW()
		WHERE id=$1`, id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "プロバイダーが見つかりません"})
		return
	}

	_, _ = h.pool.Exec(c.Request.Context(), `
		UPDATE cloud_identity_providers
		SET sync_status='synced', last_sync=NOW(),
		    user_count=0, group_count=0, error_msg=NULL, updated_at=NOW()
		WHERE id=$1`,
		id,
	)

	c.JSON(http.StatusAccepted, gin.H{"message": "同期を開始しました", "sync_status": "syncing"})
}

// ListIdentities GET /identities — filter by provider_id, is_active, email
func (h *CloudIdentityHandler) ListIdentities(c *gin.Context) {
	providerID := c.Query("provider_id")
	isActiveStr := c.Query("is_active")
	email := c.Query("email")

	query := `
		SELECT id, provider_id, external_id, email, COALESCE(display_name,''),
		       groups, roles, COALESCE(local_user_id::text,''),
		       is_active, last_seen, risk_indicators, created_at, updated_at
		FROM federated_identities
		WHERE 1=1`
	args := []interface{}{}
	idx := 1

	if providerID != "" {
		query += fmt.Sprintf(" AND provider_id=$%d", idx)
		args = append(args, providerID)
		idx++
	}
	if isActiveStr != "" {
		active := isActiveStr == "true"
		query += fmt.Sprintf(" AND is_active=$%d", idx)
		args = append(args, active)
		idx++
	}
	if email != "" {
		query += fmt.Sprintf(" AND email ILIKE $%d", idx)
		args = append(args, "%"+email+"%")
		idx++
	}
	_ = idx
	query += " ORDER BY created_at DESC"

	rows, err := h.pool.Query(c.Request.Context(), query, args...)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type Identity struct {
		ID             string     `json:"id"`
		ProviderID     string     `json:"provider_id"`
		ExternalID     string     `json:"external_id"`
		Email          string     `json:"email"`
		DisplayName    string     `json:"display_name"`
		Groups         []byte     `json:"groups"`
		Roles          []byte     `json:"roles"`
		LocalUserID    string     `json:"local_user_id"`
		IsActive       bool       `json:"is_active"`
		LastSeen       *time.Time `json:"last_seen"`
		RiskIndicators []byte     `json:"risk_indicators"`
		CreatedAt      time.Time  `json:"created_at"`
		UpdatedAt      time.Time  `json:"updated_at"`
	}

	var identities []Identity
	for rows.Next() {
		var i Identity
		if err := rows.Scan(&i.ID, &i.ProviderID, &i.ExternalID, &i.Email, &i.DisplayName,
			&i.Groups, &i.Roles, &i.LocalUserID, &i.IsActive, &i.LastSeen,
			&i.RiskIndicators, &i.CreatedAt, &i.UpdatedAt); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		identities = append(identities, i)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if identities == nil {
		identities = []Identity{}
	}
	c.JSON(http.StatusOK, gin.H{"identities": identities})
}

// GetIdentity GET /identities/:id
func (h *CloudIdentityHandler) GetIdentity(c *gin.Context) {
	id := c.Param("id")

	type Identity struct {
		ID             string     `json:"id"`
		ProviderID     string     `json:"provider_id"`
		ExternalID     string     `json:"external_id"`
		Email          string     `json:"email"`
		DisplayName    string     `json:"display_name"`
		Groups         []byte     `json:"groups"`
		Roles          []byte     `json:"roles"`
		LocalUserID    string     `json:"local_user_id"`
		IsActive       bool       `json:"is_active"`
		LastSeen       *time.Time `json:"last_seen"`
		RiskIndicators []byte     `json:"risk_indicators"`
		CreatedAt      time.Time  `json:"created_at"`
		UpdatedAt      time.Time  `json:"updated_at"`
	}

	var i Identity
	err := h.pool.QueryRow(c.Request.Context(), `
		SELECT id, provider_id, external_id, email, COALESCE(display_name,''),
		       groups, roles, COALESCE(local_user_id::text,''),
		       is_active, last_seen, risk_indicators, created_at, updated_at
		FROM federated_identities WHERE id=$1`, id,
	).Scan(&i.ID, &i.ProviderID, &i.ExternalID, &i.Email, &i.DisplayName,
		&i.Groups, &i.Roles, &i.LocalUserID, &i.IsActive, &i.LastSeen,
		&i.RiskIndicators, &i.CreatedAt, &i.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "アイデンティティが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, i)
}

// LinkIdentity PATCH /identities/:id/link
func (h *CloudIdentityHandler) LinkIdentity(c *gin.Context) {
	id := c.Param("id")
	var body struct {
		LocalUserID string `json:"local_user_id" binding:"required"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tag, err := h.pool.Exec(c.Request.Context(), `
		UPDATE federated_identities
		SET local_user_id=$1::uuid, updated_at=NOW()
		WHERE id=$2`,
		body.LocalUserID, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "アイデンティティが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "ローカルユーザーにリンクしました"})
}

// GetStats GET /stats — identity counts by provider, risk indicator summary
func (h *CloudIdentityHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()

	// Identity counts by provider
	rows, err := h.pool.Query(ctx, `
		SELECT p.name, p.provider_type,
		       COUNT(fi.id) AS total,
		       SUM(CASE WHEN fi.is_active THEN 1 ELSE 0 END) AS active_count,
		       SUM(CASE WHEN jsonb_array_length(fi.risk_indicators) > 0 THEN 1 ELSE 0 END) AS risky_count
		FROM cloud_identity_providers p
		LEFT JOIN federated_identities fi ON fi.provider_id = p.id
		GROUP BY p.id, p.name, p.provider_type
		ORDER BY p.name`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	type ProviderStat struct {
		Name         string `json:"name"`
		ProviderType string `json:"provider_type"`
		Total        int    `json:"total"`
		ActiveCount  int    `json:"active_count"`
		RiskyCount   int    `json:"risky_count"`
	}
	var byProvider []ProviderStat
	for rows.Next() {
		var s ProviderStat
		if err := rows.Scan(&s.Name, &s.ProviderType, &s.Total, &s.ActiveCount, &s.RiskyCount); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
			return
		}
		byProvider = append(byProvider, s)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	rows.Close()
	if byProvider == nil {
		byProvider = []ProviderStat{}
	}

	// Overall risk summary
	var totalIdentities, totalRisky, totalLinked int
	_ = h.pool.QueryRow(ctx, `
		SELECT COUNT(*),
		       SUM(CASE WHEN jsonb_array_length(risk_indicators) > 0 THEN 1 ELSE 0 END),
		       SUM(CASE WHEN local_user_id IS NOT NULL THEN 1 ELSE 0 END)
		FROM federated_identities`).Scan(&totalIdentities, &totalRisky, &totalLinked)

	c.JSON(http.StatusOK, gin.H{
		"by_provider":      byProvider,
		"total_identities": totalIdentities,
		"total_risky":      totalRisky,
		"total_linked":     totalLinked,
	})
}
