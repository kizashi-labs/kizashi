package handlers

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// ServiceAccountHandler manages service accounts.
type ServiceAccountHandler struct {
	pool *pgxpool.Pool
}

// NewServiceAccountHandler creates a new ServiceAccountHandler.
func NewServiceAccountHandler(pool *pgxpool.Pool) *ServiceAccountHandler {
	return &ServiceAccountHandler{pool: pool}
}

type serviceAccount struct {
	ID             string          `json:"id"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	ClientIDMasked string          `json:"client_id"`
	Scopes         json.RawMessage `json:"scopes"`
	AllowedIPs     json.RawMessage `json:"allowed_ips"`
	Enabled        bool            `json:"enabled"`
	ExpiresAt      *time.Time      `json:"expires_at,omitempty"`
	LastUsedAt     *time.Time      `json:"last_used_at,omitempty"`
	CreatedBy      *string         `json:"created_by,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

func maskClientID(id string) string {
	if len(id) <= 4 {
		return "****"
	}
	return strings.Repeat("*", len(id)-4) + id[len(id)-4:]
}

func (h *ServiceAccountHandler) ensureTable(ctx context.Context) error {
	_, err := h.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS service_accounts (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  client_id TEXT NOT NULL UNIQUE,
  client_secret_hash TEXT NOT NULL,
  scopes JSONB NOT NULL DEFAULT '["read"]',
  allowed_ips JSONB NOT NULL DEFAULT '[]',
  enabled BOOL NOT NULL DEFAULT TRUE,
  expires_at TIMESTAMPTZ,
  last_used_at TIMESTAMPTZ,
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_service_accounts_client_id ON service_accounts(client_id);
`)
	return err
}

func generateServiceAccountClientID() (string, error) {
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return "sa_" + hex.EncodeToString(b), nil
}

func generateServiceAccountSecret() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// List — GET /admin/service-accounts
func (h *ServiceAccountHandler) List(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, name, description, client_id, scopes, allowed_ips, enabled,
		        expires_at, last_used_at, created_by::TEXT, created_at, updated_at
		 FROM service_accounts ORDER BY created_at DESC`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取得に失敗しました"})
		return
	}
	defer rows.Close()

	var result []serviceAccount
	for rows.Next() {
		var sa serviceAccount
		var rawClientID string
		if err := rows.Scan(&sa.ID, &sa.Name, &sa.Description, &rawClientID,
			&sa.Scopes, &sa.AllowedIPs, &sa.Enabled,
			&sa.ExpiresAt, &sa.LastUsedAt, &sa.CreatedBy,
			&sa.CreatedAt, &sa.UpdatedAt); err != nil {
			continue
		}
		sa.ClientIDMasked = maskClientID(rawClientID)
		result = append(result, sa)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取得に失敗しました"})
		return
	}
	if result == nil {
		result = []serviceAccount{}
	}
	c.JSON(http.StatusOK, gin.H{"service_accounts": result})
}

// Get — GET /admin/service-accounts/:id
func (h *ServiceAccountHandler) Get(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	var sa serviceAccount
	var rawClientID string
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT id, name, description, client_id, scopes, allowed_ips, enabled,
		        expires_at, last_used_at, created_by::TEXT, created_at, updated_at
		 FROM service_accounts WHERE id = $1`, id).
		Scan(&sa.ID, &sa.Name, &sa.Description, &rawClientID,
			&sa.Scopes, &sa.AllowedIPs, &sa.Enabled,
			&sa.ExpiresAt, &sa.LastUsedAt, &sa.CreatedBy,
			&sa.CreatedAt, &sa.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "サービスアカウントが見つかりません"})
		return
	}
	sa.ClientIDMasked = maskClientID(rawClientID)
	c.JSON(http.StatusOK, sa)
}

// Create — POST /admin/service-accounts
func (h *ServiceAccountHandler) Create(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	var req struct {
		Name        string          `json:"name" binding:"required"`
		Description string          `json:"description"`
		Scopes      json.RawMessage `json:"scopes"`
		AllowedIPs  json.RawMessage `json:"allowed_ips"`
		ExpiresAt   *time.Time      `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	clientID, err := generateServiceAccountClientID()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "client_idの生成に失敗しました"})
		return
	}

	secret, err := generateServiceAccountSecret()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "シークレットの生成に失敗しました"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "シークレットのハッシュ化に失敗しました"})
		return
	}

	scopes := req.Scopes
	if scopes == nil {
		scopes = json.RawMessage(`["read"]`)
	}
	allowedIPs := req.AllowedIPs
	if allowedIPs == nil {
		allowedIPs = json.RawMessage(`[]`)
	}

	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(string)

	var id string
	err = h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO service_accounts (name, description, client_id, client_secret_hash, scopes, allowed_ips, expires_at, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::UUID) RETURNING id`,
		req.Name, req.Description, clientID, string(hash), scopes, allowedIPs, req.ExpiresAt, nilIfEmpty(userID)).
		Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "作成に失敗しました"})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":            id,
		"client_id":     clientID,
		"client_secret": secret,
		"note":          "このシークレットは一度だけ表示されます。安全な場所に保存してください。",
	})
}

// Update — PUT /admin/service-accounts/:id
func (h *ServiceAccountHandler) Update(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	var req struct {
		Name        *string         `json:"name"`
		Description *string         `json:"description"`
		Scopes      json.RawMessage `json:"scopes"`
		AllowedIPs  json.RawMessage `json:"allowed_ips"`
		ExpiresAt   *time.Time      `json:"expires_at"`
		Enabled     *bool           `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tag, err := h.pool.Exec(c.Request.Context(),
		`UPDATE service_accounts SET
		   name = COALESCE($2, name),
		   description = COALESCE($3, description),
		   scopes = COALESCE($4, scopes),
		   allowed_ips = COALESCE($5, allowed_ips),
		   expires_at = COALESCE($6, expires_at),
		   enabled = COALESCE($7, enabled),
		   updated_at = NOW()
		 WHERE id = $1`,
		id, req.Name, req.Description, req.Scopes, req.AllowedIPs, req.ExpiresAt, req.Enabled)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "サービスアカウントが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新しました"})
}

// Delete — DELETE /admin/service-accounts/:id
func (h *ServiceAccountHandler) Delete(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	tag, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM service_accounts WHERE id = $1`, id)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "サービスアカウントが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "削除しました"})
}

// RotateSecret — POST /admin/service-accounts/:id/rotate
func (h *ServiceAccountHandler) RotateSecret(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	secret, err := generateServiceAccountSecret()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "シークレットの生成に失敗しました"})
		return
	}

	hash, err := bcrypt.GenerateFromPassword([]byte(secret), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "シークレットのハッシュ化に失敗しました"})
		return
	}

	tag, err := h.pool.Exec(c.Request.Context(),
		`UPDATE service_accounts SET client_secret_hash = $2, updated_at = NOW() WHERE id = $1`,
		id, string(hash))
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "サービスアカウントが見つかりません"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"client_secret": secret,
		"note":          "このシークレットは一度だけ表示されます。安全な場所に保存してください。",
	})
}

// Toggle — POST /admin/service-accounts/:id/toggle
func (h *ServiceAccountHandler) Toggle(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	var enabled bool
	err := h.pool.QueryRow(c.Request.Context(),
		`UPDATE service_accounts SET enabled = NOT enabled, updated_at = NOW()
		 WHERE id = $1 RETURNING enabled`, id).Scan(&enabled)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "サービスアカウントが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": enabled})
}
