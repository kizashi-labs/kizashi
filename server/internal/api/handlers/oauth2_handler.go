package handlers

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"log/slog"
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
	"golang.org/x/crypto/bcrypt"
)

// OAuth2Handler manages OAuth2/OIDC client registrations.
type OAuth2Handler struct {
	pool *pgxpool.Pool
}

// NewOAuth2Handler creates a new OAuth2Handler.
func NewOAuth2Handler(pool *pgxpool.Pool) *OAuth2Handler {
	return &OAuth2Handler{pool: pool}
}

// oauth2Client represents a registered OAuth2 client (never includes the secret hash).
type oauth2Client struct {
	ID             string          `json:"id"`
	ClientID       string          `json:"client_id"`
	Name           string          `json:"name"`
	Description    string          `json:"description"`
	RedirectURIs   json.RawMessage `json:"redirect_uris"`
	AllowedScopes  json.RawMessage `json:"allowed_scopes"`
	GrantTypes     json.RawMessage `json:"grant_types"`
	IsConfidential bool            `json:"is_confidential"`
	Enabled        bool            `json:"enabled"`
	CreatedBy      *string         `json:"created_by,omitempty"`
	LastUsedAt     *time.Time      `json:"last_used_at,omitempty"`
	CreatedAt      time.Time       `json:"created_at"`
	UpdatedAt      time.Time       `json:"updated_at"`
}

// ensureOAuth2Table creates the table if it doesn't exist.
func (h *OAuth2Handler) ensureOAuth2Table(c *gin.Context) bool {
	_, err := h.pool.Exec(c.Request.Context(), `
CREATE TABLE IF NOT EXISTS oauth2_clients (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  client_id TEXT NOT NULL UNIQUE,
  client_secret_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  description TEXT NOT NULL DEFAULT '',
  redirect_uris JSONB NOT NULL DEFAULT '[]',
  allowed_scopes JSONB NOT NULL DEFAULT '["read"]',
  grant_types JSONB NOT NULL DEFAULT '["authorization_code"]',
  is_confidential BOOL NOT NULL DEFAULT TRUE,
  enabled BOOL NOT NULL DEFAULT TRUE,
  created_by UUID,
  last_used_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_oauth2_client_id ON oauth2_clients(client_id);
`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return false
	}
	return true
}

// ListClients lists all registered OAuth2 clients.
// GET /admin/oauth2
func (h *OAuth2Handler) ListClients(c *gin.Context) {
	if !h.ensureOAuth2Table(c) {
		return
	}

	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT id, client_id, name, description, redirect_uris, allowed_scopes, grant_types,
		        is_confidential, enabled, created_by::TEXT, last_used_at, created_at, updated_at
		 FROM oauth2_clients
		 ORDER BY created_at DESC`,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	defer rows.Close()

	var clients []oauth2Client
	for rows.Next() {
		var cl oauth2Client
		if err := rows.Scan(
			&cl.ID, &cl.ClientID, &cl.Name, &cl.Description,
			&cl.RedirectURIs, &cl.AllowedScopes, &cl.GrantTypes,
			&cl.IsConfidential, &cl.Enabled, &cl.CreatedBy,
			&cl.LastUsedAt, &cl.CreatedAt, &cl.UpdatedAt,
		); err == nil {
			clients = append(clients, cl)
		}
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}
	if clients == nil {
		clients = []oauth2Client{}
	}

	c.JSON(http.StatusOK, gin.H{"clients": clients, "total": len(clients)})
}

// GetClient returns a single OAuth2 client.
// GET /admin/oauth2/:id
func (h *OAuth2Handler) GetClient(c *gin.Context) {
	if !h.ensureOAuth2Table(c) {
		return
	}

	id := c.Param("id")
	var cl oauth2Client
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT id, client_id, name, description, redirect_uris, allowed_scopes, grant_types,
		        is_confidential, enabled, created_by::TEXT, last_used_at, created_at, updated_at
		 FROM oauth2_clients WHERE id = $1`,
		id,
	).Scan(
		&cl.ID, &cl.ClientID, &cl.Name, &cl.Description,
		&cl.RedirectURIs, &cl.AllowedScopes, &cl.GrantTypes,
		&cl.IsConfidential, &cl.Enabled, &cl.CreatedBy,
		&cl.LastUsedAt, &cl.CreatedAt, &cl.UpdatedAt,
	)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "クライアントが見つかりません"})
		return
	}

	c.JSON(http.StatusOK, cl)
}

// CreateClient registers a new OAuth2 client.
// POST /admin/oauth2
func (h *OAuth2Handler) CreateClient(c *gin.Context) {
	if !h.ensureOAuth2Table(c) {
		return
	}

	var req struct {
		Name           string   `json:"name" binding:"required"`
		Description    string   `json:"description"`
		RedirectURIs   []string `json:"redirect_uris"`
		AllowedScopes  []string `json:"allowed_scopes"`
		GrantTypes     []string `json:"grant_types"`
		IsConfidential bool     `json:"is_confidential"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです: " + err.Error()})
		return
	}

	// Generate random client_id (32 hex chars)
	clientIDBytes := make([]byte, 16)
	if _, err := rand.Read(clientIDBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "client_idの生成に失敗しました"})
		return
	}
	clientID := hex.EncodeToString(clientIDBytes)

	// Generate random client_secret (48 chars)
	secretBytes := make([]byte, 24)
	if _, err := rand.Read(secretBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "client_secretの生成に失敗しました"})
		return
	}
	clientSecret := hex.EncodeToString(secretBytes)

	// Bcrypt hash the secret
	hash, err := bcrypt.GenerateFromPassword([]byte(clientSecret), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "シークレットのハッシュ化に失敗しました"})
		return
	}

	// Defaults
	if req.AllowedScopes == nil {
		req.AllowedScopes = []string{"read"}
	}
	if req.GrantTypes == nil {
		req.GrantTypes = []string{"authorization_code"}
	}
	if req.RedirectURIs == nil {
		req.RedirectURIs = []string{}
	}

	ruriJSON, _ := json.Marshal(req.RedirectURIs)
	scopesJSON, _ := json.Marshal(req.AllowedScopes)
	grantJSON, _ := json.Marshal(req.GrantTypes)

	userID, _ := c.Get("user_id")
	userIDStr, _ := userID.(string)

	ctx := c.Request.Context()
	var id string
	err = h.pool.QueryRow(ctx,
		`INSERT INTO oauth2_clients (client_id, client_secret_hash, name, description,
		        redirect_uris, allowed_scopes, grant_types, is_confidential, created_by)
		 VALUES ($1, $2, $3, $4, $5::jsonb, $6::jsonb, $7::jsonb, $8, $9::uuid)
		 RETURNING id`,
		clientID, string(hash), req.Name, req.Description,
		string(ruriJSON), string(scopesJSON), string(grantJSON),
		req.IsConfidential, nilIfEmpty(userIDStr),
	).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusCreated, gin.H{
		"id":            id,
		"client_id":     clientID,
		"client_secret": clientSecret,
		"note":          "この値は一度のみ表示されます",
		"message":       "OAuth2クライアントを作成しました",
	})
}

// UpdateClient updates an OAuth2 client.
// PUT /admin/oauth2/:id
func (h *OAuth2Handler) UpdateClient(c *gin.Context) {
	if !h.ensureOAuth2Table(c) {
		return
	}

	id := c.Param("id")
	var req struct {
		Name          string          `json:"name"`
		Description   string          `json:"description"`
		RedirectURIs  json.RawMessage `json:"redirect_uris"`
		AllowedScopes json.RawMessage `json:"allowed_scopes"`
		GrantTypes    json.RawMessage `json:"grant_types"`
		Enabled       *bool           `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです: " + err.Error()})
		return
	}

	ctx := c.Request.Context()
	_, err := h.pool.Exec(ctx,
		`UPDATE oauth2_clients
		 SET name = COALESCE(NULLIF($2, ''), name),
		     description = COALESCE(NULLIF($3, ''), description),
		     redirect_uris = CASE WHEN $4::TEXT != 'null' THEN $4::jsonb ELSE redirect_uris END,
		     allowed_scopes = CASE WHEN $5::TEXT != 'null' THEN $5::jsonb ELSE allowed_scopes END,
		     grant_types = CASE WHEN $6::TEXT != 'null' THEN $6::jsonb ELSE grant_types END,
		     enabled = COALESCE($7, enabled),
		     updated_at = NOW()
		 WHERE id = $1`,
		id, req.Name, req.Description,
		nullableJSON(req.RedirectURIs),
		nullableJSON(req.AllowedScopes),
		nullableJSON(req.GrantTypes),
		req.Enabled,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	h.GetClient(c)
}

// DeleteClient deletes an OAuth2 client.
// DELETE /admin/oauth2/:id
func (h *OAuth2Handler) DeleteClient(c *gin.Context) {
	if !h.ensureOAuth2Table(c) {
		return
	}

	id := c.Param("id")
	_, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM oauth2_clients WHERE id = $1`, id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "クライアントを削除しました"})
}

// RotateSecret generates a new secret for an OAuth2 client.
// POST /admin/oauth2/:id/rotate-secret
func (h *OAuth2Handler) RotateSecret(c *gin.Context) {
	if !h.ensureOAuth2Table(c) {
		return
	}

	id := c.Param("id")

	// Generate new secret
	secretBytes := make([]byte, 24)
	if _, err := rand.Read(secretBytes); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "シークレットの生成に失敗しました"})
		return
	}
	newSecret := hex.EncodeToString(secretBytes)

	hash, err := bcrypt.GenerateFromPassword([]byte(newSecret), bcrypt.DefaultCost)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "シークレットのハッシュ化に失敗しました"})
		return
	}

	_, err = h.pool.Exec(c.Request.Context(),
		`UPDATE oauth2_clients SET client_secret_hash = $1, updated_at = NOW() WHERE id = $2`,
		string(hash), id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"client_secret": newSecret,
		"warning":       "この値は一度のみ表示されます。安全な場所に保存してください",
		"message":       "クライアントシークレットをローテーションしました",
	})
}

// ToggleClient enables or disables an OAuth2 client.
// POST /admin/oauth2/:id/toggle
func (h *OAuth2Handler) ToggleClient(c *gin.Context) {
	if !h.ensureOAuth2Table(c) {
		return
	}

	id := c.Param("id")
	_, err := h.pool.Exec(c.Request.Context(),
		`UPDATE oauth2_clients SET enabled = NOT enabled, updated_at = NOW() WHERE id = $1`,
		id,
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": dbErrMsg(err)})
		return
	}

	h.GetClient(c)
}

// nullableJSON returns a string representation of JSON bytes or "null" if empty.
func nullableJSON(raw json.RawMessage) string {
	if len(raw) == 0 {
		return "null"
	}
	return string(raw)
}
