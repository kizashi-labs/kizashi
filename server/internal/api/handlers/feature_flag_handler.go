package handlers

import (
	"context"
	"encoding/json"
	"hash/fnv"
	"log/slog"
	"net/http"
	"regexp"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// FeatureFlagHandler manages feature flags.
type FeatureFlagHandler struct {
	pool *pgxpool.Pool
}

// NewFeatureFlagHandler creates a new FeatureFlagHandler.
func NewFeatureFlagHandler(pool *pgxpool.Pool) *FeatureFlagHandler {
	return &FeatureFlagHandler{pool: pool}
}

var featureFlagNameRe = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

var protectedFlagNames = map[string]bool{
	"new_dashboard":       true,
	"ai_threat_detection": true,
	"dark_mode_v2":        true,
	"advanced_reporting":  true,
}

type featureFlag struct {
	ID                string          `json:"id"`
	Name              string          `json:"name"`
	Description       string          `json:"description"`
	Enabled           bool            `json:"enabled"`
	RolloutPercentage int             `json:"rollout_percentage"`
	TargetRoles       json.RawMessage `json:"target_roles"`
	TargetUsers       json.RawMessage `json:"target_users"`
	Metadata          json.RawMessage `json:"metadata"`
	CreatedBy         *string         `json:"created_by,omitempty"`
	CreatedAt         time.Time       `json:"created_at"`
	UpdatedAt         time.Time       `json:"updated_at"`
}

func (h *FeatureFlagHandler) ensureTable(ctx context.Context) error {
	_, err := h.pool.Exec(ctx, `
CREATE TABLE IF NOT EXISTS feature_flags (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL UNIQUE,
  description TEXT NOT NULL DEFAULT '',
  enabled BOOL NOT NULL DEFAULT FALSE,
  rollout_percentage INT NOT NULL DEFAULT 0 CHECK (rollout_percentage BETWEEN 0 AND 100),
  target_roles JSONB NOT NULL DEFAULT '[]',
  target_users JSONB NOT NULL DEFAULT '[]',
  metadata JSONB NOT NULL DEFAULT '{}',
  created_by UUID,
  created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
INSERT INTO feature_flags (name, description, enabled, rollout_percentage) VALUES
  ('new_dashboard', '新しいダッシュボードレイアウト', false, 0),
  ('ai_threat_detection', 'AI脅威検知エンジン (ベータ)', false, 0),
  ('dark_mode_v2', 'ダークモードV2', true, 100),
  ('advanced_reporting', '高度レポート機能', false, 25)
ON CONFLICT (name) DO NOTHING;
`)
	return err
}

func scanFeatureFlag(row interface{ Scan(...interface{}) error }) (featureFlag, error) {
	var f featureFlag
	err := row.Scan(&f.ID, &f.Name, &f.Description, &f.Enabled, &f.RolloutPercentage,
		&f.TargetRoles, &f.TargetUsers, &f.Metadata, &f.CreatedBy, &f.CreatedAt, &f.UpdatedAt)
	return f, err
}

const featureFlagSelectCols = `id, name, description, enabled, rollout_percentage,
	target_roles, target_users, metadata, created_by::TEXT, created_at, updated_at`

// List — GET /admin/feature-flags
func (h *FeatureFlagHandler) List(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	rows, err := h.pool.Query(c.Request.Context(),
		`SELECT `+featureFlagSelectCols+` FROM feature_flags ORDER BY name`)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取得に失敗しました"})
		return
	}
	defer rows.Close()

	var result []featureFlag
	for rows.Next() {
		f, err := scanFeatureFlag(rows)
		if err != nil {
			continue
		}
		result = append(result, f)
	}
	if err := rows.Err(); err != nil {
		slog.Error("rows.Err: 結果の読み出しが途中で失敗しました", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "取得に失敗しました"})
		return
	}
	if result == nil {
		result = []featureFlag{}
	}
	c.JSON(http.StatusOK, gin.H{"flags": result})
}

// Get — GET /admin/feature-flags/:id
func (h *FeatureFlagHandler) Get(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	f, err := scanFeatureFlag(h.pool.QueryRow(c.Request.Context(),
		`SELECT `+featureFlagSelectCols+` FROM feature_flags WHERE id = $1`, id))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "フラグが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, f)
}

// GetByName — GET /feature-flags/by-name/:name
func (h *FeatureFlagHandler) GetByName(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	name := c.Param("name")
	f, err := scanFeatureFlag(h.pool.QueryRow(c.Request.Context(),
		`SELECT `+featureFlagSelectCols+` FROM feature_flags WHERE name = $1`, name))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "フラグが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, f)
}

// Create — POST /admin/feature-flags
func (h *FeatureFlagHandler) Create(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	var req struct {
		Name              string          `json:"name" binding:"required"`
		Description       string          `json:"description"`
		Enabled           bool            `json:"enabled"`
		RolloutPercentage int             `json:"rollout_percentage"`
		TargetRoles       json.RawMessage `json:"target_roles"`
		TargetUsers       json.RawMessage `json:"target_users"`
		Metadata          json.RawMessage `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if !featureFlagNameRe.MatchString(req.Name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "フラグ名は英数字とアンダースコアのみ使用できます"})
		return
	}

	if req.TargetRoles == nil {
		req.TargetRoles = json.RawMessage(`[]`)
	}
	if req.TargetUsers == nil {
		req.TargetUsers = json.RawMessage(`[]`)
	}
	if req.Metadata == nil {
		req.Metadata = json.RawMessage(`{}`)
	}

	userIDVal, _ := c.Get("user_id")
	userID, _ := userIDVal.(string)

	var id string
	err := h.pool.QueryRow(c.Request.Context(),
		`INSERT INTO feature_flags (name, description, enabled, rollout_percentage, target_roles, target_users, metadata, created_by)
		 VALUES ($1, $2, $3, $4, $5, $6, $7, $8::UUID) RETURNING id`,
		req.Name, req.Description, req.Enabled, req.RolloutPercentage,
		req.TargetRoles, req.TargetUsers, req.Metadata, nilIfEmpty(userID)).
		Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "作成に失敗しました"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "message": "フラグを作成しました"})
}

// Update — PUT /admin/feature-flags/:id
func (h *FeatureFlagHandler) Update(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	var req struct {
		Name              *string         `json:"name"`
		Description       *string         `json:"description"`
		Enabled           *bool           `json:"enabled"`
		RolloutPercentage *int            `json:"rollout_percentage"`
		TargetRoles       json.RawMessage `json:"target_roles"`
		TargetUsers       json.RawMessage `json:"target_users"`
		Metadata          json.RawMessage `json:"metadata"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	if req.Name != nil && !featureFlagNameRe.MatchString(*req.Name) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "フラグ名は英数字とアンダースコアのみ使用できます"})
		return
	}

	tag, err := h.pool.Exec(c.Request.Context(),
		`UPDATE feature_flags SET
		   name = COALESCE($2, name),
		   description = COALESCE($3, description),
		   enabled = COALESCE($4, enabled),
		   rollout_percentage = COALESCE($5, rollout_percentage),
		   target_roles = COALESCE($6, target_roles),
		   target_users = COALESCE($7, target_users),
		   metadata = COALESCE($8, metadata),
		   updated_at = NOW()
		 WHERE id = $1`,
		id, req.Name, req.Description, req.Enabled, req.RolloutPercentage,
		req.TargetRoles, req.TargetUsers, req.Metadata)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "フラグが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "更新しました"})
}

// Delete — DELETE /admin/feature-flags/:id
func (h *FeatureFlagHandler) Delete(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")

	// Check if this is a protected flag
	var name string
	if !ReadOK(c, h.pool.QueryRow(c.Request.Context(), `SELECT name FROM feature_flags WHERE id = $1`, id).Scan(&name)) {
		return
	}
	if protectedFlagNames[name] {
		c.JSON(http.StatusForbidden, gin.H{"error": "デフォルトフラグは削除できません"})
		return
	}

	tag, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM feature_flags WHERE id = $1`, id)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "フラグが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "削除しました"})
}

// Toggle — POST /admin/feature-flags/:id/toggle
func (h *FeatureFlagHandler) Toggle(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	var enabled bool
	err := h.pool.QueryRow(c.Request.Context(),
		`UPDATE feature_flags SET enabled = NOT enabled, updated_at = NOW()
		 WHERE id = $1 RETURNING enabled`, id).Scan(&enabled)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "フラグが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"enabled": enabled})
}

// SetRollout — POST /admin/feature-flags/:id/rollout
func (h *FeatureFlagHandler) SetRollout(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	id := c.Param("id")
	var req struct {
		Percentage int `json:"percentage" binding:"required,min=0,max=100"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	tag, err := h.pool.Exec(c.Request.Context(),
		`UPDATE feature_flags SET rollout_percentage = $2, updated_at = NOW() WHERE id = $1`,
		id, req.Percentage)
	if err != nil || tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "フラグが見つかりません"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"rollout_percentage": req.Percentage})
}

// Evaluate — POST /feature-flags/evaluate
func (h *FeatureFlagHandler) Evaluate(c *gin.Context) {
	if err := h.ensureTable(c.Request.Context()); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "テーブルの初期化に失敗しました"})
		return
	}

	var req struct {
		FlagName string `json:"flag_name" binding:"required"`
		UserID   string `json:"user_id"`
		Role     string `json:"role"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	var f featureFlag
	err := h.pool.QueryRow(c.Request.Context(),
		`SELECT `+featureFlagSelectCols+` FROM feature_flags WHERE name = $1`, req.FlagName).
		Scan(&f.ID, &f.Name, &f.Description, &f.Enabled, &f.RolloutPercentage,
			&f.TargetRoles, &f.TargetUsers, &f.Metadata, &f.CreatedBy, &f.CreatedAt, &f.UpdatedAt)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "フラグが見つかりません"})
		return
	}

	if !f.Enabled {
		c.JSON(http.StatusOK, gin.H{
			"flag_name": req.FlagName,
			"enabled":   false,
			"reason":    "フラグが無効です",
		})
		return
	}

	// Check target_users
	if req.UserID != "" {
		var users []string
		if err := json.Unmarshal(f.TargetUsers, &users); err == nil {
			for _, u := range users {
				if u == req.UserID {
					c.JSON(http.StatusOK, gin.H{
						"flag_name": req.FlagName,
						"enabled":   true,
						"reason":    "ターゲットユーザーに含まれています",
					})
					return
				}
			}
		}
	}

	// Check target_roles
	if req.Role != "" {
		var roles []string
		if err := json.Unmarshal(f.TargetRoles, &roles); err == nil {
			for _, r := range roles {
				if r == req.Role {
					c.JSON(http.StatusOK, gin.H{
						"flag_name": req.FlagName,
						"enabled":   true,
						"reason":    "ターゲットロールに含まれています",
					})
					return
				}
			}
		}
	}

	// Check rollout_percentage (100% = everyone)
	if f.RolloutPercentage >= 100 {
		c.JSON(http.StatusOK, gin.H{
			"flag_name": req.FlagName,
			"enabled":   true,
			"reason":    "100%ロールアウト中",
		})
		return
	}

	if f.RolloutPercentage > 0 && req.UserID != "" {
		// Deterministic hash-based rollout
		h2 := fnv.New32a()
		h2.Write([]byte(req.FlagName + ":" + req.UserID))
		bucket := int(h2.Sum32() % 100)
		if bucket < f.RolloutPercentage {
			c.JSON(http.StatusOK, gin.H{
				"flag_name": req.FlagName,
				"enabled":   true,
				"reason":    "ロールアウト対象ユーザー",
			})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"flag_name": req.FlagName,
		"enabled":   false,
		"reason":    "ロールアウト対象外",
	})
}
