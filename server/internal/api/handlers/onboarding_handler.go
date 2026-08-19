package handlers

import (
	"context"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// OnboardingHandler serves the setup wizard status endpoint.
type OnboardingHandler struct {
	pool *pgxpool.Pool
}

// NewOnboardingHandler constructs a new OnboardingHandler.
func NewOnboardingHandler(pool *pgxpool.Pool) *OnboardingHandler {
	return &OnboardingHandler{pool: pool}
}

// OnboardingStep represents one step in the setup wizard.
type OnboardingStep struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	Description string `json:"description"`
	Completed   bool   `json:"completed"`
	Required    bool   `json:"required"`
	ActionURL   string `json:"action_url"`
}

// tableExists checks whether a table exists in the public schema.
func (h *OnboardingHandler) tableExists(ctx context.Context, table string) bool {
	return tableIsThere(ctx, h.pool, table)
}

// countRows returns true when the table has at least one row matching the optional WHERE clause.
// whereClause may be empty ("") for a plain COUNT(*) with no filter.
func (h *OnboardingHandler) countRows(ctx context.Context, table, whereClause string) bool {
	query := `SELECT COUNT(*) FROM ` + table
	if whereClause != "" {
		query += ` WHERE ` + whereClause
	}
	var n int
	err := h.pool.QueryRow(ctx, query).Scan(&n)
	return err == nil && n > 0
}

// GetStatus handles GET /api/v1/admin/onboarding.
func (h *OnboardingHandler) GetStatus(c *gin.Context) {
	ctx := c.Request.Context()

	steps := []OnboardingStep{
		{
			ID:          "database",
			Title:       "データベース接続",
			Description: "PostgreSQL データベースに正常に接続されています。",
			Required:    true,
			ActionURL:   "/admin/migrations",
		},
		{
			ID:          "first_agent",
			Title:       "初回エージェント登録",
			Description: "少なくとも 1 台のエンドポイントにエージェントを配布してください。",
			Required:    true,
			ActionURL:   "/admin/agent-deployment",
		},
		{
			ID:          "alert_rules",
			Title:       "アラートルール設定",
			Description: "有効な検知ルールが 1 件以上必要です。",
			Required:    true,
			ActionURL:   "/rules",
		},
		{
			ID:          "notification_channel",
			Title:       "通知チャンネル設定",
			Description: "アラートを受け取るための通知チャンネルを設定してください。",
			Required:    false,
			ActionURL:   "/admin/notifications",
		},
		{
			ID:          "sso_or_ldap",
			Title:       "SSO/LDAP 設定",
			Description: "シングルサインオンまたは LDAP/AD 連携を設定してください。",
			Required:    false,
			ActionURL:   "/admin/sso",
		},
		{
			ID:          "first_user",
			Title:       "追加ユーザー招待",
			Description: "管理者以外のユーザーを 1 名以上招待してください。",
			Required:    false,
			ActionURL:   "/admin/users",
		},
		{
			ID:          "backup_configured",
			Title:       "バックアップ設定",
			Description: "データベースのバックアップを少なくとも 1 回実行してください。",
			Required:    false,
			ActionURL:   "/admin/backups",
		},
		{
			ID:          "threat_feeds",
			Title:       "脅威フィード設定",
			Description: "外部の脅威インテリジェンスフィードを有効にしてください。",
			Required:    false,
			ActionURL:   "/admin/integrations",
		},
	}

	// ── Step 1: database — always true if we can respond ──────────────────
	steps[0].Completed = true

	// ── Step 2: first_agent ───────────────────────────────────────────────
	if h.tableExists(ctx, "agents") {
		steps[1].Completed = h.countRows(ctx, "agents", "")
	}

	// ── Step 3: alert_rules ───────────────────────────────────────────────
	if h.tableExists(ctx, "rules") {
		steps[2].Completed = h.countRows(ctx, "rules", "enabled = true")
	}

	// ── Step 4: notification_channel ─────────────────────────────────────
	if h.tableExists(ctx, "notification_channels") {
		steps[3].Completed = h.countRows(ctx, "notification_channels", "enabled = true")
	}

	// ── Step 5: sso_or_ldap ──────────────────────────────────────────────
	ssoConfigured := false
	if h.tableExists(ctx, "sso_configs") {
		ssoConfigured = h.countRows(ctx, "sso_configs", "")
	}
	ldapConfigured := false
	if h.tableExists(ctx, "system_metadata") {
		var val string
		err := h.pool.QueryRow(ctx,
			`SELECT value FROM system_metadata WHERE key = 'ldap_config' LIMIT 1`,
		).Scan(&val)
		ldapConfigured = err == nil && val != "" && val != "{}" && val != "null"
	}
	steps[4].Completed = ssoConfigured || ldapConfigured

	// ── Step 6: first_user (more than just admin) ─────────────────────────
	if h.tableExists(ctx, "users") {
		steps[5].Completed = h.countRows(ctx, "users", "role != 'admin'")
	}

	// ── Step 7: backup_configured ─────────────────────────────────────────
	if h.tableExists(ctx, "backups") {
		steps[6].Completed = h.countRows(ctx, "backups", "status = 'completed'")
	}

	// ── Step 8: threat_feeds ──────────────────────────────────────────────
	if h.tableExists(ctx, "threat_feeds") {
		steps[7].Completed = h.countRows(ctx, "threat_feeds", "")
	}

	// ── Compute summary ───────────────────────────────────────────────────
	completed := 0
	for _, s := range steps {
		if s.Completed {
			completed++
		}
	}
	total := len(steps)
	percentage := 0
	if total > 0 {
		percentage = (completed * 100) / total
	}

	c.JSON(http.StatusOK, gin.H{
		"steps":      steps,
		"completed":  completed,
		"total":      total,
		"percentage": percentage,
	})
}
