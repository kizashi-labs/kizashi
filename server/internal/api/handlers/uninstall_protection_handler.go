package handlers

import (
	"crypto/pbkdf2"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
)

// DefaultTenantID is the tenant a single-tenant deployment operates as. It
// matches the row migration 200 seeds, and mirrors how the rest of the API
// treats an absent tenant_id.
const DefaultTenantID = "00000000-0000-0000-0000-000000000001"

// PBKDF2 parameters. These MUST match agent/internal/uninstallguard: the server
// derives the digest, the agent verifies against it, and a mismatch in either
// the hash or the iteration count means every endpoint rejects the correct
// password with no indication of why.
//
// The iteration count also travels in the stored row, so agents honour whatever
// was used at derivation time even if this constant is raised later.
const (
	uninstallKDFIterations = 600_000
	uninstallKDFKeyLen     = 32
	uninstallKDFAlgorithm  = "pbkdf2-hmac-sha256"
	uninstallKDFVersion    = 1
)

// minUninstallPasswordLen is a floor, not a policy engine.
//
// The digest sits on every endpoint the password protects, so an attacker who
// gets local administrator on any one of them can attack it offline at their
// own pace. A four-character password would fall in seconds regardless of the
// KDF cost. Twelve is the NIST 800-63B memorised-secret guidance for
// machine-generated-adjacent secrets and is what the console suggests.
const minUninstallPasswordLen = 12

// UninstallProtectionHandler owns the tenant uninstall password and the record
// of attempts to remove agents.
type UninstallProtectionHandler struct {
	store *store.UninstallProtectionStore
}

// NewUninstallProtectionHandler creates the handler.
func NewUninstallProtectionHandler(s *store.UninstallProtectionStore) *UninstallProtectionHandler {
	return &UninstallProtectionHandler{store: s}
}

// tenantOf resolves the tenant for a request, falling back to the default
// tenant in single-tenant deployments — the same convention as the rest of the
// API (see AgentHandler.ensureAgentInTenant).
func tenantOf(c *gin.Context) string {
	if v, ok := c.Get("tenant_id"); ok {
		if s, _ := v.(string); s != "" {
			return s
		}
	}
	return DefaultTenantID
}

// uninstallStatusResponse is what the console shows. It deliberately carries no
// salt and no digest: the console has no use for them, and an endpoint that
// hands out the material an offline attack needs is an endpoint worth attacking.
type uninstallStatusResponse struct {
	Configured bool       `json:"configured"`
	UpdatedAt  *time.Time `json:"updated_at,omitempty"`
	UpdatedBy  string     `json:"updated_by,omitempty"`
	Algorithm  string     `json:"algorithm,omitempty"`
	Iterations int        `json:"iterations,omitempty"`
}

// GetStatus reports whether an uninstall password is configured.
// GET /api/v1/admin/uninstall-protection
func (h *UninstallProtectionHandler) GetStatus(c *gin.Context) {
	g, err := h.store.GetGuard(c.Request.Context(), tenantOf(c))
	if errors.Is(err, store.ErrNoUninstallGuard) {
		c.JSON(http.StatusOK, uninstallStatusResponse{Configured: false})
		return
	}
	if err != nil {
		slog.Error("[uninstall] 保護設定の取得に失敗", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "アンインストール保護の設定を取得できませんでした"})
		return
	}
	updated := g.UpdatedAt
	c.JSON(http.StatusOK, uninstallStatusResponse{
		Configured: true,
		UpdatedAt:  &updated,
		UpdatedBy:  g.UpdatedBy,
		Algorithm:  g.Algorithm,
		Iterations: g.Iterations,
	})
}

type setUninstallPasswordRequest struct {
	Password string `json:"password"`
}

// SetPassword installs or rotates the tenant's uninstall password.
// POST /api/v1/admin/uninstall-protection
//
// The plaintext exists only for the duration of this request: it is derived
// immediately and never stored, logged, or returned. Rotation takes effect on
// each endpoint at its next heartbeat, so a fleet converges within the
// heartbeat interval rather than instantly — worth stating plainly to whoever
// just rotated it because they believe the old one leaked.
func (h *UninstallProtectionHandler) SetPassword(c *gin.Context) {
	var req setUninstallPasswordRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストの形式が不正です"})
		return
	}

	// Trim only the ends: a password whose value depends on invisible trailing
	// whitespace is a support call waiting to happen, since the operator will
	// retype it from a chat message or a ticket.
	password := strings.TrimSpace(req.Password)
	if utf8.RuneCountInString(password) < minUninstallPasswordLen {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "アンインストールパスワードは " + strconv.Itoa(minUninstallPasswordLen) + " 文字以上にしてください",
			"reason": "digest は保護対象の各端末上に置かれるため、端末のローカル管理者を取った攻撃者は" +
				"オフラインで総当たりできます。短いパスワードは KDF の強度に関わらず破られます。",
		})
		return
	}

	salt := make([]byte, 16)
	if _, err := rand.Read(salt); err != nil {
		slog.Error("[uninstall] salt の生成に失敗", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "パスワードを設定できませんでした"})
		return
	}
	digest, err := pbkdf2.Key(sha256.New, password, salt, uninstallKDFIterations, uninstallKDFKeyLen)
	if err != nil {
		slog.Error("[uninstall] digest の導出に失敗", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "パスワードを設定できませんでした"})
		return
	}

	actor, _ := c.Get("username")
	actorStr, _ := actor.(string)

	g := &store.UninstallGuard{
		TenantID:   tenantOf(c),
		Version:    uninstallKDFVersion,
		Algorithm:  uninstallKDFAlgorithm,
		Iterations: uninstallKDFIterations,
		SaltB64:    base64.StdEncoding.EncodeToString(salt),
		DigestB64:  base64.StdEncoding.EncodeToString(digest),
		UpdatedBy:  actorStr,
	}
	if err := h.store.SetGuard(c.Request.Context(), g); err != nil {
		slog.Error("[uninstall] 保護設定の保存に失敗", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "パスワードを設定できませんでした"})
		return
	}

	slog.Info("[uninstall] アンインストールパスワードを設定しました",
		"tenant_id", g.TenantID, "updated_by", actorStr)

	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"note": "各エンドポイントには次回ハートビート時に配布されます（既定30秒間隔）。" +
			"配布前の端末は直前のパスワード、または未設定のまま動作します。",
	})
}

// ClearPassword removes the uninstall password, returning the fleet to
// unprotected uninstalls.
// DELETE /api/v1/admin/uninstall-protection
func (h *UninstallProtectionHandler) ClearPassword(c *gin.Context) {
	tenantID := tenantOf(c)
	if err := h.store.ClearGuard(c.Request.Context(), tenantID); err != nil {
		slog.Error("[uninstall] 保護設定の削除に失敗", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "設定を削除できませんでした"})
		return
	}
	actor, _ := c.Get("username")
	slog.Warn("[uninstall] アンインストール保護を解除しました（以後どの端末も無条件にアンインストール可能）",
		"tenant_id", tenantID, "actor", actor)

	// The endpoints keep their guard file until an operator removes it, because
	// clearing the tenant password stops the server *advertising* one but the
	// heartbeat has no "forget it" instruction to send. Say so rather than let
	// an operator discover it at the next uninstall.
	c.JSON(http.StatusOK, gin.H{
		"ok": true,
		"note": "既に配布済みの端末では、次回のパスワード設定まで従来のパスワードが有効なままです。" +
			"即時に解除したい端末は uninstall.guard を手動で削除してください。",
	})
}

// ListAttempts returns recent uninstall attempts.
// GET /api/v1/admin/uninstall-protection/attempts?denied_only=true&limit=100
func (h *UninstallProtectionHandler) ListAttempts(c *gin.Context) {
	deniedOnly := c.Query("denied_only") == "true"
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "100"))

	attempts, err := h.store.ListAttempts(c.Request.Context(), tenantOf(c), deniedOnly, limit)
	if err != nil {
		slog.Error("[uninstall] 試行履歴の取得に失敗", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "履歴を取得できませんでした"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": attempts, "total": len(attempts)})
}

type reportAttemptRequest struct {
	AgentID    string    `json:"agent_id"`
	Authorised bool      `json:"authorised"`
	Hostname   string    `json:"hostname"`
	OccurredAt time.Time `json:"occurred_at"`
}

// ReportAttempt records an uninstall attempt reported by an agent.
// POST /api/v1/agents/:id/uninstall-attempt
//
// Unauthenticated, like the heartbeat and update-check endpoints it sits beside.
// The caller is an agent that is in the process of being removed and may
// already have had its credentials pulled; requiring auth here would mean the
// most interesting reports — the ones from a host an attacker is dismantling —
// are exactly the ones that never arrive.
//
// The trade is that anyone who can reach the API can write rows here. That is
// acceptable for a record whose only consumer is an analyst view: the worst
// outcome is noise in a list, not a state change. It must never be allowed to
// grow into anything that alters agent state.
func (h *UninstallProtectionHandler) ReportAttempt(c *gin.Context) {
	agentID := c.Param("id")
	var req reportAttemptRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "リクエストの形式が不正です"})
		return
	}
	// The path parameter wins over the body: the body is attacker-controlled in
	// exactly the scenario this endpoint exists for.
	if agentID == "" {
		agentID = req.AgentID
	}

	occurred := req.OccurredAt
	if occurred.IsZero() {
		occurred = time.Now().UTC()
	}

	attempt := &store.UninstallAttempt{
		TenantID:   tenantOf(c),
		AgentID:    agentID,
		Hostname:   req.Hostname,
		Authorised: req.Authorised,
		OccurredAt: occurred,
	}
	if err := h.store.RecordAttempt(c.Request.Context(), attempt); err != nil {
		slog.Error("[uninstall] 試行の記録に失敗", "error", err, "agent_id", agentID)
		// Still 200: the agent cannot act on a failure here, and a non-2xx would
		// only make it log a second error about a report it cannot retry.
		c.JSON(http.StatusOK, gin.H{"ok": false})
		return
	}

	if req.Authorised {
		slog.Info("[uninstall] 承認済みのアンインストールが実行されました",
			"agent_id", agentID, "hostname", req.Hostname)
	} else {
		slog.Warn("[uninstall] アンインストールを拒否しました（パスワード不一致）",
			"agent_id", agentID, "hostname", req.Hostname)
	}
	c.JSON(http.StatusOK, gin.H{"ok": true})
}

// GuardMaterialForHeartbeat returns the tenant's guard in the shape the
// heartbeat response carries, or nil when the tenant has no password set.
//
// Exported so the agents handler can attach it without importing the store's
// error sentinel: "not configured" and "the query failed" must not collapse
// into the same nil at the call site, so the error is swallowed here — where
// it can be logged — and a nil result means only "send nothing this time".
// An agent that receives nothing simply keeps the guard it already has.
func (h *UninstallProtectionHandler) GuardMaterialForHeartbeat(c *gin.Context) map[string]any {
	g, err := h.store.GetGuard(c.Request.Context(), tenantOf(c))
	if errors.Is(err, store.ErrNoUninstallGuard) {
		return nil
	}
	if err != nil {
		slog.Warn("[uninstall] ハートビートへの保護設定添付に失敗（今回は送出せず継続）", "error", err)
		return nil
	}
	return map[string]any{
		"version":    g.Version,
		"algorithm":  g.Algorithm,
		"iterations": g.Iterations,
		"salt":       g.SaltB64,
		"digest":     g.DigestB64,
		"updated_at": g.UpdatedAt,
	}
}
