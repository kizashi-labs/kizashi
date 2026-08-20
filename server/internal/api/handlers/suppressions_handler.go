package handlers

import (
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// SuppressionPublisher signals the detection engine to reload its suppression cache.
type SuppressionPublisher interface {
	Publish(subject string, data []byte) error
}

// SuppressionHandler provides alert suppression rule endpoints.
type SuppressionHandler struct {
	Store     *store.SuppressionStore
	Pool      *pgxpool.Pool        // for candidates query
	Publisher SuppressionPublisher // optional; signals detection engine on changes
}

func (h *SuppressionHandler) publishInvalidate() {
	if h.Publisher != nil {
		if err := h.Publisher.Publish("suppressions.invalidate", []byte("{}")); err != nil {
			slog.Warn("NATS publish failed", "subject", "suppressions.invalidate", "error", err)
		}
	}
}

func NewSuppressionHandler(s *store.SuppressionStore) *SuppressionHandler {
	return &SuppressionHandler{Store: s}
}

// List returns all suppression rules.
// GET /api/v1/suppressions?active=true
func (h *SuppressionHandler) List(c *gin.Context) {
	activeOnly := c.Query("active") == "true"
	rules, err := h.Store.List(c.Request.Context(), activeOnly)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "抑制ルール一覧の取得に失敗しました"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"data": rules, "total": len(rules)})
}

// Create adds a new suppression rule.
// POST /api/v1/suppressions
func (h *SuppressionHandler) Create(c *gin.Context) {
	var req struct {
		Name        string                      `json:"name"        binding:"required"`
		Description string                      `json:"description"`
		Conditions  store.SuppressionConditions `json:"conditions"`
		DurationH   int                         `json:"duration_h"`
		IsActive    *bool                       `json:"is_active"`
		ExpiresAt   *string                     `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name は必須です"})
		return
	}

	userID, _ := c.Get("user_id")
	uid, _ := userID.(string)

	r := &store.SuppressionRule{
		Name:        req.Name,
		Description: req.Description,
		Conditions:  req.Conditions,
		DurationH:   req.DurationH,
		IsActive:    true, // 省略時は有効
		CreatedBy:   &uid,
	}
	// **省略と false を区別する。** bool のままだと未指定の false と
	// 「無効なルールとして作る」が同じ値になり、後者を前者として扱って
	// 必ず有効にしていた —— 無効のつもりで作ったルールが即座に
	// アラートを落とし始める。
	if req.IsActive != nil {
		r.IsActive = *req.IsActive
	}

	// Parse optional expires_at.
	//
	// **解釈できない期限を無期限として受け入れない。** 以前はパース失敗を
	// 捨てていたので、期限付きのつもりで作ったルールが無期限で残り、
	// 止めたはずの日を過ぎてもアラートを落とし続けた。
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "expires_at は RFC3339 形式で指定してください"})
			return
		}
		r.ExpiresAt = &t
	}

	if err := h.Store.Insert(c.Request.Context(), r); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "抑制ルールの作成に失敗しました"})
		return
	}
	h.publishInvalidate()
	c.JSON(http.StatusCreated, gin.H{"message": "抑制ルールを作成しました"})
}

// resolveActiveFlag decides the on/off value from the two spellings a request
// may carry, and reports whether either was present.
//
// **旗の名前が2つあります。** DB の列は is_active と enabled の2つで、
// コンソールは以前 `{"enabled": …}` を送っていました。読み手は is_active
// しか見ないので、bool のゼロ値 false が入り、**「有効にする」を押すと
// 無効になっていました**（しかも「更新しました」と表示されます）。
//
// 画面側は is_active を送るよう直しましたが、**サーバ側でも両方を受けます。**
// この API は SDK / edr-cli / 顧客のスクリプトからも呼ばれ、そちらは
// 画面と同時には直りません。
//
// ポインタで受けるのは **「省略された」と「明示的に false」を区別する**
// ためです。bool で受けると両者が同じ値になり、省略を無効化と読みます。
func resolveActiveFlag(isActive, enabled *bool) (value bool, present bool) {
	if isActive != nil {
		return *isActive, true
	}
	if enabled != nil {
		return *enabled, true
	}
	return false, false
}

// Update replaces an existing suppression rule.
// PUT /api/v1/suppressions/:id
//
// **conditions は送られた内容で丸ごと置き換わる。** 部分更新にすると
// 「条件を消した」と「送り手がそのキーを知らない」が区別できない。
// 画面は編集後の条件をすべて送ること。
func (h *SuppressionHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var req struct {
		Name        string                      `json:"name"        binding:"required"`
		Description string                      `json:"description"`
		Conditions  store.SuppressionConditions `json:"conditions"`
		DurationH   int                         `json:"duration_h"`
		IsActive    *bool                       `json:"is_active"`
		Enabled     *bool                       `json:"enabled"`
		ExpiresAt   *string                     `json:"expires_at"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name は必須です"})
		return
	}

	// **省略された旗は「現在値」です。「有効」ではありません。**
	// 既定を true にすると、無効にしてあったルールを名前だけ直して保存した
	// 瞬間に有効化します。運用者は何も有効化していないつもりなので、
	// 抑制が突然効き始めた理由が分かりません。
	active, present := resolveActiveFlag(req.IsActive, req.Enabled)
	if !present {
		cur, err := h.Store.GetIsActive(c.Request.Context(), id)
		if err != nil {
			if errors.Is(err, store.ErrSuppressionNotFound) {
				c.JSON(http.StatusNotFound, gin.H{"error": "抑制ルールが見つかりません"})
				return
			}
			slog.Warn("suppressions: read current state failed", "id", id, "error", err)
			c.JSON(http.StatusInternalServerError, gin.H{"error": "抑制ルールの更新に失敗しました"})
			return
		}
		active = cur
	}

	r := &store.SuppressionRule{
		ID:          id,
		Name:        req.Name,
		Description: req.Description,
		Conditions:  req.Conditions,
		DurationH:   req.DurationH,
		IsActive:    active,
	}
	if req.ExpiresAt != nil && *req.ExpiresAt != "" {
		t, err := time.Parse(time.RFC3339, *req.ExpiresAt)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "expires_at は RFC3339 形式で指定してください"})
			return
		}
		r.ExpiresAt = &t
	}

	if err := h.Store.Update(c.Request.Context(), r); err != nil {
		if errors.Is(err, store.ErrSuppressionNotFound) {
			c.JSON(http.StatusNotFound, gin.H{"error": "抑制ルールが見つかりません"})
			return
		}
		slog.Warn("suppressions: update failed", "id", id, "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "抑制ルールの更新に失敗しました"})
		return
	}
	h.publishInvalidate()
	c.JSON(http.StatusOK, gin.H{"message": "抑制ルールを更新しました", "id": id})
}

// Delete removes a suppression rule.
// DELETE /api/v1/suppressions/:id
func (h *SuppressionHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	if err := h.Store.Delete(c.Request.Context(), id); err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "抑制ルールが見つかりません"})
		return
	}
	h.publishInvalidate()
	c.JSON(http.StatusOK, gin.H{"message": "抑制ルールを削除しました", "id": id})
}

// Toggle enables or disables a suppression rule.
// PUT /api/v1/suppressions/:id/toggle
func (h *SuppressionHandler) Toggle(c *gin.Context) {
	id := c.Param("id")
	// 旗の名前は2つあります（resolveActiveFlag の注記を参照）。
	// どちらも無ければ 400 —— **どちらの旗も分からないまま無効化しない。**
	var req struct {
		IsActive *bool `json:"is_active"`
		Enabled  *bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストです"})
		return
	}
	active, present := resolveActiveFlag(req.IsActive, req.Enabled)
	if !present {
		c.JSON(http.StatusBadRequest, gin.H{"error": "is_active または enabled が必要です"})
		return
	}
	if err := h.Store.SetActive(c.Request.Context(), id, active); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "抑制ルールの更新に失敗しました"})
		return
	}
	h.publishInvalidate()
	c.JSON(http.StatusOK, gin.H{"message": "抑制ルールを更新しました", "id": id, "is_active": active})
}

// SuppressCandidate represents a frequently repeating alert that may be a suppression candidate.
type SuppressCandidate struct {
	RuleName  string `json:"rule_name"`
	Hostname  string `json:"hostname"`
	Count     int    `json:"count"`
	FirstSeen string `json:"first_seen"`
	LastSeen  string `json:"last_seen"`
}

// Candidates returns alert rule+hostname combinations that fired >= threshold times
// in the last N days without being resolved — suppression candidates for noisy alerts.
// GET /api/v1/suppressions/candidates?days=7&threshold=10
func (h *SuppressionHandler) Candidates(c *gin.Context) {
	days := 7
	threshold := 10
	if v := c.Query("days"); v != "" {
		if d, err := strconv.Atoi(v); err == nil && d > 0 {
			days = d
		}
	}
	if v := c.Query("threshold"); v != "" {
		if t, err := strconv.Atoi(v); err == nil && t > 0 {
			threshold = t
		}
	}

	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"candidates": []SuppressCandidate{}})
		return
	}

	// alerts に rule_name / agent_hostname 列は無い。ルール名は rules、
	// ホスト名は agents から JOIN で引く。
	//
	// ここは「うるさいアラートの種類」でまとめるのが目的なので、
	// rules に紐付かないアラート (組み込み検知器は rule_id を埋めない) は
	// title でまとめる。r.name だけで GROUP BY すると、そういうアラートが
	// 全部 1 つの空名バケットに潰れて候補として使い物にならない。
	//
	// 期間は make_interval(days => $1) で組む。($1 || ' days')::interval は
	// $1 を text と推論させるため、pgx が Go の int を encode できず
	// "unable to encode 1 into text format for text (OID 25)" で落ちる。
	rows, err := h.Pool.Query(c.Request.Context(), `
		SELECT COALESCE(NULLIF(r.name,''), al.title) AS rule_name,
		       COALESCE(ag.hostname,'') AS hostname,
		       COUNT(*) AS cnt,
		       MIN(al.created_at) AS first_seen,
		       MAX(al.created_at) AS last_seen
		FROM alerts al
		LEFT JOIN agents ag ON ag.id = al.agent_id
		LEFT JOIN rules r ON r.id = al.rule_id
		WHERE al.created_at >= NOW() - make_interval(days => $1)
		  AND al.status NOT IN ('resolved','false_positive','closed')
		GROUP BY 1, 2
		HAVING COUNT(*) >= $2
		ORDER BY cnt DESC
		LIMIT 20`,
		days, threshold)
	if err != nil {
		slog.Warn("suppressions: candidates query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "候補の取得に失敗しました"})
		return
	}
	defer rows.Close()

	var candidates []SuppressCandidate
	for rows.Next() {
		var s SuppressCandidate
		var first, last time.Time
		if err := rows.Scan(&s.RuleName, &s.Hostname, &s.Count, &first, &last); err != nil {
			continue
		}
		s.FirstSeen = first.Format(time.RFC3339)
		s.LastSeen = last.Format(time.RFC3339)
		candidates = append(candidates, s)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("suppressions: candidates query failed", "error", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "候補の取得に失敗しました"})
		return
	}
	if candidates == nil {
		candidates = []SuppressCandidate{}
	}
	c.JSON(http.StatusOK, gin.H{
		"candidates": candidates,
		"days":       days,
		"threshold":  threshold,
	})
}
