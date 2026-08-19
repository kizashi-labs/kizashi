package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/edr-platform/server/internal/metrics"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// AssetCriticalityHandler computes and stores asset criticality scores.
type AssetCriticalityHandler struct {
	pool *pgxpool.Pool
}

// NewAssetCriticalityHandler creates a new AssetCriticalityHandler.
func NewAssetCriticalityHandler(pool *pgxpool.Pool) *AssetCriticalityHandler {
	return &AssetCriticalityHandler{pool: pool}
}

type criticalityFactor struct {
	Name   string `json:"name"`
	Impact int    `json:"impact"`
	Value  string `json:"value"`
}

type criticalityResult struct {
	AgentID string              `json:"agent_id"`
	Score   int                 `json:"score"`
	Factors []criticalityFactor `json:"factors"`
	Tier    string              `json:"tier"`
	// ManualOverride marks a score an operator set by hand.
	//
	// **この印が無かったので、手で決めた重要度は一度も効いていません
	// でした**（実測 2026-08-12）。`PUT /endpoints/:id/criticality` は
	// `system_metadata` の `agent_criticality_<id>` に書いて 200 を返し、
	// **誰もその行を読みませんでした** —— 次に画面を開くと
	// `computeScoreForAgent` が OS・状態・アラート・脆弱性から計算し直し、
	// **同じ行を上書きします。** 一覧の再計算ボタン1回で消えます。
	//
	// 印が付いているので、この列を持たない古い行（計算値のキャッシュ）は
	// `false` として読まれ、手動と混ざりません。
	ManualOverride bool   `json:"manual_override"`
	Reason         string `json:"reason,omitempty"`
}

func scoreTier(score int) string {
	switch {
	case score >= 85:
		return "critical"
	case score >= 65:
		return "high"
	case score >= 40:
		return "medium"
	default:
		return "low"
	}
}

// storedCriticality returns the saved score for an agent, if there is one.
//
// **手動で決めた重要度を、計算し直しが上書きしないためのものです。**
// 行が無い／読めない／壊れているときは「無い」を返します —— ここで
// 要求を失敗させると、**一度も手で決めていない端末の重要度が見られなく
// なります。**
func (h *AssetCriticalityHandler) storedCriticality(ctx context.Context, agentID string) (*criticalityResult, bool) {
	var raw string
	if err := h.pool.QueryRow(ctx,
		`SELECT value FROM system_metadata WHERE key = $1`, criticalityKey(agentID),
	).Scan(&raw); err != nil {
		if !absent(err) {
			metrics.BackgroundFailed("criticality_override_read", err,
				"手動で決めた重要度を読めませんでした。計算値で上書きされます",
				"agent_id", agentID)
		}
		return nil, false
	}
	saved, err := manualCriticality(raw)
	if err != nil {
		// **壊れた行は「無い」と同じではありません。** 手で決めた重要度が
		// 読めなくなっているので、件数に出します。
		metrics.BackgroundFailed("criticality_override_read", err,
			"重要度の保存値を読めませんでした。手動の値があっても計算値が返ります",
			"agent_id", agentID)
		return nil, false
	}
	return saved, saved != nil
}

// manualCriticality decides whether a stored row is a manual override.
//
// **切り出してあるのは、これが唯一の判定だからです。** ここが「手動
// ではない」と答えれば計算し直しになり、上書きこそしなくなりましたが
// **手で決めた値は画面に出ません。** 判定を関数にしておくと、DB を
// 立てずに直接確かめられます（`criticality_override_test.go`）。
//
// この変更より前に書かれた行は計算値のキャッシュで、`manual_override`
// を持ちません。**それが `false` として読まれることが、移行の全部です**
// —— migration は要りません。
func manualCriticality(raw string) (*criticalityResult, error) {
	var saved criticalityResult
	if err := json.Unmarshal([]byte(raw), &saved); err != nil {
		return nil, err
	}
	if !saved.ManualOverride {
		return nil, nil
	}
	return &saved, nil
}

func criticalityKey(agentID string) string { return "agent_criticality_" + agentID }

// manualScoreOf picks the score out of the two spellings the request may use.
//
// **`binding:"required"` は 0 を弾きます。** 重要度 0 は正しい値なので、
// 「未指定」と「0」を型で分けます —— `int` のままだと、**0 点にしたい
// 要求と、点数を書き忘れた要求が同じ形**です。
func manualScoreOf(score, manualScore *int) (int, bool) {
	v := score
	if v == nil {
		v = manualScore
	}
	if v == nil || *v < 0 || *v > 100 {
		return 0, false
	}
	return *v, true
}

// manualResult builds what SetManualScore stores.
//
// **書く側と読む側を1つの検査で結ぶために切り出してあります。**
// 検査が自分で同じ構造体を組み立てていると、**書く側が印を付けるのを
// やめても検査は通ります** —— 実際に、その変異が生き残りました。
// いまは `manualResult` が作ったものを `manualCriticality` に通します。
func manualResult(agentID string, score int, reason string) *criticalityResult {
	return &criticalityResult{
		AgentID: agentID,
		Score:   score,
		Factors: []criticalityFactor{
			{Name: "manual_override", Impact: 0, Value: reason},
		},
		Tier: scoreTier(score),
		// **この印が、計算し直しから守ります。** 印の無い行（この変更より
		// 前に計算値として書かれたもの）は手動として読まれません。
		ManualOverride: true,
		Reason:         reason,
	}
}

// criticalityInputs is everything the score depends on.
//
// **点数の作り方を1箇所にするための型です。** 1台ぶんを見る経路と一覧を
// 作る経路で ladder を書き写すと、**片方だけ直した日に、同じ端末が画面に
// よって別の重要度で出ます。**
type criticalityInputs struct {
	agentID      string
	osType       string
	osVersion    string
	status       string
	activeAlerts int
	highVulns    int
}

// scoreAgent turns the inputs into a score. No database, no request.
func scoreAgent(in criticalityInputs) *criticalityResult {
	score := 50
	var factors []criticalityFactor

	// +20 if server OS (linux/server type)
	combined := strings.ToLower(in.osType + " " + in.osVersion)
	if strings.Contains(combined, "server") || strings.Contains(combined, "linux") ||
		strings.Contains(combined, "centos") || strings.Contains(combined, "rhel") ||
		strings.Contains(combined, "debian") {
		score += 20
		factors = append(factors, criticalityFactor{
			Name:   "server_os",
			Impact: 20,
			Value:  in.osType + " " + in.osVersion,
		})
	}

	// -10 if offline
	//
	// 'inactive'(30日以上未確認で DeadAgentCleanup が退役判定した状態)も対象に含める。
	// 'offline' だけを見ていると、**より長く死んでいるホストほど減点されない**という
	// 反転が起きる(数時間落ちた 'offline' は -10、30日死んだ 'inactive' は減点なし)。
	if in.status == "offline" || in.status == "inactive" {
		score -= 10
		factors = append(factors, criticalityFactor{
			Name:   "offline_penalty",
			Impact: -10,
			Value:  in.status,
		})
	}

	if in.activeAlerts > 0 {
		score += 15
		factors = append(factors, criticalityFactor{
			Name:   "active_alerts",
			Impact: 15,
			Value:  fmt.Sprintf("%d", in.activeAlerts),
		})
	}

	if in.highVulns > 0 {
		score += 10
		factors = append(factors, criticalityFactor{
			Name:   "high_vulnerabilities",
			Impact: 10,
			Value:  fmt.Sprintf("%d", in.highVulns),
		})
	}

	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	if factors == nil {
		factors = []criticalityFactor{}
	}

	return &criticalityResult{
		AgentID: in.agentID,
		Score:   score,
		Factors: factors,
		Tier:    scoreTier(score),
	}
}

// agentCriticalityInputs loads one agent's inputs.
//
// **読めなかった 0 は、その資産の重要度を静かに下げます**（アラートで
// 15点、脆弱性で10点）。この関数は error を返せるので、返します。
func (h *AssetCriticalityHandler) agentCriticalityInputs(ctx context.Context, agentID string) (criticalityInputs, error) {
	in := criticalityInputs{agentID: agentID}
	if err := h.pool.QueryRow(ctx,
		`SELECT os_type, COALESCE(os_version, ''), status FROM agents WHERE id = $1`, agentID,
	).Scan(&in.osType, &in.osVersion, &in.status); err != nil {
		return in, err
	}
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM alerts WHERE agent_id = $1 AND status NOT IN ('resolved', 'closed')`, agentID,
	).Scan(&in.activeAlerts); err != nil && !absent(err) {
		return in, err
	}
	if err := h.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM vulnerabilities WHERE agent_id = $1 AND severity IN ('high','critical')`, agentID,
	).Scan(&in.highVulns); err != nil && !absent(err) {
		return in, err
	}
	return in, nil
}

func (h *AssetCriticalityHandler) computeScoreForAgent(c *gin.Context, agentID string) (*criticalityResult, error) {
	ctx := c.Request.Context()

	// **手動が先です。** 保存されているのが手動なら、そのまま返して
	// 計算も上書きもしません。
	if saved, ok := h.storedCriticality(ctx, agentID); ok {
		saved.AgentID = agentID
		saved.Tier = scoreTier(saved.Score)
		return saved, nil
	}

	in, err := h.agentCriticalityInputs(ctx, agentID)
	if err != nil {
		return nil, err
	}

	// **計算値は保存しません。**
	//
	// 元は算出のあと `agent_criticality_<id>` に書いていましたが、**その行を
	// 読むものはありませんでした** —— 毎回計算し直すので、保存しても誰の
	// 役にも立ちません。役に立たないどころか、**手動で決めた重要度を
	// 上書きしていたのがその書き込みです。**
	return scoreAgent(in), nil
}

// GetScore computes and returns the criticality score for a specific agent.
// GET /api/v1/endpoints/:id/criticality
func (h *AssetCriticalityHandler) GetScore(c *gin.Context) {
	agentID := c.Param("id")
	result, err := h.computeScoreForAgent(c, agentID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to compute criticality score"})
		return
	}
	c.JSON(http.StatusOK, result)
}

// criticalityListRow is one line of the asset-criticality console.
//
// **画面が読む項目に合わせてあります。** 一覧に無かったのは経路だけでは
// ありません —— 点数を作る側は `agent_id`／`score` を返し、画面は
// `id`／`criticality_score`／`hostname`／`os` を読んでいました。
// 経路だけ足しても、全行が「点数0の名無し」で並びます。
type criticalityListRow struct {
	ID           string              `json:"id"`
	Hostname     string              `json:"hostname"`
	OS           string              `json:"os"`
	Score        int                 `json:"criticality_score"`
	Tier         string              `json:"tier"`
	Factors      []criticalityFactor `json:"factors"`
	Manual       bool                `json:"manual_override"`
	ManualScore  *int                `json:"manual_score,omitempty"`
	ManualReason string              `json:"manual_reason,omitempty"`
	Calculated   time.Time           `json:"last_calculated"`
	IsOnline     bool                `json:"is_online"`
}

// criticalityAgentRow is one agents row as the console list reads it.
type criticalityAgentRow struct {
	id, hostname, osType, osVersion, status string
	lastSeen                                *time.Time
}

// listInputs maps one agents row plus the two count maps onto the scorer's
// inputs.
//
// **切り出してあるのは、ここが落とし物をしても誰も気づかないからです。**
// `status` を渡し忘れれば一覧だけオフライン減点が効かず、`alerts` と
// `vulns` を取り違えれば点数が 15 と 10 で入れ替わります —— どちらも
// 「それらしい点数」で並ぶので、画面からは分かりません。
func listInputs(a criticalityAgentRow, alerts, vulns map[string]int) criticalityInputs {
	return criticalityInputs{
		agentID:      a.id,
		osType:       a.osType,
		osVersion:    a.osVersion,
		status:       a.status,
		activeAlerts: alerts[a.id],
		highVulns:    vulns[a.id],
	}
}

// identityRow fills the parts of a console row that do not depend on the score.
func identityRow(a criticalityAgentRow) criticalityListRow {
	return criticalityListRow{
		ID:       a.id,
		Hostname: a.hostname,
		OS:       strings.TrimSpace(a.osType + " " + a.osVersion),
		IsOnline: a.status == "online",
	}
}

// manualRow finishes a row from a stored manual override.
//
// **検査が同じ構造体を組み立て直さないために切り出してあります。**
// 組み立て直していたときは、**`manual_score` を落とす変異が生き残り
// ました** —— 画面の上書きダイアログは、そこから前の値を出します。
func manualRow(row criticalityListRow, m storedManual) criticalityListRow {
	score := m.result.Score
	row.Score = score
	row.Tier = scoreTier(score)
	row.Factors = m.result.Factors
	row.Manual = true
	row.ManualScore = &score
	row.ManualReason = m.result.Reason
	row.Calculated = m.updated
	return row
}

// computedRow finishes a row from a freshly computed score.
//
// `now` は呼び出し側から渡します。**いま計算した値なので、保存していない
// 以上これ以外に正直な時刻はありません。**
func computedRow(row criticalityListRow, r *criticalityResult, now time.Time) criticalityListRow {
	row.Score = r.Score
	row.Tier = r.Tier
	row.Factors = r.Factors
	row.Calculated = now
	return row
}

// criticalityListLimit bounds one page of the console.
//
// **上限に当たったことは応答に出します。** 黙って切ると、1000 台目より
// 後ろの端末は「重要度が低い」ではなく**画面に存在しない**ことになり、
// 一覧を眺めている人からは区別がつきません。
const criticalityListLimit = 1000

// scoreAllAgents computes the console rows in a fixed number of queries.
//
// **1台ずつ計算すると、この一覧だけで問い合わせが 3×N 本になります**
// （1000 台で 3000 本）。入力を3本のまとめ読みで集めて、点数は1台ぶんと
// 同じ `scoreAgent` に通します。
func (h *AssetCriticalityHandler) scoreAllAgents(ctx context.Context) ([]criticalityListRow, bool, error) {
	rows, err := h.pool.Query(ctx, `
		SELECT id::text, COALESCE(hostname,''), COALESCE(os_type,''),
		       COALESCE(os_version,''), COALESCE(status,''), last_seen
		  FROM agents ORDER BY created_at DESC LIMIT $1`, criticalityListLimit+1)
	if err != nil {
		return nil, false, err
	}
	defer rows.Close()

	var agents []criticalityAgentRow
	for rows.Next() {
		var a criticalityAgentRow
		if err := rows.Scan(&a.id, &a.hostname, &a.osType, &a.osVersion, &a.status, &a.lastSeen); err != nil {
			return nil, false, err
		}
		agents = append(agents, a)
	}
	if err := rows.Err(); err != nil {
		return nil, false, err
	}
	truncated := len(agents) > criticalityListLimit
	if truncated {
		agents = agents[:criticalityListLimit]
	}

	alerts, err := h.countByAgent(ctx,
		`SELECT agent_id::text, COUNT(*) FROM alerts
		  WHERE agent_id IS NOT NULL AND status NOT IN ('resolved','closed')
		  GROUP BY agent_id`)
	if err != nil {
		return nil, false, err
	}
	vulns, err := h.countByAgent(ctx,
		`SELECT agent_id::text, COUNT(*) FROM vulnerabilities
		  WHERE agent_id IS NOT NULL AND severity IN ('high','critical')
		  GROUP BY agent_id`)
	if err != nil {
		return nil, false, err
	}
	manual, err := h.allManualCriticality(ctx)
	if err != nil {
		return nil, false, err
	}

	now := time.Now().UTC()
	out := make([]criticalityListRow, 0, len(agents))
	for _, a := range agents {
		row := identityRow(a)
		if m, ok := manual[a.id]; ok {
			out = append(out, manualRow(row, m))
			continue
		}
		out = append(out, computedRow(row, scoreAgent(listInputs(a, alerts, vulns)), now))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	return out, truncated, nil
}

// countByAgent runs a `agent_id, COUNT(*)` query into a map.
func (h *AssetCriticalityHandler) countByAgent(ctx context.Context, sql string) (map[string]int, error) {
	out := map[string]int{}
	rows, err := h.pool.Query(ctx, sql)
	if err != nil {
		// **テーブルがまだ無い配置では 0 で続けます。** 読めなかったのと
		// 「1件も無い」を分けるのは呼び出し側の仕事ではありません ——
		// ここで分けます。
		if absent(err) {
			return out, nil
		}
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var id string
		var n int
		if err := rows.Scan(&id, &n); err != nil {
			return nil, err
		}
		out[id] = n
	}
	return out, rows.Err()
}

type storedManual struct {
	result  *criticalityResult
	updated time.Time
}

// allManualCriticality reads every manual override in one query.
func (h *AssetCriticalityHandler) allManualCriticality(ctx context.Context) (map[string]storedManual, error) {
	out := map[string]storedManual{}
	rows, err := h.pool.Query(ctx,
		`SELECT key, value, COALESCE(updated_at, NOW()) FROM system_metadata WHERE key LIKE $1`,
		criticalityKey("")+"%")
	if err != nil {
		if absent(err) {
			return out, nil
		}
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var key, raw string
		var updated time.Time
		if err := rows.Scan(&key, &raw, &updated); err != nil {
			return nil, err
		}
		saved, err := manualCriticality(raw)
		if err != nil {
			metrics.BackgroundFailed("criticality_override_read", err,
				"重要度の保存値を読めませんでした。手動の値があっても計算値が返ります",
				"key", key)
			continue
		}
		if saved == nil {
			continue // 印の無い古い行（計算値のキャッシュ）です
		}
		out[strings.TrimPrefix(key, criticalityKey(""))] = storedManual{result: saved, updated: updated}
	}
	return out, rows.Err()
}

// List returns the criticality of every endpoint, most critical first.
// GET /api/v1/endpoints/criticality
//
// **この経路がありませんでした**（実測 2026-08-12）。画面
// （`app/admin/asset-criticality/page.tsx`）はここから一覧を取りますが、
// router には `/:id/criticality`・`/criticality/bulk`・`PUT` しか
// ありませんでした —— gin は 404 を返し、`useQuery` の失敗は空配列に
// なって、**資産が1台も無い画面**として出ていました。
func (h *AssetCriticalityHandler) List(c *gin.Context) {
	rows, truncated, err := h.scoreAllAgents(c.Request.Context())
	if !ReadOK(c, err) {
		return
	}
	body := gin.H{"data": rows, "total": len(rows)}
	if truncated {
		body["truncated"] = true
		body["limit"] = criticalityListLimit
	}
	c.JSON(http.StatusOK, body)
}

// BulkScore computes criticality scores for all agents and returns them sorted.
// POST /api/v1/endpoints/criticality/bulk
//
// **`List` と同じものを返します。** 計算値を保存しなくなったので、
// 「再計算」で変わるものはありません —— 一覧を開くたびに計算しています。
// 画面のボタンを残すかどうかは `docs/判断待ちの一覧.md` に出してあります。
func (h *AssetCriticalityHandler) BulkScore(c *gin.Context) {
	h.List(c)
}

// ClearManualScore drops a manual override so the score goes back to computed.
// DELETE /api/v1/endpoints/:id/criticality
//
// **手動にしたあと、自動計算に戻す方法がありませんでした。** 元は
// 「次の表示で勝手に戻る」形でしたが、それは解除ではなく、手動が
// 機能していなかっただけです（`computeScoreForAgent` が同じ行を上書き
// していました）。手動が効くようにした以上、外す経路が要ります。
//
// **行を消すだけです。** 印の付いた行が無くなれば `storedCriticality` は
// 「無い」と答え、次の表示から `scoreAgent` の計算値に戻ります ——
// 「自動に戻った」という別の状態を新しく作ると、それ自体が読み手の
// 要る行になります。
//
// 消す行が無くても 200 で答えます。**「もともと自動だった」と「いま
// 自動にした」は、利用者にとって同じ結果**です —— 404 を返すと、画面は
// 「自動に戻せませんでした」と出しますが、実際には自動です。
func (h *AssetCriticalityHandler) ClearManualScore(c *gin.Context) {
	agentID := c.Param("id")
	if _, err := h.pool.Exec(c.Request.Context(),
		`DELETE FROM system_metadata WHERE key = $1`, criticalityKey(agentID),
	); err != nil {
		// **消せなかったことを 200 で隠さないこと。** 手動のまま残って
		// いるのに画面が「自動に戻しました」と出すと、次に一覧を開いた
		// 人は手動の点数を自動の算出結果として読みます。
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to clear manual score"})
		return
	}

	// 消したあとの点数を返します。**画面が再取得を待たずに、戻った先の
	// 点数をその場で出せます。**
	result, err := h.computeScoreForAgent(c, agentID)
	if err != nil {
		if strings.Contains(err.Error(), "no rows") {
			c.JSON(http.StatusNotFound, gin.H{"error": "Agent not found"})
			return
		}
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to compute criticality score"})
		return
	}
	c.JSON(http.StatusOK, result)
}

// SetManualScore stores a manual override for an agent's criticality score.
// PUT /api/v1/endpoints/:id/criticality
func (h *AssetCriticalityHandler) SetManualScore(c *gin.Context) {
	agentID := c.Param("id")
	var req struct {
		// **綴りが2つあります。** 画面は `manual_score` を送りますが、
		// ここは `score` しか読まず、しかも `binding:"required"` でした
		// —— 上書きの保存は**必ず 400 で落ちていました**（実測
		// 2026-08-12）。両方受けます。
		Score       *int   `json:"score"`
		ManualScore *int   `json:"manual_score"`
		Reason      string `json:"reason"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	score, ok := manualScoreOf(req.Score, req.ManualScore)
	if !ok {
		c.JSON(http.StatusBadRequest, gin.H{
			"error": "score（または manual_score）を 0〜100 で指定してください",
		})
		return
	}

	result := manualResult(agentID, score, req.Reason)

	key := criticalityKey(agentID)
	scoreJSON, _ := json.Marshal(result)
	_, err := h.pool.Exec(c.Request.Context(),
		`INSERT INTO system_metadata (key, value) VALUES ($1, $2)
		 ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = NOW()`,
		key, string(scoreJSON),
	)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to store manual score"})
		return
	}

	c.JSON(http.StatusOK, result)
}
