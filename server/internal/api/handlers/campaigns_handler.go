package handlers

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/detection"
)

// CampaignsHandler detects and returns threat campaigns (correlated alert groups).
type CampaignsHandler struct {
	Pool *pgxpool.Pool
}

func NewCampaignsHandler(pool *pgxpool.Pool) *CampaignsHandler {
	return &CampaignsHandler{Pool: pool}
}

type Campaign struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Description string   `json:"description"`
	AlertCount  int      `json:"alert_count"`
	AgentCount  int      `json:"agent_count"`
	MaxSeverity int      `json:"max_severity"`
	Status      string   `json:"status"` // active / contained / resolved / monitoring / inactive
	Severity    string   `json:"severity"`
	ThreatActor string   `json:"threat_actor,omitempty"`
	Tactics     []string `json:"tactics"`
	Techniques  []string `json:"techniques"`
	FirstSeen   string   `json:"first_seen"`
	LastSeen    string   `json:"last_seen"`
	Agents      []string `json:"agents"`
	RuleNames   []string `json:"rule_names"`
	IocCount    int      `json:"ioc_count"`

	// alertIDs はこのキャンペーンが束ねたアラートの ID 集合。
	//
	// 重複排除にだけ使うのでレスポンスには出さない。以前は
	//
	//   - 戦略2: 既存キャンペーンと「件数が同じ」なら重複とみなす
	//   - 最終段: Agents を "," で連結した文字列が同じなら重複とみなす
	//
	// という近似をしていた。件数一致は無関係なキャンペーン同士を
	// 巻き込み、Agents の連結は並び順に依存する (同じ集合でも順序が
	// 違えば別物と見なす)。束ねたアラートそのもので比べれば、どちらも
	// 起きない。
	alertIDs map[string]struct{}
}

// sameAlertSet は 2 つのキャンペーンが同じアラート集合を束ねているかを返す。
// 片方でも ID を持たない場合 (利用者が作ったキャンペーンなど) は比較しない。
func sameAlertSet(a, b map[string]struct{}) bool {
	if len(a) == 0 || len(b) == 0 || len(a) != len(b) {
		return false
	}
	for id := range a {
		if _, ok := b[id]; !ok {
			return false
		}
	}
	return true
}

// alertIDSet は array_agg で得た ID 配列を集合にする。
func alertIDSet(ids []string) map[string]struct{} {
	set := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if id != "" {
			set[id] = struct{}{}
		}
	}
	return set
}

// setToSortedSlice は集合を安定した順序のスライスにする。
// map の反復順は不定なので、そのまま返すとレスポンスの並びが毎回変わる。
func setToSortedSlice(set map[string]struct{}) []string {
	out := make([]string, 0, len(set))
	for v := range set {
		out = append(out, v)
	}
	sort.Strings(out)
	return out
}

// List detects threat campaigns by correlating alerts.
// GET /api/v1/campaigns?hours=72
func (h *CampaignsHandler) List(c *gin.Context) {
	hours, _ := strconv.Atoi(c.DefaultQuery("hours", "72"))
	if hours < 1 || hours > 720 {
		hours = 72
	}
	ctx := c.Request.Context()

	if h.Pool == nil {
		c.JSON(http.StatusOK, gin.H{"campaigns": []Campaign{}, "total": 0})
		return
	}

	var campaigns []Campaign

	// alerts に mitre_tactic / agent_hostname / rule_name 列は無い。
	// 実在するのは mitre_technique / agent_id / rule_id。
	//
	// タクティク別にまとめたいが、写像表は Go 側 (detection.TacticForTechnique)
	// にしかないので、SQL ではテクニック単位で集計し、タクティクへの畳み込みは
	// Go でやる。テクニックの種類数は高々数十なので行数は増えない。
	rows, err := h.Pool.Query(ctx, fmt.Sprintf(`
		SELECT
			al.mitre_technique,
			COUNT(*) AS alert_count,
			MAX(al.severity) AS max_sev,
			MIN(al.created_at)::text AS first_seen,
			MAX(al.created_at)::text AS last_seen,
			array_agg(DISTINCT COALESCE(ag.hostname,'unknown')) AS agents,
			array_agg(DISTINCT COALESCE(NULLIF(r.name,''), al.title)) AS rules,
			array_agg(DISTINCT al.id::text) AS alert_ids
		FROM alerts al
		LEFT JOIN agents ag ON ag.id = al.agent_id
		LEFT JOIN rules r ON r.id = al.rule_id
		WHERE al.created_at >= NOW() - INTERVAL '%d hours'
		  AND al.status NOT IN ('resolved','false_positive')
		  AND al.mitre_technique IS NOT NULL AND al.mitre_technique != ''
		GROUP BY 1`, hours))
	if err != nil {
		slog.Warn("campaigns: tactic query failed", "error", err)
	}
	if err == nil {
		// テクニック行をタクティクへ畳み込む。
		type tacticAgg struct {
			alertCnt  int
			maxSev    int
			firstSeen string
			lastSeen  string
			agents    map[string]struct{}
			rules     map[string]struct{}
			alertIDs  map[string]struct{}
		}
		agg := map[string]*tacticAgg{}

		for rows.Next() {
			var technique string
			var alertCnt, maxSev int
			var firstSeen, lastSeen string
			var agents, rules, alertIDs []string
			if err := rows.Scan(&technique, &alertCnt, &maxSev,
				&firstSeen, &lastSeen, &agents, &rules, &alertIDs); err != nil {
				continue
			}
			tactic := detection.TacticForTechnique(technique)
			if tactic == "" {
				// 写像表に無いテクニックは「どの段階か分からない」ので
				// キャンペーンとしてまとめない。
				continue
			}

			a := agg[tactic]
			if a == nil {
				a = &tacticAgg{
					firstSeen: firstSeen, lastSeen: lastSeen,
					agents: map[string]struct{}{}, rules: map[string]struct{}{},
					alertIDs: map[string]struct{}{},
				}
				agg[tactic] = a
			}
			a.alertCnt += alertCnt
			if maxSev > a.maxSev {
				a.maxSev = maxSev
			}
			// 文字列は ISO8601 なので辞書順比較で時刻順になる。
			if firstSeen < a.firstSeen {
				a.firstSeen = firstSeen
			}
			if lastSeen > a.lastSeen {
				a.lastSeen = lastSeen
			}
			for _, h := range agents {
				if h != "" {
					a.agents[h] = struct{}{}
				}
			}
			for _, r := range rules {
				if r != "" {
					a.rules[r] = struct{}{}
				}
			}
			for id := range alertIDSet(alertIDs) {
				a.alertIDs[id] = struct{}{}
			}
		}
		if err := rows.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows.Close()

		// map の反復順は不定なので、出力を安定させるために並べ替える。
		tactics := make([]string, 0, len(agg))
		for tactic := range agg {
			tactics = append(tactics, tactic)
		}
		sort.Slice(tactics, func(x, y int) bool {
			ax, ay := agg[tactics[x]], agg[tactics[y]]
			if ax.maxSev != ay.maxSev {
				return ax.maxSev > ay.maxSev
			}
			if ax.alertCnt != ay.alertCnt {
				return ax.alertCnt > ay.alertCnt
			}
			return tactics[x] < tactics[y]
		})
		if len(tactics) > 20 {
			tactics = tactics[:20]
		}

		for i, tactic := range tactics {
			a := agg[tactic]
			// 元のクエリの HAVING と同じ足切り。
			if a.alertCnt < 2 {
				continue
			}
			agentList := setToSortedSlice(a.agents)
			ruleList := setToSortedSlice(a.rules)
			agentCnt := len(agentList)

			desc := fmt.Sprintf("%d台のエンドポイントで%d件の関連アラートを検出", agentCnt, a.alertCnt)
			if agentCnt > 2 {
				desc += " — 横展開の可能性があります"
			}

			campaigns = append(campaigns, Campaign{
				ID:          fmt.Sprintf("camp-%d", i),
				Name:        fmt.Sprintf("%s キャンペーン", tactic),
				Description: desc,
				AlertCount:  a.alertCnt,
				AgentCount:  agentCnt,
				MaxSeverity: a.maxSev,
				Status:      "active",
				Tactics:     []string{tactic},
				FirstSeen:   a.firstSeen,
				LastSeen:    a.lastSeen,
				Agents:      agentList,
				RuleNames:   ruleList,
				alertIDs:    a.alertIDs,
			})
		}
	}

	// Strategy 2: Group by common rule name prefix (same rule family across multiple hosts)
	// ルール名は rules から JOIN で引き、紐付かないもの (組み込み検知器は
	// rule_id を埋めない) は title を使う。ホスト名は agents から引く。
	// タクティクは mitre_technique から Go 側で写すので、ここでは
	// テクニックを集めておく。
	rows2, err := h.Pool.Query(ctx, fmt.Sprintf(`
		SELECT
			SPLIT_PART(COALESCE(NULLIF(r.name,''), al.title), ' - ', 1) AS rule_family,
			COUNT(*) AS alert_count,
			COUNT(DISTINCT COALESCE(ag.hostname,'unknown')) AS agent_count,
			MAX(al.severity) AS max_sev,
			MIN(al.created_at)::text AS first_seen,
			MAX(al.created_at)::text AS last_seen,
			array_agg(DISTINCT COALESCE(ag.hostname,'unknown')) AS agents,
			array_agg(DISTINCT COALESCE(al.mitre_technique,'')) AS techniques,
			array_agg(DISTINCT al.id::text) AS alert_ids
		FROM alerts al
		LEFT JOIN agents ag ON ag.id = al.agent_id
		LEFT JOIN rules r ON r.id = al.rule_id
		WHERE al.created_at >= NOW() - INTERVAL '%d hours'
		  AND al.status NOT IN ('resolved','false_positive')
		GROUP BY 1
		HAVING COUNT(DISTINCT COALESCE(ag.hostname,'unknown')) >= 2
		   AND COUNT(*) >= 3
		ORDER BY max_sev DESC, agent_count DESC
		LIMIT 10`, hours))
	if err != nil {
		slog.Warn("campaigns: rule-family query failed", "error", err)
	}
	if err == nil {
		i := len(campaigns)
		for rows2.Next() {
			var family string
			var alertCnt, agentCnt, maxSev int
			var firstSeen, lastSeen string
			var agents, techniques, alertIDsRaw []string
			if err := rows2.Scan(&family, &alertCnt, &agentCnt, &maxSev,
				&firstSeen, &lastSeen, &agents, &techniques, &alertIDsRaw); err != nil {
				continue
			}
			ruleAlertIDs := alertIDSet(alertIDsRaw)

			// 既に同じアラート集合を束ねたキャンペーンが出ているなら重ねない。
			//
			// 以前は「件数が同じなら重複」と見ていたため、たまたま件数が
			// 一致しただけの無関係なキャンペーンを取り違えて捨てていた。
			alreadyCovered := false
			for _, existing := range campaigns {
				if sameAlertSet(existing.alertIDs, ruleAlertIDs) {
					alreadyCovered = true
					break
				}
			}
			if alreadyCovered {
				continue
			}

			// テクニックをタクティクへ写して重複を落とす。
			tacticSet := map[string]struct{}{}
			for _, t := range techniques {
				if tactic := detection.TacticForTechnique(t); tactic != "" {
					tacticSet[tactic] = struct{}{}
				}
			}
			cleanTactics := setToSortedSlice(tacticSet)

			campaigns = append(campaigns, Campaign{
				ID:          fmt.Sprintf("camp-rule-%d", i),
				Name:        fmt.Sprintf("%s — 多拠点検知", family),
				Description: fmt.Sprintf("同一ルール系統が%d台で%d件検出 — 組織的攻撃の可能性", agentCnt, alertCnt),
				AlertCount:  alertCnt,
				AgentCount:  agentCnt,
				MaxSeverity: maxSev,
				Status:      "active",
				Tactics:     cleanTactics,
				FirstSeen:   firstSeen,
				LastSeen:    lastSeen,
				Agents:      agents,
				RuleNames:   []string{family},
				alertIDs:    ruleAlertIDs,
			})
			i++
		}
		if err := rows2.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows2.Close()
	}

	// Strategy 3: Time-clustered critical alerts (burst of critical alerts within 30min window)
	//
	// ここには結果を捨てるだけの QueryRow が残っていた。Scan に
	// []interface{} を 1 引数として渡しており 5 列を受けられず必ず失敗する上、
	// 戻り値も burstCampaign も使われていなかったので削除した。
	//
	// severity = 4 を「クリティカル」としていたが、alerts.severity は
	// CHECK (1..10) で、コードベースの他所 (dashboard_stats / ops_report /
	// notification) はいずれも >= 9 を critical としている。4 は中程度に
	// あたるため、この集中検知は実質的に別の重大度を見ていた。
	rows3, err := h.Pool.Query(ctx, fmt.Sprintf(`
		WITH windows AS (
			SELECT
				date_trunc('hour', al.created_at) AS window_start,
				COUNT(*) AS cnt,
				COUNT(DISTINCT COALESCE(ag.hostname,'')) AS agents,
				array_agg(DISTINCT COALESCE(ag.hostname,'')) AS agent_list,
				array_agg(DISTINCT al.id::text) AS alert_ids,
				MIN(al.created_at)::text AS first_seen,
				MAX(al.created_at)::text AS last_seen
			FROM alerts al
			LEFT JOIN agents ag ON ag.id = al.agent_id
			WHERE al.severity >= 9
			  AND al.status NOT IN ('resolved','false_positive')
			  AND al.created_at >= NOW() - INTERVAL '%d hours'
			GROUP BY 1
		)
		SELECT window_start::text, cnt, agents, agent_list, alert_ids, first_seen, last_seen
		FROM windows WHERE cnt >= 5
		ORDER BY cnt DESC LIMIT 3`, hours))
	if err != nil {
		slog.Warn("campaigns: critical burst query failed", "error", err)
	}
	if err == nil {
		i := len(campaigns) + 100
		for rows3.Next() {
			var windowStart, firstSeen, lastSeen string
			var cnt, agentCnt int
			var agents, alertIDsRaw []string
			if err := rows3.Scan(&windowStart, &cnt, &agentCnt, &agents, &alertIDsRaw,
				&firstSeen, &lastSeen); err != nil {
				continue
			}

			hour := ""
			if len(windowStart) >= 16 {
				hour = windowStart[5:16]
			}
			cleanAgents := []string{}
			for _, a := range agents {
				if a != "" {
					cleanAgents = append(cleanAgents, a)
				}
			}

			campaigns = append(campaigns, Campaign{
				ID:          fmt.Sprintf("camp-burst-%d", i),
				Name:        fmt.Sprintf("クリティカルアラート集中 (%s)", hour),
				Description: fmt.Sprintf("1時間以内に%d件のクリティカルアラートが%d台で集中発生", cnt, agentCnt),
				AlertCount:  cnt,
				AgentCount:  agentCnt,
				// 上のクエリが severity >= 9 だけを集めるので、この
				// キャンペーンは定義上クリティカル。4 のままだと UI では
				// 「中」として出る (1-4 スケール時代の名残)。
				MaxSeverity: 9,
				Status:      "active",
				Tactics:     []string{},
				FirstSeen:   firstSeen,
				LastSeen:    lastSeen,
				Agents:      cleanAgents,
				RuleNames:   []string{},
				alertIDs:    alertIDSet(alertIDsRaw),
			})
			i++
		}
		if err := rows3.Err(); err != nil {
			slog.Warn("row iteration error", "error", err)
		}
		rows3.Close()
	}

	// 同じアラート集合を束ねたキャンペーンは 1 つに畳む。
	//
	// 以前は Agents を "," で連結した文字列をキーにしていた。ホスト集合が
	// 同じでも別のアラートを見ているキャンペーン (例: 同一ホストのタクティク別と
	// クリティカル集中) を取り違えて捨てるうえ、連結キーは並び順に依存する。
	var dedupd []Campaign
	for _, camp := range campaigns {
		dup := false
		for _, kept := range dedupd {
			if sameAlertSet(kept.alertIDs, camp.alertIDs) {
				dup = true
				break
			}
		}
		if !dup {
			dedupd = append(dedupd, camp)
		}
	}
	if dedupd == nil {
		dedupd = []Campaign{}
	}

	// Also include user-created campaigns from threat_campaigns table.
	tcExists := tableIsThere(ctx, h.Pool, "threat_campaigns")
	if tcExists {
		rows4, err4 := h.Pool.Query(ctx, `
			SELECT id::text, name, COALESCE(description,''), COALESCE(threat_actor,''),
			       status, severity,
			       first_seen, last_seen,
			       ioc_count, alert_count, techniques
			FROM threat_campaigns ORDER BY created_at DESC LIMIT 100`)
		if err4 == nil {
			defer rows4.Close()
			for rows4.Next() {
				var camp Campaign
				var firstSeen, lastSeen *time.Time
				var techniquesJSON []byte
				if rows4.Scan(&camp.ID, &camp.Name, &camp.Description, &camp.ThreatActor,
					&camp.Status, &camp.Severity, &firstSeen, &lastSeen,
					&camp.IocCount, &camp.AlertCount, &techniquesJSON) == nil {
					if firstSeen != nil {
						s := firstSeen.Format(time.RFC3339)
						camp.FirstSeen = s
					}
					if lastSeen != nil {
						s := lastSeen.Format(time.RFC3339)
						camp.LastSeen = s
					}
					_ = json.Unmarshal(techniquesJSON, &camp.Techniques)
					if camp.Techniques == nil {
						camp.Techniques = []string{}
					}
					dedupd = append(dedupd, camp)
				}
			}
			if err := rows4.Err(); err != nil {
				slog.Warn("List: rows4 の読み取りが途中で終わりました。この区画は不完全です", "error", err)
			}
		}
	}

	c.JSON(http.StatusOK, gin.H{"campaigns": dedupd, "total": len(dedupd)})
}

// Create stores a new user-defined campaign.
// POST /api/v1/campaigns
func (h *CampaignsHandler) Create(c *gin.Context) {
	var in struct {
		Name        string   `json:"name" binding:"required"`
		Description string   `json:"description"`
		ThreatActor string   `json:"threat_actor"`
		Status      string   `json:"status"`
		Severity    string   `json:"severity"`
		Techniques  []string `json:"techniques"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	if in.Status == "" {
		in.Status = "active"
	}
	if in.Severity == "" {
		in.Severity = "medium"
	}
	if in.Techniques == nil {
		in.Techniques = []string{}
	}

	ctx := c.Request.Context()
	tcExists := tableIsThere(ctx, h.Pool, "threat_campaigns")
	if !tcExists {
		// **でっち上げた id を返していました。** 画面はそれを「作成済みの
		// 1件」として持ち、一覧には出ません。
		FeatureNotInstalled(c, "キャンペーンの作成")
		return
	}

	techJSON, _ := json.Marshal(in.Techniques)
	var id string
	err := h.Pool.QueryRow(ctx, `
		INSERT INTO threat_campaigns (name, description, threat_actor, status, severity, techniques)
		VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
		in.Name, in.Description, in.ThreatActor, in.Status, in.Severity, string(techJSON)).Scan(&id)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to create campaign"})
		return
	}
	c.JSON(http.StatusCreated, gin.H{"id": id, "name": in.Name, "message": "created"})
}

// Update modifies a user-defined campaign.
// PUT /api/v1/campaigns/:id
func (h *CampaignsHandler) Update(c *gin.Context) {
	id := c.Param("id")
	var in struct {
		Name        *string  `json:"name"`
		Description *string  `json:"description"`
		ThreatActor *string  `json:"threat_actor"`
		Status      *string  `json:"status"`
		Severity    *string  `json:"severity"`
		Techniques  []string `json:"techniques"`
	}
	if err := c.ShouldBindJSON(&in); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	ctx := c.Request.Context()
	tcExists := tableIsThere(ctx, h.Pool, "threat_campaigns")
	if !tcExists {
		FeatureNotInstalled(c, "キャンペーンの更新")
		return
	}

	techJSON, _ := json.Marshal(in.Techniques)
	if in.Techniques == nil {
		techJSON = nil
	}

	tag, err := h.Pool.Exec(ctx, `
		UPDATE threat_campaigns SET
		  name         = COALESCE($2, name),
		  description  = COALESCE($3, description),
		  threat_actor = COALESCE($4, threat_actor),
		  status       = COALESCE($5, status),
		  severity     = COALESCE($6, severity),
		  techniques   = CASE WHEN $7::text IS NOT NULL THEN $7::jsonb ELSE techniques END,
		  updated_at   = NOW()
		WHERE id = $1`,
		id, in.Name, in.Description, in.ThreatActor, in.Status, in.Severity,
		func() interface{} {
			if techJSON == nil {
				return nil
			}
			return string(techJSON)
		}())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to update campaign"})
		return
	}
	if tag.RowsAffected() == 0 {
		c.JSON(http.StatusNotFound, gin.H{"error": "campaign not found"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"message": "updated"})
}

// Delete removes a user-defined campaign.
// DELETE /api/v1/campaigns/:id
func (h *CampaignsHandler) Delete(c *gin.Context) {
	id := c.Param("id")
	ctx := c.Request.Context()
	tcExists := tableIsThere(ctx, h.Pool, "threat_campaigns")
	if tcExists {
		tag, err := h.Pool.Exec(ctx, `DELETE FROM threat_campaigns WHERE id=$1`, id)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "failed to delete campaign"})
			return
		}
		if tag.RowsAffected() == 0 {
			c.JSON(http.StatusNotFound, gin.H{"error": "campaign not found"})
			return
		}
	}
	c.JSON(http.StatusOK, gin.H{"message": "deleted"})
}
