package handlers_test

// キャンペーン検知とキルチェーン図が常に空だった件の再発防止。
//
// どちらも alerts に無い列 (category / mitre_tactic / rule_name /
// agent_hostname) を参照しており、実 DB では必ず
//
//	ERROR:  column "category" does not exist
//	ERROR:  column "mitre_tactic" does not exist
//
// で失敗していた。エラーは握りつぶして空配列を返すため、画面上は
// 「キャンペーンなし」「キルチェーン該当なし」としか見えなかった。
//
// 実在するのは mitre_technique (T1059 のようなテクニック ID) だけなので、
// タクティクへの写像は Go 側の detection.TacticForTechnique が担う。

import (
	"context"
	"fmt"
	"net/http"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/api/handlers"
)

// seedCampaignAlerts は「同一ルール系統が複数ホストで鳴っている」状況を作る。
// hosts 台 × perHost 件のアラートを、指定テクニックで入れる。
func seedCampaignAlerts(t *testing.T, pool *pgxpool.Pool, tag, technique, ruleTitle string,
	hosts, perHost, severity int) []string {
	return seedCampaignAlertsAt(t, pool, tag, technique, ruleTitle, hosts, perHost, severity, false)
}

// seedCampaignAlertsAt は sameHourBucket=true のとき、全アラートの created_at を
// 「現在時刻の時間バケットの先頭 + 1 分」に揃える。
//
// クリティカル集中の検知は date_trunc('hour', created_at) でまとめるため、
// NOW() から数分ずつずらして入れると時刻によってバケットが割れ、
// しきい値 (5 件) に届かないことがある。
func seedCampaignAlertsAt(t *testing.T, pool *pgxpool.Pool, tag, technique, ruleTitle string,
	hosts, perHost, severity int, sameHourBucket bool) []string {
	t.Helper()
	ctx := context.Background()

	createdAt := "NOW() - (g || ' minutes')::INTERVAL"
	if sameHourBucket {
		createdAt = "date_trunc('hour', NOW()) + INTERVAL '1 minute'"
	}

	var agentIDs []string
	for i := 0; i < hosts; i++ {
		hostname := fmt.Sprintf("camp-%s-%02d", tag, i)
		var agentID string
		if err := pool.QueryRow(ctx,
			`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
			 VALUES ($1, 'linux', 'online', NOW(), NOW()) RETURNING id::text`,
			hostname).Scan(&agentID); err != nil {
			t.Fatalf("seed agent: %v", err)
		}
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, agentID) })
		t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM alerts WHERE agent_id = $1`, agentID) })

		if _, err := pool.Exec(ctx, `
			INSERT INTO alerts (agent_id, severity, title, description, status,
			                    mitre_technique, created_at)
			SELECT $1::uuid, $2, $3, 'd', 'open', $4, `+createdAt+`
			FROM generate_series(1, $5) g`,
			agentID, severity, ruleTitle, technique, perHost); err != nil {
			t.Fatalf("seed alerts: %v", err)
		}
		agentIDs = append(agentIDs, agentID)
	}
	return agentIDs
}

// ── /api/v1/alerts/kill-chain-stats ──────────────────────────────

func TestKillChainStats_MapsTechniquesToStages(t *testing.T) {
	pool := testPool(t)

	// T1059 = execution      → exploit 段階
	// T1547 = persistence    → install 段階
	// T1071 = command-and-control → c2 段階
	seedCampaignAlerts(t, pool, "kcexec", "T1059", "camp-kc-exec", 1, 4, 8)
	seedCampaignAlerts(t, pool, "kcpersist", "T1547", "camp-kc-persist", 1, 3, 8)
	seedCampaignAlerts(t, pool, "kcc2", "T1071", "camp-kc-c2", 1, 2, 8)

	h := &handlers.AlertHandler{Pool: pool}
	code, resp := doJSON(t, http.MethodGet,
		"/api/v1/alerts/kill-chain-stats", nil, h.KillChainStats)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}

	data, ok := resp["data"].([]any)
	if !ok || len(data) == 0 {
		t.Fatalf("キルチェーン統計が空: %v", resp["data"])
	}

	byStage := map[string]float64{}
	var order []string
	for _, it := range data {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		stage, _ := m["stage"].(string)
		count, _ := m["count"].(float64)
		byStage[stage] = count
		order = append(order, stage)
	}

	if byStage["exploit"] < 4 {
		t.Errorf("exploit = %v, want >= 4 (T1059 を 4 件入れている): %v", byStage["exploit"], byStage)
	}
	if byStage["install"] < 3 {
		t.Errorf("install = %v, want >= 3 (T1547 を 3 件入れている): %v", byStage["install"], byStage)
	}
	if byStage["c2"] < 2 {
		t.Errorf("c2 = %v, want >= 2 (T1071 を 2 件入れている): %v", byStage["c2"], byStage)
	}

	// 段階は攻撃の進行順で返す (件数順だと図の並びが日によって変わる)。
	want := []string{"recon", "weaponize", "delivery", "exploit", "install", "c2", "actions"}
	pos := map[string]int{}
	for i, s := range want {
		pos[s] = i
	}
	for i := 1; i < len(order); i++ {
		if pos[order[i-1]] > pos[order[i]] {
			t.Errorf("段階の並びが進行順でない: %v", order)
			break
		}
	}
}

// ── /api/v1/campaigns ────────────────────────────────────────────

func TestCampaigns_DetectsTacticAndRuleFamily(t *testing.T) {
	pool := testPool(t)

	// 戦略2 には「戦略1 と件数が同じキャンペーンは重複として捨てる」
	// という既存の判定がある。同一テクニック・同一タイトルの 1 グループ
	// だけを入れると、タクティク別 (12件) とルール系統別 (12件) が
	// 同じ件数になり、後者が正しく抑制されてしまう。
	//
	// 同じタクティク (T1486 = impact) で、ルール系統だけ違う 2 グループを
	// 入れる。タクティク別は合計 18 件、ルール系統別は 12 件と 6 件になり、
	// どちらも重複判定に当たらない。
	seedCampaignAlerts(t, pool, "ransom", "T1486", "camp-ransomware - stage1", 3, 4, 9)
	seedCampaignAlerts(t, pool, "other", "T1486", "camp-other - stage1", 2, 3, 8)

	h := handlers.NewCampaignsHandler(pool)
	code, resp := doJSON(t, http.MethodGet, "/api/v1/campaigns?hours=72", nil, h.List)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}

	items, ok := resp["campaigns"].([]any)
	if !ok || len(items) == 0 {
		t.Fatalf("キャンペーンが 1 件も出ていない: %v", resp)
	}

	var sawTactic, sawRuleFamily bool
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		name, _ := m["name"].(string)
		switch {
		case name == "impact キャンペーン":
			sawTactic = true
			// ホスト名は agents から JOIN で引く。2 グループ分の 5 台。
			agents, _ := m["agents"].([]any)
			if len(agents) < 5 {
				t.Errorf("タクティクキャンペーンのホストが %d 台, want >= 5: %v", len(agents), m)
			}
		case name == "camp-ransomware — 多拠点検知":
			sawRuleFamily = true
			// タクティクはテクニックから写す。
			tactics, _ := m["tactics"].([]any)
			found := false
			for _, tv := range tactics {
				if tv == "impact" {
					found = true
				}
			}
			if !found {
				t.Errorf("ルール系統キャンペーンに impact タクティクが出ていない: %v", m)
			}
		}
	}

	if !sawTactic {
		t.Errorf("タクティク別キャンペーンが出ていない: %v", items)
	}
	if !sawRuleFamily {
		t.Errorf("ルール系統キャンペーンが出ていない: %v", items)
	}
}

func TestCampaigns_CriticalBurstUsesTenPointScale(t *testing.T) {
	pool := testPool(t)

	// 1 ホストに severity 9 を 6 件、同じ時間バケットに固定して入れる。
	// 以前は severity = 4 を「クリティカル」としていたため、
	// 1-10 スケールの実データでは 1 件も引っかからなかった。
	//
	// テクニックは写像表に無い T9999 にする。最終段に「ホスト集合が同じ
	// キャンペーンは 1 つに畳む」処理があるため、同じホストでタクティク別
	// キャンペーンも立つと集中検知の方が畳まれてしまう。写像できない
	// テクニックなら戦略1 が拾わないので、集中検知だけが残る。
	seedCampaignAlertsAt(t, pool, "burst", "T9999", "camp-burst-alert", 1, 6, 9, true)

	h := handlers.NewCampaignsHandler(pool)
	code, resp := doJSON(t, http.MethodGet, "/api/v1/campaigns?hours=72", nil, h.List)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}

	items, _ := resp["campaigns"].([]any)
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if id, _ := m["id"].(string); len(id) > 10 && id[:10] == "camp-burst" {
			return // 集中検知が出た
		}
	}
	t.Errorf("クリティカルアラート集中のキャンペーンが出ていない: %v", items)
}
