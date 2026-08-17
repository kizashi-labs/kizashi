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
	"strings"
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
	ctx := context.Background()

	// 1 台のホストに、同じ時間バケットで
	//
	//   T1486 (impact)    severity 9 × 6 件
	//   T1059 (execution) severity 9 × 3 件
	//
	// を入れる。すると 1 ホストに対して 3 つのキャンペーンが立つ:
	//
	//   タクティク別 impact     (6 件)
	//   タクティク別 execution  (3 件)
	//   クリティカル集中        (9 件、同一バケット)
	//
	// 束ねているアラートはそれぞれ違うので、3 つとも出るのが正しい。
	//
	// 以前の重複排除は Agents を "," で連結した文字列をキーにしていたため、
	// ホストが同じというだけで後の 2 つが消えていた。severity も 4 を
	// 「クリティカル」としており、1-10 スケールの実データでは集中検知が
	// そもそも 1 件も引っかからなかった。
	var agentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ('camp-burst-single', 'linux', 'online', NOW(), NOW()) RETURNING id::text`).
		Scan(&agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM alerts WHERE agent_id = $1`, agentID) })
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, agentID) })

	for _, seed := range []struct {
		technique string
		title     string
		n         int
	}{
		{"T1486", "camp-burst-impact", 6},
		{"T1059", "camp-burst-exec", 3},
	} {
		if _, err := pool.Exec(ctx, `
			INSERT INTO alerts (agent_id, severity, title, description, status,
			                    mitre_technique, created_at)
			SELECT $1::uuid, 9, $2, 'd', 'open', $3,
			       date_trunc('hour', NOW()) + INTERVAL '1 minute'
			FROM generate_series(1, $4) g`,
			agentID, seed.title, seed.technique, seed.n); err != nil {
			t.Fatalf("seed alerts (%s): %v", seed.technique, err)
		}
	}

	h := handlers.NewCampaignsHandler(pool)
	code, resp := doJSON(t, http.MethodGet, "/api/v1/campaigns?hours=72", nil, h.List)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}

	items, _ := resp["campaigns"].([]any)
	var sawBurst, sawImpact, sawExecution bool
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		id, _ := m["id"].(string)
		name, _ := m["name"].(string)
		switch {
		case strings.HasPrefix(id, "camp-burst"):
			sawBurst = true
			// 投入した 9 件は必ず含まれる。/api/v1/campaigns は全体集計で、
			// 他パッケージのテストが同じ DB に並行でアラートを入れるため、
			// ちょうど 9 件とは限らない。
			if cnt, _ := m["alert_count"].(float64); cnt < 9 {
				t.Errorf("集中検知の件数 = %v, want >= 9", cnt)
			}
			// 集中検知は定義上クリティカル (severity >= 9 のみを集める)。
			if sev, _ := m["max_severity"].(float64); sev < 9 {
				t.Errorf("集中検知の max_severity = %v, want >= 9", sev)
			}
		case name == "impact キャンペーン":
			sawImpact = true
		case name == "execution キャンペーン":
			sawExecution = true
		}
	}

	if !sawBurst {
		t.Errorf("クリティカルアラート集中のキャンペーンが出ていない: %v", items)
	}
	if !sawImpact {
		t.Errorf("impact のタクティク別キャンペーンが出ていない: %v", items)
	}
	if !sawExecution {
		t.Errorf("execution のタクティク別キャンペーンが出ていない (同一ホストというだけで畳まれている): %v", items)
	}
}

// seedAlertsOn は既存ホストに (テクニック, タイトル, 件数) のアラートを入れる。
func seedAlertsOn(t *testing.T, pool *pgxpool.Pool, agentID, technique, title string, n int) {
	t.Helper()
	if _, err := pool.Exec(context.Background(), `
		INSERT INTO alerts (agent_id, severity, title, description, status,
		                    mitre_technique, created_at)
		SELECT $1::uuid, 8, $2, 'd', 'open', $3, NOW() - (g || ' minutes')::INTERVAL
		FROM generate_series(1, $4) g`, agentID, title, technique, n); err != nil {
		t.Fatalf("seed alerts (%s/%s): %v", technique, title, err)
	}
}

// newCampaignHost はホストを 1 台作り、後始末を登録する。
func newCampaignHost(t *testing.T, pool *pgxpool.Pool, hostname string) string {
	t.Helper()
	ctx := context.Background()
	var id string
	if err := pool.QueryRow(ctx,
		`INSERT INTO agents (hostname, os_type, status, last_seen, enrolled_at)
		 VALUES ($1, 'linux', 'online', NOW(), NOW()) RETURNING id::text`, hostname).
		Scan(&id); err != nil {
		t.Fatalf("seed agent %s: %v", hostname, err)
	}
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM alerts WHERE agent_id = $1`, id) })
	t.Cleanup(func() { _, _ = pool.Exec(ctx, `DELETE FROM agents WHERE id = $1`, id) })
	return id
}

// 戦略2 の「既に出ているキャンペーンと重複か」の判定が、件数の一致ではなく
// 束ねたアラートの一致で行われることを確認する。
//
// 以前は `existing.AlertCount == alertCnt` だったため、たまたま件数が同じ
// だけの無関係なキャンペーンを取り違えて捨てていた。
func TestCampaigns_RuleFamilyNotDroppedByCountCollision(t *testing.T) {
	pool := testPool(t)

	// タクティク impact をちょうど 6 件にする (ホスト 2 台 × 3 件)。
	// このルール系統はタクティクと同じ集合なので、最終段で正しく畳まれる。
	for _, h := range []string{"camp-coll-a0", "camp-coll-a1"} {
		seedAlertsOn(t, pool, newCampaignHost(t, pool, h), "T1486", "camp-alpha - s1", 3)
	}

	// 別のルール系統を、**合計 6 件・別のアラート**になるように作る。
	// 2 タクティクにまたがるので、どのタクティク別キャンペーンとも
	// 集合が一致しない。件数だけが impact と同じ 6。
	for _, h := range []string{"camp-coll-b0", "camp-coll-b1"} {
		id := newCampaignHost(t, pool, h)
		seedAlertsOn(t, pool, id, "T1059", "camp-beta - s1", 2) // execution
		seedAlertsOn(t, pool, id, "T1105", "camp-beta - s2", 1) // command-and-control
	}

	h := handlers.NewCampaignsHandler(pool)
	code, resp := doJSON(t, http.MethodGet, "/api/v1/campaigns?hours=72", nil, h.List)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200 (body: %v)", code, resp)
	}

	items, _ := resp["campaigns"].([]any)
	var sawBeta bool
	for _, it := range items {
		m, ok := it.(map[string]any)
		if !ok {
			continue
		}
		if name, _ := m["name"].(string); name == "camp-beta — 多拠点検知" {
			sawBeta = true
			if cnt, _ := m["alert_count"].(float64); cnt != 6 {
				t.Errorf("camp-beta の件数 = %v, want 6", cnt)
			}
		}
	}
	if !sawBeta {
		t.Errorf("件数が impact キャンペーンと同じ 6 というだけで camp-beta が捨てられている: %v", items)
	}
}
