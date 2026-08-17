package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// alerts.severity is a smallint scored 1–10. Three statements in
// predictive_analytics_handler.go compared it against the severity *labels*:
//
//	fetchStats  WHERE severity = 'high'                        -> 22P02
//	fetchStats  WHERE severity = 'medium'                      -> 22P02
//	GetTrends   FILTER (WHERE severity IN ('critical','high')) -> 22P02
//
// Measured against a database seeded with 1 critical (9), 2 high (7,8) and
// 3 medium (4,5,6):
//
//	                                     before               after
//	fetchStats.highAlerts                0  (22P02)           2
//	fetchStats.mediumAlerts              0  (22P02)           3
//	GetTrends  rows returned             0  (22P02)           1 day
//
// Every row was scanned with `_ =` and GetTrends swallowed its error with
// `if err == nil`, so none of the three ever surfaced. The costs:
//
//   - computeVulnRisk weights high 2 and medium 1 against critical's 4, so a
//     fleet carrying 500 high-severity alerts and no criticals reported a
//     vulnerability risk of exactly 0.00. GetRiskForecast extrapolated that 0
//     out to 90 days and listed 「高優先度アラート数: 0」 among its key drivers.
//   - GetTrends returned 30 days built from the zero value of its row struct:
//     alert_count 0, anomaly_count 0, risk_score 0.00 and patch_compliance 1.00
//     for every day of the month. A flat, perfect month indistinguishable from
//     a genuinely quiet one, from a query that never ran.
//
// Both endpoints advertised "data_source": "live" throughout.

func predictivePool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	dsn := os.Getenv("TEST_DATABASE_URL")
	if dsn == "" {
		t.Skip("TEST_DATABASE_URL not set - skipping DB integration tests")
	}
	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		t.Fatalf("connect: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// seedSeverityLadder inserts one alert at each severity 1..10 against a
// throwaway agent and returns its id. Scoping every assertion to that agent
// keeps the counts exact on a database other packages are writing to.
func seedSeverityLadder(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	ctx := context.Background()
	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'severity-ladder-fixture','linux','online',NOW())`, agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM alerts WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})
	for sev := 1; sev <= 10; sev++ {
		if _, err := pool.Exec(ctx,
			`INSERT INTO alerts (agent_id,severity,status,title,description,created_at)
			 VALUES ($1::uuid,$2,'open','severity ladder','',NOW() - INTERVAL '1 day')`,
			agentID, sev); err != nil {
			t.Fatalf("seed severity %d: %v", sev, err)
		}
	}
	return agentID
}

// countBand runs one of the band predicates against the fixture agent.
func countBand(t *testing.T, pool *pgxpool.Pool, agentID, predicate string) int {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM alerts WHERE agent_id=$1::uuid AND `+predicate, agentID).Scan(&n); err != nil {
		t.Fatalf("band %q did not run: %v", predicate, err)
	}
	return n
}

// The headline: each band predicate executes and selects the severities the
// platform says it should. A label compared against the smallint column does
// not reach this assertion — it fails to run at all.
func TestSeverityBandsSelectTheRightSeverities(t *testing.T) {
	pool := predictivePool(t)
	agentID := seedSeverityLadder(t, pool)

	for _, tc := range []struct {
		name      string
		predicate string
		want      int
		covers    string
	}{
		{"critical", sevCritical, 2, "9,10"},
		{"high", sevHigh, 2, "7,8"},
		{"medium", sevMedium, 3, "4,5,6"},
		{"high or above", sevHighOrAbove, 4, "7,8,9,10"},
	} {
		if got := countBand(t, pool, agentID, tc.predicate); got != tc.want {
			t.Errorf("%s (%s): 重大度 %s の %d 件を期待しましたが %d 件でした。"+
				"alerts.severity は smallint (1-10) です",
				tc.name, tc.predicate, tc.covers, tc.want, got)
		}
	}
}

// And the bands do not overlap or leave a gap: critical, high, medium and the
// implicit low band must partition 1..10 exactly once. A band that quietly
// widened would otherwise double-count alerts into the risk score.
func TestSeverityBandsPartitionTheScale(t *testing.T) {
	pool := predictivePool(t)
	agentID := seedSeverityLadder(t, pool)

	total := countBand(t, pool, agentID, sevCritical) +
		countBand(t, pool, agentID, sevHigh) +
		countBand(t, pool, agentID, sevMedium) +
		countBand(t, pool, agentID, `severity BETWEEN 1 AND 3`)
	if total != 10 {
		t.Errorf("critical/high/medium/low の合計が %d 件です (10 件であるべき)。"+
			"帯域が重複しているか、抜けがあります", total)
	}

	// No severity may satisfy two bands at once.
	for _, pair := range [][2]string{
		{sevCritical, sevHigh},
		{sevCritical, sevMedium},
		{sevHigh, sevMedium},
	} {
		if n := countBand(t, pool, agentID, "("+pair[0]+") AND ("+pair[1]+")"); n != 0 {
			t.Errorf("%q と %q が %d 件重複しています", pair[0], pair[1], n)
		}
	}
}

// fetchStats must map each band onto the field the risk model reads.
//
// Asserted against the source rather than by seeding and diffing two
// fetchStats calls. fetchStats counts the whole table, so a delta across two
// reads is at the mercy of every other package sharing this database — one of
// them deleting its fixture between the reads makes the delta smaller than
// what was seeded, and the test fails pointing at the code. That is the same
// shared-database trap the counts themselves were measured against; a gate
// that reports it as a defect in the thing it guards is worse than no gate.
//
// The band predicates are verified against real rows by
// TestSeverityBandsSelectTheRightSeverities above, which scopes every count to
// its own fixture agent. What is left to check is the wiring: that the entry
// filling highAlerts uses sevHigh and not some other band. A swap is exactly
// the mutation this must catch.
func TestFetchStatsPairsEachBandWithItsOwnField(t *testing.T) {
	b, err := os.ReadFile("predictive_analytics_handler.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	src := stripGoComments(string(b))

	for _, tc := range []struct{ field, band string }{
		{"s.criticalAlerts", "sevCritical"},
		{"s.highAlerts", "sevHigh"},
		{"s.mediumAlerts", "sevMedium"},
	} {
		i := strings.Index(src, "{&"+tc.field+",")
		if i < 0 {
			t.Errorf("%s を読み込む箇所が見つかりません", tc.field)
			continue
		}
		// The entry ends at the start of the next one.
		entry := src[i:]
		if j := strings.Index(entry[1:], "{&s."); j >= 0 {
			entry = entry[:j+1]
		}
		if !strings.Contains(entry, tc.band) {
			t.Errorf("%s が %s を使っていません: %s\n"+
				"  帯域と代入先が入れ替わると、リスクスコアの重み付けが"+
				"静かに間違ったまま動き続けます",
				tc.field, tc.band, strings.TrimSpace(entry))
		}
		// And not a different band as well — a widened predicate double-counts.
		for _, other := range []string{"sevCritical", "sevHigh", "sevMedium"} {
			if other != tc.band && strings.Contains(entry, other) {
				t.Errorf("%s が %s と %s の両方を参照しています", tc.field, tc.band, other)
			}
		}
	}
}

// A count that could not be read is not a count of zero. fetchStats used to
// discard every scan error with `_ =`, which is why three broken statements
// survived: the numbers they produced looked exactly like a quiet deployment.
func TestFetchStatsReportsAFailedReadInsteadOfZero(t *testing.T) {
	pool := predictivePool(t)
	h := NewPredictiveAnalyticsHandler(pool)

	dead, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := h.fetchStats(dead)
	if err == nil {
		t.Fatal("読み取りに失敗してもエラーが返りませんでした。" +
			"ゼロ件と「読めなかった」は別の事実で、後者を前者として報告すると" +
			"壊れたクエリが静かなデプロイと見分けられなくなります")
	}
	// The error must name the read that failed. fetchStats runs several
	// statements, and an assertion satisfied by *any* of them failing lets a
	// later one cover for an earlier one being silenced — the count queries
	// could go back to `_ =` and the incidents probe alone would still keep
	// this test green.
	if !strings.Contains(err.Error(), "predictive: read ") {
		t.Errorf("エラーが失敗した読み取りを特定していません: %q。"+
			"どの統計が読めなかったのかが分からないと、"+
			"あるクエリの沈黙を別のクエリの失敗が覆い隠します", err)
	}
}

// GetTrends must not answer with a month of fabricated days when its query
// fails. Before this change it returned 200 and 30 entries of alert_count 0,
// anomaly_count 0, risk_score 0.00 and patch_compliance 1.00.
func TestGetTrendsDoesNotFabricateAMonthOfZeroes(t *testing.T) {
	pool := predictivePool(t)
	gin.SetMode(gin.TestMode)
	h := NewPredictiveAnalyticsHandler(pool)

	r := gin.New()
	r.GET("/trends", h.GetTrends)

	dead, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodGet, "/trends", nil).WithContext(dead)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, req)

	if w.Code == http.StatusOK {
		var body struct {
			Trends []struct {
				AlertCount      int     `json:"alert_count"`
				PatchCompliance float64 `json:"patch_compliance"`
			} `json:"trends"`
		}
		_ = json.Unmarshal(w.Body.Bytes(), &body)
		t.Errorf("クエリ失敗時に 200 と %d 日分のトレンドを返しました。"+
			"読めなかった月を「アラート0件・パッチ準拠100%%」の月として"+
			"描画することになります", len(body.Trends))
	}
	if w.Code != http.StatusServiceUnavailable {
		t.Errorf("status %d を返しました (503 を期待)", w.Code)
	}
}

// GetTrends must return real days for a database that has alerts.
//
// Reporting the query failure exposed a second, independent reason this
// endpoint could never have produced data: DATE(created_at) yields a date
// (OID 1082) and the row scans it into a string, which pgx rejects in binary
// format. Every row would have been dropped by `_ = dbRows.Scan(...)` even with
// the severity filter corrected, and the month would still have come out flat.
// Two separate defects, one visible outcome, and neither could be seen while
// the errors were discarded.
func TestGetTrendsReturnsRealDays(t *testing.T) {
	pool := predictivePool(t)
	seedSeverityLadder(t, pool)

	gin.SetMode(gin.TestMode)
	h := NewPredictiveAnalyticsHandler(pool)
	r := gin.New()
	r.GET("/trends", h.GetTrends)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/trends", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}

	var body struct {
		Trends []struct {
			Date         string `json:"date"`
			AlertCount   int    `json:"alert_count"`
			AnomalyCount int    `json:"anomaly_count"`
		} `json:"trends"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if len(body.Trends) != 30 {
		t.Fatalf("%d 日分を返しました (30日を期待)", len(body.Trends))
	}
	// The fixture put 10 alerts on yesterday, 4 of them severity >= 7. If every
	// row were dropped by a failed scan, all 30 days would read zero — which is
	// exactly what this endpoint did.
	var alerts, anomalies int
	for _, d := range body.Trends {
		alerts += d.AlertCount
		anomalies += d.AnomalyCount
	}
	if alerts == 0 {
		t.Error("30日分すべてがアラート0件です。行が1件も読めていません — " +
			"DATE(created_at) は date 型で、文字列には直接スキャンできません")
	}
	if anomalies == 0 {
		t.Error("30日分すべてが異常0件です。重大度フィルタが機能していません")
	}
}

// The severity labels must not reappear in a comparison against the column.
// This is the shape of the original defect, and it is not one Go's type
// checker can catch — the SQL is a string literal.
func TestNoSeverityLabelIsComparedAgainstTheColumn(t *testing.T) {
	b, err := os.ReadFile("predictive_analytics_handler.go")
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	src := stripGoComments(string(b))

	bad := regexp.MustCompile(`(?i)severity\s*(=|IN)\s*\(?\s*'(critical|high|medium|low)'`)
	for _, m := range bad.FindAllString(src, -1) {
		t.Errorf("重大度ラベルとの比較が残っています: %q。"+
			"alerts.severity は smallint です (critical 9-10 / high 7-8 / "+
			"medium 4-6 / low 1-3)", m)
	}
}

// stripGoComments removes comments before a source scan, so a comment quoting
// the defect it describes is not mistaken for the defect.
func stripGoComments(src string) string {
	src = regexp.MustCompile(`(?s)/\*.*?\*/`).ReplaceAllString(src, "")
	return regexp.MustCompile(`(?m)(^|[^:])//.*$`).ReplaceAllString(src, "$1")
}
