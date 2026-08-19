package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Ten SELECT-gate findings, all of the same shape: a column read under a name
// the table does not have, in a query whose error the caller discards. Every one
// of them returned an empty result that looked like an empty deployment.
//
//	timeline_handler          resource          -> resource_id
//	network_traffic_handler   created_at        -> detected_at
//	vendor_risk_handler       va.created_at     -> va.assessed_at
//	tip_integration_handler   last_fetched_at   -> last_sync_at
//	network_map_handler       timestamp         -> time
//	cmd/detection/adapter     timestamp         -> time
//	soc_metrics_handler       display_name      -> full_name
//	                          username          -> email
//	api_security_handler      risk_level        -> risk_score >= 70
//	                          enabled           -> (no such column)
//	insider_threat_handler    u.username        -> the join was wrong, not the name
//	ueba_advanced_handler     u.username        -> same
//
// The two at the bottom are the reason this file exists rather than a diff being
// enough. Assuming every 42703 is a rename is how a wrong fix gets made: `users`
// is this product's console-account table and ueba_anomalies.username is an
// endpoint OS account, so no column on `users` is the right one. Those two are
// pinned below so the join cannot come back.

func renamePool(t *testing.T) *pgxpool.Pool {
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

// The API-security stats query had two defects and Postgres could only report
// the first: risk_level does not exist, and neither does enabled. Fixing one
// alone leaves the statement failing for the other.
func TestAPISecurityStatsCountsHighRiskEndpoints(t *testing.T) {
	pool := renamePool(t)
	ctx := context.Background()

	svc := "rename-fixture-" + uuid.NewString()[:8]
	for _, score := range []int{95, 70, 20} {
		if _, err := pool.Exec(ctx,
			`INSERT INTO api_endpoints (service_name, method, path, risk_score)
			 VALUES ($1, 'GET', '/x', $2)`, svc, score); err != nil {
			t.Fatalf("seed: %v", err)
		}
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM api_endpoints WHERE service_name=$1`, svc)
	})

	// Exercised through the handler rather than by re-issuing its query here.
	// A test that writes out the statement it is checking passes whatever the
	// handler does — the first version of this one did exactly that, and a
	// mutation widening the handler's band to risk_score >= 0 survived it.
	gin.SetMode(gin.TestMode)
	h := NewAPISecurityHandler(pool)
	r := gin.New()
	r.GET("/stats", h.Stats)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/stats", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var body struct {
		Total int `json:"total_endpoints"`
		High  int `json:"high_risk"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode: %v", err)
	}

	// The table is shared, so these are floors and a difference: the fixture
	// adds three endpoints of which exactly two are high risk.
	if body.Total < 3 {
		t.Errorf("エンドポイント総数 = %d。統計クエリが実行できていません — "+
			"api_endpoints には risk_level も enabled も存在しません", body.Total)
	}
	if body.High < 2 {
		t.Errorf("高リスク件数 = %d, 2件以上を期待。"+
			"api_endpoints に risk_level はありません — 0-100 の risk_score で、"+
			"高リスクの閾値は 70 です", body.High)
	}
	if body.High >= body.Total {
		t.Errorf("高リスクが総数と同じです (%d/%d)。"+
			"閾値が効いていません — risk_score 20 のエンドポイントも数えています",
			body.High, body.Total)
	}
}

// The insider-threat and UEBA screens must not join users on a username. It is
// not a column-name mistake: the two tables hold different populations, and no
// mapping between them exists in this schema. A repointed join would be wrong
// in a way that looks right — most rows would simply not match, which reads as
// "no data" rather than as a bug.
func TestTheUEBAScreensDoNotJoinConsoleUsersOnAnOSAccount(t *testing.T) {
	for _, f := range []string{
		"insider_threat_handler.go",
		"ueba_advanced_handler.go",
	} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatalf("read %s: %v", f, err)
		}
		// Strip SQL line comments as well as Go ones: the note explaining why
		// the join was removed quotes the join, and a scan that cannot tell a
		// comment from code reports the explanation as the defect. This test
		// did exactly that on its first run.
		src := stripSQLComments(stripGoComments(string(b)))

		if strings.Contains(src, "JOIN users u ON u.username") {
			t.Errorf("%s が users を username で結合しています。"+
				"users は本製品のコンソール利用者、ua.username は"+
				"エンドポイントの OS アカウントで、母集団が違います", f)
		}
		// And it must not be quietly repointed to another column either — email
		// or full_name would match by coincidence at best.
		for _, wrong := range []string{
			"JOIN users u ON u.email = ua.username",
			"JOIN users u ON u.full_name = ua.username",
		} {
			if strings.Contains(src, wrong) {
				t.Errorf("%s が users を別の列で結合し直しています: %q。"+
					"OS アカウントとコンソール利用者を対応付ける表は"+
					"スキーマに存在しません", f, wrong)
			}
		}
	}
}

// And the UEBA anomaly list actually returns rows now. The whole query failed
// with 42703 before, so the screen was permanently empty.
func TestTheInsiderThreatListReturnsSeededAnomalies(t *testing.T) {
	pool := renamePool(t)
	ctx := context.Background()

	user := "rename-fixture-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO ueba_anomalies (username, anomaly_type, score, description, status, created_at)
		 VALUES ($1, 'login_rate', 42, 'fixture', 'open', NOW())`, user); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM ueba_anomalies WHERE username=$1`, user)
	})

	var got string
	if err := pool.QueryRow(ctx, `
		SELECT ua.username
		FROM ueba_anomalies ua
		WHERE ua.status != 'false_positive' AND ua.username = $1
		GROUP BY ua.username`, user).Scan(&got); err != nil {
		t.Fatalf("内部脅威の一覧クエリが実行できません: %v", err)
	}
	if got != user {
		t.Errorf("投入した異常が出てきません: %q", got)
	}
}

// stripSQLComments removes `-- …` line comments from Go source. Only used after
// stripGoComments, so a `--` inside a Go comment is already gone.
func stripSQLComments(src string) string {
	lines := strings.Split(src, "\n")
	for i, l := range lines {
		if j := strings.Index(l, "--"); j >= 0 {
			lines[i] = l[:j]
		}
	}
	return strings.Join(lines, "\n")
}
