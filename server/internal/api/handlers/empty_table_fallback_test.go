package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Three screens chose their data source by asking whether a table EXISTS, then
// fell back to a derived source only when it did not. All three primary tables
// are created by migrations and written by nothing:
//
//	fim_events     — no INSERT anywhere in the tree
//	dns_alerts     — no INSERT anywhere in the tree
//	tip_platforms  — migration 219 creates it, nothing populates it
//
// So the existence check passed every time, the fallback never ran, and each
// screen returned an empty list while the data it wanted sat in `events` or
// `threat_feeds`. Nothing failed: no error, no log line, a 200 with an empty
// array. The table existing is not the same as the table having rows, and only
// the second question is the one worth asking.
//
// The repair is the same in all three: read the primary, and fall through when
// it yields no rows rather than when it is absent.

// tablesWrittenByNobody are the primary sources above. Each entry is the reason
// the check matters, and the test asserts both halves — that nothing writes the
// table, and that the handler still answers from the fallback.
var tablesWrittenByNobody = map[string]string{
	"fim_events":    "FIM の改ざん一覧。実データは events (event_type='file') にあります",
	"dns_alerts":    "DNS セキュリティのアラート。実データは events (event_type='dns') にあります",
	"tip_platforms": "TIP 連携の一覧。実データは threat_feeds にあります",
}

// If one of these ever gains a writer, the fallback ordering needs revisiting
// and this test says so rather than silently continuing to assert the old
// arrangement.
func TestTheFallbackPrimariesStillHaveNoWriter(t *testing.T) {
	root := "../../.."
	var srcs []string
	err := walkGoSources(root, func(path, src string) {
		if strings.Contains(path, "_test.go") {
			return
		}
		srcs = append(srcs, stripSQLComments(stripGoComments(src)))
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	if len(srcs) < 100 {
		t.Fatalf("Go ソースが %d 個しか見つかりませんでした — "+
			"走査が壊れており、このテストはほぼ無条件に通ってしまいます", len(srcs))
	}

	for table, why := range tablesWrittenByNobody {
		for _, src := range srcs {
			for _, verb := range []string{"INSERT INTO " + table, "insert into " + table} {
				if strings.Contains(src, verb) {
					t.Errorf("%s に書き込むコードができました (%s)。"+
						"フォールバックの順序を見直してください — "+
						"この表が埋まるなら、そちらが一次ソースです", table, why)
				}
			}
		}
	}
}

// The headline for the FIM screen: it answers from events even though
// fim_events exists and is empty.
func TestTheFIMScreenAnswersFromEventsWhenItsTableIsEmpty(t *testing.T) {
	pool := renamePool(t)
	requireEmpty(t, pool, "fim_events")

	agentID := seedTelemetryAgent(t, pool, []string{"10.0.0.3"})
	path := "/etc/shadow-fixture-" + uuid.NewString()[:8]
	seedEvent(t, pool, agentID, "file", map[string]any{
		"path": path, "operation": "FILE_ACTION_MODIFY",
	})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/fim", NewFIMPageHandler(pool).ListSuspicious)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/fim", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), path) {
		t.Errorf("投入したファイルイベントが一覧に出ません。"+
			"fim_events は存在しますが誰も書き込まないため、"+
			"「テーブルが有る」を条件にすると events 側の分岐に到達しません:\n%s",
			w.Body.String())
	}
}

// And the same for the DNS screen.
func TestTheDNSScreenAnswersFromEventsWhenItsTableIsEmpty(t *testing.T) {
	pool := renamePool(t)
	requireEmpty(t, pool, "dns_alerts")

	agentID := seedTelemetryAgent(t, pool, []string{"10.0.0.4"})
	query := "fallback-" + uuid.NewString()[:8] + ".example"
	seedEvent(t, pool, agentID, "dns", map[string]any{
		"query": query, "is_suspicious": true,
	})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/dns", NewDNSSecurityHandler(pool).ListAlerts)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/dns", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), query) {
		t.Errorf("投入した DNS イベントが一覧に出ません。"+
			"dns_alerts は存在しますが誰も書き込みません:\n%s", w.Body.String())
	}
}

// And the TIP integrations list.
func TestTheTIPListFallsBackToThreatFeedsWhenItsTableIsEmpty(t *testing.T) {
	pool := renamePool(t)
	ctx := context.Background()
	requireEmpty(t, pool, "tip_platforms")

	name := "tip-fixture-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO threat_feeds (name, url, enabled) VALUES ($1, 'https://example.invalid/feed', true)`,
		name); err != nil {
		t.Fatalf("seed feed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM threat_feeds WHERE name=$1`, name)
	})

	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/tip", NewTIPIntegrationHandler(pool).List)
	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/tip", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s", w.Code, w.Body.String())
	}
	var platforms []struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &platforms); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, p := range platforms {
		if p.Name == name {
			return
		}
	}
	t.Errorf("投入したフィードが TIP 一覧に出ません。"+
		"tip_platforms はマイグレーション 219 が作りますが誰も書き込まないため、"+
		"「テーブルが有る」を条件にすると threat_feeds に到達しません:\n%s",
		w.Body.String())
}

// requireEmpty skips when a shared-database fixture from elsewhere has put rows
// into the primary table, because then the fallback is legitimately not taken.
func requireEmpty(t *testing.T, pool *pgxpool.Pool, table string) {
	t.Helper()
	var n int
	if err := pool.QueryRow(context.Background(),
		`SELECT COUNT(*) FROM `+table).Scan(&n); err != nil {
		t.Fatalf("count %s: %v", table, err)
	}
	if n != 0 {
		t.Skipf("%s に %d 行あるため、フォールバックは正当に使われません", table, n)
	}
}

// walkGoSources calls fn for every .go file under root.
func walkGoSources(root string, fn func(path, src string)) error {
	return filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			if name := info.Name(); name == "node_modules" || name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") {
			return nil
		}
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		fn(path, string(b))
		return nil
	})
}
