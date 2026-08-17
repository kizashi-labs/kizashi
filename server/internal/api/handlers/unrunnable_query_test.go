package handlers

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Two statements that Postgres refused outright — not a wrong answer, no answer
// at all — with the error discarded in one case and turned into a 500 in the
// other.
//
//	soar_handler         42883  operator does not exist: text = uuid
//	endpoint_tag_handler 42P10  SELECT DISTINCT / ORDER BY mismatch
//
// The SOAR one was wrong twice over, which is the usual shape: incident_alerts
// .alert_id is text and alerts.id is uuid, so the join could not be compiled;
// fixing that exposes a.hostname, which alerts does not have (hostname is on
// agents). Postgres reports only the first error, so repairing one leaves the
// statement just as unrunnable.

func unrunnablePool(t *testing.T) *pgxpool.Pool {
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

// The headline: an incident's linked alerts come back, with the host named.
// This is what SOAR playbooks receive as the incident description, so an empty
// result is a playbook acting on an incident it cannot see the alerts for.
func TestAnIncidentsLinkedAlertsAreRetrievable(t *testing.T) {
	pool := unrunnablePool(t)
	ctx := context.Background()

	agentID := uuid.NewString()
	host := "soar-fixture-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,$2,'linux','online',NOW())`, agentID, host); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	var alertID, incidentID string
	if err := pool.QueryRow(ctx,
		`INSERT INTO alerts (agent_id,severity,status,title,description)
		 VALUES ($1::uuid,9,'open','soar fixture alert','') RETURNING id::text`,
		agentID).Scan(&alertID); err != nil {
		t.Fatalf("seed alert: %v", err)
	}
	if err := pool.QueryRow(ctx,
		`INSERT INTO incidents (title,description,severity,status)
		 VALUES ('soar fixture incident','',9,'open') RETURNING id::text`).Scan(&incidentID); err != nil {
		t.Fatalf("seed incident: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO incident_alerts (incident_id, alert_id) VALUES ($1::uuid, $2)`,
		incidentID, alertID); err != nil {
		t.Fatalf("link: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM incident_alerts WHERE incident_id=$1::uuid`, incidentID)
		_, _ = pool.Exec(c, `DELETE FROM incidents WHERE id=$1::uuid`, incidentID)
		_, _ = pool.Exec(c, `DELETE FROM alerts WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	// The statement is taken from the handler rather than written out here, so
	// a change to the handler is a change to what this test runs. CreateTicket
	// needs a configured SOAR backend to reach it end to end; extracting its
	// query is the closest thing to exercising it that does not require one.
	stmt := linkedAlertsQuery(t)

	var gotTitle, gotHost string
	var gotSeverity int
	if err := pool.QueryRow(ctx, stmt, incidentID).Scan(&gotTitle, &gotSeverity, &gotHost); err != nil {
		t.Fatalf("関連アラートのクエリが実行できません: %v\n"+
			"incident_alerts.alert_id は text、alerts.id は uuid です。"+
			"また alerts にホスト名の列はありません\n%s", err, stmt)
	}
	if gotTitle != "soar fixture alert" || gotSeverity != 9 {
		t.Errorf("アラート = %q severity=%d", gotTitle, gotSeverity)
	}
	if gotHost != host {
		t.Errorf("ホスト名 = %q, want %q。"+
			"SOAR プレイブックに渡る説明文からホストが落ちます", gotHost, host)
	}
}

// Filtering endpoints by tag answered 500 on every request: SELECT DISTINCT
// with an ORDER BY naming an expression that is not in the select list is
// rejected before it runs.
func TestFilteringEndpointsByTagRuns(t *testing.T) {
	pool := unrunnablePool(t)
	ctx := context.Background()

	// endpoint_tags has no migration — the handler creates it lazily on first
	// use. Seeding it directly therefore only works on a database some earlier
	// request has already touched, which is why this passed locally and failed
	// on CI's fresh database. Ask the handler to create it, as a real first
	// request would.
	h := NewEndpointTagHandler(pool)
	if err := h.ensureTable(ctx); err != nil {
		t.Fatalf("ensureTable: %v", err)
	}

	agentID := uuid.NewString()
	tag := "tagfix-" + uuid.NewString()[:8]
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'tag-fixture','linux','online',NOW())`, agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	if _, err := pool.Exec(ctx,
		`INSERT INTO endpoint_tags (agent_id, tag) VALUES ($1::uuid, $2)`,
		agentID, tag); err != nil {
		t.Fatalf("seed tag: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM endpoint_tags WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	// Through the handler, not by re-issuing its query. Writing the statement
	// out in the test produces a test that passes whatever the handler does —
	// three tests in this campaign have been written that way and each let its
	// mutation through.
	gin.SetMode(gin.TestMode)
	r := gin.New()
	r.GET("/search", h.SearchByTag)

	w := httptest.NewRecorder()
	r.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/search?tag="+tag, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("status %d: %s\n"+
			"SELECT DISTINCT では ORDER BY の式が選択リストに現れる必要があります "+
			"— et.agent_id と et.agent_id::TEXT は別の式です", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), agentID) {
		t.Errorf("投入した端末が結果に出ません: %s", w.Body.String())
	}
}

// linkedAlertsQuery lifts the linked-alerts statement out of soar_handler.go so
// the test runs what the handler runs. A test that restates the query cannot
// see a change to the handler at all — which is exactly what happened the first
// time this file was written.
func linkedAlertsQuery(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("soar_handler.go")
	if err != nil {
		t.Fatalf("read soar_handler.go: %v", err)
	}
	src := string(b)
	i := strings.Index(src, "SELECT a.title, a.severity")
	if i < 0 {
		t.Fatal("関連アラートのクエリが soar_handler.go に見つかりません")
	}
	j := strings.IndexByte(src[i:], '`')
	if j < 0 {
		t.Fatal("クエリの終端が見つかりません")
	}
	return src[i : i+j]
}
