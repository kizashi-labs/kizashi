package handlers

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Two of the four bulk alert endpoints reported success for work that failed.
// Measured against the migrated schema before this change:
//
//	alerts.tags         exists=false
//	alerts.assigned_to  exists=true  (uuid, FK -> users.id)
//
//	UPDATE alerts SET tags = ...        -> 42703 column "tags" does not exist
//	UPDATE alerts SET assigned_to = ... -> 23503 when the user is not in users
//
//	POST /alerts/bulk-tag    -> 200 {"updated":0,"note":"tagsカラムの形式を確認してください"}
//	POST /alerts/bulk-assign -> 200 {"updated":0,"note":"assigned_toカラムを確認してください"}
//
// frontend/components/alerts/BulkAlertActions.tsx checks only the HTTP status,
// so both rendered 「N件にタグを追加しました」/「N件をアサインしました」 over a
// request that stored nothing. Tagging alerts had never worked at all — no
// migration has ever created the column — and it had never once looked broken.

func bulkPool(t *testing.T) *pgxpool.Pool {
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

// seedBulkAlerts creates n alerts on one throwaway agent and returns the
// agent id alongside them, so a read path can be filtered down to this
// fixture rather than hoping it lands on the first page of a shared database.
func seedBulkAlerts(t *testing.T, pool *pgxpool.Pool, n int) (string, []string) {
	t.Helper()
	ctx := context.Background()
	agentID := uuid.NewString()
	if _, err := pool.Exec(ctx,
		`INSERT INTO agents (id,hostname,os_type,status,last_seen)
		 VALUES ($1::uuid,'bulk-fixture','linux','online',NOW())`, agentID); err != nil {
		t.Fatalf("seed agent: %v", err)
	}
	t.Cleanup(func() {
		c := context.Background()
		_, _ = pool.Exec(c, `DELETE FROM alerts WHERE agent_id=$1::uuid`, agentID)
		_, _ = pool.Exec(c, `DELETE FROM agents WHERE id=$1::uuid`, agentID)
	})

	ids := make([]string, 0, n)
	for i := 0; i < n; i++ {
		var id string
		if err := pool.QueryRow(ctx,
			`INSERT INTO alerts (agent_id,title,description,severity,status)
			 VALUES ($1::uuid,$2,'fixture',5,'open') RETURNING id::text`,
			agentID, fmt.Sprintf("bulk fixture %d", i)).Scan(&id); err != nil {
			t.Fatalf("seed alert: %v", err)
		}
		ids = append(ids, id)
	}
	return agentID, ids
}

// callBulk invokes one bulk handler and returns its status and decoded body.
func callBulk(t *testing.T, fn gin.HandlerFunc, body string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPost, "/api/v1/alerts/bulk", strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	fn(c)

	var decoded map[string]interface{}
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &decoded)
	}
	return w.Code, decoded
}

// tagsOf reads the column back.
func tagsOf(t *testing.T, pool *pgxpool.Pool, alertID string) []string {
	t.Helper()
	var raw string
	if err := pool.QueryRow(context.Background(),
		`SELECT COALESCE(tags,'[]'::jsonb)::text FROM alerts WHERE id=$1::uuid`, alertID).Scan(&raw); err != nil {
		t.Fatalf("read tags: %v", err)
	}
	var out []string
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		t.Fatalf("tags is not an array of strings: %v (%s)", err, raw)
	}
	return out
}

func idsJSON(t *testing.T, ids []string) string {
	t.Helper()
	b, err := json.Marshal(ids)
	if err != nil {
		t.Fatalf("marshal ids: %v", err)
	}
	return string(b)
}

// TestBulkTaggingActuallyStoresTheTag is the core gate.
func TestBulkTaggingActuallyStoresTheTag(t *testing.T) {
	pool := bulkPool(t)
	_, ids := seedBulkAlerts(t, pool, 3)
	h := NewAlertBulkHandler(pool)

	code, body := callBulk(t, h.BulkTag,
		fmt.Sprintf(`{"ids":%s,"tag":"要調査"}`, idsJSON(t, ids)))
	if code != http.StatusOK {
		t.Fatalf("status = %d (%v)", code, body)
	}
	if body["updated"] != float64(len(ids)) {
		t.Errorf("updated = %v, want %d. A response of 0 with HTTP 200 is what the "+
			"console renders as 「タグを追加しました」 while nothing is stored.",
			body["updated"], len(ids))
	}
	for _, id := range ids {
		got := tagsOf(t, pool, id)
		if len(got) != 1 || got[0] != "要調査" {
			t.Errorf("alert %s tags = %v, want [要調査]", id, got)
		}
	}
}

// TestTaggingTwiceDoesNotAccumulateDuplicates. Bulk selections overlap
// routinely; `tags || jsonb_build_array($1)` would grow the array every time.
func TestTaggingTwiceDoesNotAccumulateDuplicates(t *testing.T) {
	pool := bulkPool(t)
	_, ids := seedBulkAlerts(t, pool, 1)
	h := NewAlertBulkHandler(pool)
	req := fmt.Sprintf(`{"ids":%s,"tag":"triage"}`, idsJSON(t, ids))

	for i := 0; i < 3; i++ {
		if code, body := callBulk(t, h.BulkTag, req); code != http.StatusOK {
			t.Fatalf("pass %d: status = %d (%v)", i, code, body)
		}
	}
	if got := tagsOf(t, pool, ids[0]); len(got) != 1 {
		t.Errorf("tags = %v after tagging three times; the same label is stored once "+
			"per request and no reader deduplicates it", got)
	}

	// The console sends whatever was typed into the tag box. "triage" and
	// " triage " are the same label to the operator, and would be two entries
	// that neither matches the other in a filter.
	if code, body := callBulk(t, h.BulkTag,
		fmt.Sprintf(`{"ids":%s,"tag":"  triage  "}`, idsJSON(t, ids))); code != http.StatusOK {
		t.Fatalf("padded tag: status = %d (%v)", code, body)
	}
	if got := tagsOf(t, pool, ids[0]); len(got) != 1 || got[0] != "triage" {
		t.Errorf("tags = %v after re-tagging with surrounding whitespace, want [triage]", got)
	}
}

// TestASecondTagIsAddedRatherThanReplacing. Two operators labelling the same
// alert must both survive.
func TestASecondTagIsAddedRatherThanReplacing(t *testing.T) {
	pool := bulkPool(t)
	_, ids := seedBulkAlerts(t, pool, 1)
	h := NewAlertBulkHandler(pool)

	for _, tag := range []string{"triage", "phishing"} {
		if code, body := callBulk(t, h.BulkTag,
			fmt.Sprintf(`{"ids":%s,"tag":%q}`, idsJSON(t, ids), tag)); code != http.StatusOK {
			t.Fatalf("tag %q: status = %d (%v)", tag, code, body)
		}
	}
	got := tagsOf(t, pool, ids[0])
	if len(got) != 2 || got[0] != "triage" || got[1] != "phishing" {
		t.Errorf("tags = %v, want [triage phishing]", got)
	}
}

// TestOnlyTheSelectedAlertsAreTagged guards the WHERE clause.
func TestOnlyTheSelectedAlertsAreTagged(t *testing.T) {
	pool := bulkPool(t)
	_, ids := seedBulkAlerts(t, pool, 3)
	h := NewAlertBulkHandler(pool)

	if code, body := callBulk(t, h.BulkTag,
		fmt.Sprintf(`{"ids":%s,"tag":"selected"}`, idsJSON(t, ids[:1]))); code != http.StatusOK {
		t.Fatalf("status = %d (%v)", code, body)
	}
	if got := tagsOf(t, pool, ids[0]); len(got) != 1 {
		t.Errorf("the selected alert has tags = %v", got)
	}
	for _, id := range ids[1:] {
		if got := tagsOf(t, pool, id); len(got) != 0 {
			t.Errorf("alert %s was not selected but carries tags = %v", id, got)
		}
	}
}

// TestATagIsReadableThroughTheAlertAPI. A tag nothing can read back is the same
// inert feature in a different place: the console has no other way to see it.
func TestATagIsReadableThroughTheAlertAPI(t *testing.T) {
	pool := bulkPool(t)
	agentID, ids := seedBulkAlerts(t, pool, 1)

	if code, body := callBulk(t, NewAlertBulkHandler(pool).BulkTag,
		fmt.Sprintf(`{"ids":%s,"tag":"exfil"}`, idsJSON(t, ids))); code != http.StatusOK {
		t.Fatalf("tag: status = %d (%v)", code, body)
	}

	var raw string
	if err := pool.QueryRow(context.Background(), `
		SELECT COALESCE(al.tags,'[]'::jsonb)::text FROM alerts al WHERE al.id=$1::uuid`,
		ids[0]).Scan(&raw); err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(raw, "exfil") {
		t.Fatalf("tags = %s", raw)
	}

	// And through the store, which is what the REST handlers serialise. Both
	// read paths are checked: the console lists alerts and opens one.
	db, err := store.Connect(context.Background(), os.Getenv("TEST_DATABASE_URL"))
	if err != nil {
		t.Fatalf("connect store: %v", err)
	}
	t.Cleanup(db.Close)
	as := store.NewAlertStore(db)

	single, err := as.GetAlert(context.Background(), ids[0])
	if err != nil {
		t.Fatalf("GetAlert: %v", err)
	}
	if len(single.Tags) != 1 || single.Tags[0] != "exfil" {
		t.Errorf("GetAlert reports tags = %v; an operator who tags an alert has no "+
			"way to see that it happened", single.Tags)
	}

	listed, _, err := as.ListAlerts(context.Background(),
		store.AlertFilter{AgentID: agentID, Limit: 50})
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	if len(listed) != 1 {
		t.Fatalf("the fixture agent has %d alerts, want 1", len(listed))
	}
	if len(listed[0].Tags) != 1 || listed[0].Tags[0] != "exfil" {
		t.Errorf("ListAlerts reports tags = %v for the tagged alert", listed[0].Tags)
	}
}

// TestAFailedAssignmentIsNotReportedAsSuccess. assigned_to is a uuid with a
// foreign key onto users, so assigning to somebody who is not a user fails with
// 23503 — which used to be answered 200 {"updated":0}.
func TestAFailedAssignmentIsNotReportedAsSuccess(t *testing.T) {
	pool := bulkPool(t)
	_, ids := seedBulkAlerts(t, pool, 1)
	h := NewAlertBulkHandler(pool)

	code, body := callBulk(t, h.BulkAssign,
		fmt.Sprintf(`{"ids":%s,"user_id":%q}`, idsJSON(t, ids), uuid.NewString()))
	if code == http.StatusOK {
		t.Errorf("assigning to a user that does not exist answered 200 (%v). The "+
			"console reports 「アサインしました」 and the alert stays unassigned.", body)
	}
	if code != http.StatusBadRequest {
		t.Errorf("status = %d, want 400 — the caller named a user that is not there", code)
	}

	var assigned *string
	if err := pool.QueryRow(context.Background(),
		`SELECT assigned_to::text FROM alerts WHERE id=$1::uuid`, ids[0]).Scan(&assigned); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if assigned != nil {
		t.Errorf("assigned_to = %v after a rejected assignment", *assigned)
	}
}

// TestAMalformedAlertIDIsARequestError. A non-uuid reaches Postgres as 22P02.
// Answering 200 hides a client bug; answering 500 blames the server for it.
func TestAMalformedAlertIDIsARequestError(t *testing.T) {
	pool := bulkPool(t)
	h := NewAlertBulkHandler(pool)

	for name, call := range map[string]func() (int, map[string]interface{}){
		"bulk-tag": func() (int, map[string]interface{}) {
			return callBulk(t, h.BulkTag, `{"ids":["not-a-uuid"],"tag":"x"}`)
		},
		"bulk-status": func() (int, map[string]interface{}) {
			return callBulk(t, h.BulkStatus, `{"ids":["not-a-uuid"],"status":"resolved"}`)
		},
		"bulk-delete": func() (int, map[string]interface{}) {
			return callBulk(t, h.BulkDelete, `{"ids":["not-a-uuid"]}`)
		},
		"bulk-assign": func() (int, map[string]interface{}) {
			return callBulk(t, h.BulkAssign, `{"ids":["not-a-uuid"],"user_id":"`+uuid.NewString()+`"}`)
		},
	} {
		if code, body := call(); code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400 (%v)", name, code, body)
		}
	}
}

// TestBulkStatusAndDeleteStillWork pins the two arms that were already correct,
// so the shared error mapping cannot break them.
func TestBulkStatusAndDeleteStillWork(t *testing.T) {
	pool := bulkPool(t)
	_, ids := seedBulkAlerts(t, pool, 2)
	h := NewAlertBulkHandler(pool)

	code, body := callBulk(t, h.BulkStatus,
		fmt.Sprintf(`{"ids":%s,"status":"investigating"}`, idsJSON(t, ids)))
	if code != http.StatusOK || body["updated"] != float64(2) {
		t.Fatalf("bulk-status: %d %v", code, body)
	}
	var status string
	if err := pool.QueryRow(context.Background(),
		`SELECT status FROM alerts WHERE id=$1::uuid`, ids[0]).Scan(&status); err != nil {
		t.Fatalf("read back: %v", err)
	}
	if status != "investigating" {
		t.Errorf("status = %q", status)
	}

	code, body = callBulk(t, h.BulkDelete, fmt.Sprintf(`{"ids":%s}`, idsJSON(t, ids)))
	if code != http.StatusOK || body["deleted"] != float64(2) {
		t.Fatalf("bulk-delete: %d %v", code, body)
	}
}

// TestAnAlertIsNotLostBecauseOfAMalformedTagsValue. tags is JSONB with no
// constraint on its contents, so anything that writes the column directly can
// leave a value that is not an array of strings. Scanning it straight into
// []string would fail the Scan, and ListAlerts skips a row whose Scan fails —
// which would drop the alert out of the console entirely because of a label.
func TestAnAlertIsNotLostBecauseOfAMalformedTagsValue(t *testing.T) {
	pool := bulkPool(t)
	agentID, ids := seedBulkAlerts(t, pool, 1)

	for _, bad := range []string{`{"not":"an array"}`, `["ok", 1]`, `"a string"`} {
		if _, err := pool.Exec(context.Background(),
			`UPDATE alerts SET tags = $1::jsonb WHERE id = $2::uuid`, bad, ids[0]); err != nil {
			t.Fatalf("seed %s: %v", bad, err)
		}

		db, err := store.Connect(context.Background(), os.Getenv("TEST_DATABASE_URL"))
		if err != nil {
			t.Fatalf("connect store: %v", err)
		}
		as := store.NewAlertStore(db)

		single, err := as.GetAlert(context.Background(), ids[0])
		if err != nil {
			db.Close()
			t.Fatalf("GetAlert with tags=%s: %v", bad, err)
		}
		if single.Tags == nil {
			t.Errorf("tags=%s -> GetAlert reports null rather than an empty array", bad)
		}

		listed, _, err := as.ListAlerts(context.Background(),
			store.AlertFilter{AgentID: agentID, Limit: 50})
		db.Close()
		if err != nil {
			t.Fatalf("ListAlerts with tags=%s: %v", bad, err)
		}
		if len(listed) != 1 {
			t.Errorf("tags=%s -> the alert disappeared from the list", bad)
			continue
		}
		// A partial decode is not trusted: ["ok", 1] must not become ["ok"].
		if len(listed[0].Tags) != 0 {
			t.Errorf("tags=%s -> reported as %v; a value that did not decode is "+
				"reported as if it had", bad, listed[0].Tags)
		}
	}
}
