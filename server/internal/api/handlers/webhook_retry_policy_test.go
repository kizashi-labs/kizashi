package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// PUT /api/v1/webhooks/:id/retry-policy accepted max_retries,
// retry_delay_seconds and timeout_seconds and stored none of them.
//
// Measured against the migrated schema before this change:
//
//	webhook_targets.max_retries          exists=false
//	webhook_targets.retry_delay_seconds  exists=false
//	webhook_targets.timeout_seconds      exists=false
//	webhook_targets.system_metadata      exists=false
//
//	PUT /webhooks/<real id>/retry-policy    -> 200 {"max_retries":7,...}
//	PUT /webhooks/<unknown id>/retry-policy -> 200 {"max_retries":7,...}
//
// The handler probed for max_retries, fell back to probing for system_metadata,
// and when neither existed returned 200 echoing the request body. The response
// is indistinguishable from a stored value, so the policy looked saved on every
// call and was discarded on every call — including against a webhook that does
// not exist.

func webhookPool(t *testing.T) *pgxpool.Pool {
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

// seedWebhook creates one webhook target and returns its id.
func seedWebhook(t *testing.T, pool *pgxpool.Pool) string {
	t.Helper()
	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO webhook_targets (name, url, secret, events, enabled)
		VALUES ('policy-fixture', 'https://example.invalid/hook', 's', ARRAY['alert.critical'], true)
		RETURNING id::text`).Scan(&id); err != nil {
		t.Fatalf("seed: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_targets WHERE id=$1::uuid`, id)
	})
	return id
}

// putPolicy invokes the handler for one webhook id.
func putPolicy(t *testing.T, h *WebhookHandler, id, body string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodPut, "/api/v1/webhooks/"+id+"/retry-policy",
		strings.NewReader(body))
	c.Request.Header.Set("Content-Type", "application/json")
	c.Params = gin.Params{{Key: "id", Value: id}}
	h.UpdateRetryPolicy(c)

	var decoded map[string]interface{}
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &decoded)
	}
	return w.Code, decoded
}

// TestTheRetryPolicyIsStored is the core gate: it must be read back, not echoed.
func TestTheRetryPolicyIsStored(t *testing.T) {
	pool := webhookPool(t)
	id := seedWebhook(t, pool)
	ws := store.NewWebhookStore(pool)
	h := NewWebhookHandler(ws, nil)

	code, body := putPolicy(t, h, id, `{"max_retries":7,"retry_delay_seconds":42,"timeout_seconds":55}`)
	if code != http.StatusOK {
		t.Fatalf("status = %d (%v)", code, body)
	}

	target, err := ws.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	got := target.RetryPolicy
	if got.MaxRetries != 7 || got.RetryDelaySeconds != 42 || got.TimeoutSeconds != 55 {
		t.Errorf("stored policy = %+v, want {7 42 55}. The endpoint answered 200 "+
			"with the request body, which is indistinguishable from a stored value.", got)
	}
}

// TestTheStoredPolicyIsWhatTheNotifierReads. The delivery path reads targets
// through ListEnabledForEvent, not Get; a policy present in one query and
// missing from the other is invisible until a delivery fails.
func TestTheStoredPolicyIsWhatTheNotifierReads(t *testing.T) {
	pool := webhookPool(t)
	id := seedWebhook(t, pool)
	ws := store.NewWebhookStore(pool)

	if code, body := putPolicy(t, NewWebhookHandler(ws, nil), id,
		`{"max_retries":6,"retry_delay_seconds":11,"timeout_seconds":22}`); code != http.StatusOK {
		t.Fatalf("status = %d (%v)", code, body)
	}

	targets, err := ws.ListEnabledForEvent(context.Background(), "alert.critical")
	if err != nil {
		t.Fatalf("ListEnabledForEvent: %v", err)
	}
	found := false
	for _, target := range targets {
		if target.ID != id {
			continue
		}
		found = true
		got := target.RetryPolicy
		if got.MaxRetries != 6 || got.RetryDelaySeconds != 11 || got.TimeoutSeconds != 22 {
			t.Errorf("the delivery path sees %+v, want {6 11 22}", got)
		}
	}
	if !found {
		t.Fatal("the fixture is not in the delivery path's target list")
	}
}

// TestSettingAPolicyOnAWebhookThatIsNotThereIsNotSuccess.
func TestSettingAPolicyOnAWebhookThatIsNotThereIsNotSuccess(t *testing.T) {
	pool := webhookPool(t)
	h := NewWebhookHandler(store.NewWebhookStore(pool), nil)

	code, _ := putPolicy(t, h, "11111111-2222-3333-4444-555555555555",
		`{"max_retries":3,"retry_delay_seconds":5,"timeout_seconds":10}`)
	if code != http.StatusNotFound {
		t.Errorf("status = %d, want 404. Reporting success for a webhook nobody "+
			"has tells the console the policy is in effect somewhere.", code)
	}
}

// TestAPolicyOutsideTheAcceptedRangeIsRejected. The bounds exist because a
// retry policy parks a goroutine per delivery: an unbounded delay or retry
// count turns one failing endpoint into an unbounded backlog.
func TestAPolicyOutsideTheAcceptedRangeIsRejected(t *testing.T) {
	pool := webhookPool(t)
	id := seedWebhook(t, pool)
	ws := store.NewWebhookStore(pool)
	h := NewWebhookHandler(ws, nil)

	for name, body := range map[string]string{
		"negative retries":  `{"max_retries":-1,"retry_delay_seconds":5,"timeout_seconds":10}`,
		"too many retries":  `{"max_retries":100,"retry_delay_seconds":5,"timeout_seconds":10}`,
		"negative delay":    `{"max_retries":3,"retry_delay_seconds":-5,"timeout_seconds":10}`,
		"delay of an hour":  `{"max_retries":3,"retry_delay_seconds":3600,"timeout_seconds":10}`,
		"zero timeout":      `{"max_retries":3,"retry_delay_seconds":5,"timeout_seconds":0}`,
		"timeout of a week": `{"max_retries":3,"retry_delay_seconds":5,"timeout_seconds":604800}`,
	} {
		if code, _ := putPolicy(t, h, id, body); code != http.StatusBadRequest {
			t.Errorf("%s: status = %d, want 400", name, code)
		}
	}

	// None of the rejected requests may have taken effect.
	target, err := ws.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if got := target.RetryPolicy; got.MaxRetries != 3 || got.RetryDelaySeconds != 5 || got.TimeoutSeconds != 10 {
		t.Errorf("policy = %+v after only rejected requests, want the defaults {3 5 10}", got)
	}
}

// TestTheHandlerBoundsMatchWhatTheDatabaseAccepts. The CHECK constraint is the
// backstop for writes from any other path; if the handler were more permissive
// than the constraint, a request inside the handler's range would fail with a
// 23514 and be reported as a server fault.
func TestTheHandlerBoundsMatchWhatTheDatabaseAccepts(t *testing.T) {
	pool := webhookPool(t)
	id := seedWebhook(t, pool)
	h := NewWebhookHandler(store.NewWebhookStore(pool), nil)

	for name, body := range map[string]string{
		"lowest accepted":  `{"max_retries":0,"retry_delay_seconds":0,"timeout_seconds":1}`,
		"highest accepted": `{"max_retries":10,"retry_delay_seconds":300,"timeout_seconds":120}`,
	} {
		if code, resp := putPolicy(t, h, id, body); code != http.StatusOK {
			t.Errorf("%s: status = %d (%v); the handler accepted a policy the "+
				"database refused", name, code, resp)
		}
	}
}

// TestANewWebhookStartsWithAUsablePolicy. A target created before this column
// existed, or through any path that does not set one, must not end up with a
// zero timeout — that would fail instantly on every attempt.
//
// Every read path is exercised, not just Get. Create and Update return the row
// they wrote, and their column lists were the ones this change had to touch:
// a mistake there is a broken query rather than a wrong value, so it takes out
// webhook creation entirely.
func TestANewWebhookStartsWithAUsablePolicy(t *testing.T) {
	pool := webhookPool(t)
	ws := store.NewWebhookStore(pool)
	ctx := context.Background()

	created, err := ws.Create(ctx, store.WebhookTarget{
		Name: "policy-default-fixture", URL: "https://example.invalid/hook",
		Events: []string{"alert.critical"}, Enabled: true,
	})
	if err != nil {
		t.Fatalf("Create: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_targets WHERE id=$1::uuid`, created.ID)
	})

	for name, target := range map[string]*store.WebhookTarget{"Create": created} {
		if !target.RetryPolicy.Valid() {
			t.Errorf("%s returns policy %+v, which is outside the accepted range",
				name, target.RetryPolicy)
		}
		if target.RetryPolicy.TimeoutSeconds <= 0 {
			t.Errorf("%s returns timeout_seconds = %d; every delivery would fail "+
				"immediately", name, target.RetryPolicy.TimeoutSeconds)
		}
	}

	// The policy must survive an edit of the unrelated fields, and Update must
	// report it back.
	updated, err := ws.Update(ctx, created.ID, store.WebhookTarget{
		Name: "renamed", URL: "https://example.invalid/hook2",
		Events: []string{"alert.high"}, Enabled: false,
	})
	if err != nil {
		t.Fatalf("Update: %v", err)
	}
	if updated.RetryPolicy != created.RetryPolicy {
		t.Errorf("editing name/url changed the retry policy from %+v to %+v",
			created.RetryPolicy, updated.RetryPolicy)
	}

	got, err := ws.Get(ctx, created.ID)
	if err != nil {
		t.Fatalf("Get: %v", err)
	}
	if got.RetryPolicy != created.RetryPolicy {
		t.Errorf("Get reports %+v, Create reported %+v", got.RetryPolicy, created.RetryPolicy)
	}

	listed, err := ws.List(ctx)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	for _, target := range listed {
		if target.ID == created.ID && target.RetryPolicy != created.RetryPolicy {
			t.Errorf("List reports %+v, Create reported %+v", target.RetryPolicy, created.RetryPolicy)
		}
	}
}

// TestUpdatingEventTypesReportsAMissingWebhook. Same shape as the retry policy:
// the endpoint had two probe-and-fall-back arms and neither noticed the webhook
// was not there.
func TestUpdatingEventTypesReportsAMissingWebhook(t *testing.T) {
	pool := webhookPool(t)
	ws := store.NewWebhookStore(pool)
	h := NewWebhookHandler(ws, nil)
	id := seedWebhook(t, pool)

	gin.SetMode(gin.TestMode)
	call := func(target, body string) int {
		w := httptest.NewRecorder()
		c, _ := gin.CreateTestContext(w)
		c.Request = httptest.NewRequest(http.MethodPut, "/x", strings.NewReader(body))
		c.Request.Header.Set("Content-Type", "application/json")
		c.Params = gin.Params{{Key: "id", Value: target}}
		h.UpdateEventTypes(c)
		return w.Code
	}

	if code := call(id, `{"event_types":["alert.high","agent.offline"]}`); code != http.StatusOK {
		t.Fatalf("status = %d", code)
	}
	target, err := ws.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	if len(target.Events) != 2 || target.Events[0] != "alert.high" {
		t.Errorf("events = %v, want [alert.high agent.offline]", target.Events)
	}

	if code := call("11111111-2222-3333-4444-555555555555",
		`{"event_types":["alert.high"]}`); code != http.StatusNotFound {
		t.Errorf("status = %d for a webhook that does not exist, want 404", code)
	}
}
