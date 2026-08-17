package handlers

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/edr-platform/server/internal/store"
	"github.com/gin-gonic/gin"
	"github.com/jackc/pgx/v5/pgxpool"
)

// GET /api/v1/webhooks/:id/deliveries returned 500 on every call and could
// never have returned a row.
//
// Measured against the migrated schema before this change:
//
//	webhook_deliveries.event          exists=true
//	webhook_deliveries.event_type     exists=false
//	webhook_deliveries.attempt        exists=false
//	webhook_deliveries.attempted_at   exists=true
//	webhook_deliveries.created_at     exists=false
//	webhook_deliveries.webhook_id references: webhook_configs
//
//	GET /webhooks/<real webhook_targets id>/deliveries -> 500
//
// Three of the selected columns do not exist, so the query was 42703. Fixing
// only the names would have left the endpoint reading a table keyed to
// webhook_configs with a webhook_targets id, which matches nothing — an empty
// 200 that reads as "no deliveries yet" rather than "wrong table". These tests
// pin both halves: the rows exist, and the endpoint returns them.

// getDeliveries invokes the handler for one webhook id.
func getDeliveries(t *testing.T, h *WebhookHandler, id string) (int, map[string]interface{}) {
	t.Helper()
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	c.Request = httptest.NewRequest(http.MethodGet, "/api/v1/webhooks/"+id+"/deliveries", nil)
	c.Params = gin.Params{{Key: "id", Value: id}}
	h.GetDeliveryLog(c)

	var decoded map[string]interface{}
	if w.Body.Len() > 0 {
		_ = json.Unmarshal(w.Body.Bytes(), &decoded)
	}
	return w.Code, decoded
}

// seedDelivery appends one attempt row for a webhook.
func seedDelivery(t *testing.T, pool *pgxpool.Pool, id, event string, attempt, code int, delivered bool) {
	t.Helper()
	st := store.NewWebhookStore(pool)
	if err := st.RecordDelivery(context.Background(), store.WebhookDelivery{
		WebhookID:  id,
		Event:      event,
		Attempt:    attempt,
		StatusCode: code,
		Delivered:  delivered,
		DurationMs: 12,
	}); err != nil {
		t.Fatalf("record delivery attempt %d: %v", attempt, err)
	}
}

// A recorded attempt comes back. This is what returned 500 before.
func TestTheDeliveryLogReturnsRecordedAttempts(t *testing.T) {
	pool := webhookPool(t)
	id := seedWebhook(t, pool)
	h := &WebhookHandler{store: store.NewWebhookStore(pool)}

	seedDelivery(t, pool, id, "alert.critical", 1, 200, true)

	code, body := getDeliveries(t, h, id)
	if code != http.StatusOK {
		t.Fatalf("配信ログが %d を返しました (期待: 200): %v", code, body)
	}
	list, _ := body["deliveries"].([]interface{})
	if len(list) != 1 {
		t.Fatalf("記録した1件が返っていません: %v", body)
	}
	row, _ := list[0].(map[string]interface{})
	if row["status_code"].(float64) != 200 || row["event"] != "alert.critical" {
		t.Errorf("記録した内容と返却値が一致しません: %v", row)
	}
	if row["delivered"] != true {
		t.Errorf("delivered が反映されていません: %v", row)
	}
}

// The retry sequence is legible: a delivery that succeeded on its third
// attempt leaves two failed rows and one delivered, newest first.
func TestTheDeliveryLogShowsEveryAttemptNewestFirst(t *testing.T) {
	pool := webhookPool(t)
	id := seedWebhook(t, pool)
	h := &WebhookHandler{store: store.NewWebhookStore(pool)}

	seedDelivery(t, pool, id, "alert.critical", 1, 502, false)
	seedDelivery(t, pool, id, "alert.critical", 2, 502, false)
	seedDelivery(t, pool, id, "alert.critical", 3, 200, true)

	_, body := getDeliveries(t, h, id)
	list, _ := body["deliveries"].([]interface{})
	if len(list) != 3 {
		t.Fatalf("3回の試行が揃っていません: %v", body)
	}
	// Newest first, so attempt 3 leads.
	wantAttempt := []float64{3, 2, 1}
	wantDelivered := []bool{true, false, false}
	for i, item := range list {
		row := item.(map[string]interface{})
		if row["attempt"].(float64) != wantAttempt[i] {
			t.Errorf("%d番目の attempt が %v、期待は %v", i, row["attempt"], wantAttempt[i])
		}
		if row["delivered"] != wantDelivered[i] {
			t.Errorf("%d番目の delivered が %v、期待は %v", i, row["delivered"], wantDelivered[i])
		}
	}
	if body["total"].(float64) != 3 {
		t.Errorf("total が件数と一致しません: %v", body["total"])
	}
}

// A webhook that has never fired is an empty list, not an error — and it must
// be distinguishable from an id that does not exist.
func TestAWebhookThatNeverFiredHasAnEmptyLog(t *testing.T) {
	pool := webhookPool(t)
	id := seedWebhook(t, pool)
	h := &WebhookHandler{store: store.NewWebhookStore(pool)}

	code, body := getDeliveries(t, h, id)
	if code != http.StatusOK {
		t.Fatalf("未配信のwebhookが %d を返しました (期待: 200)", code)
	}
	list, ok := body["deliveries"].([]interface{})
	if !ok {
		t.Fatalf("deliveries が配列ではありません (null は許容しません): %v", body["deliveries"])
	}
	if len(list) != 0 {
		t.Errorf("未配信なのに %d 件返りました", len(list))
	}
}

// An unknown webhook is 404. Before this change every id — real or not —
// produced the same 500.
func TestAnUnknownWebhookDeliveryLogIs404(t *testing.T) {
	pool := webhookPool(t)
	h := &WebhookHandler{store: store.NewWebhookStore(pool)}

	code, _ := getDeliveries(t, h, "00000000-0000-0000-0000-000000000000")
	if code != http.StatusNotFound {
		t.Fatalf("存在しないwebhookが %d を返しました (期待: 404)", code)
	}
}

// The endpoint must not read the other subsystem's table. A row written for a
// webhook_configs id must never surface under a webhook_targets id — that is
// the confusion that made a name-only fix look correct.
func TestTheDeliveryLogDoesNotReadTheOtherSubsystemsTable(t *testing.T) {
	pool := webhookPool(t)
	ctx := context.Background()
	id := seedWebhook(t, pool)
	h := &WebhookHandler{store: store.NewWebhookStore(pool)}

	var configID string
	if err := pool.QueryRow(ctx, `
		INSERT INTO webhook_configs (name, url, enabled)
		VALUES ('other-subsystem', 'https://example.invalid/other', true)
		RETURNING id::text`).Scan(&configID); err != nil {
		t.Fatalf("seed webhook_configs: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(ctx, `DELETE FROM webhook_configs WHERE id=$1::uuid`, configID)
	})
	if _, err := pool.Exec(ctx, `
		INSERT INTO webhook_deliveries (webhook_id, event, status, status_code)
		VALUES ($1::uuid, 'alert.critical', 'success', 200)`, configID); err != nil {
		t.Fatalf("seed webhook_deliveries: %v", err)
	}

	// The webhook_targets id has no history of its own.
	_, body := getDeliveries(t, h, id)
	list, _ := body["deliveries"].([]interface{})
	if len(list) != 0 {
		t.Errorf("別サブシステムの配信履歴が漏れています: %v", list)
	}

	// And the webhook_configs id is not a webhook_target at all.
	if code, _ := getDeliveries(t, h, configID); code != http.StatusNotFound {
		t.Errorf("webhook_configs の id が %d を返しました (期待: 404)", code)
	}
}

// The read is capped, so one noisy webhook cannot return an unbounded body.
func TestTheDeliveryLogIsCapped(t *testing.T) {
	pool := webhookPool(t)
	id := seedWebhook(t, pool)
	h := &WebhookHandler{store: store.NewWebhookStore(pool)}

	for i := 1; i <= store.DeliveryHistoryLimit+10; i++ {
		seedDelivery(t, pool, id, "alert.critical", i, 200, true)
	}

	_, body := getDeliveries(t, h, id)
	list, _ := body["deliveries"].([]interface{})
	if len(list) != store.DeliveryHistoryLimit {
		t.Fatalf("返却件数が %d、上限は %d", len(list), store.DeliveryHistoryLimit)
	}
}
