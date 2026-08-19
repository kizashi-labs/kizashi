package notification

import (
	"context"
	"testing"
	"time"

	"github.com/edr-platform/server/internal/store"
)

// The delivery path recorded no per-attempt history at all: internal/notification
// only stamped last_status on the target, so an endpoint that answered on the
// first try and one that burned every retry in its policy were indistinguishable
// after the fact. GET /webhooks/:id/deliveries is only as truthful as what gets
// written here, so these gates pin the writing rather than the reading.

// waitForDeliveries polls until the expected number of rows is present, so the
// assertions do not race the recording, which runs on its own context.
func waitForDeliveries(t *testing.T, n *WebhookNotifier, id string, want int) []store.WebhookDelivery {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	var last []store.WebhookDelivery
	for time.Now().Before(deadline) {
		got, err := n.store.ListDeliveries(context.Background(), id, store.DeliveryHistoryLimit)
		if err != nil {
			t.Fatalf("配信履歴の取得に失敗: %v", err)
		}
		last = got
		if len(got) == want {
			return got
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("配信履歴が %d 件になりませんでした (現在 %d 件)", want, len(last))
	return nil
}

// A delivery that succeeds first time writes exactly one row, marked delivered.
func TestASuccessfulDeliveryIsRecordedOnce(t *testing.T) {
	n, id := notifier(t)
	srv, hits := countingEndpoint(t, 200)

	deliverTo(t, n, id, srv.URL, store.WebhookRetryPolicy{
		MaxRetries: 3, RetryDelaySeconds: 0, TimeoutSeconds: 5,
	}, hits)

	rows := waitForDeliveries(t, n, id, 1)
	if rows[0].Attempt != 1 {
		t.Errorf("attempt が %d、期待は 1", rows[0].Attempt)
	}
	if !rows[0].Delivered || rows[0].StatusCode != 200 {
		t.Errorf("成功が記録されていません: %+v", rows[0])
	}
	if rows[0].Event != "alert.critical" {
		t.Errorf("event が %q", rows[0].Event)
	}
	if rows[0].WebhookID != id {
		t.Errorf("webhook_id が %q、期待は %q", rows[0].WebhookID, id)
	}
}

// Two 502s then a 200 leaves three rows — the sequence that tells a flaky
// endpoint from a healthy one, which a single final status cannot.
func TestEveryRetryAttemptIsRecorded(t *testing.T) {
	n, id := notifier(t)
	srv, hits := countingEndpoint(t, 502, 502, 200)

	deliverTo(t, n, id, srv.URL, store.WebhookRetryPolicy{
		MaxRetries: 3, RetryDelaySeconds: 0, TimeoutSeconds: 5,
	}, hits)

	rows := waitForDeliveries(t, n, id, 3)
	// Newest first, so the successful third attempt leads.
	if rows[0].Attempt != 3 || !rows[0].Delivered || rows[0].StatusCode != 200 {
		t.Errorf("最終試行が成功として記録されていません: %+v", rows[0])
	}
	for _, r := range rows[1:] {
		if r.Delivered || r.StatusCode != 502 {
			t.Errorf("失敗試行が正しく記録されていません: %+v", r)
		}
	}
}

// A rejected payload is one row, not retried, and not marked delivered — a 4xx
// must not be recorded as a success just because the endpoint answered.
func TestARejectedDeliveryIsRecordedAsNotDelivered(t *testing.T) {
	n, id := notifier(t)
	srv, hits := countingEndpoint(t, 400)

	deliverTo(t, n, id, srv.URL, store.WebhookRetryPolicy{
		MaxRetries: 3, RetryDelaySeconds: 0, TimeoutSeconds: 5,
	}, hits)

	rows := waitForDeliveries(t, n, id, 1)
	if rows[0].Delivered {
		t.Errorf("400 が delivered として記録されました: %+v", rows[0])
	}
	if rows[0].StatusCode != 400 {
		t.Errorf("status_code が %d、期待は 400", rows[0].StatusCode)
	}
}

// A transport error records the reason rather than a fabricated status code.
func TestATransportErrorIsRecordedWithItsReason(t *testing.T) {
	n, id := notifier(t)

	// A port with nothing listening: every attempt fails to connect.
	deliverTo(t, n, id, "http://127.0.0.1:1/hook", store.WebhookRetryPolicy{
		MaxRetries: 1, RetryDelaySeconds: 0, TimeoutSeconds: 2,
	}, new(int32))

	rows := waitForDeliveries(t, n, id, 2)
	for _, r := range rows {
		if r.StatusCode != 0 {
			t.Errorf("応答がないのに status_code %d が記録されました: %+v", r.StatusCode, r)
		}
		if r.Error == "" {
			t.Errorf("転送エラーの理由が記録されていません: %+v", r)
		}
		if r.Delivered {
			t.Errorf("未達なのに delivered が true です: %+v", r)
		}
	}
}

// History is bounded per webhook. There is no scheduled prune in this codebase,
// so without a bound at write time a busy target grows the table without limit.
func TestDeliveryHistoryIsPrunedPerWebhook(t *testing.T) {
	n, id := notifier(t)
	ctx := context.Background()

	const over = 20
	for i := 1; i <= store.DeliveryRetainPerWebhook+over; i++ {
		if err := n.store.RecordDelivery(ctx, store.WebhookDelivery{
			WebhookID: id, Event: "alert.critical", Attempt: i, StatusCode: 200, Delivered: true,
		}); err != nil {
			t.Fatalf("record %d: %v", i, err)
		}
	}

	// ListDeliveries caps its read, so count the rows directly — the cap would
	// hide an unpruned table.
	var stored int
	if err := n.store.Pool().QueryRow(ctx,
		`SELECT COUNT(*) FROM webhook_target_deliveries WHERE webhook_id=$1::uuid`, id,
	).Scan(&stored); err != nil {
		t.Fatalf("count: %v", err)
	}
	if stored > store.DeliveryRetainPerWebhook {
		t.Fatalf("履歴が %d 件まで増えました (上限 %d)", stored, store.DeliveryRetainPerWebhook)
	}

	// Which rows survive is the point, not just how many. A prune that evicts
	// the newest rows instead of the oldest also settles at the retain count
	// and still leaves the single most recent row in place, so asserting on
	// rows[0] alone cannot tell the two apart. The retained window must be the
	// newest DeliveryRetainPerWebhook attempts: 21..520, not 1..499 plus 520.
	var oldest, newest int
	if err := n.store.Pool().QueryRow(ctx,
		`SELECT MIN(attempt), MAX(attempt) FROM webhook_target_deliveries WHERE webhook_id=$1::uuid`, id,
	).Scan(&oldest, &newest); err != nil {
		t.Fatalf("range: %v", err)
	}
	if newest != store.DeliveryRetainPerWebhook+over {
		t.Errorf("最新の試行が残っていません: 最大 attempt %d", newest)
	}
	if oldest != over+1 {
		t.Errorf("古い試行が削除されていません: 最小 attempt %d (期待: %d)", oldest, over+1)
	}
}
