package notification

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"sync/atomic"
	"testing"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Webhook delivery made exactly one attempt with a hardcoded 10 second timeout.
// There was no retry loop anywhere in this file, and PUT /webhooks/:id/retry-
// policy — which accepts max_retries, retry_delay_seconds and timeout_seconds —
// stored none of them and answered 200 echoing the request back.
//
// So a single 502 from the customer's SIEM lost the alert notification, with a
// Warn line as the only evidence, and there was no setting an operator could
// change to alter that.
//
// These tests count the attempts a real HTTP server actually receives.

// notifier returns a WebhookNotifier backed by the test database, plus the id
// of a webhook_targets row it can record delivery status against. The notifier
// is not stubbed: recording the outcome is part of what deliver() does, and a
// stub would hide a panic like the one a nil store produces.
func notifier(t *testing.T) (*WebhookNotifier, string) {
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

	var id string
	if err := pool.QueryRow(context.Background(), `
		INSERT INTO webhook_targets (name, url, secret, events, enabled)
		VALUES ('retry-fixture', 'https://example.invalid/hook', 's', ARRAY['alert.critical'], true)
		RETURNING id::text`).Scan(&id); err != nil {
		t.Fatalf("seed webhook target: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), `DELETE FROM webhook_targets WHERE id=$1::uuid`, id)
	})

	return NewWebhookNotifier(store.NewWebhookStore(pool), nil), id
}

// lastStatus reads back what the notifier recorded for a target.
func lastStatus(t *testing.T, n *WebhookNotifier, id string) *int {
	t.Helper()
	target, err := n.store.Get(context.Background(), id)
	if err != nil {
		t.Fatalf("read back: %v", err)
	}
	return target.LastStatus
}

// countingEndpoint serves the given status codes in order, repeating the last
// one, and counts requests.
func countingEndpoint(t *testing.T, codes ...int) (*httptest.Server, *int32) {
	t.Helper()
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		n := int(atomic.AddInt32(&hits, 1)) - 1
		if n >= len(codes) {
			n = len(codes) - 1
		}
		w.WriteHeader(codes[n])
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

// deliverTo runs one delivery against url with the given policy and returns the
// number of requests the endpoint saw.
func deliverTo(t *testing.T, n *WebhookNotifier, id, url string, policy store.WebhookRetryPolicy, hits *int32) int {
	t.Helper()
	n.deliver(context.Background(), store.WebhookTarget{
		ID:          id,
		Name:        "retry-fixture",
		URL:         url,
		RetryPolicy: policy,
	}, "alert.critical", []byte(`{"event":"alert.critical"}`))
	return int(atomic.LoadInt32(hits))
}

// TestATransientFailureIsRetried is the core gate.
func TestATransientFailureIsRetried(t *testing.T) {
	n, id := notifier(t)
	srv, hits := countingEndpoint(t, http.StatusBadGateway, http.StatusBadGateway, http.StatusOK)

	got := deliverTo(t, n, id, srv.URL, store.WebhookRetryPolicy{
		MaxRetries: 3, RetryDelaySeconds: 0, TimeoutSeconds: 5,
	}, hits)

	if got != 3 {
		t.Errorf("the endpoint saw %d request(s); two 502s followed by a 200 must "+
			"end in a delivered notification, not a dropped one", got)
	}
	if s := lastStatus(t, n, id); s == nil || *s != http.StatusOK {
		t.Errorf("last_status = %v; the console shows the outcome of the last "+
			"attempt, which succeeded", s)
	}
}

// TestTheConfiguredRetryCountIsWhatIsUsed. A policy that is stored but not read
// is the same silent failure one layer along.
func TestTheConfiguredRetryCountIsWhatIsUsed(t *testing.T) {
	n, id := notifier(t)
	for _, maxRetries := range []int{0, 1, 4} {
		srv, hits := countingEndpoint(t, http.StatusServiceUnavailable)

		got := deliverTo(t, n, id, srv.URL, store.WebhookRetryPolicy{
			MaxRetries: maxRetries, RetryDelaySeconds: 0, TimeoutSeconds: 5,
		}, hits)

		if want := maxRetries + 1; got != want {
			t.Errorf("max_retries=%d produced %d attempt(s), want %d", maxRetries, got, want)
		}
	}
}

// TestARejectedPayloadIsNotRetried. A 400 or a 404 will be a 400 or a 404 the
// next four times too; retrying only multiplies load on an endpoint that has
// already answered.
func TestARejectedPayloadIsNotRetried(t *testing.T) {
	n, id := notifier(t)
	for _, code := range []int{http.StatusBadRequest, http.StatusNotFound, http.StatusUnauthorized} {
		srv, hits := countingEndpoint(t, code)

		got := deliverTo(t, n, id, srv.URL, store.WebhookRetryPolicy{
			MaxRetries: 5, RetryDelaySeconds: 0, TimeoutSeconds: 5,
		}, hits)

		if got != 1 {
			t.Errorf("HTTP %d was retried %d times; the endpoint has answered and "+
				"will answer the same way again", code, got-1)
		}
	}
}

// TestBeingRateLimitedIsRetried. 429 is the one 4xx that means "later", not
// "no", and dropping the notification on it is exactly wrong.
func TestBeingRateLimitedIsRetried(t *testing.T) {
	n, id := notifier(t)
	srv, hits := countingEndpoint(t, http.StatusTooManyRequests, http.StatusOK)

	got := deliverTo(t, n, id, srv.URL, store.WebhookRetryPolicy{
		MaxRetries: 2, RetryDelaySeconds: 0, TimeoutSeconds: 5,
	}, hits)

	if got != 2 {
		t.Errorf("the endpoint saw %d request(s); a 429 followed by a 200 must be "+
			"delivered", got)
	}
}

// TestASuccessfulDeliveryIsNotRepeated.
func TestASuccessfulDeliveryIsNotRepeated(t *testing.T) {
	n, id := notifier(t)
	srv, hits := countingEndpoint(t, http.StatusOK)

	got := deliverTo(t, n, id, srv.URL, store.WebhookRetryPolicy{
		MaxRetries: 5, RetryDelaySeconds: 0, TimeoutSeconds: 5,
	}, hits)

	if got != 1 {
		t.Errorf("an accepted payload was sent %d times", got)
	}
}

// TestTheConfiguredTimeoutIsWhatBoundsAnAttempt. The timeout was hardcoded at
// 10 seconds; an operator who sets 1 second must get 1 second.
func TestTheConfiguredTimeoutIsWhatBoundsAnAttempt(t *testing.T) {
	n, id := notifier(t)
	release := make(chan struct{})
	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	// Registered in this order so that, cleanups being LIFO, the handlers are
	// released BEFORE srv.Close() — Close waits for outstanding handlers, and
	// the other order makes this test wait out the whole hang it is provoking.
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) })

	start := time.Now()
	got := deliverTo(t, n, id, srv.URL, store.WebhookRetryPolicy{
		MaxRetries: 1, RetryDelaySeconds: 0, TimeoutSeconds: 1,
	}, &hits)
	elapsed := time.Since(start)

	if got != 2 {
		t.Errorf("the endpoint saw %d request(s), want 2 (one attempt + one retry)", got)
	}
	// Two attempts at a 1 second timeout: well under the 10 seconds a single
	// hardcoded attempt used to take, and nowhere near 30.
	if elapsed > 6*time.Second {
		t.Errorf("delivery took %v; the configured timeout is not bounding the "+
			"attempt", elapsed)
	}
}

// TestAnUnreachableEndpointIsRetried covers the transport-error arm — nobody
// answers at all, so there is no status code to classify.
func TestAnUnreachableEndpointIsRetried(t *testing.T) {
	n, id := notifier(t)
	srv, _ := countingEndpoint(t, http.StatusOK)
	url := srv.URL
	srv.Close() // nothing is listening now

	before := lastStatus(t, n, id)
	done := make(chan struct{})
	go func() {
		defer close(done)
		n.deliver(context.Background(), store.WebhookTarget{
			ID: id, Name: "gone", URL: url,
			RetryPolicy: store.WebhookRetryPolicy{MaxRetries: 2, RetryDelaySeconds: 0, TimeoutSeconds: 2},
		}, "alert.critical", []byte(`{}`))
	}()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("delivery to a dead endpoint never returned")
	}
	// Nobody answered, so there is no status code to record — the column must
	// not be overwritten with a fabricated one.
	if after := lastStatus(t, n, id); (before == nil) != (after == nil) {
		t.Errorf("last_status changed from %v to %v after a delivery nobody answered",
			before, after)
	}
}

// TestClassifyAttempt pins the decision table directly, so the reason a status
// code is or is not retried is stated in one place.
func TestClassifyAttempt(t *testing.T) {
	for _, tc := range []struct {
		name string
		code int
		err  error
		want attemptOutcome
	}{
		{"accepted", 200, nil, outcomeDelivered},
		{"accepted, no content", 204, nil, outcomeDelivered},
		{"bad gateway", 502, nil, outcomeRetryable},
		{"unavailable", 503, nil, outcomeRetryable},
		{"rate limited", 429, nil, outcomeRetryable},
		{"bad request", 400, nil, outcomeRejected},
		{"unauthorized", 401, nil, outcomeRejected},
		{"not found", 404, nil, outcomeRejected},
		{"gone", 410, nil, outcomeRejected},
		{"nobody answered", 0, context.DeadlineExceeded, outcomeRetryable},
		{"redirect", 301, nil, outcomeRejected},
	} {
		if got := classifyAttempt(tc.code, tc.err); got != tc.want {
			t.Errorf("%s: classifyAttempt(%d, %v) = %v, want %v", tc.name, tc.code, tc.err, got, tc.want)
		}
	}
}

// TestRetryBackoffGrowsAndIsClamped.
func TestRetryBackoffGrowsAndIsClamped(t *testing.T) {
	p := store.WebhookRetryPolicy{RetryDelaySeconds: 5}
	if got := retryBackoff(p, 1); got != 5*time.Second {
		t.Errorf("first retry waits %v, want 5s", got)
	}
	if got := retryBackoff(p, 3); got != 15*time.Second {
		t.Errorf("third retry waits %v, want 15s", got)
	}
	// A policy at the top of its range must not multiply into minutes of a
	// parked goroutine per delivery.
	clamped := retryBackoff(store.WebhookRetryPolicy{RetryDelaySeconds: store.RetryDelaySecondsLimit}, 10)
	if clamped != time.Duration(store.RetryDelaySecondsLimit)*time.Second {
		t.Errorf("backoff = %v, want it clamped to %ds", clamped, store.RetryDelaySecondsLimit)
	}
}

// TestATargetWithNoPolicyStillDelivers. Not every read path selects the policy
// columns; a zero timeout would fail instantly on every attempt and turn a
// missing SELECT into total delivery failure.
func TestATargetWithNoPolicyStillDelivers(t *testing.T) {
	n, id := notifier(t)
	srv, hits := countingEndpoint(t, http.StatusOK)

	got := deliverTo(t, n, id, srv.URL, store.WebhookRetryPolicy{}, hits)

	if got != 1 {
		t.Errorf("a target with a zero-valued policy produced %d attempt(s), want 1", got)
	}
}
