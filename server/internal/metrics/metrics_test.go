package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

// DetectionsByEngine must be registered on the default registry and exposed via
// the metrics Handler (which now serves the promauto registry, not just the
// hand-written atomic counters).
func TestDetectionsByEngine_ExposedViaHandler(t *testing.T) {
	DetectionsByEngine.WithLabelValues("sigma", "T1059").Inc()
	DetectionsByEngine.WithLabelValues("chain", "T1566.001").Inc()

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	Handler()(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "edr_detections_total") {
		t.Fatalf("metrics handler should expose edr_detections_total, got:\n%s", body)
	}
	if !strings.Contains(body, `engine="chain"`) {
		t.Errorf("expected chain engine label in output")
	}
}

// ─── atomic counters ──────────────────────────────────────────────────────────

func TestHTTPRequests_Increment(t *testing.T) {
	before := HTTPRequests.Load()
	HTTPRequests.Add(1)
	if HTTPRequests.Load() != before+1 {
		t.Errorf("HTTPRequests: got %d, want %d", HTTPRequests.Load(), before+1)
	}
}

func TestHTTPErrors_Increment(t *testing.T) {
	before := HTTPErrors.Load()
	HTTPErrors.Add(1)
	if HTTPErrors.Load() != before+1 {
		t.Errorf("HTTPErrors: got %d, want %d", HTTPErrors.Load(), before+1)
	}
}

func TestAlertsCreated_Increment(t *testing.T) {
	before := AlertsCreated.Load()
	AlertsCreated.Add(1)
	if AlertsCreated.Load() != before+1 {
		t.Errorf("AlertsCreated: got %d, want %d", AlertsCreated.Load(), before+1)
	}
}

func TestEventsIngested_Increment(t *testing.T) {
	before := EventsIngested.Load()
	EventsIngested.Add(5)
	if EventsIngested.Load() != before+5 {
		t.Errorf("EventsIngested: got %d, want %d", EventsIngested.Load(), before+5)
	}
}

func TestAgentsOnline_SetAndLoad(t *testing.T) {
	AgentsOnline.Store(42)
	if AgentsOnline.Load() != 42 {
		t.Errorf("AgentsOnline: got %d, want 42", AgentsOnline.Load())
	}
}

func TestRulesLoaded_Increment(t *testing.T) {
	before := RulesLoaded.Load()
	RulesLoaded.Add(10)
	if RulesLoaded.Load() != before+10 {
		t.Errorf("RulesLoaded: got %d, want %d", RulesLoaded.Load(), before+10)
	}
}

// ─── Handler ──────────────────────────────────────────────────────────────────

func TestHandler_NotNil(t *testing.T) {
	h := Handler()
	if h == nil {
		t.Fatal("Handler() は nil を返すべきではありません")
	}
}

func TestHandler_ReturnsPrometheusText(t *testing.T) {
	h := Handler()
	w := httptest.NewRecorder()
	h(w, nil)
	body := w.Body.String()
	if !strings.Contains(body, "edr_") {
		t.Errorf("Handler レスポンスに edr_ メトリクスが含まれていません: %s", body[:min(200, len(body))])
	}
}

func TestHandler_ContentTypeIsText(t *testing.T) {
	h := Handler()
	w := httptest.NewRecorder()
	h(w, nil)
	ct := w.Header().Get("Content-Type")
	if !strings.HasPrefix(ct, "text/plain") {
		t.Errorf("Content-Type: got %q, want text/plain prefix", ct)
	}
}

func TestHandler_ContainsUptimeMetric(t *testing.T) {
	h := Handler()
	w := httptest.NewRecorder()
	h(w, nil)
	if !strings.Contains(w.Body.String(), "edr_uptime_seconds") {
		t.Error("Handler: edr_uptime_seconds が含まれていません")
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
