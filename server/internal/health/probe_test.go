package health

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

type fakePinger struct{ err error }

func (f fakePinger) Ping(context.Context) error { return f.err }

func TestLivenessHandler_AlwaysOK(t *testing.T) {
	rec := httptest.NewRecorder()
	LivenessHandler()(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("liveness: want 200, got %d", rec.Code)
	}
}

func TestReadinessHandler_DBHealthy(t *testing.T) {
	rec := httptest.NewRecorder()
	// nil nc → NATS check skipped; healthy DB → ready.
	ReadinessHandler(fakePinger{err: nil}, nil)(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("readiness (DB ok): want 200, got %d", rec.Code)
	}
}

func TestReadinessHandler_DBDown(t *testing.T) {
	rec := httptest.NewRecorder()
	ReadinessHandler(fakePinger{err: errors.New("connection refused")}, nil)(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Errorf("readiness (DB down): want 503, got %d", rec.Code)
	}
	if body := rec.Body.String(); !contains(body, "not_ready") || !contains(body, "connection refused") {
		t.Errorf("readiness body should name the failed dependency, got %q", body)
	}
}

func TestReadinessHandler_NoDeps(t *testing.T) {
	// Both nil → nothing to fail → ready (a service wired without deps).
	rec := httptest.NewRecorder()
	ReadinessHandler(nil, nil)(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Errorf("readiness (no deps): want 200, got %d", rec.Code)
	}
}

func contains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
