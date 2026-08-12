package threatintel

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestEnricher(base string) *LiveEnricher {
	return &LiveEnricher{
		client: &http.Client{Timeout: 2 * time.Second},
		vtKey:  "vt", otxKey: "otx", abuseKey: "abuse",
		vtBase: base, otxBase: base, abuseBase: base,
		timeout: 2 * time.Second,
	}
}

func TestLiveEnricher_NotConfiguredIsInert(t *testing.T) {
	e := &LiveEnricher{} // no keys
	if e.Configured() {
		t.Fatal("expected not configured with no keys")
	}
	r := e.Enrich(context.Background(), "1.2.3.4", "ip")
	if r.Found {
		t.Errorf("expected no result when unconfigured, got %+v", r)
	}
}

func TestLiveEnricher_VTHashMalicious(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-apikey") != "vt" {
			t.Errorf("missing VT api key header")
		}
		w.Write([]byte(`{"data":{"attributes":{"last_analysis_stats":{"malicious":50,"suspicious":5,"harmless":15},"tags":["trojan","peexe"]}}}`))
	}))
	defer srv.Close()
	e := newTestEnricher(srv.URL)
	e.otxKey = "" // isolate VT
	r := e.Enrich(context.Background(), "abc123hash", "hash")
	if !r.Found {
		t.Fatal("expected found")
	}
	if r.Verdict != "malicious" {
		t.Errorf("verdict = %q, want malicious (score=%d)", r.Verdict, r.Score)
	}
	if r.Malicious != 50 {
		t.Errorf("malicious = %d, want 50", r.Malicious)
	}
	if len(r.Tags) == 0 {
		t.Error("expected tags from VT")
	}
}

func TestLiveEnricher_AbuseIPDB(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"data":{"abuseConfidenceScore":90,"totalReports":12,"usageType":"Data Center"}}`))
	}))
	defer srv.Close()
	e := newTestEnricher(srv.URL)
	e.otxKey = "" // isolate AbuseIPDB
	r := e.Enrich(context.Background(), "9.9.9.9", "ip")
	if !r.Found || r.Verdict != "malicious" {
		t.Errorf("expected malicious, got found=%v verdict=%q score=%d", r.Found, r.Verdict, r.Score)
	}
	if len(r.Sources) != 1 || r.Sources[0] != "AbuseIPDB" {
		t.Errorf("sources = %v", r.Sources)
	}
}

func TestLiveEnricher_ProviderErrorSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // simulate bad key / rate limit
	}))
	defer srv.Close()
	e := newTestEnricher(srv.URL)
	r := e.Enrich(context.Background(), "abc", "hash")
	if r.Found {
		t.Errorf("expected no result when providers error, got %+v", r)
	}
}

func TestVerdictForScore(t *testing.T) {
	cases := []struct {
		score int
		want  string
	}{{70, "malicious"}, {40, "suspicious"}, {10, "clean"}, {0, "unknown"}}
	for _, c := range cases {
		if got := verdictForScore(c.score); got != c.want {
			t.Errorf("verdictForScore(%d) = %q, want %q", c.score, got, c.want)
		}
	}
}
