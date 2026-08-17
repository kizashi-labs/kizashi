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

// 答えなかった提供元は、集計から黙って外れないこと。
//
// この検査は以前 ProviderErrorSkipped という名前で、Found=false だけを
// 確かめていました。それは「全部の提供元が答えて、誰もこの指標を知らな
// かった」場合とまったく同じ形です。評判サービスが全部落ちていても、
// その IP は「知られていない」＝清潔として扱われます。
func TestLiveEnricher_ProviderErrorIsReportedNotSkipped(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden) // simulate bad key / rate limit
	}))
	defer srv.Close()
	e := newTestEnricher(srv.URL)
	r := e.Enrich(context.Background(), "abc", "hash")
	if r.Found {
		t.Errorf("expected no result when providers error, got %+v", r)
	}
	if len(r.Unreachable) == 0 {
		t.Fatalf("答えなかった提供元が報告されていません: %+v", r)
	}
	for _, want := range []string{"VirusTotal", "AlienVault OTX"} {
		found := false
		for _, got := range r.Unreachable {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s が Unreachable にありません: %v", want, r.Unreachable)
		}
	}
}

// 全部が答えて「知らない」と言った場合は、Unreachable は空であること。
// 上の検査だけだと「常に全部を Unreachable に入れる」でも通ります。
func TestLiveEnricher_AnsweredButUnknownIsNotUnreachable(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{}`))
	}))
	defer srv.Close()
	e := newTestEnricher(srv.URL)
	r := e.Enrich(context.Background(), "abc", "hash")
	if len(r.Unreachable) != 0 {
		t.Errorf("答えた提供元が Unreachable に入っています: %v", r.Unreachable)
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
