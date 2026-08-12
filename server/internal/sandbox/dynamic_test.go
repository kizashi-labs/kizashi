package sandbox

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func newTestDynamic(base string) *DynamicClient {
	return &DynamicClient{client: &http.Client{Timeout: 2 * time.Second}, baseURL: base, apiKey: "k"}
}

func TestDynamicClient_InertWhenUnconfigured(t *testing.T) {
	c := &DynamicClient{}
	if c.Configured() {
		t.Fatal("expected not configured")
	}
	if _, err := c.Submit(context.Background(), "x", []byte("y")); err == nil {
		t.Error("expected error submitting when unconfigured")
	}
}

func TestDynamicClient_SubmitAndReport(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/tasks/create/file":
			if r.Header.Get("Authorization") != "Token k" {
				t.Errorf("missing auth header")
			}
			w.Write([]byte(`{"task_id": 4242}`))
		case r.Method == http.MethodGet && r.URL.Path == "/tasks/report/4242":
			w.Write([]byte(`{"info":{"score":8.5},"signatures":[{"name":"ransomware_files"},{"description":"c2_beacon"}]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer srv.Close()
	c := newTestDynamic(srv.URL)

	id, err := c.Submit(context.Background(), "sample.exe", []byte("MZ..."))
	if err != nil {
		t.Fatalf("submit: %v", err)
	}
	if id != "4242" {
		t.Errorf("job id = %q, want 4242", id)
	}
	rep, err := c.Report(context.Background(), id)
	if err != nil {
		t.Fatalf("report: %v", err)
	}
	if rep.Status != "completed" || rep.Verdict != "malicious" {
		t.Errorf("report = %+v, want completed/malicious", rep)
	}
	if len(rep.Signatures) != 2 {
		t.Errorf("signatures = %v", rep.Signatures)
	}
}

func TestDynamicClient_ReportRunning(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound) // report not ready yet
	}))
	defer srv.Close()
	c := newTestDynamic(srv.URL)
	rep, err := c.Report(context.Background(), "1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if rep.Status != "running" {
		t.Errorf("status = %q, want running", rep.Status)
	}
}

func TestVerdictForDynamicScore(t *testing.T) {
	cases := []struct {
		s float64
		w string
	}{{8, "malicious"}, {4, "suspicious"}, {1, "clean"}, {0, "unknown"}}
	for _, c := range cases {
		if got := verdictForDynamicScore(c.s); got != c.w {
			t.Errorf("verdictForDynamicScore(%v)=%q want %q", c.s, got, c.w)
		}
	}
}
