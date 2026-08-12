package siem

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func sampleAlert() *AlertPayload {
	return &AlertPayload{
		ID:             "alertABCDEF12",
		AgentID:        "agent-1",
		Hostname:       "WIN-01",
		OS:             "windows",
		RuleName:       "Encoded PowerShell",
		Severity:       9, // platform alert severity is 1-10 (9 = critical)
		Status:         "open",
		MITRETechnique: "T1059",
		AIThreatName:   "CobaltStrike",
		AISummary:      "beacon",
		CreatedAt:      time.Unix(1_700_000_000, 0).UTC(),
	}
}

// hostPort splits an httptest server URL into (host, port) for the Target, which
// rebuilds the URL from Host/Port rather than taking a full URL.
func hostPort(t *testing.T, rawURL string) (string, int) {
	t.Helper()
	u, err := url.Parse(rawURL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}
	p, err := strconv.Atoi(u.Port())
	if err != nil {
		t.Fatalf("parse port: %v", err)
	}
	return u.Hostname(), p
}

func TestFormatCEF(t *testing.T) {
	a := sampleAlert()
	a.RuleName = `rule|with\pipe` // must be CEF-escaped in the header
	out := formatCEF(a)

	if !strings.HasPrefix(out, "<134>1 ") {
		t.Errorf("missing syslog envelope prefix: %q", out)
	}
	if !strings.Contains(out, "CEF:0|FalconEDR|EDR Platform|1.0|") {
		t.Errorf("missing CEF header: %q", out)
	}
	// Pipe and backslash escaped in the header Name field.
	if !strings.Contains(out, `rule\|with\\pipe`) {
		t.Errorf("rule name not CEF-escaped: %q", out)
	}
	// Severity 9 → CEF 9 (alert severity is 1-10, aligned with CEF 0-10).
	if !strings.Contains(out, "|9|") {
		t.Errorf("severity not mapped to 9: %q", out)
	}
	for _, want := range []string{"src=agent-1", "dhost=WIN-01", "act=open", "rt=", "cs1=T1059", "cs1Label=MITRETechnique", "cs2=CobaltStrike"} {
		if !strings.Contains(out, want) {
			t.Errorf("CEF extension missing %q in: %q", want, out)
		}
	}
}

func TestFormatCEF_SeverityCap(t *testing.T) {
	a := sampleAlert()
	a.Severity = 250 // out-of-range severity clamps to CEF 10
	if !strings.Contains(formatCEF(a), "|10|") {
		t.Errorf("out-of-range severity should clamp CEF severity to 10")
	}
}

func TestFormatCEF_OptionalFieldsOmitted(t *testing.T) {
	a := sampleAlert()
	a.MITRETechnique = ""
	a.AIThreatName = ""
	out := formatCEF(a)
	if strings.Contains(out, "cs1Label") || strings.Contains(out, "cs2Label") {
		t.Errorf("empty MITRE/threat should omit cs1/cs2: %q", out)
	}
}

func TestFormatLEEF(t *testing.T) {
	a := sampleAlert()
	a.Severity = 5 // 1-10 severity maps 1:1 to LEEF sev
	out := formatLEEF(a)
	if !strings.HasPrefix(out, "LEEF:2.0|FalconEDR|EDR Platform|1.0|") {
		t.Errorf("missing LEEF header: %q", out)
	}
	for _, want := range []string{"sev=5", "hostname=WIN-01", "name=Encoded PowerShell", "status=open"} {
		if !strings.Contains(out, want) {
			t.Errorf("LEEF missing %q in: %q", want, out)
		}
	}
	// Fields are tab-delimited.
	if !strings.Contains(out, "\t") {
		t.Errorf("LEEF fields should be tab-delimited: %q", out)
	}
}

func TestForwardSplunkHEC(t *testing.T) {
	var gotPath, gotAuth, gotEventID string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		var body map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&body)
		if ev, ok := body["event"].(map[string]interface{}); ok {
			gotEventID, _ = ev["id"].(string)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	f := NewForwarder()
	host, port := hostPort(t, srv.URL)
	tgt := &Target{Type: "splunk_hec", Host: host, Port: port, Token: "tok", IndexName: "main"}

	if err := f.forward(context.Background(), tgt, sampleAlert()); err != nil {
		t.Fatalf("splunk forward err: %v", err)
	}
	if gotPath != "/services/collector/event" {
		t.Errorf("splunk path=%q", gotPath)
	}
	if gotAuth != "Splunk tok" {
		t.Errorf("splunk auth=%q", gotAuth)
	}
	if gotEventID != "alertABCDEF12" {
		t.Errorf("splunk event id=%q", gotEventID)
	}

	// A 4xx from the collector must surface as an error.
	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer errSrv.Close()
	eh, ep := hostPort(t, errSrv.URL)
	if err := f.forward(context.Background(), &Target{Type: "splunk_hec", Host: eh, Port: ep}, sampleAlert()); err == nil {
		t.Error("splunk 403 should error")
	}
}

func TestForwardElasticECS(t *testing.T) {
	var gotPath, gotAuth string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotAuth = r.Header.Get("Authorization")
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	f := NewForwarder()
	host, port := hostPort(t, srv.URL)
	tgt := &Target{Type: "elastic_ecs", Host: host, Port: port, Token: "apikey", IndexName: "edr-alerts"}

	if err := f.forward(context.Background(), tgt, sampleAlert()); err != nil {
		t.Fatalf("elastic forward err: %v", err)
	}
	if gotPath != "/edr-alerts/_doc" {
		t.Errorf("elastic path=%q", gotPath)
	}
	if gotAuth != "ApiKey apikey" {
		t.Errorf("elastic auth=%q", gotAuth)
	}

	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
	}))
	defer errSrv.Close()
	eh, ep := hostPort(t, errSrv.URL)
	if err := f.forward(context.Background(), &Target{Type: "elastic_ecs", Host: eh, Port: ep}, sampleAlert()); err == nil {
		t.Error("elastic 400 should error")
	}
}

func TestForward_UnknownType(t *testing.T) {
	f := NewForwarder()
	err := f.forward(context.Background(), &Target{Type: "bogus"}, sampleAlert())
	if err == nil || !strings.Contains(err.Error(), "unknown SIEM type") {
		t.Errorf("unknown type should error, got: %v", err)
	}
}

func TestLoadTargets(t *testing.T) {
	f := NewForwarder()
	f.LoadTargets([]*Target{{ID: "t1", Enabled: true}})
	f.mu.RLock()
	n := len(f.targets)
	f.mu.RUnlock()
	if n != 1 {
		t.Errorf("LoadTargets: want 1 target, got %d", n)
	}
}
