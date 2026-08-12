package notification

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/edr-platform/server/internal/store"
)

func sampleNotification() *AlertNotification {
	return &AlertNotification{
		AlertID:      "a1",
		Title:        "Suspicious PowerShell",
		Severity:     9,
		Status:       "open",
		Hostname:     "WIN-01",
		OS:           "windows",
		RuleName:     "PS EncodedCommand",
		Summary:      "エンコードされたコマンド",
		DashboardURL: "https://edr.example/alerts/a1",
		CreatedAt:    time.Unix(1_700_000_000, 0).UTC(),
	}
}

// ─── severity → presentation mappings (Slack/Teams/Email) ──────────────────────

func TestSeverityMappings_Boundaries(t *testing.T) {
	cases := []struct {
		sev                         int
		color, icon, bgColor, teams string
	}{
		{10, "#FF0000", "🔴", "#C0392B", "FF0000"},
		{9, "#FF0000", "🔴", "#C0392B", "FF0000"},
		{8, "#FF6600", "🟠", "#E67E22", "FF6600"},
		{7, "#FF6600", "🟠", "#E67E22", "FF6600"},
		{6, "#FFCC00", "🟡", "#F39C12", "FFCC00"},
		{5, "#FFCC00", "🟡", "#F39C12", "FFCC00"},
		{4, "#0099CC", "🔵", "#2980B9", "0099CC"},
		{1, "#0099CC", "🔵", "#2980B9", "0099CC"},
	}
	for _, c := range cases {
		if got := severityColor(c.sev); got != c.color {
			t.Errorf("severityColor(%d)=%s want %s", c.sev, got, c.color)
		}
		if got := severityIcon(c.sev); got != c.icon {
			t.Errorf("severityIcon(%d)=%s want %s", c.sev, got, c.icon)
		}
		if got := severityBGColor(c.sev); got != c.bgColor {
			t.Errorf("severityBGColor(%d)=%s want %s", c.sev, got, c.bgColor)
		}
		if got := teamsColor(c.sev); got != c.teams {
			t.Errorf("teamsColor(%d)=%s want %s", c.sev, got, c.teams)
		}
	}
}

func TestStatusJP(t *testing.T) {
	cases := map[string]string{
		"open":           "未対応",
		"investigating":  "調査中",
		"resolved":       "解決済み",
		"false_positive": "誤検知",
		"weird":          "weird", // default: passthrough
	}
	for in, want := range cases {
		if got := statusJP(in); got != want {
			t.Errorf("statusJP(%q)=%q want %q", in, got, want)
		}
	}
}

func TestEmailConfigDefaults(t *testing.T) {
	empty := EmailConfig{}
	if empty.senderName() != "EDR Platform" {
		t.Errorf("default senderName=%q", empty.senderName())
	}
	if empty.subjectPrefix() != "[EDR]" {
		t.Errorf("default subjectPrefix=%q", empty.subjectPrefix())
	}
	custom := EmailConfig{SenderName: "SecOps", SubjectPrefix: "[ALERT]"}
	if custom.senderName() != "SecOps" || custom.subjectPrefix() != "[ALERT]" {
		t.Errorf("custom overrides not honored: %q / %q", custom.senderName(), custom.subjectPrefix())
	}
}

// ─── webhook routing + payload ─────────────────────────────────────────────────

func TestAlertEventType(t *testing.T) {
	w := &WebhookNotifier{}
	cases := map[string]string{
		"alerts.critical": "alert.critical",
		"alerts.CRITICAL": "alert.critical", // case-insensitive
		"alerts.high":     "alert.high",
		"alerts.new":      "alert.any",
		"alerts":          "alert.any", // len<2
		"x":               "alert.any",
	}
	for subj, want := range cases {
		if got := w.alertEventType(subj); got != want {
			t.Errorf("alertEventType(%q)=%q want %q", subj, got, want)
		}
	}
}

func TestAgentEventType(t *testing.T) {
	w := &WebhookNotifier{}
	cases := map[string]string{
		"agent.events.abc.offline":       "agent.offline",
		"agent.events.abc.offline.extra": "agent.offline",
		"agent.events.abc.online":        "",
		"agent.events.abc.heartbeat":     "",
	}
	for subj, want := range cases {
		if got := w.agentEventType(subj); got != want {
			t.Errorf("agentEventType(%q)=%q want %q", subj, got, want)
		}
	}
}

func TestBuildPayload(t *testing.T) {
	raw := []byte(`{"agent_id":"x","severity":9}`)
	out, err := buildPayload("alert.critical", raw)
	if err != nil {
		t.Fatalf("buildPayload err: %v", err)
	}
	var env map[string]json.RawMessage
	if err := json.Unmarshal(out, &env); err != nil {
		t.Fatalf("payload not valid JSON: %v", err)
	}
	if string(env["event"]) != `"alert.critical"` {
		t.Errorf("event=%s", env["event"])
	}
	// The raw data must be embedded verbatim (not double-encoded to a string).
	if string(env["data"]) != string(raw) {
		t.Errorf("data not embedded raw: %s", env["data"])
	}
	if _, ok := env["timestamp"]; !ok {
		t.Error("timestamp missing from payload")
	}
}

// ─── email body building (formatting + HTML escaping) ──────────────────────────

func TestBuildEmail_ContentAndEscaping(t *testing.T) {
	s := NewEmailSender(EmailConfig{SubjectPrefix: "[EDR]"})
	n := sampleNotification()
	// Inject an XSS payload into a user-influenced field.
	n.Title = `<script>alert(1)</script>`
	subject, body, err := s.buildEmail(n)
	if err != nil {
		t.Fatalf("buildEmail err: %v", err)
	}
	if !strings.Contains(subject, "Lv.9") || !strings.Contains(subject, "WIN-01") {
		t.Errorf("subject missing severity/host: %q", subject)
	}
	// The raw <script> must be HTML-escaped, never emitted verbatim.
	if strings.Contains(body, "<script>alert(1)</script>") {
		t.Error("XSS: unescaped <script> in email body")
	}
	if !strings.Contains(body, "&lt;script&gt;") {
		t.Error("expected HTML-escaped title in body")
	}
	if !strings.Contains(body, "PS EncodedCommand") || !strings.Contains(body, "WIN-01") {
		t.Error("body missing rule/host details")
	}
	// sev 9 → critical background color
	if !strings.Contains(body, "#C0392B") {
		t.Error("body missing severity background color")
	}
}

// ─── Send paths via httptest (payload build + HTTP handling) ───────────────────

func TestSlackSend_SuccessAndError(t *testing.T) {
	var gotColor string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var p slackPayload
		_ = json.NewDecoder(r.Body).Decode(&p)
		if len(p.Attachments) > 0 {
			gotColor = p.Attachments[0].Color
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := NewSlackSender(srv.URL).Send(context.Background(), sampleNotification()); err != nil {
		t.Fatalf("Send (200) err: %v", err)
	}
	if gotColor != "#FF0000" {
		t.Errorf("slack payload color=%s want #FF0000", gotColor)
	}

	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errSrv.Close()
	if err := NewSlackSender(errSrv.URL).Send(context.Background(), sampleNotification()); err == nil {
		t.Error("Send (500) should error")
	}
}

func TestTeamsSend(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		if !strings.Contains(string(body), "MessageCard") {
			t.Errorf("teams body not a MessageCard: %s", body)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	if err := NewTeamsSender(srv.URL).Send(context.Background(), sampleNotification()); err != nil {
		t.Fatalf("Teams Send err: %v", err)
	}
	// Empty URL is a config error.
	if err := NewTeamsSender("").Send(context.Background(), sampleNotification()); err == nil {
		t.Error("empty Teams URL should error")
	}
}

func TestWebhookSenderSend_PayloadAndHMAC(t *testing.T) {
	var gotSig, gotTitle string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-EDR-Signature")
		var p map[string]interface{}
		_ = json.NewDecoder(r.Body).Decode(&p)
		gotTitle, _ = p["title"].(string)
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	if err := NewWebhookSender(srv.URL, "k").Send(context.Background(), sampleNotification()); err != nil {
		t.Fatalf("WebhookSender.Send err: %v", err)
	}
	if gotTitle != "Suspicious PowerShell" {
		t.Errorf("payload title=%q", gotTitle)
	}
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Errorf("HMAC signature not set: %q", gotSig)
	}

	// No secret → no signature header, but still delivers.
	var sawSig bool
	srv2 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		sawSig = r.Header.Get("X-EDR-Signature") != ""
		w.WriteHeader(http.StatusOK)
	}))
	defer srv2.Close()
	if err := NewWebhookSender(srv2.URL, "").Send(context.Background(), sampleNotification()); err != nil {
		t.Fatalf("WebhookSender.Send (no secret) err: %v", err)
	}
	if sawSig {
		t.Error("no secret should omit signature header")
	}
}

func TestSenderTypes(t *testing.T) {
	cases := []struct {
		sender interface{ Type() string }
		want   string
	}{
		{NewEmailSender(EmailConfig{}), ChannelEmail},
		{NewSlackSender("u"), ChannelSlack},
		{NewTeamsSender("u"), ChannelTeams},
		{NewWebhookSender("u", ""), ChannelWebhook},
	}
	for _, c := range cases {
		if got := c.sender.Type(); got != c.want {
			t.Errorf("Type()=%q want %q", got, c.want)
		}
	}
}

func TestDeliverTest_StatusAndHMAC(t *testing.T) {
	var gotSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotSig = r.Header.Get("X-Hub-Signature-256")
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	ok, code, err := DeliverTest(context.Background(),
		store.WebhookTarget{URL: srv.URL, Secret: "s3cr3t"}, map[string]string{"ping": "1"})
	if err != nil || !ok || code != 200 {
		t.Fatalf("DeliverTest(200): ok=%v code=%d err=%v", ok, code, err)
	}
	if !strings.HasPrefix(gotSig, "sha256=") {
		t.Errorf("HMAC signature header not set/invalid: %q", gotSig)
	}

	errSrv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer errSrv.Close()
	ok, code, err = DeliverTest(context.Background(), store.WebhookTarget{URL: errSrv.URL}, map[string]string{})
	if err != nil {
		t.Fatalf("DeliverTest(500) unexpected err: %v", err)
	}
	if ok || code != 500 {
		t.Errorf("DeliverTest(500): ok=%v code=%d, want false/500", ok, code)
	}
}
