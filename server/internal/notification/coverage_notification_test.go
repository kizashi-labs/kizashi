package notification

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/edr-platform/server/internal/store"
)

func covAlert() *AlertNotification {
	tr := true
	return &AlertNotification{
		AlertID: "cov-1", Title: "cov alert", Severity: 9, Status: "open",
		Hostname: "host-1", OS: "linux", RuleName: "cov-rule",
		Summary: "summary", AIIsThreat: &tr, CreatedAt: time.Now(),
	}
}

// TestSenders_HTTP points the webhook-style senders at a local httptest server
// so their payload-building + POST paths run without external network.
func TestSenders_HTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ctx := context.Background()
	n := covAlert()

	slack := NewSlackSender(srv.URL)
	if slack.Type() != ChannelSlack {
		t.Fatalf("slack type")
	}
	if err := slack.Send(ctx, n); err != nil {
		t.Fatalf("slack Send: %v", err)
	}

	teams := NewTeamsSender(srv.URL)
	if teams.Type() != ChannelTeams {
		t.Fatalf("teams type")
	}
	if err := teams.Send(ctx, n); err != nil {
		t.Fatalf("teams Send: %v", err)
	}

	wh := NewWebhookSender(srv.URL, "cov-secret")
	if wh.Type() != ChannelWebhook {
		t.Fatalf("webhook type")
	}
	if err := wh.Send(ctx, n); err != nil {
		t.Fatalf("webhook Send: %v", err)
	}

	ok, code, err := DeliverTest(ctx, store.WebhookTarget{Name: "cov", URL: srv.URL, Events: []string{"alert.created"}, Enabled: true}, map[string]any{"k": "v"})
	if err != nil || !ok || code != http.StatusOK {
		t.Fatalf("DeliverTest: ok=%v code=%d err=%v", ok, code, err)
	}
}

func TestDispatcher_HTTP(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()
	ctx := context.Background()

	d := NewDispatcher("https://dash.local")
	d.LoadChannels([]ChannelConfig{
		{ID: "s1", Name: "slack", Type: ChannelSlack, Config: map[string]string{"webhook_url": srv.URL}, Enabled: true, MinSeverity: 1},
		{ID: "t1", Name: "teams", Type: ChannelTeams, Config: map[string]string{"webhook_url": srv.URL}, Enabled: true, MinSeverity: 1},
		{ID: "w1", Name: "webhook", Type: ChannelWebhook, Config: map[string]string{"webhook_url": srv.URL}, Enabled: true, MinSeverity: 1},
	})
	d.Notify(ctx, covAlert())
	if err := d.NotifyText(ctx, "cov message", 8); err != nil {
		t.Fatalf("NotifyText: %v", err)
	}
	if err := d.TestChannel(ctx, "s1"); err != nil {
		t.Fatalf("TestChannel: %v", err)
	}
}
