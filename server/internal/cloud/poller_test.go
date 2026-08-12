package cloud

import (
	"testing"
)

// ─── NewPoller ────────────────────────────────────────────────────────────────

func TestNewPoller_NotNil(t *testing.T) {
	p := NewPoller(nil)
	if p == nil {
		t.Fatal("NewPoller は nil を返すべきではありません")
	}
}

func TestNewPoller_HTTPClientNotNil(t *testing.T) {
	p := NewPoller(nil)
	if p.client == nil {
		t.Error("httpClient が nil です")
	}
}

func TestNewPoller_IntervalSet(t *testing.T) {
	p := NewPoller(nil)
	if p.interval <= 0 {
		t.Errorf("interval: got %v, want > 0", p.interval)
	}
}

func TestNewPoller_PoolNil(t *testing.T) {
	p := NewPoller(nil)
	if p.pool != nil {
		t.Error("pool=nil で作成したとき pool は nil であるべきです")
	}
}

// ─── NewPollerWithNATS ────────────────────────────────────────────────────────

func TestNewPollerWithNATS_NotNil(t *testing.T) {
	p := NewPollerWithNATS(nil, nil)
	if p == nil {
		t.Fatal("NewPollerWithNATS は nil を返すべきではありません")
	}
}

func TestNewPollerWithNATS_NATSNil(t *testing.T) {
	p := NewPollerWithNATS(nil, nil)
	if p.nc != nil {
		t.Error("nc=nil で作成したとき nc は nil であるべきです")
	}
}

// ─── Integration 構造体フィールド ─────────────────────────────────────────────

func TestIntegration_Fields(t *testing.T) {
	intg := Integration{
		ID:       "intg-1",
		Provider: "aws",
		Enabled:  true,
	}
	if intg.Provider != "aws" {
		t.Errorf("Provider: got %q, want aws", intg.Provider)
	}
	if !intg.Enabled {
		t.Error("Enabled: got false, want true")
	}
}

// ─── CloudEventMsg 構造体フィールド ───────────────────────────────────────────

func TestCloudEventMsg_Fields(t *testing.T) {
	msg := CloudEventMsg{
		ID:        "evt-1",
		Provider:  "azure",
		EventType: "signin",
		SourceIP:  "1.2.3.4",
	}
	if msg.Provider != "azure" {
		t.Errorf("Provider: got %q, want azure", msg.Provider)
	}
	if msg.SourceIP != "1.2.3.4" {
		t.Errorf("SourceIP: got %q, want 1.2.3.4", msg.SourceIP)
	}
}
