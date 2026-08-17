package scheduler

import (
	"testing"
)

// ─── NewInsiderThreatDetector ─────────────────────────────────────────────────

func TestNewInsiderThreatDetector_NotNil(t *testing.T) {
	d := NewInsiderThreatDetector(nil, nil)
	if d == nil {
		t.Fatal("NewInsiderThreatDetector は nil を返すべきではありません")
	}
}

// ─── NewAgentHealthAlerter ────────────────────────────────────────────────────

func TestNewAgentHealthAlerter_NotNil(t *testing.T) {
	a := NewAgentHealthAlerter(nil, nil)
	if a == nil {
		t.Fatal("NewAgentHealthAlerter は nil を返すべきではありません")
	}
}

// ─── NewAlertDigestSender ─────────────────────────────────────────────────────

func TestNewAlertDigestSender_NotNil(t *testing.T) {
	s := NewAlertDigestSender(nil, nil)
	if s == nil {
		t.Fatal("NewAlertDigestSender は nil を返すべきではありません")
	}
}

// ─── NewAPIKeyRotator ─────────────────────────────────────────────────────────

func TestNewAPIKeyRotator_NotNil(t *testing.T) {
	r := NewAPIKeyRotator(nil, nil)
	if r == nil {
		t.Fatal("NewAPIKeyRotator は nil を返すべきではありません")
	}
}
