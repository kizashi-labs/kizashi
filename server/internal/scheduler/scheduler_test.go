package scheduler

import (
	"testing"
)

// ─── NewAlertAggregator ───────────────────────────────────────────────────────

func TestNewAlertAggregator_NotNil(t *testing.T) {
	a := NewAlertAggregator(nil)
	if a == nil {
		t.Fatal("NewAlertAggregator は nil を返すべきではありません")
	}
}

func TestNewAlertAggregator_PoolNil(t *testing.T) {
	a := NewAlertAggregator(nil)
	if a.pool != nil {
		t.Error("pool=nil で作成したとき pool は nil であるべきです")
	}
}

// ─── NewIOCMatcher ────────────────────────────────────────────────────────────

func TestNewIOCMatcher_NotNil(t *testing.T) {
	m := NewIOCMatcher(nil, nil)
	if m == nil {
		t.Fatal("NewIOCMatcher は nil を返すべきではありません")
	}
}

func TestNewIOCMatcher_PoolNil(t *testing.T) {
	m := NewIOCMatcher(nil, nil)
	if m.pool != nil {
		t.Error("pool=nil で作成したとき pool は nil であるべきです")
	}
}

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
