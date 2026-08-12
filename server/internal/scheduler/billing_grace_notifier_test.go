package scheduler

import (
	"strings"
	"testing"
	"time"
)

func TestNewBillingGraceNotifier_NotNil(t *testing.T) {
	n := NewBillingGraceNotifier(nil)
	if n == nil {
		t.Fatal("NewBillingGraceNotifier は nil を返すべきではありません")
	}
}

func TestNewBillingGraceNotifier_DefaultTick(t *testing.T) {
	n := NewBillingGraceNotifier(nil)
	if n.tick != 24*time.Hour {
		t.Errorf("default tick = %v, want 24h", n.tick)
	}
}

func TestBillingGracePeriodDays_Default(t *testing.T) {
	t.Setenv("BILLING_GRACE_PERIOD_DAYS", "")
	if got := billingGracePeriodDays(); got != defaultBillingGracePeriodDays {
		t.Errorf("default = %d, want %d", got, defaultBillingGracePeriodDays)
	}
}

func TestBillingGracePeriodDays_EnvOverride(t *testing.T) {
	t.Setenv("BILLING_GRACE_PERIOD_DAYS", "7")
	if got := billingGracePeriodDays(); got != 7 {
		t.Errorf("override = %d, want 7", got)
	}
}

func TestBillingGracePeriodDays_InvalidFallsBack(t *testing.T) {
	t.Setenv("BILLING_GRACE_PERIOD_DAYS", "garbage")
	if got := billingGracePeriodDays(); got != defaultBillingGracePeriodDays {
		t.Errorf("invalid → default, got %d want %d", got, defaultBillingGracePeriodDays)
	}
}

func TestSafeStr_FallbackWhenNil(t *testing.T) {
	if got := safeStr(nil, "fallback"); got != "fallback" {
		t.Errorf("nil → fallback, got %q", got)
	}
}

func TestSafeStr_FallbackWhenEmpty(t *testing.T) {
	empty := ""
	if got := safeStr(&empty, "fallback"); got != "fallback" {
		t.Errorf("empty → fallback, got %q", got)
	}
}

func TestSafeStr_PrefersValue(t *testing.T) {
	v := "real value"
	if got := safeStr(&v, "fallback"); got != "real value" {
		t.Errorf("got %q, want real value", got)
	}
}

// ─── buildGraceEmail ─────────────────────────────────────────────────────────

func TestBuildGraceEmail_ExpiredToday(t *testing.T) {
	end := time.Date(2026, 4, 21, 0, 0, 0, 0, time.UTC)
	subject, body := buildGraceEmail("Tenant A", "starter", end, 0)
	if !strings.Contains(subject, "本日終了") {
		t.Errorf("subject should mention 本日終了, got: %s", subject)
	}
	if !strings.Contains(body, "Free プラン") {
		t.Error("body should mention Free プラン for day-0 notifications")
	}
}

func TestBuildGraceEmail_OneDayRemaining(t *testing.T) {
	end := time.Date(2026, 4, 22, 0, 0, 0, 0, time.UTC)
	subject, body := buildGraceEmail("Tenant B", "professional", end, 1)
	if !strings.Contains(subject, "残り 1 日") {
		t.Errorf("subject should mention 残り 1 日, got: %s", subject)
	}
	if !strings.Contains(body, "再契約") {
		t.Error("body should prompt for 再契約")
	}
}

func TestBuildGraceEmail_SevenDaysRemaining(t *testing.T) {
	end := time.Date(2026, 4, 28, 0, 0, 0, 0, time.UTC)
	subject, _ := buildGraceEmail("Tenant C", "starter", end, 7)
	if !strings.Contains(subject, "残り 7 日") {
		t.Errorf("subject should mention 残り 7 日, got: %s", subject)
	}
}
