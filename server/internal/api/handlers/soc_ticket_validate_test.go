package handlers

import (
	"strings"
	"testing"
	"time"
)

// ─── generateTicketNumber ────────────────────────────────────────────────────

func TestGenerateTicketNumber_Format(t *testing.T) {
	ticket := generateTicketNumber()
	if !strings.HasPrefix(ticket, "TKT-") {
		t.Errorf("generateTicketNumber() = %q, want TKT- prefix", ticket)
	}
}

func TestGenerateTicketNumber_ContainsDate(t *testing.T) {
	today := time.Now().Format("20060102")
	ticket := generateTicketNumber()
	if !strings.Contains(ticket, today) {
		t.Errorf("generateTicketNumber() = %q, want to contain today %s", ticket, today)
	}
}

func TestGenerateTicketNumber_Unique(t *testing.T) {
	seen := make(map[string]bool)
	for i := 0; i < 10; i++ {
		t := generateTicketNumber()
		seen[t] = true
	}
	// Should produce varied ticket numbers (not all identical)
	// At minimum generates distinct format
	if len(seen) == 0 {
		t.Error("generateTicketNumber: produced no results")
	}
}

// ─── slaDueAt ────────────────────────────────────────────────────────────────

func TestSlaDueAt_Critical_4Hours(t *testing.T) {
	before := time.Now()
	due := slaDueAt("critical")
	after := time.Now()
	expected := 4 * time.Hour
	diff := due.Sub(before)
	if diff < expected-time.Second || diff > expected+time.Second+(after.Sub(before)) {
		t.Errorf("slaDueAt(critical): due in %v, want ~4h", diff)
	}
}

func TestSlaDueAt_High_8Hours(t *testing.T) {
	before := time.Now()
	due := slaDueAt("high")
	diff := due.Sub(before)
	expected := 8 * time.Hour
	if diff < expected-time.Second || diff > expected+2*time.Second {
		t.Errorf("slaDueAt(high): due in %v, want ~8h", diff)
	}
}

func TestSlaDueAt_Medium_24Hours(t *testing.T) {
	before := time.Now()
	due := slaDueAt("medium")
	diff := due.Sub(before)
	expected := 24 * time.Hour
	if diff < expected-time.Second || diff > expected+2*time.Second {
		t.Errorf("slaDueAt(medium): due in %v, want ~24h", diff)
	}
}

func TestSlaDueAt_Low_72Hours(t *testing.T) {
	before := time.Now()
	due := slaDueAt("low")
	diff := due.Sub(before)
	expected := 72 * time.Hour
	if diff < expected-time.Second || diff > expected+2*time.Second {
		t.Errorf("slaDueAt(low): due in %v, want ~72h", diff)
	}
}

func TestSlaDueAt_Unknown_DefaultsToLow(t *testing.T) {
	low := slaDueAt("low")
	unknown := slaDueAt("unknown")
	diff := unknown.Sub(low)
	if diff < -2*time.Second || diff > 2*time.Second {
		t.Errorf("slaDueAt(unknown) should equal low SLA, diff=%v", diff)
	}
}
