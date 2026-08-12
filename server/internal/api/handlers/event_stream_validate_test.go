package handlers

import (
	"testing"
)

// ─── parseEventTypes ─────────────────────────────────────────────────────────

func TestParseEventTypes_EmptyReturnsAll(t *testing.T) {
	got := parseEventTypes("")
	if len(got) != 3 {
		t.Errorf("parseEventTypes('') = %v, want all 3 types", got)
	}
}

func TestParseEventTypes_WildcardReturnsAll(t *testing.T) {
	got := parseEventTypes("*")
	if len(got) != 3 {
		t.Errorf("parseEventTypes('*') = %v, want all 3 types", got)
	}
}

func TestParseEventTypes_SingleValid(t *testing.T) {
	got := parseEventTypes("alert")
	if len(got) != 1 || got[0] != "alert" {
		t.Errorf("parseEventTypes('alert') = %v, want ['alert']", got)
	}
}

func TestParseEventTypes_PluralStripped(t *testing.T) {
	got := parseEventTypes("alerts")
	if len(got) != 1 || got[0] != "alert" {
		t.Errorf("parseEventTypes('alerts') = %v, want ['alert']", got)
	}
}

func TestParseEventTypes_MultipleValues(t *testing.T) {
	got := parseEventTypes("alert,agent")
	if len(got) != 2 {
		t.Errorf("parseEventTypes('alert,agent') = %v, want 2 entries", got)
	}
}

func TestParseEventTypes_InvalidType_Ignored(t *testing.T) {
	got := parseEventTypes("unknown")
	// unknown is ignored, returns all (fallback)
	if len(got) != 3 {
		t.Errorf("parseEventTypes('unknown') = %v, want fallback to all 3", got)
	}
}

func TestParseEventTypes_MixedValidInvalid(t *testing.T) {
	got := parseEventTypes("alert,unknown")
	if len(got) != 1 || got[0] != "alert" {
		t.Errorf("parseEventTypes('alert,unknown') = %v, want ['alert']", got)
	}
}

func TestParseEventTypes_Deduplicates(t *testing.T) {
	got := parseEventTypes("alert,alert,alert")
	if len(got) != 1 {
		t.Errorf("parseEventTypes with duplicates = %v, want 1 unique", got)
	}
}
