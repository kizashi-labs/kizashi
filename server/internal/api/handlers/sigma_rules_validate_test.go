package handlers

import (
	"sort"
	"testing"
)

// ─── sigmaCollectStrings ──────────────────────────────────────────────────────

func TestSigmaCollectStrings_PlainString(t *testing.T) {
	got := sigmaCollectStrings("hello")
	if len(got) != 1 || got[0] != "hello" {
		t.Errorf("sigmaCollectStrings(string) = %v, want ['hello']", got)
	}
}

func TestSigmaCollectStrings_StringSlice(t *testing.T) {
	input := []interface{}{"a", "b", "c"}
	got := sigmaCollectStrings(input)
	if len(got) != 3 {
		t.Errorf("sigmaCollectStrings(slice) = %v, want 3 elements", got)
	}
}

func TestSigmaCollectStrings_NestedMap(t *testing.T) {
	input := map[string]interface{}{
		"key1": "value1",
		"key2": "value2",
	}
	got := sigmaCollectStrings(input)
	if len(got) != 2 {
		t.Errorf("sigmaCollectStrings(map) = %v, want 2 elements", got)
	}
	sort.Strings(got)
	if got[0] != "value1" || got[1] != "value2" {
		t.Errorf("sigmaCollectStrings(map) = %v, want [value1, value2]", got)
	}
}

func TestSigmaCollectStrings_DeepNested(t *testing.T) {
	input := map[string]interface{}{
		"level1": map[string]interface{}{
			"level2": []interface{}{"deep1", "deep2"},
		},
	}
	got := sigmaCollectStrings(input)
	if len(got) != 2 {
		t.Errorf("sigmaCollectStrings(deep nested) = %v, want 2 elements", got)
	}
}

func TestSigmaCollectStrings_Nil_ReturnsEmpty(t *testing.T) {
	got := sigmaCollectStrings(nil)
	if len(got) != 0 {
		t.Errorf("sigmaCollectStrings(nil) = %v, want empty", got)
	}
}

func TestSigmaCollectStrings_NonString_Skipped(t *testing.T) {
	// integers are not collected
	input := []interface{}{42, "valid", 3.14}
	got := sigmaCollectStrings(input)
	if len(got) != 1 || got[0] != "valid" {
		t.Errorf("sigmaCollectStrings(mixed) = %v, want ['valid']", got)
	}
}
