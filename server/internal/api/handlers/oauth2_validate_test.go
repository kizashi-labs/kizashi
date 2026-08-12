package handlers

import (
	"encoding/json"
	"testing"
)

// ─── nullableJSON ─────────────────────────────────────────────────────────────
// Note: this is a different function from cwfNullableJSON; it returns a string.

func TestNullableJSON_Empty_ReturnsNull(t *testing.T) {
	if got := nullableJSON(json.RawMessage{}); got != "null" {
		t.Errorf("nullableJSON(empty) = %q, want 'null'", got)
	}
}

func TestNullableJSON_Nil_ReturnsNull(t *testing.T) {
	if got := nullableJSON(nil); got != "null" {
		t.Errorf("nullableJSON(nil) = %q, want 'null'", got)
	}
}

func TestNullableJSON_ValidJSON_ReturnsString(t *testing.T) {
	raw := json.RawMessage(`{"key":"value"}`)
	got := nullableJSON(raw)
	if got != `{"key":"value"}` {
		t.Errorf("nullableJSON(valid) = %q, want original string", got)
	}
}

func TestNullableJSON_JSONArray_ReturnsString(t *testing.T) {
	raw := json.RawMessage(`[1,2,3]`)
	got := nullableJSON(raw)
	if got != "[1,2,3]" {
		t.Errorf("nullableJSON(array) = %q, want '[1,2,3]'", got)
	}
}
