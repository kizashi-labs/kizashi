package handlers

import "testing"

// ─── jsonRawOrEmpty ───────────────────────────────────────────────────────────

func TestJsonRawOrEmpty_Nil_ReturnsEmptySlice(t *testing.T) {
	got := jsonRawOrEmpty(nil)
	if got == nil {
		t.Fatal("jsonRawOrEmpty(nil): should return empty slice, not nil")
	}
	// Should be []interface{}{}
	if arr, ok := got.([]interface{}); !ok || len(arr) != 0 {
		t.Errorf("jsonRawOrEmpty(nil) = %v, want empty []interface{}", got)
	}
}

func TestJsonRawOrEmpty_ValidJSON_ReturnsNonNil(t *testing.T) {
	data := []byte(`[1,2,3]`)
	got := jsonRawOrEmpty(data)
	if got == nil {
		t.Fatal("jsonRawOrEmpty(valid): should return non-nil")
	}
	// The function returns the raw bytes directly (not an empty slice)
	if _, isSlice := got.([]interface{}); isSlice {
		t.Error("jsonRawOrEmpty(valid): should not return empty []interface{} for non-nil input")
	}
}
