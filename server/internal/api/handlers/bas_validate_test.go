package handlers

import (
	"encoding/json"
	"testing"
)

func TestBasNullableJSON_EmptyInput_ReturnsNil(t *testing.T) {
	if got := basNullableJSON(json.RawMessage{}); got != nil {
		t.Errorf("basNullableJSON({}) = %v, want nil", got)
	}
	if got := basNullableJSON(nil); got != nil {
		t.Errorf("basNullableJSON(nil) = %v, want nil", got)
	}
}

func TestBasNullableJSON_NonEmpty_ReturnsSameBytes(t *testing.T) {
	raw := json.RawMessage(`{"key":"value"}`)
	got := basNullableJSON(raw)
	if got == nil {
		t.Fatal("basNullableJSON with data should return non-nil")
	}
	gotBytes, ok := got.(json.RawMessage)
	if !ok {
		t.Fatalf("returned value is not json.RawMessage, got %T", got)
	}
	if string(gotBytes) != `{"key":"value"}` {
		t.Errorf("returned bytes changed: %s", string(gotBytes))
	}
}

func TestBasNullableJSON_JSONNull_ReturnsNonNil(t *testing.T) {
	// The literal JSON null token is non-empty bytes — should be returned as-is.
	raw := json.RawMessage(`null`)
	got := basNullableJSON(raw)
	if got == nil {
		t.Error("basNullableJSON(`null`) should return the bytes, not Go nil")
	}
}
