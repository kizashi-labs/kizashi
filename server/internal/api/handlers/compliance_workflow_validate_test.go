package handlers

import (
	"encoding/json"
	"testing"
)

func TestCwfNullableJSON_Nil_ReturnsNil(t *testing.T) {
	if got := cwfNullableJSON(nil); got != nil {
		t.Errorf("cwfNullableJSON(nil) = %v, want nil", got)
	}
}

func TestCwfNullableJSON_JSONNull_ReturnsNil(t *testing.T) {
	if got := cwfNullableJSON(json.RawMessage(`null`)); got != nil {
		t.Errorf("cwfNullableJSON(`null`) = %v, want nil", got)
	}
}

func TestCwfNullableJSON_EmptyBytes_ReturnsNonNil(t *testing.T) {
	// cwfNullableJSON only treats nil and JSON "null" as nil; empty bytes
	// are a non-nil empty RawMessage and are passed through unchanged.
	got := cwfNullableJSON(json.RawMessage{})
	if _, ok := got.(json.RawMessage); !ok {
		t.Errorf("cwfNullableJSON({}) should return json.RawMessage, got %T", got)
	}
}

func TestCwfNullableJSON_ValidData_ReturnsNonNil(t *testing.T) {
	raw := json.RawMessage(`{"step":"remediate"}`)
	got := cwfNullableJSON(raw)
	if got == nil {
		t.Fatal("cwfNullableJSON with data should return non-nil")
	}
	if _, ok := got.(json.RawMessage); !ok {
		t.Errorf("expected json.RawMessage, got %T", got)
	}
}

func TestCwfNullableJSON_BooleanTrue_ReturnsNonNil(t *testing.T) {
	raw := json.RawMessage(`true`)
	if got := cwfNullableJSON(raw); got == nil {
		t.Error("cwfNullableJSON(`true`) should return non-nil")
	}
}
