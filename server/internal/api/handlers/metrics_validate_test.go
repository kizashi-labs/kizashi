package handlers

import (
	"strings"
	"testing"
)

// ─── metricsEncodeDimensions ──────────────────────────────────────────────────

func TestMetricsEncodeDimensions_Nil_ReturnsEmptyObject(t *testing.T) {
	if got := metricsEncodeDimensions(nil); got != "{}" {
		t.Errorf("metricsEncodeDimensions(nil) = %q, want '{}'", got)
	}
}

func TestMetricsEncodeDimensions_EmptyMap_ReturnsEmptyObject(t *testing.T) {
	got := metricsEncodeDimensions(map[string]interface{}{})
	if got != "{}" {
		t.Errorf("metricsEncodeDimensions(empty) = %q, want '{}'", got)
	}
}

func TestMetricsEncodeDimensions_WithData_ReturnsJSON(t *testing.T) {
	dims := map[string]interface{}{"host": "server1", "env": "prod"}
	got := metricsEncodeDimensions(dims)
	if !strings.HasPrefix(got, "{") || !strings.HasSuffix(got, "}") {
		t.Errorf("metricsEncodeDimensions: result %q is not JSON object", got)
	}
	if !strings.Contains(got, "host") || !strings.Contains(got, "server1") {
		t.Errorf("metricsEncodeDimensions: result %q missing expected fields", got)
	}
}

// ─── toJSON ──────────────────────────────────────────────────────────────────

func TestToJSON_Nil_ReturnsFallback(t *testing.T) {
	if got := toJSON(nil, "fallback"); got != "fallback" {
		t.Errorf("toJSON(nil) = %q, want 'fallback'", got)
	}
}

func TestToJSON_Map_ReturnsJSON(t *testing.T) {
	got := toJSON(map[string]int{"a": 1}, "{}")
	if !strings.Contains(got, "a") {
		t.Errorf("toJSON(map) = %q, expected JSON with key 'a'", got)
	}
}

func TestToJSON_String_ReturnsJSONString(t *testing.T) {
	got := toJSON("hello", "")
	if got != `"hello"` {
		t.Errorf("toJSON(string) = %q, want '\"hello\"'", got)
	}
}
