package handlers

import (
	"encoding/json"
	"testing"
)

func TestArNullableJSON_Nil_ReturnsNil(t *testing.T) {
	if got := arNullableJSON(nil); got != nil {
		t.Errorf("arNullableJSON(nil) = %v, want nil", got)
	}
}

func TestArNullableJSON_Empty_ReturnsNil(t *testing.T) {
	if got := arNullableJSON(json.RawMessage{}); got != nil {
		t.Errorf("arNullableJSON({}) = %v, want nil", got)
	}
}

func TestArNullableJSON_NonEmpty_ReturnsData(t *testing.T) {
	raw := json.RawMessage(`{"action":"block"}`)
	got := arNullableJSON(raw)
	if got == nil {
		t.Fatal("arNullableJSON with data should return non-nil")
	}
}

func TestIntStr_Conversion(t *testing.T) {
	cases := []struct {
		in   int
		want string
	}{{0, "0"}, {1, "1"}, {42, "42"}, {-5, "-5"}}
	for _, tc := range cases {
		if got := intStr(tc.in); got != tc.want {
			t.Errorf("intStr(%d) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
