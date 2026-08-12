package handlers

import (
	"testing"
)

// ─── intPtr ──────────────────────────────────────────────────────────────────

func TestIntPtr_ReturnsPointerToValue(t *testing.T) {
	p := intPtr(42)
	if p == nil {
		t.Fatal("intPtr(42) returned nil")
	}
	if *p != 42 {
		t.Errorf("*intPtr(42) = %d, want 42", *p)
	}
}

func TestIntPtr_ZeroValue(t *testing.T) {
	p := intPtr(0)
	if p == nil || *p != 0 {
		t.Error("intPtr(0) should return pointer to 0")
	}
}

func TestIntPtr_NegativeValue(t *testing.T) {
	p := intPtr(-1)
	if p == nil || *p != -1 {
		t.Error("intPtr(-1) should return pointer to -1")
	}
}

func TestIntPtr_TwoCallsReturnDifferentPointers(t *testing.T) {
	a := intPtr(5)
	b := intPtr(5)
	if a == b {
		t.Error("intPtr は呼び出しごとに異なるポインタを返すべきです")
	}
}

// ─── hardcodedSchema ─────────────────────────────────────────────────────────

func TestHardcodedSchema_ContainsRequiredKeys(t *testing.T) {
	schema := hardcodedSchema()
	required := []string{
		"collection_interval_seconds",
		"send_interval_seconds",
		"process_monitoring",
		"network_monitoring",
		"file_monitoring",
		"log_level",
	}
	for _, k := range required {
		if _, ok := schema[k]; !ok {
			t.Errorf("schema に %q が含まれていません", k)
		}
	}
}

func TestHardcodedSchema_IntervalHasMinMax(t *testing.T) {
	schema := hardcodedSchema()
	col := schema["collection_interval_seconds"]
	if col.Min == nil || *col.Min != 10 {
		t.Errorf("collection_interval_seconds.Min: want 10, got %v", col.Min)
	}
	if col.Max == nil || *col.Max != 3600 {
		t.Errorf("collection_interval_seconds.Max: want 3600, got %v", col.Max)
	}
}

func TestHardcodedSchema_LogLevelHasEnum(t *testing.T) {
	schema := hardcodedSchema()
	ll := schema["log_level"]
	if ll.Type != "string" {
		t.Errorf("log_level.Type: want string, got %q", ll.Type)
	}
	want := map[string]bool{"debug": true, "info": true, "warn": true, "error": true}
	for _, v := range ll.Enum {
		if !want[v] {
			t.Errorf("log_level.Enum に予期しない値 %q が含まれています", v)
		}
	}
	if len(ll.Enum) != 4 {
		t.Errorf("log_level.Enum は4エントリのはず、got %d", len(ll.Enum))
	}
}

func TestHardcodedSchema_BooleanFieldsHaveCorrectType(t *testing.T) {
	schema := hardcodedSchema()
	for _, k := range []string{"process_monitoring", "network_monitoring", "file_monitoring"} {
		if schema[k].Type != "boolean" {
			t.Errorf("%s.Type: want boolean, got %q", k, schema[k].Type)
		}
	}
}

// ─── defaultConfigValues ─────────────────────────────────────────────────────

func TestDefaultConfigValues_ContainsAllSchemaKeys(t *testing.T) {
	schema := hardcodedSchema()
	defaults := defaultConfigValues()
	for k := range schema {
		if _, ok := defaults[k]; !ok {
			t.Errorf("defaultConfigValues に %q が含まれていません", k)
		}
	}
}

func TestDefaultConfigValues_CollectionIntervalDefault(t *testing.T) {
	defaults := defaultConfigValues()
	v, ok := defaults["collection_interval_seconds"]
	if !ok {
		t.Fatal("collection_interval_seconds がdefaultsにありません")
	}
	if v != 60 {
		t.Errorf("collection_interval_seconds default: want 60, got %v", v)
	}
}

func TestDefaultConfigValues_LogLevelDefault(t *testing.T) {
	defaults := defaultConfigValues()
	if defaults["log_level"] != "info" {
		t.Errorf("log_level default: want info, got %v", defaults["log_level"])
	}
}

func TestDefaultConfigValues_FileMonitoringDefaultFalse(t *testing.T) {
	defaults := defaultConfigValues()
	if defaults["file_monitoring"] != false {
		t.Errorf("file_monitoring default: want false, got %v", defaults["file_monitoring"])
	}
}

func TestDefaultConfigValues_ProcessMonitoringDefaultTrue(t *testing.T) {
	defaults := defaultConfigValues()
	if defaults["process_monitoring"] != true {
		t.Errorf("process_monitoring default: want true, got %v", defaults["process_monitoring"])
	}
}
