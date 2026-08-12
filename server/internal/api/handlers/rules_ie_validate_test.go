package handlers

import (
	"encoding/json"
	"testing"
)

// ─── decodeRulePayload ────────────────────────────────────────────────────────

func TestDecodeRulePayload_BareArray(t *testing.T) {
	data := []byte(`[{"name":"rule1","content":"content1","type":"sigma"}]`)
	rules, err := decodeRulePayload(data)
	if err != nil {
		t.Fatalf("decodeRulePayload(array): err = %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("decodeRulePayload(array): len = %d, want 1", len(rules))
	}
}

func TestDecodeRulePayload_EnvelopeRules(t *testing.T) {
	data := []byte(`{"rules":[{"name":"r1"},{"name":"r2"}]}`)
	rules, err := decodeRulePayload(data)
	if err != nil {
		t.Fatalf("decodeRulePayload(envelope): err = %v", err)
	}
	if len(rules) != 2 {
		t.Errorf("decodeRulePayload(envelope): len = %d, want 2", len(rules))
	}
}

func TestDecodeRulePayload_EnvelopeDetectionRules(t *testing.T) {
	data := []byte(`{"detection_rules":[{"name":"r1"}]}`)
	rules, err := decodeRulePayload(data)
	if err != nil {
		t.Fatalf("decodeRulePayload(detection_rules): err = %v", err)
	}
	if len(rules) != 1 {
		t.Errorf("decodeRulePayload(detection_rules): len = %d, want 1", len(rules))
	}
}

func TestDecodeRulePayload_InvalidJSON_ReturnsError(t *testing.T) {
	_, err := decodeRulePayload([]byte("not json"))
	if err == nil {
		t.Error("decodeRulePayload(invalid): expected error")
	}
}

// ─── validateImportRule ───────────────────────────────────────────────────────

func TestValidateImportRule_Valid(t *testing.T) {
	raw := map[string]interface{}{
		"name":    "test-rule",
		"content": "title: Test\ndetection: {}",
		"type":    "sigma",
	}
	row, errMsg := validateImportRule(raw)
	if errMsg != "" {
		t.Errorf("validateImportRule(valid): errMsg = %q", errMsg)
	}
	if row == nil {
		t.Fatal("validateImportRule(valid): row is nil")
	}
}

func TestValidateImportRule_MissingName_ReturnsError(t *testing.T) {
	raw := map[string]interface{}{
		"content": "content here",
		"type":    "sigma",
	}
	_, errMsg := validateImportRule(raw)
	if errMsg == "" {
		t.Error("validateImportRule(no name): expected error")
	}
}

func TestValidateImportRule_MissingContent_ReturnsError(t *testing.T) {
	raw := map[string]interface{}{
		"name": "test-rule",
		"type": "sigma",
	}
	_, errMsg := validateImportRule(raw)
	if errMsg == "" {
		t.Error("validateImportRule(no content): expected error")
	}
}

func TestValidateImportRule_InvalidType_ReturnsError(t *testing.T) {
	raw := map[string]interface{}{
		"name":    "test-rule",
		"content": "content",
		"type":    "invalid",
	}
	_, errMsg := validateImportRule(raw)
	if errMsg == "" {
		t.Error("validateImportRule(invalid type): expected error")
	}
}

func TestValidateImportRule_DefaultTypeIsSigma(t *testing.T) {
	raw := map[string]interface{}{
		"name":    "test-rule",
		"content": "content",
	}
	row, errMsg := validateImportRule(raw)
	if errMsg != "" {
		t.Errorf("validateImportRule(no type): err = %q", errMsg)
	}
	if row.Type != "sigma" {
		t.Errorf("validateImportRule: default type = %q, want 'sigma'", row.Type)
	}
}

func TestValidateImportRule_ValidJSON_CanRoundTrip(t *testing.T) {
	raw := map[string]interface{}{
		"name":    "sigma-rule",
		"content": "title: SigmaRule\ndetection: {}",
		"type":    "sigma",
	}
	data, _ := json.Marshal(raw)
	var decoded map[string]interface{}
	json.Unmarshal(data, &decoded)
	row, errMsg := validateImportRule(decoded)
	if errMsg != "" || row == nil {
		t.Errorf("validateImportRule(roundtrip): err = %q, row = %v", errMsg, row)
	}
}
