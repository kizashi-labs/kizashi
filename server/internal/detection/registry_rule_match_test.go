package detection

import (
	"encoding/json"
	"testing"
)

// TestRegistryRuleViaFlattenNormalizedEvent runs the EXACT injected NATS payload
// through the real pipeline path (flattenNormalizedEvent → EvaluateEvent).
func TestRegistryRuleViaFlattenNormalizedEvent(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)
	const title = "Registry Run Key Persistence to Suspicious Location"

	// Nested form (injection #1) and flat form (injection #2).
	payloads := []string{
		`{"agent_id":"p","type":"registry","data":{"registry":{"key_path":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","value_name":"Updater","value_data":"C:\\Users\\victim\\AppData\\Local\\Temp\\evil.exe","operation":"modify"}}}`,
		`{"agent_id":"p","type":"registry","data":{"key_path":"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run","value_name":"Updater","value_data":"C:\\Users\\victim\\AppData\\Local\\Temp\\evil.exe","operation":"modify"}}`,
	}
	for i, p := range payloads {
		var envelope map[string]interface{}
		if err := json.Unmarshal([]byte(p), &envelope); err != nil {
			t.Fatalf("payload %d unmarshal: %v", i, err)
		}
		flat := flattenNormalizedEvent(envelope)
		matched := false
		for _, m := range ev.EvaluateEvent(flat) {
			if m.RuleTitle == title {
				matched = true
			}
		}
		if !matched {
			t.Errorf("payload %d did not match via flattenNormalizedEvent; flat=%+v", i, flat)
		}
	}
}

// TestRegistryRunKeyPersistenceRule verifies the T1547.001 Run-key value-data
// rule fires on a registry event with a suspicious value_data, and does not fire
// when the data is benign.
func TestRegistryRunKeyPersistenceRule(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	const title = "Registry Run Key Persistence to Suspicious Location"

	fired := func(event map[string]interface{}) bool {
		for _, m := range ev.EvaluateEvent(event) {
			if m.RuleTitle == title {
				return true
			}
		}
		return false
	}

	// Malicious: Run key + AppData/Temp data.
	mal := map[string]interface{}{
		"type":         "registry",
		"TargetObject": `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"Details":      `C:\Users\victim\AppData\Local\Temp\evil.exe`,
	}
	if !fired(mal) {
		t.Errorf("rule did not fire on malicious Run-key write: %+v", mal)
	}

	// Benign: Run key but a normal Program Files path.
	benign := map[string]interface{}{
		"type":         "registry",
		"TargetObject": `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"Details":      `C:\Program Files\Vendor\app.exe`,
	}
	if fired(benign) {
		t.Errorf("rule should not fire on benign Run-key write: %+v", benign)
	}

	// Realistic path: raw flat fields (as ingestion publishes) + the alias layer.
	raw := map[string]interface{}{
		"type":       "registry",
		"key_path":   `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run`,
		"value_name": "Updater",
		"value_data": `C:\Users\victim\AppData\Local\Temp\evil.exe`,
		"operation":  "modify",
	}
	addPipelineSigmaAliases(raw)
	if raw["Details"] != `C:\Users\victim\AppData\Local\Temp\evil.exe` {
		t.Errorf("alias did not map value_data->Details: Details=%v", raw["Details"])
	}
	if !fired(raw) {
		t.Errorf("rule did not fire via alias path: %+v", raw)
	}
}
