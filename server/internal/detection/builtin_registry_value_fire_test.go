package detection

import "testing"

// TestRegistryValueDisableFire verifies the registry-value "security control disabled"
// rules fire on the value DATA — the registry-sensor-depth axis. These rules read Details
// (the DWORD value the agent serialises as a decimal string) and the value-name-appended
// TargetObject (addPipelineSigmaAliases), so a *disable* (EnableLUA=0) is caught while a
// benign *re-enable* (=1) is not. Events use the raw snake_case registry keys exactly as
// ingestion publishes them; addPipelineSigmaAliases performs the TargetObject/Details map.
func TestRegistryValueDisableFire(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	fires := func(title string, event map[string]interface{}) bool {
		addPipelineSigmaAliases(event)
		for _, m := range ev.EvaluateEvent(event) {
			if m.RuleTitle == title {
				return true
			}
		}
		return false
	}

	regEvent := func(keyPath, valueName, valueData string) map[string]interface{} {
		return map[string]interface{}{
			"type":       "registry",
			"key_path":   keyPath,
			"value_name": valueName,
			"value_data": valueData,
			"operation":  "modify",
		}
	}

	// ── Positive cases: the disabling value must fire ─────────────────────
	pos := []struct {
		ruleTitle             string
		keyPath, vName, vData string
	}{
		{
			"UAC Disabled or Weakened via Registry Value",
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA", "0",
		},
		{
			// LocalAccountTokenFilterPolicy=1 enables PtH with local admins.
			"UAC Disabled or Weakened via Registry Value",
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "LocalAccountTokenFilterPolicy", "1",
		},
		{
			"LSA Protection Disabled via Registry Value",
			`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, "RunAsPPL", "0",
		},
		{
			"Windows Firewall Disabled via Registry Value",
			`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`, "EnableFirewall", "0",
		},
	}
	for _, tc := range pos {
		if !fires(tc.ruleTitle, regEvent(tc.keyPath, tc.vName, tc.vData)) {
			t.Errorf("rule %q did not fire on %s\\%s=%s", tc.ruleTitle, tc.keyPath, tc.vName, tc.vData)
		}
	}

	// ── Negative cases: the enable/benign value must NOT fire ─────────────
	neg := []struct {
		ruleTitle             string
		keyPath, vName, vData string
	}{
		{
			// Re-enabling UAC (EnableLUA=1) is benign.
			"UAC Disabled or Weakened via Registry Value",
			`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System`, "EnableLUA", "1",
		},
		{
			// LSA protection turned ON (RunAsPPL=1) is benign.
			"LSA Protection Disabled via Registry Value",
			`HKLM\SYSTEM\CurrentControlSet\Control\Lsa`, "RunAsPPL", "1",
		},
		{
			// Firewall turned ON (EnableFirewall=1) is benign.
			"Windows Firewall Disabled via Registry Value",
			`HKLM\SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy\StandardProfile`, "EnableFirewall", "1",
		},
	}
	for _, tc := range neg {
		if fires(tc.ruleTitle, regEvent(tc.keyPath, tc.vName, tc.vData)) {
			t.Errorf("rule %q should NOT fire on benign %s\\%s=%s", tc.ruleTitle, tc.keyPath, tc.vName, tc.vData)
		}
	}
}
