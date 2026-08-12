package detection

import "testing"

// "Security Tooling Registry Tampering" used to match any TargetObject containing
// "\Windows Defender". Defender's own engine (MsMpEng.exe) writes
// HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates\SignatureLastUpdated
// every time it refreshes definitions, so the highest-frequency, most obviously
// benign Defender registry write in existence raised a high-severity
// security-tooling-tampering alert. It was the second-largest false positive in
// the 2026-08-02 FP soak (24 alerts across file-server and office-pc).
//
// The rule's own description already promised the narrower thing ("the Windows
// Defender POLICY keys — DisableAntiSpyware / DisableRealtimeMonitoring"); the
// selection just did not implement it. Same shape as the LOLBin fixes: the
// description names a technique, the selection matches mere presence.
func defenderRegistryFires(t *testing.T, ev *SigmaEvaluator, keyPath, valueName string) bool {
	t.Helper()
	event := map[string]interface{}{
		"type":       "registry",
		"key_path":   keyPath,
		"value_name": valueName,
		"value_data": "1",
		"operation":  "modify",
	}
	addPipelineSigmaAliases(event)
	for _, m := range ev.EvaluateEvent(event) {
		if m.RuleTitle == "Security Tooling Registry Tampering (Direct Write)" {
			return true
		}
	}
	return false
}

func TestDefenderRegistryTampering_BenignDefenderOperationIsSilent(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	benign := []struct{ key, value string }{
		// The measured false positive.
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates`, "SignatureLastUpdated"},
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Signature Updates`, "EngineVersion"},
		// Other routine Defender bookkeeping under the same key.
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Scan`, "LastScanRun"},
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Reporting`, "LastReportTime"},
	}
	for _, b := range benign {
		if defenderRegistryFires(t, ev, b.key, b.value) {
			t.Errorf("FALSE POSITIVE: routine Defender write %s\\%s fired the tampering rule", b.key, b.value)
		}
	}
}

func TestDefenderRegistryTampering_RealTamperingStillFires(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	tampering := []struct{ key, value, why string }{
		{`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender`, "DisableAntiSpyware", "the classic policy kill-switch"},
		{`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, "DisableRealtimeMonitoring", "RTP off via policy"},
		{`HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection`, "DisableBehaviorMonitoring", "behaviour monitoring off"},
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Features`, "TamperProtection", "tamper protection off outside the policy subtree"},
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths`, `C:\Users\Public`, "blinding Defender via an exclusion"},
		{`HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Processes`, "evil.exe", "process exclusion"},
	}
	for _, c := range tampering {
		if !defenderRegistryFires(t, ev, c.key, c.value) {
			t.Errorf("MISSED true positive: %s\\%s (%s) did not fire the tampering rule", c.key, c.value, c.why)
		}
	}
}

// The tamper tokens must not fire on their own — a value called
// DisableRealtimeMonitoring under some unrelated product's key is not this rule's
// finding, and matching it would re-broaden the rule from the other direction.
func TestDefenderRegistryTampering_TamperTokenAloneIsSilent(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	if defenderRegistryFires(t, ev, `HKLM\SOFTWARE\Acme\Agent`, "DisableRealtimeMonitoring") {
		t.Errorf("FALSE POSITIVE: a tamper-looking value under a non-Defender key fired the rule")
	}
}
