package rules

import "testing"

// The LSASS-creddump → injection kill chain (migration 365) was held back during
// the PR #542 triage on the belief that its two sensors had not landed. They had
// — the belief was simply stale. Re-enabling it is only safe because its inputs
// were re-verified at every layer that can silently drop an event:
//
//	agent/internal/collector/credential_access.go  emits credential_access + target_image
//	agent/internal/collector/remote_thread.go      emits create_remote_thread + target_image
//	migrations 294 / 314                           allow both in the events CHECK constraint
//	internal/detection/field_support.go            declares target_image supported
//	alert_pipeline.go pipelineSubjects             subscribes to both (P5-10)
//
// A rule whose input never arrives is not a detection, it is a comment that costs
// CPU — the failure mode this session has now hit four separate ways (P5-5, P5-7,
// P5-8, P5-10). This test drives the shipped rule bytes with the exact event
// shape the two collectors produce, so "the sensor landed" stops being a belief.
func TestKillChain_CredDumpToInjection_FiresOnSensorEvents(t *testing.T) {
	se := loadSequenceEngine(t)

	credAccess := seqObs{"credential_access", map[string]interface{}{
		"target_image": `C:\Windows\System32\lsass.exe`,
		"source_image": `C:\Users\v\AppData\Local\Temp\mimikatz.exe`,
		"access_mask":  "0x1410",
	}}
	injection := seqObs{"create_remote_thread", map[string]interface{}{
		"target_image": `C:\Windows\System32\winlogon.exe`,
		"source_image": `C:\Users\v\AppData\Local\Temp\mimikatz.exe`,
	}}

	if !drive(se, "kc-creddump-injection", "T1055.012", []seqObs{credAccess, injection}) {
		t.Fatalf("LSASS creddump → injection kill chain did not fire on its two sensor events")
	}
}

// ordered: true is load-bearing. Injection into a system process followed later
// by an LSASS read is a much weaker signal than the reverse — treating it as the
// same chain would manufacture a severity-9 alert out of two unrelated events.
func TestKillChain_CredDumpToInjection_ReverseOrderDoesNotFire(t *testing.T) {
	se := loadSequenceEngine(t)

	injection := seqObs{"create_remote_thread", map[string]interface{}{
		"target_image": `C:\Windows\System32\winlogon.exe`,
		"source_image": `C:\Users\v\AppData\Local\Temp\tool.exe`,
	}}
	credAccess := seqObs{"credential_access", map[string]interface{}{
		"target_image": `C:\Windows\System32\lsass.exe`,
		"source_image": `C:\Users\v\AppData\Local\Temp\tool.exe`,
	}}

	if drive(se, "kc-creddump-reverse", "T1055.012", []seqObs{injection, credAccess}) {
		t.Errorf("reverse order must not fire the ordered kill chain")
	}
}

// Stage 2 is scoped to critical system processes. Injection into an ordinary
// user application after an LSASS read is not this chain, and widening it would
// make the rule fire on routine software that legitimately creates remote
// threads (installers, debuggers, some AV).
func TestKillChain_CredDumpToInjection_NonSystemTargetDoesNotFire(t *testing.T) {
	se := loadSequenceEngine(t)

	credAccess := seqObs{"credential_access", map[string]interface{}{
		"target_image": `C:\Windows\System32\lsass.exe`,
		"source_image": `C:\Users\v\AppData\Local\Temp\tool.exe`,
	}}
	injection := seqObs{"create_remote_thread", map[string]interface{}{
		"target_image": `C:\Program Files\Acme\acme.exe`,
		"source_image": `C:\Users\v\AppData\Local\Temp\tool.exe`,
	}}

	if drive(se, "kc-creddump-nonsystem", "T1055.012", []seqObs{credAccess, injection}) {
		t.Errorf("injection into a non-system target must not fire the chain")
	}
}
