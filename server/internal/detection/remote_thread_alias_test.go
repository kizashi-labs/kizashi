package detection

import "testing"

// TestRemoteThreadImageAliases guards the injection field translation: SigmaHQ
// create_remote_thread / process_access rules match SourceImage / TargetImage
// (Sysmon EID8/EID10 names), but the Windows ETW thread sensor and the
// credential-access sensor emit source_image / target_image. Without the alias
// the enabled "Process Hollowing" rule (T1055.012) stays structurally inert.
func TestRemoteThreadImageAliases(t *testing.T) {
	flat := map[string]interface{}{
		"type":         "create_remote_thread",
		"source_image": `C:\Users\v\AppData\Local\Temp\evil.exe`,
		"target_image": `C:\Windows\System32\svchost.exe`,
		"source_pid":   "1234",
		"target_pid":   "5678",
	}
	addPipelineSigmaAliases(flat)

	if got, _ := flat["SourceImage"].(string); got != `C:\Users\v\AppData\Local\Temp\evil.exe` {
		t.Errorf("SourceImage alias missing/wrong: %q", got)
	}
	if got, _ := flat["TargetImage"].(string); got != `C:\Windows\System32\svchost.exe` {
		t.Errorf("TargetImage alias missing/wrong: %q", got)
	}
	if got, _ := flat["SourceProcessId"].(string); got != "1234" {
		t.Errorf("SourceProcessId alias missing/wrong: %q", got)
	}
	if got, _ := flat["TargetProcessId"].(string); got != "5678" {
		t.Errorf("TargetProcessId alias missing/wrong: %q", got)
	}
}

// The alias must also make SourceImage/TargetImage field-supported so the curate
// field-gate stops treating create_remote_thread rules as unsupported.
func TestRemoteThreadFieldsSupported(t *testing.T) {
	sup := SupportedSigmaFields()
	for _, f := range []string{"SourceImage", "TargetImage"} {
		if !sup[f] {
			t.Errorf("%s must be in SupportedSigmaFields (via source/target_image alias)", f)
		}
	}
}
