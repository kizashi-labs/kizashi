package rules

import (
	"context"
	"testing"
)

// screenCaptureRuleYAML mirrors the Sigma rule shipped in migration
// 284_screen_capture_stabilization.sql. It stabilizes T1113 detection by matching
// BOTH the process command line and the PS4104 script-block text — the synced
// ps_script-only "Windows Screen Capture with CopyFromScreen" rule missed the
// CommandLine path entirely, which is why Caldera Super Spy scoring saw T1113 as
// "only sometimes Technique-detected / unstable". If you edit the rule in the
// migration, update this copy too.
const screenCaptureRuleYAML = `
title: Screen Capture via Graphics API (CopyFromScreen/BitBlt)
status: stable
level: medium
tags:
  - attack.t1113
  - attack.collection
logsource:
  product: windows
  category: process_creation
detection:
  api_cmd:
    CommandLine|contains:
      - CopyFromScreen
      - BitBlt
  api_script:
    ScriptBlockText|contains:
      - CopyFromScreen
      - BitBlt
  bitmap_cmd:
    CommandLine|contains|all:
      - VirtualScreen
      - Bitmap
  bitmap_script:
    ScriptBlockText|contains|all:
      - VirtualScreen
      - Bitmap
  nircmd:
    Image|endswith: \nircmd.exe
    CommandLine|contains: savescreenshot
  condition: api_cmd or api_script or bitmap_cmd or bitmap_script or nircmd
`

// TestRuleEngine_Sigma_ScreenCaptureStabilized verifies the migration-284 rule fires
// through the real sigma-go engine on every screen-capture path that Caldera/PowerShell
// tradecraft produces, AND stays quiet on a benign powershell command.
//
// The key regression this guards: the CommandLine path. The synced rule only inspects
// ScriptBlockText, so an inline `powershell -c "...CopyFromScreen..."` (which lands on
// the process command line, not necessarily in a PS4104 script block) went undetected.
func TestRuleEngine_Sigma_ScreenCaptureStabilized(t *testing.T) {
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{sigmaRule("screencap", screenCaptureRuleYAML)})

	fires := []struct {
		name  string
		event map[string]interface{}
	}{
		{
			// The gap: screenshot code inline on the command line (no script-block event).
			name: "command-line CopyFromScreen",
			event: map[string]interface{}{
				"type":        "process",
				"agent_id":    "host-1",
				"imagePath":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"commandLine": `powershell -nop -c "$g=[Drawing.Graphics]::FromImage($b);$g.CopyFromScreen(0,0,0,0,$b.Size)"`,
			},
		},
		{
			// VirtualScreen + Bitmap on the command line (full-desktop capture form).
			name: "command-line VirtualScreen+Bitmap",
			event: map[string]interface{}{
				"type":        "process",
				"agent_id":    "host-1",
				"imagePath":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"commandLine": `powershell -c "$s=[Windows.Forms.SystemInformation]::VirtualScreen;$bmp=New-Object Drawing.Bitmap $s.Width,$s.Height"`,
			},
		},
		{
			// The script-block path the synced rule already covered — must still fire here.
			// The live detection flatten exposes script telemetry under the literal
			// ScriptBlockText key (no FieldMapping), which sigma-go resolves directly.
			name: "script-block CopyFromScreen",
			event: map[string]interface{}{
				"type":            "script",
				"agent_id":        "host-1",
				"ScriptBlockText": `$graphic.CopyFromScreen($screen.Location, [Drawing.Point]::Empty, $screen.Size)`,
			},
		},
		{
			name: "nircmd savescreenshot",
			event: map[string]interface{}{
				"type":        "process",
				"agent_id":    "host-1",
				"imagePath":   `C:\Users\Public\nircmd.exe`,
				"commandLine": `nircmd.exe savescreenshot C:\Users\Public\s.png`,
			},
		},
	}
	for _, tc := range fires {
		t.Run(tc.name, func(t *testing.T) {
			matches, err := e.Evaluate(context.Background(), tc.event)
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			if !hasRule(matches, "screencap") {
				t.Fatalf("screen-capture rule should fire on %q, got %d matches", tc.name, len(matches))
			}
		})
	}

	// Benign powershell must not trip the rule.
	benign := map[string]interface{}{
		"type":        "process",
		"agent_id":    "host-1",
		"imagePath":   `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
		"commandLine": `powershell Get-Process | Sort-Object CPU`,
	}
	if m, _ := e.Evaluate(context.Background(), benign); hasRule(m, "screencap") {
		t.Errorf("benign powershell should not match the screen-capture rule")
	}
}
