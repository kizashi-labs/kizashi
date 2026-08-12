package detection

import "testing"

// TestMacOSBuiltins verifies the macOS detection-content additions (⑦) fire on
// canonical macOS手口 and stay quiet on benign look-alikes, via the real
// EvaluateEnvelope oracle. macOS telemetry ships through the agent's ESF
// collectors, so these rules are live (not inert).

func evalMacProc(image, cmd string) []EvalFinding {
	return EvaluateEnvelope("process", map[string]interface{}{
		"type":         "process",
		"image_path":   image,
		"process_name": image,
		"command_line": cmd,
		"action":       "create",
	})
}

// ── T1497: virtualization / sandbox discovery ──

func TestMacOS_VMDiscovery_Fires(t *testing.T) {
	cases := []struct{ image, cmd string }{
		{"/usr/sbin/system_profiler", "system_profiler SPHardwareDataType"},
		{"/usr/sbin/ioreg", "ioreg -rd1 -c IOPlatformExpertDevice"},
	}
	for _, c := range cases {
		if f := evalMacProc(c.image, c.cmd); !firedTitleContains(f, "macOS Virtualization/Sandbox Discovery") {
			t.Errorf("macOS VM判別が検知されるべき: %q → %v", c.cmd, titles(f))
		}
	}
}

func TestMacOS_VMDiscovery_QuietOnBenign(t *testing.T) {
	if f := evalMacProc("/usr/sbin/system_profiler", "system_profiler SPSoftwareDataType"); firedTitleContains(f, "macOS Virtualization/Sandbox Discovery") {
		t.Error("software プロファイル取得は誤検知すべきでない")
	}
}

// ── T1070.002: macOS log clearing ──

func TestMacOS_LogClearing_Fires(t *testing.T) {
	cases := []struct{ image, cmd string }{
		{"/usr/bin/log", "log erase --all"},
		{"/bin/rm", "rm -rf /private/var/log/asl"},
	}
	for _, c := range cases {
		if f := evalMacProc(c.image, c.cmd); !firedTitleContains(f, "macOS Log Clearing") {
			t.Errorf("macOS ログ消去が検知されるべき: %q → %v", c.cmd, titles(f))
		}
	}
}

func TestMacOS_LogClearing_QuietOnBenign(t *testing.T) {
	if f := evalMacProc("/usr/bin/log", "log show --predicate 'process == \"sshd\"'"); firedTitleContains(f, "macOS Log Clearing") {
		t.Error("log show は誤検知すべきでない")
	}
}

// ── T1548.006: TCC privacy tampering ──

func TestMacOS_TCCTampering_Fires(t *testing.T) {
	cases := []struct{ image, cmd string }{
		{"/usr/bin/tccutil", "tccutil reset All"},
		{"/usr/bin/sqlite3", "sqlite3 /Library/Application Support/com.apple.TCC/TCC.db 'select * from access'"},
	}
	for _, c := range cases {
		if f := evalMacProc(c.image, c.cmd); !firedTitleContains(f, "macOS TCC Privacy Protection Tampering") {
			t.Errorf("macOS TCC 改ざんが検知されるべき: %q → %v", c.cmd, titles(f))
		}
	}
}

func TestMacOS_TCCTampering_QuietOnBenign(t *testing.T) {
	if f := evalMacProc("/usr/bin/tccutil", "tccutil"); firedTitleContains(f, "macOS TCC Privacy Protection Tampering") {
		t.Error("引数なし tccutil は誤検知すべきでない")
	}
}
