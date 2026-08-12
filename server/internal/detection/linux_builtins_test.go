package detection

import "testing"

// TestLinuxBuiltins verifies the Linux detection-content additions (④ Linux
// detection thickness) fire on canonical Linux手口 and stay quiet on benign
// look-alikes, through the real EvaluateEnvelope oracle.

func evalLinuxProc(image, cmd string) []EvalFinding {
	if image == "" {
		image = "/bin/sh"
	}
	return EvaluateEnvelope("process", map[string]interface{}{
		"type":         "process",
		"image_path":   image,
		"process_name": image,
		"command_line": cmd,
		"action":       "create",
	})
}

// ── T1548.001: setuid/setgid enumeration ──

func TestLinux_SetuidEnumeration_Fires(t *testing.T) {
	cases := []struct{ image, cmd string }{
		{"/usr/bin/find", "find / -perm -4000 -type f 2>/dev/null"},
		{"/usr/bin/find", "find / -perm -u=s -type f"},
		{"/usr/bin/find", "find / -perm /6000"},
	}
	for _, c := range cases {
		if f := evalLinuxProc(c.image, c.cmd); !firedTitleContains(f, "Setuid/Setgid Binary Enumeration") {
			t.Errorf("setuid列挙が検知されるべき: %q → %v", c.cmd, titles(f))
		}
	}
}

func TestLinux_SetuidEnumeration_QuietOnBenign(t *testing.T) {
	// find without a setuid-perm predicate must not fire.
	if f := evalLinuxProc("/usr/bin/find", "find /var/log -name '*.log' -mtime -1"); firedTitleContains(f, "Setuid/Setgid Binary Enumeration") {
		t.Error("通常の find は誤検知すべきでない")
	}
}

// ── T1046: network service scanning ──

func TestLinux_NetworkScanning_Fires(t *testing.T) {
	cases := []struct{ image, cmd string }{
		{"/usr/bin/nmap", "nmap -sS -p- 10.0.0.0/24"},
		{"/usr/bin/masscan", "masscan 10.0.0.0/8 -p80,443"},
		{"/bin/nc", "nc -zv 10.0.0.5 1-1024"},
	}
	for _, c := range cases {
		if f := evalLinuxProc(c.image, c.cmd); !firedTitleContains(f, "Network Service Scanning") {
			t.Errorf("ネットワークスキャンが検知されるべき: %q → %v", c.cmd, titles(f))
		}
	}
}

func TestLinux_NetworkScanning_QuietOnBenign(t *testing.T) {
	// nc used for a single connection (no -z sweep) must not fire the scan rule.
	if f := evalLinuxProc("/bin/nc", "nc example.com 443"); firedTitleContains(f, "Network Service Scanning") {
		t.Error("スイープでない nc 接続は誤検知すべきでない")
	}
}

// ── T1552.003: credential search in shell history ──

func TestLinux_HistoryCredentialSearch_Fires(t *testing.T) {
	cases := []struct{ image, cmd string }{
		{"/bin/grep", "grep -i password ~/.bash_history"},
		{"/bin/grep", "grep -E 'aws_secret|token' ~/.zsh_history"},
	}
	for _, c := range cases {
		if f := evalLinuxProc(c.image, c.cmd); !firedTitleContains(f, "Credential Search in Shell History") {
			t.Errorf("履歴の認証情報探索が検知されるべき: %q → %v", c.cmd, titles(f))
		}
	}
}

func TestLinux_HistoryCredentialSearch_QuietOnBenign(t *testing.T) {
	// grep over a normal file (not a history file) must not fire.
	if f := evalLinuxProc("/bin/grep", "grep -i error /var/log/syslog"); firedTitleContains(f, "Credential Search in Shell History") {
		t.Error("履歴以外への grep は誤検知すべきでない")
	}
}
