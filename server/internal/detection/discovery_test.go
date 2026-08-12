package detection

import (
	"testing"
	"time"
)

func TestClassifyDiscoveryCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		want string
	}{
		// System owner/user
		{"whoami", "T1033"},
		{`C:\Windows\System32\whoami.exe /all`, "T1033"},
		{"quser", "T1033"},
		// System info
		{"systeminfo", "T1082"},
		{"uname -a", "T1082"},
		{"cat /etc/os-release", "T1082"},
		{"sw_vers", "T1082"},
		// Process
		{"tasklist /v", "T1057"},
		{"ps -ef", "T1057"},
		{"ps aux | grep ssh", "T1057"},
		// Network config
		{"ipconfig /all", "T1016"},
		{"ifconfig -a", "T1016"},
		{"ip addr show", "T1016"},
		{"arp -a", "T1016"},
		// Network connections
		{"netstat -ano", "T1049"},
		{"ss -tunlp", "T1049"},
		{"lsof -i :443", "T1049"},
		// Software
		{"rpm -qa", "T1518"},
		{"dpkg -l", "T1518"},
		{"wmic product get name", "T1518"},
		// Service
		{"sc query", "T1007"},
		{"net start", "T1007"},
		{"systemctl list-units --type=service", "T1007"},
		// Permission groups (must beat T1087 for the `net` forms)
		{"net localgroup administrators", "T1069"},
		{"net group \"Domain Admins\" /domain", "T1069"},
		{"whoami /groups", "T1069"},
		// Account (bare net user, /etc/passwd)
		{"net user", "T1087"},
		{"cat /etc/passwd", "T1087"},
		{"getent passwd", "T1087"},
		// File/dir (broad forms only)
		{"dir /s c:\\", "T1083"},
		{"find / -name id_rsa", "T1083"},
		// Non-discovery / too-generic must NOT classify
		{"ls -l", ""},
		{"dir", ""},
		{"id", ""},
		{"powershell.exe -enc AAAA", ""},
		{"git status", ""},
		{"", ""},
	}
	for _, c := range cases {
		if got := classifyDiscoveryCommand(c.cmd); got != c.want {
			t.Errorf("classifyDiscoveryCommand(%q) = %q, want %q", c.cmd, got, c.want)
		}
	}
}

func TestDiscoveryScorer_FiresOnBurst(t *testing.T) {
	d := newDiscoveryScorer()
	base := time.Unix(1_700_000_000, 0)
	// Four DISTINCT discovery techniques from one host within the window.
	cmds := []string{"whoami", "systeminfo", "ipconfig /all", "netstat -ano"}
	var fired int
	var lastTech string
	for i, c := range cmds {
		tech, m := d.Observe("agent1", c, base.Add(time.Duration(i)*time.Minute))
		lastTech = tech
		fired += len(m)
		if len(m) > 0 {
			if m[0].RuleType != "correlation" {
				t.Errorf("expected correlation match, got %q", m[0].RuleType)
			}
			if m[0].Severity < 5 {
				t.Errorf("burst severity should be >=5, got %d", m[0].Severity)
			}
			if len(m[0].MITRETags) < discMinTechniques {
				t.Errorf("burst should credit all techniques, got %v", m[0].MITRETags)
			}
		}
	}
	if lastTech != "T1049" {
		t.Errorf("last classified technique: got %q, want T1049", lastTech)
	}
	if fired != 1 {
		t.Fatalf("expected exactly 1 burst alert after 4 distinct techniques, got %d", fired)
	}
}

func TestDiscoveryScorer_SingleCommandNoAlert(t *testing.T) {
	d := newDiscoveryScorer()
	base := time.Unix(1_700_000_000, 0)
	// A lone discovery command must never raise a standalone alert — it only
	// returns its technique tag for the kill-chain feed.
	tech, m := d.Observe("agent1", "whoami /all", base)
	if tech != "T1033" {
		t.Errorf("technique: got %q, want T1033", tech)
	}
	if len(m) != 0 {
		t.Fatalf("single discovery command must not alert, got %d matches", len(m))
	}
}

func TestDiscoveryScorer_RepeatedSameTechniqueNoBurst(t *testing.T) {
	d := newDiscoveryScorer()
	base := time.Unix(1_700_000_000, 0)
	// Running the same technique many times is not a burst — distinct-count stays 1.
	for i := 0; i < 6; i++ {
		if _, m := d.Observe("agent1", "tasklist", base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			t.Fatalf("repeated same technique should not burst (iter %d)", i)
		}
	}
}

func TestDiscoveryScorer_ExpiresOutsideWindow(t *testing.T) {
	d := newDiscoveryScorer()
	base := time.Unix(1_700_000_000, 0)
	// Three techniques, then a long gap, then a fourth — the first three have
	// expired so the window never holds discMinTechniques at once.
	d.Observe("agent1", "whoami", base)
	d.Observe("agent1", "systeminfo", base.Add(1*time.Minute))
	d.Observe("agent1", "ipconfig", base.Add(2*time.Minute))
	_, m := d.Observe("agent1", "netstat", base.Add(30*time.Minute))
	if len(m) > 0 {
		t.Fatalf("techniques outside the %v window must not accumulate into a burst", discWindow)
	}
}

// TestDiscoveryCompletesKillChain proves the core value: a discovery command
// supplies the missing "discovery" tactic that lets an otherwise-stalled
// three-stage chain cross the kill-chain threshold. Without the discovery feed
// the same three non-discovery signals never correlate.
func TestDiscoveryCompletesKillChain(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)

	// Baseline: execution + credential-access + exfiltration = 3 distinct
	// tactics, one short of chainMinTactics(4) — no alert.
	k1 := newKillChainScorer()
	nonDiscovery := [][]string{{"T1059"}, {"T1003"}, {"T1048"}}
	for i, tags := range nonDiscovery {
		if m := k1.Observe("agent1", tags, base.Add(time.Duration(i)*time.Minute)); len(m) > 0 {
			t.Fatalf("baseline should not fire with only 3 tactics (step %d)", i)
		}
	}

	// With discovery: the same three, plus a discovery technique derived from a
	// real command via the classifier → 4 distinct tactics → correlated alert.
	k2 := newKillChainScorer()
	discTech := classifyDiscoveryCommand("ipconfig /all") // T1016 → discovery
	if discTech == "" {
		t.Fatal("expected ipconfig to classify as a discovery technique")
	}
	var fired int
	fired += len(k2.Observe("agent1", []string{discTech}, base))
	for i, tags := range nonDiscovery {
		fired += len(k2.Observe("agent1", tags, base.Add(time.Duration(i+1)*time.Minute)))
	}
	if fired != 1 {
		t.Fatalf("discovery should complete the kill chain (expect 1 alert), got %d", fired)
	}
}
