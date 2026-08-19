package detection

import (
	"strings"
	"testing"
	"time"
)

func TestClassifyDiscoveryCommand(t *testing.T) {
	cases := []struct {
		cmd  string
		want string
	}{
		// Security software discovery — must win over the generic process/software
		// patterns, because an attacker grepping the process table for the EDR is
		// looking for the EDR, not listing processes.
		{"ps aux | grep -i falcon-sensor", "T1518.001"},
		{"systemctl status clamav", "T1518.001"},
		{"rpm -qa | grep -i crowdstrike", "T1518.001"},
		{"ls /opt/CrowdStrike", "T1518.001"},
		// …while ordinary process/software listing stays on its own technique.
		{"ps aux", "T1057"},
		{"dpkg -l", "T1518"},
		{"snap list", "T1518"},
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
		// Remote system discovery — enumerating OTHER hosts, distinct from reading
		// this machine's own network configuration above.
		{"cat /etc/hosts", "T1018"},
		{"getent hosts", "T1018"},
		{"net view", "T1018"},
		{"nltest /dclist:corp.local", "T1018"},
		{"cat /home/u/.ssh/known_hosts", "T1018"},
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

// TestDiscoveryScorer_SpacedRecon_CreditsLaterTechniques pins the coverage hole
// found in live measurement: reconnaissance paced so the window only ever holds
// about the threshold's worth of techniques. Each new technique arrives as an
// older one expires, so the DISTINCT COUNT plateaus — under the old
// "re-fire only when the count grows" rule the burst fired once and every
// technique enumerated afterwards was never named in any alert, with the split
// decided purely by timing (T1082 was credited in one live run and missed in the
// next, same build, same pacing). Every technique in a sustained campaign must be
// reported.
func TestDiscoveryScorer_SpacedRecon_CreditsLaterTechniques(t *testing.T) {
	d := newDiscoveryScorer()
	base := time.Unix(1_700_000_000, 0)
	// 90s apart against a 5-minute window: at most ~4 techniques are ever resident,
	// so the count never grows past the threshold.
	cmds := []string{"whoami", "ps aux", "uname -a", "ip addr", "netstat -an", "systemctl list-units", "getent group sudo"}
	reported := map[string]bool{}
	for i, c := range cmds {
		_, ms := d.Observe("agent1", c, base.Add(time.Duration(i)*90*time.Second))
		for _, m := range ms {
			for _, tag := range m.MITRETags {
				reported[tag] = true
			}
		}
	}
	// Every technique the commands represent must appear in some alert.
	for _, c := range cmds {
		tech := classifyDiscoveryCommand(c)
		if tech == "" {
			t.Fatalf("test setup: %q classified as no technique", c)
		}
		if !reported[tech] {
			t.Errorf("technique %s (%q) was enumerated but never named in an alert", tech, c)
		}
	}
}

// TestDiscoveryScorer_NoRealertWithoutNewTechnique keeps the noise floor: once a
// set of techniques has been reported, repeating those same techniques must not
// produce a second alert.
func TestDiscoveryScorer_NoRealertWithoutNewTechnique(t *testing.T) {
	d := newDiscoveryScorer()
	base := time.Unix(1_700_000_000, 0)
	cmds := []string{"whoami", "ps aux", "uname -a", "ip addr"}
	alerts := 0
	for i, c := range cmds {
		_, ms := d.Observe("agent1", c, base.Add(time.Duration(i)*time.Second))
		alerts += len(ms)
	}
	if alerts != 1 {
		t.Fatalf("crossing the threshold should raise exactly one alert, got %d", alerts)
	}
	// Same techniques again, still inside the window: no new information, no alert.
	for i, c := range cmds {
		if _, ms := d.Observe("agent1", c, base.Add(time.Duration(60+i)*time.Second)); len(ms) > 0 {
			t.Errorf("re-running already-reported techniques must not alert (%q)", c)
		}
	}
}

// TestDiscoveryCompletesKillChain proves the core value: a discovery command
// supplies the missing "discovery" tactic that lets an otherwise-stalled
// three-stage chain cross the kill-chain threshold. Without the discovery feed
// the same three non-discovery signals never correlate.
func TestDiscoveryCompletesKillChain(t *testing.T) {
	base := time.Unix(1_700_000_000, 0)

	// Baseline: execution + credential-access + exfiltration = 3 distinct
	// tactics, one short of chainMinTactics(5) — no alert.
	k1 := newKillChainScorer()
	nonDiscovery := [][]string{{"T1059"}, {"T1003"}, {"T1048"}, {"T1021"}}
	for i, tags := range nonDiscovery {
		if m := k1.Observe("agent1", tags, base.Add(time.Duration(i)*time.Minute)); len(m) > 0 {
			t.Fatalf("baseline should not fire with only 4 tactics (step %d)", i)
		}
	}

	// With discovery: the same four, plus a discovery technique derived from a
	// real command via the classifier → 5 distinct tactics → correlated alert.
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

// TestDiscoveryScorer_DedupKeyTracksReportedSet pins the fix for the defect that
// made the credited-set re-fire logic above unobservable in production.
//
// The engine deduplicates alerts on (agent, title) for 5 minutes. The burst alert's
// title carries no observed values (deliberately — it keeps a stable identity), so
// every re-fire collapsed into the first one. Measured live: 11 discovery techniques
// executed over 165 seconds produced ONE alert naming 4 of them, and the remaining 7
// were never surfaced. The detector was doing the right thing and the pipeline threw
// it away.
//
// Each report therefore carries the technique set it names as DedupKey, so a
// broadening campaign is not mistaken for a repeat of itself.
func TestDiscoveryScorer_DedupKeyTracksReportedSet(t *testing.T) {
	d := newDiscoveryScorer()
	base := time.Unix(1_700_000_000, 0)
	// A burst that keeps broadening: four techniques cross the threshold, then three
	// more arrive while the window is still open.
	cmds := []string{"whoami", "ps aux", "uname -a", "ip addr", "netstat -an", "systemctl list-units", "getent group sudo"}

	var keys []string
	for i, c := range cmds {
		_, ms := d.Observe("agent1", c, base.Add(time.Duration(i)*time.Second))
		for _, m := range ms {
			if m.DedupKey == "" {
				t.Fatalf("%q: report carries no DedupKey; the engine would collapse it into the previous alert", c)
			}
			keys = append(keys, m.DedupKey)
		}
	}
	if len(keys) < 2 {
		t.Fatalf("a broadening burst must produce more than one report, got %d", len(keys))
	}
	// Every report names a different set — that is exactly what makes it new
	// information rather than a repeat.
	seen := map[string]bool{}
	for _, k := range keys {
		if seen[k] {
			t.Errorf("two reports share DedupKey %q; the second carries no new technique and must not have fired", k)
		}
		seen[k] = true
	}
	// The last report must name every technique observed, so an analyst reading the
	// most recent alert sees the whole campaign rather than its first four commands.
	last := keys[len(keys)-1]
	for _, c := range cmds {
		tech := classifyDiscoveryCommand(c)
		if tech == "" {
			t.Fatalf("test setup: %q classified as no technique", c)
		}
		if !strings.Contains(last, tech) {
			t.Errorf("final report omits %s (%q); DedupKey=%q", tech, c, last)
		}
	}
}
