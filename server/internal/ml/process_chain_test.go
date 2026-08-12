package ml

import (
	"testing"
)

func TestProcessChainEngine_BasicMatch(t *testing.T) {
	e := NewProcessChainEngine()

	// Simulate: winword(PID=10) → cmd(PID=20, PPID=10) → powershell(PID=30, PPID=20)
	e.Analyze("agent1", 10, 0, "winword.exe", "")
	e.Analyze("agent1", 20, 10, "cmd.exe", "")
	hits := e.Analyze("agent1", 30, 20, "powershell.exe", "")

	if len(hits) == 0 {
		t.Fatal("expected chain-T1566.001-a to fire, got 0 detections")
	}
	found := false
	for _, h := range hits {
		if h.RuleID == "chain-T1566.001-a" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected chain-T1566.001-a; got %v", hits)
	}
}

func TestProcessChainEngine_NoMatchShortChain(t *testing.T) {
	e := NewProcessChainEngine()

	// Only two processes: winword → powershell (no cmd in between)
	// This should NOT match chain-T1566.001-a (which requires 3 hops)
	e.Analyze("agent2", 10, 0, "winword.exe", "")
	hits := e.Analyze("agent2", 20, 10, "powershell.exe", "")

	for _, h := range hits {
		if h.RuleID == "chain-T1566.001-a" {
			t.Errorf("chain-T1566.001-a should NOT fire for winword→powershell (2 hops), got %+v", h)
		}
	}
}

func TestProcessChainEngine_CmdlineMatch(t *testing.T) {
	e := NewProcessChainEngine()

	// Simulate: powershell(PID=10) → sc.exe(PID=20, PPID=10) with cmdline mentioning WinDefend
	e.Analyze("agent3", 10, 0, "powershell.exe", "")
	hits := e.Analyze("agent3", 20, 10, "sc.exe", "sc.exe stop windefend")

	found := false
	for _, h := range hits {
		if h.RuleID == "chain-T1562.001" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("chain-T1562.001 should fire for powershell→sc stop windefend; got %v", hits)
	}
}

func TestProcessChainEngine_ShadowCopyDeletion(t *testing.T) {
	e := NewProcessChainEngine()

	// cmd(10) → vssadmin(20) with "delete shadows" in cmdline
	e.Analyze("agent4", 10, 0, "cmd.exe", "")
	hits := e.Analyze("agent4", 20, 10, "vssadmin.exe", "vssadmin.exe delete shadows /all /quiet")

	found := false
	for _, h := range hits {
		if h.RuleID == "chain-T1490" {
			found = true
		}
	}
	if !found {
		t.Errorf("chain-T1490 should fire for cmd→vssadmin delete shadows; got %v", hits)
	}
}

func TestProcessChainEngine_LookupName(t *testing.T) {
	e := NewProcessChainEngine()
	e.Analyze("agentX", 100, 0, "explorer.exe", "")

	name := e.LookupName("agentX", 100)
	if name != "explorer.exe" {
		t.Errorf("LookupName: want explorer.exe, got %q", name)
	}
	if got := e.LookupName("agentX", 999); got != "" {
		t.Errorf("LookupName for unknown PID should return \"\", got %q", got)
	}
}

func TestProcessChainEngine_AgentIsolation(t *testing.T) {
	e := NewProcessChainEngine()

	// Add processes for agent1 only
	e.Analyze("agent1", 10, 0, "winword.exe", "")
	e.Analyze("agent1", 20, 10, "cmd.exe", "")

	// agent2 sees only powershell without the ancestor chain — should NOT match
	hits := e.Analyze("agent2", 30, 20, "powershell.exe", "")
	for _, h := range hits {
		if h.RuleID == "chain-T1566.001-a" {
			t.Errorf("chain must not cross agent boundaries: agent2 fired %+v", h)
		}
	}
}

// New chains added in the parent-child correlation expansion: direct macro
// spawns (no cmd hop) and remote-execution / web-shell / SQLi parents.
func TestProcessChainEngine_ExpandedChains(t *testing.T) {
	cases := []struct {
		name     string
		ruleID   string
		parent   string
		child    string
		childCmd string
	}{
		{"Word→PowerShell direct macro", "chain-T1566.001-d", "winword.exe", "powershell.exe", ""},
		{"Excel→PowerShell direct macro", "chain-T1566.001-e", "excel.exe", "powershell.exe", ""},
		{"PowerPoint→PowerShell macro", "chain-T1566.001-f", "powerpnt.exe", "powershell.exe", ""},
		{"Word→WScript macro", "chain-T1566.001-g", "winword.exe", "wscript.exe", ""},
		{"mshta→PowerShell HTA stager", "chain-T1218.005", "mshta.exe", "powershell.exe", ""},
		{"WmiPrvSE→PowerShell remote exec", "chain-T1047-a", "wmiprvse.exe", "powershell.exe", ""},
		{"WinRM→PowerShell remote exec", "chain-T1021.006", "wsmprovhost.exe", "powershell.exe", ""},
		{"IIS w3wp→PowerShell webshell", "chain-T1505.003-b", "w3wp.exe", "powershell.exe", ""},
		{"SQL Server→cmd SQLi RCE", "chain-T1190-sql", "sqlservr.exe", "cmd.exe", ""},
	}
	for i, tc := range cases {
		e := NewProcessChainEngine()
		agent := "agent-exp"
		ppid := uint32(10 + i*10)
		cpid := ppid + 1
		e.Analyze(agent, ppid, 0, tc.parent, "")
		hits := e.Analyze(agent, cpid, ppid, tc.child, tc.childCmd)
		found := false
		for _, h := range hits {
			if h.RuleID == tc.ruleID {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s: expected %s to fire for %s→%s, got %v", tc.name, tc.ruleID, tc.parent, tc.child, hits)
		}
	}
}

func TestProcessChainEngine_BaseProcess(t *testing.T) {
	cases := []struct{ in, want string }{
		{`C:\Windows\System32\cmd.exe`, "cmd.exe"},
		{`/usr/bin/bash`, "bash"},
		{"powershell.exe", "powershell.exe"},
	}
	for _, tc := range cases {
		got := baseProcess(tc.in)
		if got != tc.want {
			t.Errorf("baseProcess(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
