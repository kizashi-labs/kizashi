package detection

import "testing"

// The resolver records pid→name and injects the parent name from ppid.
func TestParentResolver_ResolvesParent(t *testing.T) {
	r := newParentResolver()

	// Parent process seen first.
	r.enrich(map[string]any{"type": "process", "agent_id": "a1", "pid": 10.0, "processName": "wmiprvse.exe"})

	// Child process references the parent via ppid.
	child := map[string]any{"type": "process", "agent_id": "a1", "pid": 20.0, "ppid": 10.0, "processName": "cmd.exe"}
	r.enrich(child)

	if child["parent_process"] != "wmiprvse.exe" {
		t.Fatalf("expected parent_process=wmiprvse.exe, got %v", child["parent_process"])
	}
}

// An already-present parent field must not be overwritten, and unknown ppids
// leave the event unchanged. Resolution is scoped per agent.
func TestParentResolver_EdgeCases(t *testing.T) {
	r := newParentResolver()

	// Unknown ppid → no injection.
	e1 := map[string]any{"type": "process", "agent_id": "a1", "pid": 5.0, "ppid": 999.0, "processName": "x.exe"}
	r.enrich(e1)
	if _, ok := e1["parent_process"]; ok {
		t.Errorf("unknown ppid should not inject a parent")
	}

	// Cross-agent isolation: a2 must not see a1's pids.
	r.enrich(map[string]any{"type": "process", "agent_id": "a1", "pid": 10.0, "processName": "explorer.exe"})
	e2 := map[string]any{"type": "process", "agent_id": "a2", "pid": 20.0, "ppid": 10.0, "processName": "cmd.exe"}
	r.enrich(e2)
	if _, ok := e2["parent_process"]; ok {
		t.Errorf("parent resolution must not cross agent boundaries")
	}

	// Existing parent field preserved.
	e3 := map[string]any{"type": "process", "agent_id": "a1", "pid": 30.0, "ppid": 10.0, "processName": "cmd.exe", "parent_process": "already.exe"}
	r.enrich(e3)
	if e3["parent_process"] != "already.exe" {
		t.Errorf("existing parent_process must be preserved, got %v", e3["parent_process"])
	}
}

// After the full-path fix (2026-07-02), the resolver caches and injects the
// parent's FULL image path, not just its basename. SigmaHQ Linux ParentImage
// rules match path patterns (ParentImage|endswith '/nginx', |startswith '/tmp/')
// which a bare basename cannot satisfy — so basename injection left them inert.
func TestParentResolver_ResolvesFullImagePath(t *testing.T) {
	r := newParentResolver()

	// Parent seen with a full image path; child references it via ppid.
	r.enrich(map[string]any{"type": "process", "agent_id": "h", "pid": 100.0, "Image": "/usr/sbin/nginx"})
	child := map[string]any{"type": "process", "agent_id": "h", "pid": 200.0, "ppid": 100.0, "processName": "sh", "Image": "/bin/sh"}
	r.enrich(child)
	if child["parent_process"] != "/usr/sbin/nginx" {
		t.Fatalf("expected full parent path /usr/sbin/nginx, got %v", child["parent_process"])
	}

	// record/lookup is the direct API the detection engine uses.
	r.record("h", 300, "/tmp/dropper.sh")
	if got := r.lookup("h", 300); got != "/tmp/dropper.sh" {
		t.Fatalf("lookup: expected /tmp/dropper.sh, got %q", got)
	}
	if got := r.lookup("h", 999); got != "" {
		t.Fatalf("lookup of unknown pid should be empty, got %q", got)
	}
}

// End-to-end: a Linux ParentImage path-pattern rule fires only because the parent
// is now resolved to its full path (/tmp/…), not a basename. Regression guard for
// the parent-context inert bug.
func TestParentResolver_EnablesLinuxParentImagePathRule(t *testing.T) {
	// Mirrors SigmaHQ "Shell Execution Of Process Located In Tmp Directory".
	rule := `
title: Shell Spawned by Process in Tmp (Linux)
logsource:
  category: process_creation
  product: linux
detection:
  selection:
    ParentImage|startswith: '/tmp/'
    Image|endswith:
      - '/bash'
      - '/sh'
  condition: selection
`
	ev := loadOne(t, rule)
	r := newParentResolver()

	// Parent is a script located in /tmp (full path); child is a shell.
	r.enrich(map[string]any{"type": "process", "agent_id": "h", "pid": 100.0, "Image": "/tmp/dropper.sh"})
	child := map[string]any{"type": "process", "agent_id": "h", "pid": 200.0, "ppid": 100.0, "processName": "bash", "Image": "/usr/bin/bash"}
	r.enrich(child)
	addPipelineSigmaAliases(child)
	if len(ev.EvaluateEvent(child)) == 0 {
		t.Error("Linux ParentImage path rule (startswith /tmp/) should fire after full-path parent resolution")
	}
}

// End-to-end: once the resolver injects ParentImage (via the alias layer), the
// built-in WMI-spawn and Office-spawn ParentImage rules fire — confirming the
// field-mapping-audit gap (parent telemetry never reaching Sigma) is closed.
func TestParentResolver_EnablesParentImageRules(t *testing.T) {
	e := NewSigmaEvaluator()
	LoadBuiltinRules(e)
	r := newParentResolver()

	fire := func(parentName, parentPID string, child map[string]any) []SigmaMatch {
		r.enrich(map[string]any{"type": "process", "agent_id": "h", "pid": parentPID, "processName": parentName})
		r.enrich(child)
		addPipelineSigmaAliases(child)
		return e.EvaluateEvent(child)
	}

	// WmiPrvSE → cmd.exe should trigger the WMI-spawn rule.
	wmiChild := map[string]any{"type": "process", "agent_id": "h", "pid": "201", "ppid": "101", "processName": "cmd.exe", "Image": "cmd.exe"}
	if m := fire("wmiprvse.exe", "101", wmiChild); len(m) == 0 {
		t.Errorf("WMI-spawn ParentImage rule should fire for wmiprvse→cmd after parent resolution")
	}

	// winword.exe → powershell should trigger the Office-spawn rule.
	officeChild := map[string]any{"type": "process", "agent_id": "h", "pid": "202", "ppid": "102", "processName": "powershell.exe", "Image": "powershell.exe"}
	if m := fire("winword.exe", "102", officeChild); len(m) == 0 {
		t.Errorf("Office-spawn ParentImage rule should fire for winword→powershell after parent resolution")
	}
}
