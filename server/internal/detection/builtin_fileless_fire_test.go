package detection

import "testing"

// TestFilelessRulesFire verifies the Linux fileless / anti-forensic execution rules fire
// on representative telemetry (memory-backed path, deleted binary, /proc/self/exe overwrite)
// and stay quiet on benign look-alikes. memfd+execveat fileless exec itself is covered
// separately by the eBPF memory finding; these cover the on-path variants.
func TestFilelessRulesFire(t *testing.T) {
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
	proc := func(image, cmd string) map[string]interface{} {
		return map[string]interface{}{"type": "process", "image_path": image, "command_line": cmd}
	}

	pos := []struct {
		title, image, cmd string
	}{
		{"Execution From Shared-Memory Path (Linux)", "/dev/shm/.x", "/dev/shm/.x"},
		{"Execution From Shared-Memory Path (Linux)", "/run/shm/payload", "/run/shm/payload -c2"},
		{"Execution From Deleted Binary (Linux)", "/tmp/dropper (deleted)", "dropper"},
		{"Container Breakout via /proc/self/exe Overwrite (Linux)", "/bin/sh", "sh -c 'cat /tmp/payload > /proc/self/exe'"},
	}
	for _, tc := range pos {
		if !fires(tc.title, proc(tc.image, tc.cmd)) {
			t.Errorf("rule %q did not fire on image=%q cmd=%q", tc.title, tc.image, tc.cmd)
		}
	}

	neg := []struct {
		title, image, cmd string
	}{
		// A normal binary under /usr, not shared memory.
		{"Execution From Shared-Memory Path (Linux)", "/usr/bin/curl", "curl https://example.com"},
		// A normal on-disk binary (not deleted).
		{"Execution From Deleted Binary (Linux)", "/usr/sbin/nginx", "nginx"},
		// Reading /proc/self/exe without a write verb (benign introspection).
		{"Container Breakout via /proc/self/exe Overwrite (Linux)", "/bin/readlink", "readlink /proc/self/exe"},
	}
	for _, tc := range neg {
		if fires(tc.title, proc(tc.image, tc.cmd)) {
			t.Errorf("rule %q should NOT fire on image=%q cmd=%q", tc.title, tc.image, tc.cmd)
		}
	}
}
