package detection

import "testing"

// TestBasenameOnlyImageFiresEndswithRules guards the 2026-06-25 production break:
// the Windows NT Kernel Logger reports ImageFileName as a bare basename
// ("bitsadmin.exe", no path) for short-lived processes, but most built-in rules
// match `Image|endswith: \proc.exe` (leading backslash). Without the basename
// normalization in addPipelineSigmaAliases, those rules silently never fire on
// real telemetry — exactly the events here, with NO path in image_path.
func TestBasenameOnlyImageFiresEndswithRules(t *testing.T) {
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

	cases := []struct {
		ruleTitle string
		event     map[string]interface{}
	}{
		{
			"BITS Job Abuse for Download or Persistence",
			map[string]interface{}{
				"type": "process", "process_name": "bitsadmin.exe",
				"image_path":   "bitsadmin.exe", // basename only — as the kernel logger emits
				"command_line": `bitsadmin  /transfer edrx /download https://example.com/x.txt C:\Users\Public\x.txt`,
				"action":       "create",
			},
		},
		{
			"Verclsid COM Object Proxy Execution",
			map[string]interface{}{
				"type": "process", "process_name": "verclsid.exe",
				"image_path":   "verclsid.exe",
				"command_line": `verclsid.exe  /S /C {00000000-0000-0000-0000-000000000000}`,
				"action":       "create",
			},
		},
		{
			"Security Software Discovery",
			map[string]interface{}{
				"type": "process", "process_name": "tasklist.exe",
				"image_path":   "tasklist.exe",
				"command_line": `tasklist  /fi "imagename eq msmpeng.exe"`,
				"action":       "create",
			},
		},
		{
			// Parent-based rule must also work when the parent is a basename.
			"Office Application Spawning a Script Interpreter",
			map[string]interface{}{
				"type": "process", "process_name": "powershell.exe",
				"image_path":        "powershell.exe",
				"parent_image_path": "winword.exe", // basename parent
				"command_line":      `powershell -enc ZQB2AA==`,
				"action":            "create",
			},
		},
	}

	for _, c := range cases {
		t.Run(c.ruleTitle, func(t *testing.T) {
			if !fires(c.ruleTitle, c.event) {
				t.Errorf("rule %q did not fire on basename-only telemetry %+v", c.ruleTitle, c.event)
			}
		})
	}

	// FP guard: the basename normalization must NOT make the masquerading rule
	// (Image|endswith system-name AND NOT in a standard path) fire on a legitimate
	// system process reported as a bare basename — we have no path, so we cannot
	// claim it is in a non-standard location. The rule requires a real path.
	const masq = "System Process Name From Non-Standard Path (Masquerading)"
	if fires(masq, map[string]interface{}{
		"type": "process", "process_name": "svchost.exe",
		"image_path": "svchost.exe", "action": "create", // basename only — unknown path
	}) {
		t.Errorf("masquerading FALSE POSITIVE: basename-only svchost.exe must not be flagged (no path known)")
	}
	// Positive: a system-process name from an actual non-standard path IS masquerading.
	if !fires(masq, map[string]interface{}{
		"type": "process", "process_name": "svchost.exe",
		"image_path": `C:\Users\Public\svchost.exe`, "action": "create",
	}) {
		t.Errorf("masquerading rule did not fire on svchost.exe from a non-standard full path")
	}
}
