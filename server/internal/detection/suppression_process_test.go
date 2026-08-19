package detection

import "testing"

func sctx(cmd, parent string) SuppressionContext {
	return SuppressionContext{CommandLine: cmd, ParentImage: parent}
}

// The case this was built for: Amazon Inspector's SSM-launched PowerShell trips
// "Change PowerShell Policies to an Insecure Level". The rule is right in
// general; it is wrong for this one spawn chain, and neither the rule name nor
// the host distinguishes them.
func TestSuppressByParentProcess(t *testing.T) {
	m := &SuppressionMatcher{rules: []SuppressionRule{{
		ID: "1", Name: "SSM 由来の PowerShell を除外",
		RuleName:      "Change PowerShell Policies",
		ParentProcess: "ssm-document-worker.exe",
	}}}
	alert := &StoredAlert{RuleName: "Change PowerShell Policies to an Insecure Level"}

	sup, _, _ := m.IsSuppressed(alert, sctx("", `C:\Program Files\Amazon\SSM\ssm-document-worker.exe`))
	if !sup {
		t.Error("SSM 由来を抑制していない")
	}

	// The same rule firing under any other parent must still alert — that is the
	// whole point of matching on the chain rather than disabling the rule.
	sup, _, _ = m.IsSuppressed(alert, sctx("", `C:\Users\victim\AppData\Local\Temp\dropper.exe`))
	if sup {
		t.Error("別の親プロセスからの発火まで抑制した")
	}

	// No parent information at all must not match either: an unknown parent is
	// not the allowed parent.
	if sup, _, _ = m.IsSuppressed(alert, SuppressionContext{}); sup {
		t.Error("親不明のアラートを抑制した")
	}
}

func TestSuppressByCommandLine(t *testing.T) {
	m := &SuppressionMatcher{rules: []SuppressionRule{{
		ID: "1", Name: "Inspector の OVAL 取得を除外",
		RuleName:    "PowerShell",
		CommandLine: "inspectorssmplugin.exe",
	}}}
	alert := &StoredAlert{RuleName: "Suspicious PowerShell"}

	if sup, _, _ := m.IsSuppressed(alert, sctx(`"C:\Program Files\Amazon\Inspector\inspectorssmplugin.exe" -server-url-oval-definitions https://...`, "")); !sup {
		t.Error("コマンドライン一致で抑制していない")
	}
	if sup, _, _ := m.IsSuppressed(alert, sctx(`powershell.exe -enc SQBFAFgA`, "")); sup {
		t.Error("無関係なコマンドラインを抑制した")
	}
}

// Conditions are ANDed. A rule naming both must not fire on either alone.
func TestProcessConditionsAreAnded(t *testing.T) {
	m := &SuppressionMatcher{rules: []SuppressionRule{{
		ID: "1", Name: "両方指定",
		RuleName:      "PowerShell",
		CommandLine:   "inspectorssmplugin",
		ParentProcess: "ssm-document-worker.exe",
	}}}
	alert := &StoredAlert{RuleName: "Suspicious PowerShell"}

	if sup, _, _ := m.IsSuppressed(alert, sctx("inspectorssmplugin.exe -x", "")); sup {
		t.Error("親が一致しないのに抑制した")
	}
	if sup, _, _ := m.IsSuppressed(alert, sctx("something-else", `...\ssm-document-worker.exe`)); sup {
		t.Error("コマンドラインが一致しないのに抑制した")
	}
	if sup, _, _ := m.IsSuppressed(alert, sctx("inspectorssmplugin.exe -x", `...\ssm-document-worker.exe`)); !sup {
		t.Error("両方一致しているのに抑制していない")
	}
}

// A short command-line fragment matches nearly every command line, so it is the
// same hazard as a one-character rule_name and must be classified the same way.
func TestShortCommandLineFragmentIsCatchAll(t *testing.T) {
	for _, frag := range []string{"e", "-", ".exe", "powersh"} {
		b, why := ClassifySuppression(SuppressionRule{Name: "x", CommandLine: frag})
		if b != SuppressionCatchAll {
			t.Errorf("command_line_contains=%q が catch-all と判定されていない (%s, %s)", frag, b, why)
		}
	}
	if b, _ := ClassifySuppression(SuppressionRule{Name: "x", CommandLine: "inspectorssmplugin.exe"}); b == SuppressionCatchAll {
		t.Error("十分な長さの断片を catch-all と誤判定した")
	}
}

// An extension-only parent excludes every Windows process.
func TestExtensionOnlyParentIsCatchAll(t *testing.T) {
	for _, p := range []string{".exe", "e"} {
		if b, why := ClassifySuppression(SuppressionRule{Name: "x", ParentProcess: p}); b != SuppressionCatchAll {
			t.Errorf("parent_process=%q が catch-all と判定されていない (%s, %s)", p, b, why)
		}
	}
	if b, _ := ClassifySuppression(SuppressionRule{Name: "x", ParentProcess: "ssm-document-worker.exe"}); b == SuppressionCatchAll {
		t.Error("具体的な親プロセス名を catch-all と誤判定した")
	}
}

// The flatteners disagree on the parent key. Reading one spelling would make the
// condition silently inert on the other paths.
func TestSuppressionContextFromReadsEveryParentSpelling(t *testing.T) {
	for _, key := range []string{"parent_process", "parentProcessName", "parent_image_path", "parentImagePath", "ParentImage"} {
		got := SuppressionContextFrom(map[string]interface{}{key: "svchost.exe"})
		if got.ParentImage != "svchost.exe" {
			t.Errorf("キー %q を読めていない", key)
		}
	}
	if got := SuppressionContextFrom(map[string]interface{}{"command_line": "whoami /all"}); got.CommandLine != "whoami /all" {
		t.Errorf("command_line を読めていない: %+v", got)
	}
	if got := SuppressionContextFrom(map[string]interface{}{}); got.CommandLine != "" || got.ParentImage != "" {
		t.Errorf("空のイベントから値を作った: %+v", got)
	}
}
