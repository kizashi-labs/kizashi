package ml

import (
	"testing"
)

func TestAddCustomRule(t *testing.T) {
	analyzer := NewProcessLineageAnalyzer()
	analyzer.AddRule("myapp.exe", "cmd.exe", "Custom app spawning cmd", "high")

	result := analyzer.Analyze("myapp.exe", "cmd.exe")
	if !result.IsSuspicious {
		t.Error("custom rule should trigger for myapp.exe -> cmd.exe")
	}
	if result.Severity != "high" {
		t.Errorf("expected severity 'high', got %q", result.Severity)
	}
	if result.Reason == "" {
		t.Error("result should include the custom reason")
	}
}

func TestAddMultipleCustomRules(t *testing.T) {
	analyzer := NewProcessLineageAnalyzer()
	analyzer.AddRule("app1.exe", "wscript.exe", "App1 spawning wscript", "medium")
	analyzer.AddRule("app2.exe", "wscript.exe", "App2 spawning wscript", "high")

	r1 := analyzer.Analyze("app1.exe", "wscript.exe")
	if !r1.IsSuspicious {
		t.Error("rule 1 should trigger")
	}
	if r1.Severity != "medium" {
		t.Errorf("expected medium for rule 1, got %q", r1.Severity)
	}

	r2 := analyzer.Analyze("app2.exe", "wscript.exe")
	if !r2.IsSuspicious {
		t.Error("rule 2 should trigger")
	}
	if r2.Severity != "high" {
		t.Errorf("expected high for rule 2, got %q", r2.Severity)
	}
}

func TestCaseInsensitiveMatching(t *testing.T) {
	analyzer := NewProcessLineageAnalyzer()

	// Built-in rules use lowercase; inputs may be mixed case.
	tests := []struct {
		parent string
		child  string
	}{
		{"WINWORD.EXE", "POWERSHELL.EXE"},
		{"WinWord.exe", "PowerShell.exe"},
		{"winword.exe", "powershell.exe"},
		{"WINWORD", "POWERSHELL"},
	}

	for _, tc := range tests {
		tc := tc
		t.Run(tc.parent+"->"+tc.child, func(t *testing.T) {
			result := analyzer.Analyze(tc.parent, tc.child)
			if !result.IsSuspicious {
				t.Errorf("Analyze(%q, %q) should be suspicious (case-insensitive match)",
					tc.parent, tc.child)
			}
		})
	}
}

func TestBenignPairsNotFlagged(t *testing.T) {
	analyzer := NewProcessLineageAnalyzer()

	benign := []struct{ parent, child string }{
		{"explorer.exe", "notepad.exe"},
		{"explorer.exe", "calc.exe"},
		{"explorer.exe", "chrome.exe"},
		{"bash", "ls"},
		{"bash", "cat"},
		{"python3", "python3"},
	}

	for _, tc := range benign {
		tc := tc
		t.Run(tc.parent+"->"+tc.child, func(t *testing.T) {
			result := analyzer.Analyze(tc.parent, tc.child)
			if result.IsSuspicious {
				t.Errorf("Analyze(%q, %q) should NOT be suspicious, got reason: %q",
					tc.parent, tc.child, result.Reason)
			}
		})
	}
}

func TestAnalysisResultFields(t *testing.T) {
	analyzer := NewProcessLineageAnalyzer()

	// Suspicious pair.
	result := analyzer.Analyze("winword.exe", "cmd.exe")
	if !result.IsSuspicious {
		t.Fatal("expected suspicious result")
	}
	if result.Reason == "" {
		t.Error("Reason should not be empty for suspicious result")
	}
	if result.Severity == "" {
		t.Error("Severity should not be empty for suspicious result")
	}
	if result.Rule == "" {
		t.Error("Rule should not be empty for suspicious result")
	}

	// Benign pair.
	clean := analyzer.Analyze("explorer.exe", "notepad.exe")
	if clean.IsSuspicious {
		t.Error("benign result should not be suspicious")
	}
}

func TestAnalyzeLinuxWebshell(t *testing.T) {
	analyzer := NewProcessLineageAnalyzer()

	webshells := []struct {
		parent string
		child  string
		minSev string
	}{
		{"apache2", "bash", "critical"},
		{"nginx", "bash", "critical"},
		{"httpd", "sh", "critical"},
	}

	for _, tc := range webshells {
		tc := tc
		t.Run(tc.parent+"->"+tc.child, func(t *testing.T) {
			result := analyzer.Analyze(tc.parent, tc.child)
			if !result.IsSuspicious {
				t.Errorf("webshell pair %q->%q should be flagged", tc.parent, tc.child)
			}
			if result.Severity != tc.minSev {
				t.Errorf("expected severity %q, got %q", tc.minSev, result.Severity)
			}
		})
	}
}

// BenchmarkProcessLineageAnalyze measures analysis throughput.
func BenchmarkProcessLineageAnalyze(b *testing.B) {
	analyzer := NewProcessLineageAnalyzer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = analyzer.Analyze("winword.exe", "powershell.exe")
	}
}

// BenchmarkProcessLineageAnalyzeBenign measures benign-case analysis throughput.
func BenchmarkProcessLineageAnalyzeBenign(b *testing.B) {
	analyzer := NewProcessLineageAnalyzer()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_ = analyzer.Analyze("explorer.exe", "notepad.exe")
	}
}
