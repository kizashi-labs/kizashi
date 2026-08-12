package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ─── findRulesDir ──────────────────────────────────────────────────

func TestFindRulesDir_FindsRulesFromNestedStart(t *testing.T) {
	root := t.TempDir()
	sigma := filepath.Join(root, "rules", "sigma")
	if err := os.MkdirAll(sigma, 0o755); err != nil {
		t.Fatal(err)
	}
	// Start several levels below the repo root, like running from server/cmd/x.
	nested := filepath.Join(root, "server", "cmd", "validate-rules")
	if err := os.MkdirAll(nested, 0o755); err != nil {
		t.Fatal(err)
	}

	got, err := findRulesDir(nested)
	if err != nil {
		t.Fatalf("findRulesDir: %v", err)
	}
	want := filepath.Join(root, "rules")
	// t.TempDir may hand back a symlinked path (/var vs /private/var on macOS);
	// compare the resolved forms so this isn't platform-dependent.
	gotResolved, _ := filepath.EvalSymlinks(got)
	wantResolved, _ := filepath.EvalSymlinks(want)
	if gotResolved != wantResolved {
		t.Errorf("findRulesDir = %q, want %q", got, want)
	}
}

func TestFindRulesDir_ErrorsWhenNoRulesDirAnywhere(t *testing.T) {
	// A bare temp dir has no rules/sigma above it (short of the filesystem
	// root, which the 8-level walk limit stops well before).
	deep := filepath.Join(t.TempDir(), "a", "b", "c")
	if err := os.MkdirAll(deep, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := findRulesDir(deep); err == nil {
		t.Fatal("expected an error when no rules/sigma directory exists, got nil")
	}
}

func TestFindRulesDir_IgnoresRulesDirWithoutSigmaSubdir(t *testing.T) {
	// A directory literally named "rules" is not enough — the tool keys on
	// rules/sigma so it can't latch onto an unrelated folder.
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "rules", "unrelated"), 0o755); err != nil {
		t.Fatal(err)
	}
	start := filepath.Join(root, "sub")
	if err := os.MkdirAll(start, 0o755); err != nil {
		t.Fatal(err)
	}
	if _, err := findRulesDir(start); err == nil {
		t.Fatal("expected an error when rules/ has no sigma subdirectory, got nil")
	}
}

// ─── globRecursive ─────────────────────────────────────────────────

func TestGlobRecursive_MatchesNestedFilesByExtension(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.yml"), "")
	mustWrite(t, filepath.Join(root, "nested", "deep", "b.yml"), "")
	mustWrite(t, filepath.Join(root, "ignored.txt"), "")

	got, err := globRecursive(root, ".yml")
	if err != nil {
		t.Fatalf("globRecursive: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 .yml files, got %d: %v", len(got), got)
	}
	for _, p := range got {
		if strings.HasSuffix(p, ".txt") {
			t.Errorf("non-matching extension returned: %s", p)
		}
	}
}

func TestGlobRecursive_ExtensionMatchIsCaseInsensitive(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "upper.YML"), "")

	got, err := globRecursive(root, ".yml")
	if err != nil {
		t.Fatalf("globRecursive: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("expected .YML to match .yml, got %d files: %v", len(got), got)
	}
}

func TestGlobRecursive_MissingRootIsNotAnError(t *testing.T) {
	// rules/yara may legitimately not exist yet; that must not fail the run.
	got, err := globRecursive(filepath.Join(t.TempDir(), "does-not-exist"), ".yar")
	if err != nil {
		t.Fatalf("missing root should not error, got: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("expected no files, got %v", got)
	}
}

func TestGlobRecursive_AcceptsMultipleExtensions(t *testing.T) {
	root := t.TempDir()
	mustWrite(t, filepath.Join(root, "a.yar"), "")
	mustWrite(t, filepath.Join(root, "b.yara"), "")
	mustWrite(t, filepath.Join(root, "c.yml"), "")

	got, err := globRecursive(root, ".yar", ".yara")
	if err != nil {
		t.Fatalf("globRecursive: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("expected 2 files across both extensions, got %d: %v", len(got), got)
	}
}

// ─── validateSigmaFile ─────────────────────────────────────────────

const validSigma = `title: Test Rule
id: 11111111-1111-1111-1111-111111111111
status: test
logsource:
  product: linux
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'whoami'
  condition: selection
level: low
`

func TestValidateSigmaFile_AcceptsValidRule(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ok.yml")
	mustWrite(t, p, validSigma)
	if err := validateSigmaFile(p); err != nil {
		t.Fatalf("valid Sigma rule rejected: %v", err)
	}
}

func TestValidateSigmaFile_RejectsMalformedYAML(t *testing.T) {
	p := filepath.Join(t.TempDir(), "bad.yml")
	// Broken indentation under detection:.
	mustWrite(t, p, "title: X\ndetection:\n  selection:\n   a: 1\n     b: 2\n")
	if err := validateSigmaFile(p); err == nil {
		t.Fatal("expected malformed YAML to be rejected, got nil")
	}
}

func TestValidateSigmaFile_RejectsRuleMissingCondition(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nocond.yml")
	mustWrite(t, p, `title: No Condition
logsource:
  product: linux
detection:
  selection:
    CommandLine|contains: 'whoami'
`)
	if err := validateSigmaFile(p); err == nil {
		t.Fatal("expected a rule without condition: to be rejected, got nil")
	}
}

func TestValidateSigmaFile_ReportsReadErrorForMissingFile(t *testing.T) {
	err := validateSigmaFile(filepath.Join(t.TempDir(), "absent.yml"))
	if err == nil {
		t.Fatal("expected an error for a missing file, got nil")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("expected a read error, got: %v", err)
	}
}

// ─── validateYaraFileStructural (the no-`yara`-CLI fallback) ───────

const validYara = `rule Demo
{
    strings:
        $a = "malicious"
    condition:
        $a
}
`

func TestValidateYaraFileStructural_AcceptsValidRule(t *testing.T) {
	p := filepath.Join(t.TempDir(), "ok.yar")
	mustWrite(t, p, validYara)
	if err := validateYaraFileStructural(p); err != nil {
		t.Fatalf("valid YARA rule rejected: %v", err)
	}
}

func TestValidateYaraFileStructural_RejectsUnbalancedBraces(t *testing.T) {
	p := filepath.Join(t.TempDir(), "unbalanced.yar")
	mustWrite(t, p, "rule Demo\n{\n    condition:\n        true\n")
	err := validateYaraFileStructural(p)
	if err == nil {
		t.Fatal("expected unbalanced braces to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "brace") {
		t.Errorf("expected a brace-balance error, got: %v", err)
	}
}

func TestValidateYaraFileStructural_RejectsRuleMissingCondition(t *testing.T) {
	p := filepath.Join(t.TempDir(), "nocond.yar")
	mustWrite(t, p, "rule Demo\n{\n    strings:\n        $a = \"x\"\n}\n")
	err := validateYaraFileStructural(p)
	if err == nil {
		t.Fatal("expected a rule without condition: to be rejected, got nil")
	}
	if !strings.Contains(err.Error(), "condition") {
		t.Errorf("expected a missing-condition error, got: %v", err)
	}
}

func TestValidateYaraFileStructural_RejectsFileWithNoRules(t *testing.T) {
	p := filepath.Join(t.TempDir(), "empty.yar")
	mustWrite(t, p, "// only a comment\n")
	if err := validateYaraFileStructural(p); err == nil {
		t.Fatal("expected a file with no rule blocks to be rejected, got nil")
	}
}

func TestValidateYaraFileStructural_AcceptsMultipleRulesIncludingModifiers(t *testing.T) {
	p := filepath.Join(t.TempDir(), "multi.yar")
	mustWrite(t, p, `private rule First
{
    condition:
        true
}

global rule Second
{
    strings:
        $a = "x" nocase
    condition:
        $a
}
`)
	if err := validateYaraFileStructural(p); err != nil {
		t.Fatalf("multi-rule file with private/global modifiers rejected: %v", err)
	}
}

func TestValidateYaraFileStructural_ReportsReadErrorForMissingFile(t *testing.T) {
	err := validateYaraFileStructural(filepath.Join(t.TempDir(), "absent.yar"))
	if err == nil {
		t.Fatal("expected an error for a missing file, got nil")
	}
	if !strings.Contains(err.Error(), "read") {
		t.Errorf("expected a read error, got: %v", err)
	}
}

// ─── helpers ───────────────────────────────────────────────────────

func mustWrite(t *testing.T, path, content string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}
