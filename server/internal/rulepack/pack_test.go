package rulepack

import (
	"strings"
	"testing"
)

const minimalPack = `{
  "name": "core",
  "version": "2026.08",
  "rules": [
    {
      "name": "PowerShell EncodedCommand",
      "type": "sigma",
      "platform": ["windows"],
      "severity": 7,
      "content": "title: x\ndetection:\n  sel:\n    Image|endswith: '\\powershell.exe'\n  condition: sel\n"
    }
  ]
}`

func parsePack(t *testing.T, s string) (*Pack, error) {
	t.Helper()
	return Parse(strings.NewReader(s))
}

func TestParse_Minimal(t *testing.T) {
	p, err := parsePack(t, minimalPack)
	if err != nil {
		t.Fatal(err)
	}
	if p.Name != "core" || len(p.Rules) != 1 {
		t.Fatalf("got name=%q rules=%d", p.Name, len(p.Rules))
	}
	if got := p.PackKey(p.Rules[0].Name); got != "core/PowerShell EncodedCommand" {
		t.Errorf("PackKey = %q", got)
	}
}

// A pack that omits `enabled` means "run this rule". Treating the zero value of
// a plain bool as the answer would disable every rule in every pack that did
// not spell it out — which is most of them.
func TestResolvedEnabled_AbsentMeansEnabled(t *testing.T) {
	p, err := parsePack(t, minimalPack)
	if err != nil {
		t.Fatal(err)
	}
	if !p.Rules[0].ResolvedEnabled() {
		t.Error("a rule that omits enabled must load enabled")
	}

	off := false
	r := Rule{Enabled: &off}
	if r.ResolvedEnabled() {
		t.Error("enabled:false must be honoured")
	}
}

func TestResolvedSource_Defaults(t *testing.T) {
	if got := (Rule{}).ResolvedSource(); got != "community" {
		t.Errorf("default source = %q, want community", got)
	}
	if got := (Rule{Source: "sigmahq"}).ResolvedSource(); got != "sigmahq" {
		t.Errorf("explicit source = %q, want sigmahq", got)
	}
}

// A misspelled field is a rule that does not do what its author believes. It
// must not be accepted and ignored.
func TestParse_RejectsUnknownField(t *testing.T) {
	bad := strings.Replace(minimalPack, `"severity": 7`, `"severty": 7`, 1)
	if _, err := parsePack(t, bad); err == nil {
		t.Fatal("an unknown field must be rejected, not ignored")
	}
}

func TestValidate_RejectsBadValues(t *testing.T) {
	cases := map[string]struct{ from, to, want string }{
		"unknown type":     {`"type": "sigma"`, `"type": "snort"`, "not one of sigma/yara/behavioral"},
		"severity zero":    {`"severity": 7`, `"severity": 0`, "outside 1..10"},
		"severity eleven":  {`"severity": 7`, `"severity": 11`, "outside 1..10"},
		"unknown platform": {`"platform": ["windows"]`, `"platform": ["solaris"]`, "not one of windows/linux/darwin"},
		"empty platform":   {`"platform": ["windows"]`, `"platform": []`, "platform is empty"},
		"unknown source":   {`"severity": 7`, `"severity": 7, "source": "made-up"`, "not an accepted value"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			bad := strings.Replace(minimalPack, tc.from, tc.to, 1)
			_, err := parsePack(t, bad)
			if err == nil {
				t.Fatalf("expected rejection for %s", name)
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error should explain the problem (%q), got: %v", tc.want, err)
			}
		})
	}
}

// An empty rule body can never match anything. Loading it produces a rule that
// exists, is enabled, is counted, and detects nothing — the shape of defect
// this whole area keeps producing.
func TestValidate_RejectsEmptyContent(t *testing.T) {
	bad := strings.Replace(minimalPack, `"content": "title: x\ndetection:\n  sel:\n    Image|endswith: '\\powershell.exe'\n  condition: sel\n"`, `"content": ""`, 1)
	_, err := parsePack(t, bad)
	if err == nil {
		t.Fatal("empty content must be rejected")
	}
	if !strings.Contains(err.Error(), "never match") {
		t.Errorf("the error should say why it matters, got: %v", err)
	}
}

// Two rules with one name collapse onto a single pack_key, so the pack would
// load fewer rules than it lists and say nothing about it.
func TestValidate_RejectsDuplicateRuleNames(t *testing.T) {
	dup := `{"name":"core","version":"1","rules":[
	  {"name":"same","type":"sigma","platform":["linux"],"severity":5,"content":"a"},
	  {"name":"same","type":"sigma","platform":["linux"],"severity":5,"content":"b"}]}`
	_, err := parsePack(t, dup)
	if err == nil {
		t.Fatal("duplicate rule names must be rejected")
	}
	if !strings.Contains(err.Error(), "pack_key") {
		t.Errorf("the error should explain the collision, got: %v", err)
	}
}

func TestValidate_RejectsBadPackName(t *testing.T) {
	for _, name := range []string{"", "core/extra"} {
		body := strings.Replace(minimalPack, `"name": "core"`, `"name": "`+name+`"`, 1)
		if _, err := parsePack(t, body); err == nil {
			t.Errorf("pack name %q must be rejected", name)
		}
	}
}

// Every problem at once: fixing a pack one error per reload does not scale to a
// file with thousands of rules.
func TestValidate_ReportsAllProblems(t *testing.T) {
	bad := `{"name":"core","version":"1","rules":[
	  {"name":"a","type":"snort","platform":["solaris"],"severity":99,"content":""}]}`
	_, err := parsePack(t, bad)
	if err == nil {
		t.Fatal("expected rejection")
	}
	for _, want := range []string{"snort", "solaris", "outside 1..10", "never match"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("all problems should be reported; %q missing from: %v", want, err)
		}
	}
}

func TestValidate_RejectsEmptyPack(t *testing.T) {
	if _, err := parsePack(t, `{"name":"core","version":"1","rules":[]}`); err == nil {
		t.Fatal("a pack with no rules must be rejected")
	}
}
