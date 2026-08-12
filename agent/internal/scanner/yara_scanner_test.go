package scanner

import (
	"testing"
)

// ─── NewYARAScanner ───────────────────────────────────────────

func TestNewYARAScanner_Empty(t *testing.T) {
	s := NewYARAScanner()
	if s == nil {
		t.Fatal("NewYARAScanner returned nil")
	}
	if s.RuleCount() != 0 {
		t.Errorf("RuleCount = %d, want 0", s.RuleCount())
	}
}

// ─── LoadRules / RuleCount ────────────────────────────────────

func TestLoadRules_ValidRule(t *testing.T) {
	tests := []struct {
		name      string
		rules     string
		wantCount int
	}{
		{
			"single rule",
			`rule TestRule {
  strings:
    $a = "hello"
  condition:
    any of them
}`,
			1,
		},
		{
			"two rules",
			`rule RuleOne {
  strings:
    $a = "foo"
  condition:
    any of them
}
rule RuleTwo {
  strings:
    $b = "bar"
  condition:
    any of them
}`,
			2,
		},
		{
			"empty rules text",
			"",
			0,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewYARAScanner()
			err := s.LoadRules(tc.rules)
			if err != nil {
				t.Fatalf("LoadRules error: %v", err)
			}
			if s.RuleCount() != tc.wantCount {
				t.Errorf("RuleCount = %d, want %d", s.RuleCount(), tc.wantCount)
			}
		})
	}
}

func TestLoadRules_AccumulatesRules(t *testing.T) {
	s := NewYARAScanner()

	rule1 := `rule First {
  strings:
    $a = "first"
  condition:
    any of them
}`
	rule2 := `rule Second {
  strings:
    $b = "second"
  condition:
    any of them
}`

	if err := s.LoadRules(rule1); err != nil {
		t.Fatalf("first LoadRules: %v", err)
	}
	if s.RuleCount() != 1 {
		t.Errorf("after first load: RuleCount = %d, want 1", s.RuleCount())
	}

	if err := s.LoadRules(rule2); err != nil {
		t.Fatalf("second LoadRules: %v", err)
	}
	if s.RuleCount() != 2 {
		t.Errorf("after second load: RuleCount = %d, want 2", s.RuleCount())
	}
}

// ─── ReplaceRules ─────────────────────────────────────────────

func TestReplaceRules_ReplacesExisting(t *testing.T) {
	s := NewYARAScanner()

	initial := `rule Initial {
  strings:
    $a = "init"
  condition:
    any of them
}`
	if err := s.LoadRules(initial); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	replacement := `rule Replacement {
  strings:
    $b = "new"
  condition:
    any of them
}
rule AnotherNew {
  strings:
    $c = "extra"
  condition:
    any of them
}`
	if err := s.ReplaceRules(replacement); err != nil {
		t.Fatalf("ReplaceRules: %v", err)
	}

	if s.RuleCount() != 2 {
		t.Errorf("after replace: RuleCount = %d, want 2", s.RuleCount())
	}
}

func TestReplaceRules_EmptyRemovesAll(t *testing.T) {
	s := NewYARAScanner()
	s.LoadRules(`rule Foo { strings: $a = "x" condition: any of them }`)

	if err := s.ReplaceRules(""); err != nil {
		t.Fatalf("ReplaceRules empty: %v", err)
	}
	if s.RuleCount() != 0 {
		t.Errorf("RuleCount after empty replace = %d, want 0", s.RuleCount())
	}
}

// ─── ScanBytes — text matches ─────────────────────────────────

func TestScanBytes_TextMatch(t *testing.T) {
	tests := []struct {
		name      string
		rules     string
		data      []byte
		wantMatch bool
		wantRule  string
	}{
		{
			"simple text match",
			`rule FindHello {
  strings:
    $a = "hello"
  condition:
    any of them
}`,
			[]byte("say hello world"),
			true,
			"FindHello",
		},
		{
			"no match",
			`rule FindHello {
  strings:
    $a = "hello"
  condition:
    any of them
}`,
			[]byte("nothing here"),
			false,
			"",
		},
		{
			"match at start",
			`rule StartMatch {
  strings:
    $a = "BEGIN"
  condition:
    any of them
}`,
			[]byte("BEGIN some data"),
			true,
			"StartMatch",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewYARAScanner()
			if err := s.LoadRules(tc.rules); err != nil {
				t.Fatalf("LoadRules: %v", err)
			}

			matches := s.ScanBytes(tc.data)
			if tc.wantMatch && len(matches) == 0 {
				t.Error("expected a match but got none")
			}
			if !tc.wantMatch && len(matches) > 0 {
				t.Errorf("expected no match but got %d matches", len(matches))
			}
			if tc.wantMatch && len(matches) > 0 && matches[0].RuleName != tc.wantRule {
				t.Errorf("RuleName = %q, want %q", matches[0].RuleName, tc.wantRule)
			}
		})
	}
}

func TestScanBytes_MultipleRulesMultipleMatches(t *testing.T) {
	rules := `rule RuleA {
  strings:
    $a = "malware"
  condition:
    any of them
}
rule RuleB {
  strings:
    $b = "exploit"
  condition:
    any of them
}`
	s := NewYARAScanner()
	if err := s.LoadRules(rules); err != nil {
		t.Fatalf("LoadRules: %v", err)
	}

	data := []byte("this file contains malware and exploit code")
	matches := s.ScanBytes(data)
	if len(matches) != 2 {
		t.Errorf("expected 2 matches, got %d", len(matches))
	}
}

// ─── ScanBytes — conditions ───────────────────────────────────

func TestScanBytes_AllOfThem(t *testing.T) {
	rules := `rule NeedsAll {
  strings:
    $a = "alpha"
    $b = "beta"
  condition:
    all of them
}`
	s := NewYARAScanner()
	s.LoadRules(rules)

	t.Run("both present", func(t *testing.T) {
		matches := s.ScanBytes([]byte("alpha and beta are here"))
		if len(matches) != 1 {
			t.Errorf("expected 1 match, got %d", len(matches))
		}
	})

	t.Run("only one present", func(t *testing.T) {
		matches := s.ScanBytes([]byte("only alpha here"))
		if len(matches) != 0 {
			t.Errorf("expected 0 matches, got %d", len(matches))
		}
	})

	t.Run("neither present", func(t *testing.T) {
		matches := s.ScanBytes([]byte("nothing relevant"))
		if len(matches) != 0 {
			t.Errorf("expected 0 matches, got %d", len(matches))
		}
	})
}

func TestScanBytes_NOfThem(t *testing.T) {
	rules := `rule NeedsTwo {
  strings:
    $a = "one"
    $b = "two"
    $c = "three"
  condition:
    2 of them
}`
	s := NewYARAScanner()
	s.LoadRules(rules)

	t.Run("exactly 2 present", func(t *testing.T) {
		matches := s.ScanBytes([]byte("one and two"))
		if len(matches) != 1 {
			t.Errorf("expected 1 match, got %d", len(matches))
		}
	})

	t.Run("all 3 present satisfies 2-of", func(t *testing.T) {
		matches := s.ScanBytes([]byte("one two three"))
		if len(matches) != 1 {
			t.Errorf("expected 1 match (3 >= 2), got %d", len(matches))
		}
	})

	t.Run("only 1 present", func(t *testing.T) {
		matches := s.ScanBytes([]byte("one here"))
		if len(matches) != 0 {
			t.Errorf("expected 0 matches (1 < 2), got %d", len(matches))
		}
	})
}

// ─── ScanBytes — nocase modifier ─────────────────────────────

func TestScanBytes_NocaseModifier(t *testing.T) {
	rules := `rule CaseInsensitive {
  strings:
    $a = "password" nocase
  condition:
    any of them
}`
	s := NewYARAScanner()
	s.LoadRules(rules)

	tests := []struct {
		name      string
		data      []byte
		wantMatch bool
	}{
		{"lowercase", []byte("the password is here"), true},
		{"uppercase", []byte("the PASSWORD is here"), true},
		{"mixed case", []byte("PaSsWoRd found"), true},
		{"not present", []byte("no match here"), false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := s.ScanBytes(tc.data)
			got := len(matches) > 0
			if got != tc.wantMatch {
				t.Errorf("match = %v, want %v", got, tc.wantMatch)
			}
		})
	}
}

// ─── ScanBytes — hex patterns ─────────────────────────────────

func TestScanBytes_HexPattern(t *testing.T) {
	rules := `rule HexMatch {
  strings:
    $magic = { 4D 5A }
  condition:
    any of them
}`
	s := NewYARAScanner()
	s.LoadRules(rules)

	tests := []struct {
		name      string
		data      []byte
		wantMatch bool
	}{
		{"PE magic bytes present", append([]byte{0x4D, 0x5A}, []byte(" rest of PE")...), true},
		{"not present", []byte{0x00, 0x01, 0x02, 0x03}, false},
		{"empty data", []byte{}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := s.ScanBytes(tc.data)
			got := len(matches) > 0
			if got != tc.wantMatch {
				t.Errorf("match = %v, want %v", got, tc.wantMatch)
			}
		})
	}
}

// ─── ScanBytes — regex patterns ───────────────────────────────

func TestScanBytes_RegexPattern(t *testing.T) {
	rules := `rule RegexRule {
  strings:
    $re = /\d{3}-\d{4}/
  condition:
    any of them
}`
	s := NewYARAScanner()
	s.LoadRules(rules)

	tests := []struct {
		name      string
		data      []byte
		wantMatch bool
	}{
		{"phone number format", []byte("call 555-1234 now"), true},
		{"no match", []byte("call me later"), false},
		{"multiple matches", []byte("123-4567 and 987-6543"), true},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			matches := s.ScanBytes(tc.data)
			got := len(matches) > 0
			if got != tc.wantMatch {
				t.Errorf("match = %v, want %v", got, tc.wantMatch)
			}
		})
	}
}

// ─── ScanBytes — empty scanner ────────────────────────────────

func TestScanBytes_NoRules(t *testing.T) {
	s := NewYARAScanner()
	matches := s.ScanBytes([]byte("any content here"))
	if len(matches) != 0 {
		t.Errorf("expected 0 matches with no rules loaded, got %d", len(matches))
	}
}

// ─── ScanBytes — YARAMatch fields ────────────────────────────

func TestScanBytes_MatchFields(t *testing.T) {
	rules := `rule TaggedRule : malware suspicious {
  meta:
    author = "tester"
    description = "test rule"
  strings:
    $sig = "MALICIOUS"
  condition:
    any of them
}`
	s := NewYARAScanner()
	s.LoadRules(rules)

	matches := s.ScanBytes([]byte("contains MALICIOUS content"))
	if len(matches) != 1 {
		t.Fatalf("expected 1 match, got %d", len(matches))
	}

	m := matches[0]
	if m.RuleName != "TaggedRule" {
		t.Errorf("RuleName = %q, want %q", m.RuleName, "TaggedRule")
	}
	if len(m.Tags) < 2 {
		t.Errorf("Tags len = %d, want >= 2", len(m.Tags))
	}
	if m.Meta["author"] != "tester" {
		t.Errorf("Meta[author] = %q, want %q", m.Meta["author"], "tester")
	}
	if len(m.Strings) == 0 {
		t.Error("expected string match details but got none")
	}
}

// ─── parseCondition ───────────────────────────────────────────

func TestParseCondition(t *testing.T) {
	tests := []struct {
		cond     string
		wantType yaraConditionType
		wantN    int
	}{
		{"any of them", condAnyOf, 0},
		{"all of them", condAllOf, 0},
		{"2 of them", condNOf, 2},
		{"5 of them", condNOf, 5},
		{"$a and $b", condBool, 0},
	}

	for _, tc := range tests {
		t.Run(tc.cond, func(t *testing.T) {
			c := parseCondition(tc.cond)
			if c.condType != tc.wantType {
				t.Errorf("condType = %v, want %v", c.condType, tc.wantType)
			}
			if tc.wantN != 0 && c.n != tc.wantN {
				t.Errorf("n = %d, want %d", c.n, tc.wantN)
			}
		})
	}
}

// ─── evalSimpleBool ───────────────────────────────────────────

func TestEvalSimpleBool(t *testing.T) {
	tests := []struct {
		expr string
		want bool
	}{
		{"true", true},
		{"false", false},
		{"true || false", true},
		{"false || false", false},
		{"true && true", true},
		{"true && false", false},
		{"!true", false},
		{"!false", true},
	}

	for _, tc := range tests {
		t.Run(tc.expr, func(t *testing.T) {
			got := evalSimpleBool(tc.expr)
			if got != tc.want {
				t.Errorf("evalSimpleBool(%q) = %v, want %v", tc.expr, got, tc.want)
			}
		})
	}
}

// ─── toUTF16LE ────────────────────────────────────────────────

func TestToUTF16LE(t *testing.T) {
	tests := []struct {
		name  string
		input []byte
	}{
		{"ascii single char", []byte("A")},
		{"ascii word", []byte("hello")},
		{"empty", []byte{}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			result := toUTF16LE(tc.input)
			// UTF-16LE should produce 2 bytes per ASCII character.
			if len(tc.input) > 0 && len(result) != len(tc.input)*2 {
				t.Errorf("UTF16LE length = %d, want %d", len(result), len(tc.input)*2)
			}
			// For ASCII: each char should be (char, 0x00).
			for i, b := range tc.input {
				if result[i*2] != b {
					t.Errorf("byte[%d] = 0x%02x, want 0x%02x", i*2, result[i*2], b)
				}
				if result[i*2+1] != 0x00 {
					t.Errorf("byte[%d] = 0x%02x, want 0x00 (high byte of ASCII)", i*2+1, result[i*2+1])
				}
			}
		})
	}
}

// ─── findBytesAll ─────────────────────────────────────────────

func TestFindBytesAll(t *testing.T) {
	tests := []struct {
		name        string
		data        []byte
		pattern     []byte
		wantMatches int
	}{
		{"no occurrences", []byte("hello world"), []byte("xyz"), 0},
		{"one occurrence", []byte("hello world"), []byte("world"), 1},
		{"multiple occurrences", []byte("aaaa"), []byte("aa"), 3},
		// Regression: an empty pattern used to make bytes.Index return 0 forever,
		// walking offset one past len(data) and panicking (slice bounds out of
		// range). It must now yield zero matches and never panic.
		{"empty pattern (no panic, no match)", []byte("data"), []byte{}, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := findBytesAll("$test", tc.data, tc.pattern)
			if len(got) != tc.wantMatches {
				t.Errorf("findBytesAll matches = %d, want %d", len(got), tc.wantMatches)
			}
			// Verify identifiers are set.
			for _, m := range got {
				if m.Identifier != "$test" {
					t.Errorf("Identifier = %q, want %q", m.Identifier, "$test")
				}
			}
		})
	}
}

// ─── findStringMatches — panic regression ─────────────────────

// TestFindStringMatches_NoPanic reproduces the live agent crash
// (panic: slice bounds out of range [71:70] at findStringMatches) that took
// telemetry down: an empty text pattern, and a nocase pattern whose
// bytes.ToLower changes the searched-data length relative to the original data.
func TestFindStringMatches_NoPanic(t *testing.T) {
	tests := []struct {
		name string
		ys   *yaraString
		data []byte
		want int
	}{
		{
			"empty text pattern",
			&yaraString{id: "$e", strType: yaraText, text: []byte{}},
			[]byte("some scanned bytes"),
			0,
		},
		{
			"empty text pattern nocase",
			&yaraString{id: "$e", strType: yaraText, text: []byte{}, nocase: true},
			[]byte("MixedCase Data"),
			0,
		},
		{
			// Non-ASCII bytes: bytes.ToLower can change length, so offsets from
			// the lowercased search buffer must not slice the original out of range.
			"nocase over non-ascii data",
			&yaraString{id: "$k", strType: yaraText, text: []byte("key"), nocase: true},
			append([]byte("KEY"), []byte{0xC3, 0x28, 0xFF, 0x80, 0xE2, 0x82}...),
			1,
		},
		{
			"empty hex pattern",
			&yaraString{id: "$h", strType: yaraHex, hexPat: []byte{}},
			[]byte("anything"),
			0,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			// The assertion is primarily "does not panic"; match count is a bonus.
			got := findStringMatches(tc.ys, tc.data)
			if len(got) != tc.want {
				t.Errorf("findStringMatches matches = %d, want %d", len(got), tc.want)
			}
		})
	}
}
