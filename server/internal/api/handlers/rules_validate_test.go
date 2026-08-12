package handlers

import "testing"

// ─── testSigmaKeywords ────────────────────────────────────────────────────────

func TestSigmaKeywords_MatchingKeyword_ReturnsTrue(t *testing.T) {
	content := `title: Test
detection:
  selection:
    CommandLine: mimikatz
  condition: selection
`
	eventStr := `{"commandline":"mimikatz.exe /sekurlsa"}`
	matched, terms, _ := testSigmaKeywords(content, eventStr)
	if !matched {
		t.Errorf("testSigmaKeywords: expected match, terms=%v", terms)
	}
}

func TestSigmaKeywords_NoMatchingKeyword_ReturnsFalse(t *testing.T) {
	content := `title: Test
detection:
  selection:
    CommandLine: mimikatz
  condition: selection
`
	eventStr := `{"commandline":"notepad.exe"}`
	matched, _, _ := testSigmaKeywords(content, eventStr)
	if matched {
		t.Error("testSigmaKeywords: expected no match for different event")
	}
}

func TestSigmaKeywords_NoDetectionSection_ReturnsNoTerms(t *testing.T) {
	content := `title: Test
description: A rule with no detection section
`
	matched, _, msg := testSigmaKeywords(content, `{"event":"something"}`)
	if matched {
		t.Error("testSigmaKeywords: expected false with no detection section")
	}
	if msg == "" {
		t.Error("testSigmaKeywords: expected non-empty message")
	}
}

func TestSigmaKeywords_ListValues_AreExtracted(t *testing.T) {
	content := `title: Test
detection:
  selection:
    - powershell
    - wscript
  condition: selection
`
	eventStr := `{"process":"powershell.exe"}`
	matched, _, _ := testSigmaKeywords(content, eventStr)
	if !matched {
		t.Error("testSigmaKeywords: should match list value 'powershell'")
	}
}

func TestSigmaKeywords_CaseInsensitiveMatch(t *testing.T) {
	content := `title: Test
detection:
  selection:
    Image: NOTEPAD.EXE
  condition: selection
`
	eventStr := `{"image":"notepad.exe"}`
	matched, _, _ := testSigmaKeywords(content, eventStr)
	if !matched {
		t.Error("testSigmaKeywords: should match case-insensitively")
	}
}
