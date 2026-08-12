package handlers

import (
	"sort"
	"testing"
)

func TestStixTags_LabelsAndRelationships(t *testing.T) {
	obj := stixObject{
		ID:     "indicator--1",
		Labels: []string{"malicious-activity", "tlp:amber"},
	}
	sdoName := map[string]string{
		"malware--x":      "Emotet",
		"threat-actor--y": "APT29",
		"malware--z":      "TrickBot",
	}
	relTargets := map[string][]string{
		"indicator--1": {"malware--x", "threat-actor--y"},
	}
	got := stixTags(obj, sdoName, relTargets)
	sort.Strings(got)
	want := []string{"APT29", "Emotet", "malicious-activity", "tlp:amber"}
	if len(got) != len(want) {
		t.Fatalf("tags = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("tags = %v, want %v", got, want)
			break
		}
	}
}

func TestStixTags_Dedup(t *testing.T) {
	obj := stixObject{ID: "indicator--1", Labels: []string{"c2", "c2", "  c2  "}}
	got := stixTags(obj, nil, nil)
	if len(got) != 1 || got[0] != "c2" {
		t.Errorf("dedup/trim failed: %v", got)
	}
}

func TestStixTags_NoRelationshipsYieldsEmptySlice(t *testing.T) {
	got := stixTags(stixObject{ID: "indicator--1"}, nil, nil)
	if got == nil {
		t.Error("stixTags must return a non-nil empty slice for the text[] param")
	}
	if len(got) != 0 {
		t.Errorf("expected empty, got %v", got)
	}
}

func TestClampInt(t *testing.T) {
	cases := []struct{ v, lo, hi, want int }{
		{-5, 0, 100, 0},
		{150, 0, 100, 100},
		{50, 0, 100, 50},
		{0, 1, 10, 1},
		{7, 1, 10, 7},
	}
	for _, tc := range cases {
		if got := clampInt(tc.v, tc.lo, tc.hi); got != tc.want {
			t.Errorf("clampInt(%d,%d,%d) = %d, want %d", tc.v, tc.lo, tc.hi, got, tc.want)
		}
	}
}

// iocToSTIXPattern must round-trip the canonical "hash" type by digest length,
// which is what Export relies on for feed-sourced hash IOCs.
func TestIocToSTIXPattern_HashByLength(t *testing.T) {
	cases := map[string]string{
		"aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899": "[file:hashes.'SHA-256' = 'aabbccddeeff00112233445566778899aabbccddeeff00112233445566778899']",
		"da39a3ee5e6b4b0d3255bfef95601890afd80709":                         "[file:hashes.'SHA-1' = 'da39a3ee5e6b4b0d3255bfef95601890afd80709']",
		"d41d8cd98f00b204e9800998ecf8427e":                                 "[file:hashes.'MD5' = 'd41d8cd98f00b204e9800998ecf8427e']",
	}
	for hash, want := range cases {
		if got := iocToSTIXPattern("hash", hash); got != want {
			t.Errorf("iocToSTIXPattern(hash, %q) = %q, want %q", hash, got, want)
		}
	}
	if got := iocToSTIXPattern("ip", "1.2.3.4"); got != "[ipv4-addr:value = '1.2.3.4']" {
		t.Errorf("ip pattern = %q", got)
	}
}
