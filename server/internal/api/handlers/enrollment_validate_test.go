package handlers

import (
	"testing"
)

func TestContainsPattern_ExactMatch_ReturnsTrue(t *testing.T) {
	if !containsPattern("web-server-01", "web-server-01") {
		t.Error("exact match should return true")
	}
}

func TestContainsPattern_ExactMismatch_ReturnsFalse(t *testing.T) {
	if containsPattern("web-server-01", "web-server-02") {
		t.Error("non-matching exact pattern should return false")
	}
}

func TestContainsPattern_PrefixWildcard_Matches(t *testing.T) {
	if !containsPattern("web-server-01", "web-*") {
		t.Error("prefix wildcard 'web-*' should match 'web-server-01'")
	}
	if !containsPattern("web-db", "web-*") {
		t.Error("prefix wildcard 'web-*' should match 'web-db'")
	}
}

func TestContainsPattern_PrefixWildcard_NoMatch(t *testing.T) {
	if containsPattern("db-server-01", "web-*") {
		t.Error("prefix wildcard 'web-*' should NOT match 'db-server-01'")
	}
}

func TestContainsPattern_WildcardOnly_MatchesAll(t *testing.T) {
	for _, v := range []string{"anything", "host123", ""} {
		if !containsPattern(v, "*") {
			t.Errorf("wildcard '*' should match %q", v)
		}
	}
}

func TestContainsPattern_EmptyPattern_MatchesEmptyOnly(t *testing.T) {
	if !containsPattern("", "") {
		t.Error("empty pattern should match empty value")
	}
	if containsPattern("nonempty", "") {
		t.Error("empty pattern should NOT match non-empty value")
	}
}
