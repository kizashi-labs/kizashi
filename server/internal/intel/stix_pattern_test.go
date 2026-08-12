package intel

import "testing"

func TestExtractIOCFromSTIXPattern(t *testing.T) {
	cases := []struct {
		name     string
		pattern  string
		wantType string
		wantVal  string
		wantOK   bool
	}{
		{"ipv4", "[ipv4-addr:value = '1.2.3.4']", "ip", "1.2.3.4", true},
		{"ipv6", "[ipv6-addr:value = '2001:db8::1']", "ip", "2001:db8::1", true},
		{"domain", "[domain-name:value = 'evil.example.com']", "domain", "evil.example.com", true},
		{"url", "[url:value = 'http://evil.example.com/x']", "url", "http://evil.example.com/x", true},
		{"sha256 quoted key", "[file:hashes.'SHA-256' = 'abc123']", "sha256", "abc123", true},
		{"sha256 unquoted key", "[file:hashes.SHA-256 = 'abc123']", "sha256", "abc123", true},
		{"sha1", "[file:hashes.'SHA-1' = 'def456']", "sha1", "def456", true},
		{"md5", "[file:hashes.'MD5' = 'aa11bb22']", "md5", "aa11bb22", true},
		{"no tight spacing", "[ipv4-addr:value='9.9.9.9']", "ip", "9.9.9.9", true},
		{"unsupported", "[email-addr:value = 'x@y.com']", "", "", false},
		{"garbage", "not a pattern", "", "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			gotType, gotVal, ok := ExtractIOCFromSTIXPattern(tc.pattern)
			if ok != tc.wantOK || gotType != tc.wantType || gotVal != tc.wantVal {
				t.Fatalf("ExtractIOCFromSTIXPattern(%q) = (%q,%q,%v), want (%q,%q,%v)",
					tc.pattern, gotType, gotVal, ok, tc.wantType, tc.wantVal, tc.wantOK)
			}
		})
	}
}

// A file: hash pattern must never be misread as another type, and SHA-256 must
// win over the MD5 regex even though both mention "file:hashes".
func TestExtractIOCFromSTIXPattern_HashPrecedence(t *testing.T) {
	gotType, _, ok := ExtractIOCFromSTIXPattern("[file:hashes.'SHA-256' = 'a']")
	if !ok || gotType != "sha256" {
		t.Fatalf("expected sha256, got %q (ok=%v)", gotType, ok)
	}
}
