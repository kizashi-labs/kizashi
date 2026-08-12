package detection

import (
	"context"
	"net"
	"strings"
	"testing"
)

// TestBuiltinIOCLoader already checks that IOCs load with non-empty Type/Value.
// It does NOT check they are well-formed for their TYPE — and a malformed
// built-in IOC (an IP that isn't parseable, a hash of the wrong length, a domain
// with a scheme/space) is silent dead coverage: it ships enabled yet can never
// match real telemetry. These tests lock the shipped indicators to be matchable.

// isHexHash reports whether s is a lowercase/uppercase hex string of an MD5/SHA1/
// SHA256 length.
func isHexHash(s string) bool {
	switch len(s) {
	case 32, 40, 64: // MD5, SHA1, SHA256
	default:
		return false
	}
	for _, r := range s {
		isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
		if !isHex {
			return false
		}
	}
	return true
}

// TestBuiltinIOCs_WellFormed validates every shipped built-in IOC against its
// declared type so a malformed indicator can never silently ship as
// never-matching. Guards the same "silent dead coverage" class as the Sigma
// compile/field-support gates, but for the IOC path.
func TestBuiltinIOCs_WellFormed(t *testing.T) {
	iocs, err := BuiltinIOCLoader().ListActiveIOCs(context.Background())
	if err != nil {
		t.Fatalf("ListActiveIOCs: %v", err)
	}
	if len(iocs) == 0 {
		t.Fatal("expected built-in IOCs")
	}

	knownTypes := map[string]bool{"ip": true, "domain": true, "hash": true, "process": true, "url": true}

	for _, ioc := range iocs {
		if !knownTypes[ioc.Type] {
			t.Errorf("%s: unknown IOC type %q (matcher can never handle it)", ioc.ID, ioc.Type)
		}
		if ioc.Severity < 1 || ioc.Severity > 10 {
			t.Errorf("%s: severity %d out of [1,10]", ioc.ID, ioc.Severity)
		}
		v := strings.TrimSpace(ioc.Value)
		if v != ioc.Value {
			t.Errorf("%s: value %q has surrounding whitespace (would not match normalized telemetry)", ioc.ID, ioc.Value)
		}

		switch ioc.Type {
		case "ip":
			// "ip" IOCs also accept a CIDR range (matched by containment in
			// ioc_matcher.go), not just a single address — see ioc_matcher_cidr_test.go.
			if _, _, err := net.ParseCIDR(v); err != nil && net.ParseIP(v) == nil {
				t.Errorf("%s: ip IOC value %q does not parse as an IP or CIDR range (a typo never matches a single-IP event field)", ioc.ID, v)
			}
		case "hash":
			if !isHexHash(v) {
				t.Errorf("%s: hash IOC value %q is not valid hex of MD5/SHA1/SHA256 length", ioc.ID, v)
			}
		case "domain":
			if !strings.Contains(v, ".") || strings.ContainsAny(v, " /:") {
				t.Errorf("%s: domain IOC value %q is not a bare hostname (scheme/path/space present or no dot)", ioc.ID, v)
			}
		case "url":
			if !strings.Contains(v, "://") {
				t.Errorf("%s: url IOC value %q is not a URL", ioc.ID, v)
			}
		}
	}
}

// TestBuiltinIOCs_UniqueIDs guards against a copy-paste duplicate ID, which would
// make dedup/reporting collide and mask one of the indicators.
func TestBuiltinIOCs_UniqueIDs(t *testing.T) {
	iocs, err := BuiltinIOCLoader().ListActiveIOCs(context.Background())
	if err != nil {
		t.Fatalf("ListActiveIOCs: %v", err)
	}
	seen := map[string]bool{}
	for _, ioc := range iocs {
		if ioc.ID == "" {
			t.Errorf("built-in IOC with empty ID: %+v", ioc)
			continue
		}
		if seen[ioc.ID] {
			t.Errorf("duplicate built-in IOC ID %q", ioc.ID)
		}
		seen[ioc.ID] = true
	}
}

// TestCompositeIOCLoader_MergesBuiltins locks the contract that the composite
// loader actually surfaces the built-in indicators alongside DB feeds — the
// mechanism by which builtins reach the live cache. A regression that dropped the
// static loader would silently remove the baseline IOC coverage.
func TestCompositeIOCLoader_MergesBuiltins(t *testing.T) {
	extra := []IOCRecord{{ID: "db-1", Type: "ip", Value: "203.0.113.7", Severity: 5}}
	comp := NewCompositeIOCLoader(BuiltinIOCLoader(), NewStaticIOCLoader(extra))
	all, err := comp.ListActiveIOCs(context.Background())
	if err != nil {
		t.Fatalf("composite ListActiveIOCs: %v", err)
	}
	ids := map[string]bool{}
	for _, ioc := range all {
		ids[ioc.ID] = true
	}
	if !ids["db-1"] {
		t.Errorf("composite loader dropped the second loader's IOC")
	}
	if !ids["builtin-ip-001"] {
		t.Errorf("composite loader dropped the built-in IOCs (baseline coverage lost)")
	}
}
