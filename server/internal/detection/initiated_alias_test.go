package detection

import "testing"

// TestInitiatedAliasFromDirection guards the network Initiated translation: SigmaHQ
// network_connection rules match `Initiated: 'true'` (host-initiated/outbound), but
// agents emit direction = outbound|inbound. Measured 2026-07-02 as the 2nd-largest
// inert cause (41 enabled rules referenced Initiated with no source field).
func TestInitiatedAliasFromDirection(t *testing.T) {
	cases := []struct {
		dir  string
		want string
	}{
		{"outbound", "true"},
		{"inbound", "false"},
		{"OUTBOUND", "true"}, // case-insensitive
	}
	for _, c := range cases {
		flat := map[string]interface{}{"type": "network", "direction": c.dir, "dst_ip": "1.2.3.4"}
		addPipelineSigmaAliases(flat)
		if got, _ := flat["Initiated"].(string); got != c.want {
			t.Errorf("direction=%q → Initiated=%q, want %q", c.dir, got, c.want)
		}
	}
}

// TestInitiatedIsFieldSupported ensures the alias makes `Initiated` a supported
// field, so the curate field-gate stops classifying the 41 Initiated rules as
// unsupported (false-green) and they become genuinely enable-able.
func TestInitiatedIsFieldSupported(t *testing.T) {
	sup := SupportedSigmaFields()
	if !sup["Initiated"] && !sup["initiated"] {
		t.Fatal("Initiated must be in SupportedSigmaFields (via the direction→Initiated alias) " +
			"so network_connection rules using it are field-supported")
	}
}
