package detection

import "testing"

// TestAutoIsolateExempt covers the one response the platform cannot take back.
//
// Isolation firewalls the endpoint down to the EDR server alone, so isolating the
// host that RUNS the platform — a single-node deployment, a lab box, an operator's
// jump host — takes the service down AND locks the operator out of the machine they
// would fix it from. Recovery needs out-of-band access that may not exist.
//
// The exemption deliberately suppresses only the RESPONSE. Suppression rules cannot
// serve this purpose: they drop the alert, so exempting a host that way would blind
// detection on it, and their SeverityMax matches severity <= N, the opposite of the
// high-severity band that triggers isolation.
func TestAutoIsolateExempt(t *testing.T) {
	const agentID = "11111111-1111-1111-1111-111111111111"

	cases := []struct {
		name   string
		exempt []string
		alert  *StoredAlert
		want   bool
	}{
		{"未設定なら誰も除外しない", nil,
			&StoredAlert{AgentID: agentID, Hostname: "edr-server"}, false},
		{"エージェントIDの完全一致", []string{agentID},
			&StoredAlert{AgentID: agentID, Hostname: "edr-server"}, true},
		{"ホスト名は大文字小文字を無視", []string{"EDR-Server"},
			&StoredAlert{AgentID: agentID, Hostname: "edr-server"}, true},
		{"別ホストは除外しない", []string{"edr-server"},
			&StoredAlert{AgentID: "22222222-2222-2222-2222-222222222222", Hostname: "workstation-7"}, false},
		{"複数指定のうち1つに一致", []string{"jump-host", "edr-server", "lab-box"},
			&StoredAlert{AgentID: agentID, Hostname: "edr-server"}, true},
		{"空白は無視する（EXEMPT=\"a, b\" の空要素で全台除外にならない）", []string{" ", ""},
			&StoredAlert{AgentID: agentID, Hostname: "edr-server"}, false},
		{"前後の空白を許容する", []string{"  edr-server  "},
			&StoredAlert{AgentID: agentID, Hostname: "edr-server"}, true},
		// A hostname that merely CONTAINS an exempt entry must not match: "edr-server"
		// should not exempt "edr-server-of-a-customer". Isolation is the one place
		// where a too-broad match silently disarms the response.
		{"部分一致では除外しない", []string{"edr-server"},
			&StoredAlert{AgentID: agentID, Hostname: "edr-server-prod-2"}, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := &Engine{config: EngineConfig{AutoIsolateExempt: c.exempt}}
			if got := e.isAutoIsolateExempt(c.alert); got != c.want {
				t.Errorf("isAutoIsolateExempt() = %v, want %v (exempt=%v, agent=%s, host=%s)",
					got, c.want, c.exempt, c.alert.AgentID, c.alert.Hostname)
			}
		})
	}
}
