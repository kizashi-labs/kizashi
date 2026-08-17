package transport

import (
	"encoding/json"
	"testing"
)

// The wire shape must match the server's store.ApplyPolicyPayload exactly. It
// carries no "type" field — ingestion's comment claimed one for years and the
// agent looked for a marker that was never sent, which is why policy push never
// reached any endpoint.
func TestApplyPolicyCmdMatchesServerPayload(t *testing.T) {
	// Verbatim shape emitted by store.EnqueueApplyPolicy.
	wire := `{"agent_id":"a1","policy_id":"p-42","scan_interval_min":30,"cpu_limit_pct":25,"enabled_modules":["network","dns"]}`

	var got ApplyPolicyCmd
	if err := json.Unmarshal([]byte(wire), &got); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if got.PolicyID != "p-42" {
		t.Errorf("PolicyID = %q, want p-42", got.PolicyID)
	}
	if got.ScanIntervalMin != 30 || got.CPULimitPct != 25 {
		t.Errorf("limits = %d/%d, want 30/25", got.ScanIntervalMin, got.CPULimitPct)
	}
	if len(got.EnabledModules) != 2 {
		t.Errorf("EnabledModules = %v, want two entries", got.EnabledModules)
	}

	// The absence of a "type" key must not stop identification: policy_id is the
	// discriminator, and it is the only field a policy push always has.
	if got.PolicyID == "" {
		t.Error("policy_id must be the discriminator, and it must survive decoding")
	}
}

// A payload without policy_id is NOT a policy push and must not be claimed as
// one — otherwise a genuine artifact collection would be swallowed.
func TestApplyPolicyCmdRejectsNonPolicyPayloads(t *testing.T) {
	for _, wire := range []string{
		`{"type":"forensics_job","job_id":"j1"}`,
		`{"type":"cert_renew","renewal_token":"t"}`,
		`{"agent_id":"a1"}`,
		`{}`,
	} {
		var got ApplyPolicyCmd
		if err := json.Unmarshal([]byte(wire), &got); err != nil {
			continue // not decodable as a policy either — also fine
		}
		if got.PolicyID != "" {
			t.Errorf("%s was misidentified as a policy push", wire)
		}
	}
}
