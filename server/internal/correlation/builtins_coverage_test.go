package correlation

import (
	"context"
	"testing"
)

// The existing correlation_test.go exercises the Engine MECHANICS with synthetic
// rules, but never loads BuiltinRules() — so the 5 shipped builtin correlation
// rules wired into the AlertPipeline (LoadBuiltins) were not regression-locked
// end-to-end. A broken condition, wrong EventTypes list, mis-set MinEvents, or a
// mistyped technique on a shipped rule would go unnoticed. This suite drives each
// shipped rule with a representative alert sequence and asserts it fires an
// incident carrying the right rule ID and technique.

// TestBuiltinCorrelationRules_AllFire loads the actual shipped builtin rules and
// drives each one's minimum qualifying alert burst, asserting the incident fires
// with the expected rule and MITRE technique.
func TestBuiltinCorrelationRules_AllFire(t *testing.T) {
	cases := []struct {
		ruleID   string
		tech     string
		baseType string
		severity int
		n        int // number of alerts to drive (== rule MinEvents)
	}{
		// corr-001: 5 auth failures within 10m, severity >= 4
		{"corr-001-lateral-movement", "T1021", "auth", 5, 5},
		// corr-002: 3 credential-dump events, event_type contains "credential" AND sev >= 7
		{"corr-002-credential-dumping", "T1003.001", "process", 8, 3},
		// corr-003: 5 file-encryption events, severity >= 8
		{"corr-003-ransomware-outbreak", "T1486", "file", 9, 5},
		// corr-004: 2 persistence events, severity >= 5
		{"corr-004-persistence", "T1547", "registry", 6, 2},
		// corr-005: 8 network-connection events, event_type contains "network" AND sev >= 4
		{"corr-005-c2-beaconing", "T1071.001", "network", 5, 8},
	}

	for _, c := range cases {
		t.Run(c.ruleID, func(t *testing.T) {
			e := NewEngine(nil) // nil pool → in-memory only, no DB
			LoadBuiltins(e)

			var fired *Incident
			for i := 0; i < c.n; i++ {
				inc := e.ProcessAlert(context.Background(),
					"alert-"+c.ruleID, "agent-1", c.baseType, c.tech, c.severity, nil)
				if inc != nil {
					fired = inc
				}
			}
			if fired == nil {
				t.Fatalf("shipped rule %s did not fire after %d qualifying alerts with base type %q + tech %q (MinEvents boundary drift?)",
					c.ruleID, c.n, c.baseType, c.tech)
			}
			if fired.RuleID != c.ruleID {
				t.Errorf("incident RuleID = %q, want %q", fired.RuleID, c.ruleID)
			}
			if fired.MITRETech != c.tech {
				t.Errorf("%s incident technique = %q, want %q", c.ruleID, fired.MITRETech, c.tech)
			}
		})
	}
}

// TestBuiltinCorrelationRules_BelowThresholdSilent verifies the shipped rules do
// NOT fire below their MinEvents — a threshold regression (e.g. MinEvents dropped
// to 1) would turn correlation into single-alert noise.
func TestBuiltinCorrelationRules_BelowThresholdSilent(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	// 4 auth failures — one below corr-001's MinEvents of 5.
	for i := 0; i < 4; i++ {
		if inc := e.ProcessAlert(context.Background(), "a", "agent-1", "auth", "T1110", 5, nil); inc != nil {
			t.Fatalf("corr-001 fired on alert %d, below its MinEvents threshold", i+1)
		}
	}
}

// TestBuiltinCorrelationRule_CloudChainFires drives corr-006 with the minimum
// qualifying burst of cloud-surface alerts (as the AlertPipeline stamps them) and
// asserts the multi-stage cloud takeover incident fires with the right technique.
func TestBuiltinCorrelationRule_CloudChainFires(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	cloud := map[string]interface{}{"_attack_surface": "cloud"}
	var fired *Incident
	// 3 cloud-technique alerts (e.g. discovery → cred creation → cloudtrail off),
	// all type "process" as cloud CLI Sigma alerts arrive, within the window.
	for i := 0; i < 3; i++ {
		if inc := e.ProcessAlert(context.Background(), "alert-cloud", "agent-1", "process", "T1526", 6, cloud); inc != nil {
			fired = inc
		}
	}
	if fired == nil {
		t.Fatalf("corr-006 did not fire after 3 cloud-surface alerts (MinEvents boundary drift?)")
	}
	if fired.RuleID != "corr-006-cloud-attack-chain" {
		t.Errorf("incident RuleID = %q, want corr-006-cloud-attack-chain", fired.RuleID)
	}
	if fired.MITRETech != "T1078.004" {
		t.Errorf("corr-006 technique = %q, want T1078.004", fired.MITRETech)
	}
}

// TestBuiltinCorrelationRule_CloudChainGating verifies corr-006 does NOT fire on
// non-cloud alerts (missing the _attack_surface marker) or below MinEvents — so
// ordinary process alerts never trip the cloud takeover rule.
func TestBuiltinCorrelationRule_CloudChainGating(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	// Process alerts with no cloud marker must never fire corr-006.
	for i := 0; i < 5; i++ {
		if inc := e.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 8, nil); inc != nil && inc.RuleID == "corr-006-cloud-attack-chain" {
			t.Fatalf("corr-006 fired on non-cloud process alerts (missing _attack_surface gate)")
		}
	}

	// 2 cloud alerts — one below corr-006's MinEvents of 3 — must stay silent.
	e2 := NewEngine(nil)
	LoadBuiltins(e2)
	cloud := map[string]interface{}{"_attack_surface": "cloud"}
	for i := 0; i < 2; i++ {
		if inc := e2.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 6, cloud); inc != nil {
			t.Fatalf("corr-006 fired on alert %d, below its MinEvents threshold of 3", i+1)
		}
	}
}

// TestBuiltinCorrelationRule_ADChainFires drives corr-007 with the minimum
// qualifying burst of AD-surface alerts (as the AlertPipeline stamps them) and
// asserts the AD domain compromise incident fires with the right technique.
func TestBuiltinCorrelationRule_ADChainFires(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	ad := map[string]interface{}{"_attack_surface": "ad"}
	var fired *Incident
	// 3 AD-technique alerts (e.g. domain recon → Kerberoasting → pass-the-hash).
	for i := 0; i < 3; i++ {
		if inc := e.ProcessAlert(context.Background(), "alert-ad", "agent-1", "process", "", 7, ad); inc != nil {
			fired = inc
		}
	}
	if fired == nil {
		t.Fatalf("corr-007 did not fire after 3 AD-surface alerts (MinEvents boundary drift?)")
	}
	if fired.RuleID != "corr-007-ad-compromise-chain" {
		t.Errorf("incident RuleID = %q, want corr-007-ad-compromise-chain", fired.RuleID)
	}
	if fired.MITRETech != "T1078.002" {
		t.Errorf("corr-007 technique = %q, want T1078.002", fired.MITRETech)
	}
}

// TestBuiltinCorrelationRule_ADChainGating verifies corr-007 stays silent on
// non-AD alerts and below MinEvents, and that cloud vs AD surfaces don't cross-fire.
func TestBuiltinCorrelationRule_ADChainGating(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	// Cloud-surface alerts must NOT fire the AD chain (and vice-versa handled in
	// the cloud test) — the surfaces are disjoint.
	cloud := map[string]interface{}{"_attack_surface": "cloud"}
	for i := 0; i < 3; i++ {
		if inc := e.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 7, cloud); inc != nil && inc.RuleID == "corr-007-ad-compromise-chain" {
			t.Fatalf("corr-007 fired on cloud-surface alerts (surface confusion)")
		}
	}

	// 2 AD alerts — below corr-007's MinEvents of 3 — must stay silent.
	e2 := NewEngine(nil)
	LoadBuiltins(e2)
	ad := map[string]interface{}{"_attack_surface": "ad"}
	for i := 0; i < 2; i++ {
		if inc := e2.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 7, ad); inc != nil {
			t.Fatalf("corr-007 fired on alert %d, below its MinEvents threshold of 3", i+1)
		}
	}
}

// TestBuiltinCorrelationRule_RansomwarePrepFires drives corr-008 with 2 destructive
// pre-encryption steps (as the AlertPipeline stamps them) and asserts the imminent
// ransomware incident fires with the right technique, before any encryption.
func TestBuiltinCorrelationRule_RansomwarePrepFires(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	prep := map[string]interface{}{"_ransomware_precursor": "true"}
	var fired *Incident
	// 2 precursor alerts (e.g. vssadmin delete shadows → disable Defender).
	for i := 0; i < 2; i++ {
		if inc := e.ProcessAlert(context.Background(), "alert-ransom", "agent-1", "process", "", 9, prep); inc != nil {
			fired = inc
		}
	}
	if fired == nil {
		t.Fatalf("corr-008 did not fire after 2 ransomware-precursor alerts (MinEvents boundary drift?)")
	}
	if fired.RuleID != "corr-008-ransomware-preparation" {
		t.Errorf("incident RuleID = %q, want corr-008-ransomware-preparation", fired.RuleID)
	}
	if fired.MITRETech != "T1486" {
		t.Errorf("corr-008 technique = %q, want T1486", fired.MITRETech)
	}
}

// TestBuiltinCorrelationRule_RansomwarePrepGating verifies corr-008 stays silent on
// alerts without the precursor marker and below its MinEvents of 2.
func TestBuiltinCorrelationRule_RansomwarePrepGating(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	// Ordinary high-severity process alerts (no precursor marker) must not fire it.
	for i := 0; i < 4; i++ {
		if inc := e.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 9, nil); inc != nil && inc.RuleID == "corr-008-ransomware-preparation" {
			t.Fatalf("corr-008 fired on non-precursor process alerts (missing _ransomware_precursor gate)")
		}
	}

	// 1 precursor alert — below corr-008's MinEvents of 2 — must stay silent (a
	// single recovery-inhibition alert is handled by its own single-event rule).
	e2 := NewEngine(nil)
	LoadBuiltins(e2)
	prep := map[string]interface{}{"_ransomware_precursor": "true"}
	if inc := e2.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 9, prep); inc != nil {
		t.Fatalf("corr-008 fired on a single precursor alert, below its MinEvents threshold of 2")
	}
}

// TestBuiltinCorrelationRule_ExfilFires drives corr-009 with 2 collection/exfil
// steps (as the AlertPipeline stamps them) and asserts the data-exfiltration
// incident fires with the right technique.
func TestBuiltinCorrelationRule_ExfilFires(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	exfil := map[string]interface{}{"_exfil_activity": "true"}
	var fired *Incident
	// 2 exfil-class alerts (e.g. archive collected data → FTP upload).
	for i := 0; i < 2; i++ {
		if inc := e.ProcessAlert(context.Background(), "alert-exfil", "agent-1", "process", "", 6, exfil); inc != nil {
			fired = inc
		}
	}
	if fired == nil {
		t.Fatalf("corr-009 did not fire after 2 exfil-activity alerts (MinEvents boundary drift?)")
	}
	if fired.RuleID != "corr-009-data-exfiltration" {
		t.Errorf("incident RuleID = %q, want corr-009-data-exfiltration", fired.RuleID)
	}
	if fired.MITRETech != "T1567" {
		t.Errorf("corr-009 technique = %q, want T1567", fired.MITRETech)
	}
}

// TestBuiltinCorrelationRule_ExfilGating verifies corr-009 stays silent without the
// exfil marker and below MinEvents of 2.
func TestBuiltinCorrelationRule_ExfilGating(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	for i := 0; i < 4; i++ {
		if inc := e.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 8, nil); inc != nil && inc.RuleID == "corr-009-data-exfiltration" {
			t.Fatalf("corr-009 fired on non-exfil process alerts (missing _exfil_activity gate)")
		}
	}

	e2 := NewEngine(nil)
	LoadBuiltins(e2)
	exfil := map[string]interface{}{"_exfil_activity": "true"}
	if inc := e2.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 6, exfil); inc != nil {
		t.Fatalf("corr-009 fired on a single exfil alert, below its MinEvents threshold of 2")
	}
}

// TestBuiltinCorrelationRule_ContainerBreakoutFires drives corr-010 with 2
// container-escalation steps (as the AlertPipeline stamps them) and asserts the
// container-breakout incident fires with the right technique.
func TestBuiltinCorrelationRule_ContainerBreakoutFires(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	esc := map[string]interface{}{"_container_escalation": "true"}
	var fired *Incident
	// 2 container-escalation alerts (e.g. privileged container deploy → escape to host).
	for i := 0; i < 2; i++ {
		if inc := e.ProcessAlert(context.Background(), "alert-esc", "agent-1", "process", "", 8, esc); inc != nil {
			fired = inc
		}
	}
	if fired == nil {
		t.Fatalf("corr-010 did not fire after 2 container-escalation alerts (MinEvents boundary drift?)")
	}
	if fired.RuleID != "corr-010-container-breakout" {
		t.Errorf("incident RuleID = %q, want corr-010-container-breakout", fired.RuleID)
	}
	if fired.MITRETech != "T1611" {
		t.Errorf("corr-010 technique = %q, want T1611", fired.MITRETech)
	}
}

// TestBuiltinCorrelationRule_ContainerBreakoutGating verifies corr-010 stays
// silent without the container-escalation marker and below MinEvents of 2.
func TestBuiltinCorrelationRule_ContainerBreakoutGating(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	for i := 0; i < 4; i++ {
		if inc := e.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 8, nil); inc != nil && inc.RuleID == "corr-010-container-breakout" {
			t.Fatalf("corr-010 fired on non-container process alerts (missing _container_escalation gate)")
		}
	}

	e2 := NewEngine(nil)
	LoadBuiltins(e2)
	esc := map[string]interface{}{"_container_escalation": "true"}
	if inc := e2.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 8, esc); inc != nil {
		t.Fatalf("corr-010 fired on a single container-escalation alert, below its MinEvents threshold of 2")
	}
}

// TestBuiltinCorrelationRule_CredentialTheftFires drives corr-011 with 2
// credential-harvesting steps (as the AlertPipeline stamps them) and asserts the
// multi-source credential-theft incident fires with the right technique.
func TestBuiltinCorrelationRule_CredentialTheftFires(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	cred := map[string]interface{}{"_credential_theft": "true"}
	var fired *Incident
	// 2 credential-theft alerts (e.g. LSASS dump → browser credential theft).
	for i := 0; i < 2; i++ {
		if inc := e.ProcessAlert(context.Background(), "alert-cred", "agent-1", "process", "", 8, cred); inc != nil {
			fired = inc
		}
	}
	if fired == nil {
		t.Fatalf("corr-011 did not fire after 2 credential-theft alerts (MinEvents boundary drift?)")
	}
	if fired.RuleID != "corr-011-multi-source-credential-theft" {
		t.Errorf("incident RuleID = %q, want corr-011-multi-source-credential-theft", fired.RuleID)
	}
	if fired.MITRETech != "T1003" {
		t.Errorf("corr-011 technique = %q, want T1003", fired.MITRETech)
	}
}

// TestBuiltinCorrelationRule_CredentialTheftGating verifies corr-011 stays silent
// without the credential-theft marker and below MinEvents of 2.
func TestBuiltinCorrelationRule_CredentialTheftGating(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	for i := 0; i < 4; i++ {
		if inc := e.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 8, nil); inc != nil && inc.RuleID == "corr-011-multi-source-credential-theft" {
			t.Fatalf("corr-011 fired on non-credential process alerts (missing _credential_theft gate)")
		}
	}

	e2 := NewEngine(nil)
	LoadBuiltins(e2)
	cred := map[string]interface{}{"_credential_theft": "true"}
	if inc := e2.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 8, cred); inc != nil {
		t.Fatalf("corr-011 fired on a single credential-theft alert, below its MinEvents threshold of 2")
	}
}

// TestBuiltinCorrelationRule_ReconBurstFires drives corr-012 with 3 discovery
// steps (as the AlertPipeline stamps them) and asserts the reconnaissance-burst
// incident fires with the right technique.
func TestBuiltinCorrelationRule_ReconBurstFires(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	recon := map[string]interface{}{"_discovery_recon": "true"}
	var fired *Incident
	// 3 discovery alerts (e.g. account → network → domain-trust enumeration).
	for i := 0; i < 3; i++ {
		if inc := e.ProcessAlert(context.Background(), "alert-recon", "agent-1", "process", "", 4, recon); inc != nil {
			fired = inc
		}
	}
	if fired == nil {
		t.Fatalf("corr-012 did not fire after 3 discovery alerts (MinEvents boundary drift?)")
	}
	if fired.RuleID != "corr-012-reconnaissance-burst" {
		t.Errorf("incident RuleID = %q, want corr-012-reconnaissance-burst", fired.RuleID)
	}
	if fired.MITRETech != "T1087" {
		t.Errorf("corr-012 technique = %q, want T1087", fired.MITRETech)
	}
}

// TestBuiltinCorrelationRule_ReconBurstGating verifies corr-012 stays silent
// without the discovery marker and below its MinEvents of 3.
func TestBuiltinCorrelationRule_ReconBurstGating(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	for i := 0; i < 5; i++ {
		if inc := e.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 4, nil); inc != nil && inc.RuleID == "corr-012-reconnaissance-burst" {
			t.Fatalf("corr-012 fired on non-discovery process alerts (missing _discovery_recon gate)")
		}
	}

	e2 := NewEngine(nil)
	LoadBuiltins(e2)
	recon := map[string]interface{}{"_discovery_recon": "true"}
	// 2 discovery alerts — one below the MinEvents threshold of 3, must not fire.
	for i := 0; i < 2; i++ {
		if inc := e2.ProcessAlert(context.Background(), "a", "agent-1", "process", "", 4, recon); inc != nil && inc.RuleID == "corr-012-reconnaissance-burst" {
			t.Fatalf("corr-012 fired on 2 discovery alerts, below its MinEvents threshold of 3")
		}
	}
}

// TestBuiltinCorrelationRules_ConditionGating verifies the per-rule Conditions
// actually gate: an event of the right type but failing the severity/contains
// condition must not advance the correlation.
func TestBuiltinCorrelationRules_ConditionGating(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)

	// corr-003 ransomware requires severity >= 8. Drive 6 file_encrypted events at
	// severity 7 (one below) — must never fire.
	for i := 0; i < 6; i++ {
		if inc := e.ProcessAlert(context.Background(), "a", "agent-1", "file_encrypted", "", 7, nil); inc != nil {
			t.Fatalf("corr-003 fired with severity 7 events, below its gte-8 condition")
		}
	}

	// corr-002 requires event_type to CONTAIN "credential". An lsass_access event
	// is in EventTypes but fails the contains-"credential" condition → no fire.
	for i := 0; i < 5; i++ {
		if inc := e.ProcessAlert(context.Background(), "a", "agent-2", "lsass_access", "", 9, nil); inc != nil {
			t.Fatalf("corr-002 fired on lsass_access events that fail the event_type~credential condition")
		}
	}
}

// TestLoadBuiltins_RuleCount is a lightweight guard that all 12 shipped rules load
// (so an accidental removal or a duplicate ID that AddRule dedupes is caught).
func TestLoadBuiltins_RuleCount(t *testing.T) {
	e := NewEngine(nil)
	LoadBuiltins(e)
	rules := e.ListRules()
	if len(rules) != 12 {
		t.Fatalf("expected 12 builtin correlation rules loaded, got %d", len(rules))
	}
	// Every shipped rule must carry a technique and a positive MinEvents.
	for _, r := range rules {
		if r.MITRETech == "" {
			t.Errorf("builtin rule %s has no MITRE technique", r.ID)
		}
		if r.MinEvents < 1 {
			t.Errorf("builtin rule %s has MinEvents %d (< 1) — would fire on a single alert", r.ID, r.MinEvents)
		}
	}
}
