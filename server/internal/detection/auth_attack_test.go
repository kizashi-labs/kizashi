package detection

import (
	"testing"
	"time"
)

func TestAuthAttack_BruteForceFires(t *testing.T) {
	a := newAuthAttackScorer()
	base := time.Unix(1_700_000_000, 0)
	var fired int
	for i := 0; i < bruteMinFails; i++ {
		m := a.Observe("agent1", "10.0.0.9", "administrator", false, base.Add(time.Duration(i)*time.Second))
		fired += len(m)
		if len(m) > 0 && m[0].MITRETags[0] != "T1110" {
			t.Errorf("brute-force should tag T1110, got %v", m[0].MITRETags)
		}
	}
	if fired != 1 {
		t.Fatalf("expected exactly 1 brute-force alert after %d fails, got %d", bruteMinFails, fired)
	}
}

func TestAuthAttack_SuccessResetsBrute(t *testing.T) {
	a := newAuthAttackScorer()
	base := time.Unix(1_700_000_000, 0)
	// A few fails, then a success (correct password) resets the counter, so the
	// next batch of fails must start over and not reach the threshold combined.
	for i := 0; i < bruteMinFails-1; i++ {
		a.Observe("agent1", "10.0.0.9", "bob", false, base.Add(time.Duration(i)*time.Second))
	}
	a.Observe("agent1", "10.0.0.9", "bob", true, base.Add(10*time.Second)) // success clears
	var fired int
	for i := 0; i < bruteMinFails-1; i++ {
		fired += len(a.Observe("agent1", "10.0.0.9", "bob", false, base.Add(time.Duration(20+i)*time.Second)))
	}
	if fired != 0 {
		t.Fatalf("success should have reset the brute counter; got %d alerts", fired)
	}
}

func TestAuthAttack_PasswordSprayFires(t *testing.T) {
	a := newAuthAttackScorer()
	base := time.Unix(1_700_000_000, 0)
	// One source, many DISTINCT accounts, each failing once — the spray shape.
	accounts := []string{"alice", "bob", "carol", "dave", "erin", "frank", "grace"}
	var fired int
	var sprayTag string
	for i, acct := range accounts {
		m := a.Observe("agent1", "203.0.113.7", acct, false, base.Add(time.Duration(i)*time.Second))
		fired += len(m)
		for _, mm := range m {
			if mm.MITRETags[0] == "T1110.003" {
				sprayTag = "T1110.003"
			}
		}
	}
	if sprayTag != "T1110.003" {
		t.Errorf("expected a password-spray (T1110.003) alert")
	}
	if fired != 1 {
		t.Fatalf("expected exactly 1 spray alert after %d distinct accounts, got %d", sprayMinAccounts, fired)
	}
}

func TestAuthAttack_FewFailsNoAlert(t *testing.T) {
	a := newAuthAttackScorer()
	base := time.Unix(1_700_000_000, 0)
	// Below both thresholds: a couple of typos on one account, one source.
	for i := 0; i < 3; i++ {
		if m := a.Observe("agent1", "10.0.0.9", "bob", false, base.Add(time.Duration(i)*time.Second)); len(m) > 0 {
			t.Fatalf("3 fails on one account must not alert")
		}
	}
}

func TestAuthAttack_WindowExpiryNoBrute(t *testing.T) {
	a := newAuthAttackScorer()
	base := time.Unix(1_700_000_000, 0)
	// Fails spread wider than the window never accumulate to the threshold.
	for i := 0; i < bruteMinFails+2; i++ {
		if m := a.Observe("agent1", "10.0.0.9", "bob", false, base.Add(time.Duration(i)*2*time.Minute)); len(m) > 0 {
			t.Fatalf("fails spaced beyond the window must not brute-force (iter %d)", i)
		}
	}
}

// The success that closes a failure burst is the compromise (T1110→T1078). It
// must be reported, and it must carry BOTH tactics — an alert tagged only
// credential-access understates a host that has actually been logged into.
func TestAuthAttack_BruteForceSuccessFires(t *testing.T) {
	a := newAuthAttackScorer()
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < bruteSuccessMinFails; i++ {
		a.Observe("agent1", "203.0.113.9", "administrator", false, base.Add(time.Duration(i)*time.Second))
	}
	m := a.Observe("agent1", "203.0.113.9", "administrator", true, base.Add(30*time.Second))
	if len(m) != 1 {
		t.Fatalf("success after %d fails must raise exactly 1 alert, got %d", bruteSuccessMinFails, len(m))
	}
	tags := map[string]bool{}
	for _, tag := range m[0].MITRETags {
		tags[tag] = true
	}
	for _, want := range []string{"T1110", "T1078"} {
		if !tags[want] {
			t.Errorf("brute-force success must tag %s; got %v", want, m[0].MITRETags)
		}
	}
	if m[0].Severity < 9 {
		t.Errorf("a confirmed compromise must outrank the attempt alert; got severity %d", m[0].Severity)
	}
	// A human who eventually remembers their password is the residual FP, so this
	// must stay a triage signal rather than an automatic host isolation.
	if m[0].AutoIsolate || m[0].AutoKill {
		t.Errorf("brute-force success must not auto-respond; AutoIsolate=%v AutoKill=%v", m[0].AutoIsolate, m[0].AutoKill)
	}
}

// Between bruteMinFails and bruteSuccessMinFails the attempt alert still fires,
// but the success does not — that band is where the mistyping-user FP lives.
func TestAuthAttack_BruteForceSuccessBelowThresholdIsSilent(t *testing.T) {
	a := newAuthAttackScorer()
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < bruteSuccessMinFails-1; i++ {
		a.Observe("agent1", "10.0.0.9", "bob", false, base.Add(time.Duration(i)*time.Second))
	}
	if m := a.Observe("agent1", "10.0.0.9", "bob", true, base.Add(30*time.Second)); len(m) > 0 {
		t.Fatalf("%d fails is below the success threshold; got %d alerts", bruteSuccessMinFails-1, len(m))
	}
}

// Failures spread wider than the window are not a burst. The success branch never
// pruned before this rule existed, so crediting stale timestamps is the specific
// way this check can silently turn into an every-login alert.
func TestAuthAttack_BruteForceSuccessIgnoresExpiredFailures(t *testing.T) {
	a := newAuthAttackScorer()
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < bruteSuccessMinFails+2; i++ {
		a.Observe("agent1", "10.0.0.9", "bob", false, base.Add(time.Duration(i)*2*time.Minute))
	}
	last := base.Add(time.Duration(bruteSuccessMinFails+2) * 2 * time.Minute)
	if m := a.Observe("agent1", "10.0.0.9", "bob", true, last); len(m) > 0 {
		t.Fatalf("fails spaced beyond the window are not a burst; got %d alerts", len(m))
	}
}

// One burst must produce one alert. A user logging in repeatedly after a real
// brute force would otherwise re-alert on every single login.
func TestAuthAttack_BruteForceSuccessDoesNotRefire(t *testing.T) {
	a := newAuthAttackScorer()
	base := time.Unix(1_700_000_000, 0)
	for i := 0; i < bruteSuccessMinFails; i++ {
		a.Observe("agent1", "203.0.113.9", "administrator", false, base.Add(time.Duration(i)*time.Second))
	}
	a.Observe("agent1", "203.0.113.9", "administrator", true, base.Add(30*time.Second))
	for i := 0; i < 3; i++ {
		if m := a.Observe("agent1", "203.0.113.9", "administrator", true, base.Add(time.Duration(40+i)*time.Second)); len(m) > 0 {
			t.Fatalf("the burst already alerted; subsequent logins must be silent (iter %d)", i)
		}
	}
}

func TestAuthSucceeded(t *testing.T) {
	cases := []struct {
		flat map[string]interface{}
		want bool
	}{
		{map[string]interface{}{"success": true}, true},
		{map[string]interface{}{"success": false}, false},
		{map[string]interface{}{"action": "failed"}, false},
		{map[string]interface{}{"action": "failure"}, false},
		{map[string]interface{}{"failure_reason": "bad password"}, false},
		{map[string]interface{}{"action": "logon"}, true}, // no failure signal
		{map[string]interface{}{}, true},
	}
	for _, c := range cases {
		if got := authSucceeded(c.flat); got != c.want {
			t.Errorf("authSucceeded(%v) = %v, want %v", c.flat, got, c.want)
		}
	}
}
