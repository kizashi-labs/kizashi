package detection

import (
	"testing"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

func TestProcessThreatCorrelator_CompromiseThenC2Fires(t *testing.T) {
	p := newProcessThreatCorrelator()
	base := time.Unix(1_700_000_000, 0)

	if m := p.Observe("a1", 4242, "", procSigCompromise, base); len(m) != 0 {
		t.Fatalf("compromise alone should not correlate, got %d", len(m))
	}
	m := p.Observe("a1", 4242, "", procSigC2, base.Add(2*time.Minute))
	if len(m) != 1 {
		t.Fatalf("compromise + C2 on one PID should correlate, got %d", len(m))
	}
	if m[0].Severity != 10 {
		t.Errorf("active-implant correlation: want sev 10, got %d", m[0].Severity)
	}
	if m[0].RuleType != "correlation" {
		t.Errorf("RuleType = %q, want correlation", m[0].RuleType)
	}
}

func TestProcessThreatCorrelator_DifferentPIDsDoNotCorrelate(t *testing.T) {
	p := newProcessThreatCorrelator()
	base := time.Unix(1_700_000_000, 0)
	p.Observe("a1", 100, "", procSigCompromise, base)
	if m := p.Observe("a1", 200, "", procSigC2, base.Add(time.Minute)); len(m) != 0 {
		t.Errorf("compromise and C2 on different PIDs must not correlate, got %d", len(m))
	}
}

func TestProcessThreatCorrelator_SingleAxisDoesNotFire(t *testing.T) {
	p := newProcessThreatCorrelator()
	base := time.Unix(1_700_000_000, 0)
	if m := p.Observe("a1", 1, "", procSigC2, base); len(m) != 0 {
		t.Errorf("C2 alone must not correlate, got %d", len(m))
	}
	if m := p.Observe("a1", 2, "", procSigCompromise, base); len(m) != 0 {
		t.Errorf("compromise alone must not correlate, got %d", len(m))
	}
}

func TestProcessThreatCorrelator_WindowExpiry(t *testing.T) {
	p := newProcessThreatCorrelator()
	base := time.Unix(1_700_000_000, 0)
	p.Observe("a1", 4242, "", procSigCompromise, base)
	// C2 arrives after the window → the compromise signal has expired, no correlation.
	if m := p.Observe("a1", 4242, "", procSigC2, base.Add(procThreatWindow+time.Minute)); len(m) != 0 {
		t.Errorf("axes separated by more than the window must not correlate, got %d", len(m))
	}
}

// A PID recycled between the two axes must not correlate: the compromise signal
// belonged to a process that no longer exists, and the C2 signal belongs to an
// unrelated one that inherited its PID. A false agreement here puts a severity-10
// "active implant" at the top of the analyst queue for two events sharing nothing.
func TestProcessThreatCorrelator_RecycledPIDDoesNotCorrelate(t *testing.T) {
	p := newProcessThreatCorrelator()
	base := time.Unix(1_700_000_000, 0)

	p.Observe("a1", 4242, `C:\tools\mimikatz.exe`, procSigCompromise, base)
	if m := p.Observe("a1", 4242, `C:\Program Files\backup\agent.exe`, procSigC2, base.Add(20*time.Minute)); len(m) != 0 {
		t.Fatalf("a recycled PID with a different image must not correlate, got %d", len(m))
	}
	// Suppression must not consume the fire-once budget: the real implant reusing
	// that PID later still has to alert.
	m := p.Observe("a1", 4242, `C:\tools\mimikatz.exe`, procSigC2, base.Add(25*time.Minute))
	if len(m) != 1 {
		t.Fatalf("matching image after a suppressed pair must still correlate, got %d", len(m))
	}
	if m[0].Severity != 10 {
		t.Errorf("want the genuine correlation at severity 10, got %d", m[0].Severity)
	}
}

// The two axes name a process differently — credential-access events carry a full
// path, network events a bare name — so identity must compare on the basename.
func TestProcessThreatCorrelator_PathAndBareNameAreSameProcess(t *testing.T) {
	p := newProcessThreatCorrelator()
	base := time.Unix(1_700_000_000, 0)
	p.Observe("a1", 77, `C:\Windows\System32\rundll32.exe`, procSigCompromise, base)
	if m := p.Observe("a1", 77, "RUNDLL32.EXE", procSigC2, base.Add(time.Minute)); len(m) != 1 {
		t.Errorf("same image spelled as path vs bare name must correlate, got %d", len(m))
	}
}

// An unnamed axis (the target_pid of an injection, which names only the injector)
// keeps the permissive behaviour — suppressing here would kill the detection this
// correlator exists for.
func TestProcessThreatCorrelator_UnknownNameStillCorrelates(t *testing.T) {
	p := newProcessThreatCorrelator()
	base := time.Unix(1_700_000_000, 0)
	p.Observe("a1", 99, "", procSigCompromise, base)
	if m := p.Observe("a1", 99, "svchost.exe", procSigC2, base.Add(time.Minute)); len(m) != 1 {
		t.Errorf("unknown name on one axis must not suppress, got %d", len(m))
	}
}

// The name attributed to a PID must come from the field describing THAT pid.
func TestCandidateActorPIDs_NamesPerPID(t *testing.T) {
	flat := map[string]interface{}{
		"pid": float64(10), "process_name": "mimikatz.exe",
		"source_pid": float64(20), "source_image": `C:\tmp\inject.exe`,
		"target_pid": float64(30), "target_image": `C:\Windows\System32\lsass.exe`,
	}
	got := candidateActorPIDs(flat)
	want := map[int]string{10: "mimikatz.exe", 20: `C:\tmp\inject.exe`, 30: `C:\Windows\System32\lsass.exe`}
	if len(got) != 3 {
		t.Fatalf("want 3 identities, got %v", got)
	}
	for _, id := range got {
		if want[id.PID] != id.Name {
			t.Errorf("pid %d: name = %q, want %q", id.PID, id.Name, want[id.PID])
		}
	}
	// An injection event names the injector only: target_pid must stay unnamed
	// rather than inherit process_name, which would suppress the later C2 signal
	// from the injected process.
	inj := map[string]interface{}{"pid": float64(1), "process_name": "injector.exe", "target_pid": float64(2)}
	for _, id := range candidateActorPIDs(inj) {
		if id.PID == 2 && id.Name != "" {
			t.Errorf("target_pid must not inherit the injector's name, got %q", id.Name)
		}
	}
}

func TestIsCompromiseSignal(t *testing.T) {
	yaraHit := map[string]interface{}{"yara_matched": true}
	yes := []struct {
		m    *detectionrules.RuleMatch
		flat map[string]interface{}
	}{
		{&detectionrules.RuleMatch{RuleType: "memory", RuleName: "メモリ検知"}, yaraHit},
		{&detectionrules.RuleMatch{RuleType: "credential_access", RuleName: "LSASSアクセス"}, nil},
		{&detectionrules.RuleMatch{MITRETags: []string{"T1055.012"}, RuleName: "Svchost With Non-Standard Parent (Process Hollowing / Masquerade)"}, nil},
		{&detectionrules.RuleMatch{MITRETags: []string{"T1003.001"}}, nil},
	}
	for i, c := range yes {
		if !isCompromiseSignal(c.m, c.flat) {
			t.Errorf("case %d should be a compromise signal: %+v", i, c.m)
		}
	}
	no := []struct {
		m    *detectionrules.RuleMatch
		flat map[string]interface{}
	}{
		{&detectionrules.RuleMatch{MITRETags: []string{"T1046"}, RuleName: "port scan"}, nil},
		{&detectionrules.RuleMatch{RuleType: "behavioral", RuleName: "C2ビーコン疑い"}, nil},
		{nil, nil},
	}
	for i, c := range no {
		if isCompromiseSignal(c.m, c.flat) {
			t.Errorf("case %d should NOT be a compromise signal: %+v", i, c.m)
		}
	}
}

// The observed production false positive: .NET JIT memory in powershell.exe is
// RWX *and* unbacked — the memory scanner's strongest structural class — so only a
// YARA content match may promote a memory finding to a compromise axis.
func TestIsCompromiseSignal_StructuralMemoryIsNotEnough(t *testing.T) {
	mem := &detectionrules.RuleMatch{RuleType: "memory", RuleName: "メモリ検知: 不審な実行メモリ領域", Severity: 7}
	jit := map[string]interface{}{
		"process_name": "powershell.exe", "rwx": true, "unbacked": true, "yara_matched": false,
	}
	if isCompromiseSignal(mem, jit) {
		t.Error("RWX+unbacked without a YARA hit must not be a compromise axis (.NET JIT looks exactly like this)")
	}
	// Same region, now content-confirmed: this IS shellcode-grade evidence.
	shellcode := map[string]interface{}{
		"process_name": "powershell.exe", "rwx": true, "unbacked": true, "yara_matched": true,
	}
	if !isCompromiseSignal(mem, shellcode) {
		t.Error("a YARA-confirmed memory region must remain a compromise axis")
	}
	// A missing/absent flat event must fail closed, not open.
	if isCompromiseSignal(mem, nil) {
		t.Error("memory axis must be refused when the event is unavailable")
	}
}

// The correlation must no longer drive unattended isolation: 27 false positives and
// zero confirmed true positives in four months of live operation.
func TestProcessThreatCorrelator_DoesNotAutoIsolate(t *testing.T) {
	p := newProcessThreatCorrelator()
	base := time.Unix(1_700_000_000, 0)
	p.Observe("a1", 4242, "implant.exe", procSigCompromise, base)
	m := p.Observe("a1", 4242, "implant.exe", procSigC2, base.Add(time.Minute))
	if len(m) != 1 {
		t.Fatalf("want the correlation to still fire, got %d", len(m))
	}
	if m[0].AutoIsolate {
		t.Error("this correlation must not auto-isolate until it has a demonstrated true positive")
	}
	if m[0].Severity != 10 {
		t.Errorf("severity = %d, want 10 (analyst priority is retained)", m[0].Severity)
	}
}

func TestCandidateActorPIDsAndEventPID(t *testing.T) {
	// JSON-style float64 values, plus source/target for an injection event.
	flat := map[string]interface{}{"pid": float64(10), "source_pid": float64(20), "target_pid": float64(30)}
	pids := candidateActorPIDs(flat)
	if len(pids) != 3 {
		t.Fatalf("want 3 candidate pids, got %v", pids)
	}
	if got := eventPID(flat); got.PID != 10 {
		t.Errorf("eventPID = %d, want 10", got.PID)
	}
	// Dedup + zero-skip.
	flat2 := map[string]interface{}{"pid": float64(5), "source_pid": float64(5), "target_pid": float64(0)}
	if got := candidateActorPIDs(flat2); len(got) != 1 || got[0].PID != 5 {
		t.Errorf("dedup/zero-skip failed: %v", got)
	}
}
