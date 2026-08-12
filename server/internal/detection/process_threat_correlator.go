// Package detection — process_threat_correlator.go: per-process compromise↔C2 correlation.
//
// The C2 correlator links network signals to each other by destination. This is its
// process-centric counterpart: it links the ENDPOINT-behavioral axis to the NETWORK axis
// by PID. A process that both (a) shows a compromise signal — code injection, process
// hollowing, YARA-confirmed memory, or credential access — AND (b) conducts C2 (beacon /
// known C2 JA3 / threat-intel / DNS C2) is a confirmed active implant, not two unrelated
// heuristics. That agreement on ONE process is among the strongest signals an EDR can
// produce, so it escalates to a critical (severity 10) alert.
//
// It does NOT auto-isolate. Live operation 2026-04..08 produced 27 of these and zero
// confirmed true positives; both the axis-quality fix (structural memory findings no
// longer qualify) and the identity fix (PID recycling) landed after that, so the path
// has to earn automatic response back with a demonstrated true positive first. See
// docs/死蔵経路の全数棚卸し_20260810.md §2-4.
package detection

import (
	"fmt"
	"strings"
	"sync"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

const (
	procThreatWindow  = 30 * time.Minute
	procThreatMaxKeys = 16384
)

type procThreatState struct {
	compromise int64 // last-seen unix of a compromise signal (0 = none)
	c2         int64 // last-seen unix of a C2 signal (0 = none)
	lastAlert  int64
	// Process identity observed on each axis, when the event carried one. The
	// correlation key is (agent, pid), but a PID is not a stable process identity
	// over the 30-minute window: Linux wraps pid_max (32768 by default) in minutes
	// on a busy host and Windows recycles aggressively. Without this, a compromise
	// signal on PID 4321 and a C2 signal from an unrelated process that later
	// reused PID 4321 would "agree", producing a severity-10 "active implant" alert
	// for two events that share nothing. Empty = the event did not name the
	// process (notably the target_pid of an injection, where only the injector is
	// named); those keep the old permissive behaviour rather than losing the
	// detection.
	compromiseName string
	c2Name         string
}

// procIdentity is a PID together with the image/process name the event attributed
// to it, when known.
type procIdentity struct {
	PID  int
	Name string
}

// sameProcessName reports whether two observed process identities refer to the same
// image. Compares the basename case-insensitively because the axes name a process
// differently: credential-access events carry a full path (`C:\Windows\System32\
// lsass.exe`) while network events carry a bare `lsass.exe`.
func sameProcessName(a, b string) bool {
	return strings.EqualFold(processBasename(a), processBasename(b))
}

// processBasename strips a Windows or POSIX directory prefix.
func processBasename(p string) string {
	if i := strings.LastIndexAny(p, `\/`); i >= 0 {
		return p[i+1:]
	}
	return p
}

// ProcessThreatCorrelator is a stateful, concurrency-safe per-(agent,pid) correlator.
type ProcessThreatCorrelator struct {
	mu    sync.Mutex
	procs map[string]*procThreatState
}

func newProcessThreatCorrelator() *ProcessThreatCorrelator {
	return &ProcessThreatCorrelator{procs: make(map[string]*procThreatState)}
}

// Process-signal classes.
const (
	procSigCompromise = "compromise"
	procSigC2         = "c2"
)

// isCompromiseSignal reports whether a match indicates the process is running attacker
// code or accessing credentials: injection (T1055*), a content-confirmed memory finding,
// credential access, or a process-hollowing ancestry hit.
//
// flat is the flattened event the match came from; it may be nil, in which case the
// memory axis is refused (see below) rather than assumed.
func isCompromiseSignal(m *detectionrules.RuleMatch, flat map[string]interface{}) bool {
	if m == nil {
		return false
	}
	// A memory finding counts as a compromise signal ONLY when its content was
	// confirmed by YARA.
	//
	// The memory scanner's other discriminators — RWX permissions and "unbacked"
	// (not file-backed) — are STRUCTURAL, and a managed runtime satisfies both by
	// design: .NET JITs into anonymous RWX pages, so every powershell.exe on the
	// estate produces the scanner's strongest class ("RWXかつ非バック実行領域",
	// severity 7). On the verification EC2 that turned a 6-hourly PowerShell
	// scheduled task into a severity-10 auto-isolating "active implant" alert every
	// six hours for a week (27 alerts, one host, a different PID each time), paired
	// with a DNS-tunnelling heuristic on the same PID. Only AUTO_RESPONSE_ENABLED=false
	// — set for an unrelated incident — kept it from isolating a production endpoint.
	//
	// This does NOT weaken memory detection: an RWX/unbacked region still raises its
	// own severity-6/7 alert exactly as before. It only refuses to let a structural
	// heuristic be one half of the product that drives automatic isolation, which
	// demands the axis actually distinguish shellcode from a JIT.
	if m.RuleType == "memory" {
		matched, _ := flat["yara_matched"].(bool)
		return matched
	}
	if m.RuleType == "credential_access" {
		return true
	}
	for _, tag := range m.MITRETags {
		u := strings.ToUpper(tag)
		if strings.HasPrefix(u, "T1055") || strings.HasPrefix(u, "T1003") {
			return true
		}
	}
	return strings.Contains(m.RuleName, "ハロウイング") || strings.Contains(m.RuleName, "Hollowing")
}

// Observe records a class signal for a process and returns a critical alert the first time
// a process has shown BOTH a compromise signal and a C2 signal within the window.
// name is the image/process name the event attributed to the PID, or "" when the
// event did not name it.
func (p *ProcessThreatCorrelator) Observe(agentID string, pid int, name, class string, now time.Time) []*detectionrules.RuleMatch {
	if agentID == "" || pid <= 0 || (class != procSigCompromise && class != procSigC2) {
		return nil
	}
	nu := now.Unix()
	winSec := int64(procThreatWindow / time.Second)
	key := fmt.Sprintf("%s|%d", agentID, pid)

	p.mu.Lock()
	defer p.mu.Unlock()

	if len(p.procs) > procThreatMaxKeys {
		p.evictStale(nu, winSec)
	}
	st := p.procs[key]
	if st == nil {
		st = &procThreatState{}
		p.procs[key] = st
	}
	// Expire a stale opposite-axis signal so old, unrelated activity does not correlate.
	if st.compromise != 0 && nu-st.compromise > winSec {
		st.compromise, st.compromiseName = 0, ""
	}
	if st.c2 != 0 && nu-st.c2 > winSec {
		st.c2, st.c2Name = 0, ""
	}
	switch class {
	case procSigCompromise:
		st.compromise, st.compromiseName = nu, name
	case procSigC2:
		st.c2, st.c2Name = nu, name
	}

	if st.compromise == 0 || st.c2 == 0 {
		return nil
	}
	// Both axes named a process and they disagree: the PID was recycled between the
	// two signals, so this is not one implant doing both things. Do NOT arm
	// lastAlert — a genuine correlation on this PID later must still be able to
	// fire.
	if st.compromiseName != "" && st.c2Name != "" && !sameProcessName(st.compromiseName, st.c2Name) {
		return nil
	}
	// Fire once per window (both axes present); re-arm only after the window lapses.
	if st.lastAlert != 0 && nu-st.lastAlert < winSec {
		return nil
	}
	st.lastAlert = nu

	return []*detectionrules.RuleMatch{{
		RuleID:   "",
		RuleName: "プロセス相関: 侵害シグナルとC2を併発する稼働中インプラント",
		RuleType: "correlation",
		Severity: 10,
		// AutoIsolate is deliberately NOT set. This correlator is the product of two
		// heuristics, and it produced 27 false positives and zero confirmed true
		// positives in four months of live operation (2026-04..08). Automatic
		// isolation is a business-stopping action; it should be re-enabled only once
		// this path has a demonstrated true positive. Severity 10 still routes it to
		// the top of the analyst queue and still feeds the kill-chain scorer, so no
		// detection is lost — only the unattended response.
		Title: fmt.Sprintf("[PROC-CORRELATION] 稼働中インプラントの疑い: PID %d が侵害挙動とC2を併発", pid),
		Description: fmt.Sprintf("PID %d が%d分以内に『侵害シグナル(注入/ハロウイング/メモリ異常/資格アクセス)』と『C2通信』の両方を示した。エンドポイント挙動軸とネットワーク軸がPIDで一致=能動的に稼働中のインプラントの確証。",
			pid, int(procThreatWindow/time.Minute)),
		MITRETags: []string{"T1055", "T1071"}, // Process Injection + C2
	}}
}

func (p *ProcessThreatCorrelator) evictStale(nowUnix, winSec int64) {
	for k, st := range p.procs {
		newest := st.compromise
		if st.c2 > newest {
			newest = st.c2
		}
		if nowUnix-newest > winSec {
			delete(p.procs, k)
		}
	}
}

// candidateActorPIDs returns the non-zero PIDs an event attributes activity to: the acting
// process (pid), plus source_pid/target_pid for injection/cred events, each paired with the
// image name that event names for it. Handles the numeric types a JSON round-trip produces.
//
// The name comes from the field that describes THAT pid, never from a neighbouring one:
// `process_name` describes `pid`, `source_image` describes `source_pid`, `target_image`
// describes `target_pid`. An injection event names the injector, not the injectee, so
// target_pid usually resolves to "" — deliberately, because attributing the injector's name
// to the target would make the later C2 signal from the target look like a different
// process and suppress the very correlation this detector exists for.
func candidateActorPIDs(flat map[string]interface{}) []procIdentity {
	nameFields := map[string][]string{
		"pid":        {"process_name"},
		"source_pid": {"source_image", "process_name"},
		"target_pid": {"target_image"},
	}
	out := make([]procIdentity, 0, 3)
	seen := map[int]bool{}
	for _, k := range []string{"pid", "source_pid", "target_pid"} {
		v, ok := toInt(flat[k])
		if !ok || v <= 0 || seen[v] {
			continue
		}
		seen[v] = true
		name := ""
		for _, nf := range nameFields[k] {
			if s, ok := flat[nf].(string); ok && s != "" {
				name = s
				break
			}
		}
		out = append(out, procIdentity{PID: v, Name: name})
	}
	return out
}

// eventPID returns the acting process (the connecting/executing one) for C2-axis
// attribution — just "pid", not the injection source/target.
func eventPID(flat map[string]interface{}) procIdentity {
	v, ok := toInt(flat["pid"])
	if !ok || v <= 0 {
		return procIdentity{}
	}
	name, _ := flat["process_name"].(string)
	return procIdentity{PID: v, Name: name}
}

// toInt coerces the numeric types (float64/int/int64/uint32/…) JSON and proto decoding
// produce into an int.
func toInt(v interface{}) (int, bool) {
	switch n := v.(type) {
	case int:
		return n, true
	case int64:
		return int(n), true
	case uint32:
		return int(n), true
	case uint64:
		return int(n), true
	case float64:
		return int(n), true
	}
	return 0, false
}
