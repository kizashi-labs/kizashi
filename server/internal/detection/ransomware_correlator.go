// Package detection — ransomware_correlator.go: composite ransomware-precursor scoring.
//
// Individual ransomware-precursor Sigma rules (shadow-copy/backup deletion, AV/backup
// service tampering, broad ACL grants for encryption staging) each fire independently at
// high/critical level, but a REAL pre-encryption sequence combines several of them on one
// host within minutes — an operator stops Defender/the backup agent, THEN deletes shadow
// copies, often followed by ACL changes to make files attacker-writable. Legitimate admin
// activity essentially never combines two or more of these axes in a short window. This
// stateful, host-keyed correlator watches for that composite pattern and escalates
// BEFORE mass encryption completes — the highest-value moment an EDR can intervene in a
// ransomware intrusion.
//
// Two axes alert (severity 9). Unattended isolation requires three or more distinct axes
// AND at least one specific axis (recovery inhibition or defense tampering), because the
// other two — broad ACL grants and mass file modification — are noisy on real hosts; see
// isStrongRansomAxis for the measurement and docs/死蔵経路の全数棚卸し_20260810.md §7.
//
// Mirrors C2Correlator (windowed, bounded-key, injectable clock, multi-signal escalation)
// but keyed by agentID alone: ransomware precursors are host-scoped, not tied to one
// process or network destination the way C2/compromise signals are.
package detection

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

const (
	// ransomWindow is the sliding window over which distinct ransomware-precursor
	// signal classes are counted on one host. Narrower than the C2/kill-chain windows
	// because a real pre-encryption sequence unfolds in minutes, not hours.
	ransomWindow     = 15 * time.Minute
	ransomMinSignals = 2
	ransomMaxKeys    = 8192
	// ransomIsolateFrom is the distinct-axis count at which the composite escalates
	// from "alert an analyst" to "take the host off the network", mirroring
	// C2Correlator's c2IsolateFrom. Two axes are NOT enough, because two of the four
	// are empirically noisy on real hosts (see isStrongRansomAxis).
	ransomIsolateFrom = 3
)

// isStrongRansomAxis reports whether an axis is specific enough that its presence is
// evidence of an intrusion rather than of ordinary activity.
//
// Measured on the verification EC2 over 30 days (2026-07-11..08-10):
//
//	mass_modify      129   ← noisy: mostly "ホスト全体(プロセス特定不可)" bursts
//	acl_stage         67   ← noisy: entirely Linux chmod rules ("Chmod Targeting
//	                          Sensitive Directories", "Suspicious chmod of Executable
//	                          in /tmp", "Linux Overly Permissive chmod") on ONE host
//	recovery_inhibit  14   ← specific: shadow-copy / backup deletion
//	defense_tamper     0   ← specific: AV/EDR/backup service stop
//
// The file header asserts "legitimate admin activity essentially never combines two
// or more of these axes in a short window". The data does not support that for the
// two noisy axes: routine chmod plus a benign build/backup burst is exactly a
// two-axis co-occurrence, and two such 15-minute windows appeared in those 30 days.
// So a two-axis composite still alerts (severity 9) but must not isolate on its own.
func isStrongRansomAxis(sig string) bool {
	return sig == ransomSigRecoveryInhibit || sig == ransomSigDefenseTamper
}

// Ransomware precursor signal classes — the orthogonal axes we correlate.
const (
	ransomSigRecoveryInhibit = "recovery_inhibit" // T1490: shadow copy / backup catalog / free-space wipe
	ransomSigDefenseTamper   = "defense_tamper"   // T1489: AV/EDR/backup service stop or disable
	ransomSigACLStage        = "acl_stage"        // T1222: broad permission grant (encryption staging)
	// ransomSigMassModify (T1486) is the encryption itself rather than a precursor,
	// fed in from FileBurstScorer. It is here because the burst rate alone is not
	// specific — benign builds and backups trip it (38 hits in a fully benign FP
	// soak) — so it must never isolate a host by itself. Correlated with any of the
	// three precursor axes above it becomes decisive: legitimate bulk file work does
	// not also stop the AV service or delete shadow copies. This is the axis that
	// separates "a build is running" from "encryption has started".
	ransomSigMassModify = "mass_modify" // T1486: destructive mass file-operation burst
)

var ransomSignalLabels = map[string]string{
	ransomSigRecoveryInhibit: "復旧妨害(シャドウコピー/バックアップ削除)",
	ransomSigDefenseTamper:   "防御/バックアップサービス改ざん",
	ransomSigACLStage:        "広範囲ACL付与(暗号化準備)",
	ransomSigMassModify:      "ファイル大量破壊的操作(暗号化フェーズ)",
}

// classifyRansomwareSignal maps a RuleMatch to a ransomware-precursor signal class, or ""
// if it is not one of the correlated axes. Keyed on the MITRE technique the underlying
// Sigma rule tags itself with (attack.t1490 / attack.t1489 / attack.t1222.001) rather than
// rule-name substrings, since these builtin rules carry stable, English titles.
func classifyRansomwareSignal(m *detectionrules.RuleMatch) string {
	if m == nil {
		return ""
	}
	for _, tag := range m.MITRETags {
		u := strings.ToUpper(strings.TrimSpace(tag))
		switch {
		case strings.HasPrefix(u, "T1490"):
			return ransomSigRecoveryInhibit
		case strings.HasPrefix(u, "T1489"):
			return ransomSigDefenseTamper
		case strings.HasPrefix(u, "T1222"):
			return ransomSigACLStage
		}
	}
	return ""
}

type ransomState struct {
	signals    map[string]int64 // signal class -> last-seen unix seconds
	lastAlertN int              // distinct-signal count at the last alert (for escalation)
}

// RansomwareCorrelator is a stateful, concurrency-safe multi-signal ransomware-precursor
// correlator keyed by agentID (host-wide).
type RansomwareCorrelator struct {
	mu   sync.Mutex
	host map[string]*ransomState
}

func newRansomwareCorrelator() *RansomwareCorrelator {
	return &RansomwareCorrelator{host: make(map[string]*ransomState)}
}

// Observe records that agentID showed signalClass and returns a composite ransomware
// alert the first time the host has shown ≥ransomMinSignals distinct precursor classes
// within the window, escalating further as more axes confirm. now is injected for
// deterministic tests. Empty inputs or an unknown signal class are ignored.
func (r *RansomwareCorrelator) Observe(agentID, signalClass string, now time.Time) []*detectionrules.RuleMatch {
	if agentID == "" || signalClass == "" {
		return nil
	}
	if _, ok := ransomSignalLabels[signalClass]; !ok {
		return nil
	}
	nu := now.Unix()
	winSec := int64(ransomWindow / time.Second)

	r.mu.Lock()
	defer r.mu.Unlock()

	if len(r.host) > ransomMaxKeys {
		r.evictStale(nu, winSec*2)
	}
	st := r.host[agentID]
	if st == nil {
		st = &ransomState{signals: make(map[string]int64)}
		r.host[agentID] = st
	}
	// Expire signals outside the window.
	for sig, ts := range st.signals {
		if nu-ts > winSec {
			delete(st.signals, sig)
		}
	}
	st.signals[signalClass] = nu

	n := len(st.signals)
	if n < ransomMinSignals {
		st.lastAlertN = 0
		return nil
	}
	// Fire on first crossing and escalate as more distinct axes confirm.
	if n <= st.lastAlertN {
		return nil
	}
	st.lastAlertN = n

	sigs := make([]string, 0, len(st.signals))
	strong := false
	for sig := range st.signals {
		sigs = append(sigs, ransomSignalLabels[sig])
		if isStrongRansomAxis(sig) {
			strong = true
		}
	}
	sort.Strings(sigs)

	// Unattended isolation needs BOTH breadth and specificity: enough distinct axes
	// that coincidence is implausible, AND at least one axis that ordinary activity
	// does not produce. chmod + a file burst satisfies neither test on its own.
	sev := 9
	autoIsolate := false
	if n >= ransomIsolateFrom && strong {
		sev = 10
		autoIsolate = true
	}

	return []*detectionrules.RuleMatch{{
		RuleID:      "",
		RuleName:    "ランサムウェア相関: 複合前兆シグナルによる暗号化直前の疑い",
		RuleType:    "correlation",
		Severity:    sev,
		AutoIsolate: autoIsolate,
		Title:       fmt.Sprintf("[RANSOMWARE-CORRELATION] 暗号化直前の疑い: %d系統の前兆シグナルを併発", n),
		Description: fmt.Sprintf("ホストが%d分以内に%d個の独立したランサムウェア前兆シグナルで該当: %s。正規の管理作業がこれらを短時間に併発することは通常なく、大規模暗号化が始まる前の高信頼な介入機会。",
			int(ransomWindow/time.Minute), n, strings.Join(sigs, " + ")),
		MITRETags: []string{"T1486", "T1490"}, // Data Encrypted for Impact + Inhibit System Recovery
	}}
}

func (r *RansomwareCorrelator) evictStale(nowUnix, maxAgeSec int64) {
	for key, st := range r.host {
		var newest int64
		for _, ts := range st.signals {
			if ts > newest {
				newest = ts
			}
		}
		if nowUnix-newest > maxAgeSec {
			delete(r.host, key)
		}
	}
}
