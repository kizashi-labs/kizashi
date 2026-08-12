// Package rules — c2_fusion.go
//
// C2FusionScorer fuses independent weak network signals at the (agent, destination)
// level into a single, higher-confidence C2 verdict. It implements **Phase 1** of
// docs/design/ネットワークC2振る舞い検知の多信号フュージョン設計.md, which uses ONLY
// signals already present in the live event stream (no new agent telemetry):
//
//	S1 — periodicity  (BeaconDetector, harmonic-folded beacon cadence)
//	S2 — reputation   (agent threat-intel match on the destination)
//
// Rationale: the periodicity detector alone fires medium-severity for ANY regular
// outbound cadence — including legitimate heartbeats — which is the main false-positive
// pain. A periodic beacon whose destination is ALSO known-malicious is high-confidence
// C2, so it escalates to critical. Periodicity alone is unchanged (medium), so this is a
// strict superset of prior behaviour — no regression. Later phases add S3 (JA3), S4
// (DGA/DNS entropy), S5 (destination novelty) and S6 (raw-IP/no-DNS).
package rules

import (
	"fmt"
	"strings"
	"sync"
)

// TISignal is the destination-reputation signal (S2): whether the agent's threat-intel
// matcher flagged this destination, and the matching category/source for the alert text.
type TISignal struct {
	Matched  bool
	Category string
	Source   string
}

// c2FusionMaxKeys bounds the per-destination TI memory so a churny fleet cannot grow it
// without limit. When exceeded the map is reset (the TI verdict re-populates on the next
// connection to any still-active destination).
const c2FusionMaxKeys = 100000

// rareAgentThreshold: a destination contacted by at most this many distinct agents across
// the fleet is treated as "rare" (S5). Real C2 infrastructure is typically reached by one
// or a few compromised hosts, whereas legitimate services (updates, SaaS) fan out widely.
const rareAgentThreshold = 2

// C2FusionScorer accumulates per-destination signals and fuses them with a fired
// periodicity beacon. Phases:
//
//	Ph1 — S2 (TI reputation)
//	Ph2 — S5 (fleet rarity of the destination) + S6 (raw-IP / no prior DNS resolution)
//	Ph3 — S4 (destination resolved from a DGA-like domain)
//
// All use signals already on the live event stream; no new agent telemetry.
type C2FusionScorer struct {
	mu        sync.Mutex
	tiSeen    map[string]TISignal            // agentID|dstIP → TI verdict (S2)
	dstAgents map[string]map[string]struct{} // dstIP → set of agentIDs seen (S5 rarity)
	resolved  map[string]struct{}            // agentID|dstIP → dst was a DNS answer (S6: not raw)
	agentDNS  map[string]struct{}            // agentID → has any DNS answer (S6 guard: only conclude raw when DNS telemetry exists)
	dgaIP     map[string]struct{}            // agentID|dstIP → dst resolved from a DGA-like domain (S4)
}

// NewC2FusionScorer creates an empty fusion scorer.
func NewC2FusionScorer() *C2FusionScorer {
	return &C2FusionScorer{
		tiSeen:    make(map[string]TISignal),
		dstAgents: make(map[string]map[string]struct{}),
		resolved:  make(map[string]struct{}),
		agentDNS:  make(map[string]struct{}),
		dgaIP:     make(map[string]struct{}),
	}
}

// ObserveNetwork records that agentID contacted dstIP, maintaining the per-destination
// distinct-agent set used for the rarity signal (S5). Bounded like the other maps.
func (s *C2FusionScorer) ObserveNetwork(agentID, dstIP string) {
	if dstIP == "" {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.dstAgents) >= c2FusionMaxKeys {
		s.dstAgents = make(map[string]map[string]struct{})
	}
	set := s.dstAgents[dstIP]
	if set == nil {
		set = make(map[string]struct{}, 1)
		s.dstAgents[dstIP] = set
	}
	// Cap the per-destination agent set; once it is clearly non-rare we stop growing it.
	if len(set) <= rareAgentThreshold+1 {
		set[agentID] = struct{}{}
	}
}

// ObserveDNS records a DNS resolution: every answer IP is marked as DNS-resolved for the
// agent (so a later beacon to it is NOT a raw-IP connection, S6). If the query was judged
// DGA-like (dgaSuspicious), those answer IPs are additionally marked DGA-associated (S4).
// The DGA verdict is computed by the caller (detection.AnalyzeDGA) to avoid an import cycle.
func (s *C2FusionScorer) ObserveDNS(agentID string, answers []string, dgaSuspicious bool) {
	if agentID == "" || len(answers) == 0 {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.resolved) >= c2FusionMaxKeys {
		s.resolved = make(map[string]struct{})
		s.dgaIP = make(map[string]struct{})
	}
	s.agentDNS[agentID] = struct{}{}
	for _, ip := range answers {
		if ip == "" {
			continue
		}
		key := agentID + "|" + ip
		s.resolved[key] = struct{}{}
		if dgaSuspicious {
			s.dgaIP[key] = struct{}{}
		}
	}
}

// ObserveTI records the destination-reputation verdict for a connection. It is called on
// every network event so the scorer remembers whether a destination was EVER TI-matched,
// independent of which specific connection later triggers the beacon (the beacon fires on
// the Nth event, which may not itself carry the TI flag). Only positive matches are stored.
func (s *C2FusionScorer) ObserveTI(agentID, dstIP string, ti TISignal) {
	if dstIP == "" || !ti.Matched {
		return
	}
	s.mu.Lock()
	if len(s.tiSeen) >= c2FusionMaxKeys {
		s.tiSeen = make(map[string]TISignal)
	}
	s.tiSeen[agentID+"|"+dstIP] = ti
	s.mu.Unlock()
}

// Fuse combines a fired beacon match (S1) with the accumulated destination signals and
// returns the alert to emit, escalating severity by how many independent C2 indicators
// concur on the destination:
//   - S2 (known-malicious TI)                         → critical(9), single signal suffices
//   - S4 (resolved from a DGA-like domain)            → high(8)
//   - S5 (fleet-rare destination) AND S6 (raw IP)     → high(8), new infra reached without DNS
//   - otherwise (periodicity alone / a single weak    → medium(7), unchanged from Ph0
//     signal)
//
// Periodicity alone stays medium, so this remains a strict superset of the pre-fusion
// behaviour (no regression).
func (s *C2FusionScorer) Fuse(bm *BeaconMatch) *RuleMatch {
	if bm == nil {
		return nil
	}
	base := bm.ToRuleMatch()
	key := bm.AgentID + "|" + bm.DstIP

	s.mu.Lock()
	ti, tiOK := s.tiSeen[key]
	s2 := tiOK && ti.Matched
	_, s4 := s.dgaIP[key]
	agents := len(s.dstAgents[bm.DstIP])
	_, agentHasDNS := s.agentDNS[bm.AgentID]
	_, dstResolved := s.resolved[key]
	s.mu.Unlock()

	s5 := agents > 0 && agents <= rareAgentThreshold // fleet-rare destination
	s6 := agentHasDNS && !dstResolved                // agent uses DNS but reached this IP raw

	// S2 confirmed → critical, regardless of the weaker signals.
	if s2 {
		base.Severity = 9
		base.Title = "[BEHAVIORAL] C2ビーコン確度高（周期通信＋既知の悪性インフラ）"
		base.Description = fmt.Sprintf(
			"%s。宛先は脅威インテリで既知の悪性インフラと一致（category: %s, source: %s）。周期性(S1)＋レピュテーション(S2)一致でC2確度高。",
			base.Description, tiOrUnknown(ti.Category), tiOrUnknown(ti.Source),
		)
		return base
	}

	// Weaker-signal fusion → high when a strong indicator concurs with periodicity.
	signals := []string{}
	if s4 {
		signals = append(signals, "DGA由来ドメイン(S4)")
	}
	if s5 {
		signals = append(signals, "宛先の希少性(S5)")
	}
	if s6 {
		signals = append(signals, "DNS解決を経ない生IP直結(S6)")
	}
	escalate := s4 || (s5 && s6) // DGA alone, or rare+raw-IP together
	if !escalate {
		return base // periodicity alone or a single weak signal → unchanged medium
	}
	base.Severity = 8
	base.Title = "[BEHAVIORAL] C2ビーコン確度中（周期通信＋C2的振る舞い）"
	base.Description = fmt.Sprintf(
		"%s。周期性(S1)に加え %s が一致（複数信号でC2の疑いを強化）。",
		base.Description, strings.Join(signals, "・"),
	)
	return base
}

func tiOrUnknown(s string) string {
	if s == "" {
		return "unknown"
	}
	return s
}

// tiSignalFromEvent extracts the destination-reputation signal (S2) from a flattened
// network event. These fields are set upstream by the agent's threat-intel matcher and
// travel on the same event the RuleEngine evaluates.
func tiSignalFromEvent(flatMap map[string]interface{}) TISignal {
	matched, _ := flatMap["threat_intel_matched"].(bool)
	if !matched {
		return TISignal{}
	}
	cat, _ := flatMap["threat_intel_category"].(string)
	src, _ := flatMap["threat_intel_source"].(string)
	return TISignal{Matched: true, Category: cat, Source: src}
}
