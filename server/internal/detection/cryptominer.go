// Package detection — cryptominer.go: sustained-high-CPU resource-hijacking scorer.
//
// The agent's process-stats collector ships a full per-process CPU/memory
// snapshot every 30s ("process_stats:<uuid>:<json-array>" of {pid, name,
// cpu_pct, mem_mb}), but no detector consumed it — a whole telemetry source
// that was collected, promoted and stored yet never raised a finding.
//
// Cryptomining / resource hijacking (ATT&CK T1496) has a distinctive signature
// a single snapshot cannot separate from a benign compile or media encode: a
// process that pegs most of the machine's CPU *continuously*. This stateful
// scorer folds successive snapshots per host and raises a single suspected
// alert only when one PID sustains a high whole-system CPU share across several
// consecutive intervals — the "and it never lets up" property that betrays a
// miner. A one-off spike (build, backup, render) resets and never alerts.
package detection

import (
	"encoding/json"
	"fmt"
	"sync"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

const (
	// minerCPUThreshold is the whole-system CPU share (cpu_pct is 0–100, capped,
	// measured against total system jiffies) at or above which a single process is
	// considered to be hogging the machine. Set high: a miner pins the CPU near
	// saturation, whereas ordinary interactive load rarely holds one process this
	// high for long.
	minerCPUThreshold = 80.0
	// minerSustainCount is the number of CONSECUTIVE snapshots (the collector emits
	// one every 30s, so this is ~90s) a PID must stay above the threshold before it
	// alerts. This is the false-positive guard: bursty heavy work (compile, backup,
	// video encode) dips between snapshots and resets; a miner does not.
	minerSustainCount = 3
	// minerMaxKeys bounds the per-agent state map.
	minerMaxKeys = 8192
)

// minerState tracks, for one host, each still-hot PID's consecutive-high-CPU
// streak and whether it has already alerted (so a sustained miner fires once,
// not every snapshot).
type minerState struct {
	streak   map[int]int    // pid -> consecutive snapshots at/above threshold
	name     map[int]string // pid -> last-seen process name
	alerted  map[int]bool   // pid -> already alerted this hot streak
	lastSeen int64          // unix seconds of the last snapshot (for eviction)
}

// CryptoMinerScorer is a stateful, concurrency-safe resource-hijacking detector.
type CryptoMinerScorer struct {
	mu     sync.Mutex
	agents map[string]*minerState
}

func newCryptoMinerScorer() *CryptoMinerScorer {
	return &CryptoMinerScorer{agents: make(map[string]*minerState)}
}

// procStatSample is the server-side shape of one entry in the agent's
// process_stats snapshot array.
type procStatSample struct {
	PID    int     `json:"pid"`
	Name   string  `json:"name"`
	CPUPct float64 `json:"cpu_pct"`
	MemMB  float64 `json:"mem_mb"`
}

// Observe folds one process_stats snapshot (the raw JSON array the agent emits)
// into the host's per-PID CPU streaks and returns a T1496 finding for each PID
// that has just crossed minerSustainCount consecutive high-CPU snapshots. now is
// injected for deterministic tests.
func (c *CryptoMinerScorer) Observe(agentID string, snapshot []byte, now time.Time) []*detectionrules.RuleMatch {
	if agentID == "" || len(snapshot) == 0 {
		return nil
	}
	var samples []procStatSample
	if err := json.Unmarshal(snapshot, &samples); err != nil || len(samples) == 0 {
		return nil
	}
	nu := now.Unix()

	c.mu.Lock()
	defer c.mu.Unlock()

	if len(c.agents) > minerMaxKeys {
		c.evictStale(nu, int64(2*minerSustainCount)*60)
	}
	st := c.agents[agentID]
	if st == nil {
		st = &minerState{
			streak:  make(map[int]int),
			name:    make(map[int]string),
			alerted: make(map[int]bool),
		}
		c.agents[agentID] = st
	}
	st.lastSeen = nu

	var matches []*detectionrules.RuleMatch
	present := make(map[int]bool, len(samples))
	for _, s := range samples {
		present[s.PID] = true
		if s.CPUPct < minerCPUThreshold {
			// Dropped below the bar — reset so a genuine one-off spike doesn't
			// accumulate across unrelated busy moments, and so a later true streak
			// can alert again.
			st.streak[s.PID] = 0
			st.alerted[s.PID] = false
			continue
		}
		st.streak[s.PID]++
		st.name[s.PID] = s.Name
		if st.streak[s.PID] >= minerSustainCount && !st.alerted[s.PID] {
			st.alerted[s.PID] = true
			name := s.Name
			if name == "" {
				name = "不明"
			}
			matches = append(matches, &detectionrules.RuleMatch{
				RuleID:   "",
				RuleName: "リソース占有: 暗号通貨採掘の疑い",
				RuleType: "cryptomining",
				Severity: 5,
				Title:    "[MINER] 持続的な高CPU占有プロセス（暗号採掘の疑い）: " + name,
				Description: fmt.Sprintf("プロセス %s (pid=%d) が %d回連続のスナップショット(約%d秒)でCPUを%.0f%%以上占有し続けています。暗号通貨採掘によるリソース・ハイジャック(T1496)の疑い。",
					name, s.PID, st.streak[s.PID], minerSustainCount*30, s.CPUPct),
				MITRETags: []string{"T1496"}, // Resource Hijacking
			})
		}
	}

	// Forget PIDs absent from this snapshot (process exited or reused): clear their
	// streaks so the maps don't grow without bound and a recycled PID starts fresh.
	for pid := range st.streak {
		if !present[pid] {
			delete(st.streak, pid)
			delete(st.name, pid)
			delete(st.alerted, pid)
		}
	}

	return matches
}

func (c *CryptoMinerScorer) evictStale(nowUnix, maxAgeSec int64) {
	for agentID, st := range c.agents {
		if nowUnix-st.lastSeen > maxAgeSec {
			delete(c.agents, agentID)
		}
	}
}
