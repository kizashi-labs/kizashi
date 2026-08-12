package detection

import (
	"encoding/json"
	"testing"
	"time"
)

// snap builds a process_stats snapshot payload (the raw JSON array the agent
// emits) from (pid,name,cpu) triples.
func snap(entries ...procStatSample) []byte {
	b, _ := json.Marshal(entries)
	return b
}

func TestCryptoMinerScorer_FiresOnSustainedHighCPU(t *testing.T) {
	c := newCryptoMinerScorer()
	base := time.Unix(1_700_000_000, 0)
	miner := procStatSample{PID: 4242, Name: "xmrig", CPUPct: 97, MemMB: 120}

	var fired int
	for i := 0; i < minerSustainCount; i++ {
		m := c.Observe("agent1", snap(miner), base.Add(time.Duration(i)*30*time.Second))
		fired += len(m)
		if i < minerSustainCount-1 && len(m) > 0 {
			t.Fatalf("fired early at snapshot %d (need %d consecutive)", i+1, minerSustainCount)
		}
		if i == minerSustainCount-1 {
			if len(m) != 1 {
				t.Fatalf("expected exactly 1 alert at the %dth consecutive snapshot, got %d", minerSustainCount, len(m))
			}
			if m[0].RuleType != "cryptomining" || len(m[0].MITRETags) == 0 || m[0].MITRETags[0] != "T1496" {
				t.Errorf("unexpected match shape: type=%q tags=%v", m[0].RuleType, m[0].MITRETags)
			}
			if m[0].RuleID != "" {
				t.Errorf("RuleID must be empty (uuid-typed alerts.rule_id), got %q", m[0].RuleID)
			}
		}
	}
	if fired != 1 {
		t.Fatalf("expected 1 total alert across the streak, got %d", fired)
	}

	// A sustained miner alerts ONCE, not on every subsequent snapshot.
	if m := c.Observe("agent1", snap(miner), base.Add(10*30*time.Second)); len(m) != 0 {
		t.Fatalf("re-fired on a continuing streak (should dedup), got %d", len(m))
	}
}

func TestCryptoMinerScorer_NoFireOnBurstOrLowCPU(t *testing.T) {
	c := newCryptoMinerScorer()
	base := time.Unix(1_700_000_000, 0)

	// A one-off spike that dips back down must never accumulate to an alert.
	seq := []float64{95, 10, 92, 20, 96}
	for i, cpu := range seq {
		m := c.Observe("agent1", snap(procStatSample{PID: 10, Name: "gcc", CPUPct: cpu}),
			base.Add(time.Duration(i)*30*time.Second))
		if len(m) > 0 {
			t.Fatalf("bursty high-CPU should not alert (snapshot %d, cpu=%.0f)", i, cpu)
		}
	}

	// A steadily busy-but-not-pegged process stays under the bar forever.
	for i := 0; i < 6; i++ {
		m := c.Observe("agent2", snap(procStatSample{PID: 11, Name: "chrome", CPUPct: 60}),
			base.Add(time.Duration(i)*30*time.Second))
		if len(m) > 0 {
			t.Fatalf("sub-threshold CPU should never alert (snapshot %d)", i)
		}
	}
}

func TestCryptoMinerScorer_ResetsWhenProcessLeaves(t *testing.T) {
	c := newCryptoMinerScorer()
	base := time.Unix(1_700_000_000, 0)
	miner := procStatSample{PID: 7, Name: "kdevtmpfsi", CPUPct: 99}

	// Two hot snapshots (one short of the bar), then the PID disappears.
	c.Observe("agent1", snap(miner), base)
	c.Observe("agent1", snap(miner), base.Add(30*time.Second))
	c.Observe("agent1", snap(procStatSample{PID: 99, Name: "bash", CPUPct: 1}), base.Add(60*time.Second))

	// The same PID returning hot must start its streak over, not resume at 2.
	if m := c.Observe("agent1", snap(miner), base.Add(90*time.Second)); len(m) != 0 {
		t.Fatalf("streak should reset after the PID left the snapshot, but it alerted")
	}
}
