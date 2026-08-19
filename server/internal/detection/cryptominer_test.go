package detection

import (
	"bytes"
	"encoding/json"
	"testing"
	"time"
)

// mem は測れたメモリ量を *float64 にします。**エージェントは測れなかった
// メモリを送りません** —— `mem_mb` の欠落が「測っていない」の表現です。
func mem(v float64) *float64 { return &v }

// snap builds a process_stats snapshot payload (the raw JSON array the agent
// emits) from (pid,name,cpu) triples.
func snap(entries ...procStatSample) []byte {
	b, _ := json.Marshal(entries)
	return b
}

func TestCryptoMinerScorer_FiresOnSustainedHighCPU(t *testing.T) {
	c := newCryptoMinerScorer()
	base := time.Unix(1_700_000_000, 0)
	miner := procStatSample{PID: 4242, Name: "xmrig", CPUPct: 97, MemMB: mem(120)}

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

// メモリを測れなかった行も、CPU で採点されること。
//
// エージェントは、常駐メモリを読めなかった／ユーザ空間を持たない
// タスクの `mem_mb` を送りません。**その行が落ちると、この検知器
// (T1496) はそのプロセスを一度も見ません。**
//
// 実測（agent 側、2026-08-11 のコンテナ）: /proc の PID 75 件のうち
// snapshot に載っていたのは 8 件でした。残り 67 件は「VmRSS 行が無い」
// —— カーネルスレッドで、**CPU は普通に回っています。**
func TestCryptoMinerScorer_ScoresSamplesWithNoMemoryReading(t *testing.T) {
	c := newCryptoMinerScorer()
	base := time.Unix(1_700_000_000, 0)
	// mem_mb を持たない行。JSON にも出ません。
	miner := procStatSample{PID: 99, Name: "[kworker/u8:3]", CPUPct: 97}

	payload := snap(miner)
	if bytes.Contains(payload, []byte("mem_mb")) {
		t.Fatalf("mem_mb が出ています: %s。**欠落が「測っていない」の表現です**", payload)
	}

	var fired int
	for i := 0; i < minerSustainCount; i++ {
		fired += len(c.Observe("agent1", payload, base.Add(time.Duration(i)*30*time.Second)))
	}
	if fired != 1 {
		t.Fatalf("メモリを測れなかったプロセスが採点されていません (fired=%d)", fired)
	}
}

// 欠けた mem_mb が 0.0 に化けないこと。
//
// **float64 のままだと、欠落と「常駐 0 MB」が同じ姿になります。**
func TestAnAbsentMemMBStaysAbsent(t *testing.T) {
	var got []procStatSample
	if err := json.Unmarshal([]byte(`[{"pid":1,"name":"x","cpu_pct":5}]`), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d samples", len(got))
	}
	if got[0].MemMB != nil {
		t.Errorf("MemMB = %v, want nil", *got[0].MemMB)
	}

	// 送られてきた 0 は、測定値としてそのまま残ること。
	if err := json.Unmarshal([]byte(`[{"pid":1,"name":"x","cpu_pct":5,"mem_mb":0}]`), &got); err != nil {
		t.Fatal(err)
	}
	if got[0].MemMB == nil || *got[0].MemMB != 0 {
		t.Errorf("明示的な 0 が %v になっています", got[0].MemMB)
	}
}
