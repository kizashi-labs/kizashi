package detection

import (
	"context"
	"strings"
	"testing"
	"time"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

// captureStore is a minimal in-memory DetectionStore that records saved alerts,
// so a test can drive the real Engine.processEventData end-to-end without a DB or
// NATS and assert which detectors actually fired.
type captureStore struct{ saved []*StoredAlert }

func (c *captureStore) SaveAlert(_ context.Context, a *StoredAlert) error {
	c.saved = append(c.saved, a)
	return nil
}
func (c *captureStore) UpdateAlert(_ context.Context, _ string, _ AlertUpdate) error     { return nil }
func (c *captureStore) GetAlert(_ context.Context, _ string) (*StoredAlert, error)       { return nil, nil }
func (c *captureStore) SaveResponseAction(_ context.Context, _ *ResponseActionLog) error { return nil }
func (c *captureStore) GetRecentEvents(_ string, _ int) ([]EventSummary, error)          { return nil, nil }
func (c *captureStore) GetAlertHistory(_ string, _ int) ([]AlertSummary, error)          { return nil, nil }

// newTestEngine builds an Engine wired with ONLY the runtime stateful detectors +
// a capture store — no DB, NATS, IOC, behavioral, suppression, notifier. It is
// the seam for exercising processEventData's real event→detector field wiring.
func newTestEngine() (*Engine, *captureStore) {
	cs := &captureStore{}
	return &Engine{
		store:         cs,
		rules:         detectionrules.NewRuleEngine(), // empty; typedFindings/scorers do the work
		parents:       newParentResolver(),
		netScan:       newNetworkScanDetector(),
		dnsAgg:        newDNSTunnelAggregator(),
		killChain:     newKillChainScorer(),
		discovery:     newDiscoveryScorer(),
		authAttack:    newAuthAttackScorer(),
		fileBurst:     newFileBurstScorer(),
		lateralFanout: newLateralFanoutScorer(),
		exfilVol:      newExfilVolumeDetector(),
		alertDedup:    make(map[string]time.Time),
		// AIAnalysisMinSeverity high + AutoResponse off so no AI/commander/nats paths run.
		config: EngineConfig{AutoResponseEnabled: false, AIAnalysisMinSeverity: 100},
	}, cs
}

// feed drives one synthetic NormalizedEvent (exact agent/ingestion wire form) through
// the real detection path. eventType and the inner data keys mirror
// ingestion/handler.go so the test exercises the SAME field names production uses.
func feedEvent(t *testing.T, e *Engine, agentID, platform, etype, dataJSON string) {
	t.Helper()
	env := `{"agent_id":"` + agentID + `","hostname":"e2e","platform":"` + platform + `","type":"` + etype + `","data":` + dataJSON + `}`
	if err := e.processEventData(context.Background(), []byte(env)); err != nil {
		t.Fatalf("processEventData(%s): %v", etype, err)
	}
}

func firedTech(cs *captureStore, tech string) bool {
	for _, a := range cs.saved {
		if a.MITRETech == tech {
			return true
		}
		for _, tg := range a.MITRETags {
			if tg == tech {
				return true
			}
		}
	}
	return false
}

func firedTitleHas(cs *captureStore, sub string) bool {
	for _, a := range cs.saved {
		if strings.Contains(a.Title, sub) {
			return true
		}
	}
	return false
}

// TestRuntimeDetectorsFireThroughEngine is the live-fire regression gate for the
// runtime stateful detectors. It drives processEventData with events shaped
// EXACTLY as ingestion emits (file action under the "operation" key, network
// "bytes_sent", auth "success"/"source_ip", …) and asserts each detector produces
// an alert. This is the gate that would have caught the ⑩ reachability bug
// (fileBurst read "action" but ingestion emits "operation" → inert in production):
// a pure scorer unit test cannot, because the break was in the engine's field
// wiring, not the scorer.
func TestRuntimeDetectorsFireThroughEngine(t *testing.T) {
	const agent = "11111111-1111-1111-1111-111111111111"

	t.Run("ransomware_file_burst_T1486_via_operation_key", func(t *testing.T) {
		e, cs := newTestEngine()
		// Real ingestion form: file action under "operation" as FILE_ACTION_MODIFY.
		for i := 0; i < fileBurstMinFiles+2; i++ {
			data := `{"process_name":"cryptor.exe","path":"C:\\v\\f` + itoa(i) + `.docx","operation":"FILE_ACTION_MODIFY"}`
			feedEvent(t, e, agent, "windows", "file", data)
		}
		if !firedTech(cs, "T1486") {
			t.Fatal("file-burst detector did not fire on ingestion-shaped file events (operation key) — reachability regression")
		}
	})

	t.Run("brute_force_T1110", func(t *testing.T) {
		e, cs := newTestEngine()
		for i := 0; i < bruteMinFails+1; i++ {
			feedEvent(t, e, agent, "windows", "auth", `{"username":"administrator","source_ip":"203.0.113.7","success":false,"action":"failed"}`)
		}
		if !firedTech(cs, "T1110") {
			t.Fatal("brute-force detector did not fire through the engine")
		}
	})

	t.Run("password_spray_T1110.003", func(t *testing.T) {
		e, cs := newTestEngine()
		for i := 0; i < sprayMinAccounts+1; i++ {
			data := `{"username":"user` + itoa(i) + `","source_ip":"203.0.113.9","success":false,"action":"failed"}`
			feedEvent(t, e, agent, "windows", "auth", data)
		}
		if !firedTech(cs, "T1110.003") {
			t.Fatal("password-spray detector did not fire through the engine")
		}
	})

	t.Run("lateral_fanout_T1021", func(t *testing.T) {
		e, cs := newTestEngine()
		for i := 0; i < lateralMinHosts+1; i++ {
			data := `{"direction":"outbound","dst_ip":"10.0.0.` + itoa(i+1) + `","dst_port":445,"protocol":"tcp","process_name":"psexec.exe"}`
			feedEvent(t, e, agent, "windows", "network", data)
		}
		if !firedTech(cs, "T1021") {
			t.Fatal("lateral-fanout detector did not fire through the engine")
		}
	})

	t.Run("exfil_volume_T1048_via_bytes_sent", func(t *testing.T) {
		e, cs := newTestEngine()
		chunk := 60 << 20         // 60 MiB
		for i := 0; i < 10; i++ { // 600 MiB > 500 MiB threshold, external dst
			data := `{"direction":"outbound","dst_ip":"203.0.113.66","dst_port":443,"protocol":"tcp","bytes_sent":` + itoa(chunk) + `}`
			feedEvent(t, e, agent, "windows", "network", data)
		}
		if !firedTech(cs, "T1048") {
			t.Fatal("exfil-volume detector did not fire on ingestion-shaped network events (bytes_sent) — reachability regression")
		}
	})

	t.Run("discovery_burst_via_command_line", func(t *testing.T) {
		e, cs := newTestEngine()
		cmds := []string{"whoami /all", "systeminfo", "ipconfig /all", "netstat -ano"}
		for _, c := range cmds {
			feedEvent(t, e, agent, "windows", "process", `{"process_name":"cmd.exe","command_line":"`+c+`"}`)
		}
		if !firedTitleHas(cs, "DISCOVERY") {
			t.Fatal("discovery burst did not fire through the engine")
		}
	})
}

// feedEventAt is feedEvent with an explicit event timestamp, so a test can
// simulate a replayed backlog (old events processed now).
func feedEventAt(t *testing.T, e *Engine, agentID, platform, etype, dataJSON string, ts time.Time) {
	t.Helper()
	env := `{"agent_id":"` + agentID + `","hostname":"e2e","platform":"` + platform +
		`","type":"` + etype + `","timestamp":"` + ts.UTC().Format(time.RFC3339Nano) + `","data":` + dataJSON + `}`
	if err := e.processEventData(context.Background(), []byte(env)); err != nil {
		t.Fatalf("processEventData(%s): %v", etype, err)
	}
}

// ─── バックログ再生で偽のバーストを作らないこと ───────────────────────────
//
// 実機で観測: オフラインの Windows ホストが「5秒内に60個のファイルを破壊的操作」
// というランサムウェアアラートを何時間も出し続けた。エンジンが JetStream の
// バックログを再生する際、レート検知器を time.Now() で採点していたため、
// 何時間ぶんもの履歴が一つの瞬間に潰れて全ての閾値を踏み抜いていた。
// イベント自身の時刻で採点すれば、緩やかに発生した履歴は緩やかなまま扱われる。
func TestReplayedBacklogDoesNotFabricateFileBurst(t *testing.T) {
	e, cs := newTestEngine()
	// 200ファイルを「10分かけて」破壊的操作した履歴を、いま一括で再処理する。
	base := time.Now().Add(-6 * time.Hour)
	for i := 0; i < 200; i++ {
		data := `{"path":"C:\\Users\\u\\doc` + itoa(i) + `.txt","operation":"FILE_ACTION_MODIFY","process_name":""}`
		feedEventAt(t, e, "agent-replay", "windows", "file", data, base.Add(time.Duration(i)*3*time.Second))
	}
	if firedTech(cs, "T1486") {
		t.Fatal("緩やかに発生した履歴の一括再生で、ランサムウェアバーストを捏造してはならない")
	}
}

// 逆に、イベント時刻の上で本当に高レートだったバーストは、再生であっても検知する。
// (インシデント後にオフラインだった端末が再接続してバックログを流した場合など)
func TestReplayedBacklogStillDetectsGenuineBurst(t *testing.T) {
	e, cs := newTestEngine()
	base := time.Now().Add(-6 * time.Hour)
	for i := 0; i < 80; i++ {
		data := `{"path":"C:\\Users\\u\\doc` + itoa(i) + `.txt","operation":"FILE_ACTION_MODIFY","process_name":""}`
		// 80ファイルを実時間で2秒以内に集中させる
		feedEventAt(t, e, "agent-replay2", "windows", "file", data, base.Add(time.Duration(i)*25*time.Millisecond))
	}
	if !firedTech(cs, "T1486") {
		t.Fatal("イベント時刻上で高レートな本物のバーストは、再生でも検知すべき")
	}
}

// TestBroadeningDiscoveryReportsSurviveAlertDedup is the engine-level gate for a
// defect class that detector unit tests are structurally blind to.
//
// discovery.go re-fires whenever the window holds a technique it has not yet named,
// and its unit tests proved that. In production it still reported once: alerts are
// deduplicated on (agent, title) for alertDedupWindow, and the burst title carries
// no observed values, so every later report collapsed into the first. Measured live
// 2026-08-03: 11 discovery techniques over 165 seconds produced ONE alert naming 4
// of them, and the other 7 were never surfaced at all.
//
// Both halves were individually correct — the detector reported, the pipeline
// deduplicated — so only a test that spans BOTH can see it. This one drives the
// real engine and counts alerts that actually reached the store.
func TestBroadeningDiscoveryReportsSurviveAlertDedup(t *testing.T) {
	const agent = "22222222-2222-2222-2222-222222222222"
	e, cs := newTestEngine()

	// A hands-on-keyboard survey that keeps widening: each command adds a technique
	// the previous alert did not name.
	cmds := []string{
		"whoami", "ps aux", "uname -a", "ip addr", // crosses the burst threshold
		"cat /etc/hosts", "ss -tun", "systemctl list-units", "getent group sudo",
	}
	for _, c := range cmds {
		feedEvent(t, e, agent, "linux", "process",
			`{"process_name":"bash","command_line":"`+c+`"}`)
	}

	var reports []*StoredAlert
	for _, a := range cs.saved {
		if strings.Contains(a.Title, "[DISCOVERY]") {
			reports = append(reports, a)
		}
	}
	if len(reports) < 2 {
		t.Fatalf("広がり続ける偵察が %d 件しか報告されていません。"+
			"アラート重複排除が新しい報告を握り潰しています（実機で観測された欠陥そのもの）", len(reports))
	}

	// The point is coverage, not alert count: every technique the survey performed
	// must appear in some report that actually reached the store.
	named := map[string]bool{}
	for _, a := range reports {
		for _, tg := range a.MITRETags {
			named[tg] = true
		}
	}
	for _, c := range cmds {
		tech := classifyDiscoveryCommand(c)
		if tech == "" {
			t.Fatalf("test setup: %q classified as no technique", c)
		}
		if !named[tech] {
			t.Errorf("%s (%q) は実行されたのに、保存されたどのアラートにも名前が出ていません", tech, c)
		}
	}

	// The noise floor must not have moved: repeating the same techniques adds no
	// information and must not produce further alerts.
	before := len(cs.saved)
	for _, c := range cmds {
		feedEvent(t, e, agent, "linux", "process",
			`{"process_name":"bash","command_line":"`+c+`"}`)
	}
	if len(cs.saved) != before {
		t.Errorf("報告済みの技術を繰り返しただけで %d 件の追加アラートが出ました（ノイズ床が下がっています）",
			len(cs.saved)-before)
	}
}
