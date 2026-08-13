// Package detection implements the server-side detection and auto-response engine.
// Event flow:
//
//	NATS (events.>) → Detection Engine → YARA/Sigma/Behavioral matching
//	                                   → Local alert creation
//	                                   → AI Agent (Claude) for deep analysis
//	                                   → Auto-Response execution
package detection

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/server/internal/behavioral"
	detectionrules "github.com/edr-platform/server/internal/detection/rules"
	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/ml"
	"github.com/edr-platform/server/internal/notification"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// SIEMForwarder forwards alerts to external SIEM targets.
type SIEMForwarder interface {
	Forward(ctx context.Context, alert *SIEMAlertPayload)
}

// SIEMAlertPayload is the alert data sent to SIEM targets.
type SIEMAlertPayload struct {
	ID             string
	AgentID        string
	Hostname       string
	OS             string
	RuleName       string
	Severity       int
	Status         string
	MITRETechnique string
	AIThreatName   string
	AISummary      string
	CreatedAt      time.Time
}

// SuppressionHitCounter increments the hit count for a suppression rule.
type SuppressionHitCounter interface {
	IncrHitCount(ctx context.Context, ruleID string)
}

// Engine is the central detection and auto-response orchestrator.
type Engine struct {
	nats           *nats.Conn
	js             jetstream.JetStream
	store          DetectionStore
	aiAgent        *AIAgent
	commander      AgentCommander
	rules          *detectionrules.RuleEngine
	notifier       *notification.Dispatcher // nil = notifications disabled
	playbooks      *PlaybookRunner          // nil = playbooks disabled
	iocMatcher     *IOCMatcher              // nil = IOC matching disabled
	suppression    *SuppressionMatcher      // nil = suppression disabled
	suppressionHit SuppressionHitCounter    // nil = hit count tracking disabled
	siemForwarder  SIEMForwarder            // nil = SIEM forwarding disabled
	behavioral     *ml.BehavioralEngine     // nil = ML behavioral analysis disabled
	parents        *parentResolver          // resolves parent image PATH from ppid for ParentImage rules
	netScan        *NetworkScanDetector     // stateful port-scan / fan-out detection (T1046)
	dnsAgg         *DNSTunnelAggregator     // stateful cross-query DNS tunneling detection (T1071.004)
	dnsFastFlux    *DNSFastFluxDetector     // stateful fast-flux infrastructure detection (T1568.001)
	killChain      *KillChainScorer         // cross-signal kill-chain risk scoring
	c2corr         *C2Correlator            // multi-signal C2 destination correlation
	resLinker      *ResolutionLinker        // DNS-resolution bridge (domain↔IP) for C2 correlation
	procThreat     *ProcessThreatCorrelator // per-PID compromise↔C2 correlation (active-implant confirmation)
	ransomCorr     *RansomwareCorrelator    // composite ransomware-precursor scoring (host-wide)
	discovery      *DiscoveryScorer         // host-enumeration burst + kill-chain discovery-stage feed
	authAttack     *AuthAttackScorer        // real-time brute-force / password-spray detection (T1110)
	fileBurst      *FileBurstScorer         // ransomware-style mass file-modification burst (T1486)
	lateralFanout  *LateralFanoutScorer     // lateral-movement fan-out to many hosts on service ports (T1021)
	exfilVol       *ExfilVolumeDetector     // bulk data-exfiltration by volume to external hosts (T1048)
	cryptoMiner    *CryptoMinerScorer       // sustained-high-CPU resource hijacking / cryptomining (T1496)
	baseline       *behavioral.Engine       // nil = per-agent baseline checks disabled
	baselineAlerts bool                     // gate baseline unknown-process alerts
	baselineSeen   map[string]struct{}      // dedup: agentID|process already alerted
	baselineMu     sync.Mutex
	alertDedup     map[string]time.Time // dedup: agentID|title → last save time
	alertDedupMu   sync.Mutex
	mu             sync.RWMutex
	config         EngineConfig
	// isoGuard は自動隔離の安全弁（冷却期間・時間あたり上限・ドライラン）。
	isoGuard *isolationGuard
}

// alertDedupWindow は同一 (エージェント+アラート題名) の再発火を抑制する時間窓。
// AlertPipeline(NATS sigma 経路)は既に5分窓 dedup を持つが、Engine(RuleEngine/
// typedFindings 経路)には無く、network イベント毎に発火する状態系ルール
// (例: "Publicly Accessible RDP Service")が同一 finding を秒間隔で無限に新規
// 行として書き続けアラートを氾濫させていた。両経路の意味論を揃えて横断的に抑制する。
const alertDedupWindow = 5 * time.Minute

// SetBaselineEngine attaches a per-agent behavioral baseline engine. When enabled,
// the live process path flags processes never seen in an agent's own history
// (deduped once per agent+process, gated, low severity). The engine's in-memory
// baselines must be built separately (BuildBaseline) — the detection process runs
// its own builder so this is self-contained.
func (e *Engine) SetBaselineEngine(b *behavioral.Engine, enabled bool) {
	e.baseline = b
	e.baselineAlerts = enabled
	e.baselineSeen = make(map[string]struct{}, 4096)
}

// markBaselineSeen records (and reports first-seen of) an agent+process key so the
// same unknown process is alerted only once. Bounded to avoid unbounded growth.
func (e *Engine) markBaselineSeen(key string) bool {
	e.baselineMu.Lock()
	defer e.baselineMu.Unlock()
	if _, ok := e.baselineSeen[key]; ok {
		return false
	}
	if len(e.baselineSeen) > 50000 {
		e.baselineSeen = make(map[string]struct{}, 4096) // reset cap
	}
	e.baselineSeen[key] = struct{}{}
	return true
}

// isDuplicateAlert reports whether an alert with the same (agent, title) key was
// saved within alertDedupWindow, recording the current time otherwise. Mirrors
// AlertPipeline.isDuplicate so both detection paths collapse a continuously
// re-asserting finding (a state condition like exposed-RDP, or a benign recurring
// memory region) into one alert per window instead of thousands of rows.
// The key space is bounded by (#agents × #distinct titles), so no eviction is
// needed beyond a safety cap.
func (e *Engine) isDuplicateAlert(key string) bool {
	e.alertDedupMu.Lock()
	defer e.alertDedupMu.Unlock()
	if last, ok := e.alertDedup[key]; ok && time.Since(last) < alertDedupWindow {
		return true
	}
	if len(e.alertDedup) > 100000 {
		e.alertDedup = make(map[string]time.Time, 4096) // safety cap: reset
	}
	e.alertDedup[key] = time.Now()
	return false
}

// SetSuppressionHitCounter attaches a hit counter for suppression rule tracking.
func (e *Engine) SetSuppressionHitCounter(c SuppressionHitCounter) {
	e.suppressionHit = c
}

// SetSIEMForwarder attaches a SIEM forwarder to the engine.
func (e *Engine) SetSIEMForwarder(f SIEMForwarder) {
	e.siemForwarder = f
}

// SetBehavioralEngine attaches an ML behavioral engine for process lineage analysis.
func (e *Engine) SetBehavioralEngine(b *ml.BehavioralEngine) {
	e.behavioral = b
}

type EngineConfig struct {
	// Auto-response is fully automated (no human approval needed)
	AutoResponseEnabled bool
	// Minimum severity for AI analysis (saves API costs)
	AIAnalysisMinSeverity int
	// Minimum anomaly score from local ML to trigger AI analysis
	AIAnalysisMinAnomalyScore float64
	// Maximum concurrent AI analyses
	AIAnalysisConcurrency int
	// Minimum alert severity required to trigger auto-isolation (1-10, default 9).
	// A rule must also have auto_isolate=true. Set to 0 to disable threshold enforcement.
	AutoIsolateSeverityThreshold int
	// AutoIsolateCooldown は同じ端末を再び自動隔離するまでの最短間隔（既定 30m）。
	AutoIsolateCooldown time.Duration
	// AutoIsolateHourlyBudget は 1 時間あたりに自動隔離を許す台数（既定 3）。
	AutoIsolateHourlyBudget int
	// AutoIsolateDryRun が true なら、隔離せず「隔離するはずだった」ことだけ記録する。
	AutoIsolateDryRun bool
}

type DetectionStore interface {
	AlertStore
	SaveAlert(ctx context.Context, alert *StoredAlert) error
	UpdateAlert(ctx context.Context, id string, update AlertUpdate) error
	GetAlert(ctx context.Context, id string) (*StoredAlert, error)
	SaveResponseAction(ctx context.Context, action *ResponseActionLog) error
}

type StoredAlert struct {
	ID          string
	AgentID     string
	Hostname    string
	OS          string
	RuleID      string
	RuleName    string
	Severity    int
	Status      string
	Title       string
	Description string
	EventIDs    []string
	MITRETech   string
	// MITRETags is the FULL set of ATT&CK techniques the matching rule maps to
	// (a correlation alert like the discovery burst covers many). Persisted to
	// ai_mitre_tags so each detected technique is credited, not just MITRETech.
	MITRETags    []string
	AnomalyScore float64
	RawEvent     json.RawMessage
	AIAnalysis   *ThreatAnalysis
	CreatedAt    time.Time
	UpdatedAt    time.Time
}

type AlertUpdate struct {
	Status     *string
	AIAnalysis *ThreatAnalysis
	UpdatedAt  time.Time
}

type ResponseActionLog struct {
	ID         string
	AlertID    string
	AgentID    string
	ActionType string
	Target     string
	Reason     string
	ExecutedBy string // "ai_agent" | "auto_rule" | user ID
	Success    bool
	Error      string
	ExecutedAt time.Time
}

func NewEngine(
	nc *nats.Conn,
	store DetectionStore,
	aiAgent *AIAgent,
	commander AgentCommander,
	rules *detectionrules.RuleEngine,
	notifier *notification.Dispatcher,
	playbooks *PlaybookRunner,
	iocMatcher *IOCMatcher,
	suppression *SuppressionMatcher,
	config EngineConfig,
) (*Engine, error) {
	js, err := jetstream.New(nc)
	if err != nil {
		return nil, fmt.Errorf("JetStream初期化に失敗しました: %w", err)
	}
	return &Engine{
		nats:        nc,
		js:          js,
		store:       store,
		aiAgent:     aiAgent,
		commander:   commander,
		rules:       rules,
		notifier:    notifier,
		playbooks:   playbooks,
		iocMatcher:  iocMatcher,
		suppression: suppression,
		isoGuard: newIsolationGuard(
			config.AutoIsolateCooldown, config.AutoIsolateHourlyBudget, config.AutoIsolateDryRun),
		parents:       newParentResolver(),
		netScan:       newNetworkScanDetector(),
		dnsAgg:        newDNSTunnelAggregator(),
		dnsFastFlux:   newDNSFastFluxDetector(),
		killChain:     newKillChainScorer(),
		c2corr:        newC2Correlator(),
		resLinker:     newResolutionLinker(),
		procThreat:    newProcessThreatCorrelator(),
		ransomCorr:    newRansomwareCorrelator(),
		discovery:     newDiscoveryScorer(),
		authAttack:    newAuthAttackScorer(),
		fileBurst:     newFileBurstScorer(),
		lateralFanout: newLateralFanoutScorer(),
		exfilVol:      newExfilVolumeDetector(),
		cryptoMiner:   newCryptoMinerScorer(),
		alertDedup:    make(map[string]time.Time),
		config:        config,
	}, nil
}

// Start begins consuming events from NATS and processing them.
func (e *Engine) Start(ctx context.Context) error {
	// Create consumer for all event types
	stream, err := e.js.Stream(ctx, "EVENTS")
	if err != nil {
		return fmt.Errorf("get events stream: %w", err)
	}

	// Per-process worker concurrency. Env-tunable so a single replica can be
	// scaled vertically, and so MaxAckPending can be derived from it (below).
	concurrency := detEnvInt("DETECTION_CONCURRENCY", 20)

	// MaxAckPending must stay aligned with the REAL worker parallelism, NOT set
	// to a large fixed number. JetStream prefetches up to MaxAckPending messages
	// to the client; only `concurrency` of them are processed at a time and the
	// rest sit buffered with their AckWait timer already ticking. If the buffered
	// backlog can't drain within AckWait, those messages time out and get
	// redelivered BEFORE they are ever processed — a redelivery storm that burns
	// throughput on duplicates and stalls the consumer's ack_floor (observed live:
	// MaxAckPending=1024 vs 20 workers → ~64s tail wait ≫ 30s AckWait → ~0 net
	// progress while pending grew). Default to a small multiple of concurrency so
	// the buffer always drains well within AckWait. Shared across replicas (the
	// durable is one consumer), so keep the value identical on every replica.
	maxAckPending := detEnvInt("DETECTION_MAX_ACK_PENDING", concurrency*3)

	// AckWait bounds how long a delivered-but-unacked message waits before
	// redelivery. Made explicit (default 60s) with headroom over real per-message
	// processing time so a transiently slow message is not needlessly redelivered.
	// A genuinely poison message still hits MaxDeliver and is dropped, advancing
	// ack_floor instead of pinning it.
	ackWait := time.Duration(detEnvInt("DETECTION_ACK_WAIT_SEC", 60)) * time.Second

	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:       "detection-engine",
		FilterSubject: "events.>",
		AckPolicy:     jetstream.AckExplicitPolicy,
		MaxDeliver:    3,
		MaxAckPending: maxAckPending,
		AckWait:       ackWait,
	})
	if err != nil {
		return fmt.Errorf("create consumer: %w", err)
	}

	// Start workers.
	sem := make(chan struct{}, concurrency)
	slog.Info("検知consumerを起動しました",
		"durable", "detection-engine",
		"concurrency", concurrency,
		"max_ack_pending", maxAckPending,
		"ack_wait", ackWait.String(),
	)

	cc, err := consumer.Consume(func(msg jetstream.Msg) {
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			if err := e.processMessage(ctx, msg); err != nil {
				slog.Error("event processing failed", "error", err)
				// Nak が通らないと再配信されず、そのイベントは失われる。
				if nakErr := msg.Nak(); nakErr != nil {
					slog.Warn("NATS Nak に失敗しました(再配信されません)", "error", nakErr)
				}
				return
			}
			// Ack が通らないと ack_wait 後に再配信される。処理は済んでいるので
			// 重複検知の原因になる。
			if ackErr := msg.Ack(); ackErr != nil {
				slog.Warn("NATS Ack に失敗しました(再配信される可能性があります)", "error", ackErr)
			}
		}()
	})
	if err != nil {
		return fmt.Errorf("start consumer: %w", err)
	}
	defer cc.Stop()

	// Publish consumer backpressure (pending message count) so ops can alert when
	// detection falls behind ingestion before it stalls outright.
	go e.monitorConsumerLag(ctx, consumer)

	// Subscribe to cloud events from cloud poller
	cloudSub, err := e.nats.Subscribe("cloud.events.>", func(msg *nats.Msg) {
		payload, err := ParseCloudEvent(msg.Data)
		if err != nil {
			return
		}

		verdict := DefaultCloudRules.Evaluate(payload)
		if !verdict.Suspicious {
			return
		}

		alert := &StoredAlert{
			ID:       generateAlertID(),
			Hostname: payload.Hostname,
			// RuleID intentionally empty: alerts.rule_id is uuid-typed; a non-UUID
			// sentinel makes the INSERT fail (SQLSTATE 22P02). Identity is in RuleName.
			RuleID:      "",
			RuleName:    "クラウド不審操作検知",
			Severity:    verdict.Severity,
			Status:      "open",
			Title:       "不審なクラウド操作を検出: " + payload.EventType,
			Description: verdict.Reason,
			MITRETech:   verdict.Technique,
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
		}
		e.enrichAnomalyScore(alert)
		if err := e.store.SaveAlert(context.Background(), alert); err != nil {
			slog.Error("クラウドアラートの保存に失敗しました", "error", err)
			metrics.AlertInsertFailures.WithLabelValues("cloud").Inc()
			return
		}
		metrics.AlertsCreated.Add(1)
		e.publishAlert(context.Background(), alert)
		if e.notifier != nil && alert.Severity >= 5 {
			go e.sendNotification(context.Background(), alert, nil)
		}
		slog.Info("クラウド不審操作検知",
			"provider", payload.Provider,
			"event_type", payload.EventType,
			"hostname", payload.Hostname,
		)
	})
	if err != nil {
		return fmt.Errorf("subscribe cloud events: %w", err)
	}
	defer cloudSub.Unsubscribe()

	// Block until context is cancelled
	<-ctx.Done()
	return nil
}

// processMessage handles a single event from NATS JetStream.
// typedFindings derives the non-Sigma detection matches from an event's type and
// flattened fields: DNS tunneling/DGA heuristics, agent-side YARA/threat-intel
// verdicts, and memory/credential-access findings. Pure over (eventType,
// flatEvent) so each source is regression-testable without the engine, DB or
// NATS. Every match uses an empty RuleID — alerts.rule_id is uuid-typed, so a
// non-UUID string there fails the INSERT (the bug that silently broke six
// sources, 2026-06); the identity lives in RuleName/Title.
func typedFindings(eventType string, flatEvent map[string]interface{}) []*detectionrules.RuleMatch {
	var matches []*detectionrules.RuleMatch

	// Heuristic DNS tunneling / exfiltration detection (T1048.003 / T1071.004).
	// Volume-based behavioral rules catch beaconing; this catches low-and-slow
	// exfil whose structure (long, high-entropy encoded name) betrays it.
	if eventType == "dns" {
		serverFired := false
		if q, _ := flatEvent["query"].(string); q != "" {
			if v := AnalyzeDNSQuery(q); v.Suspicious {
				serverFired = true
				matches = append(matches, &detectionrules.RuleMatch{
					RuleID:      "",
					RuleName:    "DNSトンネリング/データ流出の疑い",
					RuleType:    "heuristic",
					Severity:    7,
					Title:       "[HEURISTIC] DNSトンネリング/データ流出の疑い",
					Description: "DNSクエリの構造（長さ・高エントロピー・エンコード文字列）がDNSトンネリング/データ流出に合致: " + strings.Join(v.Reasons, ", "),
					MITRETags:   []string{"T1048.003", "T1071.004"},
				})
			}
			// DGA: the registrable domain itself looks algorithmically generated — the
			// rendezvous pattern of C2 that cycles through generated domains. Distinct
			// from exfil (encoded subdomain payload), so checked separately.
			if v := AnalyzeDGA(q); v.Suspicious {
				serverFired = true
				matches = append(matches, &detectionrules.RuleMatch{
					RuleID:      "",
					RuleName:    "DGA（アルゴリズム生成ドメイン）の疑い",
					RuleType:    "heuristic",
					Severity:    6,
					Title:       "[HEURISTIC] DGA（アルゴリズム生成C2ドメイン）の疑い",
					Description: "ドメイン '" + v.Domain + "' がアルゴリズム生成の特徴に合致（DGA型C2の疑い）: " + strings.Join(v.Reasons, ", "),
					MITRETags:   []string{"T1568.002", "T1071.004"},
				})
			}
		}
		// Agent-side DNS verdict (is_suspicious): the endpoint resolver flagged the
		// query as DGA/homograph on-host and shipped that verdict, but it was
		// discarded here while the server recomputed its own heuristics. Honor it
		// when the server heuristics did NOT already fire — the agent models signals
		// the server does not (e.g. IDN/homograph confusables), so dropping it lost
		// real detections. Mirrors how yara_matched / threat_intel_matched agent
		// verdicts are surfaced. Gated on serverFired to avoid a duplicate alert.
		if !serverFired {
			if susp, _ := flatEvent["is_suspicious"].(bool); susp {
				q, _ := flatEvent["query"].(string)
				if q == "" {
					q = "不明"
				}
				matches = append(matches, &detectionrules.RuleMatch{
					RuleID:      "",
					RuleName:    "エージェントDNS判定: DGA/ホモグラフの疑い",
					RuleType:    "heuristic",
					Severity:    5,
					Title:       "[HEURISTIC] エージェント側DNS判定で不審と判定: " + q,
					Description: "エージェントがDNSクエリ '" + q + "' をDGA/ホモグラフ（類似綴りドメイン）としてオンホストで不審と判定しました。サーバ側ヒューリスティックが検出しない信号（IDN/ホモグラフ等）を回収。",
					MITRETags:   []string{"T1568.002", "T1071.004"},
				})
			}
		}
	}

	// TLS fingerprint (JA3/JA3S) match against the C2-framework blocklist. An
	// implant's TLS stack fingerprints consistently regardless of its C2 domain or
	// IP, so this catches beaconing whose 5-tuple and command line are unremarkable —
	// the "プロセス署名なきC2" gap that signature/LOLBin rules cannot cover.
	if eventType == "tls_handshake" {
		dstIP, _ := flatEvent["dst_ip"].(string)
		sni, _ := flatEvent["sni"].(string)
		dstDesc := dstIP
		if sni != "" {
			dstDesc = sni + " (" + dstIP + ")"
		}
		ja3, _ := flatEvent["ja3"].(string)
		ja3s, _ := flatEvent["ja3s"].(string)
		for _, fp := range []struct {
			md5, kind string
		}{{ja3, "JA3"}, {ja3s, "JA3S"}} {
			if sig, ok := matchJA3(fp.md5); ok {
				matches = append(matches, &detectionrules.RuleMatch{
					RuleID:      "",
					RuleName:    "C2ツール既知TLSフィンガープリント(" + fp.kind + ")一致: " + sig.Tool,
					RuleType:    "behavioral",
					Severity:    sig.Severity,
					Title:       "[BEHAVIORAL] 既知C2の" + fp.kind + "フィンガープリント一致: " + sig.Tool,
					Description: fmt.Sprintf("%s への TLS ハンドシェイクの %s フィンガープリント(%s)が既知の %s と一致（プロセス署名なきC2の疑い）", dstDesc, fp.kind, fp.md5, sig.Tool),
					MITRETags:   sig.MITRETags,
				})
			}
		}
	}

	// Surface high-confidence agent-side verdicts as alerts. These were computed
	// on the endpoint and previously dropped during normalization (now lifted in
	// ingestion); acting on them recovers on-endpoint YARA and threat-intel hits.
	if v, _ := flatEvent["yara_matched"].(bool); v {
		ids, _ := flatEvent["yara_rule_ids"].([]interface{})
		matches = append(matches, &detectionrules.RuleMatch{
			RuleID:      "",
			RuleName:    "エージェントYARA検知",
			RuleType:    "yara",
			Severity:    8,
			Title:       "[YARA] エージェント上でYARAルールに一致",
			Description: fmt.Sprintf("エージェントがファイルをYARAルールに一致と判定しました (rules: %v)", ids),
			MITRETags:   []string{"T1204"},
		})
	}
	if v, _ := flatEvent["threat_intel_matched"].(bool); v {
		cat, _ := flatEvent["threat_intel_category"].(string)
		src, _ := flatEvent["threat_intel_source"].(string)
		matches = append(matches, &detectionrules.RuleMatch{
			RuleID:      "",
			RuleName:    "脅威インテリジェンス一致",
			RuleType:    "ioc",
			Severity:    7,
			Title:       "[THREAT-INTEL] 既知の悪性インフラへの通信",
			Description: fmt.Sprintf("エージェントの脅威インテリ照合に一致 (category: %s, source: %s)", cat, src),
			MITRETags:   []string{"T1071"},
		})
	}
	// Memory/injection finding (M1 scanner): the agent emits only vetted suspicious
	// regions (RWX / unbacked-executable), so surface each as an alert. Unbacked
	// executable memory (floating code) is the stronger injection signal.
	if eventType == "memory" {
		proc, _ := flatEvent["process_name"].(string)
		reason, _ := flatEvent["reason"].(string)
		addr, _ := flatEvent["address"].(string)
		unbacked, _ := flatEvent["unbacked"].(bool)
		rwx, _ := flatEvent["rwx"].(bool)
		yaraMatched, _ := flatEvent["yara_matched"].(bool)
		perms, _ := flatEvent["perms"].(string)
		writable := strings.Contains(strings.ToLower(perms), "w")

		// FP gate: an unbacked but NON-writable (r-x) executable region, with no
		// YARA hit, in a known-benign long-running system daemon is the floating-code
		// false-positive firehose (~3.6k/7d on the verification EC2 — e.g.
		// unattended-upgrades / networkd-dispatcher, whose mapped shared objects the
		// scanner intermittently reports as "unbacked" r-x). The strong injection
		// signals are NEVER gated: a currently writable+executable region (rwx / W^X
		// violation), a YARA match, or the same finding in any non-allowlisted process
		// all still alert. Telemetry is persisted to `events` regardless — only the
		// alert is suppressed.
		if unbacked && !rwx && !writable && !yaraMatched && isBenignMemoryRegionProcess(proc) {
			// suppressed benign floating-code FP
		} else {
			sev := 6
			if unbacked {
				sev = 7
			}
			matches = append(matches, &detectionrules.RuleMatch{
				RuleID:      "",
				RuleName:    "メモリ検知: 不審な実行メモリ領域",
				RuleType:    "memory",
				Severity:    sev,
				Title:       "[MEMORY] 不審な実行メモリ領域: " + proc,
				Description: fmt.Sprintf("%s (process=%s addr=%s)", reason, proc, addr),
				MITRETags:   []string{"T1055"}, // Process Injection
			})
		}
	}
	// Credential-access finding: a process read another process's memory. Two
	// sources with very different base rates:
	//   - Windows (ObRegisterCallbacks, M3): a PROCESS_VM_READ open of lsass.exe —
	//     rare and almost always the LSASS read used by dumpers (mimikatz/procdump).
	//   - Linux (eBPF LSM ptrace_access_check): fires on EVERY cross-process
	//     ptrace/mem access, the overwhelming majority of which is benign system
	//     activity (systemd-journal reading /proc, runc/containerd namespace setup,
	//     landscape-sysinfo). Alerting on all of it floods false "LSASS" positives.
	// Branch on access_mask: "ptrace_mode=.." ⇒ Linux; allowlist benign tracers so
	// only anomalous accessors (gdb/strace/python/dd, custom tools) surface as
	// T1003/T1055. enforced=true means the access was stripped/denied.
	if eventType == "credential_access" {
		srcProc, _ := flatEvent["source_image"].(string)
		if srcProc == "" {
			srcProc = "不明"
		}
		tgtProc, _ := flatEvent["target_image"].(string)
		if tgtProc == "" {
			tgtProc = "不明"
		}
		accessMask, _ := flatEvent["access_mask"].(string)
		enforced, _ := flatEvent["enforced"].(bool)

		if strings.HasPrefix(accessMask, "ptrace_mode=") {
			// Linux ptrace/mem access. Two suppressions, telemetry always kept in
			// `events` for hunting/correlation — only the ALERT is gated:
			//   1. ATTACH-mode only. The LSM ptrace_access_check hook fires on
			//      ptrace_may_access, which the kernel also calls for benign /proc
			//      reads. `ps`/`top`/`pgrep` scanning /proc/<pid>/{stat,status,cmdline}
			//      trigger PTRACE_MODE_READ (0x0d = READ_FSCREDS, no ATTACH bit) on
			//      EVERY pid — a firehose (~97k alerts/7d on the verification EC2,
			//      e.g. "ps → kworker/0:2", "ps → docker-proxy"). The actual
			//      credential-dump / injection primitive (process_vm_readv,
			//      open /proc/pid/mem, PTRACE_ATTACH) always carries PTRACE_MODE_ATTACH
			//      (0x02). Gating on ATTACH keeps mimikatz/gdb/strace-style reads while
			//      dropping the /proc-enumeration noise (which also fed the detection
			//      consumer backlog).
			//   2. Benign system tracers (isBenignLinuxTracer) as before.
			if ptraceModeIsAttach(accessMask) && !isBenignLinuxTracer(srcProc) {
				sev := 6
				if isSensitiveCredTarget(tgtProc) {
					sev = 8 // reading a credential-bearing process (sshd, agents, keyrings)
				}
				matches = append(matches, &detectionrules.RuleMatch{
					RuleID:   "",
					RuleName: "認証情報/メモリアクセス: プロセス間ptrace/mem読取 (Linux)",
					RuleType: "credential_access",
					Severity: sev,
					Title:    "[CRED] プロセスメモリ・アクセス（認証情報ダンプ/インジェクションの疑い）: " + srcProc + " → " + tgtProc,
					Description: fmt.Sprintf("プロセス %s (pid=%v) が %s (pid=%v) のメモリに %s でアクセス",
						srcProc, flatEvent["source_pid"], tgtProc, flatEvent["target_pid"], accessMask),
					MITRETags: []string{"T1003", "T1055"}, // Credential Dumping / Process Injection
				})
			}
		} else {
			// Windows LSASS. Severity 8 (below auto-isolate) until an AV/system
			// allowlist exists, since legitimate security tools also read LSASS.
			verdict := "検知（audit・許可）"
			if enforced {
				verdict = "拒否（VM_READ剥奪・ダンプ阻止）"
			}
			matches = append(matches, &detectionrules.RuleMatch{
				RuleID:   "",
				RuleName: "認証情報アクセス: LSASSハンドル(PROCESS_VM_READ)",
				RuleType: "credential_access",
				Severity: 8,
				Title:    "[CRED] LSASSメモリ・アクセス（認証情報ダンプの疑い）: " + srcProc,
				Description: fmt.Sprintf("プロセス %s (pid=%v) が lsass.exe (pid=%v) を %s で開封 [%s]",
					srcProc, flatEvent["source_pid"], flatEvent["target_pid"], accessMask, verdict),
				MITRETags: []string{"T1003.001"}, // OS Credential Dumping: LSASS Memory
			})
		}
	}

	// Process-block decision (agent-side prevention): the agent already blocked a
	// process and reports {process_name, pid, action, rule_name, severity}. This
	// was ingested and persisted to events but had no detection consumer — so a
	// prevention left no alert (zero visibility into what the agent stopped).
	// Surface it as a BLOCKED alert; the "阻止" wording also marks it on the
	// Protection axis (attack-scorer isBlocking).
	if eventType == "process_block" {
		proc, _ := flatEvent["process_name"].(string)
		action, _ := flatEvent["action"].(string)
		ruleName, _ := flatEvent["rule_name"].(string)
		sev := 7
		switch s := flatEvent["severity"].(type) {
		case float64: // JSON numbers decode to float64
			if s > 0 {
				sev = int(s)
			}
		case int:
			if s > 0 {
				sev = s
			}
		}
		matches = append(matches, &detectionrules.RuleMatch{
			RuleID:   "",
			RuleName: "プロセス実行ブロック（予防）",
			RuleType: "process_block",
			Severity: sev,
			Title:    "[BLOCKED] プロセス実行を阻止: " + proc,
			Description: fmt.Sprintf("エージェントがプロセスの実行を阻止しました (process=%s action=%s rule=%s pid=%v)",
				proc, action, ruleName, flatEvent["pid"]),
			MITRETags: []string{"T1059"}, // Execution (generic; the blocked technique varies)
		})
	}

	// Windows event-log clearing (agent-side: Security EID 1102 / System EID 104).
	// Clearing the audit log is a high-signal defense-evasion move that destroys
	// the very telemetry the rest of the pipeline relies on — attackers do it to
	// cover post-compromise tracks, and legitimate admins almost never clear the
	// Security log on a monitored endpoint. It had no detection consumer, so a
	// wipe was previously invisible. Surface it as T1070.001.
	if eventType == "eventlog_cleared" {
		channel, _ := flatEvent["channel"].(string)
		if channel == "" {
			channel = "不明"
		}
		user, _ := flatEvent["user"].(string)
		if user == "" {
			user = "不明"
		}
		matches = append(matches, &detectionrules.RuleMatch{
			RuleID:      "",
			RuleName:    "防御回避: Windowsイベントログの消去",
			RuleType:    "eventlog_cleared",
			Severity:    8,
			Title:       "[EVASION] イベントログが消去されました: " + channel,
			Description: fmt.Sprintf("%s のイベントログが消去されました (実行ユーザー=%s)。監査証跡の破壊による痕跡隠蔽の疑い。", channel, user),
			MITRETags:   []string{"T1070.001"}, // Indicator Removal: Clear Windows Event Logs
		})
	}

	// Windows service installation (agent-side: System EID 7045). Installing a
	// service is the classic PsExec / Cobalt Strike lateral-movement + persistence
	// primitive (T1543.003). Legitimate software installs services too, so this
	// only alerts when the service binary looks malicious — a LOLBin/script host,
	// an encoded command, or a binary dropped in a world-writable/temp directory —
	// keeping benign Program Files service installs quiet.
	if eventType == "service_installed" {
		svc, _ := flatEvent["service_name"].(string)
		img, _ := flatEvent["image_path"].(string)
		if reason := suspiciousServiceImage(img); reason != "" {
			if svc == "" {
				svc = "不明"
			}
			matches = append(matches, &detectionrules.RuleMatch{
				RuleID:      "",
				RuleName:    "永続化/横展開: 不審なサービスのインストール",
				RuleType:    "service_installed",
				Severity:    8,
				Title:       "[PERSIST] 不審なサービスがインストールされました: " + svc,
				Description: fmt.Sprintf("サービス '%s' がインストールされました (ImagePath=%s)。%s。PsExec/Cobalt Strike 等の横展開・永続化の疑い。", svc, img, reason),
				MITRETags:   []string{"T1543.003"}, // Create or Modify System Process: Windows Service
			})
		}
	}

	// Removable-device connection (agent-side device collector). A removable drive
	// or USB device attaching to a monitored endpoint is the vector for malware
	// replication (T1091), hardware implants (T1200), and USB exfiltration
	// (T1052.001). The event was collected but previously dropped at ingestion, so
	// nothing surfaced. Only "connected" is actionable (a disconnect is not a
	// threat), and we gate on device class to keep FP low: mass storage is the
	// higher-signal exfil/replication vector; a bare USB attach is informational
	// hardware-addition telemetry. Input (keyboard/mouse) and network devices are
	// too noisy/benign to alert on.
	if eventType == "device_event" {
		action, _ := flatEvent["action"].(string)
		devType, _ := flatEvent["type"].(string)
		if action == "connected" && (devType == "storage" || devType == "usb") {
			name, _ := flatEvent["name"].(string)
			if name == "" {
				name = "不明なデバイス"
			}
			vid, _ := flatEvent["vendor_id"].(string)
			pid, _ := flatEvent["product_id"].(string)
			sev := 3 // bare USB attach: informational hardware-addition telemetry
			if devType == "storage" {
				sev = 5 // removable storage: the replication / USB-exfil vector
			}
			matches = append(matches, &detectionrules.RuleMatch{
				RuleID:   "",
				RuleName: "リムーバブルデバイスの接続",
				RuleType: "device_event",
				Severity: sev,
				Title:    "[DEVICE] リムーバブルデバイスが接続されました: " + name,
				Description: fmt.Sprintf("デバイス '%s' (type=%s vendor=%s product=%s) が接続されました。リムーバブルメディア経由の感染拡大(T1091)/USBデータ持ち出し(T1052)の監視対象イベント。",
					name, devType, vid, pid),
				MITRETags: []string{"T1091", "T1200", "T1052.001"},
			})
		}
	}

	return matches
}

// suspiciousServiceImage returns a non-empty reason when a service's binary path
// matches a known-malicious shape (LOLBin/script host, encoded command, or a
// world-writable/temp drop location), or "" when it looks like a normal install.
func suspiciousServiceImage(imagePath string) string {
	if strings.TrimSpace(imagePath) == "" {
		return "ImagePath が空"
	}
	lower := strings.ToLower(imagePath)

	for _, frag := range []string{"-enc", "-encodedcommand", "-e ", "iex", "downloadstring", "frombase64string", "invoke-expression"} {
		if strings.Contains(lower, frag) {
			return "エンコード/難読化されたコマンドをサービスバイナリに指定"
		}
	}
	// Compare the service binary's basename (the first token of ImagePath, minus
	// any directory and surrounding quotes) against the LOLBin/script-host set —
	// so both "C:\Windows\System32\cmd.exe" and a bare "rundll32.exe ..." match.
	switch serviceImageBase(lower) {
	case "cmd.exe", "powershell.exe", "pwsh.exe", "rundll32.exe", "regsvr32.exe",
		"mshta.exe", "wscript.exe", "cscript.exe", "msbuild.exe", "installutil.exe":
		return "LOLBin/スクリプトホストをサービスバイナリに指定"
	}
	for _, ext := range []string{".ps1", ".bat", ".cmd", ".vbs", ".js", ".hta"} {
		if strings.HasSuffix(strings.TrimRight(lower, `" `), ext) {
			return "スクリプトファイルをサービスバイナリに指定"
		}
	}
	for _, dir := range []string{`\temp\`, `\tmp\`, `\appdata\`, `\users\public\`, `\programdata\`, `\windows\temp\`, `\downloads\`} {
		if strings.Contains(lower, dir) {
			return "書込可能/一時ディレクトリからサービスを起動"
		}
	}
	return ""
}

// serviceImageBase returns the lowercased basename of a service ImagePath's
// executable: the first whitespace-separated token, unquoted, minus its
// directory. e.g. `"c:\windows\system32\cmd.exe" /c x` → "cmd.exe".
func serviceImageBase(lowerImagePath string) string {
	s := strings.TrimSpace(lowerImagePath)
	if s == "" {
		return ""
	}
	if s[0] == '"' {
		if end := strings.IndexByte(s[1:], '"'); end >= 0 {
			s = s[1 : end+1]
		} else {
			s = s[1:]
		}
	} else if i := strings.IndexAny(s, " \t"); i >= 0 {
		s = s[:i]
	}
	if i := strings.LastIndexAny(s, `\/`); i >= 0 {
		s = s[i+1:]
	}
	return s
}

// iocSeverity weights an IOC alert's severity by its multi-source reputation:
// a high-confidence indicator (corroborated by multiple feeds) is bumped one
// level so it ranks above a single-source hit of the same base severity.
func iocSeverity(ioc IOCRecord) int {
	sev := ioc.Severity
	if ioc.Confidence >= 75 && sev < 10 {
		sev++
	}
	return sev
}

// sourceLabel normalizes a match's RuleType into a non-empty metric label so the
// AlertInsertFailures counter never carries an empty source.
func sourceLabel(ruleType string) string {
	if ruleType == "" {
		return "unknown"
	}
	return ruleType
}

func (e *Engine) processMessage(ctx context.Context, msg jetstream.Msg) error {
	return e.processEventData(ctx, msg.Data())
}

// consumerLagInterval is how often the detection consumer's pending count is
// sampled for the backpressure metric.
const consumerLagInterval = 30 * time.Second

// monitorConsumerLag periodically samples the JetStream detection consumer's
// pending (undelivered) message count into edr_detection_consumer_pending until
// ctx is cancelled. A growing value is backpressure — detection is not keeping up
// with ingestion — which precedes an outright pipeline stall.
func (e *Engine) monitorConsumerLag(ctx context.Context, consumer jetstream.Consumer) {
	ticker := time.NewTicker(consumerLagInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			info, err := consumer.Info(ctx)
			if err != nil {
				slog.Debug("consumer info の取得に失敗しました", "error", err)
				continue
			}
			metrics.DetectionConsumerPending.Set(float64(info.NumPending))
		}
	}
}

// processEventData runs the full detection pipeline over one raw NormalizedEvent
// JSON payload. Split from processMessage (which only unwraps the JetStream
// envelope) so the end-to-end path — flatten → IOC/baseline/typedFindings/rules
// → real alert INSERT — is exercisable in tests without a live JetStream consumer.
func (e *Engine) processEventData(ctx context.Context, data []byte) error {
	var eventEnvelope EventEnvelope
	if err := json.Unmarshal(data, &eventEnvelope); err != nil {
		return fmt.Errorf("unmarshal event: %w", err)
	}
	metrics.EventsIngested.Add(1)
	// Dead-man's-switch: stamp the last-processed time so ops can alert when the
	// ingestion→NATS→detection pipeline silently stalls (process alive, no events).
	metrics.DetectionLastEventTimestamp.SetToCurrentTime()

	// Build flat map for sigma evaluation
	flatEvent := eventEnvelope.FlatMap()

	// De-obfuscate the command line before any matcher sees it, so the detection
	// server's DB Sigma rules, IOC matcher and the SequenceEngine (kill-chain /
	// burst correlation) are all robust to caret/quote/backtick obfuscation and
	// encoded-PowerShell payloads — the same pre-pass the API pipeline applies
	// (commandline_normalize.go). Appends, never replaces, so no rule regresses.
	normalizeCommandLine(flatEvent)

	// Every stateful rate/burst detector below must be scored on the time the
	// event ACTUALLY HAPPENED, not on when we got around to processing it. Using
	// the wall clock breaks them whenever ingestion is not real time — an engine
	// restart replaying the JetStream backlog, a redelivery after AckWait, or an
	// agent that buffered offline and flushed on reconnect. In those cases hours
	// of events are all stamped "now", collapse into a single instant, and every
	// rate threshold trips at once. Observed live: an OFFLINE Windows host emitted
	// a steady stream of "60 files destroyed in 5 seconds" ransomware alerts for
	// hours while its buffered events were replayed. The envelope carries the
	// real timestamp; use it, falling back to the clock only when absent.
	evTime := eventEnvelope.EventTime()

	// ── IOC matching ─────────────────────────────────────────────
	if e.iocMatcher != nil {
		for _, hit := range e.iocMatcher.CheckEvent(flatEvent) {
			iocAlert := &StoredAlert{
				ID:       generateAlertID(),
				AgentID:  eventEnvelope.AgentID,
				Hostname: eventEnvelope.Hostname,
				OS:       eventEnvelope.Platform,
				// RuleID intentionally empty: alerts.rule_id is uuid-typed and
				// the previous "ioc-match" sentinel made the INSERT silently fail.
				// Rule identity is captured in RuleName.
				RuleName: "IOCマッチ: " + hit.IOC.Type,
				Severity: iocSeverity(hit.IOC),
				Status:   "open",
				Title:    "既知IOC検出: " + hit.Value,
				Description: fmt.Sprintf("フィールド %s が既知の脅威インジケーター (%s) に一致しました。信頼度 %d/100。%s",
					hit.MatchedOn, hit.IOC.Type, hit.IOC.Confidence, hit.IOC.Description),
				MITRETech: "T1071", // C2/IOC matches often map to Application Layer Protocol
				CreatedAt: time.Now(),
				UpdatedAt: time.Now(),
			}
			// Check suppression rules before saving the alert
			if e.suppression != nil {
				if suppressed, ruleName, ruleID := e.suppression.IsSuppressed(iocAlert); suppressed {
					slog.Debug("IOCアラートが抑制されました", "rule", ruleName, "ioc_type", hit.IOC.Type, "value", hit.Value)
					if e.suppressionHit != nil {
						e.suppressionHit.IncrHitCount(ctx, ruleID)
					}
					continue
				}
			}
			e.enrichAnomalyScore(iocAlert)
			if err := e.store.SaveAlert(ctx, iocAlert); err != nil {
				slog.Error("IOCアラートの保存に失敗しました", "error", err)
				metrics.AlertInsertFailures.WithLabelValues("ioc").Inc()
				continue
			}
			metrics.AlertsCreated.Add(1)
			iocMitre := "none"
			if iocAlert.MITRETech != "" {
				iocMitre = iocAlert.MITRETech
			}
			metrics.DetectionsByEngine.WithLabelValues("ioc", iocMitre).Inc()
			e.publishAlert(ctx, iocAlert)
			if e.notifier != nil && iocAlert.Severity >= 5 {
				go e.sendNotification(ctx, iocAlert, nil)
			}
			if e.playbooks != nil {
				e.playbooks.Run(ctx, iocAlert)
			}
			if (iocAlert.Severity >= e.config.AIAnalysisMinSeverity ||
				(e.config.AIAnalysisMinAnomalyScore > 0 && iocAlert.AnomalyScore >= e.config.AIAnalysisMinAnomalyScore)) &&
				e.aiAgent != nil {
				go e.runAIAnalysis(ctx, iocAlert, &eventEnvelope)
			}
			slog.Info("IOC検出", "type", hit.IOC.Type, "value", hit.Value, "agent", eventEnvelope.AgentID)
		}
	}

	// ── ML behavioral analysis (process lineage + chain) ─────────────
	if e.behavioral != nil && eventEnvelope.Type == "process" {
		parentProc, _ := flatEvent["parent_process"].(string)
		childProc, _ := flatEvent["process_name"].(string)
		if childProc == "" {
			childProc, _ = flatEvent["Image"].(string)
		}
		action, _ := flatEvent["action"].(string)

		// Extract PID/PPID for multi-hop chain analysis.
		var pid, ppid uint32
		if v, ok := flatEvent["pid"]; ok {
			switch n := v.(type) {
			case uint32:
				pid = n
			case float64:
				pid = uint32(n)
			case int:
				pid = uint32(n)
			}
		}
		if v, ok := flatEvent["ppid"]; ok {
			switch n := v.(type) {
			case uint32:
				ppid = n
			case float64:
				ppid = uint32(n)
			case int:
				ppid = uint32(n)
			}
		}
		cmdline, _ := flatEvent["command_line"].(string)

		slog.Info("behavioral process event",
			"agent", eventEnvelope.AgentID,
			"child", childProc,
			"pid", pid,
			"ppid", ppid,
			"action", action,
		)

		// Cache this process's FULL image path keyed by pid, so a later child event
		// can resolve its parent by PATH (ParentImage rules match '/nginx', '/tmp/…').
		// Done before the "existing" early-return so already-running parents are cached.
		if img, _ := flatEvent["Image"].(string); img != "" && pid != 0 {
			e.parents.record(eventEnvelope.AgentID, uint64(pid), img)
		}

		// "existing" events seed the chain cache without generating alerts.
		// They represent processes already running when the agent started.
		if action == "existing" && childProc != "" && pid != 0 {
			e.behavioral.Chain.Analyze(eventEnvelope.AgentID, pid, ppid, childProc, cmdline)
			return nil
		}

		// Resolve the parent from the PPID cache if not present in the event. Prefer
		// the full image PATH (parentResolver) so ParentImage path-pattern rules match;
		// fall back to the chain's basename when only that is known.
		if parentProc == "" && ppid != 0 {
			if pp := e.parents.lookup(eventEnvelope.AgentID, uint64(ppid)); pp != "" {
				parentProc = pp
			} else {
				parentProc = e.behavioral.Chain.LookupName(eventEnvelope.AgentID, ppid)
			}
		}

		// Expose the resolved parent name to the rule engine so Sigma ParentImage
		// rules can match (the RuleEngine maps ParentImage → parent_image_path).
		if parentProc != "" {
			if _, ok := flatEvent["parent_image_path"]; !ok {
				flatEvent["parent_image_path"] = parentProc
			}
		}

		if childProc != "" {
			detections := e.behavioral.ProcessEvent(eventEnvelope.AgentID, parentProc, childProc, pid, ppid, cmdline)
			for _, d := range detections {
				ruleName := "ML行動分析: 不審なプロセス系統"
				mitre := "T1059"
				if d.Type == "suspicious_process_chain" {
					ruleName = "プロセスチェーン検知: " + d.Details["mitre"]
					mitre = d.Details["mitre"]
				}
				mlAlert := &StoredAlert{
					ID:       generateAlertID(),
					AgentID:  eventEnvelope.AgentID,
					Hostname: eventEnvelope.Hostname,
					OS:       eventEnvelope.Platform,
					// RuleID intentionally empty: alerts.rule_id is uuid-typed;
					// chain rule identity is captured in RuleName and Description.
					RuleName:    ruleName,
					Severity:    severityStringToInt(d.Severity),
					Status:      "open",
					Title:       "不審なプロセス系統を検出: " + d.Message,
					Description: d.Message,
					MITRETech:   mitre,
					CreatedAt:   time.Now(),
					UpdatedAt:   time.Now(),
				}
				e.enrichAnomalyScore(mlAlert)
				if err := e.store.SaveAlert(ctx, mlAlert); err != nil {
					slog.Error("ML alert save failed", "error", err)
					metrics.AlertInsertFailures.WithLabelValues("chain").Inc()
					continue
				}
				metrics.AlertsCreated.Add(1)
				chainMitre := "none"
				if mitre != "" {
					chainMitre = mitre
				}
				metrics.DetectionsByEngine.WithLabelValues("chain", chainMitre).Inc()
				e.publishAlert(ctx, mlAlert)
				if e.notifier != nil && mlAlert.Severity >= 5 {
					go e.sendNotification(ctx, mlAlert, nil)
				}
				slog.Info("ML行動分析検知",
					"type", d.Type,
					"severity", d.Severity,
					"agent", eventEnvelope.AgentID,
					"parent", parentProc,
					"child", childProc,
					"chain", d.Details["chain"],
				)
			}

			// Per-agent behavioral baseline: flag a process never seen in this
			// agent's own history AND running from a suspicious drop/staging
			// directory. Gated + deduped (once per agent+process) + low severity to
			// avoid noise; independent of the rule/Sigma path. The raw image_path
			// (not the Sigma-normalized "Image", which may be a comm basename with a
			// prepended separator) drives the location gate in CheckProcessAnomaly.
			if e.baseline != nil && e.baselineAlerts && action != "existing" {
				imagePath, _ := flatEvent["image_path"].(string)
				if imagePath == "" {
					imagePath, _ = flatEvent["imagePath"].(string)
				}
				if anom := e.baseline.CheckProcessAnomaly(eventEnvelope.AgentID, childProc, imagePath); anom != nil &&
					e.markBaselineSeen(eventEnvelope.AgentID+"|"+childProc) {
					baAlert := &StoredAlert{
						ID:          generateAlertID(),
						AgentID:     eventEnvelope.AgentID,
						Hostname:    eventEnvelope.Hostname,
						OS:          eventEnvelope.Platform,
						RuleName:    "行動ベースライン: 未知のプロセスが不審な場所から実行",
						Severity:    4,
						Status:      "open",
						Title:       "通常見られないプロセスが不審な場所から実行: " + childProc,
						Description: anom.Detail,
						MITRETech:   "T1059",
						CreatedAt:   time.Now(),
						UpdatedAt:   time.Now(),
					}
					e.enrichAnomalyScore(baAlert)
					if err := e.store.SaveAlert(ctx, baAlert); err != nil {
						slog.Error("baseline alert save failed", "error", err)
						metrics.AlertInsertFailures.WithLabelValues("baseline").Inc()
					} else {
						metrics.AlertsCreated.Add(1)
						metrics.DetectionsByEngine.WithLabelValues("baseline", "T1059").Inc()
						e.publishAlert(ctx, baAlert)
						slog.Info("行動ベースライン検知: 未知プロセス",
							"agent", eventEnvelope.AgentID, "process", childProc)
					}
				}
			}
		}
	}

	// Run detection rules
	matches, err := e.rules.Evaluate(ctx, flatEvent)
	if err != nil {
		return fmt.Errorf("rule evaluation: %w", err)
	}

	// Type/verdict-based detections (DNS heuristics, agent YARA/threat-intel
	// verdicts, memory & credential-access findings). Extracted as a pure function
	// over (eventType, flatEvent) so every source stays regression-testable —
	// guarding against the silent-break class found 2026-06 (non-UUID RuleID into
	// the uuid column, dropped field aliases). See engine_typed_findings_test.go.
	matches = append(matches, typedFindings(eventEnvelope.Type, flatEvent)...)

	// Stateful port-scan / fan-out detection (T1046). A scan is a rate/fan-out
	// phenomenon that pure per-event rules cannot see; feed outbound network events
	// to the windowed detector. Tool-agnostic — fires the same for nmap/masscan or a
	// `bash /dev/tcp` loop, closing the evasion gap that slipped past process-string
	// rules (docs/results/live-20260702-linux-evasion-adversarial.md).
	if e.netScan != nil && eventEnvelope.Type == "network" {
		if dir, _ := flatEvent["direction"].(string); dir != "inbound" {
			dstPort := 0
			if f, ok := toFloat64(flatEvent["dst_port"]); ok {
				dstPort = int(f)
			}
			dstIP, _ := flatEvent["dst_ip"].(string)
			proc, _ := flatEvent["process_name"].(string)
			state, _ := flatEvent["state"].(string)
			refused := state == "refused" || state == "rejected" || state == "closed"
			matches = append(matches, e.netScan.Observe(eventEnvelope.AgentID, proc, dstIP, dstPort, refused, evTime)...)
			// Lateral-movement fan-out (T1021): one host reaching many DISTINCT hosts
			// on remote-service ports (SMB/RDP/WinRM/SSH/WMI) — horizontal spread,
			// distinct from netScan's vertical (many-ports-one-host) view.
			if e.lateralFanout != nil {
				matches = append(matches, e.lateralFanout.Observe(eventEnvelope.AgentID, dstIP, dstPort, evTime)...)
			}
		}
	}

	// Bulk data-exfiltration by volume (T1048): accumulate outbound bytes per
	// external destination; a large cumulative upload is the exfil kill-chain
	// stage that per-connection and beacon rules cannot see. Kept as its own block
	// (not folded into the netScan block) so it composes cleanly with other
	// network detectors. Matches feed the kill chain (exfiltration stage) below.
	if e.exfilVol != nil && eventEnvelope.Type == "network" {
		if dir, _ := flatEvent["direction"].(string); dir != "inbound" {
			dstIP, _ := flatEvent["dst_ip"].(string)
			var bytesSent int64
			if f, ok := toFloat64(flatEvent["bytes_sent"]); ok {
				bytesSent = int64(f)
			}
			matches = append(matches, e.exfilVol.Observe(eventEnvelope.AgentID, dstIP, bytesSent, evTime)...)
		}
	}

	// Stateful cross-query DNS tunneling detection (T1071.004): the per-query
	// structural analyzers (AnalyzeDNSQuery/AnalyzeDGA in typedFindings) miss
	// tunnels whose individual labels look moderate; this counts distinct
	// subdomains per registrable domain per host over a window.
	if e.dnsAgg != nil && eventEnvelope.Type == "dns" {
		if q, _ := flatEvent["query"].(string); q != "" {
			matches = append(matches, e.dnsAgg.Observe(eventEnvelope.AgentID, q, evTime)...)
			// Feed the resolution into C2 fusion: answer IPs (S6 raw-IP guard) and the
			// DGA verdict (S4). Reuses the existing AnalyzeDGA structural analyzer.
			if e.rules != nil {
				e.rules.ObserveDNSForFusion(eventEnvelope.AgentID, dnsAnswerIPs(flatEvent), AnalyzeDGA(q).Suspicious)
			}
		}
	}

	// Fast-flux infrastructure detection (T1568.001): one domain resolving to a
	// rapidly-rotating set of many IPs across unrelated networks — the resilient-C2 /
	// botnet rendezvous pattern the per-query and tunneling analyzers cannot see.
	if e.dnsFastFlux != nil && eventEnvelope.Type == "dns" {
		if q, _ := flatEvent["query"].(string); q != "" {
			if answers := dnsAnswers(flatEvent); len(answers) > 0 {
				matches = append(matches, e.dnsFastFlux.Observe(eventEnvelope.AgentID, q, answers, evTime)...)
			}
		}
	}

	// Multi-signal C2 target correlation: when the SAME target — a destination IP
	// (beacon periodicity / known C2 JA3-JA3S / threat-intel) or a registrable domain
	// (DGA / fast-flux / DNS tunneling) — has been independently flagged by ≥2 orthogonal
	// axes within the window, escalate to a critical, high-confidence C2 alert. Each axis
	// alone is heuristic; their agreement on one target is near-certain C2. Signals may
	// arrive across separate events (beaconing accretes over many connections; DNS axes
	// over many queries), which the correlator's per-target state stitches together.
	if e.c2corr != nil && len(matches) > 0 {
		now := time.Now()
		dstIP := c2DestIP(flatEvent)
		domain := ""
		if q, _ := flatEvent["query"].(string); q != "" {
			domain, _ = registrableAndSub(q)
		}
		domainSignalFired := false
		seen := map[string]bool{}
		for _, m := range matches {
			sig := classifyC2Signal(m)
			if sig == "" || seen[sig] {
				continue
			}
			seen[sig] = true
			if isDomainAxisSignal(sig) {
				if domain != "" {
					domainSignalFired = true
					matches = append(matches, e.c2corr.ObserveSignal(eventEnvelope.AgentID, domain, sig, now)...)
				}
				continue
			}
			// IP-axis signal: correlate on the destination IP.
			if dstIP == "" {
				continue
			}
			matches = append(matches, e.c2corr.ObserveSignal(eventEnvelope.AgentID, dstIP, sig, now)...)
			// Cross-axis bridge: if this IP was recently resolved from a suspicious
			// domain, the IP-axis signal also confirms that domain — folding the two
			// key spaces together (e.g. DGA-domain + beacon-to-its-IP → confirmed C2).
			if e.resLinker != nil {
				if linked := e.resLinker.Domain(eventEnvelope.AgentID, dstIP, now); linked != "" && linked != domain {
					matches = append(matches, e.c2corr.ObserveSignal(eventEnvelope.AgentID, linked, sig, now)...)
				}
			}
		}
		// Record the resolution link when a DNS-axis signal fired: tie this suspicious
		// domain's answer IPs to it so a later IP-axis signal on any of them bridges back.
		if domainSignalFired && e.resLinker != nil {
			if answers := dnsAnswers(flatEvent); len(answers) > 0 {
				e.resLinker.Record(eventEnvelope.AgentID, domain, answers, now)
			}
		}
	}

	// Per-process compromise↔C2 correlation: a process that both runs attacker code
	// (injection/hollowing/memory) or accesses credentials AND conducts C2 is a
	// confirmed active implant. Compromise signals are attributed to every candidate
	// PID of the event (pid/source_pid/target_pid) so whichever process later beacons
	// matches; C2 signals to the connecting pid.
	if e.procThreat != nil && len(matches) > 0 {
		compromise, c2 := false, false
		for _, m := range matches {
			if isCompromiseSignal(m, flatEvent) {
				compromise = true
			}
			if classifyC2Signal(m) != "" {
				c2 = true
			}
		}
		if compromise {
			for _, actor := range candidateActorPIDs(flatEvent) {
				matches = append(matches, e.procThreat.Observe(eventEnvelope.AgentID, actor.PID, actor.Name, procSigCompromise, evTime)...)
			}
		}
		if c2 {
			if actor := eventPID(flatEvent); actor.PID > 0 {
				matches = append(matches, e.procThreat.Observe(eventEnvelope.AgentID, actor.PID, actor.Name, procSigC2, evTime)...)
			}
		}
	}

	// Composite ransomware-precursor scoring: recovery-inhibition (shadow copy/backup
	// deletion), defense/backup-service tampering and broad ACL staging each fire
	// individually, but two or more on one host within minutes is the pre-encryption
	// sequence itself — escalate before mass encryption completes.
	if e.ransomCorr != nil && len(matches) > 0 {
		for _, m := range matches {
			if sig := classifyRansomwareSignal(m); sig != "" {
				matches = append(matches, e.ransomCorr.Observe(eventEnvelope.AgentID, sig, evTime)...)
			}
		}
	}

	// Real-time authentication-attack detection (brute force T1110 / password
	// spray T1110.003). A single failed login is not an attack; these are
	// rate/fan-out phenomena the per-event Sigma rule cannot see. Matches feed the
	// kill chain (credential-access stage) below.
	if e.authAttack != nil && eventEnvelope.Type == "auth" {
		src, _ := flatEvent["source_ip"].(string)
		user, _ := flatEvent["username"].(string)
		success := authSucceeded(flatEvent)
		matches = append(matches, e.authAttack.Observe(eventEnvelope.AgentID, src, user, success, evTime)...)
	}

	// Ransomware-style mass file-operation burst (T1486): one process rapidly
	// modifying/renaming/deleting many distinct files. Behavioral rate, so it
	// catches encryption even when the extension/tooling is unknown.
	if e.fileBurst != nil && eventEnvelope.Type == "file" {
		path, _ := flatEvent["path"].(string)
		if path == "" {
			path, _ = flatEvent["file_path"].(string)
		}
		proc, _ := flatEvent["process_name"].(string)
		if proc == "" {
			proc, _ = flatEvent["image_path"].(string)
		}
		// Ingestion flattens a FileEvent's action to the "operation" key
		// (handler.go: "operation": f.GetAction().String() → e.g. "FILE_ACTION_MODIFY"),
		// NOT "action" (that key is process-event-only). Reading "action" here left
		// the ransomware detector INERT in production — it always saw "" and counted
		// nothing. Read "operation" first, keeping "action" as a fallback for the
		// flat/replay event shape. (isDestructiveFileAction is substring/case-
		// insensitive, so the FILE_ACTION_* enum form matches.)
		action, _ := flatEvent["operation"].(string)
		if action == "" {
			action, _ = flatEvent["action"].(string)
		}
		burst := e.fileBurst.Observe(eventEnvelope.AgentID, proc, path, action, evTime)
		matches = append(matches, burst...)
		// Feed the burst to the ransomware correlator as its encryption-phase axis.
		// On its own the burst is severity 8 and never isolates (benign builds and
		// backups trip it); combined with recovery-inhibition / defense-tampering /
		// ACL-staging on the same host it escalates to the severity-10 auto-isolating
		// composite alert. Fed here rather than through classifyRansomwareSignal so
		// the correlator's own T1486-tagged output cannot re-enter as an axis.
		if e.ransomCorr != nil && len(burst) > 0 {
			matches = append(matches, e.ransomCorr.Observe(eventEnvelope.AgentID, ransomSigMassModify, evTime)...)
		}
	}

	// Sustained-high-CPU / resource-hijacking scoring (T1496). The agent's
	// process_stats snapshot is a JSON array of per-process stats, so it never
	// flattens into the Sigma flat map (FlatMap sees an array, not an object) and
	// no rule can consume it. Feed the raw snapshot to the stateful miner scorer,
	// which folds successive snapshots and alerts only on a PID that pegs the CPU
	// across several consecutive intervals.
	if e.cryptoMiner != nil && eventEnvelope.Type == "process_stats" {
		matches = append(matches, e.cryptoMiner.Observe(eventEnvelope.AgentID, eventEnvelope.Data, evTime)...)
	}

	// Host-enumeration (ATT&CK Discovery) scoring. A single discovery command is
	// near-pure false positive as a standalone alert, so we NEVER raise one per
	// command; instead the recognized technique feeds the kill chain (below) as
	// the "discovery" stage, and a correlated alert fires only on a rapid
	// multi-technique enumeration burst. See discovery.go.
	var discTags []string
	if e.discovery != nil && eventEnvelope.Type == "process" {
		cmd, _ := flatEvent["command_line"].(string)
		tech, dm := e.discovery.Observe(eventEnvelope.AgentID, cmd, evTime)
		if tech != "" {
			discTags = append(discTags, tech)
		}
		matches = append(matches, dm...)
	}

	// Cross-signal kill-chain scoring (correlation): fold the tactics behind every
	// match so far — including weak, tactic-level ones, plus the discovery-command
	// technique above that intentionally never became its own alert — into the
	// host's chain, and raise a correlated multi-stage-attack alert when distinct
	// kill-chain stages accumulate. Runs on the matches computed above (not the
	// kill-chain's own).
	if e.killChain != nil && (len(matches) > 0 || len(discTags) > 0) {
		tags := discTags
		for _, m := range matches {
			tags = append(tags, m.MITRETags...)
		}
		matches = append(matches, e.killChain.Observe(eventEnvelope.AgentID, tags, evTime)...)
	}

	rawEventJSON, _ := json.Marshal(flatEvent)

	for _, match := range matches {
		alert := &StoredAlert{
			ID:          generateAlertID(),
			AgentID:     eventEnvelope.AgentID,
			Hostname:    eventEnvelope.Hostname,
			OS:          eventEnvelope.Platform,
			RuleID:      match.RuleID,
			RuleName:    match.RuleName,
			Severity:    match.Severity,
			Status:      "open",
			Title:       match.Title,
			Description: match.Description,
			RawEvent:    json.RawMessage(rawEventJSON),
			CreatedAt:   time.Now(),
			UpdatedAt:   time.Now(),
			EventIDs:    evidenceEventIDs(eventEnvelope.EventID),
		}
		// Propagate MITRE ATT&CK techniques. The primary (most-specific, first)
		// technique → mitre_technique; the FULL set → ai_mitre_tags so a single
		// correlation alert (e.g. the discovery burst → T1033/T1057/T1082/…) is
		// credited for every technique it detected, not just the first tag.
		if len(match.MITRETags) > 0 {
			alert.MITRETech = match.MITRETags[0]
			alert.MITRETags = match.MITRETags
		}

		// Time-window dedup: collapse the same finding re-asserting on every event
		// (e.g. an exposed-RDP state condition matching each RDP flow) into one
		// alert per alertDedupWindow. Keyed on agent+title so distinct findings and
		// distinct correlation variants (e.g. "4段" vs "5段" kill-chain) stay separate.
		// Runs before suppression/save/response so duplicates skip the full pipeline,
		// matching AlertPipeline semantics.
		if e.isDuplicateAlert(alert.AgentID + "\x00" + alert.Title) {
			metrics.AlertsDeduped.WithLabelValues(sourceLabel(match.RuleType)).Inc()
			continue
		}

		// Check suppression rules before saving
		if e.suppression != nil {
			if suppressed, ruleName, ruleID := e.suppression.IsSuppressed(alert); suppressed {
				slog.Debug("アラートが抑制されました", "suppression_rule", ruleName, "rule", match.RuleName, "agent", alert.AgentID)
				if e.suppressionHit != nil {
					e.suppressionHit.IncrHitCount(ctx, ruleID)
				}
				continue
			}
		}

		// Save initial alert
		e.enrichAnomalyScore(alert)
		if err := e.store.SaveAlert(ctx, alert); err != nil {
			slog.Error("save alert failed", "error", err, "source", match.RuleType, "rule", match.RuleName)
			metrics.AlertInsertFailures.WithLabelValues(sourceLabel(match.RuleType)).Inc()
			continue
		}
		metrics.AlertsCreated.Add(1)

		// Per-engine detection counter for dashboards (which layers actually fire).
		engineLabel := match.RuleType
		if engineLabel == "" {
			engineLabel = "unknown"
		}
		mitreLabel := "none"
		if alert.MITRETech != "" {
			mitreLabel = alert.MITRETech
		}
		metrics.DetectionsByEngine.WithLabelValues(engineLabel, mitreLabel).Inc()

		// Forward to SIEM targets asynchronously
		if e.siemForwarder != nil {
			payload := &SIEMAlertPayload{
				ID:             alert.ID,
				AgentID:        alert.AgentID,
				Hostname:       alert.Hostname,
				OS:             alert.OS,
				RuleName:       alert.RuleName,
				Severity:       alert.Severity,
				Status:         alert.Status,
				MITRETechnique: alert.MITRETech,
				CreatedAt:      alert.CreatedAt,
			}
			go e.siemForwarder.Forward(context.Background(), payload)
		}

		// Publish initial alert to NATS for WebSocket broadcast
		e.publishAlert(ctx, alert)

		// Send external notifications (email/Slack/webhook) for high severity
		if e.notifier != nil && alert.Severity >= 5 {
			go e.sendNotification(ctx, alert, nil)
		}

		// Apply rule-based auto-response (fast, no AI)
		e.applyRuleBasedResponse(ctx, alert, &eventEnvelope, match)

		// Execute matching response playbooks
		if e.playbooks != nil {
			e.playbooks.Run(ctx, alert)
		}

		// Trigger AI analysis for high-severity events, OR for high behavioral-
		// anomaly alerts when an anomaly threshold is configured (ML-guided triage).
		// AIAnalysisMinAnomalyScore defaults to 0 = disabled, so this adds no AI
		// cost unless an operator opts in by setting a threshold (>0).
		shouldAnalyze := match.Severity >= e.config.AIAnalysisMinSeverity ||
			(e.config.AIAnalysisMinAnomalyScore > 0 && alert.AnomalyScore >= e.config.AIAnalysisMinAnomalyScore)

		if shouldAnalyze && e.aiAgent != nil {
			go e.runAIAnalysis(ctx, alert, &eventEnvelope)
		}
	}

	return nil
}

// applyRuleBasedResponse executes immediate auto-response based on rule config
// (without waiting for AI analysis).
// enrichAnomalyScore updates the per-agent behavioral profile (UEBA) from this
// alert and stamps the alert with the entity's current anomaly score (0–1),
// populating the previously-unused StoredAlert.AnomalyScore / alerts.anomaly_score.
// This turns each alert from a bare rule verdict into "…and this agent is N%
// anomalous", accumulating off-hours / privilege-escalation / exfil / volume
// signals across alerts (the UEBA + Isolation Forest were trained but never
// consulted on live events). Lightweight, no AI cost (AI gating uses severity,
// not anomaly score). No-op if the behavioral engine is absent or the score was
// already set (e.g. by a dedicated ML path).
func (e *Engine) enrichAnomalyScore(alert *StoredAlert) {
	if alert == nil || alert.AgentID == "" || alert.AnomalyScore != 0 {
		return
	}
	if e.behavioral == nil || e.behavioral.UEBA == nil {
		return
	}
	ts := alert.CreatedAt
	if ts.IsZero() {
		ts = time.Now()
	}
	hour := ts.Hour()
	tag := strings.ToLower(alert.MITRETech + " " + alert.Title)
	feat := ml.UserBehaviorFeatures{
		LoginHour:  hour,
		NewAlerts:  1,
		IsOffHours: hour < 6 || hour >= 22,
		PrivilegeEscal: strings.Contains(tag, "privilege") || strings.Contains(tag, "権限昇格") ||
			strings.Contains(tag, "t1068") || strings.Contains(tag, "t1134") || strings.Contains(tag, "t1548"),
		MassDownload: strings.Contains(tag, "exfil") || strings.Contains(tag, "collection") ||
			strings.Contains(tag, "t1048") || strings.Contains(tag, "大量"),
	}
	if strings.Contains(tag, "brute") || strings.Contains(tag, "t1110") ||
		strings.Contains(tag, "login_failed") || strings.Contains(tag, "ログイン失敗") {
		feat.FailedLogins = 1
	}
	e.behavioral.UEBA.UpdateProfile(alert.AgentID, "agent", feat)
	alert.AnomalyScore = e.behavioral.UEBA.GetRiskScore(alert.AgentID) / 100.0
}

func (e *Engine) applyRuleBasedResponse(ctx context.Context, alert *StoredAlert, evt *EventEnvelope, match *detectionrules.RuleMatch) {
	if !e.config.AutoResponseEnabled {
		return
	}

	// Auto-isolation is authorised by EITHER source:
	//
	//  1. The DB rule the alert came from (rules.auto_isolate), looked up by ID.
	//  2. The match itself (RuleMatch.AutoIsolate), set by the stateful correlators.
	//
	// Only (1) used to be consulted, and it is reachable only when alert.RuleID
	// identifies a loaded DB rule. The correlators — ransomware_correlator,
	// c2_correlator, process_threat_correlator — all emit RuleID:"" because they
	// are code, not rows, so GetRule("") returned nil and this function returned
	// before ever reading their AutoIsolate flag. Every one of them sets
	// AutoIsolate:true at severity 10 on a multi-signal confirmation (the
	// pre-encryption ransomware sequence, a C2 channel confirmed on ≥N orthogonal
	// axes, an implant showing both host-compromise behaviour and C2 on one PID) —
	// precisely the cases where isolation is meant to be automatic, and precisely
	// the cases that never fired. Honour the match's own flag so those decisions
	// take effect, while keeping the DB-rule path intact.
	autoIsolate := match != nil && match.AutoIsolate
	ruleLabel := alert.RuleName

	e.mu.RLock()
	rule := e.rules.GetRule(alert.RuleID)
	e.mu.RUnlock()

	if rule != nil && rule.AutoIsolate {
		autoIsolate = true
		ruleLabel = rule.Name
	}

	// Immediate isolation for critical rules
	threshold := e.config.AutoIsolateSeverityThreshold
	if autoIsolate && alert.Severity >= threshold {
		// The DB-rule path guaranteed a non-nil commander implicitly (a loaded rule
		// meant a fully wired engine); the correlator path does not, so check.
		if e.commander == nil {
			return
		}

		// severity は検知器が自分で決める値なので、誤検知が 10 を出せばそのまま
		// 端末が止まる。判定の質はここでは直せないので、被害の大きさを抑える。
		if e.isoGuard != nil {
			if v := e.isoGuard.allow(alert.AgentID); !v.allow {
				e.isoGuard.logRefusal(alert.AgentID, ruleLabel, v.reason)
				return
			}
			if e.isoGuard.isDryRun() {
				// 何が止まるはずだったかを先に見るための状態。実際には隔離しない。
				slog.Warn("自動隔離（ドライラン）: 実際には隔離していません",
					"agent", alert.AgentID, "rule", ruleLabel, "severity", alert.Severity)
				return
			}
		}

		reason := fmt.Sprintf("ルールベース自動隔離: %s (重大度: %d)", ruleLabel, alert.Severity)
		if err := e.commander.IsolateEndpoint(ctx, alert.AgentID, reason, alert.ID, ""); err != nil {
			slog.Error("auto isolate failed", "agent", alert.AgentID, "error", err)
		} else {
			e.logAction(ctx, alert.ID, alert.AgentID, "isolate", "", reason, "auto_rule", true, "")
			slog.Info("endpoint isolated", "agent", alert.AgentID, "rule", ruleLabel)
		}
	}
}

// runAIAnalysis sends the alert to Claude for deep analysis.
func (e *Engine) runAIAnalysis(ctx context.Context, stored *StoredAlert, evt *EventEnvelope) {
	aiCtx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()

	alert := &Alert{
		ID:                  stored.ID,
		AgentID:             stored.AgentID,
		Hostname:            stored.Hostname,
		OS:                  stored.OS,
		RuleName:            stored.RuleName,
		Severity:            stored.Severity,
		DetectedAt:          stored.CreatedAt,
		AnomalyScore:        0,
		TriggerEvent:        evt.FlatMap(),
		RelatedEvents:       nil,
		AutoResponseEnabled: e.config.AutoResponseEnabled,
	}

	analysis, err := e.aiAgent.AnalyzeThreat(aiCtx, alert)
	if err != nil {
		slog.Error("AI analysis failed", "alert", stored.ID, "error", err)
		return
	}

	// Update alert with AI analysis
	updatedStatus := "open"
	if analysis.IsFalsePositive {
		updatedStatus = "false_positive"
	} else if analysis.IsThreat && analysis.Severity >= 7 {
		updatedStatus = "investigating"
	}

	if err := e.store.UpdateAlert(aiCtx, stored.ID, AlertUpdate{
		Status:     &updatedStatus,
		AIAnalysis: analysis,
		UpdatedAt:  time.Now(),
	}); err != nil {
		slog.Error("update alert with AI analysis failed", "alert", stored.ID, "error", err)
	}

	// Publish updated alert for real-time dashboard refresh
	stored.AIAnalysis = analysis
	stored.Status = updatedStatus
	e.publishAlert(aiCtx, stored)

	// Re-notify with AI enrichment (skip false positives).
	// Use a fresh background context: aiCtx is cancelled by defer when this function
	// returns, which would kill the goroutine's HTTP/SMTP call mid-flight.
	if e.notifier != nil && !analysis.IsFalsePositive {
		go e.sendNotification(context.Background(), stored, analysis)
	}

	slog.Info("AI analysis complete",
		"alert", stored.ID,
		"is_threat", analysis.IsThreat,
		"severity", analysis.Severity,
		"confidence", analysis.Confidence,
	)
}

// sendNotification fans out an alert to external channels (email/Slack/webhook).
// analysis may be nil for initial (pre-AI) notifications.
func (e *Engine) sendNotification(ctx context.Context, alert *StoredAlert, analysis *ThreatAnalysis) {
	n := &notification.AlertNotification{
		AlertID:   alert.ID,
		Title:     alert.Title,
		Severity:  alert.Severity,
		Status:    alert.Status,
		Hostname:  alert.Hostname,
		OS:        alert.OS,
		RuleName:  alert.RuleName,
		CreatedAt: alert.CreatedAt,
	}

	if analysis != nil {
		n.Summary = analysis.Summary
		isThreat := analysis.IsThreat
		n.AIIsThreat = &isThreat
	}

	notifyCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	e.notifier.Notify(notifyCtx, n)
}

func (e *Engine) publishAlert(ctx context.Context, alert *StoredAlert) {
	if e.nats == nil {
		return // NATS not wired (e.g. unit tests exercising the detection path only)
	}
	data, _ := json.Marshal(alert)
	if err := e.nats.Publish("alerts."+alert.ID, data); err != nil {
		slog.Warn("publish alert failed", "error", err)
	}
}

func (e *Engine) logAction(ctx context.Context, alertID, agentID, actionType, target, reason, executedBy string, success bool, errMsg string) {
	_ = e.store.SaveResponseAction(ctx, &ResponseActionLog{
		ID:         generateAlertID(),
		AlertID:    alertID,
		AgentID:    agentID,
		ActionType: actionType,
		Target:     target,
		Reason:     reason,
		ExecutedBy: executedBy,
		Success:    success,
		Error:      errMsg,
		ExecutedAt: time.Now(),
	})
}

// EventEnvelope is the canonical normalized event schema shared between
// the ingestion service (publisher) and the detection engine (consumer).
// JSON tags MUST match NormalizedEvent in ingestion/handler.go exactly.
type EventEnvelope struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	Platform string `json:"platform"`
	Type     string `json:"type"`
	// EventID is the events.event_id of the row ingestion persisted this event as.
	// Empty when the publisher predates the field; treat that as "unknown", never
	// as an error.
	EventID   string    `json:"event_id,omitempty"`
	Timestamp time.Time `json:"timestamp"`
	// Data holds the JSON-encoded proto Event; unmarshaled on demand for rule evaluation.
	Data json.RawMessage `json:"data"`
}

// EventTime returns the moment the event actually occurred on the endpoint, for
// scoring the stateful rate/burst detectors. Falls back to the wall clock only
// when the producer sent no timestamp — scoring a replayed backlog by wall clock
// squeezes hours of history into one instant and trips every rate threshold.
func (e *EventEnvelope) EventTime() time.Time {
	if !e.Timestamp.IsZero() {
		return e.Timestamp
	}
	return time.Now()
}

// FlatMap converts the envelope into a flat map[string]interface{} suitable
// for Sigma rule evaluation. It merges envelope-level fields (agent_id, platform)
// with the inner event data fields.
func (e *EventEnvelope) FlatMap() map[string]interface{} {
	// Start with envelope metadata
	flat := map[string]interface{}{
		"agent_id": e.AgentID,
		"hostname": e.Hostname,
		"platform": e.Platform,
		"type":     e.Type,
	}

	// Merge inner event data (JSON-encoded proto Event)
	if len(e.Data) > 0 {
		var inner map[string]interface{}
		if err := json.Unmarshal(e.Data, &inner); err == nil {
			mergeProtoEvent(flat, inner)
		}
	}
	return flat
}

// mergeProtoEvent flattens nested proto-JSON structures into the sigma flat map.
// Handles three formats:
//  1. protojson: {"process": {...}, "file": {...}, ...}
//  2. standard encoding/json of proto oneof: {"Payload": {"Process": {...}}}
//  3. normalizeEventData flat format: {"process_name": ..., "command_line": ..., ...}
func mergeProtoEvent(flat map[string]interface{}, inner map[string]interface{}) {
	// Format 1: protojson — lowercase sub-object key
	for _, key := range []string{"process", "file", "network", "dns", "registry", "auth"} {
		if sub, ok := inner[key].(map[string]interface{}); ok {
			for k, v := range sub {
				flat[k] = v
			}
			addSigmaAliases(flat)
			return
		}
	}
	// Format 2: standard encoding/json of proto oneof — {"Payload": {"Process": {...}}}
	if payload, ok := inner["Payload"].(map[string]interface{}); ok {
		for _, key := range []string{"Process", "File", "Network", "Dns", "Registry", "Auth"} {
			if sub, ok := payload[key].(map[string]interface{}); ok {
				for k, v := range sub {
					flat[k] = v
				}
				addSigmaAliases(flat)
				return
			}
		}
	}
	// Format 3: flat event (normalizeEventData or unknown) — copy directly
	for k, v := range inner {
		flat[k] = v
	}
	addSigmaAliases(flat)
}

// addSigmaAliases applies the canonical Sigma field-normalization to an event the
// detection engine flattened (DB / SigmaHQ-synced rules + IOC + SequenceEngine).
//
// It delegates to addPipelineSigmaAliases (alert_pipeline.go) so the detection
// server and the API AlertPipeline share ONE alias layer. Previously this was a
// separate, smaller map that omitted registry (TargetObject/Details/EventType),
// image_load (ImageLoaded/Signed/Signer), script (ScriptBlockText), the Hashes
// synthesis and the Image basename normalization — exactly the SigmaHQ sync
// categories (registry/image_load/powershell). The drift meant synced rules in
// those categories silently never matched on the detection server even when
// enabled. Unifying on the superset is the prerequisite for curate-enabling
// SigmaHQ rules (roadmap P1 Phase A).
func addSigmaAliases(flat map[string]interface{}) {
	addPipelineSigmaAliases(flat)
}

func generateAlertID() string {
	return uuid.New().String()
}

// severityStringToInt maps ML severity strings to integer severity levels.
func severityStringToInt(s string) int {
	switch s {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	default:
		return 5
	}
}

// benignLinuxTracerPrefixes are process comms (TASK_COMM_LEN=16, so comms are
// truncated to 15 chars) of system components that legitimately ptrace / read
// other processes' memory constantly on a normal Linux host. Prefix-matched so
// truncated comms (e.g. "landscape-sysin", "containerd-shim") and worker suffixes
// (e.g. "runc:[1:CHILD]") are covered. The Linux eBPF LSM ptrace_access_check
// sensor fires on all of these; without this allowlist they would drown real
// credential-dumping / injection in false positives.
var benignLinuxTracerPrefixes = []string{
	"systemd",    // journal, logind, udevd, oomd, resolved, networkd, PID1
	"runc",       // container runtime (incl. "runc:[1:CHILD]")
	"containerd", // containerd, containerd-shim*
	"dockerd", "docker-", "moby",
	"landscape", // landscape-sysinfo (Ubuntu telemetry)
	"snapd", "snap-",
	"polkitd", "packagekitd", "udevadm", "dbus-daemon",
	"kizashi-agent", // the EDR agent self (defence-in-depth; agent also self-excludes)
	"gmain", "gdbus", "pool-",
}

// ptraceModeIsAttach reports whether a "ptrace_mode=0x.." access mask has the
// PTRACE_MODE_ATTACH bit (0x02) set. ATTACH is required by the kernel to read
// another process's memory — process_vm_readv, open("/proc/<pid>/mem"), and
// PTRACE_ATTACH all go through ptrace_may_access with PTRACE_MODE_ATTACH_* — i.e.
// the actual credential-dump / injection primitive (mimikatz-linux, gdb, strace,
// procdump). READ-only accesses (/proc/<pid>/{stat,status,cmdline} that ps/top/
// pgrep issue for every pid) carry PTRACE_MODE_READ (0x01) WITHOUT the ATTACH bit
// (e.g. 0x0d = READ|NOAUDIT|FSCREDS) and are the benign /proc-enumeration firehose.
// Unparseable masks fail-open (keep alerting) so a format change never silently
// drops a real detection.
func ptraceModeIsAttach(accessMask string) bool {
	const ptraceModeAttach = 0x02
	v := strings.TrimSpace(strings.TrimPrefix(accessMask, "ptrace_mode="))
	n, err := strconv.ParseUint(v, 0, 64)
	if err != nil {
		return true // fail-open: unparseable → do not suppress
	}
	return n&ptraceModeAttach != 0
}

// isBenignLinuxTracer reports whether comm is a known-benign system tracer that
// should not by itself raise a credential-access alert.
func isBenignLinuxTracer(comm string) bool {
	c := strings.ToLower(strings.TrimSpace(comm))
	if c == "" || c == "不明" {
		return true // no attributable accessor — do not alert on the firehose
	}
	for _, p := range benignLinuxTracerPrefixes {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}

// benignMemoryRegionProcesses are long-running system daemons that routinely
// present an unbacked, NON-writable (r-x) executable region — typically a mapped
// shared object the memory scanner could not attribute to a file (overlay/deleted
// path), not floating code. Comms are TASK_COMM_LEN=16 (15 visible chars), so the
// entries are the truncated forms and matched by prefix. This only gates the WEAK
// signal (unbacked & !writable & !rwx & no YARA); an actual W^X region, a YARA hit,
// or the same finding in any process NOT on this list still alerts.
var benignMemoryRegionProcesses = []string{
	"unattended-upgr", // unattended-upgrades (Ubuntu automatic security updates)
	"networkd-dispat", // networkd-dispatcher
	"update-notifier",
	"update-manager",
	"cloud-init",
	"landscape-sysin", // landscape-sysinfo
	"apport",          // Ubuntu crash reporter
	"packagekitd",
	"fwupd", // firmware update daemon
}

// isBenignMemoryRegionProcess reports whether a process is a known-benign system
// daemon whose unbacked non-writable executable region is a scanner artifact, not
// injection. Used only to suppress the weak floating-code signal (see the memory
// branch in typedFindings).
func isBenignMemoryRegionProcess(proc string) bool {
	c := strings.ToLower(strings.TrimSpace(proc))
	if c == "" {
		return false // unattributable → do not suppress
	}
	c = strings.TrimPrefix(c, `\`) // agent sometimes prefixes Image with a backslash
	for _, p := range benignMemoryRegionProcesses {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}

// sensitiveCredTargetPrefixes are processes whose memory, if read by a
// non-allowlisted tracer, warrants a higher severity: they hold credentials or
// are security-critical.
var sensitiveCredTargetPrefixes = []string{
	"sshd", "ssh-agent", "gpg-agent", "gnome-keyring", "polkitd",
	"vaultd", "vault", "systemd-logind", "login", "sudo", "su",
	"kizashi-agent",
}

// isSensitiveCredTarget reports whether the accessed process is credential-bearing
// or security-critical.
func isSensitiveCredTarget(comm string) bool {
	c := strings.ToLower(strings.TrimSpace(comm))
	for _, p := range sensitiveCredTargetPrefixes {
		if strings.HasPrefix(c, p) {
			return true
		}
	}
	return false
}

// dnsAnswerIPs extracts the resolved IP strings from a flattened DNS event's "answers"
// field (a []interface{} of strings, per the agent's DNS telemetry). Used to feed C2
// fusion's raw-IP (S6) and DGA-association (S4) bookkeeping.
func dnsAnswerIPs(flatEvent map[string]interface{}) []string {
	raw, ok := flatEvent["answers"].([]interface{})
	if !ok || len(raw) == 0 {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, a := range raw {
		if s, ok := a.(string); ok && s != "" {
			out = append(out, s)
		}
	}
	return out
}

// detEnvInt reads a positive integer from the environment, falling back to def
// when the variable is unset, empty, non-numeric, or non-positive.
func detEnvInt(key string, def int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}
