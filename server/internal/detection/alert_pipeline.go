// Package detection — AlertPipeline subscribes to NATS event subjects and runs
// events through the SigmaEvaluator, IOCMatcher, and StatAnomalyDetector to
// generate alerts and UEBA anomaly records in real time.
package detection

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/server/internal/correlation"
	"github.com/edr-platform/server/internal/metrics"
	"github.com/edr-platform/server/internal/remediation"
	"github.com/edr-platform/server/internal/store"
	"github.com/edr-platform/server/internal/wsbus"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// ─── Pipeline ────────────────────────────────────────────────

// AlertPipeline subscribes to NATS event subjects and generates alerts using
// the detection engines wired into the pipeline.
type AlertPipeline struct {
	pool        *pgxpool.Pool
	nc          *nats.Conn
	sigma       *SigmaEvaluator
	ioc         *IOCMatcher // existing IOCMatcher from ioc_matcher.go
	anomaly     *StatAnomalyDetector
	remediation *remediation.Engine  // optional; wired via SetRemediationEngine
	corr        *correlation.Engine  // optional; wired via SetCorrelationEngine
	parents     *parentResolver      // resolves ParentImage from ppid for Sigma rules
	custom      *CustomRuleEvaluator // ユーザー定義ルール (custom_alert_rules)
	// suppression は運用者が作った抑制ルール。nil = 抑制無効。
	// server-detect (Engine) は最初からこれを見ていたが、こちら (server-api) は
	// 見ていなかった——SetSuppressionMatcher のコメントを参照。
	suppression    *SuppressionMatcher
	suppressionHit SuppressionHitCounter
	// selfRemediation drops alerts caused by our own containment. nil = disabled.
	selfRemediation *SelfRemediationSuppressor
	dedupMu         sync.Mutex
	dedupCache      map[string]time.Time // key → last alert time
}

// NewAlertPipeline creates an AlertPipeline with freshly initialised detection engines.
// Call GetSigmaEvaluator() to obtain the SigmaEvaluator for rule loading before Start().
func NewAlertPipeline(pool *pgxpool.Pool, nc *nats.Conn) *AlertPipeline {
	return &AlertPipeline{
		pool:       pool,
		nc:         nc,
		sigma:      NewSigmaEvaluator(),
		anomaly:    NewStatAnomalyDetector(),
		parents:    newParentResolver(),
		custom:     NewCustomRuleEvaluator(),
		dedupCache: make(map[string]time.Time),
		// IOCMatcher is not wired here — the existing Engine already owns one.
		// AlertPipeline uses its own sigma + anomaly engines only.
	}
}

// SetSuppressionMatcher wires the operator-authored suppression rules into this
// pipeline. Call before Start(); nil disables suppression.
//
// ★ これが無いと、運用者が UI で作った抑制ルールが**効かない**。
//
// 抑制エンジン自体は前からあり、server-detect の Engine は起動時からそれを見て
// いた。ところが P4-6 (#647) で DB Sigma ルールの所有権が server-api に移り、
// リアルタイムのアラートはほぼ全部この AlertPipeline が作るようになった。
// **抑制を効かせる側と、アラートを作る側が入れ替わった**わけだが、結線は
// 移らなかった。結果として「抑制ルールを作ったのにアラートが止まらない」状態が
// 残る——しかも UI 上はルールが有効に見えるので、壊れていること自体が見えない。
//
// 同じ matcher / 同じローダを使うので、両プロセスは同じルールを見る。
// SetSelfRemediationSuppressor wires the self-inflicted-alert filter. nil は無効。
func (p *AlertPipeline) SetSelfRemediationSuppressor(s *SelfRemediationSuppressor) {
	p.selfRemediation = s
}

func (p *AlertPipeline) SetSuppressionMatcher(m *SuppressionMatcher, hits SuppressionHitCounter) {
	p.suppression = m
	p.suppressionHit = hits
}

// SetRemediationEngine wires a remediation.Engine so that every new alert
// automatically triggers matching remediation rules.
// Call this before Start(); safe to call with nil (disables auto-remediation).
func (p *AlertPipeline) SetRemediationEngine(e *remediation.Engine) {
	p.remediation = e
}

// SetCorrelationEngine wires a correlation.Engine so that every new alert is
// fed into the sliding-window incident correlator.
// Call this before Start(); safe to call with nil (disables correlation).
func (p *AlertPipeline) SetCorrelationEngine(e *correlation.Engine) {
	p.corr = e
}

// isDuplicate returns true if an alert with the same key fired within the window.
// Thread-safe via dedupMu.
func (p *AlertPipeline) isDuplicate(key string, window time.Duration) bool {
	p.dedupMu.Lock()
	defer p.dedupMu.Unlock()
	if last, ok := p.dedupCache[key]; ok && time.Since(last) < window {
		return true
	}
	p.dedupCache[key] = time.Now()
	return false
}

// GetSigmaEvaluator returns the SigmaEvaluator used by this pipeline so that
// callers can load rules before starting the pipeline.
func (p *AlertPipeline) GetSigmaEvaluator() *SigmaEvaluator {
	return p.sigma
}

// ReloadSigmaRules atomically replaces all Sigma rules (builtins + DB) without
// restarting the pipeline. Call this after API writes to detection_rules so the
// live pipeline picks up the change immediately.
func (p *AlertPipeline) ReloadSigmaRules() {
	if err := p.sigma.ReloadFromDB(p.pool); err != nil {
		metrics.BackgroundFailed("alert_pipeline", err, "alert_pipeline: sigma rule reload failed")
		return
	}
	slog.Info("alert_pipeline: sigma rules reloaded", "count", p.sigma.RuleCount())
}

// GetAnomalyDetector returns the StatAnomalyDetector used by this pipeline.
func (p *AlertPipeline) GetAnomalyDetector() *StatAnomalyDetector {
	return p.anomaly
}

// pipelineSubjects are the event subjects the AlertPipeline consumes. Events are
// published as events.<agentID>.<type> (ingestion/handler.go).
//
// This list is DERIVED, not hand-written. The AlertPipeline is the only evaluator
// that loads the built-in Sigma rule set, so an event type missing from this
// filter makes every built-in rule targeting it structurally dark — the sensor
// emits, ingestion publishes, the DB stores it, and the rule is simply never
// reached. Hand-maintaining the list is what produced exactly that: it listed
// four types while eventTypeCategories (sigma_category.go) declares fourteen,
// so the built-in ps_script, image_load, dns_query, authentication,
// create_remote_thread, process_access, pipe_created, wmi_event and device_event
// rules could not fire in production regardless of their content.
//
// eventTypeCategories is the right source because it is precisely "the event
// types a built-in rule may legitimately match", maintained against the rule
// corpus. Subscribing to a type nothing publishes yet is harmless (the filter
// simply never matches), and it means a new sensor's rules work the day the
// sensor lands instead of failing silently until someone runs a live test.
//
// Types deliberately NOT here are those with no Sigma rules at all
// (process_stats, process_block, memory, resource_usage): they are handled by
// engine.go's typedFindings path, and feeding this pipeline high-rate pure
// telemetry would cost throughput for no detection.
var pipelineSubjects = buildPipelineSubjects()

func buildPipelineSubjects() []string {
	out := make([]string, 0, len(eventTypeCategories))
	for evType := range eventTypeCategories {
		out = append(out, "events.*."+evType)
	}
	// Stable order: FilterSubjects is part of the durable consumer's config, and
	// map iteration order would make CreateOrUpdateConsumer look like a config
	// change on every restart.
	sort.Strings(out)
	return out
}

// Start consumes events and runs them through the detection engines until ctx
// is cancelled. It prefers a DURABLE JetStream consumer on the EVENTS stream so
// a burst (e.g. a discovery flood, or a real attack spawning many processes)
// cannot silently drop events the way a core-NATS subscription does — JetStream
// paces delivery to the consumer and redelivers un-acked messages. If JetStream
// is unavailable it falls back to the original core-NATS subscription.
func (p *AlertPipeline) Start(ctx context.Context) error {
	js, err := jetstream.New(p.nc)
	if err != nil {
		metrics.BackgroundFailed("alert_pipeline", err, "alert_pipeline: JetStream unavailable — falling back to core NATS (events may drop under burst)")
		return p.startCoreNATS(ctx)
	}
	stream, err := js.Stream(ctx, "EVENTS")
	if err != nil {
		metrics.BackgroundFailed("alert_pipeline", err, "alert_pipeline: EVENTS stream not found — falling back to core NATS")
		return p.startCoreNATS(ctx)
	}
	consumer, err := stream.CreateOrUpdateConsumer(ctx, jetstream.ConsumerConfig{
		Durable:        "alert-pipeline",
		FilterSubjects: pipelineSubjects,
		AckPolicy:      jetstream.AckExplicitPolicy,
		MaxDeliver:     3,
		// New consumer: start at the head of the stream, NOT DeliverAll — the
		// stream retains 7 days of events and replaying them would emit a flood
		// of stale alerts on first deploy.
		DeliverPolicy: jetstream.DeliverNewPolicy,
	})
	if err != nil {
		metrics.BackgroundFailed("alert_pipeline", err, "alert_pipeline: durable consumer create failed — falling back to core NATS")
		return p.startCoreNATS(ctx)
	}

	sem := make(chan struct{}, 20) // bound concurrent event processing
	cc, err := consumer.Consume(func(msg jetstream.Msg) {
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			p.handleEvent(ctx, msg.Subject(), msg.Data())
			// Best-effort: ack after processing. Redelivery on crash before ack
			// is de-duplicated by isDuplicate, so at-least-once is safe.
			_ = msg.Ack()
		}()
	})
	if err != nil {
		metrics.BackgroundFailed("alert_pipeline", err, "alert_pipeline: consume failed — falling back to core NATS")
		return p.startCoreNATS(ctx)
	}
	defer cc.Stop()

	slog.Info("alert_pipeline: started (JetStream durable consumer 'alert-pipeline')", "subjects", pipelineSubjects)
	<-ctx.Done()
	return nil
}

// startCoreNATS is the fallback path: a plain core-NATS subscription (at-most-once;
// may drop under burst). Used only when JetStream is unavailable.
func (p *AlertPipeline) startCoreNATS(ctx context.Context) error {
	subs := make([]*nats.Subscription, 0, len(pipelineSubjects))
	for _, subj := range pipelineSubjects {
		sub, err := p.nc.Subscribe(subj, func(msg *nats.Msg) {
			p.handleEvent(ctx, msg.Subject, msg.Data)
		})
		if err != nil {
			for _, s := range subs {
				_ = s.Unsubscribe()
			}
			return fmt.Errorf("alert_pipeline: subscribe %s: %w", subj, err)
		}
		subs = append(subs, sub)
		slog.Info("alert_pipeline: subscribed (core NATS)", "subject", subj)
	}
	defer func() {
		for _, s := range subs {
			_ = s.Unsubscribe()
		}
		slog.Info("alert_pipeline: stopped")
	}()
	<-ctx.Done()
	return nil
}

// ─── Event Handler ───────────────────────────────────────────

// handleEvent processes a single NATS event message.
func (p *AlertPipeline) handleEvent(ctx context.Context, subject string, data []byte) {
	var envelope map[string]interface{}
	if err := json.Unmarshal(data, &envelope); err != nil {
		metrics.BackgroundFailed("alert_pipeline", err, "alert_pipeline: failed to parse event JSON", "subject", subject)
		return
	}

	// Flatten NormalizedEvent: copy top-level metadata and merge nested data payload.
	event := flattenNormalizedEvent(envelope)

	// The events.event_id ingestion persisted this event as, recorded on every
	// alert built from it so the alert can be traced back to its evidence.
	// Deliberately NOT merged into `event`: flattenNormalizedEvent copies a fixed
	// allowlist, and "event_id" is already a DETECTION field name (the numeric
	// Windows Event ID, e.g. 5861) — merging the envelope's UUID under that key
	// would silently break every rule selecting on it.
	evidenceID, _ := envelope["event_id"].(string)

	// Resolve the parent image name from ppid so Sigma ParentImage rules can fire.
	// flattenNormalizedEvent already applied the alias layer; re-apply it so the
	// freshly-injected parent_process maps onto ParentImage.
	if p.parents != nil {
		p.parents.enrich(event)
		addPipelineSigmaAliases(event)
	}

	// ── Sigma evaluation ────────────────────────────────────
	for _, match := range p.sigma.EvaluateEvent(event) {
		slog.Info("alert_pipeline: sigma match",
			"rule", match.RuleTitle,
			"level", match.Level,
			"subject", subject,
		)
		p.createAlertFromSigma(ctx, match, event, evidenceID)
	}

	// ── IOC matching via existing IOCMatcher ────────────────
	if p.ioc != nil {
		for _, hit := range p.ioc.CheckEvent(event) {
			slog.Info("alert_pipeline: IOC match",
				"type", hit.IOC.Type,
				"value", hit.Value,
				"field", hit.MatchedOn,
			)
			p.createAlertFromIOC(ctx, hit, event, evidenceID)
		}
	}

	// ── ユーザー定義ルール ──────────────────────────────────
	if p.custom != nil {
		for _, m := range p.custom.EvaluateEvent(event) {
			slog.Info("alert_pipeline: custom rule match",
				"rule", m.Rule.Name, "count", m.Count, "subject", subject)
			p.createAlertFromCustomRule(ctx, m, event, evidenceID)
		}
	}

	// ── UEBA anomaly detection ───────────────────────────────
	p.checkUEBAAnomaly(ctx, event)
}

// GetCustomRuleEvaluator returns the custom rule evaluator so callers can
// load/reload rules from the DB.
func (p *AlertPipeline) GetCustomRuleEvaluator() *CustomRuleEvaluator { return p.custom }

// ReloadCustomRules re-reads custom_alert_rules from the DB.
func (p *AlertPipeline) ReloadCustomRules(ctx context.Context) error {
	if p.custom == nil {
		return nil
	}
	return p.custom.LoadFromDB(ctx, p.pool)
}

// createAlertFromCustomRule inserts an alert for a custom rule that reached its
// threshold.
func (p *AlertPipeline) createAlertFromCustomRule(ctx context.Context, m CustomRuleMatch, event map[string]interface{}, evidenceID string) {
	hostname, _ := event["hostname"].(string)
	agentID, _ := event["agent_id"].(string)

	// Sigma / IOC と同じ 5 分の重複抑制。閾値到達のたびに同じアラートが
	// 積み上がるのを防ぐ。
	if p.isDuplicate("custom:"+agentID+":"+m.Rule.ID, 5*time.Minute) {
		return
	}

	title := m.Rule.AlertTitle
	if title == "" {
		title = m.Rule.Name
	}
	desc := m.Rule.AlertDescription
	if m.Count > 1 {
		desc = fmt.Sprintf("%s (%d件/%d秒)", desc, m.Count, m.Rule.TimeWindowSeconds)
	}
	var mitre string
	if len(m.Rule.MitreTags) > 0 {
		mitre = m.Rule.MitreTags[0]
	}

	alertID, err := p.insertAlert(ctx, insertAlertParams{
		AgentID:     agentID,
		Hostname:    hostname,
		RuleName:    m.Rule.Name,
		Severity:    m.Rule.Severity,
		Title:       title,
		Description: desc,
		Status:      "open",
		MITRETech:   mitre,
		EventIDs:    evidenceEventIDs(evidenceID),
		Suppression: SuppressionContextFrom(event),
	})
	if errors.Is(err, errAlertSuppressed) {
		return // 運用者の抑制ルールに当たった。失敗ではないので計上もログもしない
	}
	if err != nil {
		metrics.BackgroundFailed("alert_pipeline", err, "alert_pipeline: ユーザー定義ルールのアラート登録に失敗しました",
			"rule", m.Rule.Name)
		return
	}
	p.publishAlertCreated(alertID)
}

// ─── Alert Creation ──────────────────────────────────────────

// createAlertFromSigma inserts an alert for a Sigma rule match.
func (p *AlertPipeline) createAlertFromSigma(ctx context.Context, match SigmaMatch, event map[string]interface{}, evidenceID string) {
	hostname, _ := event["hostname"].(string)
	agentID, _ := event["agent_id"].(string)

	// Deduplicate: suppress repeat alerts for the same rule+agent within 5 minutes.
	dedupKey := agentID + ":" + match.RuleTitle
	if p.isDuplicate(dedupKey, 5*time.Minute) {
		return
	}

	// A rule loaded from the `rules` table reports the severity that table
	// declares; only builtins (Severity 0) fall back to deriving one from the
	// Sigma level.
	//
	// This is not cosmetic. server-detect emits the same finding using the same
	// column, and dedup.DedupKey is (title, severity, source, agent) — so while
	// the API said 3 ("low" -> 3) and the engine said 4, the two copies of one
	// detection could never be recognised as duplicates. Title case already did
	// not matter (DedupKey lowercases it); severity was the whole difference.
	// It matters because the engines' copies arrive 7-8 minutes apart on average
	// (measured), far outside the cross-engine pass's 6-minute window — so the
	// 1-hour title pass is the only one that can reach them, and a severity
	// mismatch is enough to keep it from trying.
	severity := match.Severity
	if severity == 0 {
		severity = sigmaLevelToInt(match.Level)
	}

	alertID, err := p.insertAlert(ctx, insertAlertParams{
		AgentID:     agentID,
		Hostname:    hostname,
		RuleName:    match.RuleTitle,
		Severity:    severity,
		Title:       "[Sigma] " + match.RuleTitle,
		Description: fmt.Sprintf("Sigma rule '%s' matched (level: %s)", match.RuleTitle, match.Level),
		Status:      "open",
		MITRETech:   parseMITRETechFromTags(match.Tags),
		EventIDs:    evidenceEventIDs(evidenceID),
		Suppression: SuppressionContextFrom(event),
	})
	if errors.Is(err, errAlertSuppressed) {
		return // 運用者の抑制ルールに当たった。失敗ではないので計上もログもしない
	}
	if err != nil {
		slog.Warn("alert_pipeline: failed to insert sigma alert", "rule", match.RuleTitle, "error", err)
		metrics.AlertInsertFailures.WithLabelValues("sigma").Inc()
		return
	}

	p.publishAlertCreated(alertID)
	wsbus.Global().Broadcast("new_alert", map[string]interface{}{
		"id":       alertID,
		"severity": match.Level,
		"title":    "[Sigma] " + match.RuleTitle,
		"agent_id": agentID,
	})

	if p.remediation != nil {
		go p.remediation.TriggerOnAlert(context.Background(), alertID, agentID, hostname, severity, match.Tags)
	}

	if p.corr != nil {
		eventType, _ := event["type"].(string)
		// Enrich a per-call copy of the event with the matched technique and
		// attack-surface marker so correlation rules can key on them. A copy
		// (not the shared event map) avoids a data race with concurrent Sigma
		// matches mutating the same event and overwriting the marker.
		tech := parseMITRETechFromTags(match.Tags)
		corrData := make(map[string]interface{}, len(event)+2)
		for k, v := range event {
			corrData[k] = v
		}
		corrData["_matched_technique"] = tech
		switch {
		case isCloudTechnique(tech):
			corrData["_attack_surface"] = "cloud"
		case isADTechnique(tech):
			corrData["_attack_surface"] = "ad"
		}
		if isRansomwarePrecursor(tech) {
			corrData["_ransomware_precursor"] = "true"
		}
		if isExfilTechnique(tech) {
			corrData["_exfil_activity"] = "true"
		}
		if isContainerEscalation(tech) {
			corrData["_container_escalation"] = "true"
		}
		if isCredentialTheft(tech) {
			corrData["_credential_theft"] = "true"
		}
		if isDiscoveryRecon(tech) {
			corrData["_discovery_recon"] = "true"
		}
		go func() {
			if inc := p.corr.ProcessAlert(context.Background(), alertID, agentID, eventType, tech, severity, corrData); inc != nil {
				p.publishIncidentCreated(inc.ID, inc.Title, inc.Severity)
			}
		}()
	}
}

// cloudAttackTechniques is the set of ATT&CK techniques whose builtin Sigma rules
// indicate hands-on-keyboard cloud attacker activity (cloud CLI discovery,
// persistence, privilege escalation, defense evasion, and cloud credential
// theft). An alert on any of these marks the event's attack surface as "cloud"
// so the multi-stage cloud correlation rule (corr-006) can chain them.
var cloudAttackTechniques = map[string]bool{
	"T1526":     true, // Cloud Service / IAM Discovery
	"T1580":     true, // Cloud Infrastructure Discovery
	"T1619":     true, // Cloud Storage Object Discovery
	"T1136.003": true, // Cloud Account Creation
	"T1098.001": true, // Additional Cloud Credentials
	"T1098.003": true, // Additional Cloud Roles
	"T1562.008": true, // Disable/Modify Cloud Logs
	"T1562.007": true, // Disable/Modify Cloud Firewall
	"T1578":     true, // Modify Cloud Compute Infrastructure
	"T1552.005": true, // Cloud Instance Metadata API
	"T1552.007": true, // Container/K8s API credentials
	"T1078.004": true, // Valid Accounts: Cloud
}

// isCloudTechnique reports whether a primary ATT&CK technique (as produced by
// parseMITRETechFromTags) belongs to the cloud attack surface.
func isCloudTechnique(tech string) bool {
	return cloudAttackTechniques[strings.ToUpper(tech)]
}

// adAttackTechniques is the set of ATT&CK techniques whose builtin Sigma rules
// indicate hands-on-keyboard Active Directory attacker activity — domain
// reconnaissance, Kerberos credential theft/forging, and credential-material
// lateral movement — i.e. the classic on-prem path to Domain Admin. An alert on
// any of these marks the event's attack surface as "ad" so the multi-stage AD
// correlation rule (corr-007) can chain them.
var adAttackTechniques = map[string]bool{
	// Domain reconnaissance
	"T1482":     true, // Domain Trust Discovery
	"T1087.002": true, // Domain Account Discovery (+ BloodHound/SharpHound)
	"T1018":     true, // Remote System / DC Discovery
	"T1069.002": true, // Domain Group Discovery
	"T1135":     true, // Network Share Discovery
	"T1615":     true, // Group Policy Discovery
	// Kerberos credential access / forging
	"T1558.003": true, // Kerberoasting
	"T1558.004": true, // AS-REP Roasting
	"T1558.001": true, // Golden/Silver Ticket
	// Credential-material lateral movement / replication
	"T1550.002": true, // Pass-the-Hash
	"T1550.003": true, // Pass-the-Ticket
	"T1003.006": true, // DCSync
	"T1207":     true, // DCShadow (rogue DC)
	// Modern AD → Domain Admin: AD CS abuse, coercion, and NTLM relay (the
	// ESC8 coercion → relay → certificate → DA path).
	"T1649":     true, // AD CS Certificate Abuse (Certipy / ESC1-16)
	"T1187":     true, // Authentication Coercion (PetitPotam/Coercer/DFSCoerce)
	"T1557.001": true, // LLMNR/NBT-NS Poisoning & NTLM Relay (Responder/ntlmrelayx)
}

// isADTechnique reports whether a primary ATT&CK technique belongs to the
// on-prem Active Directory attack surface.
func isADTechnique(tech string) bool {
	return adAttackTechniques[strings.ToUpper(tech)]
}

// ransomwarePrecursorTechniques is the set of ATT&CK techniques whose builtin
// Sigma rules fire on the destructive "prep" steps ransomware runs just BEFORE
// mass encryption — inhibiting recovery, stopping services, disabling defenses,
// wiping, and clearing logs. Any two of these in a short window is a strong
// pre-encryption ransomware signal that corr-008 escalates.
var ransomwarePrecursorTechniques = map[string]bool{
	"T1490":     true, // Inhibit System Recovery (vssadmin/wbadmin/bcdedit)
	"T1489":     true, // Service Stop
	"T1562.001": true, // Impair Defenses: Disable Security Tools
	"T1562.004": true, // Impair Defenses: Disable/Modify System Firewall
	"T1485":     true, // Data Destruction
	"T1561":     true, // Disk Wipe
	"T1070.001": true, // Indicator Removal: Clear Windows Event Logs
}

// isRansomwarePrecursor reports whether a primary ATT&CK technique is a
// destructive ransomware pre-encryption step.
func isRansomwarePrecursor(tech string) bool {
	return ransomwarePrecursorTechniques[strings.ToUpper(tech)]
}

// exfilTechniques is the set of ATT&CK techniques whose builtin Sigma rules
// indicate data collection/staging and exfiltration over a channel. Seeing
// collection followed by an exfil channel (or two exfil channels) in a short
// window is data theft in progress, which corr-009 escalates.
var exfilTechniques = map[string]bool{
	"T1560.001": true, // Archive Collected Data via Utility
	"T1071.002": true, // Exfil over FTP/TFTP
	"T1071.003": true, // Exfil over mail protocols
	"T1071.004": true, // DNS tunneling / exfil
	"T1048":     true, // Exfil over alternative protocol
	"T1567.002": true, // Exfil to cloud storage
}

// isExfilTechnique reports whether a primary ATT&CK technique is data
// collection/staging or exfiltration over a channel.
func isExfilTechnique(tech string) bool {
	return exfilTechniques[strings.ToUpper(tech)]
}

// containerEscalationTechniques is the set of ATT&CK techniques whose builtin
// Sigma rules fire on steps of a container-to-host or container-to-cluster
// breakout — deploying a privileged container, escaping to the host namespace,
// running commands inside containers, and stealing the in-pod Kubernetes
// service-account token. Any two of these in a short window is an active
// container breakout that corr-010 escalates.
var containerEscalationTechniques = map[string]bool{
	"T1610":     true, // Deploy Container (privileged / host namespace)
	"T1611":     true, // Escape to Host
	"T1609":     true, // Container Administration Command (exec)
	"T1552.007": true, // Container/K8s API credentials (service-account token)
	"T1613":     true, // Container and Resource Discovery
}

// isContainerEscalation reports whether a primary ATT&CK technique is a step in
// a container-to-host / container-to-cluster breakout.
func isContainerEscalation(tech string) bool {
	return containerEscalationTechniques[strings.ToUpper(tech)]
}

// credentialTheftTechniques is the set of ATT&CK techniques whose builtin Sigma
// rules fire on credential harvesting from a specific source — OS credential
// stores (LSASS/SAM/LSA/NTDS/DCC2/DCSync), password/credential stores
// (browsers, Credential Manager, keychain), and unsecured credentials (files,
// registry, GPP, shell history, cloud metadata). Two or more of these in a short
// window is multi-source credential theft by a hands-on operator that corr-011
// escalates — distinct from corr-002 (one technique fanning across ≥3 agents).
var credentialTheftTechniques = map[string]bool{
	// OS Credential Dumping (T1003.*)
	"T1003.001": true, // LSASS memory
	"T1003.002": true, // Security Account Manager (SAM)
	"T1003.003": true, // NTDS.dit
	"T1003.004": true, // LSA secrets
	"T1003.005": true, // Cached domain credentials (DCC2)
	"T1003.006": true, // DCSync
	"T1003.007": true, // Proc filesystem memory
	"T1003.008": true, // /etc/passwd and /etc/shadow
	// Credentials from Password Stores (T1555.*)
	"T1555.001": true, // Keychain
	"T1555.003": true, // Credentials from web browsers
	"T1555.004": true, // Windows Credential Manager
	"T1555.005": true, // Password managers
	// Unsecured Credentials (T1552.*)
	"T1552.001": true, // Credentials in files
	"T1552.002": true, // Credentials in registry
	"T1552.003": true, // Bash / shell history
	"T1552.004": true, // Private keys
	"T1552.005": true, // Cloud instance metadata
	"T1552.006": true, // Group Policy Preferences
	// Steal or Forge Kerberos Tickets (T1558.*)
	"T1558.001": true, // Golden/Silver ticket
	"T1558.003": true, // Kerberoasting
	"T1558.004": true, // AS-REP roasting
}

// isCredentialTheft reports whether a primary ATT&CK technique is credential
// harvesting from an OS store, password store, or unsecured location.
func isCredentialTheft(tech string) bool {
	return credentialTheftTechniques[strings.ToUpper(tech)]
}

// discoveryReconTechniques is the set of ATT&CK Discovery techniques whose
// builtin Sigma rules fire on a single enumeration command (accounts, system,
// network, domain/AD, shares, services, security software). A burst of three or
// more of these in a short window is an operator mapping the environment before
// escalation/lateral movement, which corr-012 escalates. This mirrors the
// detection-server SequenceEngine's discovery-burst rule (migration 307) in the
// api-server correlation engine.
var discoveryReconTechniques = map[string]bool{
	"T1087":     true, // Account Discovery
	"T1087.001": true, // Local Account
	"T1087.002": true, // Domain Account
	"T1082":     true, // System Information Discovery
	"T1016":     true, // System Network Configuration
	"T1018":     true, // Remote System Discovery
	"T1046":     true, // Network Service Scanning
	"T1057":     true, // Process Discovery
	"T1069":     true, // Permission Groups Discovery
	"T1069.001": true, // Local Groups
	"T1069.002": true, // Domain Groups
	"T1049":     true, // System Network Connections
	"T1033":     true, // System Owner/User Discovery
	"T1007":     true, // System Service Discovery
	"T1012":     true, // Query Registry
	"T1518":     true, // Software Discovery
	"T1518.001": true, // Security Software Discovery
	"T1615":     true, // Group Policy Discovery
	"T1482":     true, // Domain Trust Discovery
	"T1135":     true, // Network Share Discovery
	"T1201":     true, // Password Policy Discovery
	"T1613":     true, // Container and Resource Discovery
}

// isDiscoveryRecon reports whether a primary ATT&CK technique is a Discovery /
// environment-enumeration command.
func isDiscoveryRecon(tech string) bool {
	return discoveryReconTechniques[strings.ToUpper(tech)]
}

// createAlertFromIOC inserts an alert for an IOC match.
//
// title は store.IOCAlertTitlePrefixEN から組み立てる。IOC とアラートを結ぶ
// 手掛かりは title しかなく (alerts に ioc_id は無く、rule_id は uuid なので
// この経路では NULL のまま)、store 側の IOCStats / TopHits は同じ定数で
// 突き合わせている。プレフィックスを直接書くとエラーにはならず IOC 統計が
// 黙って 0 になるので、定数を経由すること。
func (p *AlertPipeline) createAlertFromIOC(ctx context.Context, hit IOCMatch, event map[string]interface{}, evidenceID string) {
	hostname, _ := event["hostname"].(string)
	agentID, _ := event["agent_id"].(string)

	ruleName := fmt.Sprintf("IOC Match: %s", hit.IOC.Type)
	iocTitle := store.IOCAlertTitlePrefixEN + hit.Value
	alertID, err := p.insertAlert(ctx, insertAlertParams{
		AgentID:     agentID,
		Hostname:    hostname,
		RuleName:    ruleName,
		Severity:    hit.IOC.Severity,
		Title:       iocTitle,
		Description: fmt.Sprintf("Field '%s' matched %s IOC: %s", hit.MatchedOn, hit.IOC.Type, hit.IOC.Description),
		Status:      "open",
		EventIDs:    evidenceEventIDs(evidenceID),
		Suppression: SuppressionContextFrom(event),
	})
	if errors.Is(err, errAlertSuppressed) {
		return // 運用者の抑制ルールに当たった。失敗ではないので計上もログもしない
	}
	if err != nil {
		slog.Warn("alert_pipeline: failed to insert IOC alert", "type", hit.IOC.Type, "error", err)
		metrics.AlertInsertFailures.WithLabelValues("ioc").Inc()
		return
	}

	p.publishAlertCreated(alertID)
	wsbus.Global().Broadcast("new_alert", map[string]interface{}{
		"id":       alertID,
		"severity": severityIntToLabel(hit.IOC.Severity),
		"title":    iocTitle,
		"agent_id": agentID,
	})

	if p.remediation != nil {
		iocTags := []string{"ioc", hit.IOC.Type}
		go p.remediation.TriggerOnAlert(context.Background(), alertID, agentID, hostname, hit.IOC.Severity, iocTags)
	}

	if p.corr != nil {
		eventType, _ := event["type"].(string)
		go func() {
			// IOC hits carry no MITRE tag; the base event category still yields
			// the relevant network/dns sub-types for C2 correlation.
			if inc := p.corr.ProcessAlert(context.Background(), alertID, agentID, eventType, "", hit.IOC.Severity, event); inc != nil {
				p.publishIncidentCreated(inc.ID, inc.Title, inc.Severity)
			}
		}()
	}
}

// ─── UEBA Anomaly Detection ──────────────────────────────────

// checkUEBAAnomaly runs statistical anomaly detection for user-activity events.
func (p *AlertPipeline) checkUEBAAnomaly(ctx context.Context, event map[string]interface{}) {
	userKey, _ := event["username"].(string)
	if userKey == "" {
		userKey, _ = event["user"].(string)
	}
	if userKey == "" {
		return
	}

	// Update and check a handful of standard UEBA metrics.
	type uebaSample struct {
		metric string
		value  float64
	}

	var samples []uebaSample

	// Process execution count proxy: presence of a process event counts as 1.
	if _, ok := event["process_name"]; ok {
		samples = append(samples, uebaSample{"process_exec_count", 1})
	}
	if _, ok := event["imagePath"]; ok {
		samples = append(samples, uebaSample{"process_exec_count", 1})
	}
	// Network bytes transferred.
	if bytesVal, ok := event["bytes"]; ok {
		if f, ok := toFloat64(bytesVal); ok {
			samples = append(samples, uebaSample{"network_bytes", f})
		}
	}
	// Login hour-of-day (detect off-hours logins).
	if _, ok := event["logon_type"]; ok {
		hour := float64(time.Now().Hour())
		samples = append(samples, uebaSample{"login_hour", hour})
	}
	// Expanded behavioral features (each event contributes a per-user rate proxy;
	// the anomaly detector flags spikes vs the user's own baseline — catching novel
	// activity no signature covers).
	if _, ok := event["query"]; ok { // DNS query volume (beaconing/tunneling proxy)
		samples = append(samples, uebaSample{"dns_query_count", 1})
	}
	if _, ok := event["file_path"]; ok { // file operation rate (mass-encrypt/collect proxy)
		samples = append(samples, uebaSample{"file_op_count", 1})
	}
	if _, ok := event["path"]; ok {
		samples = append(samples, uebaSample{"file_op_count", 1})
	}
	if act, _ := event["action"].(string); act == "failed" || act == "failure" {
		samples = append(samples, uebaSample{"auth_fail_count", 1}) // brute-force / spraying proxy
	}
	// Off-hours execution (not just logins): a process at an unusual hour for this user.
	if _, ok := event["process_name"]; ok {
		samples = append(samples, uebaSample{"exec_hour", float64(time.Now().Hour())})
	}

	for _, s := range samples {
		p.anomaly.UpdateBaseline(userKey, s.metric, s.value)
		result := p.anomaly.CheckAnomaly(userKey, s.metric, s.value)
		if result.IsAnomaly {
			slog.Info("alert_pipeline: UEBA anomaly detected",
				"user", userKey,
				"metric", s.metric,
				"z_score", result.ZScore,
				"severity", result.Severity,
			)
			p.saveUEBAAnomaly(ctx, userKey, s.metric, result, event)
		}
	}
}

// saveUEBAAnomaly persists an anomaly record to ueba_anomalies.
//
// The table carries two generations of column names: migration 121 created it
// with username/anomaly_type/score, and migration 205 bolted on
// user_key/agent_id/metric_name/z_score/detected_at because the Go code had
// diverged. This INSERT has to fill both sets — the 121 columns are NOT NULL
// with no default, and the readers are split across them too
// (insider_threat_handler.go groups by username, ueba_advanced_handler.go reads
// the newer names).
//
// It previously wrote only the 205 columns, so every insert failed on
// `null value in column "username" violates not-null constraint` and UEBA
// anomalies were never persisted at all. The failure was invisible: it logged at
// Debug level with the guess "table may not exist", which is not what the error
// said. Same silent-failure shape as the detectionmetrics rule_name bug — the
// code ran, the caller was healthy, and the output was quietly empty. The FP
// soak surfaced it by flooding a CI postgres log with ~700 of these.
func (p *AlertPipeline) saveUEBAAnomaly(
	ctx context.Context,
	userKey, metric string,
	result AnomalyResult,
	event map[string]interface{},
) {
	details, _ := json.Marshal(map[string]interface{}{
		"metric":   metric,
		"baseline": result.Baseline,
		"actual":   result.Actual,
		"z_score":  result.ZScore,
		"severity": result.Severity,
	})

	agentID, _ := event["agent_id"].(string)
	description := fmt.Sprintf("%s が基準値 %.2f に対し %.2f (z=%.2f)",
		metric, result.Baseline, result.Actual, result.ZScore)

	// The casts are load-bearing. Reusing one placeholder across both column
	// generations makes Postgres deduce a single type for it, and the pairs
	// disagree: username is VARCHAR(255) while user_key is TEXT, anomaly_type is
	// VARCHAR(100) while metric_name is TEXT, score is NUMERIC(6,2) while z_score
	// is NUMERIC(8,4). Without the casts the statement is rejected outright with
	// "inconsistent types deduced for parameter $1 (character varying versus
	// text)" — which is how this INSERT would keep failing, just for a new reason.
	_, err := p.pool.Exec(ctx, `
		INSERT INTO ueba_anomalies (
			username, anomaly_type, score, baseline_value, actual_value, description,
			user_key, agent_id, metric_name, z_score, severity, details, detected_at
		) VALUES (
			$1::text, $2::text, $3::numeric, $4, $5, $6,
			$1::text, $7::uuid, $2::text, $3::numeric, $8, $9::jsonb, NOW()
		)
		ON CONFLICT DO NOTHING
	`, userKey, metric, result.ZScore, result.Baseline, result.Actual, description,
		nilStr(agentID), result.Severity, string(details))
	if err != nil {
		// Warn, not Debug: a persistent failure here empties the whole
		// insider-threat view and nothing else reports it.
		slog.Warn("alert_pipeline: ueba_anomalies への書き込みに失敗しました",
			"error", err, "user", userKey, "metric", metric,
		)
	}
}

// ─── DB Helpers ──────────────────────────────────────────────

type insertAlertParams struct {
	AgentID     string
	Hostname    string
	RuleName    string
	Severity    int
	Title       string
	Description string
	Status      string
	MITRETech   string
	EventIDs    []string
	// Suppression matching inputs. Not persisted — see SuppressionContext.
	Suppression SuppressionContext
}

// errAlertSuppressed is returned by insertAlert when an operator suppression rule
// matched. It is not a failure: callers must stop quietly, not log an error.
var errAlertSuppressed = errors.New("alert suppressed by an operator rule")

// insertAlert writes to the alerts table and returns the new alert ID.
//
// 抑制の判定はここで行う。**この関数がアラート生成の唯一の絞り**で、Sigma /
// IOC / ユーザー定義ルールの 3 経路がすべてここを通る。呼び出し側それぞれに
// 判定を置くと、経路が増えたときに抜ける。
func (p *AlertPipeline) insertAlert(ctx context.Context, params insertAlertParams) (string, error) {
	candidate := &StoredAlert{
		AgentID:   params.AgentID,
		Hostname:  params.Hostname,
		RuleName:  params.RuleName,
		Severity:  params.Severity,
		Title:     params.Title,
		MITRETech: params.MITRETech,
	}

	sctx := params.Suppression

	// Our own containment changes the endpoint's firewall, which the
	// firewall-modification rules then detect. See self_remediation_suppression.go.
	// nil レシーバでも安全なので、構成されていない場合は素通りする。
	if p.selfRemediation.IsSelfInflicted(ctx, candidate) {
		return "", errAlertSuppressed
	}

	if p.suppression != nil {
		if suppressed, ruleName, ruleID := p.suppression.IsSuppressed(candidate, sctx); suppressed {
			slog.Debug("alert_pipeline: アラートが抑制されました",
				"suppression_rule", ruleName, "rule", params.RuleName, "agent", params.AgentID)
			if p.suppressionHit != nil {
				// 抑制の判断そのものは変えない（ここで失敗しても抑制は成立している）。
				// ただし黙って捨てると、抑制ルールの棚卸しで使うヒット数が実態より
				// 少なく見え、「効いていないルール」と誤って判断される。
				if err := p.suppressionHit.IncrHitCount(ctx, ruleID); err != nil {
					slog.Warn("alert_pipeline: 抑制ヒット数を数えられませんでした。"+
						"抑制は成立していますが、このルールのヒット数は実態より少なく出ます",
						"suppression_rule", ruleName, "rule_id", ruleID, "error", err)
				}
			}
			return "", errAlertSuppressed
		}
	}

	var alertID string
	var mitreTech *string
	if params.MITRETech != "" {
		mitreTech = &params.MITRETech
	}
	err := p.pool.QueryRow(ctx, `
		INSERT INTO alerts (agent_id, severity, status, title, description, mitre_technique, event_ids)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7::uuid[])
		RETURNING id
	`,
		nilStr(params.AgentID),
		params.Severity,
		params.Status,
		params.Title,
		params.Description,
		mitreTech,
		params.EventIDs,
	).Scan(&alertID)
	return alertID, err
}

// parseMITRETechFromTags extracts the first MITRE technique from Sigma tags.
// Tags are formatted as "attack.t1087.001" → returns "T1087.001".
func parseMITRETechFromTags(tags []string) string {
	for _, tag := range tags {
		lower := strings.ToLower(tag)
		if strings.HasPrefix(lower, "attack.t") {
			tech := strings.TrimPrefix(lower, "attack.")
			return strings.ToUpper(tech)
		}
	}
	return ""
}

// publishAlertCreated publishes to both "alert.created" and "alerts.new".
// "alert.created" is consumed by the API/frontend SSE stream.
// "alerts.new" is consumed by the RealtimeCorrelator.
func (p *AlertPipeline) publishAlertCreated(alertID string) {
	if p.nc == nil {
		return // NATS optional: publishing is best-effort telemetry, never block alert creation
	}
	payload, _ := json.Marshal(map[string]string{"alert_id": alertID})
	for _, subj := range []string{"alert.created", "alerts.new"} {
		if err := p.nc.Publish(subj, payload); err != nil {
			slog.Warn("alert_pipeline: failed to publish", "subject", subj, "alert_id", alertID, "error", err)
		}
	}
}

// publishIncidentCreated publishes an "incident.created" message to NATS.
func (p *AlertPipeline) publishIncidentCreated(incidentID, title string, severity int) {
	if p.nc == nil {
		return // NATS optional: publishing is best-effort telemetry
	}
	payload, _ := json.Marshal(map[string]interface{}{
		"incident_id": incidentID,
		"title":       title,
		"severity":    severity,
	})
	if err := p.nc.Publish("incident.created", payload); err != nil {
		slog.Warn("alert_pipeline: failed to publish incident.created", "incident_id", incidentID, "error", err)
	}
}

// ─── Event Flattening ────────────────────────────────────────

// flattenNormalizedEvent converts a NormalizedEvent envelope into a flat
// map[string]interface{} suitable for Sigma rule evaluation.
// It copies top-level metadata fields and merges the nested proto data payload.
func flattenNormalizedEvent(envelope map[string]interface{}) map[string]interface{} {
	flat := make(map[string]interface{}, len(envelope))
	// Copy top-level metadata.
	for _, k := range []string{"agent_id", "hostname", "platform", "type", "timestamp"} {
		if v, ok := envelope[k]; ok {
			flat[k] = v
		}
	}

	// Merge the nested data field (JSON-encoded proto Event).
	inner, _ := envelope["data"].(map[string]interface{})
	if inner == nil {
		return flat
	}

	// Format 1: protojson lowercase sub-object key ("file", "process", etc.)
	for _, key := range []string{"process", "file", "network", "dns", "registry", "auth"} {
		if sub, ok := inner[key].(map[string]interface{}); ok {
			for k, v := range sub {
				flat[k] = v
			}
			addPipelineSigmaAliases(flat)
			return flat
		}
	}
	// Format 2: standard encoding/json of proto oneof — {"Payload": {"File": {...}}}
	if payload, ok := inner["Payload"].(map[string]interface{}); ok {
		for _, key := range []string{"Process", "File", "Network", "Dns", "Registry", "Auth"} {
			if sub, ok := payload[key].(map[string]interface{}); ok {
				for k, v := range sub {
					flat[k] = v
				}
				addPipelineSigmaAliases(flat)
				return flat
			}
		}
	}
	// Format 3: flat event — copy directly.
	for k, v := range inner {
		flat[k] = v
	}
	addPipelineSigmaAliases(flat)
	return flat
}

// addPipelineSigmaAliases adds Sigma field name aliases to the flat event map.
func addPipelineSigmaAliases(flat map[string]interface{}) {
	// De-obfuscate the command line first (caret/quote/backtick stripping + encoded
	// PowerShell decode), so the alias below and Sigma evaluation see the effective
	// command. Appends, never replaces — see commandline_normalize.go.
	normalizeCommandLine(flat)

	aliases := map[string][]string{
		"imagePath":    {"Image", "image"},
		"commandLine":  {"CommandLine"},
		"processName":  {"ProcessName"},
		"pid":          {"ProcessId"},
		"dstIp":        {"DestinationIp", "dst_ip"},
		"dstPort":      {"DestinationPort", "dst_port"},
		"username":     {"User", "SubjectUserName"},
		"image_path":   {"Image", "image"},
		"command_line": {"CommandLine"},
		"process_name": {"ProcessName"},
		"ppid":         {"ParentProcessId"}, // SigmaHQ parent-pid correlation
		"dst_ip":       {"DestinationIp"},
		"dst_port":     {"DestinationPort"},
		// Network (Sysmon EID 3) fields SigmaHQ network_connection rules use.
		"hostname": {"DestinationHostname"}, // resolved-DNS destination name
		"protocol": {"Protocol"},
		"src_ip":   {"SourceIp"},
		"src_port": {"SourcePort"},
		"path":     {"TargetFilename", "FilePath"},
		"query":    {"QueryName"},
		// File operation: the proto FileEvent.action (create/modify/rename/…) must
		// be exposed as Operation so file rules using `Operation|contains` can fire.
		// Without this, rules like the /etc/passwd-write detection silently never match.
		"action":      {"Operation", "EventType"},
		"operation":   {"Operation"},
		"change_type": {"Operation"},
		// DNS query type for rules using `QueryType` (Sysmon) or `record_type`
		// (SigmaHQ dns category — same datum, the resolved record type A/AAAA/TXT/…).
		"queryType":  {"QueryType", "record_type"},
		"query_type": {"QueryType", "record_type"},
		// Parent process: aliased for ParentImage/ParentCommandLine rules (e.g. WMI
		// spawn, Office-spawns-script). These were inert for as long as the agent
		// telemetry carried no parent at all — ProcessEvent had ppid and nothing
		// else — so every ParentImage rule was structurally dark. The agent now
		// resolves the parent on the endpoint and ingestion writes parent_image /
		// parent_name, which is what the first two entries below carry.
		"parent_image":        {"ParentImage"},
		"parent_name":         {"ParentImage"},
		"parentImagePath":     {"ParentImage"},
		"parent_image_path":   {"ParentImage"},
		"parentProcessName":   {"ParentImage"},
		"parent_process":      {"ParentImage"},
		"parentCommandLine":   {"ParentCommandLine"},
		"parent_command_line": {"ParentCommandLine"},
		// Cross-process injection (Sysmon EID8 CreateRemoteThread / EID10 ProcessAccess
		// field names). The Windows ETW thread sensor and the credential-access sensor
		// emit source_image/target_image; expose them under the Sysmon names so the
		// "Process Hollowing" (create_remote_thread) SigmaHQ rule can match.
		"source_image": {"SourceImage"},
		"target_image": {"TargetImage"},
		"source_pid":   {"SourceProcessId"},
		"target_pid":   {"TargetProcessId"},
		// DesiredAccess on the handle (Sysmon EID10 GrantedAccess). The
		// credential-access sensor emits it as access_mask and server-detect's
		// RuleEngine has mapped GrantedAccess→access_mask for a long time; this
		// pipeline never did, so every GrantedAccess-gated rule was inert on the api
		// side only — including the shipped "LSASS ダンプ" rule (T1003.001,
		// migration 003), which selects on GrantedAccess AND TargetImage and so
		// could not fire here at all. Same parity gap, and same fix, as logon_type
		// below. Found by TestMigrationSigmaFieldSupportInAPIEvaluator.
		"access_mask": {"GrantedAccess"},
		// Registry: expose key/value under the standard Sigma names. Following the
		// Sysmon convention, TargetObject is the key path and Details is the value
		// DATA (what persistence rules match on); value_name stays available raw.
		"keyPath":    {"TargetObject"},
		"key_path":   {"TargetObject"},
		"value_data": {"Details"},
		"valueData":  {"Details"},
		// Image/DLL load: standard Sigma names for sideloading rules.
		"image_loaded":     {"ImageLoaded"},
		"signature_status": {"SignatureStatus"},
		"signer":           {"Signer", "Signature"}, // Sysmon EID7 Signature = signer subject
		"signed":           {"Signed"},              // SigmaHQ image_load `Signed: 'false'`
		// Script content: standard Sigma name for ScriptBlock/AMSI rules.
		"script_block_text": {"ScriptBlockText"},
		// PowerShell Module Logging (EventID 4103): the invoked commands + bound
		// parameters (payload) and the host/user/command context block. SigmaHQ
		// ps_module category rules (Invoke-Obfuscation launchers, malicious cmdlets,
		// in-memory compile) select on Payload/ContextInfo — the field-gap canary's
		// top residual inert cause on 2026-07-13 (Payload=22, ContextInfo=3).
		"payload":      {"Payload"},
		"context_info": {"ContextInfo"},
		// Named-pipe creation (Sysmon EID17 pipe_created): C2 frameworks (Cobalt Strike
		// & clones) use predictably-named SMB pipes (\msagent_/\postex_/\mojo. …). The
		// shipped "Cobalt Strike Beacon via Named Pipe" rule (critical, auto-isolate)
		// selects on PipeName — the last field-gap lever after 4103 (2026-07-13).
		"pipe_name": {"PipeName"},
		// PE VERSIONINFO: the Windows agent lifts these four strings off the
		// executable's version resource (best-effort). They map onto the Sysmon
		// process_creation field names that renamed-binary / LOLBin SigmaHQ rules
		// select on — measured 2026-07-02 as the largest inert cause once network
		// Initiated was handled (OriginalFileName 74, Description 12, Product 6,
		// Company 2 enabled rules referenced them with no source field).
		"original_file_name": {"OriginalFileName"},
		"file_description":   {"Description"},
		"product_name":       {"Product"},
		"company_name":       {"Company"},
		// Token integrity level: the Windows agent emits the Sysmon label
		// (Untrusted|Low|Medium|High|System) that UAC-bypass / privilege-escalation
		// rules gate on via IntegrityLevel.
		"integrity_level": {"IntegrityLevel"},
		// Logon session ID (Sysmon hex LUID, e.g. "0x3e7" = SYSTEM) for
		// elevated-shell / privilege-escalation rules gating on LogonId.
		"logon_id": {"LogonId"},
		// Windows 4624/4625 LogonType (3=Network, 10=RDP, …). Ingestion emits it and
		// the detection-server RuleEngine already maps it, but this pipeline did not —
		// so every LogonType-gated rule was inert on the api side only. Parity fix.
		"logon_type": {"LogonType"},
	}
	for protoField, sigmaNames := range aliases {
		if val, ok := flat[protoField]; ok {
			for _, name := range sigmaNames {
				if _, exists := flat[name]; !exists {
					flat[name] = val
				}
			}
		}
	}

	// Sysmon-style combined Hashes field. SigmaHQ process_creation/image_load rules
	// very frequently match `Hashes|contains: <md5/sha256>` (or the labelled form),
	// but we collect md5/sha1/sha256 as separate fields — synthesize the combined
	// "MD5=..,SHA1=..,SHA256=.." string so those rules can fire (labelled form makes
	// both `Hashes|contains: SHA256=x` and `Hashes|contains: <rawhash>` match).
	if _, exists := flat["Hashes"]; !exists {
		parts := make([]string, 0, 3)
		if v, ok := flat["md5"].(string); ok && v != "" {
			parts = append(parts, "MD5="+v)
		}
		if v, ok := flat["sha1"].(string); ok && v != "" {
			parts = append(parts, "SHA1="+v)
		}
		if v, ok := flat["sha256"].(string); ok && v != "" {
			parts = append(parts, "SHA256="+v)
		}
		if len(parts) > 0 {
			flat["Hashes"] = strings.Join(parts, ",")
		}
	}

	// Image fallback: network/image_load events carry only process_name (no full
	// image_path), but SigmaHQ rules match `Image|endswith: '\proc.exe'`. Set Image
	// from process_name only when image_path's alias didn't already populate it, so
	// process_creation rules keep the full path.
	if _, exists := flat["Image"]; !exists {
		if pn, ok := flat["process_name"].(string); ok && pn != "" {
			flat["Image"] = pn
		}
	}

	// Basename normalization for Image/ParentImage. The Windows NT Kernel Logger
	// often reports ImageFileName as a bare basename ("bitsadmin.exe") for
	// short-lived processes that exited before the full path could be enriched. But
	// most SigmaHQ/Sysmon process rules match `Image|endswith: '\proc.exe'` (leading
	// backslash) — and a bare basename does NOT end with "\proc.exe", so those rules
	// silently never fire on basename-only telemetry. This was the break found
	// 2026-06-25: built-in rules using `Image|endswith: \X.exe` were inert in
	// production while older `Image|contains: X.exe` rules worked. Prepend a
	// separator to a bare basename so `endswith \X` matches; `contains` and
	// `endswith X` rules are unaffected (still a substring/suffix).
	for _, key := range []string{"Image", "ParentImage"} {
		if v, ok := flat[key].(string); ok && v != "" && !strings.ContainsAny(v, `\/`) {
			flat[key] = `\` + v
		}
	}

	// Registry EventType in Sysmon vocabulary. SigmaHQ registry_event rules match
	// `EventType: SetValue|CreateKey|DeleteValue|DeleteKey`, but our registry events
	// carry operation = create|modify|delete. Translate so those rules can fire.
	if _, exists := flat["EventType"]; !exists {
		if op, ok := flat["operation"].(string); ok {
			switch op {
			case "modify":
				flat["EventType"] = "SetValue"
			case "create":
				flat["EventType"] = "CreateKey"
			case "delete":
				flat["EventType"] = "DeleteValue"
			}
		}
	}

	// Sysmon registry EventID. SigmaHQ registry_event rules occasionally gate on
	// EventID:[12,13] (12 = key create/delete, 13 = value set) instead of the
	// EventType label — the Azorult localNETService persistence rule is one. Our
	// registry events carry operation; map it to the numeric EventID. Gated on
	// key_path so only registry events get a registry EventID (a file event, which
	// also carries `operation`, keeps its own event semantics).
	if _, exists := flat["EventID"]; !exists {
		if _, isRegistry := flat["key_path"]; isRegistry {
			if op, ok := flat["operation"].(string); ok {
				switch op {
				case "modify":
					flat["EventID"] = "13"
				case "create", "delete":
					flat["EventID"] = "12"
				}
			}
		}
	}

	// Security-log EventID for AUTH events. Ingestion flattens an AuthEvent to
	// username/action/success/source_ip/auth_method/logon_type — it does NOT carry
	// the numeric event ID, while essentially every `service: security` Sigma rule
	// (ours and SigmaHQ's) selects on `EventID: 4625` / 4624 / 4672. The whole
	// class was therefore unreachable from agent telemetry: the shipped
	// brute-force rule could not match a single event the product has ever
	// produced, and a 2026-07-20 audit still recorded it as "field-supported"
	// because EventID *is* derived — for registry events only. Derive it here from
	// the action, mirroring the registry block above.
	//
	// Gated on `auth_method`, which only the auth flat map carries, so a process or
	// file event that happens to have an `action` never acquires a logon EventID.
	// NOTE — a Security-log EventID (4624/4625/4672) and TargetUserName are
	// deliberately NOT derived for auth events, even though every `service: security`
	// Sigma rule selects on them and our auth telemetry carries the equivalent data
	// in `action`/`username`.
	//
	// SupportedSigmaFields() is not merely descriptive: the curate service gates on
	// it (curate_service.go) to decide which SigmaHQ rules get ENABLED into the
	// `rules` table — and those rules are evaluated by the detection server's
	// RuleEngine, whose own FieldMappings have no entry for EventID or
	// TargetUserName. Deriving them here would therefore mark a whole class of rules
	// field-supported, enable them, and leave them unable to resolve the field in the
	// engine that actually runs them: a curate false-green, which is the exact
	// failure mode P5-7 was opened for.
	//
	// Reviving that class needs the mapping added to BOTH engines, plus a check that
	// the rules are not per-event blanket matches (the 4625 rule removed from
	// sigma_builtins.go on 2026-08-04 was one). Tracked, not done here.
	//
	// ── 2026-08-14: 4765/4766 だけを開けた ──
	//
	// AuthEvent がワイヤ上に event_id を持つようになったので(proto 変更)、
	// **アカウント操作イベントに限って** Sigma の EventID に写す。
	//
	// なぜ全部開けないか。上の段落がそのまま理由である: curate が
	// SupportedSigmaFields() を見て SigmaHQ の `service: security` ルールを
	// enabled にしており、EventID を全 auth イベントに与えると
	// **`EventID: 4624` を選ぶルール群が一斉に生き返る**。ログオンのたびに鳴る形が
	// 混ざるので、開けるならアラート量の実測(FP ソーク)が要る。ここでは測っていない。
	//
	// 4765/4766 に限れば話が違う。SID-History の付与は正常系では**ほぼ起きない**
	// (ドメイン移行時のみ)ので、ログオンのような常時発生する土台を持たない。
	// また T1134.005 はこの 2 つ以外に痕跡を残さないため、開けなければ検知手段が
	// 存在しないという状態が続く。
	//
	// 許可リストにしてあるのは、後から「全部開ける」に切り替えるときに
	// **この判断を通らずには変えられない**ようにするためである。
	if _, exists := flat["EventID"]; !exists {
		if _, isAuth := flat["auth_method"]; isAuth {
			if id, ok := toFloat64(flat["event_id"]); ok && sigmaExposedAuthEventIDs[uint64(id)] {
				flat["EventID"] = strconv.FormatUint(uint64(id), 10)
			}
		}
	}

	// Sysmon-style TargetObject includes the value name (e.g. ...\Winlogon\Shell),
	// but our registry events carry the key path and value name separately. Append
	// the value name so value-qualified SigmaHQ rules (Winlogon\Shell, \Userinit,
	// IFEO\<img>\Debugger, …) match. `contains` rules that key on the path are
	// unaffected (still a substring).
	if kp, ok := flat["key_path"].(string); ok && kp != "" {
		if vn, ok := flat["value_name"].(string); ok && vn != "" {
			flat["TargetObject"] = kp + `\` + vn
		}
	}

	// Sysmon network Initiated (bool as string "true"/"false"). SigmaHQ
	// network_connection rules very frequently match `Initiated: 'true'` (outbound,
	// host-initiated), but we carry direction = outbound|inbound. Translate so those
	// rules can fire — measured 2026-07-02 as the 2nd-largest inert cause (41 enabled
	// rules referenced Initiated with no source field).
	if _, exists := flat["Initiated"]; !exists {
		if dir, ok := flat["direction"].(string); ok {
			switch strings.ToLower(dir) {
			case "outbound", "egress", "out":
				flat["Initiated"] = "true"
			case "inbound", "ingress", "in":
				flat["Initiated"] = "false"
			}
		}
	}

	// SourceIsIpv6 (Sysmon network EID 3, bool as string). SigmaHQ
	// network_connection rules gate on it (e.g. the WinRM 5985/5986 remote-
	// PowerShell rule keys `SourceIsIpv6: 'false'`). It is derivable from the
	// source IP with no extra telemetry: an IPv6 literal contains a colon, IPv4
	// does not.
	if _, exists := flat["SourceIsIpv6"]; !exists {
		if src, ok := flat["src_ip"].(string); ok && src != "" {
			flat["SourceIsIpv6"] = strconv.FormatBool(strings.Contains(src, ":"))
		}
	}

	// DNS `answer` (SigmaHQ dns category). Our DNS events carry the resolved
	// records as an `answers` array; expose the joined form so `answer|contains`
	// rules (e.g. TXT responses carrying "IEX"/"Invoke-Expression") can match.
	if _, exists := flat["answer"]; !exists {
		if s := joinStringList(flat["answers"]); s != "" {
			flat["answer"] = s
		}
	}
}

// joinStringList renders a []string / []interface{} field (e.g. DNS answers,
// after a JSON round-trip through NATS) as a single space-joined string, or ""
// when the value is absent or not a list of strings.
func joinStringList(v interface{}) string {
	switch list := v.(type) {
	case []string:
		return strings.Join(list, " ")
	case []interface{}:
		parts := make([]string, 0, len(list))
		for _, e := range list {
			if s, ok := e.(string); ok {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, " ")
	}
	return ""
}

// ─── Utility helpers ─────────────────────────────────────────

// severityIntToLabel converts an integer severity (1-10) to a label string.
func severityIntToLabel(sev int) string {
	switch {
	case sev >= 9:
		return "critical"
	case sev >= 7:
		return "high"
	case sev >= 4:
		return "medium"
	default:
		return "low"
	}
}

// sigmaLevelToInt converts a Sigma level string to an integer severity (1-10).
func sigmaLevelToInt(level string) int {
	switch level {
	case "critical":
		return 10
	case "high":
		return 8
	case "medium":
		return 5
	case "low":
		return 3
	case "informational":
		return 1
	default:
		return 3
	}
}

// toFloat64 converts common numeric types to float64.
func toFloat64(v interface{}) (float64, bool) {
	switch n := v.(type) {
	case float64:
		return n, true
	case float32:
		return float64(n), true
	case int:
		return float64(n), true
	case int64:
		return float64(n), true
	case int32:
		return float64(n), true
	}
	return 0, false
}

// nilStr returns nil if s is empty, otherwise s (for pgx UUID parameters).
func nilStr(s string) interface{} {
	if s == "" {
		return nil
	}
	return s
}
