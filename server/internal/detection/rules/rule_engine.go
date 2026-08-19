// Package rules implements the Sigma and behavioral detection rule engines.
//
// Sigma rules are evaluated using the github.com/bradleyjkemp/sigma-go library,
// which provides full Sigma v2 support including conditions, aggregations, and
// field modifiers (contains, endswith, startswith, re, cidr, etc.).
//
// Rules are pre-compiled at load time for performance. The compiled evaluator
// cache is protected by a sync.RWMutex for concurrent reads.
package rules

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"

	sigma "github.com/bradleyjkemp/sigma-go"
	"github.com/bradleyjkemp/sigma-go/evaluator"

	"github.com/edr-platform/server/internal/metrics"
)

// RuleMatch represents a detection rule match.
type RuleMatch struct {
	RuleID      string
	RuleName    string
	RuleType    string // yara|sigma|behavioral
	Severity    int
	Title       string
	Description string
	MITRETags   []string
	AutoIsolate bool
	AutoKill    bool
	// DedupKey optionally distinguishes alerts that share a Title but carry
	// DIFFERENT findings. Alert dedup is keyed on (agent, title) for a 5-minute
	// window, which is right for a state condition re-asserting on every event but
	// wrong for a correlation detector whose report GROWS: a discovery burst that
	// names 4 techniques, then 7, then 11 as the campaign unfolds emits the same
	// title each time, so every report after the first was silently dropped and the
	// techniques enumerated afterwards were never surfaced. Detectors that report a
	// changing set set DedupKey to that set; identical repeats still collapse, and
	// the title stays free of observed values so it keeps a stable identity.
	DedupKey string
}

// DetectionRule defines a single detection rule.
type DetectionRule struct {
	ID          string
	Name        string
	Type        string
	Platform    []string
	Severity    int
	Content     string
	Enabled     bool
	AutoIsolate bool
	AutoKill    bool
	MITRETags   []string
}

// compiledSigmaRule holds a rule and its pre-compiled evaluator.
type compiledSigmaRule struct {
	rule      *DetectionRule
	evaluator *evaluator.RuleEvaluator
	// category は logsource.category をそのまま持つ("" = 未指定)。
	// これが評価対象を絞るインデックスの鍵になる(logsource_index.go)。
	category string
}

// RuleEngine loads and evaluates detection rules.
type RuleEngine struct {
	mu           sync.RWMutex
	rules        map[string]*DetectionRule
	sigma        map[string]*compiledSigmaRule // pre-compiled sigma evaluators
	sequence     *SequenceEngine               // time-window correlation
	beacon       *BeaconDetector               // network periodicity (C2 beacon) detection
	c2fusion     *C2FusionScorer               // fuse beacon periodicity (S1) with TI reputation (S2)
	config       sigma.Config
	platformGate bool // when true, skip a rule whose Platform excludes the event's OS
	// dbSigmaOwned: when true this engine compiles the `rules` table's Sigma rules.
	//
	// Defaults to TRUE, so a RuleEngine built in isolation behaves the way it
	// always has. Ownership is a property of the deployed topology, not of the
	// library: only cmd/detection knows that an api server is also reading the
	// same table, so only cmd/detection turns this off. Encoding the deployment's
	// answer as the library default would make every direct user of RuleEngine
	// silently evaluate nothing. See SetDBSigmaEvaluation.
	dbSigmaOwned bool
	// index は「イベント種別 → 評価すべきルールID」の事前計算(logsource_index.go)。
	// 全ルールの線形総当たりが検知エンジンの律速なので、種別の合わないルールを外す。
	index *logsourceIndex
	// logsourceIndexGate が false なら index を使わず全ルールを評価する。
	// 絞り込みが原因で検知が落ちたと疑ったときに切り分けるためのエスケープハッチ。
	logsourceIndexGate bool
}

// NewRuleEngine creates a RuleEngine with the default Sigma field mapping.
func NewRuleEngine() *RuleEngine {
	return &RuleEngine{
		rules:        make(map[string]*DetectionRule),
		sigma:        make(map[string]*compiledSigmaRule),
		sequence:     NewSequenceEngine(),
		beacon:       NewBeaconDetector(),
		c2fusion:     NewC2FusionScorer(),
		platformGate: true, // on by default; ops can disable via SetPlatformGate
		dbSigmaOwned: true, // library default: evaluate. cmd/detection turns this
		//                      off because the api server owns DB Sigma in the
		//                      deployed topology — see SetDBSigmaEvaluation.
		// on by default; ops can disable via SetLogsourceIndex.
		// 空のインデックスを先に置いておく(LoadRules 前に Evaluate されても
		// candidates() が nil スライスを返して全ルール0件、ではなく確実に
		// 全ルール評価にフォールバックするよう all を空にしておく)。
		logsourceIndexGate: true,
		index:              &logsourceIndex{byEventType: map[string][]string{}},
		// Field mapping translates Sigma's standard field names (PascalCase, Windows-centric)
		// to the proto JSON field names produced by our agents.
		config: sigma.Config{
			FieldMappings: map[string]sigma.FieldMapping{
				// Process events
				"Image":             {TargetNames: []string{"imagePath", "Image", "image_path"}},
				"CommandLine":       {TargetNames: []string{"commandLine", "CommandLine", "command_line"}},
				"ParentImage":       {TargetNames: []string{"parentImagePath", "parent_image_path"}},
				"ParentCommandLine": {TargetNames: []string{"parentCommandLine", "parent_command_line"}},
				"ProcessName":       {TargetNames: []string{"processName", "process_name", "ProcessName"}},
				"User":              {TargetNames: []string{"username", "User", "SubjectUserName"}},
				"ProcessId":         {TargetNames: []string{"pid", "ProcessId"}},
				// File events
				"TargetFilename": {TargetNames: []string{"path", "TargetFilename", "file_path"}},
				"FileName":       {TargetNames: []string{"path", "fileName"}},
				"FileExtension":  {TargetNames: []string{"extension"}},
				// Image-load events — the DLL side-loading / signer-mismatch rules select on
				// these Sigma names; ingestion emits the snake_case forms.
				//
				// migration 385（第 2 波）がこれらを使うルールを 3 件持ち込み、
				// TestMigrationSigmaFieldSupport が「このエンジンでは解決できない」と
				// 落ちたので別名を足してある。api が DB Sigma ルールを所有している現状
				// （PR #671）では AlertPipeline 側で解決されるので実害は出ないが、
				// EDR_SIGMA_DB_RULES=0 で所有権を detect に戻すロールバック経路が
				// 文書化されている。写像が無いままだと、その切り戻しで **この 3 件だけが
				// 黙って落ちる**。切り戻しは事故の最中に行う操作なので、そこで被覆が
				// 減るのは最も避けたい。
				//
				// 元キーは ingestion/handler.go が出している名前に合わせてある
				// （image_loaded ← ImagePath / signature_status / signer）。
				"ImageLoaded":      {TargetNames: []string{"image_loaded", "imageLoaded", "image_path", "ImageLoaded"}},
				"SignatureStatus":  {TargetNames: []string{"signature_status", "signatureStatus", "SignatureStatus"}},
				"Signature":        {TargetNames: []string{"signer", "signature", "Signature"}},
				"OriginalFileName": {TargetNames: []string{"original_file_name", "originalFileName", "OriginalFileName"}},
				// Auth events — LogonType-derived method and the failure status code.
				"auth_method":    {TargetNames: []string{"auth_method", "authMethod"}},
				"failure_reason": {TargetNames: []string{"failure_reason", "failureReason"}},
				// Process environment (LD_PRELOAD / GCONV_PATH runtime injection rules).
				"environment": {TargetNames: []string{"environment", "env_vars", "envVars"}},
				// GeoIP enrichment + network direction (opt-in country rule).
				"country_code": {TargetNames: []string{"country_code", "countryCode"}},
				"direction":    {TargetNames: []string{"direction"}},
				// Network events
				"DestinationIp":   {TargetNames: []string{"dstIp", "dst_ip", "DestinationIp"}},
				"DestinationPort": {TargetNames: []string{"dstPort", "dst_port", "DestinationPort"}},
				"SourceIp":        {TargetNames: []string{"srcIp", "src_ip", "SourceIp"}},
				"SourcePort":      {TargetNames: []string{"srcPort", "src_port", "SourcePort"}},
				"Protocol":        {TargetNames: []string{"protocol", "Protocol"}},
				// DNS events
				"QueryName": {TargetNames: []string{"query", "QueryName"}},
				"QueryType": {TargetNames: []string{"queryType", "query_type", "QueryType"}},
				// Auth events
				"SubjectUserName": {TargetNames: []string{"username", "SubjectUserName"}},
				"LogonType":       {TargetNames: []string{"logon_type", "LogonType"}},
				// Metadata
				"ComputerName": {TargetNames: []string{"hostname", "ComputerName"}},
				"Platform":     {TargetNames: []string{"platform", "Platform"}},
				// Sysmon-form fields the agent emits under native names. Without these
				// aliases, shipped DB sigma rules keyed on the Sysmon names (LSASS
				// GrantedAccess, registry TargetObject, process-hollowing SourceImage)
				// are silently inert in this engine even though the api-server
				// AlertPipeline resolves them. See TestMigrationSigmaFieldSupport.
				"TargetImage":   {TargetNames: []string{"target_image", "TargetImage"}},
				"SourceImage":   {TargetNames: []string{"source_image", "SourceImage"}},
				"GrantedAccess": {TargetNames: []string{"access_mask", "GrantedAccess"}},
				"TargetObject":  {TargetNames: []string{"key_path", "keyPath", "TargetObject"}},
				"Details":       {TargetNames: []string{"value_data", "Details"}},
				"EventType":     {TargetNames: []string{"operation", "EventType"}},
			},
		},
	}
}

// LoadRules replaces the current rule set with new rules and recompiles them.
func (e *RuleEngine) LoadRules(rules []*DetectionRule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules = make(map[string]*DetectionRule, len(rules))
	e.sigma = make(map[string]*compiledSigmaRule, len(rules))

	compiled := 0
	failed := 0
	skipped := 0

	for _, r := range rules {
		e.rules[r.ID] = r

		if r.Type == "sigma" {
			// Ownership gate. Since P4-6 the api server's AlertPipeline also loads
			// the `rules` table, so a DB Sigma rule is evaluated TWICE per event —
			// once here and once there — and one event becomes two alert rows.
			// Dedup merges them but does not delete them, so the duplication is
			// real, persisted, and visible to anything that counts rows.
			//
			// Exactly one engine must own them. The default owner is the api,
			// because this consumer lags chronically (docs/検知ルールの二重管理と
			// デプロイ.md) and a rule that fires late is worse than the same rule
			// firing promptly elsewhere.
			//
			// Only Sigma compilation is gated. Sequence/behavioural rules below and
			// e.rules lookups are untouched — those have no counterpart on the api
			// side, and dropping them would be a coverage loss rather than a
			// de-duplication.
			if !e.dbSigmaOwned {
				skipped++
				continue
			}
			cs, err := compileSigmaRule(r, e.config)
			if err != nil {
				// A rule that fails to compile is enabled in the DB yet never
				// evaluated — silent dead coverage. Name it so ops can see which
				// rules are dark (previously this was swallowed unlogged).
				slog.Warn("Sigmaルールのコンパイルに失敗しました(未評価)",
					"rule", r.Name, "id", r.ID, "error", err)
				failed++
				continue
			}
			e.sigma[r.ID] = cs
			compiled++
		}
	}

	slog.Info("Sigmaルールをロードしました",
		"compiled", compiled, "failed", failed,
		"skipped_owned_by_api", skipped, "db_sigma_owner", ownerName(e.dbSigmaOwned))

	// 評価対象を絞るインデックスを張り直す。ルール集合が変わるたびに必要。
	e.index = buildLogsourceIndex(e.rules, e.sigma)

	// Load sequence rules (behavioral rules with window+threshold directives)
	e.sequence.LoadRules(rules)
}

// SetPlatformGate toggles the OS-scoping gate. It is on by default; the detection
// service can turn it off (EDR_RULE_PLATFORM_GATE=0) as an escape hatch if a
// mislabeled rule platform ever suppresses a real detection.
// SetDBSigmaEvaluation decides whether THIS engine compiles the `rules` table's
// Sigma rules.
//
// It is driven by the same EDR_SIGMA_DB_RULES switch the api server reads, with
// the opposite sense, so the two processes cannot both evaluate them and cannot
// both skip them: one variable, one owner. Default (unset) = the api owns them
// and this engine skips, which is the de-duplicated configuration.
//
// Setting EDR_SIGMA_DB_RULES=0 hands ownership back here — the escape hatch for
// an operator who needs the api to shed the load, or who hits a rule the api
// evaluates differently. It is deliberately not two independent knobs: the
// failure mode of independent knobs is silent double-evaluation or silent zero
// coverage, and neither announces itself.
func (e *RuleEngine) SetDBSigmaEvaluation(own bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.dbSigmaOwned = own
}

func ownerName(ownedHere bool) string {
	if ownedHere {
		return "server-detect"
	}
	return "server-api"
}

func (e *RuleEngine) SetPlatformGate(on bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.platformGate = on
}

// SetLogsourceIndex toggles the event-type narrowing. It is on by default; the
// detection service can turn it off (EDR_RULE_LOGSOURCE_INDEX=0) if a rule ever
// stops firing and the index is suspected. Turning it off restores the previous
// behaviour exactly (every rule evaluated against every event).
func (e *RuleEngine) SetLogsourceIndex(on bool) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.logsourceIndexGate = on
}

// GetRule retrieves a rule by ID.
func (e *RuleEngine) GetRule(id string) *DetectionRule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.rules[id]
}

// Evaluate runs all applicable rules against a flat event map.
// evt must be a map[string]interface{} produced by EventEnvelope.FlatMap().
func (e *RuleEngine) Evaluate(ctx context.Context, evt interface{}) ([]*RuleMatch, error) {
	e.mu.RLock()
	defer e.mu.RUnlock()

	flatMap, ok := evt.(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("expected map[string]interface{}, got %T", evt)
	}

	var matches []*RuleMatch

	// The agent stamps every event with the reporting OS (linux/windows/darwin).
	// A rule scoped to a specific OS must not be evaluated against another OS's
	// telemetry — that is how a MacOS-only Sigma rule ("File and Directory
	// Discovery - MacOS") false-matches Linux processes.
	eventPlatform, _ := flatMap["platform"].(string)

	// 評価対象をイベント種別で絞る(logsource_index.go)。全ルールの線形総当たりが
	// 検知エンジンの律速で、2,500 ルールでは 1 イベント 31.4 ミリ秒・42,500 allocs かかる。
	// ゲートが off のときと未知のイベント種別では index.all(= 全ルール)にフォールバックし、
	// 従来と同じ挙動になる。絞り込みで検知が変わってはいけない。
	eventType, _ := flatMap["type"].(string)
	candidates := e.index.all
	if e.logsourceIndexGate {
		candidates = e.index.candidates(eventType)
	}

	for _, id := range candidates {
		rule := e.rules[id]
		if rule == nil || !rule.Enabled {
			continue
		}
		// Counted, not just skipped. Until 2026-08-04 the agent never stamped
		// EventBatch.Platform, so eventPlatform was always "unknown" and this gate
		// fell through its fail-open branch for every event — a no-op since the day
		// it shipped. Now that agents report their OS the gate actually removes
		// evaluations, and that is a behaviour change ops must be able to see:
		// a rule carrying a WRONG platform label stops matching, silently.
		// Watch edr_rules_platform_gated_total by platform after rollout.
		if e.platformGate && !platformMatchesEvent(rule.Platform, eventPlatform) {
			metrics.RulesPlatformGated.WithLabelValues(canonPlatform(eventPlatform)).Inc()
			continue
		}

		var matched bool
		var err error

		switch rule.Type {
		case "sigma":
			matched, err = e.evaluateSigma(ctx, id, flatMap)
		case "behavioral":
			matched, err = e.evaluateBehavioral(rule, flatMap)
		default:
			continue
		}

		if err != nil {
			// 評価できなかったルールを「一致しなかった」と同じ扱いに
			// していました。検知が1本静かに減り、症状はアラートが出ない
			// ことだけです。一致しなかったのと、見られなかったのは別です。
			metrics.BackgroundFailed("rule_engine", err,
				"ルールを評価できませんでした。この1本は今回のイベントに適用されていません",
				"rule", rule.ID, "type", rule.Type)
			continue
		}
		if !matched {
			continue
		}

		matches = append(matches, &RuleMatch{
			RuleID:      rule.ID,
			RuleName:    rule.Name,
			RuleType:    rule.Type,
			Severity:    rule.Severity,
			Title:       fmt.Sprintf("[%s] %s", strings.ToUpper(rule.Type), rule.Name),
			Description: fmt.Sprintf("ルール '%s' に一致しました", rule.Name),
			MITRETags:   rule.MITRETags,
			AutoIsolate: rule.AutoIsolate,
			AutoKill:    rule.AutoKill,
		})
	}

	// Run sequence (time-window) correlation engine.
	// The sequence engine is lock-free internally; call outside the read lock.
	agentID, _ := flatMap["agent_id"].(string)
	// eventType は上のインデックス絞り込みで取得済み。
	seqMatches := e.sequence.Observe(agentID, eventType, flatMap)
	matches = append(matches, seqMatches...)

	// Network periodicity (C2 beacon) detection — process signature-free call-home.
	// Ph1 fusion: feed the destination's threat-intel verdict (S2) into the fusion
	// scorer on every network event, then fuse it with a fired beacon (S1) so a
	// periodic beacon to a known-malicious destination escalates to critical.
	if eventType == "network" {
		dst := beaconDstIP(flatMap)
		e.c2fusion.ObserveTI(agentID, dst, tiSignalFromEvent(flatMap))
		e.c2fusion.ObserveNetwork(agentID, dst) // S5 fleet-rarity bookkeeping
		if bm := e.beacon.Observe(agentID, dst, beaconBytesSent(flatMap)); bm != nil {
			matches = append(matches, e.c2fusion.Fuse(bm))
		}
	}

	return matches, nil
}

// platformMatchesEvent reports whether a rule scoped to rulePlatforms should be
// evaluated against an event from eventPlatform. It is deliberately permissive so
// the gate only removes clear cross-OS mismatches, never real detections:
//   - a rule with no platform, or one spanning every supported OS (SigmaHQ
//     category-only rules with no logsource.product), is universal → always run;
//   - an unknown/empty event platform is never gated out (fail-open: better a
//     rare cross-platform FP than silently dropping detection);
//   - darwin and macos are the same OS — agents report "darwin" (runtime.GOOS)
//     while SigmaHQ logsource.product is "macos", so equality alone would wrongly
//     stop MacOS rules from ever matching MacOS events.
//
// PlatformMatchesEvent is the exported form, for the api server's Sigma
// evaluator.
//
// Exported rather than reimplemented: this gate and its canonical-spelling table
// are already pinned by platform_contract_test.go (darwin≡macos, unknown OS
// fail-open, unlabelled rule ungated), and a second copy would drift from those
// tests the first time a spelling is added. The api needs it because DB Sigma
// rules moved to that engine — see SetDBSigmaEvaluation — and it had no platform
// scoping of its own.
func PlatformMatchesEvent(rulePlatforms []string, eventPlatform string) bool {
	return platformMatchesEvent(rulePlatforms, eventPlatform)
}

func platformMatchesEvent(rulePlatforms []string, eventPlatform string) bool {
	if len(rulePlatforms) == 0 {
		return true
	}
	ep := canonPlatform(eventPlatform)
	if ep == "" { // unknown / unrecognized event OS → fail-open
		return true
	}
	for _, rp := range rulePlatforms {
		if canonPlatform(rp) == ep {
			return true
		}
	}
	return false
}

// CanonPlatform is the exported form, so the api server labels
// edr_rules_platform_gated_total with the same bounded value set this engine
// does. Labelling it with anything else (a service name, the raw string) either
// breaks the existing dashboards or gives the counter unbounded cardinality.
func CanonPlatform(p string) string { return canonPlatform(p) }

// canonPlatform folds the OS spellings the rules and agents use into a single
// canonical token (linux/windows/macos); "" for anything unrecognized.
func canonPlatform(p string) string {
	switch strings.ToLower(strings.TrimSpace(p)) {
	case "linux":
		return "linux"
	case "windows", "win":
		return "windows"
	case "macos", "darwin", "osx", "macosx", "mac":
		return "macos"
	default:
		return ""
	}
}

// beaconDstIP extracts the destination IP from a flattened network event, tolerating the
// field-name variants the agents emit.
// ObserveDNSForFusion feeds a DNS resolution into the C2 fusion scorer: the answer IPs
// (so a later beacon to them is not treated as raw-IP, S6) and whether the query was
// DGA-like (S4). The DGA verdict is computed by the caller (detection.AnalyzeDGA) so the
// rules package need not import detection. Called from the Engine's DNS handling path.
func (e *RuleEngine) ObserveDNSForFusion(agentID string, answers []string, dgaSuspicious bool) {
	e.c2fusion.ObserveDNS(agentID, answers, dgaSuspicious)
}

func beaconDstIP(flatMap map[string]interface{}) string {
	for _, k := range []string{"dstIp", "dst_ip", "DestinationIp", "destinationIp"} {
		if s, ok := flatMap[k].(string); ok && s != "" {
			return s
		}
	}
	return ""
}

// beaconBytesSent extracts the outbound byte count from a flattened network event for the
// payload-size regularity axis, tolerating the numeric types JSON/proto decoding produces.
// Returns 0 when absent, which the detector treats as "no size telemetry".
func beaconBytesSent(flatMap map[string]interface{}) uint64 {
	for _, k := range []string{"bytes_sent", "bytesSent", "BytesSent"} {
		switch v := flatMap[k].(type) {
		case uint64:
			return v
		case int64:
			if v > 0 {
				return uint64(v)
			}
		case int:
			if v > 0 {
				return uint64(v)
			}
		case float64:
			if v > 0 {
				return uint64(v)
			}
		}
	}
	return 0
}

// evaluateSigma runs a pre-compiled Sigma evaluator against the event map.
func (e *RuleEngine) evaluateSigma(ctx context.Context, ruleID string, event map[string]interface{}) (matched bool, evalErr error) {
	cs, ok := e.sigma[ruleID]
	if !ok {
		return false, nil // uncompiled rule (compilation failed at load time)
	}

	// Defence in depth: a rule must never be able to kill the detection server.
	// sigma-go panics on constructs it does not fully implement (observed: nil
	// dereference on aggregation conditions), and rules arrive from community
	// feeds we do not control, so any endpoint event could otherwise crash the
	// process. Contain the blast radius to the one rule and keep consuming events.
	defer func() {
		if r := recover(); r != nil {
			slog.Error("Sigmaルール評価中にpanicが発生しました(該当ルールのみ不一致として継続)",
				"rule_id", ruleID, "panic", r)
			matched, evalErr = false, fmt.Errorf("sigma rule %s panicked: %v", ruleID, r)
		}
	}()

	result, err := cs.evaluator.Matches(ctx, event)
	if err != nil {
		return false, err
	}
	return result.Match, nil
}

// stripDetectionTimeframe removes a `timeframe:` entry from the detection block.
// See compileSigmaRule for why (sigma-go v0.6.6 cannot parse it).
func stripDetectionTimeframe(content string) string {
	if !strings.Contains(content, "timeframe:") {
		return content
	}
	lines := strings.Split(content, "\n")
	out := lines[:0]
	for _, ln := range lines {
		trimmed := strings.TrimSpace(ln)
		// Only drop the indented key inside a block, never a top-level field.
		if strings.HasPrefix(trimmed, "timeframe:") && ln != trimmed {
			continue
		}
		out = append(out, ln)
	}
	return strings.Join(out, "\n")
}

// evaluateBehavioral matches behavioral sequence rules against an event map.
// These rules check for specific field patterns without full Sigma syntax.
func (e *RuleEngine) evaluateBehavioral(rule *DetectionRule, event map[string]interface{}) (bool, error) {
	// Behavioral rules are expressed as simple key:value pairs in the content field.
	// Format: "field: value\nfield2: value2" — ALL conditions must match (AND logic).
	for _, line := range strings.Split(rule.Content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		idx := strings.Index(line, ":")
		if idx < 0 {
			continue
		}
		field := strings.TrimSpace(line[:idx])
		value := strings.ToLower(strings.TrimSpace(line[idx+1:]))

		eventVal, ok := event[field]
		if !ok {
			return false, nil
		}
		if !strings.Contains(strings.ToLower(fmt.Sprintf("%v", eventVal)), value) {
			return false, nil
		}
	}
	return true, nil
}

// ─── Compilation ──────────────────────────────────────────────

// compileSigmaRule parses a Sigma YAML rule and builds a ready-to-use evaluator.
func compileSigmaRule(rule *DetectionRule, config sigma.Config) (*compiledSigmaRule, error) {
	// Expand `all of <prefix>*` conditions that sigma-go cannot parse (see
	// expandAllOfWildcards). No-op for rules without that pattern.
	content := expandAllOfWildcards(rule.Content)
	// Work around a sigma-go v0.6.6 bug: Detection.UnmarshalYAML decodes the whole
	// `detection:` mapping into the time.Duration field instead of the timeframe
	// value (rule_parser.go: `node.Decode(&d.Timeframe)` should be `value.Decode`).
	// Any rule carrying `timeframe:` therefore fails to parse with the misleading
	// "line N: cannot unmarshal !!map into time.Duration", pointing at the first
	// line of the detection block. Such rules were silently skipped entirely.
	// Dropping the key lets the rest of the rule evaluate; the time bound is not
	// enforced by this evaluator either way.
	content = stripDetectionTimeframe(content)
	parsed, err := sigma.ParseRule([]byte(content))
	if err != nil {
		return nil, fmt.Errorf("parse sigma rule '%s': %w", rule.Name, err)
	}

	// Reject aggregation conditions (`... | count() > 10`) at COMPILE time. The
	// sigma-go v0.6.6 evaluator does not implement them and dereferences a nil
	// aggregation state when a matching event arrives — a panic that would take
	// the whole detection server down, triggered by ordinary endpoint telemetry.
	// Failing to compile is the safe outcome: the rule is skipped deliberately and
	// visibly instead of being a latent crash. (Until now these rules happened to
	// be shielded only because the timeframe bug above stopped them parsing at all.)
	for _, c := range parsed.Detection.Conditions {
		if c.Aggregation != nil {
			return nil, fmt.Errorf("sigma rule '%s': 集約条件(count/sum等)は評価器が未実装で"+
				"一致時にpanicするため無効化しました。ルールを非集約の形に書き換えてください", rule.Name)
		}
	}

	// Default behavior is case-insensitive (standard Sigma v2 behavior).
	// WithConfig applies field name mappings from our canonical map above.
	eval := evaluator.ForRule(parsed,
		evaluator.WithConfig(config),
	)

	return &compiledSigmaRule{
		rule:      rule,
		evaluator: eval,
		category:  strings.ToLower(strings.TrimSpace(parsed.Logsource.Category)),
	}, nil
}
