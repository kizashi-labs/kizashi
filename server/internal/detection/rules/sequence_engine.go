// Package rules — sequence_engine.go
//
// SequenceEngine implements time-window correlation for behavioral rules.
//
// Rule content format (YAML-like key:value, one directive per line):
//
//	window:    60s           # observation window duration
//	threshold: 5             # how many events must occur to trigger
//	event_type: auth         # filter: only process events of this type
//	field:     eventName     # field to inspect
//	value:     login_failure # field must contain this string (case-insensitive)
//	value_any: rdp,smb,winrm # field matches if it contains ANY of these (comma-separated, case-insensitive)
//	group_by:  agentId       # partition counters by this field (default: agent_id)
//	distinct:  true          # count distinct field values (default: false)
//	distinct_field: dstPort  # which field to count distinct values of (default: field)
//	cooldown:  5m            # min interval between fires for the same group key
//	                         # (default: defaultSequenceCooldown; "0" allows re-fires)
//
// ── Staged (kill-chain) rules ────────────────────────────────────────────────
// A SECOND rule shape detects a multi-stage kill chain: distinct attack stages
// occurring (optionally in order) within the window, rather than N repetitions of
// one condition. This catches chains whose individual steps are each below the
// single-event alerting bar but together signal hands-on-keyboard intrusion.
//
//	window:   10m            # observation window
//	stages:   3              # number of stages; enables staged mode
//	ordered:  true           # require stages in temporal order (default false = all-present)
//	event_type: process      # filter (as above)
//	field:    commandLine    # field each stage is matched against
//	stage_1:  whoami, nltest, net group       # stage 1 SUBSTRING tokens (OR; comma-separated)
//	stage_2:  reg save, lsadump, ntdsutil      # stage 2 tokens
//	stage_3:  psexec, winrs, wmic /node        # stage 3 tokens
//	                         # fires when ≥1 event matches EACH stage within the window
//	                         # (and, if ordered, stage_1 before stage_2 before …)
//
// Staged rules use SUBSTRING matching (like `value`), so authors pick specific
// tokens ("reg save", not "reg") to keep false positives low. A staged rule needs
// window + stages (threshold is implied = number of stages).
//
// ALL directives are optional except window + (threshold OR stages).
// If neither field/value is set the engine counts all matching event_type events.
//
// Thread-safety: all exported methods are safe for concurrent use.
package rules

import (
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"
)

// timedEvent is a lightweight snapshot stored in the ring buffer.
type timedEvent struct {
	ts        time.Time
	agentID   string
	eventType string
	fields    map[string]string // lowercased field → lowercased value
}

// sequenceRule is a parsed behavioral sequence rule.
type sequenceRule struct {
	rule            *DetectionRule
	window          time.Duration
	threshold       int
	eventTypeFilter string // "" = all
	field           string
	value           string
	valueAny        []string // field matches if it contains ANY of these (case-insensitive); empty = unused
	groupBy         string   // field name used to partition counters (default "agent_id")
	distinct        bool
	distinctField   string
	cooldown        time.Duration   // minimum interval between successive fires for the same group key
	stages          []sequenceStage // non-empty = staged kill-chain rule (overrides threshold counting)
	ordered         bool            // staged: require stages in temporal order
}

// sequenceStage is one stage of a staged kill-chain rule: a set of substring
// tokens matched (OR) against a field. eventType/field are per-stage overrides
// (stage_N_event_type / stage_N_field) that fall back to the rule-level
// event_type/field when empty — this lets one kill chain cross heterogeneous
// event types (e.g. process commandline → wmi_activity Type → named_pipe
// PipeName → create_remote_thread TargetImage), which a single rule-wide field
// cannot express since each event type populates different fields.
type sequenceStage struct {
	tokens    []string // lowercased substring tokens; event matches the stage if field contains ANY
	eventType string   // "" = fall back to the rule's event_type
	field     string   // "" = fall back to the rule's field
}

// SequenceEngine maintains per-agent event ring buffers and evaluates
// time-window correlation rules against them.
type SequenceEngine struct {
	mu    sync.Mutex
	rules []*sequenceRule
	// buffers maps groupKey → []timedEvent (append-only, pruned lazily)
	buffers map[string][]timedEvent
	// lastFire maps groupKey → time of most recent alert fire (for cooldown)
	lastFire map[string]time.Time
	// maxWindow is the largest window across all rules; used for pruning.
	maxWindow time.Duration
}

// NewSequenceEngine creates an empty SequenceEngine.
func NewSequenceEngine() *SequenceEngine {
	return &SequenceEngine{
		buffers:  make(map[string][]timedEvent),
		lastFire: make(map[string]time.Time),
	}
}

// LoadRules replaces the current sequence rule set.
func (e *SequenceEngine) LoadRules(rules []*DetectionRule) {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.rules = nil
	e.maxWindow = 0

	for _, r := range rules {
		if r.Type != "behavioral" || !r.Enabled {
			continue
		}
		sr, err := parseSequenceRule(r)
		if err != nil {
			continue // not a sequence rule (plain key:value behavioral rule)
		}
		e.rules = append(e.rules, sr)
		if sr.window > e.maxWindow {
			e.maxWindow = sr.window
		}
	}
}

// Observe records a new event and returns any sequence rule matches.
// evt must be the flat map produced by EventEnvelope.FlatMap().
func (e *SequenceEngine) Observe(agentID, eventType string, evt map[string]any) []*RuleMatch {
	return e.observeAt(agentID, eventType, evt, time.Now())
}

// observeAt is the time-injectable core of Observe (tests pass controlled
// timestamps to exercise multi-minute, low-and-slow correlation windows).
func (e *SequenceEngine) observeAt(agentID, eventType string, evt map[string]any, now time.Time) []*RuleMatch {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.rules) == 0 {
		return nil
	}

	// Build a lightweight snapshot
	te := timedEvent{
		ts:        now,
		agentID:   agentID,
		eventType: eventType,
		fields:    flattenToStrings(evt),
	}

	// Find the group keys this event belongs to across all rules,
	// add to each relevant buffer.
	groupKeys := e.groupKeysForEvent(te)
	for gk := range groupKeys {
		e.buffers[gk] = append(e.buffers[gk], te)
	}

	// Prune stale events from all touched buffers.
	cutoff := now.Add(-e.maxWindow)
	for gk := range groupKeys {
		e.buffers[gk] = pruneOlderThan(e.buffers[gk], cutoff)
	}

	// Evaluate rules
	var matches []*RuleMatch
	for _, sr := range e.rules {
		gk := e.groupKeyFor(sr, te)
		buf := e.buffers[gk]
		if buf == nil {
			continue
		}

		// Skip if within cooldown period for this group key.
		if sr.cooldown > 0 {
			if last, fired := e.lastFire[gk]; fired && now.Sub(last) < sr.cooldown {
				continue
			}
		}

		if e.evaluateSequenceRule(sr, buf, now) {
			e.lastFire[gk] = now
			matches = append(matches, &RuleMatch{
				RuleID:      sr.rule.ID,
				RuleName:    sr.rule.Name,
				RuleType:    "behavioral",
				Severity:    sr.rule.Severity,
				Title:       fmt.Sprintf("[BEHAVIORAL] %s", sr.rule.Name),
				Description: sequenceMatchDescription(sr),
				MITRETags:   sr.rule.MITRETags,
				AutoIsolate: sr.rule.AutoIsolate,
				AutoKill:    sr.rule.AutoKill,
			})
		}
	}
	return matches
}

// sequenceMatchDescription builds a human-readable alert description appropriate
// to the rule shape (staged kill chain vs. threshold count).
func sequenceMatchDescription(sr *sequenceRule) string {
	if len(sr.stages) > 0 {
		order := "順不同"
		if sr.ordered {
			order = "順序付き"
		}
		return fmt.Sprintf("キルチェーン '%s' を検知: %d段階の攻撃シーケンス(%s)が %s 以内に連鎖しました",
			sr.rule.Name, len(sr.stages), order, sr.window)
	}
	return fmt.Sprintf("振る舞いルール '%s' に一致: %d件のイベントが %s 以内に検出されました",
		sr.rule.Name, sr.threshold, sr.window)
}

// evaluateSequenceRule checks whether the buffer satisfies the rule's
// threshold within its window.
func (e *SequenceEngine) evaluateSequenceRule(sr *sequenceRule, buf []timedEvent, now time.Time) bool {
	cutoff := now.Add(-sr.window)

	if len(sr.stages) > 0 {
		return e.evaluateStaged(sr, buf, cutoff)
	}

	if sr.distinct {
		// Count distinct values of distinctField within the window
		seen := make(map[string]struct{})
		df := sr.distinctField
		if df == "" {
			df = sr.field
		}
		for i := len(buf) - 1; i >= 0; i-- {
			ev := buf[i]
			if ev.ts.Before(cutoff) {
				break
			}
			if !matchesFilter(sr, ev) {
				continue
			}
			if v, ok := ev.fields[df]; ok {
				seen[v] = struct{}{}
			}
		}
		return len(seen) >= sr.threshold
	}

	// Count matching events within the window
	count := 0
	for i := len(buf) - 1; i >= 0; i-- {
		ev := buf[i]
		if ev.ts.Before(cutoff) {
			break
		}
		if matchesFilter(sr, ev) {
			count++
		}
	}
	return count >= sr.threshold
}

// evaluateStaged reports whether the buffer satisfies a staged kill-chain rule:
// at least one in-window event matches EACH stage. When sr.ordered, the stages must
// appear in temporal order (a subsequence) — stage_1 before stage_2 before … . buf is
// in append (chronological) order.
func (e *SequenceEngine) evaluateStaged(sr *sequenceRule, buf []timedEvent, cutoff time.Time) bool {
	if sr.ordered {
		stageIdx := 0
		for i := range buf {
			ev := buf[i]
			if ev.ts.Before(cutoff) {
				continue
			}
			if !e.stageEventField(sr, stageIdx, ev, func(v string) bool { return stageMatches(sr.stages[stageIdx], v) }) {
				continue
			}
			stageIdx++
			if stageIdx == len(sr.stages) {
				return true
			}
		}
		return false
	}

	matched := make([]bool, len(sr.stages))
	remaining := len(sr.stages)
	for i := range buf {
		ev := buf[i]
		if ev.ts.Before(cutoff) {
			continue
		}
		for s := range sr.stages {
			if matched[s] {
				continue
			}
			if e.stageEventField(sr, s, ev, func(v string) bool { return stageMatches(sr.stages[s], v) }) {
				matched[s] = true
				remaining--
				if remaining == 0 {
					return true
				}
			}
		}
	}
	return false
}

// stageEventField applies the stage's event_type/field (falling back to the
// rule-level event_type/field when the stage does not override them), and
// reports whether match(fieldValue) is true.
func (e *SequenceEngine) stageEventField(sr *sequenceRule, stageIdx int, ev timedEvent, match func(string) bool) bool {
	st := sr.stages[stageIdx]

	evType := st.eventType
	if evType == "" {
		evType = sr.eventTypeFilter
	}
	if evType != "" && !strings.EqualFold(ev.eventType, evType) {
		return false
	}

	field := st.field
	if field == "" {
		field = sr.field
	}
	v, ok := ev.fields[field]
	if !ok {
		return false
	}
	return match(v)
}

// stageMatches reports whether field value v contains any of the stage's substring
// tokens (case-insensitive; v is already lowercased in the buffer).
func stageMatches(st sequenceStage, v string) bool {
	for _, tok := range st.tokens {
		if tok != "" && strings.Contains(v, tok) {
			return true
		}
	}
	return false
}

// groupKeysForEvent returns the set of buffer keys this event touches.
// One event may satisfy the group_by field of multiple rules.
func (e *SequenceEngine) groupKeysForEvent(te timedEvent) map[string]struct{} {
	seen := make(map[string]struct{})
	for _, sr := range e.rules {
		gk := e.groupKeyFor(sr, te)
		seen[gk] = struct{}{}
	}
	return seen
}

func (e *SequenceEngine) groupKeyFor(sr *sequenceRule, te timedEvent) string {
	groupField := sr.groupBy
	if groupField == "" || groupField == "agent_id" {
		return sr.rule.ID + "|" + te.agentID
	}
	groupVal := te.fields[strings.ToLower(groupField)]
	return sr.rule.ID + "|" + groupField + "=" + groupVal
}

// ─── Parsing ──────────────────────────────────────────────────

// parseSequenceRule attempts to parse a behavioral rule as a sequence rule.
// Returns an error if the rule does not contain window+threshold directives.
func parseSequenceRule(r *DetectionRule) (*sequenceRule, error) {
	directives := parseDirectives(r.Content)

	windowStr, hasWindow := directives["window"]
	thresholdStr, hasThreshold := directives["threshold"]
	stagesStr, hasStages := directives["stages"]

	// A rule needs a window plus either a threshold (count rule) or stages (kill chain).
	if !hasWindow || (!hasThreshold && !hasStages) {
		return nil, fmt.Errorf("not a sequence rule")
	}

	window, err := parseDuration(windowStr)
	if err != nil {
		return nil, fmt.Errorf("invalid window '%s': %w", windowStr, err)
	}

	// Parse stages first so a staged rule can default its threshold to the stage count.
	stages := parseStages(directives, stagesStr, hasStages)

	threshold := len(stages) // staged default; overridden below if an explicit threshold is set
	if hasThreshold {
		threshold, err = strconv.Atoi(strings.TrimSpace(thresholdStr))
		if err != nil || threshold < 1 {
			return nil, fmt.Errorf("invalid threshold '%s'", thresholdStr)
		}
	}
	if len(stages) > 0 && len(stages) < 2 {
		return nil, fmt.Errorf("staged rule needs at least 2 stages")
	}

	sr := &sequenceRule{
		rule:            r,
		window:          window,
		threshold:       threshold,
		eventTypeFilter: strings.TrimSpace(directives["event_type"]),
		field:           strings.ToLower(strings.TrimSpace(directives["field"])),
		value:           strings.ToLower(strings.TrimSpace(directives["value"])),
		valueAny:        parseValueAny(directives["value_any"]),
		groupBy:         strings.TrimSpace(directives["group_by"]),
		distinct:        strings.TrimSpace(directives["distinct"]) == "true",
		distinctField:   strings.ToLower(strings.TrimSpace(directives["distinct_field"])),
		stages:          stages,
		ordered:         strings.TrimSpace(directives["ordered"]) == "true",
	}
	if sr.groupBy == "" {
		sr.groupBy = "agent_id"
	}
	if cdStr, ok := directives["cooldown"]; ok && cdStr != "" {
		// Explicit cooldown (including "cooldown: 0" to allow re-fires).
		if cd, err := parseDuration(cdStr); err == nil {
			sr.cooldown = cd
		}
	} else {
		// No explicit cooldown: apply a sane default so a single incident does
		// not re-fire on every subsequent qualifying event (alert fatigue). A
		// discovery burst of 8 commands previously emitted ~15 alerts; with the
		// default a group fires at most once per defaultSequenceCooldown.
		// Authors can opt out with an explicit "cooldown: 0".
		sr.cooldown = defaultSequenceCooldown
	}
	return sr, nil
}

// defaultSequenceCooldown is the minimum interval between successive fires of
// the same sequence rule for the same group key when the rule does not specify
// an explicit cooldown. Prevents one ongoing incident (a discovery burst, an
// active brute-force, a port scan) from flooding the alert stream.
const defaultSequenceCooldown = 5 * time.Minute

// parseDirectives extracts key:value pairs from rule content, ignoring
// lines that are blank or start with '#'.
func parseDirectives(content string) map[string]string {
	out := make(map[string]string)
	for line := range strings.SplitSeq(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		rawKey, rawVal, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(rawKey))
		val := strings.TrimSpace(rawVal)
		out[key] = val
	}
	return out
}

// parseDuration parses "30s", "5m", "1h" etc.
func parseDuration(s string) (time.Duration, error) {
	s = strings.TrimSpace(s)
	return time.ParseDuration(s)
}

// parseStages reads stage_1, stage_2, … directives into ordered stages. The "stages"
// directive gives the count; absent or unparsable count falls back to scanning for
// consecutive stage_N keys starting at 1. Each stage value is a value_any-style
// comma list of lowercased substring tokens.
func parseStages(directives map[string]string, stagesStr string, hasStages bool) []sequenceStage {
	if !hasStages {
		return nil
	}
	n, err := strconv.Atoi(strings.TrimSpace(stagesStr))
	if err != nil || n < 1 {
		// Fall back to counting consecutive stage_N keys.
		for n = 1; ; n++ {
			if _, ok := directives[fmt.Sprintf("stage_%d", n)]; !ok {
				n--
				break
			}
		}
	}
	var stages []sequenceStage
	for i := 1; i <= n; i++ {
		tokens := parseValueAny(directives[fmt.Sprintf("stage_%d", i)])
		if len(tokens) == 0 {
			continue // skip empty/missing stage
		}
		stages = append(stages, sequenceStage{
			tokens: tokens,
			// Optional per-stage overrides so one kill chain can cross event
			// types that populate different fields (stage_N_event_type /
			// stage_N_field); empty falls back to the rule-level event_type/field.
			eventType: strings.TrimSpace(directives[fmt.Sprintf("stage_%d_event_type", i)]),
			field:     strings.ToLower(strings.TrimSpace(directives[fmt.Sprintf("stage_%d_field", i)])),
		})
	}
	return stages
}

// parseValueAny splits a comma-separated "value_any" directive into a slice of
// lowercased, trimmed values. Blank entries are dropped; returns nil if empty.
func parseValueAny(s string) []string {
	s = strings.TrimSpace(s)
	if s == "" {
		return nil
	}
	var out []string
	for part := range strings.SplitSeq(s, ",") {
		v := strings.ToLower(strings.TrimSpace(part))
		if v != "" {
			out = append(out, v)
		}
	}
	return out
}

// ─── Helpers ──────────────────────────────────────────────────

func matchesFilter(sr *sequenceRule, ev timedEvent) bool {
	if sr.eventTypeFilter != "" && !strings.EqualFold(ev.eventType, sr.eventTypeFilter) {
		return false
	}
	// Value matching: when a field is configured, the event must satisfy at
	// least one of the configured value constraints (value OR any value_any
	// entry). OR semantics maximize detection coverage when both are set.
	if sr.field != "" && (sr.value != "" || len(sr.valueAny) > 0) {
		v, ok := ev.fields[sr.field]
		if !ok {
			return false
		}
		if !valueMatches(sr, v) {
			return false
		}
	}
	return true
}

// valueMatches reports whether field value v satisfies the rule's value
// constraints: it contains sr.value, or it matches any entry of sr.valueAny.
//
// value_any entries are matched two ways depending on their shape:
//   - entries beginning with "." (e.g. ".locked", ".encrypted") are treated as
//     suffix/extension tokens and matched by SUBSTRING (a file "x.locked"
//     contains ".locked"). The ransomware file-extension rule relies on this.
//   - all other entries (command/process names) are matched by EXACT basename
//     (path stripped, a trailing ".exe" removed). This lets terse Linux command
//     names (ps, id, ss, ip) be listed without "ss" wrongly matching "sshd",
//     while Windows "tasklist" still matches a "tasklist.exe" image.
func valueMatches(sr *sequenceRule, v string) bool {
	if sr.value != "" && strings.Contains(v, sr.value) {
		return true
	}
	if len(sr.valueAny) == 0 {
		return false
	}
	lv := strings.ToLower(v)
	base := procBasename(v)
	for _, want := range sr.valueAny {
		w := strings.ToLower(strings.TrimSpace(want))
		if strings.HasPrefix(w, ".") {
			if strings.Contains(lv, w) {
				return true
			}
		} else if base == procBasename(w) {
			return true
		}
	}
	return false
}

// procBasename lowercases s and reduces it to the executable basename with a
// single trailing ".exe" removed, so "C:\\Windows\\System32\\tasklist.exe",
// "tasklist.exe" and "tasklist" all normalize to "tasklist".
func procBasename(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if i := strings.LastIndexAny(s, `/\`); i >= 0 {
		s = s[i+1:]
	}
	return strings.TrimSuffix(s, ".exe")
}

func flattenToStrings(evt map[string]any) map[string]string {
	out := make(map[string]string, len(evt))
	for k, v := range evt {
		out[strings.ToLower(k)] = strings.ToLower(fmt.Sprintf("%v", v))
	}
	return out
}

func pruneOlderThan(buf []timedEvent, cutoff time.Time) []timedEvent {
	for len(buf) > 0 && buf[0].ts.Before(cutoff) {
		buf = buf[1:]
	}
	return buf
}
