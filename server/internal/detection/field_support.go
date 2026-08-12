package detection

import (
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// Field-support gate. A Sigma rule can only fire if the fields its detection
// selects on are actually present in the telemetry our agents emit (after the
// shared alias layer, addPipelineSigmaAliases). A rule that selects on a field
// OUTSIDE that set is permanently inert — the silent class of break the basename
// bug (2026-06-25) belonged to. These helpers expose that gate so it can guard
// BOTH the built-in field-support audit AND curate-enabling of SigmaHQ-synced
// rules (roadmap P1): enabling a field-unsupported rule produces a "false green"
// (a rule that is on but can never match).

// SupportedSigmaFields returns the set of field names live telemetry can
// populate: every native field normalizeEventData emits (across all event types),
// the parent fields the parentResolver injects, the hash fields, plus every
// Sysmon/SigmaHQ alias addPipelineSigmaAliases derives from them. Keys are stored
// in both their original case and lowercased for case-insensitive lookup.
func SupportedSigmaFields() map[string]bool {
	// Kitchen-sink native event: a union of every field normalizeEventData emits
	// for process/network/dns/registry/auth/image_load/script/file events, plus
	// the parent fields the parentResolver injects and the hash fields.
	kitchen := map[string]interface{}{
		// process
		"process_name": "x.exe", "pid": float64(1), "ppid": float64(2),
		"command_line": "x", "image_path": "x.exe", "username": "u", "action": "create",
		"environment": "LD_PRELOAD=/t/e.so", "integrity_level": "High", "logon_id": "0x3e7",
		// PE VERSIONINFO (Windows agent, best-effort) → OriginalFileName/Description/
		// Product/Company via the alias layer.
		"original_file_name": "orig.exe", "file_description": "desc",
		"product_name": "prod", "company_name": "co",
		// parent (parentResolver)
		"parent_image_path": "p.exe", "parent_process": "p.exe", "parent_command_line": "p",
		// hashes
		"md5": "m", "sha1": "s1", "sha256": "s2", "imphash": "ih",
		// network
		"src_ip": "1.1.1.1", "src_port": float64(1), "dst_ip": "2.2.2.2", "dst_port": float64(2),
		"protocol": "tcp", "direction": "outbound", "hostname": "h", "country_code": "US",
		"threat_intel_matched": true, "threat_intel_source": "f", "threat_intel_category": "c2",
		// network volume/state (ingestion emits these; the exfil-volume detector and
		// netScan consume bytes_sent/state — they must be marked field-supported so
		// rules keying on them are not falsely deferred).
		"bytes_sent": float64(0), "bytes_recv": float64(0), "state": "ESTABLISHED",
		// dns
		"query": "q", "query_type": "A", "is_suspicious": true,
		"answers": []interface{}{"1.2.3.4"},
		// registry
		"key_path": `HKLM\x`, "keyPath": `HKLM\x`, "value_name": "v", "value_data": "d", "operation": "modify",
		// auth
		"success": false, "source_ip": "1.1.1.1", "auth_method": "ntlm", "failure_reason": "bad",
		"logon_type": "3",
		// image_load
		"image_loaded": `C:\x.dll`, "signed": false, "signature_status": "unsigned", "signer": "",
		// script
		"script_block_text": "iex", "engine": "powershell", "content_hash": "ch",
		// ps_module (PowerShell Module Logging 4103) → Payload/ContextInfo via alias
		"payload": "CommandInvocation(Add-Type)", "context_info": "Command Name = Add-Type",
		// pipe_created (named-pipe creation) → PipeName via alias (image_path already present)
		"pipe_name": `\msagent_5x`,
		// wmi_activity (Microsoft-Windows-WMI-Activity 5858/5861). The payload uses
		// SigmaHQ's wmi_event field names on purpose — see collector/wmi_activity.go.
		// "operation" and "query" are already present above (registry / dns), so only
		// the WMI-specific ones are added here. "name" is generic enough to look out
		// of place, but it is the literal SigmaHQ/Sysmon field for the filter or
		// consumer name in this category, and leaving it out would defer any rule
		// that selects on it as unsupported — inert rather than merely non-matching.
		"event_type": "WmiBindingEvent", "consumer": `CommandLineEventConsumer="x"`,
		"name": "SCM Event Log Filter", "namespace": `//./root/subscription`,
		"destination": "DC01", "possible_cause": "", "event_id": float64(5861),
		// file
		"path": `C:\f`, "old_path": `C:\old`, "file_size": float64(0),
		"yara_matched": true, "yara_rule_ids": []interface{}{"r"},
		// credential_access (Windows kernel M3) + memory (M1 scanner)
		"target_image": `C:\Windows\System32\lsass.exe`, "target_pid": float64(8),
		"source_image": "mimikatz.exe", "source_pid": float64(9), "access_mask": "0x1410",
		"enforced": false, "reason": "RWX", "address": "0x1000", "unbacked": true,
		// tamper (agent self-protection). Most of this payload deliberately reuses
		// the credential_access vocabulary above — source_pid, target_pid,
		// source_image, access_mask, enforced, reason are already present — so only
		// the fields with no existing counterpart are added here. Leaving them out
		// would defer any rule selecting on them as unsupported: inert, and
		// indistinguishable from an endpoint nobody has tampered with.
		"tamper_type": "agent_killed", "component": "edr-agent", "signal": float64(9),
		"exit_code": float64(0), "expected_hash": "a1b2", "actual_hash": "c3d4",
	}
	addPipelineSigmaAliases(kitchen)
	supported := make(map[string]bool, len(kitchen)*2)
	for k := range kitchen {
		supported[k] = true
		supported[strings.ToLower(k)] = true
	}
	return supported
}

// RuleSelectedFields extracts the field names a Sigma rule's detection selects on
// (keys of every selection sub-map, minus the |modifier suffix and the special
// "condition"/"timeframe" keys). Returns nil for unparseable YAML.
func RuleSelectedFields(ruleYAML string) []string {
	var doc struct {
		Detection map[string]interface{} `yaml:"detection"`
	}
	if err := yaml.Unmarshal([]byte(ruleYAML), &doc); err != nil {
		return nil
	}
	set := map[string]bool{}
	collectKeys := func(m map[string]interface{}) {
		for k := range m {
			if k == "condition" || k == "timeframe" {
				continue
			}
			field := k
			if i := strings.IndexByte(field, '|'); i >= 0 {
				field = field[:i]
			}
			set[field] = true
		}
	}
	var walk func(v interface{})
	walk = func(v interface{}) {
		switch t := v.(type) {
		case map[string]interface{}:
			collectKeys(t)
			for k, sub := range t {
				if k == "condition" {
					continue
				}
				walk(sub)
			}
		case []interface{}:
			for _, e := range t {
				walk(e)
			}
		}
	}
	for name, sel := range doc.Detection {
		if name == "condition" {
			continue
		}
		walk(sel)
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// BehavioralRuleReferencedFields extracts the event-field names a behavioral
// (SequenceEngine) rule reads: the `field`, `distinct_field`, and a non-default
// `group_by` directive. The default group_by (agent_id / empty) is handled
// specially by the engine (it partitions by the agent, not by an event field) and
// is therefore NOT a field reference. Staged kill-chain rules also read `field`.
//
// This is the behavioral-rule analogue of RuleSelectedFields for Sigma: a rule
// that references a field the flattened telemetry never populates is permanently
// inert — the silent class the auth eventName rules (value:4625 on a non-existent
// field) and the dstIp/dstPort/srcIp network rules belonged to.
func BehavioralRuleReferencedFields(content string) []string {
	directives := parseBehavioralDirectives(content)
	set := map[string]bool{}
	add := func(v string) {
		v = strings.TrimSpace(v)
		if v == "" || v == "agent_id" {
			return // agent_id/empty group_by is engine-partitioning, not a field read
		}
		set[v] = true
	}
	add(directives["field"])
	add(directives["distinct_field"])
	add(directives["group_by"])
	// Per-stage `stage_N_field` overrides. Without these a cross-event-type kill
	// chain would report only its rule-level field, so the very stages that read
	// a different field — the ones most likely to name something the telemetry
	// never populates — would escape the inert-rule check this function exists
	// to feed.
	for key, val := range directives {
		if strings.HasPrefix(key, "stage_") && strings.HasSuffix(key, "_field") {
			add(val)
		}
	}
	out := make([]string, 0, len(set))
	for f := range set {
		out = append(out, f)
	}
	sort.Strings(out)
	return out
}

// BehavioralRuleFieldSupportWith reports whether every field a behavioral rule
// references is populated by live telemetry (SupportedSigmaFields is the shared
// supported set — the SequenceEngine sees the SAME aliased flat map as Sigma
// evaluation). unsupported lists offending fields. A rule referencing no fields
// (e.g. a pure volume threshold or staged rule with only stage_N tokens) is
// supported: it counts events without reading a field.
func BehavioralRuleFieldSupportWith(content string, supportedFields map[string]bool) (supported bool, unsupported []string) {
	for _, f := range BehavioralRuleReferencedFields(content) {
		if !supportedFields[f] && !supportedFields[strings.ToLower(f)] {
			unsupported = append(unsupported, f)
		}
	}
	return len(unsupported) == 0, unsupported
}

// parseBehavioralDirectives extracts key:value directives from a behavioral rule's
// content (one `key: value` per line, '#'-comments ignored) — the same shape the
// SequenceEngine parses. Only the first value of each key is kept.
func parseBehavioralDirectives(content string) map[string]string {
	out := map[string]string{}
	for _, line := range strings.Split(content, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, found := strings.Cut(line, ":")
		if !found {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(k))
		if _, exists := out[key]; !exists {
			out[key] = strings.TrimSpace(v)
		}
	}
	return out
}

// RuleFieldSupport reports whether every field a Sigma rule selects on is
// populated by live telemetry. unsupported lists the offending fields (empty when
// fully supported). A rule with unsupported fields is inert in production, so
// curate must NOT enable it (it would be a "false green"). A rule that selects on
// no fields at all (unparseable / no detection) is treated as unsupported so it is
// never silently enabled.
//
// Batch callers (curate over thousands of rules) should compute SupportedSigmaFields()
// once and use RuleFieldSupportWith to avoid rebuilding the set per rule.
func RuleFieldSupport(ruleYAML string) (supported bool, unsupported []string) {
	return RuleFieldSupportWith(ruleYAML, SupportedSigmaFields())
}

// RuleFieldSupportWith is RuleFieldSupport against a precomputed supported set.
//
// A rule is supported when its detection can FIRE using only supported fields —
// not when EVERY field it mentions is supported. Sigma selections are frequently
// OR-structured: a rule may match on a supported branch (e.g. TargetObject +
// EventType) while an alternative branch references a field the agent never emits
// (e.g. registry-rename NewName). Requiring every field to be supported wrongly
// marks such a rule inert even though it demonstrably fires on the supported
// branch. This gate instead evaluates the rule's `condition` over per-block
// satisfiability: a block is satisfiable if all its fields are supported (a
// list-valued block — an OR of sub-selections — is satisfiable if ANY element
// is), and a negated term is free (a `not filter` never requires a field to be
// present, so a filter on an unsupported field cannot make the rule inert).
//
// unsupported still lists every referenced field absent from the set, for
// diagnostics — it may be non-empty even when supported is true (the unsupported
// fields live only in alternative or negated branches).
func RuleFieldSupportWith(ruleYAML string, supportedFields map[string]bool) (supported bool, unsupported []string) {
	selected := RuleSelectedFields(ruleYAML)
	if len(selected) == 0 {
		return false, nil // no parseable field selection → never enable
	}
	for _, f := range selected {
		if !supportedFields[f] && !supportedFields[strings.ToLower(f)] {
			unsupported = append(unsupported, f)
		}
	}

	var doc struct {
		Detection map[string]interface{} `yaml:"detection"`
	}
	if err := yaml.Unmarshal([]byte(ruleYAML), &doc); err != nil || len(doc.Detection) == 0 {
		return false, unsupported
	}
	sup := func(f string) bool { return supportedFields[f] || supportedFields[strings.ToLower(f)] }
	sat := map[string]bool{}
	for name, val := range doc.Detection {
		if name == "condition" || name == "timeframe" {
			continue
		}
		sat[name] = blockSatisfiable(val, sup)
	}
	cond := conditionString(doc.Detection["condition"])
	if cond == "" {
		return false, unsupported
	}
	return evalSupportCondition(cond, sat), unsupported
}

// blockSatisfiable reports whether a detection block can match given the
// supported field set. A map block needs all its fields supported; a list block
// is an OR of sub-selections (satisfiable if any element is) — a list of scalars
// is a field-agnostic keyword search and is treated as satisfiable.
func blockSatisfiable(val interface{}, sup func(string) bool) bool {
	switch v := val.(type) {
	case map[string]interface{}:
		return mapFieldsSupported(v, sup)
	case []interface{}:
		sawMap := false
		for _, e := range v {
			if m, ok := e.(map[string]interface{}); ok {
				sawMap = true
				if mapFieldsSupported(m, sup) {
					return true
				}
			}
		}
		return !sawMap // no maps → keyword list (field-agnostic)
	default:
		return true // scalar keyword
	}
}

// mapFieldsSupported reports whether every field key of a selection map (minus
// its |modifier suffix) is supported. An empty map is not satisfiable.
func mapFieldsSupported(m map[string]interface{}, sup func(string) bool) bool {
	if len(m) == 0 {
		return false
	}
	for k := range m {
		f := k
		if i := strings.IndexByte(f, '|'); i >= 0 {
			f = f[:i]
		}
		if f == "" {
			continue
		}
		if !sup(f) {
			return false
		}
	}
	return true
}

// conditionString normalizes a detection `condition` (a string, or a list of
// strings which are OR-ed) to a single expression.
func conditionString(c interface{}) string {
	switch v := c.(type) {
	case string:
		return v
	case []interface{}:
		parts := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok && strings.TrimSpace(s) != "" {
				parts = append(parts, "("+s+")")
			}
		}
		return strings.Join(parts, " or ")
	}
	return ""
}

// evalSupportCondition evaluates a Sigma condition over per-block satisfiability,
// returning whether the rule can fire on supported fields alone. The Sigma
// aggregation/correlation suffix ("| count() by ...") is dropped.
func evalSupportCondition(cond string, sat map[string]bool) bool {
	if i := strings.IndexByte(cond, '|'); i >= 0 {
		cond = cond[:i]
	}
	cond = strings.ReplaceAll(cond, "(", " ( ")
	cond = strings.ReplaceAll(cond, ")", " ) ")
	p := &condParser{toks: strings.Fields(cond), sat: sat}
	return p.parseOr()
}

// condParser is a recursive-descent evaluator for Sigma condition booleans
// (precedence: not > and > or) plus the `<N|all> of <pattern|them>` quantifiers.
type condParser struct {
	toks []string
	pos  int
	sat  map[string]bool
}

func (p *condParser) peek() string {
	if p.pos < len(p.toks) {
		return p.toks[p.pos]
	}
	return ""
}

func (p *condParser) next() string {
	t := p.peek()
	p.pos++
	return t
}

func (p *condParser) parseOr() bool {
	v := p.parseAnd()
	for strings.EqualFold(p.peek(), "or") {
		p.next()
		if p.parseAnd() {
			v = true
		}
	}
	return v
}

func (p *condParser) parseAnd() bool {
	v, real := p.parseNot()
	for strings.EqualFold(p.peek(), "and") {
		p.next()
		v2, real2 := p.parseNot()
		if !v2 {
			v = false
		}
		real = real || real2
	}
	// A negation is only "free" (able to ride along on another term's field
	// support) when the AND chain also contains a non-negated term genuinely
	// gated on supported fields. An AND chain made ENTIRELY of negations (most
	// commonly a bare `condition: not selection`) has no such term: at runtime
	// a selection referencing an entirely-unsupported field never matches, so
	// `not selection` is unconditionally true for every event — the rule fires
	// on all telemetry regardless of field data, not "on supported fields". That
	// is not a working detection; treat the chain as unsupported instead of
	// silently auto-enabling an always-fire rule (see the "Publicly Accessible
	// RDP Service" / "Suspicious DNS Z Flag Bit Set" FP-storm incident).
	if !real {
		return false
	}
	return v
}

// parseNot returns the operand's satisfiability plus whether this term is a
// "real" (non-vacuous) positive requirement. `not X` itself always evaluates
// to true here (a filter on an unsupported field never excludes anything —
// safe when paired with a genuinely-supported selection elsewhere in the AND
// chain), but it only counts as "real" when X's OWN fields are supported: only
// then is `not X` a genuine, data-dependent condition rather than an
// unconditional true regardless of the actual event. A bare negation over an
// unsupported field (real=false) can never single-handedly make an AND chain
// "supported" — see parseAnd.
func (p *condParser) parseNot() (val bool, real bool) {
	if strings.EqualFold(p.peek(), "not") {
		p.next()
		opVal, _ := p.parseNot() // opVal: was the negated operand itself satisfiable?
		return true, opVal
	}
	return p.parsePrimary(), true
}

func (p *condParser) parsePrimary() bool {
	t := p.peek()
	if t == "(" {
		p.next()
		v := p.parseOr()
		if p.peek() == ")" {
			p.next()
		}
		return v
	}
	// Quantifier: (all | <N>) of (<pattern> | them)
	if (strings.EqualFold(t, "all") || isConditionNumber(t)) &&
		p.pos+1 < len(p.toks) && strings.EqualFold(p.toks[p.pos+1], "of") {
		quant := p.next() // all | N
		p.next()          // of
		pat := p.next()   // pattern | them
		return p.evalQuantifier(quant, pat)
	}
	// Plain block reference (unknown name → not satisfiable).
	return p.sat[p.next()]
}

func (p *condParser) evalQuantifier(quant, pat string) bool {
	var names []string
	if strings.EqualFold(pat, "them") {
		for n := range p.sat {
			names = append(names, n)
		}
	} else {
		for n := range p.sat {
			if globMatch(pat, n) {
				names = append(names, n)
			}
		}
	}
	satisfied := 0
	for _, n := range names {
		if p.sat[n] {
			satisfied++
		}
	}
	if strings.EqualFold(quant, "all") {
		return len(names) > 0 && satisfied == len(names)
	}
	n := 1
	if v, err := strconv.Atoi(quant); err == nil && v > 0 {
		n = v
	}
	return satisfied >= n
}

func isConditionNumber(s string) bool {
	_, err := strconv.Atoi(s)
	return err == nil
}

// globMatch matches a Sigma block pattern (only '*' wildcard) against a name.
func globMatch(pattern, s string) bool {
	if !strings.Contains(pattern, "*") {
		return pattern == s
	}
	parts := strings.Split(pattern, "*")
	if parts[0] != "" && !strings.HasPrefix(s, parts[0]) {
		return false
	}
	if last := parts[len(parts)-1]; last != "" && !strings.HasSuffix(s, last) {
		return false
	}
	idx := 0
	for _, part := range parts {
		if part == "" {
			continue
		}
		j := strings.Index(s[idx:], part)
		if j < 0 {
			return false
		}
		idx += j + len(part)
	}
	return true
}
