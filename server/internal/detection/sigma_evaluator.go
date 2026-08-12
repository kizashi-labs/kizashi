// Package detection — SigmaEvaluator parses and evaluates Sigma detection rules
// expressed as YAML against flat event maps.
//
// This implementation provides a lightweight, self-contained Sigma evaluator
// that supports the most common field modifiers and condition operators used in
// community Sigma rules without pulling in heavy external dependencies beyond
// gopkg.in/yaml.v3 (already a transitive dependency of sigma-go).
package detection

import (
	"encoding/base64"
	"fmt"
	"log/slog"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"

	"gopkg.in/yaml.v3"

	"github.com/edr-platform/server/internal/metrics"
)

// ─── Sigma Rule Types ────────────────────────────────────────

// SigmaRule represents a parsed Sigma rule.
type SigmaRule struct {
	Title          string
	Description    string
	Status         string
	Level          string // informational, low, medium, high, critical
	Tags           []string
	LogSource      SigmaLogSource
	Detection      SigmaDetection
	FalsePositives []string

	// DBSeverity is the `rules.severity` column for a rule loaded from the
	// database, or 0 for a builtin. It exists so the API path reports the SAME
	// severity the detection engine reports for the same rule.
	//
	// Without it the two engines disagree: the detection engine uses the column
	// (4 for "Suspicious chmod of Executable in /tmp"), while the API derived one
	// from the Sigma `level` (low -> 3). Deduplication keys on
	// (title, severity, source, agent), so a severity mismatch alone is enough to
	// stop the same finding from being recognised as one — measured at 55
	// unmerged duplicates per 1.67 benign host-days.
	DBSeverity int
}

// SigmaLogSource describes the log source for a Sigma rule.
type SigmaLogSource struct {
	Product  string
	Category string
	Service  string
}

// SigmaDetection holds the raw detection block from a Sigma rule.
type SigmaDetection struct {
	Selections map[string]interface{} // named selections
	Condition  string
	Timeframe  string
}

// SigmaMatch represents a rule match result.
type SigmaMatch struct {
	RuleTitle     string
	Level         string
	Tags          []string
	MatchedFields map[string]interface{}

	// Severity carries the DB rule's declared severity (0 for builtins, which
	// have none and keep the level-derived value). See SigmaRule.DBSeverity.
	Severity int
}

// ─── Compiled Rule ───────────────────────────────────────────

// CompiledSigmaRule holds a parsed rule and its compiled evaluator function.
type CompiledSigmaRule struct {
	Rule     *SigmaRule
	Evaluate func(event map[string]interface{}) bool
}

// ─── Evaluator ───────────────────────────────────────────────

// SigmaEvaluator evaluates events against a set of compiled Sigma rules.
type SigmaEvaluator struct {
	mu    sync.RWMutex
	rules []*CompiledSigmaRule
}

// NewSigmaEvaluator creates an empty SigmaEvaluator.
func NewSigmaEvaluator() *SigmaEvaluator {
	return &SigmaEvaluator{}
}

// LoadRule parses a Sigma YAML string and compiles it into the evaluator.
func (e *SigmaEvaluator) LoadRule(yamlContent string) error {
	rule, err := parseSigmaYAML(yamlContent)
	if err != nil {
		return fmt.Errorf("parse sigma rule: %w", err)
	}

	evaluateFn, err := compileSigmaCondition(rule)
	if err != nil {
		return fmt.Errorf("compile sigma condition '%s': %w", rule.Title, err)
	}

	compiled := &CompiledSigmaRule{
		Rule:     rule,
		Evaluate: evaluateFn,
	}

	e.mu.Lock()
	e.rules = append(e.rules, compiled)
	e.mu.Unlock()

	return nil
}

// EvaluateEvent checks an event map against all loaded rules.
// Returns all matches (may be empty but never nil).
func (e *SigmaEvaluator) EvaluateEvent(event map[string]interface{}) []SigmaMatch {
	e.mu.RLock()
	rules := e.rules
	e.mu.RUnlock()

	eventType, _ := event["type"].(string)

	var matches []SigmaMatch
	for _, cr := range rules {
		if cr.Evaluate(event) {
			// Shadow-mode logsource.category check (P4-9): never filters, only
			// flags. See sigma_category.go for the mapping and rationale.
			if !categoryCompatible(eventType, cr.Rule.LogSource.Category) {
				metrics.SigmaCategoryMismatch.WithLabelValues(cr.Rule.Title).Inc()
				slog.Warn("sigma: rule matched an event outside its logsource.category (shadow mode, not filtered)",
					"rule", cr.Rule.Title, "rule_category", cr.Rule.LogSource.Category, "event_type", eventType)
			}
			matches = append(matches, SigmaMatch{
				RuleTitle:     cr.Rule.Title,
				Level:         cr.Rule.Level,
				Tags:          cr.Rule.Tags,
				MatchedFields: event,
				Severity:      cr.Rule.DBSeverity,
			})
		}
	}
	return matches
}

// LoadRulesFromDB loads all active Sigma rules from the database.
// pool must be a *pgxpool.Pool; typed as interface{} to avoid a hard import
// dependency at the package API boundary — callers that have the pool should
// pass it directly; the function performs a type assertion internally.
func (e *SigmaEvaluator) LoadRulesFromDB(pool interface{}) error {
	// Import pgxpool via type assertion to keep this file dependency-light.
	// The actual DB interaction is delegated to a helper that does the assertion.
	return loadSigmaRulesFromPool(e, pool)
}

// RuleCount returns the number of compiled rules currently loaded.
func (e *SigmaEvaluator) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// ClearRules removes all compiled rules, allowing a fresh reload.
func (e *SigmaEvaluator) ClearRules() {
	e.mu.Lock()
	e.rules = nil
	e.mu.Unlock()
}

// ReloadFromDB atomically replaces all rules: clears the current set,
// reloads built-in rules, then reloads custom rules from the DB.
// Safe to call concurrently with EvaluateEvent.
func (e *SigmaEvaluator) ReloadFromDB(pool interface{}) error {
	e.ClearRules()
	LoadBuiltinRules(e)
	return loadSigmaRulesFromPool(e, pool)
}

// ─── YAML Parsing ────────────────────────────────────────────

// sigmaYAMLDoc is used for raw YAML decoding before mapping to SigmaRule.
type sigmaYAMLDoc struct {
	Title          string                 `yaml:"title"`
	Description    string                 `yaml:"description"`
	Status         string                 `yaml:"status"`
	Level          string                 `yaml:"level"`
	Tags           []string               `yaml:"tags"`
	FalsePositives interface{}            `yaml:"falsepositives"`
	LogSource      map[string]string      `yaml:"logsource"`
	Detection      map[string]interface{} `yaml:"detection"`
}

func parseSigmaYAML(content string) (*SigmaRule, error) {
	var doc sigmaYAMLDoc
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, err
	}

	rule := &SigmaRule{
		Title:       doc.Title,
		Description: doc.Description,
		Status:      doc.Status,
		Level:       strings.ToLower(doc.Level),
		Tags:        doc.Tags,
		LogSource: SigmaLogSource{
			Product:  doc.LogSource["product"],
			Category: doc.LogSource["category"],
			Service:  doc.LogSource["service"],
		},
	}

	// Parse false positives (string or list)
	switch v := doc.FalsePositives.(type) {
	case string:
		rule.FalsePositives = []string{v}
	case []interface{}:
		for _, fp := range v {
			if s, ok := fp.(string); ok {
				rule.FalsePositives = append(rule.FalsePositives, s)
			}
		}
	}

	// Parse detection block
	detection := SigmaDetection{
		Selections: make(map[string]interface{}),
	}
	for key, val := range doc.Detection {
		switch key {
		case "condition":
			if s, ok := val.(string); ok {
				detection.Condition = s
			}
		case "timeframe":
			if s, ok := val.(string); ok {
				detection.Timeframe = s
			}
		default:
			detection.Selections[key] = val
		}
	}
	rule.Detection = detection

	if rule.Title == "" {
		return nil, fmt.Errorf("sigma rule missing title")
	}
	if detection.Condition == "" {
		return nil, fmt.Errorf("sigma rule '%s' missing condition", rule.Title)
	}

	return rule, nil
}

// ─── Condition Compilation ───────────────────────────────────

// compileSigmaCondition turns a SigmaRule's detection block into a Go function.
func compileSigmaCondition(rule *SigmaRule) (func(map[string]interface{}) bool, error) {
	// Pre-compile each named selection into a matcher function.
	selFuncs := make(map[string]func(map[string]interface{}) bool, len(rule.Detection.Selections))
	for name, rawSel := range rule.Detection.Selections {
		fn, err := compileSelection(name, rawSel)
		if err != nil {
			return nil, fmt.Errorf("selection '%s': %w", name, err)
		}
		selFuncs[name] = fn
	}

	condition := strings.TrimSpace(rule.Detection.Condition)
	evalFn, err := compileConditionExpr(condition, selFuncs, rule.Title)
	if err != nil {
		return nil, err
	}
	return evalFn, nil
}

// compileSelection compiles a single selection block into a matcher.
// A selection can be a map (field: value(s)) or a list of maps (OR of maps).
func compileSelection(name string, raw interface{}) (func(map[string]interface{}) bool, error) {
	switch v := raw.(type) {
	case map[string]interface{}:
		return compileFieldMap(v)
	case []interface{}:
		// List of maps — any map must match (OR logic at top level)
		var subFns []func(map[string]interface{}) bool
		for _, item := range v {
			m, ok := item.(map[string]interface{})
			if !ok {
				continue
			}
			fn, err := compileFieldMap(m)
			if err != nil {
				return nil, err
			}
			subFns = append(subFns, fn)
		}
		return func(event map[string]interface{}) bool {
			for _, fn := range subFns {
				if fn(event) {
					return true
				}
			}
			return false
		}, nil
	default:
		return func(_ map[string]interface{}) bool { return false }, nil
	}
}

// compileFieldMap compiles a map of "field|modifier: value(s)" pairs.
// All pairs must match (AND logic within a selection map).
func compileFieldMap(m map[string]interface{}) (func(map[string]interface{}) bool, error) {
	type fieldCheck struct {
		field    string
		modifier string
		matchFn  func(eventVal interface{}) bool
	}

	var checks []fieldCheck

	for key, val := range m {
		field, modifier := parseFieldKey(key)
		matchFn, err := buildMatchFn(modifier, val)
		if err != nil {
			return nil, fmt.Errorf("field '%s': %w", key, err)
		}
		checks = append(checks, fieldCheck{field: field, modifier: modifier, matchFn: matchFn})
	}

	return func(event map[string]interface{}) bool {
		for _, chk := range checks {
			eventVal, exists := event[chk.field]
			if !exists {
				// Try case-insensitive field lookup
				eventVal, exists = findFieldCaseInsensitive(event, chk.field)
			}
			if !exists {
				return false
			}
			if !chk.matchFn(eventVal) {
				return false
			}
		}
		return true
	}, nil
}

// parseFieldKey splits "FieldName|modifier" into (field, modifier).
func parseFieldKey(key string) (field, modifier string) {
	parts := strings.SplitN(key, "|", 2)
	if len(parts) == 2 {
		return parts[0], strings.ToLower(parts[1])
	}
	return key, ""
}

// findFieldCaseInsensitive does a case-insensitive field name lookup.
func findFieldCaseInsensitive(event map[string]interface{}, field string) (interface{}, bool) {
	lower := strings.ToLower(field)
	for k, v := range event {
		if strings.ToLower(k) == lower {
			return v, true
		}
	}
	return nil, false
}

// buildMatchFn creates a value-matching function for the given modifier and pattern.
func buildMatchFn(modifier string, pattern interface{}) (func(interface{}) bool, error) {
	// Normalise pattern to a slice of strings for uniform handling.
	patterns, requireAll := normalisePatterns(modifier, pattern)

	// Value-transform / typed modifiers. Handled before the string-comparison
	// switch below because they change what "match" means (an IP inside a CIDR,
	// a number over a threshold, or the base64/dash-normalised form of the
	// pattern). Previously every one of these fell through to the equality
	// default and silently never matched, so whole rule shapes were inert.
	toks := modifierTokens(modifier)

	if hasToken(toks, "cidr") {
		return buildCIDRMatch(patterns), nil
	}
	for _, op := range []string{"gte", "lte", "gt", "lt"} {
		if hasToken(toks, op) {
			return buildNumericMatch(op, patterns), nil
		}
	}
	if hasToken(toks, "base64offset") || hasToken(toks, "base64") || hasToken(toks, "windash") {
		return buildTransformMatch(toks, patterns, requireAll), nil
	}

	switch modifier {
	case "", "contains":
		return func(val interface{}) bool {
			s := stringify(val)
			return matchAnyOrAll(s, patterns, requireAll, func(v, p string) bool {
				return strings.Contains(strings.ToLower(v), strings.ToLower(p))
			})
		}, nil

	case "startswith":
		return func(val interface{}) bool {
			s := stringify(val)
			return matchAnyOrAll(s, patterns, requireAll, func(v, p string) bool {
				return strings.HasPrefix(strings.ToLower(v), strings.ToLower(p))
			})
		}, nil

	case "endswith":
		return func(val interface{}) bool {
			s := stringify(val)
			return matchAnyOrAll(s, patterns, requireAll, func(v, p string) bool {
				return strings.HasSuffix(strings.ToLower(v), strings.ToLower(p))
			})
		}, nil

	case "re":
		// Compile all regex patterns up-front.
		regs := make([]*regexp.Regexp, 0, len(patterns))
		for _, p := range patterns {
			re, err := regexp.Compile(p)
			if err != nil {
				return nil, fmt.Errorf("invalid regex '%s': %w", p, err)
			}
			regs = append(regs, re)
		}
		return func(val interface{}) bool {
			s := stringify(val)
			if requireAll {
				for _, re := range regs {
					if !re.MatchString(s) {
						return false
					}
				}
				return true
			}
			for _, re := range regs {
				if re.MatchString(s) {
					return true
				}
			}
			return false
		}, nil

	case "all":
		// "all" forces requireAll=true for the contains check on a list.
		return func(val interface{}) bool {
			s := stringify(val)
			for _, p := range patterns {
				if !strings.Contains(strings.ToLower(s), strings.ToLower(p)) {
					return false
				}
			}
			return true
		}, nil

	case "contains|all":
		return func(val interface{}) bool {
			s := stringify(val)
			for _, p := range patterns {
				if !strings.Contains(strings.ToLower(s), strings.ToLower(p)) {
					return false
				}
			}
			return true
		}, nil

	default:
		// Unknown modifier — fall back to equality / contains check.
		return func(val interface{}) bool {
			s := stringify(val)
			return matchAnyOrAll(s, patterns, requireAll, func(v, p string) bool {
				return strings.EqualFold(v, p)
			})
		}, nil
	}
}

// modifierTokens splits a Sigma modifier chain ("base64offset|contains") into
// its individual tokens for whole-token membership checks.
func modifierTokens(modifier string) []string {
	if modifier == "" {
		return nil
	}
	return strings.Split(modifier, "|")
}

// hasToken reports whether toks contains t (exact, so "gte" ≠ "gt").
func hasToken(toks []string, t string) bool {
	for _, x := range toks {
		if x == t {
			return true
		}
	}
	return false
}

// comparisonToken returns the string-comparison operator present in a modifier
// chain (contains/startswith/endswith/re), or "" if none.
func comparisonToken(toks []string) string {
	for _, t := range toks {
		switch t {
		case "contains", "startswith", "endswith", "re":
			return t
		}
	}
	return ""
}

// buildCIDRMatch matches when the event value is an IP inside any of the CIDR
// patterns (Sigma `|cidr`). List patterns are OR-ed.
func buildCIDRMatch(patterns []string) func(interface{}) bool {
	nets := make([]*net.IPNet, 0, len(patterns))
	for _, p := range patterns {
		if _, n, err := net.ParseCIDR(strings.TrimSpace(p)); err == nil {
			nets = append(nets, n)
		}
	}
	return func(val interface{}) bool {
		ip := net.ParseIP(strings.TrimSpace(stringify(val)))
		if ip == nil {
			return false
		}
		for _, n := range nets {
			if n.Contains(ip) {
				return true
			}
		}
		return false
	}
}

// buildNumericMatch matches when the numeric event value satisfies the
// comparison against any threshold pattern (Sigma `|gt|gte|lt|lte`).
func buildNumericMatch(op string, patterns []string) func(interface{}) bool {
	return func(val interface{}) bool {
		fv, ok := toFloat(val)
		if !ok {
			return false
		}
		for _, p := range patterns {
			tv, err := strconv.ParseFloat(strings.TrimSpace(p), 64)
			if err != nil {
				continue
			}
			switch op {
			case "gt":
				if fv > tv {
					return true
				}
			case "gte":
				if fv >= tv {
					return true
				}
			case "lt":
				if fv < tv {
					return true
				}
			case "lte":
				if fv <= tv {
					return true
				}
			}
		}
		return false
	}
}

// buildTransformMatch handles the value-encoding modifiers (base64 / base64offset
// / windash): it transforms each pattern into its encoded/dash-normalised form(s)
// and then applies the chain's comparison operator (default: contains for
// base64offset and windash — their outputs are substrings; equals for a bare
// base64).
func buildTransformMatch(toks, patterns []string, requireAll bool) func(interface{}) bool {
	var transformed []string
	for _, p := range patterns {
		switch {
		case hasToken(toks, "base64offset"):
			transformed = append(transformed, base64Offsets(p)...)
		case hasToken(toks, "base64"):
			transformed = append(transformed, base64.StdEncoding.EncodeToString([]byte(p)))
		}
		if hasToken(toks, "windash") {
			transformed = append(transformed, windashVariants(p)...)
		}
	}

	cmp := comparisonToken(toks)
	if cmp == "" {
		if hasToken(toks, "base64") && !hasToken(toks, "base64offset") && !hasToken(toks, "windash") {
			cmp = "equals"
		} else {
			cmp = "contains"
		}
	}

	return func(val interface{}) bool {
		s := stringify(val)
		cmpFn := func(v, p string) bool {
			switch cmp {
			case "startswith":
				return strings.HasPrefix(strings.ToLower(v), strings.ToLower(p))
			case "endswith":
				return strings.HasSuffix(strings.ToLower(v), strings.ToLower(p))
			case "equals":
				return strings.EqualFold(v, p)
			default: // contains (base64/windash are always substring-style)
				return strings.Contains(strings.ToLower(v), strings.ToLower(p))
			}
		}
		return matchAnyOrAll(s, transformed, requireAll, cmpFn)
	}
}

// base64Offsets returns the three base64 encodings of value as it would appear
// at byte offsets 0/1/2 within a larger base64 blob — the Sigma `base64offset`
// transform (mirrors pySigma's start/end slicing), so an encoded PowerShell
// payload matches regardless of its alignment in the command line.
func base64Offsets(value string) []string {
	startOffsets := [3]int{0, 2, 3}
	endOffsets := [3]int{0, -3, -2} // 0 == "to end"
	out := make([]string, 0, 3)
	for i := 0; i < 3; i++ {
		enc := base64.StdEncoding.EncodeToString([]byte(strings.Repeat(" ", i) + value))
		start := startOffsets[i]
		end := len(enc)
		if eo := endOffsets[(len(value)+i)%3]; eo < 0 {
			end = len(enc) + eo
		}
		if start < 0 || start > end || end > len(enc) {
			continue
		}
		out = append(out, enc[start:end])
	}
	return out
}

// windashVariants returns pattern variants with each "-" replaced by the dash
// characters a Windows CLI accepts interchangeably (Sigma `windash`) — catching
// "powershell /enc" and unicode-dash obfuscation of "powershell -enc".
func windashVariants(p string) []string {
	if !strings.Contains(p, "-") {
		return []string{p}
	}
	dashes := []string{"-", "/", "–", "—", "―"}
	out := make([]string, 0, len(dashes))
	for _, d := range dashes {
		out = append(out, strings.ReplaceAll(p, "-", d))
	}
	return out
}

// toFloat coerces a JSON-decoded event value (float64/int/json.Number/string) to
// a float for numeric comparison.
func toFloat(val interface{}) (float64, bool) {
	switch v := val.(type) {
	case float64:
		return v, true
	case float32:
		return float64(v), true
	case int:
		return float64(v), true
	case int64:
		return float64(v), true
	case string:
		f, err := strconv.ParseFloat(strings.TrimSpace(v), 64)
		return f, err == nil
	default:
		return 0, false
	}
}

// normalisePatterns converts a Sigma pattern value to []string and detects
// the "all" modifier embedded in compound keys like "contains|all".
func normalisePatterns(modifier string, pattern interface{}) ([]string, bool) {
	requireAll := strings.Contains(modifier, "all")

	switch v := pattern.(type) {
	case string:
		return []string{v}, requireAll
	case []interface{}:
		strs := make([]string, 0, len(v))
		for _, item := range v {
			strs = append(strs, fmt.Sprintf("%v", item))
		}
		return strs, requireAll
	case int, int64, float64, bool:
		return []string{fmt.Sprintf("%v", v)}, requireAll
	case nil:
		return []string{""}, requireAll
	default:
		return []string{fmt.Sprintf("%v", v)}, requireAll
	}
}

// matchAnyOrAll applies cmpFn to the value against all patterns.
// When requireAll=true, all patterns must match; otherwise any match suffices.
func matchAnyOrAll(val string, patterns []string, requireAll bool, cmpFn func(string, string) bool) bool {
	if requireAll {
		for _, p := range patterns {
			if !cmpFn(val, p) {
				return false
			}
		}
		return len(patterns) > 0
	}
	for _, p := range patterns {
		if cmpFn(val, p) {
			return true
		}
	}
	return false
}

// stringify converts an interface{} to a string for pattern matching.
func stringify(v interface{}) string {
	if v == nil {
		return ""
	}
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprintf("%v", v)
}

// ─── Condition Expression Compiler ───────────────────────────

// compileConditionExpr compiles the condition string into an evaluator.
// Supported forms:
//   - selection                  → single selection
//   - selection1 and selection2  → AND
//   - selection1 or selection2   → OR
//   - not selection              → negation
//   - 1 of selection*            → at least 1 of wildcard-matched selections
//   - all of selection*          → all wildcard-matched selections
func compileConditionExpr(
	condition string,
	selFuncs map[string]func(map[string]interface{}) bool,
	ruleTitle string,
) (func(map[string]interface{}) bool, error) {

	cond := strings.ToLower(strings.TrimSpace(condition))

	// "1 of selection*" / "all of selection*" / "N of selection*" / "… of them"
	if matches := reOfPattern.FindStringSubmatch(cond); len(matches) == 3 {
		quantifier := matches[1] // "1", "all", or a number
		target := strings.ToLower(matches[2])
		// "them" (and a bare "*") means every selection — previously it was
		// treated as a literal prefix, matched zero selections, and the whole
		// "N of them" / "all of them" condition could never fire.
		matchAll := target == "them" || target == "*"
		prefix := strings.TrimSuffix(target, "*")

		var selected []func(map[string]interface{}) bool
		for name, fn := range selFuncs {
			if matchAll || strings.HasPrefix(strings.ToLower(name), prefix) {
				selected = append(selected, fn)
			}
		}

		if quantifier == "all" {
			return func(event map[string]interface{}) bool {
				for _, fn := range selected {
					if !fn(event) {
						return false
					}
				}
				return len(selected) > 0
			}, nil
		}
		// "1 of" or numeric — treat all as "at least 1"
		return func(event map[string]interface{}) bool {
			for _, fn := range selected {
				if fn(event) {
					return true
				}
			}
			return false
		}, nil
	}

	// Simple tokenisation for "and" / "or" / "not".
	tokens := tokeniseCondition(condition)
	fn, _, err := parseTokens(tokens, 0, selFuncs, ruleTitle)
	return fn, err
}

var reOfPattern = regexp.MustCompile(`^(\d+|all)\s+of\s+(\w+\*?)$`)

// tokeniseCondition splits the condition string into tokens (words / parens).
func tokeniseCondition(cond string) []string {
	// Normalise parentheses to space-separated tokens.
	cond = strings.ReplaceAll(cond, "(", " ( ")
	cond = strings.ReplaceAll(cond, ")", " ) ")
	raw := strings.Fields(cond)
	return raw
}

// parseTokens parses a full expression: one operand followed by any infix
// operators.
func parseTokens(
	tokens []string,
	pos int,
	selFuncs map[string]func(map[string]interface{}) bool,
	ruleTitle string,
) (func(map[string]interface{}) bool, int, error) {

	fn, newPos, err := parsePrimary(tokens, pos, selFuncs, ruleTitle)
	if err != nil {
		return nil, pos, err
	}
	return parseInfix(fn, newPos, tokens, selFuncs, ruleTitle)
}

// parsePrimary parses exactly ONE operand: "not <primary>", a parenthesised
// group, or a bare selection name. It deliberately stops before any infix
// operator.
//
// That restraint is the whole point. `not` used to recurse into parseTokens,
// which swallowed the rest of the expression, so
//
//	condition: selection and not download and not certconv
//
// compiled as `selection and not (download and not certconv)`. With
// download=false and certconv=true that yields `true and not(false)` = TRUE —
// the rule fires on exactly the input the second exclusion was added to
// suppress. Sigma binds `not` to a single operand (not > and > or).
//
// No shipped rule tripped this: every other `not` in the corpus sits at the end
// of its condition, where "the rest of the expression" is empty and the two
// readings coincide. It surfaced the first time a rule carried two exclusions.
func parsePrimary(
	tokens []string,
	pos int,
	selFuncs map[string]func(map[string]interface{}) bool,
	ruleTitle string,
) (func(map[string]interface{}) bool, int, error) {

	if pos >= len(tokens) {
		return func(_ map[string]interface{}) bool { return false }, pos, nil
	}

	tok := tokens[pos]

	if strings.ToLower(tok) == "not" {
		inner, newPos, err := parsePrimary(tokens, pos+1, selFuncs, ruleTitle)
		if err != nil {
			return nil, pos, err
		}
		return func(event map[string]interface{}) bool { return !inner(event) }, newPos, nil
	}

	if tok == "(" {
		inner, newPos, err := parseTokens(tokens, pos+1, selFuncs, ruleTitle)
		if err != nil {
			return nil, pos, err
		}
		if newPos < len(tokens) && tokens[newPos] == ")" {
			newPos++
		}
		return inner, newPos, nil
	}

	return resolveSelection(tok, selFuncs, ruleTitle), pos + 1, nil
}

// parseInfix handles binary operators (and, or) after a primary expression.
func parseInfix(
	left func(map[string]interface{}) bool,
	pos int,
	tokens []string,
	selFuncs map[string]func(map[string]interface{}) bool,
	ruleTitle string,
) (func(map[string]interface{}) bool, int, error) {

	if pos >= len(tokens) {
		return left, pos, nil
	}

	tok := strings.ToLower(tokens[pos])

	switch tok {
	case "and":
		right, newPos, err := parsePrimary(tokens, pos+1, selFuncs, ruleTitle)
		if err != nil {
			return nil, pos, err
		}
		combined := func(event map[string]interface{}) bool {
			return left(event) && right(event)
		}
		return parseInfix(combined, newPos, tokens, selFuncs, ruleTitle)

	case "or":
		right, newPos, err := parsePrimary(tokens, pos+1, selFuncs, ruleTitle)
		if err != nil {
			return nil, pos, err
		}
		combined := func(event map[string]interface{}) bool {
			return left(event) || right(event)
		}
		return parseInfix(combined, newPos, tokens, selFuncs, ruleTitle)

	case ")":
		// End of parenthesised group — return without consuming.
		return left, pos, nil

	default:
		return left, pos, nil
	}
}

// resolveSelection looks up a selection name, supporting wildcard suffix "*".
func resolveSelection(
	name string,
	selFuncs map[string]func(map[string]interface{}) bool,
	ruleTitle string,
) func(map[string]interface{}) bool {

	// Exact match
	if fn, ok := selFuncs[name]; ok {
		return fn
	}
	// Case-insensitive match
	nameLower := strings.ToLower(name)
	for k, fn := range selFuncs {
		if strings.ToLower(k) == nameLower {
			return fn
		}
	}
	// Wildcard suffix: "selection*" matches "selection", "selection_process", etc.
	if strings.HasSuffix(name, "*") {
		prefix := strings.ToLower(strings.TrimSuffix(name, "*"))
		var matched []func(map[string]interface{}) bool
		for k, fn := range selFuncs {
			if strings.HasPrefix(strings.ToLower(k), prefix) {
				matched = append(matched, fn)
			}
		}
		return func(event map[string]interface{}) bool {
			for _, fn := range matched {
				if fn(event) {
					return true
				}
			}
			return false
		}
	}

	slog.Debug("sigma: unresolved selection name", "name", name, "rule", ruleTitle)
	return func(_ map[string]interface{}) bool { return false }
}

// ─── DB Loader ───────────────────────────────────────────────

// loadSigmaRulesFromPool queries the database for active Sigma rules and loads them.
// pool must be *pgxpool.Pool; we avoid a hard import by using reflect-free type assertion.
func loadSigmaRulesFromPool(e *SigmaEvaluator, pool interface{}) error {
	return loadSigmaRulesFromPoolTyped(e, pool)
}

// LoadRuleWithFallbackTags compiles a rule like LoadRule, but substitutes
// `fallback` for the rule's tags when the YAML itself carries no attack.* tag.
//
// This exists for the `rules` table, where the MITRE attribution lives in the
// row's mitre_tags COLUMN rather than in the Sigma document — 65 of the 225
// migration-shipped Sigma rules have an empty `tags:` and a populated column,
// including "Process Hollowing via Suspicious Executable", the rule P4-6 was
// diagnosed on. server-detect reads the column, so it attributes those alerts
// correctly; a loader that only read the YAML would emit the same detection with
// mitre_technique NULL.
//
// That is not merely cosmetic. Cross-engine deduplication
// (dedup.deduplicateByTechnique) groups on mitre_technique and skips NULL rows
// entirely, so an unattributed alert is also an UNDEDUPLICABLE one: it would
// stand alongside server-detect's copy of the same finding forever.
func (e *SigmaEvaluator) LoadRuleWithFallbackTags(yamlContent string, fallback []string) error {
	return e.loadDBRule(yamlContent, fallback, 0)
}

// loadDBRule compiles a rule from the `rules` table, carrying the row's declared
// severity so the API reports the same number the detection engine does.
func (e *SigmaEvaluator) loadDBRule(yamlContent string, fallback []string, dbSeverity int) error {
	rule, err := parseSigmaYAML(yamlContent)
	if err != nil {
		return fmt.Errorf("parse sigma rule: %w", err)
	}
	if parseMITRETechFromTags(rule.Tags) == "" && len(fallback) > 0 {
		rule.Tags = append(append([]string{}, rule.Tags...), fallback...)
	}
	evaluateFn, err := compileSigmaCondition(rule)
	if err != nil {
		return fmt.Errorf("compile sigma condition '%s': %w", rule.Title, err)
	}
	rule.DBSeverity = dbSeverity
	e.mu.Lock()
	e.rules = append(e.rules, &CompiledSigmaRule{Rule: rule, Evaluate: evaluateFn})
	e.mu.Unlock()
	return nil
}

// LoadedTitles returns the set of rule titles currently compiled into the
// evaluator. Used by the DB loader to keep a builtin from being shadowed by a
// same-titled row in the `rules` table: the two sources ship different matching
// logic under identical titles, and an alert naming a title that resolves to two
// different rules is unreadable.
func (e *SigmaEvaluator) LoadedTitles() map[string]bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make(map[string]bool, len(e.rules))
	for _, r := range e.rules {
		out[r.Rule.Title] = true
	}
	return out
}
