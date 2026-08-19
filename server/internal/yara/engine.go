// Pure-Go YARA-like rule engine (no cgo dependency)
// Supports: string matching, hex patterns, regex, conditions (any/all/none)
package yara

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"gopkg.in/yaml.v3"
)

// YaraString represents a single string pattern in a YARA rule.
type YaraString struct {
	ID        string   `yaml:"id"`
	Type      string   `yaml:"type"` // text, hex, regex
	Value     string   `yaml:"value"`
	Modifiers []string `yaml:"modifiers"` // nocase, wide, ascii
}

// Rule represents a YARA-like detection rule.
type Rule struct {
	ID        string            `yaml:"id"`
	Name      string            `yaml:"name"`
	Tags      []string          `yaml:"tags"`
	Strings   []YaraString      `yaml:"strings"`
	Condition string            `yaml:"condition"` // any, all, none
	Severity  int               `yaml:"severity"`
	Meta      map[string]string `yaml:"meta"`
}

// Match represents a positive rule match result.
type Match struct {
	RuleID         string    `json:"rule_id"`
	RuleName       string    `json:"rule_name"`
	Tags           []string  `json:"tags"`
	Severity       int       `json:"severity"`
	MatchedStrings []string  `json:"matched_strings"`
	Timestamp      time.Time `json:"timestamp"`
}

// Engine is the pure-Go YARA-like rule engine.
type Engine struct {
	rules      []*Rule
	mu         sync.RWMutex
	totalScans atomic.Int64
	totalMatch atomic.Int64
}

// rulesYAML is the top-level YAML structure for loading rules.
type rulesYAML struct {
	Rules []*Rule `yaml:"rules"`
}

// NewEngine creates a new Engine instance.
func NewEngine() *Engine {
	return &Engine{}
}

// LoadRule validates and adds a rule to the engine.
func (e *Engine) LoadRule(rule *Rule) error {
	if rule == nil {
		return fmt.Errorf("rule cannot be nil")
	}
	if rule.ID == "" {
		return fmt.Errorf("rule ID is required")
	}
	if rule.Name == "" {
		return fmt.Errorf("rule Name is required")
	}
	// Validate string patterns
	for i, s := range rule.Strings {
		if err := validateYaraString(&rule.Strings[i]); err != nil {
			return fmt.Errorf("rule %s string %s: %w", rule.ID, s.ID, err)
		}
	}
	// Default condition
	if rule.Condition == "" {
		rule.Condition = "any"
	}
	if rule.Condition != "any" && rule.Condition != "all" && rule.Condition != "none" {
		return fmt.Errorf("rule %s: invalid condition %q (must be any/all/none)", rule.ID, rule.Condition)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	// Replace if already exists
	for i, r := range e.rules {
		if r.ID == rule.ID {
			e.rules[i] = rule
			return nil
		}
	}
	e.rules = append(e.rules, rule)
	return nil
}

// LoadRulesFromYAML parses YAML rule definitions and loads them.
func (e *Engine) LoadRulesFromYAML(data []byte) error {
	var doc rulesYAML
	if err := yaml.Unmarshal(data, &doc); err != nil {
		return fmt.Errorf("failed to parse YAML: %w", err)
	}
	var errs []string
	for _, rule := range doc.Rules {
		if err := e.LoadRule(rule); err != nil {
			errs = append(errs, err.Error())
			slog.Warn("yara: failed to load rule from YAML", "error", err)
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("some rules failed to load: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ScanBytes scans binary data against all loaded rules.
func (e *Engine) ScanBytes(data []byte) []*Match {
	e.totalScans.Add(1)
	e.mu.RLock()
	rules := make([]*Rule, len(e.rules))
	copy(rules, e.rules)
	e.mu.RUnlock()

	var matches []*Match
	for _, rule := range rules {
		if m := matchRule(rule, data, nil); m != nil {
			matches = append(matches, m)
			e.totalMatch.Add(1)
		}
	}
	return matches
}

// ScanFile reads a file and scans its bytes.
func (e *Engine) ScanFile(path string) ([]*Match, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return e.ScanBytes(data), nil
}

// ScanProcess scans process attributes (name, cmdline) as text.
func (e *Engine) ScanProcess(pid int, name string, cmdline string) []*Match {
	e.totalScans.Add(1)
	e.mu.RLock()
	rules := make([]*Rule, len(e.rules))
	copy(rules, e.rules)
	e.mu.RUnlock()

	combined := []byte(strings.ToLower(name) + " " + strings.ToLower(cmdline))
	attrs := map[string]string{
		"process_name": name,
		"cmdline":      cmdline,
		"pid":          fmt.Sprintf("%d", pid),
	}

	var matches []*Match
	for _, rule := range rules {
		if m := matchRule(rule, combined, attrs); m != nil {
			matches = append(matches, m)
			e.totalMatch.Add(1)
		}
	}
	return matches
}

// ListRules returns a copy of all loaded rules.
func (e *Engine) ListRules() []*Rule {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]*Rule, len(e.rules))
	copy(out, e.rules)
	return out
}

// RemoveRule removes a rule by ID; returns true if found and removed.
func (e *Engine) RemoveRule(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	for i, r := range e.rules {
		if r.ID == id {
			e.rules = append(e.rules[:i], e.rules[i+1:]...)
			return true
		}
	}
	return false
}

// RuleCount returns the number of loaded rules.
func (e *Engine) RuleCount() int {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.rules)
}

// TotalScans returns total scan invocations.
func (e *Engine) TotalScans() int64 {
	return e.totalScans.Load()
}

// TotalMatches returns total matches found across all scans.
func (e *Engine) TotalMatches() int64 {
	return e.totalMatch.Load()
}

// --- internal helpers ---

func validateYaraString(s *YaraString) error {
	switch s.Type {
	case "text":
		// nothing to validate
	case "hex":
		cleaned := strings.ReplaceAll(s.Value, " ", "")
		if len(cleaned)%2 != 0 {
			return fmt.Errorf("hex value must have even number of hex digits")
		}
		if _, err := hex.DecodeString(cleaned); err != nil {
			return fmt.Errorf("invalid hex value: %w", err)
		}
	case "regex":
		if _, err := regexp.Compile(s.Value); err != nil {
			return fmt.Errorf("invalid regex: %w", err)
		}
	default:
		return fmt.Errorf("unknown type %q (must be text/hex/regex)", s.Type)
	}
	return nil
}

// matchRule checks whether the data matches the rule conditions.
// attrs is optional metadata (e.g., process_name, cmdline) for contextual matching.
func matchRule(rule *Rule, data []byte, attrs map[string]string) *Match {
	if len(rule.Strings) == 0 {
		return nil
	}

	var matched []string
	for _, s := range rule.Strings {
		if matchString(&s, data) {
			matched = append(matched, s.ID)
		}
	}

	var conditionMet bool
	switch rule.Condition {
	case "all":
		conditionMet = len(matched) == len(rule.Strings)
	case "none":
		conditionMet = len(matched) == 0
	default: // "any"
		conditionMet = len(matched) > 0
	}

	if !conditionMet {
		return nil
	}

	return &Match{
		RuleID:         rule.ID,
		RuleName:       rule.Name,
		Tags:           rule.Tags,
		Severity:       rule.Severity,
		MatchedStrings: matched,
		Timestamp:      time.Now().UTC(),
	}
}

// matchString checks whether a single YaraString pattern matches the data.
func matchString(s *YaraString, data []byte) bool {
	nocase := hasModifier(s.Modifiers, "nocase")

	switch s.Type {
	case "text":
		needle := s.Value
		haystack := data
		if nocase {
			needle = strings.ToLower(needle)
			haystack = bytes.ToLower(data)
		}
		return bytes.Contains(haystack, []byte(needle))

	case "hex":
		cleaned := strings.ReplaceAll(s.Value, " ", "")
		decoded, err := hex.DecodeString(cleaned)
		if err != nil {
			// 「一致しなかった」と「そもそも評価できなかった」を同じ
			// false で返していました。壊れた16進文字列を持つルールは、
			// 一度も発火しないまま有効なルールとして並び続けます。
			slog.Error("yara: 16進文字列を読めないため、この条件は評価されません",
				"string", s.ID, "error", err)
			return false
		}
		return bytes.Contains(data, decoded)

	case "regex":
		flags := ""
		if nocase {
			flags = "(?i)"
		}
		re, err := regexp.Compile(flags + s.Value)
		if err != nil {
			slog.Error("yara: 正規表現をコンパイルできないため、この条件は評価されません",
				"string", s.ID, "error", err)
			return false
		}
		return re.Match(data)
	}
	return false
}

func hasModifier(modifiers []string, mod string) bool {
	for _, m := range modifiers {
		if m == mod {
			return true
		}
	}
	return false
}
