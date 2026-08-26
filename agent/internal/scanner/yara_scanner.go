// Package scanner provides local on-device file scanning.
// yara_scanner.go implements a simplified YARA-compatible rule evaluator
// using pure Go string matching and regexp. It handles a practical subset
// of YARA syntax sufficient for most endpoint detection use cases.
package scanner

import (
	"bufio"
	"bytes"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
	"unicode/utf16"
)

// ─── Types ────────────────────────────────────────────────────

// YARAMatch represents a single rule match.
type YARAMatch struct {
	RuleName  string
	Namespace string
	Tags      []string
	Strings   []YARAStringMatch
	Meta      map[string]string
}

// YARAStringMatch is a specific string that matched within a file.
type YARAStringMatch struct {
	Identifier string
	Offset     int64
	Data       []byte
}

// yaraStringType represents the type of a YARA string pattern.
type yaraStringType int

const (
	yaraText  yaraStringType = iota // "plain text"
	yaraHex                         // { DE AD BE EF }
	yaraRegex                       // /pattern/
)

// yaraString is a compiled YARA string definition.
type yaraString struct {
	id       string
	strType  yaraStringType
	text     []byte         // for yaraText
	hexPat   []byte         // for yaraHex
	regex    *regexp.Regexp // for yaraRegex
	nocase   bool
	wide     bool
	fullword bool
}

// yaraRule is a compiled YARA rule.
type yaraRule struct {
	name      string
	namespace string
	tags      []string
	meta      map[string]string
	strings   []*yaraString
	condition yaraCondition
}

type yaraConditionType int

const (
	condAnyOf yaraConditionType = iota // any of them
	condAllOf                          // all of them
	condNOf                            // N of them
	condBool                           // boolean expression
)

type yaraCondition struct {
	condType yaraConditionType
	n        int    // for condNOf
	boolExpr string // for condBool
}

// YARAScanner holds compiled YARA rules and scans files/data.
type YARAScanner struct {
	mu    sync.RWMutex
	rules []*yaraRule
}

// NewYARAScanner creates an empty scanner.
func NewYARAScanner() *YARAScanner {
	return &YARAScanner{}
}

// LoadRules parses and compiles YARA rule text, adding to the scanner.
func (s *YARAScanner) LoadRules(rulesText string) error {
	rules, err := parseYARAText(rulesText)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = append(s.rules, rules...)
	return nil
}

// ReplaceRules replaces all rules with the given text.
func (s *YARAScanner) ReplaceRules(rulesText string) error {
	rules, err := parseYARAText(rulesText)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rules = rules
	return nil
}

// RuleCount returns the number of loaded rules.
func (s *YARAScanner) RuleCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return len(s.rules)
}

// ScanFile scans a file and returns any matching rules.
func (s *YARAScanner) ScanFile(path string) ([]YARAMatch, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	// Read up to 64MB for scanning
	const maxScan = 64 * 1024 * 1024
	data, err := io.ReadAll(io.LimitReader(f, maxScan))
	if err != nil {
		return nil, err
	}

	return s.ScanBytes(data), nil
}

// ScanBytes scans a byte slice and returns matching rules.
func (s *YARAScanner) ScanBytes(data []byte) []YARAMatch {
	s.mu.RLock()
	rules := make([]*yaraRule, len(s.rules))
	copy(rules, s.rules)
	s.mu.RUnlock()

	var matches []YARAMatch
	for _, rule := range rules {
		if m := evaluateRule(rule, data); m != nil {
			matches = append(matches, *m)
		}
	}
	return matches
}

// ─── Rule Parser ─────────────────────────────────────────────

func parseYARAText(text string) ([]*yaraRule, error) {
	var rules []*yaraRule
	sc := bufio.NewScanner(strings.NewReader(text))

	var currentRule *yaraRule
	var section string
	var ruleText strings.Builder

	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())

		// Skip comments
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") {
			continue
		}

		// New rule
		if strings.HasPrefix(line, "rule ") || strings.HasPrefix(line, "private rule ") {
			if currentRule != nil {
				rules = append(rules, currentRule)
			}
			currentRule = &yaraRule{
				meta: make(map[string]string),
			}
			ruleText.Reset()

			// Parse: rule RuleName : tag1 tag2 {
			parts := strings.Fields(line)
			idx := 0
			if parts[0] == "private" {
				idx = 1
			}
			if idx+1 < len(parts) {
				currentRule.name = parts[idx+1]
			}
			// Tags after ":"
			colonIdx := strings.Index(line, ":")
			if colonIdx > 0 {
				afterColon := strings.TrimSpace(line[colonIdx+1:])
				afterColon = strings.TrimSuffix(afterColon, "{")
				currentRule.tags = append(currentRule.tags, strings.Fields(afterColon)...)
			}
			section = ""
			continue
		}

		if currentRule == nil {
			continue
		}

		if line == "meta:" {
			section = "meta"
			continue
		}
		if line == "strings:" {
			section = "strings"
			continue
		}
		if line == "condition:" {
			section = "condition"
			continue
		}
		if line == "}" {
			if section == "condition" {
				// Condition is in ruleText
				condStr := strings.TrimSpace(ruleText.String())
				currentRule.condition = parseCondition(condStr)
				ruleText.Reset()
			}
			if currentRule.name != "" {
				rules = append(rules, currentRule)
			}
			currentRule = nil
			section = ""
			continue
		}

		switch section {
		case "meta":
			if idx := strings.Index(line, "="); idx > 0 {
				k := strings.TrimSpace(line[:idx])
				v := strings.Trim(strings.TrimSpace(line[idx+1:]), "\"")
				currentRule.meta[k] = v
			}
		case "strings":
			ys, err := parseYARAString(line)
			if err == nil && ys != nil {
				currentRule.strings = append(currentRule.strings, ys)
			}
		case "condition":
			ruleText.WriteString(line + " ")
		}
	}

	if currentRule != nil && currentRule.name != "" {
		rules = append(rules, currentRule)
	}

	return rules, sc.Err()
}

func parseYARAString(line string) (*yaraString, error) {
	// $id = "text" [modifiers]
	// $id = { hex }
	// $id = /regex/ [modifiers]
	if !strings.HasPrefix(line, "$") {
		return nil, fmt.Errorf("not a string line")
	}

	eqIdx := strings.Index(line, "=")
	if eqIdx < 0 {
		return nil, fmt.Errorf("no = in string definition")
	}

	ys := &yaraString{
		id: strings.TrimSpace(line[:eqIdx]),
	}
	rest := strings.TrimSpace(line[eqIdx+1:])

	if strings.HasPrefix(rest, "\"") {
		// Text string
		ys.strType = yaraText
		endQuote := strings.Index(rest[1:], "\"")
		if endQuote < 0 {
			return nil, fmt.Errorf("unterminated string")
		}
		text := rest[1 : endQuote+1]
		// Handle escape sequences
		text = strings.ReplaceAll(text, "\\n", "\n")
		text = strings.ReplaceAll(text, "\\t", "\t")
		text = strings.ReplaceAll(text, "\\\\", "\\")
		ys.text = []byte(text)

		mods := strings.TrimSpace(rest[endQuote+2:])
		applyModifiers(ys, mods)

	} else if strings.HasPrefix(rest, "{") {
		// Hex string
		ys.strType = yaraHex
		endBrace := strings.Index(rest, "}")
		if endBrace < 0 {
			return nil, fmt.Errorf("unterminated hex string")
		}
		hexStr := rest[1:endBrace]
		// Remove spaces and comments
		hexStr = regexp.MustCompile(`\s+`).ReplaceAllString(hexStr, "")
		hexStr = regexp.MustCompile(`\[.*?\]`).ReplaceAllString(hexStr, "??") // wildcards
		hexStr = strings.ReplaceAll(hexStr, "?", "0")
		b, err := hex.DecodeString(hexStr)
		if err != nil {
			return nil, err
		}
		ys.hexPat = b

	} else if strings.HasPrefix(rest, "/") {
		// Regex
		ys.strType = yaraRegex
		endSlash := strings.LastIndex(rest[1:], "/")
		if endSlash < 0 {
			return nil, fmt.Errorf("unterminated regex")
		}
		pattern := rest[1 : endSlash+1]
		mods := ""
		if endSlash+2 < len(rest) {
			mods = rest[endSlash+2:]
		}
		flags := ""
		if strings.Contains(mods, "i") || strings.Contains(mods, "nocase") {
			flags = "(?i)"
		}
		re, err := regexp.Compile(flags + pattern)
		if err != nil {
			return nil, err
		}
		ys.regex = re
		applyModifiers(ys, mods)
	}

	return ys, nil
}

func applyModifiers(ys *yaraString, mods string) {
	mods = strings.ToLower(mods)
	ys.nocase = strings.Contains(mods, "nocase")
	ys.wide = strings.Contains(mods, "wide")
	ys.fullword = strings.Contains(mods, "fullword")
}

func parseCondition(cond string) yaraCondition {
	cond = strings.TrimSpace(strings.ToLower(cond))
	if cond == "any of them" {
		return yaraCondition{condType: condAnyOf}
	}
	if cond == "all of them" {
		return yaraCondition{condType: condAllOf}
	}
	if strings.HasSuffix(cond, "of them") {
		var n int
		fmt.Sscanf(cond, "%d", &n)
		return yaraCondition{condType: condNOf, n: n}
	}
	return yaraCondition{condType: condBool, boolExpr: cond}
}

// ─── Rule Evaluator ───────────────────────────────────────────

func evaluateRule(rule *yaraRule, data []byte) *YARAMatch {
	// Find all matching strings
	stringMatches := make(map[string][]YARAStringMatch)
	for _, ys := range rule.strings {
		matches := findStringMatches(ys, data)
		if len(matches) > 0 {
			stringMatches[ys.id] = matches
		}
	}

	// Evaluate condition
	var matched bool
	switch rule.condition.condType {
	case condAnyOf:
		matched = len(stringMatches) > 0
	case condAllOf:
		matched = len(stringMatches) == len(rule.strings)
	case condNOf:
		matched = len(stringMatches) >= rule.condition.n
	case condBool:
		matched = evalBoolCondition(rule.condition.boolExpr, stringMatches)
	}

	if !matched {
		return nil
	}

	m := &YARAMatch{
		RuleName:  rule.name,
		Namespace: rule.namespace,
		Tags:      rule.tags,
		Meta:      rule.meta,
	}
	for _, matches := range stringMatches {
		m.Strings = append(m.Strings, matches...)
	}
	return m
}

func evalBoolCondition(expr string, matches map[string][]YARAStringMatch) bool {
	// Simple evaluator: replace $var with true/false and evaluate
	expr = strings.TrimSpace(expr)

	// Replace $identifier with true/false
	re := regexp.MustCompile(`\$\w+`)
	result := re.ReplaceAllStringFunc(expr, func(id string) string {
		if _, ok := matches[id]; ok {
			return "true"
		}
		return "false"
	})

	// Simple AND/OR evaluation (handles: $a and $b, $a or $b, not $a)
	result = strings.ToLower(result)
	result = strings.ReplaceAll(result, " and ", " && ")
	result = strings.ReplaceAll(result, " or ", " || ")
	result = strings.ReplaceAll(result, "not ", "!")

	return evalSimpleBool(result)
}

func evalSimpleBool(expr string) bool {
	expr = strings.TrimSpace(expr)
	if expr == "true" {
		return true
	}
	if expr == "false" {
		return false
	}
	// Handle "x || y"
	if idx := strings.Index(expr, "||"); idx > 0 {
		return evalSimpleBool(expr[:idx]) || evalSimpleBool(expr[idx+2:])
	}
	// Handle "x && y"
	if idx := strings.Index(expr, "&&"); idx > 0 {
		return evalSimpleBool(expr[:idx]) && evalSimpleBool(expr[idx+2:])
	}
	// Handle "!x"
	if strings.HasPrefix(expr, "!") {
		return !evalSimpleBool(expr[1:])
	}
	return false
}

func findStringMatches(ys *yaraString, data []byte) []YARAStringMatch {
	var results []YARAStringMatch

	switch ys.strType {
	case yaraText:
		pattern := ys.text
		searchData := data
		if ys.nocase {
			pattern = bytes.ToLower(pattern)
			searchData = bytes.ToLower(data)
		}
		// An empty pattern makes bytes.Index always return 0, which would walk
		// offset one past len(searchData) and panic (slice bounds out of range).
		// A zero-length string never "matches" meaningfully — skip it.
		if len(pattern) == 0 {
			break
		}
		offset := 0
		for {
			idx := bytes.Index(searchData[offset:], pattern)
			if idx < 0 {
				break
			}
			abs := offset + idx
			// Under nocase, searchData is bytes.ToLower(data), whose length can
			// diverge from data for non-ASCII bytes; clamp so indices derived
			// from searchData never slice data out of range.
			ds, de := abs, abs+len(pattern)
			if ds > len(data) {
				ds = len(data)
			}
			if de > len(data) {
				de = len(data)
			}
			results = append(results, YARAStringMatch{
				Identifier: ys.id,
				Offset:     int64(abs),
				Data:       data[ds:de],
			})
			offset = abs + 1
			if len(results) >= 100 { // cap matches per string
				break
			}
		}
		// Wide string matching (UTF-16LE)
		if ys.wide {
			wide := toUTF16LE(ys.text)
			results = append(results, findBytesAll(ys.id, data, wide)...)
		}

	case yaraHex:
		results = findBytesAll(ys.id, data, ys.hexPat)

	case yaraRegex:
		locs := ys.regex.FindAllIndex(data, 100)
		for _, loc := range locs {
			results = append(results, YARAStringMatch{
				Identifier: ys.id,
				Offset:     int64(loc[0]),
				Data:       data[loc[0]:loc[1]],
			})
		}
	}

	return results
}

func findBytesAll(id string, data, pattern []byte) []YARAStringMatch {
	var results []YARAStringMatch
	// Empty pattern would make bytes.Index always return 0 and walk offset past
	// the end of data (slice bounds out of range) — nothing to match.
	if len(pattern) == 0 {
		return results
	}
	offset := 0
	for {
		idx := bytes.Index(data[offset:], pattern)
		if idx < 0 {
			break
		}
		abs := offset + idx
		results = append(results, YARAStringMatch{
			Identifier: id,
			Offset:     int64(abs),
			Data:       data[abs : abs+len(pattern)],
		})
		offset = abs + 1
		if len(results) >= 100 {
			break
		}
	}
	return results
}

func toUTF16LE(b []byte) []byte {
	runes := []rune(string(b))
	buf := make([]byte, 0, len(runes)*2)
	for _, r := range runes {
		u := utf16.Encode([]rune{r})
		for _, v := range u {
			buf = append(buf, byte(v), byte(v>>8))
		}
	}
	return buf
}

// ─── File Scanner Integration ─────────────────────────────────

// ScanResult is the result of scanning a file.
type ScanResult struct {
	Path     string
	Matches  []YARAMatch
	ScanTime time.Duration
	Error    error
}

// ScanFileAsync scans a file asynchronously and sends result to ch.
func (s *YARAScanner) ScanFileAsync(path string, ch chan<- ScanResult) {
	go func() {
		start := time.Now()
		matches, err := s.ScanFile(path)
		ch <- ScanResult{
			Path:     path,
			Matches:  matches,
			ScanTime: time.Since(start),
			Error:    err,
		}
	}()
}
