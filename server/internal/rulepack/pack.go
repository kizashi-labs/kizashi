// Package rulepack loads detection content that ships separately from the code.
//
// Detection rules used to live inside migrations: 2,404 of them, embedded as
// INSERT statements across 96 files. That works, but it welds two things
// together that have nothing to do with each other — the shape of the database
// and the content of the detection library. A rule cannot be shipped, withheld,
// updated or dated independently of a schema change, and after the fact there
// is no way to ask which migration produced a given rule.
//
// A pack is a file describing rules. The loader upserts them into the rules
// table by pack_key, so re-reading the same pack is a no-op and an updated pack
// updates in place. Nothing else about rule evaluation changes: once loaded,
// pack rules are ordinary rows that the existing engines already read.
package rulepack

import (
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
)

// Rule mirrors the subset of the rules table that content should specify.
//
// Deliberately absent: id, compiled, created_at/updated_at, tenant_id,
// curate_state, quarantine fields. Those are the platform's business, not the
// content's — a pack that could set them would be able to describe a row the
// server never intended to accept.
type Rule struct {
	Name        string   `json:"name"`
	Type        string   `json:"type"`     // sigma | yara | behavioral
	Platform    []string `json:"platform"` // windows | linux | darwin
	Severity    int      `json:"severity"` // 1..10
	Content     string   `json:"content"`  // the rule body (Sigma YAML, YARA source, …)
	Description string   `json:"description,omitempty"`
	Source      string   `json:"source,omitempty"`     // defaults to community
	MitreTags   []string `json:"mitre_tags,omitempty"` // e.g. T1059.001
	RefLinks    []string `json:"ref_links,omitempty"`
	Tags        []string `json:"tags,omitempty"`

	// Enabled is a pointer so a pack can distinguish "leave the column at its
	// default" from "explicitly disabled". A plain bool would silently disable
	// every rule in a pack that omitted the field.
	Enabled *bool `json:"enabled,omitempty"`

	// Response flags. A rule that isolates a host is a consequential thing for
	// content to be able to declare, so these are opt-in per rule and default
	// to false rather than inheriting anything.
	AutoIsolate    bool `json:"auto_isolate,omitempty"`
	AutoKill       bool `json:"auto_kill,omitempty"`
	AutoQuarantine bool `json:"auto_quarantine,omitempty"`
}

// Pack is one file's worth of content.
type Pack struct {
	Name        string `json:"name"`    // stable identifier, used to build pack_key
	Version     string `json:"version"` // informational; shown in logs
	Description string `json:"description,omitempty"`
	Rules       []Rule `json:"rules"`
}

// Column vocabularies, mirroring the CHECK constraints on rules. Duplicated
// here on purpose: a pack that violates one should be rejected by name at load
// time, not by SQLSTATE 23514 partway through a transaction.
var (
	validTypes = map[string]bool{"sigma": true, "yara": true, "behavioral": true}

	// The spellings the detection engine canonicalises, not a tidier subset of
	// them. rules.platform carries no CHECK constraint and the seeded content
	// uses several: 269 windows, 227 linux, 159 macos, 2 darwin. The engine's
	// canonPlatform folds macos/darwin/osx/macosx/mac together, so all of those
	// match the same hosts.
	//
	// Accepting a narrower set here would reject content that the engine
	// evaluates correctly — which is what happened on the first export: 159
	// working macOS rules were refused for spelling "macos" instead of
	// "darwin". A validator stricter than the thing it guards does not make the
	// system safer, it just makes valid content unshippable.
	//
	// TestPlatformVocabularyMatchesEngine keeps this in step with canonPlatform.
	validPlatforms = map[string]bool{
		"windows": true, "win": true,
		"linux": true,
		"macos": true, "darwin": true, "osx": true, "macosx": true, "mac": true,
	}
	validSources = map[string]bool{
		"community": true, "custom": true, "threat-intel": true,
		"ai-generated": true, "builtin": true, "sigmahq": true, "builtin-parity": true,
	}
)

const defaultSource = "community"

// PackKey is the identity of a rule within a pack. Stored in rules.pack_key,
// which carries a partial unique index, so loading is idempotent.
func (p *Pack) PackKey(ruleName string) string {
	return p.Name + "/" + ruleName
}

// Parse reads a pack and validates it completely before returning.
//
// Every problem is reported, not just the first. A pack rejected one error at a
// time takes as many edit/reload cycles as it has mistakes, and the whole point
// of loading content from a file is that someone can fix it without a rebuild.
func Parse(r io.Reader) (*Pack, error) {
	var p Pack
	dec := json.NewDecoder(r)
	dec.DisallowUnknownFields() // a misspelled field must not be silently ignored
	if err := dec.Decode(&p); err != nil {
		return nil, fmt.Errorf("parse pack: %w", err)
	}
	if err := p.Validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Validate reports every problem with the pack at once.
func (p *Pack) Validate() error {
	var problems []string

	if strings.TrimSpace(p.Name) == "" {
		problems = append(problems, "pack name is empty (it forms pack_key, so it cannot be omitted)")
	}
	if strings.Contains(p.Name, "/") {
		problems = append(problems, fmt.Sprintf("pack name %q contains '/', which separates it from the rule name in pack_key", p.Name))
	}
	if len(p.Rules) == 0 {
		problems = append(problems, "pack contains no rules")
	}

	seen := map[string]int{}
	for i, r := range p.Rules {
		where := fmt.Sprintf("rule %d", i)
		if name := strings.TrimSpace(r.Name); name == "" {
			problems = append(problems, where+": name is empty")
		} else {
			where = fmt.Sprintf("rule %q", name)
			// Two rules with the same name collapse onto one pack_key, so the
			// second would overwrite the first and the pack would load fewer
			// rules than it declares — silently.
			if prev, dup := seen[name]; dup {
				problems = append(problems, fmt.Sprintf("%s: duplicate name (also rule %d); they would share one pack_key", where, prev))
			}
			seen[name] = i
		}
		if !validTypes[r.Type] {
			problems = append(problems, fmt.Sprintf("%s: type %q is not one of sigma/yara/behavioral", where, r.Type))
		}
		if r.Severity < 1 || r.Severity > 10 {
			problems = append(problems, fmt.Sprintf("%s: severity %d is outside 1..10", where, r.Severity))
		}
		if strings.TrimSpace(r.Content) == "" {
			problems = append(problems, where+": content is empty; a rule with no body can never match")
		}
		if len(r.Platform) == 0 {
			problems = append(problems, where+": platform is empty; the column is NOT NULL")
		}
		for _, plat := range r.Platform {
			if !validPlatforms[plat] {
				problems = append(problems, fmt.Sprintf("%s: platform %q is not one of windows/linux/darwin", where, plat))
			}
		}
		if r.Source != "" && !validSources[r.Source] {
			problems = append(problems, fmt.Sprintf("%s: source %q is not an accepted value", where, r.Source))
		}
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("pack %q is invalid:\n  - %s", p.Name, strings.Join(problems, "\n  - "))
}

// ResolvedSource returns the source to store, applying the default.
func (r Rule) ResolvedSource() string {
	if r.Source == "" {
		return defaultSource
	}
	return r.Source
}

// ResolvedEnabled returns the enabled flag to store. Absent means enabled:
// content that ships a rule intends it to run.
func (r Rule) ResolvedEnabled() bool {
	if r.Enabled == nil {
		return true
	}
	return *r.Enabled
}
