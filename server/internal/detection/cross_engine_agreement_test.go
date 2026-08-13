package detection

import (
	"context"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	detectionrules "github.com/edr-platform/server/internal/detection/rules"
)

// The second axis of the ownership question.
//
// api_field_parity_test.go answers "can server-api RESOLVE the fields the DB
// rules select on". That is necessary but not sufficient: the two engines are
// different Sigma implementations — server-api's own evaluator (sigma_evaluator.go,
// yaml.v3) and server-detect's sigma-go — and CLAUDE.md warns in as many words
// that the same rule can carry different matching logic on the two sides.
//
// So before the `rules` table can be given a single owner, the engines have to
// agree on what its rules MEAN, not just on whether the fields exist. This test
// asks that directly: build an event out of a rule's own selectors, and require
// both engines to match it.
//
// Why a synthesised event rather than a fixture: a fixture proves the rule fires
// on the one case someone thought of, and the interesting disagreements are in
// modifier handling (|all vs implicit OR, endswith with a leading separator,
// case folding) which fixtures chosen by hand tend to sidestep. Deriving the
// event from the rule means the event is, by construction, one the rule author
// intended to match.
//
// Scope, stated plainly: this covers rules whose selection is string equality /
// contains / startswith / endswith over flat fields, which is the shape almost
// all shipped DB rules use. Rules with regex, numeric comparison, keyword-list
// or `null` selectors are skipped and COUNTED — an unreported skip would turn a
// narrowing of the harness into a silent pass, the exact failure this file is
// modelled against.

// sigmaToProto maps a Sigma field name onto the agent/proto key that carries it
// on a real event.
//
// The synthesised event MUST be written in the proto vocabulary, not in Sigma
// names, because that is what production delivers and because the two engines
// read it from opposite directions: server-detect maps Sigma→proto through
// rules/rule_engine.go's FieldMappings, while server-api maps proto→Sigma
// through addPipelineSigmaAliases. Handing both engines an event keyed on Sigma
// names looks symmetrical and is not — server-api reads it, server-detect does
// not, and every rule reports as a disagreement. The first run of this harness
// did exactly that and produced four confident false findings.
//
// Only fields verified present on BOTH sides are listed. A rule selecting on
// anything else is skipped and counted rather than guessed at.
var sigmaToProto = map[string]string{
	"Image":             "image_path",
	"CommandLine":       "command_line",
	"ParentImage":       "parent_image_path",
	"ParentCommandLine": "parent_command_line",
	"ProcessName":       "process_name",
	"User":              "username",
	"SubjectUserName":   "username",
	"ProcessId":         "pid",
	"TargetFilename":    "path",
	"DestinationIp":     "dst_ip",
	"DestinationPort":   "dst_port",
	"SourceIp":          "src_ip",
	"SourcePort":        "src_port",
	"Protocol":          "protocol",
	"QueryName":         "query",
	"QueryType":         "query_type",
	"LogonType":         "logon_type",
	"TargetImage":       "target_image",
	"SourceImage":       "source_image",
	"GrantedAccess":     "access_mask",
	"TargetObject":      "key_path",
	"Details":           "value_data",
}

// satisfyingEvent builds an event that satisfies every selection in a Sigma
// document, or reports why it could not.
//
// It handles the shape `selection: {Field|mod: value | [values]}` with
// modifiers contains/startswith/endswith/(none), and the `|all` variant. For an
// OR-list it takes the first alternative; for `|all` it concatenates every term
// so all of them are present.
func satisfyingEvent(content string) (map[string]interface{}, string) {
	var doc struct {
		Detection map[string]interface{} `yaml:"detection"`
	}
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil {
		return nil, "does not parse"
	}
	if len(doc.Detection) == 0 {
		return nil, "no detection block"
	}

	// Constraints accumulate PER FIELD, because the common shipped shape splits one
	// field across several selections and ANDs them:
	//
	//   selection_tool: {CommandLine|contains: [curl, wget]}
	//   selection_dest: {CommandLine|contains: '/tmp/'}
	//   condition: selection_tool and selection_dest
	//
	// Bailing on the second constraint (as the first version did) skipped 107 of
	// 242 rules — nearly half the corpus, and precisely the multi-term rules where
	// modifier handling is most likely to differ between engines. A harness that
	// declines to look at the interesting half is not evidence of agreement.
	type constraint struct {
		exact      string
		hasExact   bool
		startsWith string
		endsWith   string
		contains   []string
	}
	cons := map[string]*constraint{}

	for name, sel := range doc.Detection {
		if name == "condition" || name == "timeframe" {
			continue
		}
		m, ok := sel.(map[string]interface{})
		if !ok {
			// Keyword list or a bare scalar: not the shape this harness models.
			return nil, "selection " + name + " is not a field map"
		}
		for rawField, rawVal := range m {
			field, mods, _ := strings.Cut(rawField, "|")
			modSet := map[string]bool{}
			for _, mod := range strings.Split(mods, "|") {
				if mod != "" {
					modSet[mod] = true
				}
			}
			if modSet["re"] || modSet["base64"] || modSet["base64offset"] ||
				modSet["gt"] || modSet["gte"] || modSet["lt"] || modSet["lte"] ||
				modSet["cidr"] {
				return nil, "modifier not modelled: " + rawField
			}

			var terms []string
			switch v := rawVal.(type) {
			case string:
				terms = []string{v}
			case []interface{}:
				for _, it := range v {
					s, ok := it.(string)
					if !ok {
						return nil, "non-string alternative in " + rawField
					}
					terms = append(terms, s)
				}
			case nil:
				return nil, "null selector in " + rawField
			default:
				return nil, "non-string selector in " + rawField
			}
			if len(terms) == 0 {
				return nil, "empty selector in " + rawField
			}

			proto, known := sigmaToProto[field]
			if !known {
				return nil, "field not in the shared proto vocabulary: " + field
			}
			c := cons[proto]
			if c == nil {
				c = &constraint{}
				cons[proto] = c
			}

			switch {
			case modSet["all"]:
				// Every term must be present.
				c.contains = append(c.contains, terms...)
			case modSet["endswith"]:
				if c.endsWith != "" && c.endsWith != terms[0] {
					return nil, "two different endswith constraints on " + field
				}
				c.endsWith = terms[0]
			case modSet["startswith"]:
				if c.startsWith != "" && c.startsWith != terms[0] {
					return nil, "two different startswith constraints on " + field
				}
				c.startsWith = terms[0]
			case modSet["contains"]:
				// An OR-list: one alternative suffices.
				c.contains = append(c.contains, terms[0])
			default:
				if c.hasExact && c.exact != terms[0] {
					return nil, "two different exact constraints on " + field
				}
				c.exact, c.hasExact = terms[0], true
			}
		}
	}

	ev := map[string]interface{}{}
	for proto, c := range cons {
		// An exact match cannot coexist with substring constraints: the value is
		// pinned, so any additional term would have to already be inside it, which
		// this harness will not assume.
		if c.hasExact {
			if c.startsWith != "" || c.endsWith != "" || len(c.contains) > 0 {
				return nil, "exact and substring constraints on the same field: " + proto
			}
			ev[proto] = c.exact
			continue
		}
		// startswith … contains … endswith, in that order, so all three hold at once.
		var b strings.Builder
		b.WriteString(c.startsWith)
		for _, term := range c.contains {
			b.WriteString(term)
			b.WriteString(" ")
		}
		if c.endsWith == "" {
			// Nothing pins the tail; a trailing marker keeps the value from
			// accidentally satisfying an endswith the rule did not ask for.
			b.WriteString("end")
		} else {
			b.WriteString(c.endsWith)
		}
		ev[proto] = b.String()
	}
	if len(ev) == 0 {
		return nil, "no fields derived"
	}
	return ev, ""
}

func TestBothEnginesAgreeOnDBRules(t *testing.T) {
	blocks := migrationSigmaBlocks(t)
	if len(blocks) < 100 {
		t.Fatalf("only %d DB Sigma rules extracted — extractor broken", len(blocks))
	}

	type disagreement struct {
		title, file string
		api, detect bool
	}
	var diffs []disagreement
	skipped := map[string]int{}
	compared := 0

	titles := make([]string, 0, len(blocks))
	for title := range blocks {
		titles = append(titles, title)
	}
	sort.Strings(titles)

	for _, title := range titles {
		blk := blocks[title]
		ev, why := satisfyingEvent(blk.body)
		if ev == nil {
			skipped[why]++
			continue
		}

		// server-api side.
		apiEval := NewSigmaEvaluator()
		if err := apiEval.LoadRule(blk.body); err != nil {
			// Covered by TestMigrationSigmaRulesParseInProductionEvaluator; not this
			// test's finding, and reporting it twice muddies both.
			skipped["api parse failure"]++
			continue
		}

		// server-detect side.
		det := detectionrules.NewRuleEngine()
		det.SetPlatformGate(false) // platform scoping is a separate axis
		det.LoadRules([]*detectionrules.DetectionRule{{
			ID: "x", Name: title, Type: "sigma", Content: blk.body, Enabled: true,
		}})

		apiEvent := map[string]interface{}{}
		for k, v := range ev {
			apiEvent[k] = v
		}
		addPipelineSigmaAliases(apiEvent)
		apiFired := false
		for _, m := range apiEval.EvaluateEvent(apiEvent) {
			if m.RuleTitle == title {
				apiFired = true
			}
		}

		detEvent := map[string]interface{}{"agent_id": "h"}
		for k, v := range ev {
			detEvent[k] = v
		}
		matches, err := det.Evaluate(context.Background(), detEvent)
		if err != nil {
			skipped["detect evaluate error"]++
			continue
		}
		detFired := len(matches) > 0

		compared++
		if apiFired != detFired {
			diffs = append(diffs, disagreement{title: title, file: blk.file, api: apiFired, detect: detFired})
		}
	}

	// Never silent about what was not covered: a harness that quietly narrows its
	// own scope reports "no disagreements" for a corpus it stopped reading.
	reasons := make([]string, 0, len(skipped))
	for why := range skipped {
		reasons = append(reasons, why)
	}
	sort.Strings(reasons)
	total := 0
	for _, why := range reasons {
		total += skipped[why]
		t.Logf("skipped %3d rule(s): %s", skipped[why], why)
	}
	t.Logf("compared %d of %d DB Sigma rules across both engines (%d skipped)",
		compared, len(blocks), total)

	if compared < 50 {
		t.Fatalf("only %d rules were actually compared — the event synthesiser has stopped "+
			"working and this test would pass vacuously", compared)
	}

	for _, d := range diffs {
		t.Errorf("engines disagree on %q (%s): server-api fired=%v, server-detect fired=%v\n"+
			"  Both were given an event built from the rule's own selectors, so one of them is "+
			"not matching a case its author wrote down. Until this is resolved the `rules` table "+
			"cannot be given a single owner: whichever engine is dropped takes its half of the "+
			"disagreement with it.",
			d.title, d.file, d.api, d.detect)
	}
}
