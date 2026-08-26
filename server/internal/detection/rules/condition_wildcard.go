package rules

import (
	"regexp"
	"sort"
	"strings"

	"gopkg.in/yaml.v3"
)

// allOfWildcardRe matches `all of <prefix>*` in a Sigma condition — e.g.
// `all of selection_1_*`, `all of suspicious_rundll32_*`. The captured group is
// the selection-block name prefix (word characters) preceding the `*`.
var allOfWildcardRe = regexp.MustCompile(`\ball\s+of\s+([A-Za-z0-9_]+)\*`)

// expandAllOfWildcards rewrites `all of <prefix>*` in a Sigma rule's condition
// into an explicit `(a and b and ...)` conjunction over the detection selection
// blocks whose name starts with <prefix>.
//
// Why: the RuleEngine's Sigma library (github.com/bradleyjkemp/sigma-go v0.6.6)
// supports `1 of <prefix>*` but NOT `all of <prefix>*` — it rejects the latter
// with `invalid token '*'` at parse time. Because compilation failures are
// silently dropped (see LoadRules), such rules load as `enabled=t` yet never
// evaluate. Measured on the prod detection engine: 7 real SigmaHQ rules (Shadow
// Copies Deletion/T1490, NTDS.DIT exfil/T1003.003, PrintNightmare spool,
// Schtasks-from-env, AddinUtil, Clear-PS-history, XCSSET) were dead this way.
//
// The rewrite is purely syntactic and preserves semantics: `all of sel_*` means
// "every selection matching sel_* matched" == `(sel_a and sel_b and ...)`. It is
// applied before sigma.ParseRule. Rules with nothing to expand are returned
// unchanged; anything we cannot confidently parse is left as-is so ParseRule can
// surface the original error.
func expandAllOfWildcards(content string) string {
	if !strings.Contains(content, "all of ") {
		return content
	}

	// Collect the detection selection-block identifiers (all keys under
	// `detection:` except the `condition` key itself).
	var doc struct {
		Detection map[string]yaml.Node `yaml:"detection"`
	}
	if err := yaml.Unmarshal([]byte(content), &doc); err != nil || len(doc.Detection) == 0 {
		return content
	}
	names := make([]string, 0, len(doc.Detection))
	for k := range doc.Detection {
		if k != "condition" {
			names = append(names, k)
		}
	}

	return allOfWildcardRe.ReplaceAllStringFunc(content, func(match string) string {
		prefix := allOfWildcardRe.FindStringSubmatch(match)[1]
		var matched []string
		for _, n := range names {
			if strings.HasPrefix(n, prefix) {
				matched = append(matched, n)
			}
		}
		if len(matched) == 0 {
			// No selection blocks match — leave untouched rather than emit an
			// empty/broken group; ParseRule will report if it is truly invalid.
			return match
		}
		sort.Strings(matched) // deterministic output
		return "(" + strings.Join(matched, " and ") + ")"
	})
}
