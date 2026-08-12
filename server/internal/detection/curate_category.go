package detection

import "gopkg.in/yaml.v3"

// RuleCategory returns the curate bucket for a Sigma rule: its logsource
// category (process_creation/registry/image_load/…), or a service:/product:
// fallback when category is absent. Curate caps and reports are per-category, so
// the same derivation must be shared by the curate service, the scheduler, and
// the curate-analyze CLI — keeping it here avoids the three drifting apart.
func RuleCategory(ruleYAML string) string {
	var doc struct {
		Logsource struct {
			Category string `yaml:"category"`
			Service  string `yaml:"service"`
			Product  string `yaml:"product"`
		} `yaml:"logsource"`
	}
	if err := yaml.Unmarshal([]byte(ruleYAML), &doc); err != nil {
		return "(unparseable)"
	}
	switch {
	case doc.Logsource.Category != "":
		return doc.Logsource.Category
	case doc.Logsource.Service != "":
		return "service:" + doc.Logsource.Service
	case doc.Logsource.Product != "":
		return "product:" + doc.Logsource.Product
	}
	return "(none)"
}
