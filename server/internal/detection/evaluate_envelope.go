package detection

import "sync"

// EvalFinding is a minimal, IO-free detection result. It is the unit returned by
// EvaluateEnvelope for replay tooling and the wire-format E2E test — enough to
// assert that a normalized event would raise an alert, without touching the DB,
// NATS, suppression, or notification side effects of the live pipeline.
type EvalFinding struct {
	Source   string   // "sigma" | "heuristic" | "yara" | "ioc" | "memory" | "credential_access"
	Title    string   // human-readable rule/finding title
	Severity int      // 0 for Sigma (level is in Level), >0 for typed findings
	Level    string   // Sigma level (informational..critical); "" for typed findings
	MITRE    []string // ATT&CK technique IDs
}

var (
	builtinEvalOnce sync.Once
	builtinEval     *SigmaEvaluator
)

// builtinSigmaEvaluator lazily builds and caches a SigmaEvaluator loaded with the
// compiled built-in rules. Reused across EvaluateEnvelope calls so the 100+ rule
// YAML parse happens once.
func builtinSigmaEvaluator() *SigmaEvaluator {
	builtinEvalOnce.Do(func() {
		builtinEval = NewSigmaEvaluator()
		LoadBuiltinRules(builtinEval)
	})
	return builtinEval
}

// EvaluateEnvelope runs the IO-free detection core over a normalized event
// (eventType + flat field map, exactly as ingestion's normalizeEventData +
// type promotion produce). It composes the two real detection entrypoints:
//
//   - the typed non-Sigma sources (engine.typedFindings): DNS tunneling/DGA
//     heuristics, agent-side YARA/threat-intel verdicts, memory and
//     credential-access findings; and
//   - the built-in Sigma rules evaluated through the api AlertPipeline field
//     aliases (addPipelineSigmaAliases) — the same alias layer the live pipeline
//     applies, so Sysmon/SigmaHQ field names resolve off our native telemetry.
//
// It applies no suppression and performs no IO, so it is the faithful oracle
// behind the wire-format → alert E2E and rule-replay tests. typedFindings runs
// first on the native keys; the alias pass only appends Sysmon-style keys, so
// neither entrypoint perturbs the other.
func EvaluateEnvelope(eventType string, flat map[string]interface{}) []EvalFinding {
	var out []EvalFinding

	for _, m := range typedFindings(eventType, flat) {
		out = append(out, EvalFinding{
			Source:   m.RuleType,
			Title:    m.Title,
			Severity: m.Severity,
			MITRE:    m.MITRETags,
		})
	}

	// Apply the api-pipeline field aliases, then evaluate the built-in Sigma set —
	// the path that actually evaluates the 100+ built-in rules in production.
	addPipelineSigmaAliases(flat)
	for _, sm := range builtinSigmaEvaluator().EvaluateEvent(flat) {
		out = append(out, EvalFinding{
			Source: "sigma",
			Title:  sm.RuleTitle,
			Level:  sm.Level,
			MITRE:  sm.Tags,
		})
	}

	return out
}
