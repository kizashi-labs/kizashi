package suppression

import "time"

// LoadBuiltinRules adds platform-provided suppression rules to the engine.
// These reduce noise from known-benign processes and scanning tools.
func LoadBuiltinRules(e *Engine) {
	builtins := []*SuppressionRule{
		{
			ID:          "builtin-vulnerability-scanner",
			Name:        "Known Vulnerability Scanner",
			Description: "Suppress medium/low alerts from known scanner hostnames (Nessus, Qualys)",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "hostname", Operator: "contains", Value: "nessus"},
			},
			Duration:  0,
			CreatedAt: time.Now(),
		},
		{
			ID:          "builtin-qualys-scanner",
			Name:        "Qualys Scanner Suppression",
			Description: "Suppress medium/low alerts from Qualys scanner hostnames",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "hostname", Operator: "contains", Value: "qualys"},
			},
			Duration:  0,
			CreatedAt: time.Now(),
		},
		{
			ID:          "builtin-backup-agent-veeam",
			Name:        "Backup Agent (Veeam)",
			Description: "Suppress file events from Veeam backup process",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "process_name", Operator: "contains", Value: "veeam"},
				{Field: "alert_type", Operator: "contains", Value: "file"},
			},
			Duration:  0,
			CreatedAt: time.Now(),
		},
		{
			ID:          "builtin-backup-agent-generic",
			Name:        "Backup Agent (Generic)",
			Description: "Suppress file events from generic backup processes",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "process_name", Operator: "contains", Value: "backup"},
				{Field: "alert_type", Operator: "contains", Value: "file"},
			},
			Duration:  0,
			CreatedAt: time.Now(),
		},
		{
			ID:          "builtin-av-defender",
			Name:        "Windows Defender AV",
			Description: "Suppress low-severity process events from Windows Defender",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "process_name", Operator: "contains", Value: "defender"},
				{Field: "alert_type", Operator: "contains", Value: "process"},
				{Field: "severity", Operator: "lt", Value: "5"},
			},
			Duration:  0,
			CreatedAt: time.Now(),
		},
		{
			ID:          "builtin-av-mcafee",
			Name:        "McAfee AV",
			Description: "Suppress low-severity process events from McAfee",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "process_name", Operator: "contains", Value: "mcafee"},
				{Field: "alert_type", Operator: "contains", Value: "process"},
				{Field: "severity", Operator: "lt", Value: "5"},
			},
			Duration:  0,
			CreatedAt: time.Now(),
		},
		{
			ID:          "builtin-dev-env",
			Name:        "Development/Test Environment",
			Description: "Suppress low-severity alerts from dev/test hosts",
			Enabled:     true,
			Conditions: []Condition{
				{Field: "hostname", Operator: "regex", Value: `(?i)(-dev|-test)$`},
				{Field: "severity", Operator: "lt", Value: "4"},
			},
			Duration:  0,
			CreatedAt: time.Now(),
		},
	}

	e.mu.Lock()
	e.rules = append(e.rules, builtins...)
	e.mu.Unlock()
}
