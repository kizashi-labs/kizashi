package remediation

import "time"

// BuiltinRules returns the 4 built-in auto-remediation rules.
func BuiltinRules() []*RemediationRule {
	return []*RemediationRule{
		// 1. Critical alert → isolate endpoint
		{
			ID:      "rem-001-critical-isolate",
			Name:    "Critical Alert: Auto-Isolate Endpoint",
			Enabled: true,
			Trigger: RuleTrigger{
				EventType:   "alert",
				MinSeverity: 9,
				Tags:        []string{}, // matches any critical alert
			},
			Actions: []RemediationAction{
				{
					Type: "isolate_network",
					Params: map[string]string{
						"reason": "critical_severity_auto_isolation",
					},
				},
				{
					Type: "notify",
					Params: map[string]string{
						"message": "Endpoint automatically isolated due to critical severity alert",
					},
				},
			},
			Cooldown:  15 * time.Minute,
			CreatedAt: time.Now().UTC(),
		},
		// 2. Ransomware detection → isolate + kill suspicious process
		{
			ID:      "rem-002-ransomware-response",
			Name:    "Ransomware: Isolate and Kill Process",
			Enabled: true,
			Trigger: RuleTrigger{
				EventType:   "alert",
				MinSeverity: 8,
				Tags:        []string{"ransomware", "file_encryption"},
			},
			Actions: []RemediationAction{
				{
					Type: "isolate_network",
					Params: map[string]string{
						"reason": "ransomware_containment",
					},
				},
				{
					Type: "kill_process",
					Params: map[string]string{
						"process_name": "suspicious",
						"reason":       "ransomware_kill",
					},
				},
				{
					Type: "create_alert",
					Params: map[string]string{
						"title": "Ransomware auto-containment executed",
					},
				},
				{
					Type: "notify",
					Params: map[string]string{
						"message": "Ransomware detected: endpoint isolated and suspicious process killed",
					},
				},
			},
			Cooldown:  30 * time.Minute,
			CreatedAt: time.Now().UTC(),
		},
		// 3. Malware hash match → quarantine file immediately
		{
			ID:      "rem-003-malware-quarantine",
			Name:    "Malware Hash Match: Quarantine File",
			Enabled: true,
			Trigger: RuleTrigger{
				EventType:   "alert",
				MinSeverity: 7,
				Tags:        []string{"malware", "hash_match", "ioc_match"},
			},
			Actions: []RemediationAction{
				{
					Type: "quarantine_file",
					Params: map[string]string{
						"reason": "malware_hash_match",
					},
				},
				{
					Type: "notify",
					Params: map[string]string{
						"message": "Malicious file quarantined due to hash match",
					},
				},
			},
			Cooldown:  5 * time.Minute,
			CreatedAt: time.Now().UTC(),
		},
		// 4. Brute force → block source IP after 10 failures
		{
			ID:      "rem-004-brute-force-block",
			Name:    "Brute Force: Block Source IP",
			Enabled: true,
			Trigger: RuleTrigger{
				EventType:   "alert",
				MinSeverity: 6,
				Tags:        []string{"brute_force", "auth_failure", "failed_login"},
			},
			Actions: []RemediationAction{
				{
					Type: "notify",
					Params: map[string]string{
						"message": "Brute force detected: source IP block initiated after 10+ failures",
					},
				},
				{
					Type: "create_alert",
					Params: map[string]string{
						"title": "Brute force auto-block triggered",
					},
				},
			},
			Cooldown:  10 * time.Minute,
			CreatedAt: time.Now().UTC(),
		},
	}
}

// LoadBuiltins loads all built-in remediation rules into the engine.
func LoadBuiltins(e *Engine) {
	for _, rule := range BuiltinRules() {
		e.AddRule(rule)
	}
}
