package correlation

import "time"

// BuiltinRules returns the built-in correlation rules.
func BuiltinRules() []*CorrelationRule {
	return []*CorrelationRule{
		// 1. Lateral movement: same agent, multiple auth failures + success within 10 min
		{
			ID:          "corr-001-lateral-movement",
			Name:        "Lateral Movement via Brute Force",
			Description: "Detects multiple authentication failures followed by a success on the same agent within 10 minutes, indicating potential lateral movement.",
			EventTypes:  []string{"auth_failure", "auth_success", "failed_login", "login_success"},
			Conditions: []Condition{
				{Field: "severity", Operator: "gte", Value: "4"},
			},
			TimeWindow:  10 * time.Minute,
			MinEvents:   5,
			Severity:    8,
			MITRETactic: "Lateral Movement",
			MITRETech:   "T1021",
		},
		// 2. Credential dumping campaign: Mimikatz/LSASS events on 3+ agents within 1 hour
		{
			ID:          "corr-002-credential-dumping",
			Name:        "Credential Dumping Campaign",
			Description: "Detects Mimikatz or LSASS memory access events across multiple agents within 1 hour, indicating a coordinated credential dumping campaign.",
			EventTypes:  []string{"credential_dump", "lsass_access", "mimikatz_detected", "process_access"},
			Conditions: []Condition{
				{Field: "event_type", Operator: "contains", Value: "credential"},
				{Field: "severity", Operator: "gte", Value: "7"},
			},
			TimeWindow:  1 * time.Hour,
			MinEvents:   3,
			Severity:    9,
			MITRETactic: "Credential Access",
			MITRETech:   "T1003.001",
		},
		// 3. Ransomware outbreak: file encryption events on 5+ agents within 30 min
		{
			ID:          "corr-003-ransomware-outbreak",
			Name:        "Ransomware Outbreak",
			Description: "Detects mass file encryption events spread across 5 or more agents within 30 minutes, indicating an active ransomware outbreak.",
			EventTypes:  []string{"file_encrypted", "ransomware_detected", "file_rename_bulk", "ransom_note_created"},
			Conditions: []Condition{
				{Field: "severity", Operator: "gte", Value: "8"},
			},
			TimeWindow:  30 * time.Minute,
			MinEvents:   5,
			Severity:    10,
			MITRETactic: "Impact",
			MITRETech:   "T1486",
		},
		// 4. Persistence establishment: registry + scheduled task events same agent within 5 min
		{
			ID:          "corr-004-persistence",
			Name:        "Persistence Establishment",
			Description: "Detects combined registry modification and scheduled task creation on the same agent within 5 minutes, indicating persistent access establishment.",
			EventTypes:  []string{"registry_modified", "scheduled_task_created", "startup_item_added", "service_installed"},
			Conditions: []Condition{
				{Field: "severity", Operator: "gte", Value: "5"},
			},
			TimeWindow:  5 * time.Minute,
			MinEvents:   2,
			Severity:    7,
			MITRETactic: "Persistence",
			MITRETech:   "T1547",
		},
		// 5. C2 beaconing: repeated network events to same external IP every ~60s
		{
			ID:          "corr-005-c2-beaconing",
			Name:        "C2 Beaconing Pattern",
			Description: "Detects repeated outbound network connections at regular intervals (~60s) to the same external IP, indicating Command & Control beaconing activity.",
			EventTypes:  []string{"network_connection", "outbound_connection", "dns_query", "http_request"},
			Conditions: []Condition{
				{Field: "event_type", Operator: "contains", Value: "network"},
				{Field: "severity", Operator: "gte", Value: "4"},
			},
			TimeWindow:  10 * time.Minute,
			MinEvents:   8,
			Severity:    8,
			MITRETactic: "Command and Control",
			MITRETech:   "T1071.001",
		},
		// 6. Cloud account takeover chain: 3+ cloud attack techniques (discovery /
		// persistence / privesc / defense-evasion via cloud CLIs) on the same
		// environment within 20 minutes. Any single cloud CLI action is low-signal;
		// three chained is hands-on-keyboard cloud compromise. Fed by the
		// _attack_surface="cloud" marker the AlertPipeline stamps on cloud-technique
		// Sigma alerts.
		{
			ID:          "corr-006-cloud-attack-chain",
			Name:        "Cloud Account Takeover Chain",
			Description: "Detects three or more cloud attack techniques (cloud discovery, persistence, privilege escalation, or defense evasion) within 20 minutes, indicating a multi-stage cloud account takeover.",
			Conditions: []Condition{
				{Field: "_attack_surface", Operator: "eq", Value: "cloud"},
			},
			TimeWindow:  20 * time.Minute,
			MinEvents:   3,
			Severity:    9,
			MITRETactic: "Multiple (Cloud)",
			MITRETech:   "T1078.004",
		},
		// 7. AD domain compromise chain: 3+ Active Directory attack techniques
		// (domain recon → Kerberos credential theft → credential-material lateral
		// movement) on the same environment within 30 minutes — the classic
		// hands-on-keyboard path to Domain Admin. Fed by the _attack_surface="ad"
		// marker the AlertPipeline stamps on AD-technique Sigma alerts.
		{
			ID:          "corr-007-ad-compromise-chain",
			Name:        "Active Directory Domain Compromise Chain",
			Description: "Detects three or more Active Directory attack techniques (domain reconnaissance, Kerberos credential theft/forging, AD CS abuse, authentication coercion, NTLM relay, or pass-the-hash/ticket lateral movement) within 30 minutes, indicating a multi-stage path toward Domain Admin (including the ESC8 coercion→relay→certificate chain).",
			Conditions: []Condition{
				{Field: "_attack_surface", Operator: "eq", Value: "ad"},
			},
			TimeWindow:  30 * time.Minute,
			MinEvents:   3,
			Severity:    9,
			MITRETactic: "Multiple (AD)",
			MITRETech:   "T1078.002",
		},
		// 8. Ransomware preparation: 2+ destructive pre-encryption steps (recovery
		// inhibition, service stop, defense disable, wipe, log clear) on the same
		// host within 10 minutes. This fires BEFORE mass encryption (unlike the
		// cross-agent corr-003 outbreak rule), giving a chance to isolate the host.
		// Fed by the _ransomware_precursor marker the AlertPipeline stamps.
		{
			ID:          "corr-008-ransomware-preparation",
			Name:        "Ransomware Preparation (Pre-Encryption)",
			Description: "Detects two or more destructive ransomware pre-encryption steps (inhibit recovery, stop services, disable defenses, wipe, clear logs) within 10 minutes, indicating imminent encryption — early enough to isolate the host.",
			Conditions: []Condition{
				{Field: "_ransomware_precursor", Operator: "eq", Value: "true"},
			},
			TimeWindow:  10 * time.Minute,
			MinEvents:   2,
			Severity:    10,
			MITRETactic: "Impact",
			MITRETech:   "T1486",
		},
		// 9. Data exfiltration in progress: 2+ collection/exfil-channel steps
		// (archive collected data + upload over FTP/mail/DNS/cloud) within 15
		// minutes — the stage-then-exfil pattern of an active data breach. Fed by
		// the _exfil_activity marker the AlertPipeline stamps.
		{
			ID:          "corr-009-data-exfiltration",
			Name:        "Data Exfiltration in Progress",
			Description: "Detects two or more data collection/exfiltration steps (archive collected data plus upload over FTP, mail, DNS tunneling, or cloud storage) within 15 minutes, indicating an active data breach.",
			Conditions: []Condition{
				{Field: "_exfil_activity", Operator: "eq", Value: "true"},
			},
			TimeWindow:  15 * time.Minute,
			MinEvents:   2,
			Severity:    8,
			MITRETactic: "Exfiltration",
			MITRETech:   "T1567",
		},
		// 10. Container/K8s breakout: two or more container-escalation steps
		// (privileged container deploy, escape to host, in-container exec, or
		// Kubernetes service-account token theft) within 15 minutes — a
		// container-to-host or container-to-cluster breakout in progress. Fed by
		// the _container_escalation marker the AlertPipeline stamps.
		{
			ID:          "corr-010-container-breakout",
			Name:        "Container Escape / Cluster Breakout",
			Description: "Detects two or more container-escalation steps (privileged container deployment, escape to host, in-container exec, or Kubernetes service-account token theft) within 15 minutes, indicating a container-to-host or container-to-cluster breakout in progress.",
			Conditions: []Condition{
				{Field: "_container_escalation", Operator: "eq", Value: "true"},
			},
			TimeWindow:  15 * time.Minute,
			MinEvents:   2,
			Severity:    9,
			MITRETactic: "Privilege Escalation",
			MITRETech:   "T1611",
		},
		// 11. Multi-source credential theft: two or more credential-harvesting
		// steps from different sources (e.g. LSASS dump + SAM/registry + browser
		// + GPP) within 15 minutes — a hands-on operator sweeping every credential
		// store on a host. Fed by the _credential_theft marker the AlertPipeline
		// stamps. Distinct from corr-002, which fires on ONE technique fanning
		// across ≥3 agents (a campaign); this fires on ≥2 techniques anywhere.
		{
			ID:          "corr-011-multi-source-credential-theft",
			Name:        "Multi-Source Credential Theft",
			Description: "Detects two or more credential-harvesting steps from different sources (OS credential stores, password stores, unsecured credentials, or Kerberos ticket theft) within 15 minutes, indicating a hands-on operator sweeping a host for credentials.",
			Conditions: []Condition{
				{Field: "_credential_theft", Operator: "eq", Value: "true"},
			},
			TimeWindow:  15 * time.Minute,
			MinEvents:   2,
			Severity:    8,
			MITRETactic: "Credential Access",
			MITRETech:   "T1003",
		},
		// 12. Reconnaissance burst: three or more environment-enumeration commands
		// (accounts, system, network, domain/AD, shares, services, security
		// software) within 10 minutes — an operator mapping the environment before
		// escalation or lateral movement. Fed by the _discovery_recon marker the
		// AlertPipeline stamps. Mirrors the detection-server SequenceEngine's
		// discovery-burst rule (migration 307) in the api-server correlation engine.
		{
			ID:          "corr-012-reconnaissance-burst",
			Name:        "Reconnaissance Burst",
			Description: "Detects three or more distinct environment-enumeration commands (account, system, network, domain/AD, share, service, or security-software discovery) within 10 minutes, indicating an operator actively mapping the environment before escalation or lateral movement.",
			Conditions: []Condition{
				{Field: "_discovery_recon", Operator: "eq", Value: "true"},
			},
			TimeWindow:  10 * time.Minute,
			MinEvents:   3,
			Severity:    6,
			MITRETactic: "Discovery",
			MITRETech:   "T1087",
		},
	}
}

// LoadBuiltins loads all built-in correlation rules into the engine.
func LoadBuiltins(e *Engine) {
	for _, rule := range BuiltinRules() {
		e.AddRule(rule)
	}
}
