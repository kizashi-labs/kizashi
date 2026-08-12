package compliance

import (
	"fmt"
	"time"
)

// NISTControls returns the NIST CSF controls evaluated via EDR telemetry.
func NISTControls() []Control {
	return []Control{
		{
			ID:          "ID.AM-1",
			Title:       "Physical Devices Inventoried",
			Description: "Physical devices and systems within the organization are inventoried.",
			Severity:    "medium",
			Check:       nistIDam1,
		},
		{
			ID:          "PR.DS-1",
			Title:       "Data-at-Rest Protection",
			Description: "Data-at-rest is protected — endpoint should have disk encryption enabled.",
			Severity:    "high",
			Check:       nistPRds1,
		},
		{
			ID:          "DE.CM-1",
			Title:       "Network Monitoring",
			Description: "The network is monitored to detect potential cybersecurity events.",
			Severity:    "high",
			Check:       nistDEcm1,
		},
		{
			ID:          "DE.CM-7",
			Title:       "Unauthorized Activity Monitoring",
			Description: "Monitoring for unauthorized personnel, connections, devices, and software is performed.",
			Severity:    "high",
			Check:       nistDEcm7,
		},
		{
			ID:          "RS.AN-1",
			Title:       "Detection System Notifications Investigated",
			Description: "Notifications from detection systems are investigated.",
			Severity:    "critical",
			Check:       nistRSan1,
		},
	}
}

// nistIDam1 — ID.AM-1: Asset enrolled and actively reporting.
func nistIDam1(d AgentComplianceData) CheckResult {
	if d.EnrolledAt.IsZero() {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "Enrollment timestamp not available",
			Remediation: "Ensure the agent enrollment process completed successfully.",
		}
	}

	if d.LastSeen.IsZero() {
		return CheckResult{
			Status:      "fail",
			Evidence:    fmt.Sprintf("Agent %q enrolled at %s but has never reported", d.Hostname, d.EnrolledAt.Format(time.RFC3339)),
			Remediation: "Verify the agent service is running and has network connectivity.",
		}
	}

	age := time.Since(d.LastSeen)
	if age > 48*time.Hour {
		return CheckResult{
			Status:      "fail",
			Evidence:    fmt.Sprintf("Agent %q last seen %s ago — not actively reporting", d.Hostname, age.Truncate(time.Minute)),
			Remediation: "Verify agent connectivity and restart the agent service if needed.",
		}
	}

	return CheckResult{
		Status:      "pass",
		Evidence:    fmt.Sprintf("Agent %q (enrolled %s) last seen %s ago", d.Hostname, d.EnrolledAt.Format("2006-01-02"), age.Truncate(time.Minute)),
		Remediation: "",
	}
}

// nistPRds1 — PR.DS-1: Data-at-rest protection (disk encryption).
// Queries endpoint_hardening for encryption status; unknown if no data.
func nistPRds1(d AgentComplianceData) CheckResult {
	// This check relies on supplementary data populated by the hardening module.
	// The check function uses AgentComplianceData which may be extended;
	// for now return unknown if we cannot determine encryption state from events alone.
	if d.RecentEvents == 0 && d.LastSeen.IsZero() {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "No telemetry data available to assess disk encryption status",
			Remediation: "Ensure the agent is enrolled and reporting endpoint configuration data.",
		}
	}

	// Without direct encryption telemetry in AgentComplianceData,
	// we conservatively return unknown rather than a false pass/fail.
	return CheckResult{
		Status:      "unknown",
		Evidence:    "Disk encryption status requires endpoint hardening telemetry (not yet collected for this agent)",
		Remediation: "Enable disk encryption reporting in the agent policy or use the endpoint hardening module.",
	}
}

// nistDEcm1 — DE.CM-1: Network is monitored.
func nistDEcm1(d AgentComplianceData) CheckResult {
	if d.LastSeen.IsZero() {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "Agent has no telemetry; cannot assess network monitoring",
			Remediation: "Ensure the agent is enrolled and reporting.",
		}
	}

	if d.NetworkEvents == 0 {
		return CheckResult{
			Status:      "fail",
			Evidence:    "No network events collected in the last 24 hours",
			Remediation: "Enable network monitoring in the agent policy to satisfy DE.CM-1.",
		}
	}

	return CheckResult{
		Status:      "pass",
		Evidence:    fmt.Sprintf("%d network events monitored in the last 24 hours", d.NetworkEvents),
		Remediation: "",
	}
}

// nistDEcm7 — DE.CM-7: Monitoring for unauthorized activity.
// Uses total event volume as a proxy for active monitoring coverage.
func nistDEcm7(d AgentComplianceData) CheckResult {
	if d.LastSeen.IsZero() {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "No telemetry available; cannot assess unauthorized activity monitoring",
			Remediation: "Ensure the agent is enrolled and event collection is active.",
		}
	}

	// Require both events and agent liveness within 24h.
	age := time.Since(d.LastSeen)
	if age > 24*time.Hour || d.RecentEvents == 0 {
		return CheckResult{
			Status: "fail",
			Evidence: fmt.Sprintf(
				"Agent %q: last seen %s ago, %d events in 24h — insufficient monitoring coverage",
				d.Hostname, age.Truncate(time.Minute), d.RecentEvents,
			),
			Remediation: "Ensure the agent is online and all event collection categories are enabled.",
		}
	}

	return CheckResult{
		Status:      "pass",
		Evidence:    fmt.Sprintf("Agent %q active (last seen %s ago), %d events collected in 24h", d.Hostname, age.Truncate(time.Minute), d.RecentEvents),
		Remediation: "",
	}
}

// nistRSan1 — RS.AN-1: Detection notifications investigated.
// Pass if recent alerts are at a manageable level (investigated within SLA).
func nistRSan1(d AgentComplianceData) CheckResult {
	if d.LastSeen.IsZero() {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "No telemetry available; cannot assess alert investigation posture",
			Remediation: "Ensure the agent is enrolled and the detection pipeline is active.",
		}
	}

	// If there are a large number of unresolved alerts it indicates
	// notifications are not being investigated in a timely manner.
	const criticalThreshold = 10
	if d.RecentAlerts >= criticalThreshold {
		return CheckResult{
			Status: "fail",
			Evidence: fmt.Sprintf(
				"%d alerts generated in the last 24 hours — possible investigation backlog",
				d.RecentAlerts,
			),
			Remediation: "Review and triage open alerts. Consider enabling automated response playbooks to reduce backlog.",
		}
	}

	return CheckResult{
		Status:      "pass",
		Evidence:    fmt.Sprintf("%d alerts in the last 24 hours — within investigation SLA threshold", d.RecentAlerts),
		Remediation: "",
	}
}

// SOC2Controls returns SOC 2 Type II controls relevant to EDR telemetry.
func SOC2Controls() []Control {
	return []Control{
		{
			ID:          "CC6.1",
			Title:       "Logical Access Controls",
			Description: "The entity implements logical access security software, infrastructure, and architectures over protected information assets.",
			Severity:    "high",
			Check:       soc2CC6_1,
		},
		{
			ID:          "CC7.2",
			Title:       "System Monitoring",
			Description: "The entity monitors system components and the operation of controls to detect anomalies.",
			Severity:    "high",
			Check:       soc2CC7_2,
		},
		{
			ID:          "CC7.3",
			Title:       "Incident Response",
			Description: "The entity evaluates security events to determine whether they could or have resulted in a failure of the entity to meet its objectives.",
			Severity:    "critical",
			Check:       soc2CC7_3,
		},
		{
			ID:          "CC9.2",
			Title:       "Risk Mitigation",
			Description: "The entity assesses and manages risks associated with vendors and business partners.",
			Severity:    "medium",
			Check:       soc2CC9_2,
		},
	}
}

// soc2CC6_1 — CC6.1: Logical access controls — agent is enrolled and active.
func soc2CC6_1(d AgentComplianceData) CheckResult {
	if d.LastSeen.IsZero() {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "Agent enrollment data unavailable",
			Remediation: "Ensure the agent is enrolled and reporting.",
		}
	}

	age := time.Since(d.LastSeen)
	if age > 24*time.Hour {
		return CheckResult{
			Status:      "fail",
			Evidence:    fmt.Sprintf("Agent %q last seen %s ago — endpoint may not have access controls enforced", d.Hostname, age.Truncate(time.Minute)),
			Remediation: "Restore agent connectivity to ensure continuous access control monitoring.",
		}
	}

	return CheckResult{
		Status:      "pass",
		Evidence:    fmt.Sprintf("Agent %q enrolled and reporting (last seen %s ago)", d.Hostname, age.Truncate(time.Minute)),
		Remediation: "",
	}
}

// soc2CC7_2 — CC7.2: System monitoring — events actively flowing.
func soc2CC7_2(d AgentComplianceData) CheckResult {
	if d.LastSeen.IsZero() {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "No telemetry data available",
			Remediation: "Ensure the agent is enrolled and event collection is active.",
		}
	}

	if d.RecentEvents == 0 {
		return CheckResult{
			Status:      "fail",
			Evidence:    "No system events collected in the last 24 hours",
			Remediation: "Enable system event collection in the agent policy to satisfy CC7.2.",
		}
	}

	return CheckResult{
		Status:      "pass",
		Evidence:    fmt.Sprintf("%d system events collected in the last 24 hours for %q", d.RecentEvents, d.Hostname),
		Remediation: "",
	}
}

// soc2CC7_3 — CC7.3: Incident response — alerts being generated and not overwhelming.
func soc2CC7_3(d AgentComplianceData) CheckResult {
	if d.LastSeen.IsZero() {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "No telemetry available to assess incident detection capability",
			Remediation: "Ensure the agent is enrolled and the detection pipeline is active.",
		}
	}

	const highAlertThreshold = 20
	if d.RecentAlerts >= highAlertThreshold {
		return CheckResult{
			Status: "fail",
			Evidence: fmt.Sprintf(
				"%d alerts in 24 hours on %q — possible unmanaged incident activity",
				d.RecentAlerts, d.Hostname,
			),
			Remediation: "Review alerts for active incidents and assign them to responders. Tune detection rules to reduce false positives.",
		}
	}

	return CheckResult{
		Status:      "pass",
		Evidence:    fmt.Sprintf("%d alerts in the last 24 hours on %q", d.RecentAlerts, d.Hostname),
		Remediation: "",
	}
}

// soc2CC9_2 — CC9.2: Risk mitigation — endpoint is managed and version is known.
func soc2CC9_2(d AgentComplianceData) CheckResult {
	if d.AgentVersion == "" {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "Agent version not reported; cannot assess risk management posture",
			Remediation: "Ensure the agent is up to date and reporting its version.",
		}
	}

	if d.LastSeen.IsZero() || time.Since(d.LastSeen) > 48*time.Hour {
		return CheckResult{
			Status:      "fail",
			Evidence:    fmt.Sprintf("Agent %q (version %s) is not actively reporting — endpoint at risk", d.Hostname, d.AgentVersion),
			Remediation: "Restore connectivity or investigate why the endpoint is offline.",
		}
	}

	return CheckResult{
		Status:      "pass",
		Evidence:    fmt.Sprintf("Agent %q version %s is enrolled and actively managed", d.Hostname, d.AgentVersion),
		Remediation: "",
	}
}
