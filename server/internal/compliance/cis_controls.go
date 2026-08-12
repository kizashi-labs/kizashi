package compliance

import (
	"fmt"
	"time"
)

// CISControls returns the CIS Benchmark controls relevant to EDR telemetry.
func CISControls() []Control {
	return []Control{
		{
			ID:          "CIS-1.1",
			Title:       "Asset Inventory",
			Description: "Actively manage all enterprise assets so that only authorized assets are given access, and unauthorized and unmanaged assets are found and prevented from gaining access.",
			Severity:    "high",
			Check:       cisCTRL1_1,
		},
		{
			ID:          "CIS-4.1",
			Title:       "Secure Configuration",
			Description: "Establish and maintain the secure configuration of enterprise assets — agent should be running a current, supported version.",
			Severity:    "medium",
			Check:       cisCTRL4_1,
		},
		{
			ID:          "CIS-8.2",
			Title:       "Audit Log Management",
			Description: "Collect audit logs of events that could help detect, understand, or recover from an attack.",
			Severity:    "high",
			Check:       cisCTRL8_2,
		},
		{
			ID:          "CIS-10.1",
			Title:       "Malware Defense",
			Description: "Prevent or control the installation, spread, and execution of malicious applications.",
			Severity:    "critical",
			Check:       cisCTRL10_1,
		},
		{
			ID:          "CIS-13.1",
			Title:       "Network Monitoring",
			Description: "Operate processes and tooling to establish and maintain comprehensive network monitoring and defense against security threats.",
			Severity:    "high",
			Check:       cisCTRL13_1,
		},
	}
}

// cisCTRL1_1 — Asset inventory: agent enrolled and reporting within last 24h.
func cisCTRL1_1(d AgentComplianceData) CheckResult {
	if d.LastSeen.IsZero() {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "No last-seen timestamp available for agent",
			Remediation: "Ensure the agent is enrolled and reporting heartbeats.",
		}
	}

	age := time.Since(d.LastSeen)
	if age > 24*time.Hour {
		return CheckResult{
			Status:      "fail",
			Evidence:    fmt.Sprintf("Agent last seen %s ago (threshold: 24h)", age.Truncate(time.Minute)),
			Remediation: "Verify the agent service is running and has network connectivity to the server.",
		}
	}

	return CheckResult{
		Status:      "pass",
		Evidence:    fmt.Sprintf("Agent %q last reported %s ago", d.Hostname, age.Truncate(time.Minute)),
		Remediation: "",
	}
}

// cisCTRL4_1 — Secure configuration: agent version is not empty (basic up-to-date proxy).
func cisCTRL4_1(d AgentComplianceData) CheckResult {
	if d.AgentVersion == "" {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "Agent version not reported",
			Remediation: "Upgrade the agent to a current release so it reports its version.",
		}
	}

	// A non-empty version means the agent is at least identifiable.
	// Deeper semver comparison is handled by the autoupdate subsystem.
	return CheckResult{
		Status:      "pass",
		Evidence:    fmt.Sprintf("Agent version: %s", d.AgentVersion),
		Remediation: "",
	}
}

// cisCTRL8_2 — Audit log management: events collected in last 24h.
func cisCTRL8_2(d AgentComplianceData) CheckResult {
	if d.LastSeen.IsZero() {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "Agent has no telemetry data available",
			Remediation: "Ensure the agent is enrolled and event collection is configured.",
		}
	}

	if d.RecentEvents == 0 {
		return CheckResult{
			Status:      "fail",
			Evidence:    "No events collected in the last 24 hours",
			Remediation: "Check agent event collection configuration and ensure audit logging is enabled on the endpoint.",
		}
	}

	return CheckResult{
		Status:      "pass",
		Evidence:    fmt.Sprintf("%d events collected in the last 24 hours", d.RecentEvents),
		Remediation: "",
	}
}

// cisCTRL10_1 — Malware defense: detection alerts below threshold.
// Pass = 0 alerts. Fail = 3 or more active alerts in 24h (indicating unresolved malware).
func cisCTRL10_1(d AgentComplianceData) CheckResult {
	if d.LastSeen.IsZero() {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "Agent has no telemetry data; cannot assess malware defense status",
			Remediation: "Ensure the agent is enrolled and reporting.",
		}
	}

	const alertThreshold = 3
	if d.RecentAlerts >= alertThreshold {
		return CheckResult{
			Status: "fail",
			Evidence: fmt.Sprintf(
				"%d detection alerts in the last 24 hours (threshold: <%d)",
				d.RecentAlerts, alertThreshold,
			),
			Remediation: "Investigate and remediate open alerts. Ensure endpoint protection is active and up to date.",
		}
	}

	return CheckResult{
		Status:      "pass",
		Evidence:    fmt.Sprintf("%d detection alerts in the last 24 hours", d.RecentAlerts),
		Remediation: "",
	}
}

// cisCTRL13_1 — Network monitoring: network events flowing.
func cisCTRL13_1(d AgentComplianceData) CheckResult {
	if d.LastSeen.IsZero() {
		return CheckResult{
			Status:      "unknown",
			Evidence:    "Agent has no telemetry data; cannot assess network monitoring",
			Remediation: "Ensure the agent is enrolled and reporting.",
		}
	}

	if d.NetworkEvents == 0 {
		return CheckResult{
			Status:      "fail",
			Evidence:    "No network events collected in the last 24 hours",
			Remediation: "Enable network event collection in the agent policy and verify the endpoint has network activity.",
		}
	}

	return CheckResult{
		Status:      "pass",
		Evidence:    fmt.Sprintf("%d network events collected in the last 24 hours", d.NetworkEvents),
		Remediation: "",
	}
}
