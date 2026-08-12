package detection

import "testing"

func TestCloudEventRule_IsSuspicious(t *testing.T) {
	cases := []struct {
		eventType string
		want      bool
	}{
		{"DeleteTrail", true},      // exact match
		{"deletetrail", true},      // case-insensitive
		{"AWS:DeleteBucket", true}, // substring match
		{"StopLogging", true},      // CloudTrail tampering
		{"microsoft.security/policies/write", true},
		{"DescribeInstances", false}, // benign
		{"GetObject", false},
		{"", false},
	}
	for _, tc := range cases {
		got, reason := DefaultCloudRules.IsSuspicious(&CloudEventPayload{EventType: tc.eventType})
		if got != tc.want {
			t.Errorf("IsSuspicious(%q): got %v, want %v", tc.eventType, got, tc.want)
		}
		if got && reason == "" {
			t.Errorf("IsSuspicious(%q): expected a non-empty reason when suspicious", tc.eventType)
		}
		if !got && reason != "" {
			t.Errorf("IsSuspicious(%q): expected empty reason when benign, got %q", tc.eventType, reason)
		}
	}
}

// TestCloudEventRule_Evaluate_TechniqueAttribution verifies the expanded cloud
// pattern set fires on real AWS/Azure/GCP attacker operations and attributes the
// correct ATT&CK technique (not a flat T1098) and a per-event severity.
func TestCloudEventRule_Evaluate_TechniqueAttribution(t *testing.T) {
	cases := []struct {
		eventType string
		suspect   bool
		technique string
	}{
		// Defense evasion — cloud logging tamper
		{"DeleteTrail", true, "T1562.008"},
		{"DeleteDetector", true, "T1562.008"},                               // GuardDuty
		{"microsoft.insights/diagnosticSettings/delete", true, "T1562.008"}, // Azure
		// Credential access — secret stores
		{"GetSecretValue", true, "T1555.006"},
		{"microsoft.keyvault/vaults/secrets/read", true, "T1555.006"},
		// Persistence — cloud accounts / keys
		{"CreateAccessKey", true, "T1098.001"},
		{"CreateUser", true, "T1136.003"},
		// Privilege escalation — IAM
		{"AttachUserPolicy", true, "T1098"},
		{"UpdateAssumeRolePolicy", true, "T1098"},
		{"SetIamPolicy", true, "T1098"}, // GCP
		// Collection/exfil — storage exposure
		{"PutBucketPolicy", true, "T1530"},
		// Impact — destructive
		{"ScheduleKeyDeletion", true, "T1486"},
		{"TerminateInstances", true, "T1485"},
		// Benign / noisy read events must stay quiet
		{"DescribeInstances", false, ""},
		{"GetObject", false, ""},
		{"ListBuckets", false, ""},
		{"AssumeRole", false, ""},
		{"", false, ""},
	}
	for _, tc := range cases {
		v := DefaultCloudRules.Evaluate(&CloudEventPayload{EventType: tc.eventType})
		if v.Suspicious != tc.suspect {
			t.Errorf("Evaluate(%q).Suspicious = %v, want %v", tc.eventType, v.Suspicious, tc.suspect)
			continue
		}
		if tc.suspect {
			if v.Technique != tc.technique {
				t.Errorf("Evaluate(%q).Technique = %q, want %q", tc.eventType, v.Technique, tc.technique)
			}
			if v.Severity < 1 || v.Severity > 10 {
				t.Errorf("Evaluate(%q).Severity = %d, want 1..10", tc.eventType, v.Severity)
			}
			// Technique must be recognised by the kill-chain tactic map so cloud
			// alerts contribute to multi-stage correlation.
			if tacticForTechnique(v.Technique) == "" {
				t.Errorf("Evaluate(%q): technique %q not mapped to a tactic", tc.eventType, v.Technique)
			}
		}
	}
}

func TestParseCloudEvent(t *testing.T) {
	payload, err := ParseCloudEvent([]byte(`{"id":"e1","provider":"aws","event_type":"DeleteTrail","region":"us-east-1"}`))
	if err != nil {
		t.Fatalf("ParseCloudEvent: %v", err)
	}
	if payload.ID != "e1" || payload.Provider != "aws" || payload.EventType != "DeleteTrail" {
		t.Errorf("parsed payload incorrect: %+v", payload)
	}
	if _, err := ParseCloudEvent([]byte(`{not json`)); err == nil {
		t.Error("expected error on invalid JSON")
	}
}
