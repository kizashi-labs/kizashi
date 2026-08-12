package cspm

import (
	"context"
	"testing"
)

func TestCSPMScanAWS(t *testing.T) {
	checker := NewChecker()
	cfg := ProviderConfig{
		Provider:  ProviderAWS,
		AccountID: "123456789012",
		Settings: map[string]interface{}{
			"s3_block_public_access": true,
			"root_mfa_enabled":       false,
			"cloudtrail_enabled":     true,
			"ssh_unrestricted":       false,
			"ebs_encryption":         true,
		},
	}

	result, err := checker.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if len(result.Findings) == 0 {
		t.Error("expected findings")
	}
	if result.Summary.Total == 0 {
		t.Error("expected non-zero total")
	}

	// With all pass settings, score should be high
	if result.Summary.Score < 60 {
		t.Errorf("expected score >= 60, got %d", result.Summary.Score)
	}
}

func TestCSPMScanAllFail(t *testing.T) {
	checker := NewChecker()
	cfg := ProviderConfig{
		Provider:  ProviderAWS,
		AccountID: "123456789012",
		Settings: map[string]interface{}{
			"s3_block_public_access": false,
			"root_mfa_enabled":       false,
			"cloudtrail_enabled":     false,
			"ssh_unrestricted":       true,
			"ebs_encryption":         false,
		},
	}

	result, err := checker.Scan(context.Background(), cfg)
	if err != nil {
		t.Fatalf("scan failed: %v", err)
	}
	if result.Summary.Failed == 0 {
		t.Error("expected some failures")
	}
	if result.Summary.Score > 10 {
		t.Errorf("expected low score for all-fail, got %d", result.Summary.Score)
	}
}

func TestCSPMComputeSummary(t *testing.T) {
	findings := []Finding{
		{Status: StatusPass, Severity: SeverityHigh},
		{Status: StatusFail, Severity: SeverityCritical},
		{Status: StatusFail, Severity: SeverityHigh},
		{Status: StatusSkip, Severity: SeverityLow},
	}
	s := computeSummary(findings)
	if s.Total != 4 {
		t.Errorf("expected 4 total, got %d", s.Total)
	}
	if s.Passed != 1 {
		t.Errorf("expected 1 passed, got %d", s.Passed)
	}
	if s.Failed != 2 {
		t.Errorf("expected 2 failed, got %d", s.Failed)
	}
	if s.Critical != 1 {
		t.Errorf("expected 1 critical, got %d", s.Critical)
	}
}
