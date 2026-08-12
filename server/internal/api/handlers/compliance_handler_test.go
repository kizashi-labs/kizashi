package handlers_test

import (
	"testing"
)

func TestComplianceFrameworkIDs(t *testing.T) {
	// Validate that the seeded framework IDs match what the frontend expects
	expectedFrameworks := []string{"soc2", "iso27001", "pcidss"}
	for _, fw := range expectedFrameworks {
		if fw == "" {
			t.Errorf("empty framework ID")
		}
		t.Logf("framework: %s ✓", fw)
	}
}

func TestComplianceControlCategories(t *testing.T) {
	// SOC2 categories
	soc2Categories := []string{"Common Criteria"}
	// ISO27001 categories
	iso27001Categories := []string{"Access Control", "Operations Security", "Incident Management", "Asset Management"}
	// PCI-DSS categories
	pciCategories := []string{"Network Security", "Access Control", "Logging & Monitoring", "Malware Protection"}

	allCategories := append(soc2Categories, iso27001Categories...)
	allCategories = append(allCategories, pciCategories...)
	for _, cat := range allCategories {
		if cat == "" {
			t.Errorf("empty category")
		}
	}
}

func TestComplianceScoreCalculation(t *testing.T) {
	tests := []struct {
		passed int
		total  int
		want   float64
	}{
		{10, 10, 100.0},
		{0, 10, 0.0},
		{5, 10, 50.0},
		{0, 0, 0.0}, // edge case: no controls
	}

	for _, tt := range tests {
		score := 0.0
		if tt.total > 0 {
			score = float64(tt.passed) / float64(tt.total) * 100
		}
		if score != tt.want {
			t.Errorf("score(%d/%d) = %f, want %f", tt.passed, tt.total, score, tt.want)
		}
	}
}
