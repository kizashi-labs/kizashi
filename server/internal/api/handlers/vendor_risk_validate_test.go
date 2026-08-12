package handlers

import "testing"

// ─── vendorRiskTier ──────────────────────────────────────────────────────────

func TestVendorRiskTier_Low(t *testing.T) {
	for _, score := range []int{0, 15, 30} {
		if got := vendorRiskTier(score); got != "low" {
			t.Errorf("vendorRiskTier(%d) = %q, want 'low'", score, got)
		}
	}
}

func TestVendorRiskTier_Medium(t *testing.T) {
	for _, score := range []int{31, 45, 60} {
		if got := vendorRiskTier(score); got != "medium" {
			t.Errorf("vendorRiskTier(%d) = %q, want 'medium'", score, got)
		}
	}
}

func TestVendorRiskTier_High(t *testing.T) {
	for _, score := range []int{61, 70, 80} {
		if got := vendorRiskTier(score); got != "high" {
			t.Errorf("vendorRiskTier(%d) = %q, want 'high'", score, got)
		}
	}
}

func TestVendorRiskTier_Critical(t *testing.T) {
	for _, score := range []int{81, 90, 100} {
		if got := vendorRiskTier(score); got != "critical" {
			t.Errorf("vendorRiskTier(%d) = %q, want 'critical'", score, got)
		}
	}
}

func TestVendorRiskTier_Boundary_30_IsLow(t *testing.T) {
	if got := vendorRiskTier(30); got != "low" {
		t.Errorf("vendorRiskTier(30) = %q, want 'low'", got)
	}
}

func TestVendorRiskTier_Boundary_31_IsMedium(t *testing.T) {
	if got := vendorRiskTier(31); got != "medium" {
		t.Errorf("vendorRiskTier(31) = %q, want 'medium'", got)
	}
}

func TestVendorRiskTier_Boundary_80_IsHigh(t *testing.T) {
	if got := vendorRiskTier(80); got != "high" {
		t.Errorf("vendorRiskTier(80) = %q, want 'high'", got)
	}
}

func TestVendorRiskTier_Boundary_81_IsCritical(t *testing.T) {
	if got := vendorRiskTier(81); got != "critical" {
		t.Errorf("vendorRiskTier(81) = %q, want 'critical'", got)
	}
}
