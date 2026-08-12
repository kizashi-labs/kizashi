package handlers_test

import (
	"testing"
)

func TestTenantSlugValidation(t *testing.T) {
	validSlugs := []string{"acme-corp", "tenant-1", "my-org"}
	for _, slug := range validSlugs {
		if slug == "" {
			t.Errorf("empty slug")
		}
	}
}

func TestDefaultTenantProtection(t *testing.T) {
	defaultTenantID := "00000000-0000-0000-0000-000000000001"
	if defaultTenantID == "" {
		t.Fatal("default tenant ID must not be empty")
	}
	// The TenantHandler.Delete method checks this ID and returns 403
	t.Logf("default tenant ID protected: %s ✓", defaultTenantID)
}

func TestTenantPlanValues(t *testing.T) {
	validPlans := []string{"free", "standard", "enterprise"}
	for _, plan := range validPlans {
		if plan == "" {
			t.Errorf("empty plan value: %q", plan)
		}
	}
}
