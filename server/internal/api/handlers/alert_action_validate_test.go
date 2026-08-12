package handlers

import (
	"testing"
)

func TestIsValidAlertStatus_ValidStatuses_ReturnTrue(t *testing.T) {
	for _, s := range []string{"open", "investigating", "resolved", "suppressed"} {
		if !isValidAlertStatus(s) {
			t.Errorf("isValidAlertStatus(%q) = false, want true", s)
		}
	}
}

func TestIsValidAlertStatus_InvalidStatuses_ReturnFalse(t *testing.T) {
	for _, s := range []string{"", "closed", "OPEN", "pending", "unknown"} {
		if isValidAlertStatus(s) {
			t.Errorf("isValidAlertStatus(%q) = true, want false", s)
		}
	}
}

func TestIsValidAlertStatus_CaseSensitive(t *testing.T) {
	// "Open" (capital) is NOT a valid status — map is lowercase only.
	if isValidAlertStatus("Open") {
		t.Error("isValidAlertStatus(\"Open\") should be false (case-sensitive)")
	}
}
