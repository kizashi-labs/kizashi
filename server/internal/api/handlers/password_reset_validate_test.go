package handlers

import "testing"

// ─── validateNewPassword ──────────────────────────────────────────────────────

func TestValidateNewPassword_Valid(t *testing.T) {
	if err := validateNewPassword("abc12345"); err != nil {
		t.Errorf("validateNewPassword(valid) = %v, want nil", err)
	}
}

func TestValidateNewPassword_TooShort(t *testing.T) {
	if err := validateNewPassword("abc123"); err == nil {
		t.Error("validateNewPassword(too short): expected error")
	}
}

func TestValidateNewPassword_NoDigit(t *testing.T) {
	if err := validateNewPassword("abcdefgh"); err == nil {
		t.Error("validateNewPassword(no digit): expected error")
	}
}

func TestValidateNewPassword_NoLetter(t *testing.T) {
	if err := validateNewPassword("12345678"); err == nil {
		t.Error("validateNewPassword(no letter): expected error")
	}
}

func TestValidateNewPassword_Empty(t *testing.T) {
	if err := validateNewPassword(""); err == nil {
		t.Error("validateNewPassword(empty): expected error")
	}
}

func TestValidateNewPassword_ExactlyLength8(t *testing.T) {
	if err := validateNewPassword("abcdef1!"); err != nil {
		t.Errorf("validateNewPassword(len=8) = %v, want nil", err)
	}
}
