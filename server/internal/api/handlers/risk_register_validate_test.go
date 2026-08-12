package handlers

import (
	"errors"
	"fmt"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

func TestValidateRiskConstraints(t *testing.T) {
	tests := []struct {
		name                                     string
		likelihood, impact, controlEffectiveness int
		appetite, status                         string
		wantOK                                   bool
	}{
		{"全フィールド有効", 3, 4, 50, "within", "active", true},
		{"境界値(最小/最大)", 1, 5, 0, "exceeds", "closed", true},
		{"likelihood下限未満", 0, 3, 10, "within", "active", false},
		{"likelihood上限超過", 6, 3, 10, "within", "active", false},
		{"impact下限未満", 3, 0, 10, "within", "active", false},
		{"impact上限超過", 3, 6, 10, "within", "active", false},
		{"control_effectiveness負", 3, 3, -1, "within", "active", false},
		{"control_effectiveness100超", 3, 3, 101, "within", "active", false},
		{"risk_appetite不正", 3, 3, 10, "aggressive", "active", false},
		{"risk_appetite空", 3, 3, 10, "", "active", false},
		{"status不正", 3, 3, 10, "within", "archived", false},
		{"status空", 3, 3, 10, "within", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := validateRiskConstraints(tc.likelihood, tc.impact, tc.controlEffectiveness, tc.appetite, tc.status)
			if (msg == "") != tc.wantOK {
				t.Errorf("validateRiskConstraints(...) = %q, wantOK=%v", msg, tc.wantOK)
			}
		})
	}
}

func TestIsConstraintViolation(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want bool
	}{
		{"check_violation(23514)", &pgconn.PgError{Code: "23514"}, true},
		{"not_null(23502)", &pgconn.PgError{Code: "23502"}, true},
		{"unique(23505)", &pgconn.PgError{Code: "23505"}, true},
		{"invalid_text_representation(22P02)", &pgconn.PgError{Code: "22P02"}, true},
		{"wrapped pgErr", fmt.Errorf("update failed: %w", &pgconn.PgError{Code: "23514"}), true},
		{"undefined_table(42P01)は対象外", &pgconn.PgError{Code: "42P01"}, false},
		{"接続エラー(クラス08)は対象外", &pgconn.PgError{Code: "08006"}, false},
		{"非pgエラー", errors.New("context deadline exceeded"), false},
		{"nil", nil, false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isConstraintViolation(tc.err); got != tc.want {
				t.Errorf("isConstraintViolation(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}
