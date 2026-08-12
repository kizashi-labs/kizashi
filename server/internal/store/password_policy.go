package store

import (
	"context"
	"fmt"
	"strings"
	"time"
	"unicode"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PasswordPolicy mirrors the password_policy table (singleton row, id=1).
type PasswordPolicy struct {
	ID               int       `json:"id"`
	MinLength        int       `json:"min_length"`
	RequireUppercase bool      `json:"require_uppercase"`
	RequireLowercase bool      `json:"require_lowercase"`
	RequireNumber    bool      `json:"require_number"`
	RequireSpecial   bool      `json:"require_special"`
	MaxAgeDays       int       `json:"max_age_days"`
	HistoryCount     int       `json:"history_count"`
	UpdatedAt        time.Time `json:"updated_at"`
}

// PasswordPolicyStore handles DB access for the password_policy table.
type PasswordPolicyStore struct {
	pool *pgxpool.Pool
}

func NewPasswordPolicyStore(db *DB) *PasswordPolicyStore {
	return &PasswordPolicyStore{pool: db.Pool()}
}

// Get returns the current password policy. It uses a short timeout so callers
// are not blocked if the DB is slow.
func (s *PasswordPolicyStore) Get(ctx context.Context) (*PasswordPolicy, error) {
	ctx, cancel := context.WithTimeout(ctx, 3*time.Second)
	defer cancel()

	var p PasswordPolicy
	err := s.pool.QueryRow(ctx, `
		SELECT id, min_length, require_uppercase, require_lowercase,
		       require_number, require_special, max_age_days, history_count, updated_at
		FROM password_policy WHERE id = 1`,
	).Scan(
		&p.ID, &p.MinLength, &p.RequireUppercase, &p.RequireLowercase,
		&p.RequireNumber, &p.RequireSpecial, &p.MaxAgeDays, &p.HistoryCount, &p.UpdatedAt,
	)
	if err != nil {
		return nil, fmt.Errorf("パスワードポリシーの取得に失敗しました: %w", err)
	}
	return &p, nil
}

// Update overwrites the singleton row with the supplied policy values.
func (s *PasswordPolicyStore) Update(ctx context.Context, policy PasswordPolicy) error {
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	_, err := s.pool.Exec(ctx, `
		UPDATE password_policy
		SET min_length        = $1,
		    require_uppercase = $2,
		    require_lowercase = $3,
		    require_number    = $4,
		    require_special   = $5,
		    max_age_days      = $6,
		    history_count     = $7,
		    updated_at        = NOW()
		WHERE id = 1`,
		policy.MinLength,
		policy.RequireUppercase,
		policy.RequireLowercase,
		policy.RequireNumber,
		policy.RequireSpecial,
		policy.MaxAgeDays,
		policy.HistoryCount,
	)
	if err != nil {
		return fmt.Errorf("パスワードポリシーの更新に失敗しました: %w", err)
	}
	return nil
}

// Validate checks password against the policy and returns an error listing ALL
// violations (not just the first one). Returns nil if the password is compliant.
// This method is safe to call concurrently — it reads only from the supplied
// policy value, which is already resolved.
func (s *PasswordPolicyStore) Validate(password string, policy *PasswordPolicy) error {
	var violations []string

	// Length check
	if len(password) < policy.MinLength {
		violations = append(violations,
			fmt.Sprintf("パスワードは%d文字以上である必要があります（現在: %d文字）",
				policy.MinLength, len(password)))
	}

	if policy.RequireUppercase || policy.RequireLowercase ||
		policy.RequireNumber || policy.RequireSpecial {

		var hasUpper, hasLower, hasDigit, hasSpecial bool
		for _, r := range password {
			switch {
			case unicode.IsUpper(r):
				hasUpper = true
			case unicode.IsLower(r):
				hasLower = true
			case unicode.IsDigit(r):
				hasDigit = true
			case unicode.IsPunct(r) || unicode.IsSymbol(r):
				hasSpecial = true
			}
		}

		if policy.RequireUppercase && !hasUpper {
			violations = append(violations, "大文字（A-Z）を1文字以上含める必要があります")
		}
		if policy.RequireLowercase && !hasLower {
			violations = append(violations, "小文字（a-z）を1文字以上含める必要があります")
		}
		if policy.RequireNumber && !hasDigit {
			violations = append(violations, "数字（0-9）を1文字以上含める必要があります")
		}
		if policy.RequireSpecial && !hasSpecial {
			violations = append(violations, "記号（!@#$% など）を1文字以上含める必要があります")
		}
	}

	if len(violations) == 0 {
		return nil
	}
	return fmt.Errorf("パスワードがポリシーを満たしていません: %s", strings.Join(violations, "; "))
}

// Violations returns each individual policy violation as a string slice.
// Useful for returning structured JSON to the client.
func (s *PasswordPolicyStore) Violations(password string, policy *PasswordPolicy) []string {
	var violations []string

	if len(password) < policy.MinLength {
		violations = append(violations,
			fmt.Sprintf("パスワードは%d文字以上である必要があります（現在: %d文字）",
				policy.MinLength, len(password)))
	}

	var hasUpper, hasLower, hasDigit, hasSpecial bool
	for _, r := range password {
		switch {
		case unicode.IsUpper(r):
			hasUpper = true
		case unicode.IsLower(r):
			hasLower = true
		case unicode.IsDigit(r):
			hasDigit = true
		case unicode.IsPunct(r) || unicode.IsSymbol(r):
			hasSpecial = true
		}
	}

	if policy.RequireUppercase && !hasUpper {
		violations = append(violations, "大文字（A-Z）を1文字以上含める必要があります")
	}
	if policy.RequireLowercase && !hasLower {
		violations = append(violations, "小文字（a-z）を1文字以上含める必要があります")
	}
	if policy.RequireNumber && !hasDigit {
		violations = append(violations, "数字（0-9）を1文字以上含める必要があります")
	}
	if policy.RequireSpecial && !hasSpecial {
		violations = append(violations, "記号（!@#$% など）を1文字以上含める必要があります")
	}

	return violations
}
