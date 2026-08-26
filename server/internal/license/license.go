// Package license is the open source edition stub.
//
// The commercial edition uses this package to verify a signed license key and
// to gate features by plan. The open source edition has no plans, no license
// keys, and no feature gating: everything that ships in this repository is
// available. This stub keeps the same API surface so that call sites do not
// need to be edited, and answers "yes" to every capability question.
//
// If you are reading this because you want to remove a restriction: there is
// nothing here to remove. The enterprise features referenced by the constants
// below (MDM, SSO, compliance automation, CSPM/XDR, SIEM connectors,
// AI-assisted triage) are not part of this repository at all — they are not
// disabled, they are absent.
package license

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Feature constants. Retained so existing call sites compile unchanged.
// In this edition every feature check returns true.
const (
	FeatureBasicDetection  = "basic_detection"
	FeatureAlerts          = "alerts"
	FeatureReports         = "reports"
	FeatureAIInvestigation = "ai_investigation"
	FeatureSIEM            = "siem_integration"
	FeaturePlaybooks       = "playbooks"
	FeatureThreatIntel     = "threat_intel"
	FeatureYARA            = "yara"
	FeatureMLDetection     = "ml_detection"
	FeatureThreatHunting   = "threat_hunting"
	FeatureMultiTenant     = "multi_tenant"
	FeatureCompliance      = "compliance"
	FeatureAPIAccess       = "api_access"
	FeatureXDR             = "xdr"
	FeatureDeception       = "deception"
	FeatureForensics       = "forensics"
	FeatureSOAR            = "soar"
	FeatureMDM             = "mdm"
)

// Plan constants. This edition always reports PlanOSS.
const (
	PlanOSS          = "oss"
	PlanFree         = "free"
	PlanLite         = "lite"
	PlanStarter      = "starter"
	PlanProfessional = "professional"
	PlanEnterprise   = "enterprise"
	PlanBusiness     = PlanProfessional
)

// unlimited is used for agent and user limits. Call sites treat 0 as "no limit".
const unlimited = 0

// License describes the active license. Shape is kept identical to the
// commercial edition so API responses and the console do not change.
type License struct {
	ID               string    `json:"id"`
	OrganizationName string    `json:"organization_name"`
	Plan             string    `json:"plan"`
	AgentLimit       int       `json:"agent_limit"`
	UserLimit        int       `json:"user_limit"`
	Features         []string  `json:"features"`
	ValidFrom        time.Time `json:"valid_from"`
	ExpiresAt        time.Time `json:"expires_at"`
	IsExpired        bool      `json:"is_expired"`
	DaysRemaining    int       `json:"days_remaining"`
	LicenseKey       string    `json:"license_key,omitempty"`

	// AIExternalOptin records whether the operator consented to sending data
	// to an external AI provider. The AI investigation features are not part
	// of this edition, so this stays false unless explicitly set.
	AIExternalOptin bool `json:"ai_external_optin"`
}

// UsageSummary reports agent and user counts against the (unlimited) license.
type UsageSummary struct {
	AgentsActive  int     `json:"agents_active"`
	AgentLimit    int     `json:"agent_limit"`
	AgentPercent  float64 `json:"agent_percent"`
	UsersActive   int     `json:"users_active"`
	UserLimit     int     `json:"user_limit"`
	UserPercent   float64 `json:"user_percent"`
	Plan          string  `json:"plan"`
	DaysRemaining int     `json:"days_remaining"`
	CanAddAgents  bool    `json:"can_add_agents"`
	CanAddUsers   bool    `json:"can_add_users"`
}

// AllFeatures is every feature identifier known to this build.
func AllFeatures() []string {
	return []string{
		FeatureBasicDetection, FeatureAlerts, FeatureReports, FeatureAIInvestigation,
		FeatureSIEM, FeaturePlaybooks, FeatureThreatIntel, FeatureYARA,
		FeatureMLDetection, FeatureThreatHunting, FeatureMultiTenant, FeatureCompliance,
		FeatureAPIAccess, FeatureXDR, FeatureDeception, FeatureForensics,
		FeatureSOAR, FeatureMDM,
	}
}

// Manager is the license manager. In this edition it holds no state that can
// expire, be revoked, or be exceeded.
type Manager struct {
	pool            *pgxpool.Pool
	aiExternalOptin bool
	current         *License
}

// NewManager returns a manager that always reports an unrestricted license.
func NewManager(pool *pgxpool.Pool) *Manager {
	return &Manager{pool: pool}
}

func ossLicense() *License {
	now := time.Now()
	return &License{
		ID:               "oss",
		OrganizationName: "Self-hosted",
		Plan:             PlanOSS,
		AgentLimit:       unlimited,
		UserLimit:        unlimited,
		Features:         AllFeatures(),
		ValidFrom:        now,
		// Deliberately far future rather than a zero value: the console and
		// several handlers format this field directly.
		ExpiresAt:     now.AddDate(100, 0, 0),
		IsExpired:     false,
		DaysRemaining: -1, // -1 は無期限を表すセンチネル
	}
}

// GetCurrentLicense returns the unrestricted open source license.
func (m *Manager) GetCurrentLicense(_ context.Context) (*License, error) {
	if m.current != nil {
		lic := *m.current
		return &lic, nil
	}
	lic := ossLicense()
	lic.AIExternalOptin = m.aiExternalOptin
	return lic, nil
}

// HasFeature always reports true. See the package comment.
func (m *Manager) HasFeature(_ string) bool { return true }

// HasAIExternalOptin reports whether external AI usage was opted into.
func (m *Manager) HasAIExternalOptin() bool { return m.aiExternalOptin }

// SetAIExternalOptin records the operator's choice.
func (m *Manager) SetAIExternalOptin(_ context.Context, optin bool) (*License, error) {
	m.aiExternalOptin = optin
	lic := ossLicense()
	lic.AIExternalOptin = optin
	return lic, nil
}

// ActivateLicense is a no-op: this edition needs no license key.
func (m *Manager) ActivateLicense(ctx context.Context, _ string) (*License, error) {
	return m.GetCurrentLicense(ctx)
}

// ResetLicense restores the default (unrestricted) license.
func (m *Manager) ResetLicense(ctx context.Context) (*License, error) {
	m.current = nil
	return m.GetCurrentLicense(ctx)
}

// UpdatePlan is a no-op: there are no plans in this edition.
func (m *Manager) UpdatePlan(_ context.Context, _ string, _ int, _ time.Time) error {
	return nil
}

// IsWithinLimits always reports true — there are no seat or agent limits.
func (m *Manager) IsWithinLimits(_ context.Context) (bool, string, error) {
	return true, "", nil
}

// GetUsage reports current counts with unlimited headroom.
func (m *Manager) GetUsage(ctx context.Context) (*UsageSummary, error) {
	s := &UsageSummary{
		AgentLimit:    unlimited,
		UserLimit:     unlimited,
		Plan:          PlanOSS,
		DaysRemaining: -1,
		CanAddAgents:  true,
		CanAddUsers:   true,
	}
	if m.pool == nil {
		return s, nil
	}
	// 実数だけは返す。上限が無いので割合は常に 0。
	//
	// 数えられなかったことと 0 台であることを同じ値で返さない。0 は
	// 「まだ1台も使っていない」と読めるので、読めなかった回だけコンソールに
	// 「0台」と出て、それが本当かどうかを誰も見分けられなくなる。
	if err := m.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM agents WHERE status != 'offline'`).Scan(&s.AgentsActive); err != nil {
		return nil, fmt.Errorf("license: エージェント数を数えられませんでした: %w", err)
	}
	if err := m.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM users WHERE is_active = true`).Scan(&s.UsersActive); err != nil {
		return nil, fmt.Errorf("license: ユーザー数を数えられませんでした: %w", err)
	}
	return s, nil
}

// SetCurrentLicenseForTest overrides the in-memory license. Test helper.
func (m *Manager) SetCurrentLicenseForTest(lic *License) { m.current = lic }
