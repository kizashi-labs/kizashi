package cspm

import (
	"context"
	"fmt"
	"sync"
	"time"
)

// CloudProvider represents a cloud platform
type CloudProvider string

const (
	ProviderAWS   CloudProvider = "aws"
	ProviderGCP   CloudProvider = "gcp"
	ProviderAzure CloudProvider = "azure"
)

// Severity of a CSPM finding
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// CheckStatus indicates pass/fail/skip
type CheckStatus string

const (
	StatusPass CheckStatus = "pass"
	StatusFail CheckStatus = "fail"
	StatusSkip CheckStatus = "skip"
)

// CSPMCheck defines a cloud security check
type CSPMCheck struct {
	ID            string        `json:"id"`
	Title         string        `json:"title"`
	Description   string        `json:"description"`
	Provider      CloudProvider `json:"provider"`
	Service       string        `json:"service"` // S3, IAM, EC2, etc.
	Severity      Severity      `json:"severity"`
	ATTACKTactics []string      `json:"attack_tactics"`
	Remediation   string        `json:"remediation"`
	// RunFunc returns (status, evidence, error)
	RunFunc func(ctx context.Context, cfg ProviderConfig) (CheckStatus, string, error) `json:"-"`
}

// ProviderConfig holds cloud provider credentials/config
type ProviderConfig struct {
	Provider  CloudProvider          `json:"provider"`
	Region    string                 `json:"region"`
	AccountID string                 `json:"account_id"`
	Settings  map[string]interface{} `json:"settings"` // simulated config
}

// Finding is the result of a CSPM check
type Finding struct {
	CheckID     string        `json:"check_id"`
	Title       string        `json:"title"`
	Provider    CloudProvider `json:"provider"`
	Service     string        `json:"service"`
	Severity    Severity      `json:"severity"`
	Status      CheckStatus   `json:"status"`
	Evidence    string        `json:"evidence,omitempty"`
	Remediation string        `json:"remediation"`
	CheckedAt   time.Time     `json:"checked_at"`
}

// ScanResult is the full result of a CSPM scan
type ScanResult struct {
	ScanID      string        `json:"scan_id"`
	Provider    CloudProvider `json:"provider"`
	AccountID   string        `json:"account_id"`
	StartedAt   time.Time     `json:"started_at"`
	CompletedAt time.Time     `json:"completed_at"`
	Findings    []Finding     `json:"findings"`
	Summary     ScanSummary   `json:"summary"`
}

// ScanSummary aggregates findings by severity
type ScanSummary struct {
	Total    int `json:"total"`
	Critical int `json:"critical"`
	High     int `json:"high"`
	Medium   int `json:"medium"`
	Low      int `json:"low"`
	Passed   int `json:"passed"`
	Failed   int `json:"failed"`
	Skipped  int `json:"skipped"`
	Score    int `json:"score"` // 0-100
}

// Checker runs CSPM checks against simulated cloud configurations
type Checker struct {
	mu     sync.RWMutex
	checks []CSPMCheck
	last   map[string]*ScanResult // provider -> last scan result
}

// NewChecker creates a new CSPM Checker
func NewChecker() *Checker {
	c := &Checker{
		last: make(map[string]*ScanResult),
	}
	c.checks = builtinChecks()
	return c
}

// Scan runs all applicable checks for a provider config
func (c *Checker) Scan(ctx context.Context, cfg ProviderConfig) (*ScanResult, error) {
	c.mu.RLock()
	checks := make([]CSPMCheck, len(c.checks))
	copy(checks, c.checks)
	c.mu.RUnlock()

	result := &ScanResult{
		ScanID:    fmt.Sprintf("scan-%s-%d", cfg.Provider, time.Now().UnixNano()),
		Provider:  cfg.Provider,
		AccountID: cfg.AccountID,
		StartedAt: time.Now(),
	}

	for _, check := range checks {
		if check.Provider != cfg.Provider {
			continue
		}

		status := StatusSkip
		evidence := ""
		var runErr error

		if check.RunFunc != nil {
			status, evidence, runErr = check.RunFunc(ctx, cfg)
			if runErr != nil {
				status = StatusSkip
				evidence = runErr.Error()
			}
		}

		result.Findings = append(result.Findings, Finding{
			CheckID:     check.ID,
			Title:       check.Title,
			Provider:    check.Provider,
			Service:     check.Service,
			Severity:    check.Severity,
			Status:      status,
			Evidence:    evidence,
			Remediation: check.Remediation,
			CheckedAt:   time.Now(),
		})
	}

	result.CompletedAt = time.Now()
	result.Summary = computeSummary(result.Findings)

	c.mu.Lock()
	c.last[string(cfg.Provider)] = result
	c.mu.Unlock()

	return result, nil
}

// GetLastScan returns the last scan result for a provider
func (c *Checker) GetLastScan(provider string) *ScanResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.last[provider]
}

// GetAllLastScans returns last results for all providers
func (c *Checker) GetAllLastScans() []*ScanResult {
	c.mu.RLock()
	defer c.mu.RUnlock()
	var results []*ScanResult
	for _, r := range c.last {
		results = append(results, r)
	}
	return results
}

func computeSummary(findings []Finding) ScanSummary {
	s := ScanSummary{Total: len(findings)}
	for _, f := range findings {
		switch f.Status {
		case StatusPass:
			s.Passed++
		case StatusFail:
			s.Failed++
			switch f.Severity {
			case SeverityCritical:
				s.Critical++
			case SeverityHigh:
				s.High++
			case SeverityMedium:
				s.Medium++
			case SeverityLow:
				s.Low++
			}
		case StatusSkip:
			s.Skipped++
		}
	}
	if s.Total > 0 {
		s.Score = int(float64(s.Passed) / float64(s.Total) * 100)
	}
	return s
}

// builtinChecks returns a set of built-in CSPM checks
func builtinChecks() []CSPMCheck {
	return []CSPMCheck{
		// AWS Checks
		{
			ID: "aws-s3-public-access", Title: "S3パブリックアクセス制限",
			Description: "S3バケットのパブリックアクセスブロックが有効であることを確認",
			Provider:    ProviderAWS, Service: "S3", Severity: SeverityCritical,
			ATTACKTactics: []string{"Exfiltration"},
			Remediation:   "S3バケットのBlock Public Access設定を有効にしてください",
			RunFunc: func(ctx context.Context, cfg ProviderConfig) (CheckStatus, string, error) {
				if v, ok := cfg.Settings["s3_block_public_access"].(bool); ok && v {
					return StatusPass, "パブリックアクセスブロックが有効です", nil
				}
				return StatusFail, "S3バケットにパブリックアクセスが許可されています", nil
			},
		},
		{
			ID: "aws-iam-mfa-root", Title: "ルートアカウントMFA",
			Description: "AWSルートアカウントでMFAが有効であることを確認",
			Provider:    ProviderAWS, Service: "IAM", Severity: SeverityCritical,
			ATTACKTactics: []string{"Credential Access", "Privilege Escalation"},
			Remediation:   "ルートアカウントのMFAを有効にしてください",
			RunFunc: func(ctx context.Context, cfg ProviderConfig) (CheckStatus, string, error) {
				if v, ok := cfg.Settings["root_mfa_enabled"].(bool); ok && v {
					return StatusPass, "ルートアカウントMFAが有効です", nil
				}
				return StatusFail, "ルートアカウントMFAが無効です", nil
			},
		},
		{
			ID: "aws-cloudtrail-enabled", Title: "CloudTrailログ有効化",
			Description: "すべてのリージョンでCloudTrailが有効であることを確認",
			Provider:    ProviderAWS, Service: "CloudTrail", Severity: SeverityHigh,
			ATTACKTactics: []string{"Defense Evasion"},
			Remediation:   "全リージョンのCloudTrailを有効にしてください",
			RunFunc: func(ctx context.Context, cfg ProviderConfig) (CheckStatus, string, error) {
				if v, ok := cfg.Settings["cloudtrail_enabled"].(bool); ok && v {
					return StatusPass, "CloudTrailが有効です", nil
				}
				return StatusFail, "CloudTrailが無効です。監査ログが記録されていません", nil
			},
		},
		{
			ID: "aws-sg-unrestricted-ssh", Title: "SSHポート制限",
			Description: "セキュリティグループでSSH(22)が全IPに開放されていないことを確認",
			Provider:    ProviderAWS, Service: "EC2", Severity: SeverityHigh,
			ATTACKTactics: []string{"Initial Access"},
			Remediation:   "セキュリティグループのSSHアクセスを特定のIPに制限してください",
			RunFunc: func(ctx context.Context, cfg ProviderConfig) (CheckStatus, string, error) {
				if v, ok := cfg.Settings["ssh_unrestricted"].(bool); ok && v {
					return StatusFail, "SSH(22)が0.0.0.0/0に開放されています", nil
				}
				return StatusPass, "SSHアクセスは制限されています", nil
			},
		},
		{
			ID: "aws-ebs-encryption", Title: "EBSボリューム暗号化",
			Description: "すべてのEBSボリュームが暗号化されていることを確認",
			Provider:    ProviderAWS, Service: "EBS", Severity: SeverityMedium,
			ATTACKTactics: []string{"Collection"},
			Remediation:   "EBSボリュームのデフォルト暗号化を有効にしてください",
			RunFunc: func(ctx context.Context, cfg ProviderConfig) (CheckStatus, string, error) {
				if v, ok := cfg.Settings["ebs_encryption"].(bool); ok && v {
					return StatusPass, "EBS暗号化が有効です", nil
				}
				return StatusFail, "暗号化されていないEBSボリュームが存在します", nil
			},
		},
		// GCP Checks
		{
			ID: "gcp-iam-service-account-key", Title: "サービスアカウントキー管理",
			Description: "サービスアカウントに外部キーが作成されていないことを確認",
			Provider:    ProviderGCP, Service: "IAM", Severity: SeverityHigh,
			ATTACKTactics: []string{"Credential Access"},
			Remediation:   "サービスアカウントの外部キーを削除し、Workload Identityを使用してください",
			RunFunc: func(ctx context.Context, cfg ProviderConfig) (CheckStatus, string, error) {
				if v, ok := cfg.Settings["sa_external_keys"].(bool); ok && v {
					return StatusFail, "サービスアカウントに外部キーが存在します", nil
				}
				return StatusPass, "外部キーは使用されていません", nil
			},
		},
		{
			ID: "gcp-storage-public-bucket", Title: "GCSバケットパブリックアクセス",
			Description: "Cloud Storageバケットが公開されていないことを確認",
			Provider:    ProviderGCP, Service: "Storage", Severity: SeverityCritical,
			ATTACKTactics: []string{"Exfiltration"},
			Remediation:   "バケットのallUsersおよびallAuthenticatedUsersへのアクセス許可を削除してください",
			RunFunc: func(ctx context.Context, cfg ProviderConfig) (CheckStatus, string, error) {
				if v, ok := cfg.Settings["gcs_public"].(bool); ok && v {
					return StatusFail, "GCSバケットが公開されています", nil
				}
				return StatusPass, "バケットは非公開です", nil
			},
		},
		// Azure Checks
		{
			ID: "azure-storage-https", Title: "Azure StorageのHTTPS強制",
			Description: "Azure StorageアカウントがHTTPSのみを許可することを確認",
			Provider:    ProviderAzure, Service: "Storage", Severity: SeverityHigh,
			ATTACKTactics: []string{"Collection", "Exfiltration"},
			Remediation:   "ストレージアカウントの「安全な転送が必要」を有効にしてください",
			RunFunc: func(ctx context.Context, cfg ProviderConfig) (CheckStatus, string, error) {
				if v, ok := cfg.Settings["storage_https_only"].(bool); ok && v {
					return StatusPass, "HTTPSのみが許可されています", nil
				}
				return StatusFail, "HTTPトランスポートが許可されています", nil
			},
		},
		{
			ID: "azure-defender-enabled", Title: "Microsoft Defender for Cloud有効化",
			Description: "Microsoft Defender for Cloudが有効であることを確認",
			Provider:    ProviderAzure, Service: "Security Center", Severity: SeverityHigh,
			ATTACKTactics: []string{"Defense Evasion"},
			Remediation:   "Microsoft Defender for Cloudの標準レベルを有効にしてください",
			RunFunc: func(ctx context.Context, cfg ProviderConfig) (CheckStatus, string, error) {
				if v, ok := cfg.Settings["defender_enabled"].(bool); ok && v {
					return StatusPass, "Microsoft Defenderが有効です", nil
				}
				return StatusFail, "Microsoft Defenderが無効です", nil
			},
		},
		{
			ID: "azure-mfa-all-users", Title: "全ユーザーMFA",
			Description: "Azure ADの全ユーザーにMFAが強制されていることを確認",
			Provider:    ProviderAzure, Service: "Azure AD", Severity: SeverityCritical,
			ATTACKTactics: []string{"Credential Access"},
			Remediation:   "条件付きアクセスポリシーでMFAを全ユーザーに要求してください",
			RunFunc: func(ctx context.Context, cfg ProviderConfig) (CheckStatus, string, error) {
				if v, ok := cfg.Settings["aad_mfa_enforced"].(bool); ok && v {
					return StatusPass, "全ユーザーにMFAが強制されています", nil
				}
				return StatusFail, "MFAが一部ユーザーに適用されていません", nil
			},
		},
	}
}
