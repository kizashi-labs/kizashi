package awsscan

import (
	"context"
	"time"
)

// Status は 1 項目の判定。
//
// Unknown を pass にも fail にも寄せないのがこのパッケージの方針。
// 権限不足や API エラーで読めなかったものを pass にすると「問題なし」に、
// fail にすると「大量の問題あり」に化ける。どちらも誤りなので分けて持つ。
type Status string

const (
	StatusPass    Status = "pass"
	StatusFail    Status = "fail"
	StatusUnknown Status = "unknown"
)

// Severity は不合格だったときの重大度。cspm_findings.severity と同じ語彙。
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

// Scope はチェックがアカウント全体を見るか、リージョンごとに見るか。
type Scope string

const (
	// ScopeAccount はどのリージョンから呼んでも同じ結果になるもの (IAM 等)。
	// 1 回だけ実行する。
	ScopeAccount Scope = "account"
	// ScopeRegion は有効化されているリージョンごとに実行するもの。
	ScopeRegion Scope = "region"
)

// Check は 1 つの検査項目の定義。
type Check struct {
	// ID は CIS の項番に寄せた安定識別子。cspm_findings.check_id になるため、
	// 一度公開したら変えない (変えると所見の同一性が切れて重複する)。
	ID          string
	Title       string
	Description string
	Severity    Severity
	Scope       Scope
	Service     string
	// Frameworks は cspm_findings.compliance_frameworks に入る。
	Frameworks []string
	// Remediation は運用者向けの是正手順。
	Remediation string
	// Run は判定本体。読めなかったときは StatusUnknown と理由を返す。
	Run func(ctx context.Context, c *Clients) []Result
}

// Result は 1 資源に対する 1 項目の判定結果。
type Result struct {
	CheckID string
	Status  Status
	// ResourceID は所見の同一性に使う。アカウント全体の項目なら
	// アカウント ID、資源単位ならバケット名やセキュリティグループ ID。
	ResourceID   string
	ResourceName string
	ResourceType string
	Region       string
	// Evidence は判定の根拠。「なぜそう判定したか」が後から追えるようにする。
	Evidence string
}

// ScanResult は 1 回のスキャン全体。
type ScanResult struct {
	AccountID  string
	StartedAt  time.Time
	FinishedAt time.Time
	Regions    []string
	Results    []Result
	// Errors は「検査できなかった」項目の記録。所見ではない。
	Errors []ScanError
}

// ScanError は検査そのものが実行できなかった記録。
type ScanError struct {
	CheckID string
	Region  string
	Message string
}

// Counts は重大度別の不合格件数。
func (r ScanResult) Counts(byID map[string]Check) map[Severity]int {
	out := map[Severity]int{}
	for _, res := range r.Results {
		if res.Status != StatusFail {
			continue
		}
		if c, ok := byID[res.CheckID]; ok {
			out[c.Severity]++
		}
	}
	return out
}
