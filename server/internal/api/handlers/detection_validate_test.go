package handlers

import (
	"testing"
)

// ─────────────────────────────────────────────
// validateYARARequest のテスト
// ─────────────────────────────────────────────

func TestValidateYARARequest(t *testing.T) {
	tests := []struct {
		name         string
		req          yaraRequest
		wantMsg      string
		wantSeverity string // 自動補完後の severity を確認
	}{
		{
			// 有効なリクエスト
			name: "有効なリクエスト",
			req: yaraRequest{
				Name:     "TestRule",
				Content:  `rule Test { condition: true }`,
				Severity: "high",
			},
			wantMsg:      "",
			wantSeverity: "high",
		},
		{
			// severity が空の場合は "medium" にデフォルト補完
			name: "severityが空の場合デフォルトはmedium",
			req: yaraRequest{
				Name:    "TestRule",
				Content: `rule Test { condition: true }`,
			},
			wantMsg:      "",
			wantSeverity: "medium",
		},
		{
			// name が空
			name: "nameが空",
			req: yaraRequest{
				Name:     "",
				Content:  `rule Test { condition: true }`,
				Severity: "low",
			},
			wantMsg: "name は必須です",
		},
		{
			// name がスペースのみ
			name: "nameがスペースのみ",
			req: yaraRequest{
				Name:     "   ",
				Content:  `rule Test { condition: true }`,
				Severity: "medium",
			},
			wantMsg: "name は必須です",
		},
		{
			// content が空
			name: "contentが空",
			req: yaraRequest{
				Name:     "TestRule",
				Content:  "",
				Severity: "medium",
			},
			wantMsg: "content は必須です",
		},
		{
			// content がスペースのみ
			name: "contentがスペースのみ",
			req: yaraRequest{
				Name:     "TestRule",
				Content:  "   ",
				Severity: "high",
			},
			wantMsg: "content は必須です",
		},
		{
			// 無効な severity
			name: "無効なseverity",
			req: yaraRequest{
				Name:     "TestRule",
				Content:  `rule Test { condition: true }`,
				Severity: "unknown",
			},
			wantMsg: "severity は low/medium/high/critical のいずれかを指定してください",
		},
		{
			// 有効な severity: critical
			name: "severity=critical",
			req: yaraRequest{
				Name:     "CriticalRule",
				Content:  `rule X { condition: true }`,
				Severity: "critical",
			},
			wantMsg:      "",
			wantSeverity: "critical",
		},
		{
			// 有効な severity: low
			name: "severity=low",
			req: yaraRequest{
				Name:     "LowRule",
				Content:  `rule X { condition: true }`,
				Severity: "low",
			},
			wantMsg:      "",
			wantSeverity: "low",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req // コピーして副作用を分離
			got := validateYARARequest(&req)
			if got != tc.wantMsg {
				t.Errorf("validateYARARequest() = %q, want %q", got, tc.wantMsg)
			}
			// severity デフォルト補完の確認
			if tc.wantMsg == "" && tc.wantSeverity != "" {
				if req.Severity != tc.wantSeverity {
					t.Errorf("severity after validation = %q, want %q", req.Severity, tc.wantSeverity)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────
// validateFIMRequest のテスト
// ─────────────────────────────────────────────

func TestValidateFIMRequest(t *testing.T) {
	tests := []struct {
		name         string
		req          fimRuleRequest
		wantMsg      string
		wantSeverity string
	}{
		{
			// 有効なリクエスト
			name: "有効なリクエスト",
			req: fimRuleRequest{
				Name:     "WatchEtc",
				Path:     "/etc/passwd",
				Severity: "high",
			},
			wantMsg:      "",
			wantSeverity: "high",
		},
		{
			// severity が空の場合は "high" にデフォルト補完
			name: "severityが空の場合デフォルトはhigh",
			req: fimRuleRequest{
				Name: "WatchSys",
				Path: "/sys",
			},
			wantMsg:      "",
			wantSeverity: "high",
		},
		{
			// name が空
			name: "nameが空",
			req: fimRuleRequest{
				Name:     "",
				Path:     "/etc",
				Severity: "medium",
			},
			wantMsg: "name は必須です",
		},
		{
			// name がスペースのみ
			name: "nameがスペースのみ",
			req: fimRuleRequest{
				Name:     "\t  ",
				Path:     "/etc",
				Severity: "low",
			},
			wantMsg: "name は必須です",
		},
		{
			// path が空
			name: "pathが空",
			req: fimRuleRequest{
				Name:     "WatchSomething",
				Path:     "",
				Severity: "high",
			},
			wantMsg: "path は必須です",
		},
		{
			// path がスペースのみ
			name: "pathがスペースのみ",
			req: fimRuleRequest{
				Name:     "WatchSomething",
				Path:     "   ",
				Severity: "critical",
			},
			wantMsg: "path は必須です",
		},
		{
			// 無効な severity
			name: "無効なseverity",
			req: fimRuleRequest{
				Name:     "WatchEtc",
				Path:     "/etc",
				Severity: "extreme",
			},
			wantMsg: "severity は low/medium/high/critical のいずれかを指定してください",
		},
		{
			// severity=critical が有効
			name: "severity=critical",
			req: fimRuleRequest{
				Name:     "WatchBoot",
				Path:     "/boot",
				Severity: "critical",
			},
			wantMsg:      "",
			wantSeverity: "critical",
		},
		{
			// severity=low が有効
			name: "severity=low",
			req: fimRuleRequest{
				Name:     "WatchTmp",
				Path:     "/tmp",
				Severity: "low",
			},
			wantMsg:      "",
			wantSeverity: "low",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			got := validateFIMRequest(&req)
			if got != tc.wantMsg {
				t.Errorf("validateFIMRequest() = %q, want %q", got, tc.wantMsg)
			}
			if tc.wantMsg == "" && tc.wantSeverity != "" {
				if req.Severity != tc.wantSeverity {
					t.Errorf("severity after validation = %q, want %q", req.Severity, tc.wantSeverity)
				}
			}
		})
	}
}
