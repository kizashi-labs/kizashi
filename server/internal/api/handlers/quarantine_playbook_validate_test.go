package handlers

import (
	"testing"
)

// ─────────────────────────────────────────────
// 頁送りの補完のテスト
//
// **ここには写しが3つ置いてありました** —— `clampPage` / `clampPerPage` /
// `quarantineOffset` の3つを、この検査ファイルの中で定義して試して
// いました。本物は `quarantine_handler.go` の中に直書きされていたので、
// **本物を壊しても、この検査は1本も落ちません。**
//
// 本物は `pagination.go` に切り出しました。以下はそちらを呼びます。
// 検疫の一覧は既定 20 / 上限 100 です。
// ─────────────────────────────────────────────

const (
	quarantineDefaultPerPage = 20
	quarantineMaxPerPage     = 100
)

func quarantinePerPage(perPage int) int {
	return clampPerPage(perPage, quarantineDefaultPerPage, quarantineMaxPerPage)
}

func TestClampPage(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{
			// 0 は 1 に補完
			name:     "page=0は1に補完",
			input:    0,
			expected: 1,
		},
		{
			// 負数は 1 に補完
			name:     "page=-5は1に補完",
			input:    -5,
			expected: 1,
		},
		{
			// ちょうど 1 はそのまま (境界値)
			name:     "page=1はそのまま（境界値）",
			input:    1,
			expected: 1,
		},
		{
			// 2 以上は変更なし
			name:     "page=2はそのまま",
			input:    2,
			expected: 2,
		},
		{
			// 大きな値もそのまま
			name:     "page=9999はそのまま",
			input:    9999,
			expected: 9999,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := clampPage(tc.input)
			if got != tc.expected {
				t.Errorf("clampPage(%d) = %d, want %d", tc.input, got, tc.expected)
			}
		})
	}
}

func TestClampPerPage(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{
			// 0 はデフォルト 20 に補完
			name:     "perPage=0はデフォルト20",
			input:    0,
			expected: 20,
		},
		{
			// 負数はデフォルト 20 に補完
			name:     "perPage=-1はデフォルト20",
			input:    -1,
			expected: 20,
		},
		{
			// 1 は有効 (境界値下限)
			name:     "perPage=1は有効（下限境界値）",
			input:    1,
			expected: 1,
		},
		{
			// 20 は有効
			name:     "perPage=20は有効",
			input:    20,
			expected: 20,
		},
		{
			// 100 は有効 (境界値上限)
			name:     "perPage=100は有効（上限境界値）",
			input:    100,
			expected: 100,
		},
		{
			// 101 は上限超えなのでデフォルト 20 に補完
			name:     "perPage=101は20に補完",
			input:    101,
			expected: 20,
		},
		{
			// 非常に大きな値はデフォルト 20 に補完
			name:     "perPage=99999は20に補完",
			input:    99999,
			expected: 20,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := quarantinePerPage(tc.input)
			if got != tc.expected {
				t.Errorf("clampPerPage(%d) = %d, want %d", tc.input, got, tc.expected)
			}
		})
	}
}

// ─────────────────────────────────────────────
// 検疫オフセット計算のテスト
//
// quarantine_handler.go の List() が使用するオフセット:
//   offset = (page - 1) * perPage
// ─────────────────────────────────────────────

func TestQuarantineOffset(t *testing.T) {
	tests := []struct {
		name     string
		page     int
		perPage  int
		expected int
	}{
		{
			// ページ 1: オフセット 0
			name:     "page=1はoffset=0",
			page:     1,
			perPage:  20,
			expected: 0,
		},
		{
			// ページ 2, perPage=20: オフセット 20
			name:     "page=2,perPage=20はoffset=20",
			page:     2,
			perPage:  20,
			expected: 20,
		},
		{
			// ページ 3, perPage=50: オフセット 100
			name:     "page=3,perPage=50はoffset=100",
			page:     3,
			perPage:  50,
			expected: 100,
		},
		{
			// ページ 1, perPage=100: オフセット 0
			name:     "page=1,perPage=100はoffset=0",
			page:     1,
			perPage:  100,
			expected: 0,
		},
		{
			// ページ 10, perPage=10: オフセット 90
			name:     "page=10,perPage=10はoffset=90",
			page:     10,
			perPage:  10,
			expected: 90,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := pageOffset(tc.page, tc.perPage)
			if got != tc.expected {
				t.Errorf("pageOffset(%d, %d) = %d, want %d", tc.page, tc.perPage, got, tc.expected)
			}
		})
	}
}

// ─────────────────────────────────────────────
// プレイブックアクション件数バリデーションのテスト
//
// playbooks_handler.go の Create() 内には
//   if len(req.Actions) == 0 { エラー }
// という純粋なロジックがある。同等の関数でテストする。
// ─────────────────────────────────────────────

func TestValidatePlaybookActionCount(t *testing.T) {
	tests := []struct {
		name    string
		count   int
		wantMsg string
	}{
		{
			// 0 件: エラー
			name:    "アクション0件はエラー",
			count:   0,
			wantMsg: "1つ以上のアクションが必要です",
		},
		{
			// 1 件: 有効 (境界値)
			name:    "アクション1件は有効",
			count:   1,
			wantMsg: "",
		},
		{
			// 5 件: 有効
			name:    "アクション5件は有効",
			count:   5,
			wantMsg: "",
		},
		{
			// 100 件: 有効 (上限なし)
			name:    "アクション100件は有効（上限なし）",
			count:   100,
			wantMsg: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := validatePlaybookActionCount(tc.count)
			if got != tc.wantMsg {
				t.Errorf("validatePlaybookActionCount(%d) = %q, want %q", tc.count, got, tc.wantMsg)
			}
		})
	}
}

// ─────────────────────────────────────────────
// IOC severity デフォルト補完のテスト
//
// ioc_handler.go の Create() 内には
//   if req.Severity < 1 || req.Severity > 10 { req.Severity = 7 }
// というデフォルト補完ロジックがある。
// ─────────────────────────────────────────────

func TestClampIOCSeverity(t *testing.T) {
	tests := []struct {
		name     string
		input    int
		expected int
	}{
		{
			// 0 はデフォルト 7 に補完
			name:     "severity=0はデフォルト7",
			input:    0,
			expected: 7,
		},
		{
			// 負数はデフォルト 7 に補完
			name:     "severity=-5はデフォルト7",
			input:    -5,
			expected: 7,
		},
		{
			// 1 は有効 (境界値下限)
			name:     "severity=1は有効（下限境界値）",
			input:    1,
			expected: 1,
		},
		{
			// 7 は有効 (デフォルト値と同じ値だが明示指定なのでそのまま)
			name:     "severity=7はそのまま",
			input:    7,
			expected: 7,
		},
		{
			// 10 は有効 (境界値上限)
			name:     "severity=10は有効（上限境界値）",
			input:    10,
			expected: 10,
		},
		{
			// 11 は上限超えでデフォルト 7 に補完
			name:     "severity=11はデフォルト7",
			input:    11,
			expected: 7,
		},
		{
			// 非常に大きな値はデフォルト 7 に補完
			name:     "severity=999はデフォルト7",
			input:    999,
			expected: 7,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := clampIOCSeverity(tc.input)
			if got != tc.expected {
				t.Errorf("clampIOCSeverity(%d) = %d, want %d", tc.input, got, tc.expected)
			}
		})
	}
}

// ─────────────────────────────────────────────
// FIM exclude_patterns フィールドのバリデーションテスト
//
// validateFIMRequest は ExcludePatterns に対して制限を設けない。
// nil、空スライス、パターンありのいずれも有効。
// ─────────────────────────────────────────────

func TestValidateFIMRequestExcludePatterns(t *testing.T) {
	tests := []struct {
		name            string
		excludePatterns []string
		wantMsg         string
	}{
		{
			// nil スライスは有効
			name:            "excludePatternsがnilでも有効",
			excludePatterns: nil,
			wantMsg:         "",
		},
		{
			// 空スライスは有効
			name:            "excludePatternsが空スライスでも有効",
			excludePatterns: []string{},
			wantMsg:         "",
		},
		{
			// 単一パターン付き: 有効
			name:            "excludePatterns1件は有効",
			excludePatterns: []string{"*.tmp"},
			wantMsg:         "",
		},
		{
			// 複数パターン: 有効
			name:            "excludePatterns複数件は有効",
			excludePatterns: []string{"*.tmp", "*.log", "/proc/*"},
			wantMsg:         "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := fimRuleRequest{
				Name:            "WatchEtc",
				Path:            "/etc",
				Severity:        "high",
				ExcludePatterns: tc.excludePatterns,
			}
			got := validateFIMRequest(&req)
			if got != tc.wantMsg {
				t.Errorf("validateFIMRequest() = %q, want %q", got, tc.wantMsg)
			}
		})
	}
}
