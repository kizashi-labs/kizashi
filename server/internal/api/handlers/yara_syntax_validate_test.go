package handlers

import (
	"strings"
	"testing"
)

// ─────────────────────────────────────────────
// validateYARARequest — 拡張フィールドテスト
// (name / content / severity のみでなく、tags, description,
// enabled などのオプションフィールドを含む組み合わせ)
// ─────────────────────────────────────────────

func TestValidateYARARequestExtended(t *testing.T) {
	tests := []struct {
		name         string
		req          yaraRequest
		wantMsg      string
		wantSeverity string
	}{
		{
			// tags を指定しても有効
			name: "tagsを指定しても有効",
			req: yaraRequest{
				Name:     "TaggedRule",
				Content:  `rule Tagged { condition: true }`,
				Tags:     []string{"malware", "ransomware"},
				Severity: "high",
			},
			wantMsg:      "",
			wantSeverity: "high",
		},
		{
			// description を指定しても有効
			name: "descriptionを指定しても有効",
			req: yaraRequest{
				Name:        "DescribedRule",
				Content:     `rule Described { condition: true }`,
				Description: "マルウェア検出ルール",
				Severity:    "medium",
			},
			wantMsg:      "",
			wantSeverity: "medium",
		},
		{
			// enabled=true を指定しても有効
			name: "enabledフラグあり有効",
			req: yaraRequest{
				Name:     "EnabledRule",
				Content:  `rule Enabled { condition: true }`,
				Enabled:  true,
				Severity: "low",
			},
			wantMsg:      "",
			wantSeverity: "low",
		},
		{
			// enabled=false, tags 空スライス: 有効
			name: "enabledfalseとtagsなし有効",
			req: yaraRequest{
				Name:     "DisabledRule",
				Content:  `rule Disabled { condition: false }`,
				Tags:     []string{},
				Enabled:  false,
				Severity: "critical",
			},
			wantMsg:      "",
			wantSeverity: "critical",
		},
		{
			// name が空白文字 (タブ + スペース) のみ → エラー
			name: "nameがタブとスペースのみ",
			req: yaraRequest{
				Name:     "\t  \t",
				Content:  `rule X { condition: true }`,
				Severity: "medium",
			},
			wantMsg: "name は必須です",
		},
		{
			// content が改行のみ → トリム後に空文字列 → エラー
			name: "contentが改行のみ",
			req: yaraRequest{
				Name:     "SomeRule",
				Content:  "\n\n  \n",
				Severity: "high",
			},
			wantMsg: "content は必須です",
		},
		{
			// severity の大文字は無効 (大文字小文字を区別する)
			name: "severityの大文字Highは無効",
			req: yaraRequest{
				Name:     "TestRule",
				Content:  `rule Test { condition: true }`,
				Severity: "High",
			},
			wantMsg: "severity は low/medium/high/critical のいずれかを指定してください",
		},
		{
			// severity の大文字 CRITICAL は無効
			name: "severityのCRITICALは無効",
			req: yaraRequest{
				Name:     "TestRule",
				Content:  `rule Test { condition: true }`,
				Severity: "CRITICAL",
			},
			wantMsg: "severity は low/medium/high/critical のいずれかを指定してください",
		},
		{
			// severity が空のとき、tags が多くても "medium" にデフォルト補完
			name: "severityが空でtags多数でもmediumに補完",
			req: yaraRequest{
				Name:    "MultiTagRule",
				Content: `rule Multi { condition: any of them }`,
				Tags:    []string{"apt", "lateral-movement", "persistence"},
				// Severity は空
			},
			wantMsg:      "",
			wantSeverity: "medium",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			got := validateYARARequest(&req)
			if got != tc.wantMsg {
				t.Errorf("validateYARARequest() = %q, want %q", got, tc.wantMsg)
			}
			if tc.wantMsg == "" && tc.wantSeverity != "" {
				if req.Severity != tc.wantSeverity {
					t.Errorf("severity after validation = %q, want %q", req.Severity, tc.wantSeverity)
				}
			}
		})
	}
}

func TestValidateYARARequestContentPatterns(t *testing.T) {
	validContents := []struct {
		name    string
		content string
	}{
		{
			// 最小限のルール: condition ブロックのみ
			name:    "最小限のruleブロック",
			content: `rule Minimal { condition: true }`,
		},
		{
			// strings セクションと condition を持つ典型的なルール
			name:    "stringsと条件を含むルール",
			content: "rule WithStrings {\n  strings:\n    $a = \"malware\"\n  condition:\n    $a\n}",
		},
		{
			// meta セクションつきルール
			name:    "metaセクションつきルール",
			content: "rule WithMeta {\n  meta:\n    author = \"test\"\n  condition: true\n}",
		},
		{
			// 複数ルールを含む content
			name:    "複数ルールを含むcontent",
			content: "rule RuleA { condition: true }\nrule RuleB { condition: false }",
		},
		{
			// 長い content (100 文字超): content バリデーションは長さを制限しない
			name:    "長いcontent",
			content: "rule LongRule { condition: " + strings.Repeat("true ", 20) + "}",
		},
	}

	for _, tc := range validContents {
		t.Run(tc.name, func(t *testing.T) {
			req := yaraRequest{
				Name:     "ValidRule",
				Content:  tc.content,
				Severity: "medium",
			}
			got := validateYARARequest(&req)
			if got != "" {
				t.Errorf("validateYARARequest(%q) = %q, want empty string", tc.name, got)
			}
		})
	}
}

// ─────────────────────────────────────────────
// yaraRequest severity 全値テスト
// ─────────────────────────────────────────────

func TestValidateYARARequestAllValidSeverities(t *testing.T) {
	// 有効な severity 値を網羅する
	validSeverities := []string{"low", "medium", "high", "critical"}

	for _, sev := range validSeverities {
		sev := sev // ループ変数のキャプチャ
		t.Run("severity="+sev, func(t *testing.T) {
			req := yaraRequest{
				Name:     "SeverityTest",
				Content:  `rule Test { condition: true }`,
				Severity: sev,
			}
			got := validateYARARequest(&req)
			if got != "" {
				t.Errorf("validateYARARequest() with severity=%q = %q, want empty string", sev, got)
			}
			if req.Severity != sev {
				t.Errorf("severity after validation = %q, want %q", req.Severity, sev)
			}
		})
	}
}

// ─────────────────────────────────────────────
// yaraRequest フィールドデフォルト補完の不変条件テスト
//
// severity 以外のフィールド (name, content, tags, description, enabled) は
// validateYARARequest によって変更されないことを確認する。
// ─────────────────────────────────────────────

func TestValidateYARARequestDoesNotMutateNonSeverityFields(t *testing.T) {
	tests := []struct {
		name        string
		req         yaraRequest
		wantName    string
		wantContent string
		wantDesc    string
		wantEnabled bool
		wantTags    []string
	}{
		{
			// すべてのフィールドが初期値のまま保持される
			name: "フィールドが変更されない_すべて指定あり",
			req: yaraRequest{
				Name:        "Immutable",
				Content:     `rule Keep { condition: true }`,
				Description: "変更されない説明文",
				Tags:        []string{"apt29", "lateral-movement"},
				Enabled:     true,
				Severity:    "high",
			},
			wantName:    "Immutable",
			wantContent: `rule Keep { condition: true }`,
			wantDesc:    "変更されない説明文",
			wantEnabled: true,
			wantTags:    []string{"apt29", "lateral-movement"},
		},
		{
			// severity が空でも他フィールドは変更されない
			name: "severityが空でも他フィールドは変更されない",
			req: yaraRequest{
				Name:        "AutoSeverity",
				Content:     `rule Auto { condition: false }`,
				Description: "自動補完テスト",
				Tags:        []string{"test"},
				Enabled:     false,
				// Severity は空 → "medium" に補完
			},
			wantName:    "AutoSeverity",
			wantContent: `rule Auto { condition: false }`,
			wantDesc:    "自動補完テスト",
			wantEnabled: false,
			wantTags:    []string{"test"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			_ = validateYARARequest(&req)

			if req.Name != tc.wantName {
				t.Errorf("Name = %q, want %q", req.Name, tc.wantName)
			}
			if req.Content != tc.wantContent {
				t.Errorf("Content = %q, want %q", req.Content, tc.wantContent)
			}
			if req.Description != tc.wantDesc {
				t.Errorf("Description = %q, want %q", req.Description, tc.wantDesc)
			}
			if req.Enabled != tc.wantEnabled {
				t.Errorf("Enabled = %v, want %v", req.Enabled, tc.wantEnabled)
			}
			if len(req.Tags) != len(tc.wantTags) {
				t.Errorf("Tags length = %d, want %d", len(req.Tags), len(tc.wantTags))
			} else {
				for i, tag := range req.Tags {
					if tag != tc.wantTags[i] {
						t.Errorf("Tags[%d] = %q, want %q", i, tag, tc.wantTags[i])
					}
				}
			}
		})
	}
}
