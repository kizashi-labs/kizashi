package handlers

import (
	"errors"
	"strings"
	"testing"
)

// ─────────────────────────────────────────────
// dbErrMsg のテスト
// ─────────────────────────────────────────────

func TestDbErrMsg(t *testing.T) {
	// エラーあり: 常に固定の日本語メッセージを返す
	t.Run("エラーありは固定メッセージを返す", func(t *testing.T) {
		err := errors.New("pq: syntax error at position 10")
		got := dbErrMsg(err)
		want := "データベース操作に失敗しました"
		if got != want {
			t.Errorf("dbErrMsg(err) = %q, want %q", got, want)
		}
	})

	t.Run("nilエラーも固定メッセージを返す", func(t *testing.T) {
		got := dbErrMsg(nil)
		want := "データベース操作に失敗しました"
		if got != want {
			t.Errorf("dbErrMsg(nil) = %q, want %q", got, want)
		}
	})

	t.Run("元のエラー内容をクライアントに漏洩しない", func(t *testing.T) {
		sensitiveErr := errors.New("SQLSTATE 23505: duplicate key violates unique constraint \"users_email_key\"")
		got := dbErrMsg(sensitiveErr)
		// SQL内部情報が含まれないこと
		if strings.Contains(got, "SQLSTATE") || strings.Contains(got, "users_email_key") {
			t.Errorf("SQL内部情報がクライアントに漏洩しています: %q", got)
		}
	})

	t.Run("どんなエラーでも同じメッセージを返す", func(t *testing.T) {
		errs := []error{
			errors.New("connection refused"),
			errors.New("timeout"),
			errors.New("deadlock detected"),
			errors.New("relation \"nonexistent_table\" does not exist"),
		}
		want := "データベース操作に失敗しました"
		for _, err := range errs {
			got := dbErrMsg(err)
			if got != want {
				t.Errorf("dbErrMsg(%v) = %q, want %q", err, got, want)
			}
		}
	})
}

// ─────────────────────────────────────────────
// validateFilename のテスト (BackupHandler)
// ─────────────────────────────────────────────

func TestValidateFilename(t *testing.T) {
	h := &BackupHandler{backupDir: "/tmp/backups"}

	tests := []struct {
		name     string
		filename string
		wantErr  bool
	}{
		{
			// 有効なファイル名
			name:     "有効なファイル名",
			filename: "backup_20240101_120000.sql",
			wantErr:  false,
		},
		{
			// 有効: アンダースコアとドットのみ
			name:     "シンプルなファイル名",
			filename: "backup.sql",
			wantErr:  false,
		},
		{
			// 空文字列: 無効
			name:     "空文字列は無効",
			filename: "",
			wantErr:  true,
		},
		{
			// スラッシュを含む: パストラバーサル
			name:     "スラッシュを含む",
			filename: "../../etc/passwd",
			wantErr:  true,
		},
		{
			// バックスラッシュを含む
			name:     "バックスラッシュを含む",
			filename: "backup\\evil.sql",
			wantErr:  true,
		},
		{
			// ".." を含む
			name:     "ドットドットを含む",
			filename: "backup..sql",
			wantErr:  true,
		},
		{
			// サブディレクトリ参照
			name:     "サブディレクトリ参照",
			filename: "subdir/backup.sql",
			wantErr:  true,
		},
		{
			// "../" を含むパストラバーサル
			name:     "パストラバーサル攻撃パターン",
			filename: "../../../root/.ssh/authorized_keys",
			wantErr:  true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := h.validateFilename(tc.filename)
			if tc.wantErr && err == nil {
				t.Errorf("validateFilename(%q): エラーが期待されましたが nil でした", tc.filename)
			}
			if !tc.wantErr && err != nil {
				t.Errorf("validateFilename(%q): 予期しないエラー: %v", tc.filename, err)
			}
		})
	}
}

// ─────────────────────────────────────────────
// sanitizeLine のテスト (reports_pdf.go)
// ─────────────────────────────────────────────

func TestSanitizeLine(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			// 通常のASCII文字はそのまま
			name:  "通常のASCII文字",
			input: "Hello, World!",
			want:  "Hello, World!",
		},
		{
			// タブは2スペースに変換
			name:  "タブを2スペースに変換",
			input: "Key\tValue",
			want:  "Key  Value",
		},
		{
			// 日本語などの非ASCII文字は除去
			name:  "日本語文字は除去される",
			input: "Status: 正常",
			want:  "Status: ",
		},
		{
			// 制御文字（改行、NUL）は除去
			name:  "改行と制御文字は除去",
			input: "line1\nline2\x00\x01",
			want:  "line1line2",
		},
		{
			// 空文字列は空のまま
			name:  "空文字列",
			input: "",
			want:  "",
		},
		{
			// 100文字超は切り詰め (先頭97文字 + "...")
			name:  "100文字超は切り詰め",
			input: strings.Repeat("A", 105),
			want:  strings.Repeat("A", 97) + "...",
		},
		{
			// ちょうど100文字はそのまま
			name:  "100文字はそのまま",
			input: strings.Repeat("B", 100),
			want:  strings.Repeat("B", 100),
		},
		{
			// 101文字は切り詰め
			name:  "101文字は切り詰め",
			input: strings.Repeat("C", 101),
			want:  strings.Repeat("C", 97) + "...",
		},
		{
			// 印字可能ASCII範囲 (32-126) の端値
			name:  "スペース(32)はそのまま",
			input: " ",
			want:  " ",
		},
		{
			// チルダ(126)はそのまま
			name:  "チルダ(126)はそのまま",
			input: "~",
			want:  "~",
		},
		{
			// DEL文字(127)は除去
			name:  "DEL文字は除去",
			input: "abc\x7fdef",
			want:  "abcdef",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := sanitizeLine(tc.input)
			if got != tc.want {
				t.Errorf("sanitizeLine(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// ─────────────────────────────────────────────
// validateProcessBlockRequest のテスト
// ─────────────────────────────────────────────

func strPtrMisc(s string) *string { return &s }

func TestValidateProcessBlockRequest(t *testing.T) {
	tests := []struct {
		name         string
		req          processBlockRuleRequest
		wantMsg      string
		wantDefaults map[string]string // フィールド名 → 期待値（デフォルト補完確認）
	}{
		{
			// 有効なリクエスト（すべて明示）
			name: "有効なリクエスト（全フィールド指定）",
			req: processBlockRuleRequest{
				Name:        "BlockMimikatz",
				ProcessName: "mimikatz.exe",
				RuleType:    "deny",
				Scope:       "all",
				Action:      "block",
				Severity:    "critical",
			},
			wantMsg: "",
		},
		{
			// デフォルト補完の確認: 空フィールドはデフォルト値に補完
			name: "空フィールドはデフォルト補完",
			req: processBlockRuleRequest{
				Name:        "TestRule",
				ProcessName: "test.exe",
				// RuleType, Scope, Action, Severity は空 → デフォルト補完
			},
			wantMsg: "",
			wantDefaults: map[string]string{
				"RuleType": "deny",
				"Scope":    "all",
				"Action":   "alert",
				"Severity": "high",
			},
		},
		{
			// name が空
			name: "nameが空",
			req: processBlockRuleRequest{
				Name:        "",
				ProcessName: "proc.exe",
			},
			wantMsg: "name は必須です",
		},
		{
			// name がスペースのみ
			name: "nameがスペースのみ",
			req: processBlockRuleRequest{
				Name:        "  ",
				ProcessName: "proc.exe",
			},
			wantMsg: "name は必須です",
		},
		{
			// process_name が空
			name: "process_nameが空",
			req: processBlockRuleRequest{
				Name:        "TestRule",
				ProcessName: "",
			},
			wantMsg: "process_name は必須です",
		},
		{
			// process_name がスペースのみ
			name: "process_nameがスペースのみ",
			req: processBlockRuleRequest{
				Name:        "TestRule",
				ProcessName: "   ",
			},
			wantMsg: "process_name は必須です",
		},
		{
			// 無効な rule_type
			name: "無効なrule_type",
			req: processBlockRuleRequest{
				Name:        "TestRule",
				ProcessName: "proc.exe",
				RuleType:    "block_all",
			},
			wantMsg: "rule_type は allow/deny のいずれかを指定してください",
		},
		{
			// 無効な scope
			name: "無効なscope",
			req: processBlockRuleRequest{
				Name:        "TestRule",
				ProcessName: "proc.exe",
				RuleType:    "deny",
				Scope:       "tenant",
			},
			wantMsg: "scope は all/group/agent のいずれかを指定してください",
		},
		{
			// scope=group で scope_id が nil
			name: "scope=groupでscope_idがnil",
			req: processBlockRuleRequest{
				Name:        "TestRule",
				ProcessName: "proc.exe",
				RuleType:    "deny",
				Scope:       "group",
				ScopeID:     nil,
				Action:      "alert",
				Severity:    "high",
			},
			wantMsg: "scope が all 以外の場合、scope_id は必須です",
		},
		{
			// scope=agent で scope_id が空文字列
			name: "scope=agentでscope_idが空文字列",
			req: processBlockRuleRequest{
				Name:        "TestRule",
				ProcessName: "proc.exe",
				RuleType:    "deny",
				Scope:       "agent",
				ScopeID:     strPtrMisc(""),
				Action:      "alert",
				Severity:    "high",
			},
			wantMsg: "scope が all 以外の場合、scope_id は必須です",
		},
		{
			// scope=group で scope_id あり: 有効
			name: "scope=groupでscope_idあり",
			req: processBlockRuleRequest{
				Name:        "GroupRule",
				ProcessName: "malware.exe",
				RuleType:    "deny",
				Scope:       "group",
				ScopeID:     strPtrMisc("group-uuid-001"),
				Action:      "block",
				Severity:    "critical",
			},
			wantMsg: "",
		},
		{
			// 無効な action
			name: "無効なaction",
			req: processBlockRuleRequest{
				Name:        "TestRule",
				ProcessName: "proc.exe",
				RuleType:    "deny",
				Scope:       "all",
				Action:      "terminate",
			},
			wantMsg: "action は alert/block/alert_and_block のいずれかを指定してください",
		},
		{
			// 無効な severity
			name: "無効なseverity",
			req: processBlockRuleRequest{
				Name:        "TestRule",
				ProcessName: "proc.exe",
				RuleType:    "deny",
				Scope:       "all",
				Action:      "alert",
				Severity:    "extreme",
			},
			wantMsg: "severity は low/medium/high/critical のいずれかを指定してください",
		},
		{
			// rule_type=allow が有効
			name: "rule_type=allow",
			req: processBlockRuleRequest{
				Name:        "AllowChrome",
				ProcessName: "chrome.exe",
				RuleType:    "allow",
				Scope:       "all",
				Action:      "alert",
				Severity:    "low",
			},
			wantMsg: "",
		},
		{
			// action=alert_and_block が有効
			name: "action=alert_and_block",
			req: processBlockRuleRequest{
				Name:        "BlockAndAlert",
				ProcessName: "suspicious.exe",
				RuleType:    "deny",
				Scope:       "all",
				Action:      "alert_and_block",
				Severity:    "high",
			},
			wantMsg: "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := tc.req
			got := validateProcessBlockRequest(&req)
			if got != tc.wantMsg {
				t.Errorf("validateProcessBlockRequest() = %q, want %q", got, tc.wantMsg)
			}

			// デフォルト補完の検証
			if tc.wantMsg == "" && tc.wantDefaults != nil {
				if v, ok := tc.wantDefaults["RuleType"]; ok && req.RuleType != v {
					t.Errorf("RuleType = %q, want %q", req.RuleType, v)
				}
				if v, ok := tc.wantDefaults["Scope"]; ok && req.Scope != v {
					t.Errorf("Scope = %q, want %q", req.Scope, v)
				}
				if v, ok := tc.wantDefaults["Action"]; ok && req.Action != v {
					t.Errorf("Action = %q, want %q", req.Action, v)
				}
				if v, ok := tc.wantDefaults["Severity"]; ok && req.Severity != v {
					t.Errorf("Severity = %q, want %q", req.Severity, v)
				}
			}
		})
	}
}
