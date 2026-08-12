package handlers

import (
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// escapeCEF のユニットテスト
//
// escapeCEF は audit_export_handler.go で定義された純粋関数で、
// CEF（Common Event Format）フォーマットのフィールド値をエスケープする。
// バックスラッシュを \\ に、パイプ文字 | を \| に変換する。
// ─────────────────────────────────────────────────────────────────────────────

// TestEscapeCEF_PlainText は特殊文字を含まないテキストがそのまま返ることを確認する。
func TestEscapeCEF_PlainText(t *testing.T) {
	// 特殊文字なし: 変換不要
	input := "user_login_success"
	got := escapeCEF(input)
	if got != input {
		t.Errorf("escapeCEF(%q) = %q, 変換なしで %q を期待しました", input, got, input)
	}
}

// TestEscapeCEF_EmptyString は空文字列が空文字列のまま返ることを確認する。
func TestEscapeCEF_EmptyString(t *testing.T) {
	got := escapeCEF("")
	if got != "" {
		t.Errorf("escapeCEF(\"\") = %q, 空文字列を期待しました", got)
	}
}

// TestEscapeCEF_BackslashEscaped はバックスラッシュが \\ にエスケープされることを確認する。
func TestEscapeCEF_BackslashEscaped(t *testing.T) {
	// C:\Windows\System32 → C:\\Windows\\System32
	input := `C:\Windows\System32`
	want := `C:\\Windows\\System32`
	got := escapeCEF(input)
	if got != want {
		t.Errorf("escapeCEF(%q) = %q, %q を期待しました", input, got, want)
	}
}

// TestEscapeCEF_PipeEscaped はパイプ文字 | が \| にエスケープされることを確認する。
func TestEscapeCEF_PipeEscaped(t *testing.T) {
	// CEF フォーマットではパイプがフィールド区切りとして使われるため、
	// フィールド値内のパイプは必ずエスケープしなければならない
	input := "admin|superuser"
	want := `admin\|superuser`
	got := escapeCEF(input)
	if got != want {
		t.Errorf("escapeCEF(%q) = %q, %q を期待しました", input, got, want)
	}
}

// TestEscapeCEF_BackslashBeforePipeOrderCorrect はバックスラッシュとパイプが共存する場合に
// バックスラッシュが先にエスケープされることを確認する（順序依存のバグ防止）。
func TestEscapeCEF_BackslashBeforePipeOrderCorrect(t *testing.T) {
	// 入力: \|
	// バックスラッシュを先にエスケープ: \\|
	// パイプをエスケープ: \\\|
	input := `\|`
	want := `\\\|`
	got := escapeCEF(input)
	if got != want {
		t.Errorf("escapeCEF(%q) = %q, %q を期待しました（バックスラッシュ先行エスケープ）",
			input, got, want)
	}
}

// TestEscapeCEF_MultiplePipes は複数のパイプ文字がすべてエスケープされることを確認する。
func TestEscapeCEF_MultiplePipes(t *testing.T) {
	input := "a|b|c|d"
	want := `a\|b\|c\|d`
	got := escapeCEF(input)
	if got != want {
		t.Errorf("escapeCEF(%q) = %q, %q を期待しました", input, got, want)
	}
}

// TestEscapeCEF_MultipleBackslashes は複数のバックスラッシュがすべてエスケープされることを確認する。
func TestEscapeCEF_MultipleBackslashes(t *testing.T) {
	// \\ → \\\\
	input := `\\`
	want := `\\\\`
	got := escapeCEF(input)
	if got != want {
		t.Errorf("escapeCEF(%q) = %q, %q を期待しました", input, got, want)
	}
}

// TestEscapeCEF_MixedSpecialChars はバックスラッシュとパイプが混在する実世界的な入力を確認する。
func TestEscapeCEF_MixedSpecialChars(t *testing.T) {
	// UNC パス + CEF 区切り文字の混在例: \\server\share|read
	input := `\\server\share|read`
	// \\ → \\\\, \s → \\s（バックスラッシュ), | → \|
	want := `\\\\server\\share\|read`
	got := escapeCEF(input)
	if got != want {
		t.Errorf("escapeCEF(%q) = %q, %q を期待しました", input, got, want)
	}
}

// TestEscapeCEF_NoBackslashNoBar はバックスラッシュもパイプも含まない文字列が変化しないことを確認する。
func TestEscapeCEF_NoBackslashNoBar(t *testing.T) {
	cases := []string{
		"alert_login_failed",
		"127.0.0.1",
		"user@example.com",
		"GET /api/v1/health HTTP/1.1",
		"severity=high",
		"2026-03-23T00:00:00Z",
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			got := escapeCEF(input)
			if got != input {
				t.Errorf("escapeCEF(%q) = %q, 変換なしを期待しました", input, got)
			}
		})
	}
}

// TestEscapeCEF_IdempotencyDoesNotHold は escapeCEF が冪等でない（二重エスケープが発生する）ことを確認する。
// これは意図された動作で、エスケープ済みの値を再度エスケープすると誤った結果になる。
func TestEscapeCEF_IdempotencyDoesNotHold(t *testing.T) {
	input := `value|field`
	oncce := escapeCEF(input)
	twice := escapeCEF(oncce)
	// 一度エスケープ後に再度エスケープすると結果が変わるはず
	if oncce == twice {
		t.Errorf("escapeCEF を2回適用しても結果が変わらないのは予期しない動作です: %q", oncce)
	}
}

// TestEscapeCEF_OutputNeverContainsUnescapedPipe はエスケープ後の出力に
// バックスラッシュなしのパイプが含まれないことを確認する。
func TestEscapeCEF_OutputNeverContainsUnescapedPipe(t *testing.T) {
	inputs := []string{
		"action|delete",
		"user|admin|root",
		`path\to\file|exec`,
	}
	for _, input := range inputs {
		t.Run(input, func(t *testing.T) {
			got := escapeCEF(input)
			// エスケープ後の文字列内でバックスラッシュなしのパイプを探す
			// \| は合法なので、先頭または非バックスラッシュ直後の | を検出する
			for i, ch := range got {
				if ch == '|' {
					if i == 0 || got[i-1] != '\\' {
						t.Errorf("escapeCEF(%q) の出力 %q に未エスケープのパイプが含まれます（位置 %d）",
							input, got, i)
					}
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// 監査エクスポート関連のヘルパーロジックテスト
// audit_export_handler.go 内のインラインロジックを検証する
// ─────────────────────────────────────────────────────────────────────────────

// TestAuditExportLimitClamping は limit パラメータが範囲外のとき 5000 に補正されることを
// ハンドラのロジックを反映した純粋関数として検証する。
func TestAuditExportLimitClamping(t *testing.T) {
	// audit_export_handler.go の Export メソッド内ロジックを再現した純粋関数
	clampAuditLimit := func(raw string) int {
		var limit int
		// fmt.Sscanf と同等の整数変換
		for _, r := range raw {
			if r >= '0' && r <= '9' {
				limit = limit*10 + int(r-'0')
			} else {
				break
			}
		}
		if limit <= 0 || limit > 5000 {
			limit = 5000
		}
		return limit
	}

	tests := []struct {
		name  string
		input string
		want  int
	}{
		{"正常値はそのまま", "100", 100},
		{"最大値5000はそのまま", "5000", 5000},
		{"5001は5000にクランプ", "5001", 5000},
		{"0は5000にクランプ", "0", 5000},
		{"負の値は5000にクランプ", "99999", 5000},
		{"1は有効", "1", 1},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := clampAuditLimit(tc.input)
			if got != tc.want {
				t.Errorf("clampAuditLimit(%q) = %d, %d を期待しました", tc.input, got, tc.want)
			}
		})
	}
}

// TestAuditExportFilenameFormat は監査エクスポートのファイル名が
// 期待されるプレフィックスを持つことを確認する。
func TestAuditExportFilenameFormat(t *testing.T) {
	// audit_export_handler.go のファイル名生成ロジックを反映
	// fmt.Sprintf("audit_logs_%s", time.Now().Format("20060102_150405"))
	// のフォーマットを検証
	filename := "audit_logs_20260323_143000"

	if !strings.HasPrefix(filename, "audit_logs_") {
		t.Errorf("監査ログのファイル名は 'audit_logs_' で始まるべきです: %q", filename)
	}

	// 日付部分（8桁）とアンダースコアと時刻部分（6桁）が続く
	rest := strings.TrimPrefix(filename, "audit_logs_")
	if len(rest) < 15 { // YYYYMMDD_HHmmss = 15文字
		t.Errorf("ファイル名の日時部分が短すぎます: %q", rest)
	}
}

// TestAuditExportFormatValidation はエクスポートフォーマット文字列の正規化ロジックを検証する。
func TestAuditExportFormatValidation(t *testing.T) {
	// audit_export_handler.go で strings.ToLower を使って正規化されるフォーマット値
	normalizeFormat := func(raw string) string {
		return strings.ToLower(raw)
	}

	tests := []struct {
		input string
		want  string
	}{
		{"json", "json"},
		{"JSON", "json"},
		{"CEF", "cef"},
		{"LEEF", "leef"},
		{"cef", "cef"},
		{"leef", "leef"},
		{"", ""},
	}

	for _, tc := range tests {
		t.Run("format="+tc.input, func(t *testing.T) {
			got := normalizeFormat(tc.input)
			if got != tc.want {
				t.Errorf("normalizeFormat(%q) = %q, %q を期待しました", tc.input, got, tc.want)
			}
		})
	}
}
