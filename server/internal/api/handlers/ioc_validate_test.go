package handlers

import (
	"strings"
	"testing"
)

// ─────────────────────────────────────────────
// detectIOCType のテスト
// ─────────────────────────────────────────────

func TestDetectIOCType(t *testing.T) {
	tests := []struct {
		name  string
		value string
		want  string
	}{
		// ── URL ──────────────────────────────────
		{
			// http:// プレフィックスを持つ値は "url"
			name:  "http URLはurlとして検出",
			value: "http://malware.example.com/payload",
			want:  "url",
		},
		{
			// https:// プレフィックスも "url"
			name:  "https URLはurlとして検出",
			value: "https://evil.test/c2/beacon",
			want:  "url",
		},
		{
			// 前後の空白は trim してから判定
			name:  "前後スペースつきhttps URLはurlとして検出",
			value: "  https://phish.example.org/login  ",
			want:  "url",
		},

		// ── IP アドレス ───────────────────────────
		{
			// 典型的な IPv4 アドレス
			name:  "IPv4アドレスはipとして検出",
			value: "192.168.1.1",
			want:  "ip",
		},
		{
			// 全セグメントが数字なら "ip"
			name:  "別のIPv4アドレス",
			value: "10.0.0.254",
			want:  "ip",
		},
		{
			// 先頭スペースつきでも trim 後に ip と判定
			name:  "前後スペースつきIPv4はipとして検出",
			value: "  1.2.3.4  ",
			want:  "ip",
		},

		// ── ハッシュ ──────────────────────────────
		{
			// 32 桁の 16 進数は MD5 ハッシュ
			name:  "32桁16進数はhashとして検出（MD5）",
			value: "d41d8cd98f00b204e9800998ecf8427e",
			want:  "hash",
		},
		{
			// 40 桁の 16 進数は SHA-1 ハッシュ
			name:  "40桁16進数はhashとして検出（SHA1）",
			value: "da39a3ee5e6b4b0d3255bfef95601890afd80709",
			want:  "hash",
		},
		{
			// 64 桁の 16 進数は SHA-256 ハッシュ
			name:  "64桁16進数はhashとして検出（SHA256）",
			value: strings.Repeat("a", 64),
			want:  "hash",
		},
		{
			// 大文字 16 進数も hash
			name:  "大文字MD5ハッシュはhashとして検出",
			value: "D41D8CD98F00B204E9800998ECF8427E",
			want:  "hash",
		},

		// ── メールアドレス ────────────────────────
		{
			// "@" を含む値は "email"
			name:  "メールアドレスはemailとして検出",
			value: "attacker@phishing.example.com",
			want:  "email",
		},
		{
			// シンプルなメール形式
			name:  "シンプルなメールアドレス",
			value: "evil@bad.org",
			want:  "email",
		},

		// ── ドメイン ──────────────────────────────
		{
			// サブドメインつきのドメイン
			name:  "サブドメインつきドメインはdomainとして検出",
			value: "malware.example.com",
			want:  "domain",
		},
		{
			// シンプルな 2 ラベルドメイン
			name:  "2ラベルドメインはdomainとして検出",
			value: "evil.org",
			want:  "domain",
		},
		{
			// ハイフンを含むドメイン
			name:  "ハイフンつきドメインはdomainとして検出",
			value: "c2-server.example.net",
			want:  "domain",
		},

		// ── 不明 ──────────────────────────────────
		{
			// 空文字列は型を判定できない
			name:  "空文字列は空文字列を返す",
			value: "",
			want:  "",
		},
		{
			// 一般的なテキストは判定不能
			name:  "ランダムなテキストは空文字列を返す",
			value: "not-an-ioc-value",
			want:  "",
		},
		{
			// 単一ラベルは domain パターンに一致しない
			name:  "TLDのみは空文字列を返す",
			value: "localhost",
			want:  "",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectIOCType(tc.value)
			if got != tc.want {
				t.Errorf("detectIOCType(%q) = %q, want %q", tc.value, got, tc.want)
			}
		})
	}
}

// ─────────────────────────────────────────────
// detectIOCType の優先順位テスト
// ─────────────────────────────────────────────

func TestDetectIOCTypePriority(t *testing.T) {
	// URL 判定はハッシュや IP より優先される
	t.Run("URLプレフィックスがある場合はurl優先", func(t *testing.T) {
		// ハッシュに見えるが https:// がついているので url
		v := "https://192.168.1.1/path"
		got := detectIOCType(v)
		if got != "url" {
			t.Errorf("detectIOCType(%q) = %q, want %q", v, got, "url")
		}
	})

	// IPv4 パターンはハッシュより優先される
	// (ip 判定は hash より前のため 4 オクテット数字パターンは ip)
	t.Run("IPv4形式はipとして検出される", func(t *testing.T) {
		v := "127.0.0.1"
		got := detectIOCType(v)
		if got != "ip" {
			t.Errorf("detectIOCType(%q) = %q, want %q", v, got, "ip")
		}
	})
}

// ─────────────────────────────────────────────
// contains のテスト
// ─────────────────────────────────────────────

func TestContains(t *testing.T) {
	tests := []struct {
		name string
		s    string
		sub  string
		want bool
	}{
		{
			// 完全一致
			name: "完全一致はtrue",
			s:    "hello",
			sub:  "hello",
			want: true,
		},
		{
			// 先頭部分一致
			name: "先頭部分一致はtrue",
			s:    "hello world",
			sub:  "hello",
			want: true,
		},
		{
			// 末尾部分一致
			name: "末尾部分一致はtrue",
			s:    "hello world",
			sub:  "world",
			want: true,
		},
		{
			// 中間部分一致
			name: "中間部分一致はtrue",
			s:    "ERROR: 23505 unique violation",
			sub:  "23505",
			want: true,
		},
		{
			// 大文字小文字は区別する（不一致）
			name: "大文字小文字区別で不一致はfalse",
			s:    "HELLO",
			sub:  "hello",
			want: false,
		},
		{
			// 部分文字列が存在しない
			name: "部分文字列なしはfalse",
			s:    "error occurred",
			sub:  "23505",
			want: false,
		},
		{
			// s が sub より短い
			name: "s が sub より短い場合はfalse",
			s:    "hi",
			sub:  "hello",
			want: false,
		},
		{
			// sub が空文字列: 長さ 0 なので常に true
			name: "空文字列subはtrue",
			s:    "anything",
			sub:  "",
			want: true,
		},
		{
			// s と sub ともに空文字列
			name: "両方空文字列はtrue",
			s:    "",
			sub:  "",
			want: true,
		},
		{
			// "unique" キーワードを含む
			name: "uniqueキーワード検出はtrue",
			s:    "ERROR: duplicate key violates unique constraint",
			sub:  "unique",
			want: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := contains(tc.s, tc.sub)
			if got != tc.want {
				t.Errorf("contains(%q, %q) = %v, want %v", tc.s, tc.sub, got, tc.want)
			}
		})
	}
}

// ─────────────────────────────────────────────
// isDuplicateError のテスト
// ─────────────────────────────────────────────

func TestIsDuplicateError(t *testing.T) {
	tests := []struct {
		name   string
		errMsg string // nil を表す場合は空文字列で代用し、errNil フラグを使用
		errNil bool
		want   bool
	}{
		{
			// nil エラーは false
			name:   "nilエラーはfalse",
			errNil: true,
			want:   false,
		},
		{
			// PostgreSQL 一意制約違反エラー (23505 + unique を含む)
			name:   "PostgreSQL一意制約違反エラーはtrue",
			errMsg: "ERROR: 23505 duplicate key value violates unique constraint \"ioc_entries_type_value_key\"",
			want:   true,
		},
		{
			// "unique" キーワードのみを含む ERROR
			name:   "ERRORとuniqueキーワードはtrue",
			errMsg: "ERROR: duplicate unique key violation",
			want:   true,
		},
		{
			// 一般的なデータベースエラーは false
			name:   "一般的なDBエラーはfalse",
			errMsg: "connection refused",
			want:   false,
		},
		{
			// タイムアウトエラーは false
			name:   "タイムアウトエラーはfalse",
			errMsg: "context deadline exceeded",
			want:   false,
		},
		{
			// 短すぎるエラーメッセージ (5文字未満) は false
			name:   "5文字未満のエラーメッセージはfalse",
			errMsg: "err",
			want:   false,
		},
		{
			// ちょうど5文字で "ERROR" 以外は false
			name:   "5文字だがERRORでない場合はfalse",
			errMsg: "FATAL: something bad",
			want:   false,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			if !tc.errNil {
				err = &mockError{msg: tc.errMsg}
			}
			got := isDuplicateError(err)
			if got != tc.want {
				t.Errorf("isDuplicateError(%v) = %v, want %v", err, got, tc.want)
			}
		})
	}
}

// mockError はエラーインターフェースの最小実装。
type mockError struct{ msg string }

func (e *mockError) Error() string { return e.msg }

// ─────────────────────────────────────────────
// detectIOCType ハッシュ長バリエーションのテスト
// ─────────────────────────────────────────────

func TestDetectIOCTypeHashLengths(t *testing.T) {
	// 31 桁: ハッシュとして認識されない
	t.Run("31桁16進数はhashでない", func(t *testing.T) {
		v := strings.Repeat("a", 31)
		got := detectIOCType(v)
		if got == "hash" {
			t.Errorf("detectIOCType(31桁16進数) = %q, want not hash", got)
		}
	})

	// 33 桁: ハッシュとして認識されない
	t.Run("33桁16進数はhashでない", func(t *testing.T) {
		v := strings.Repeat("b", 33)
		got := detectIOCType(v)
		if got == "hash" {
			t.Errorf("detectIOCType(33桁16進数) = %q, want not hash", got)
		}
	})

	// 63 桁: ハッシュとして認識されない
	t.Run("63桁16進数はhashでない", func(t *testing.T) {
		v := strings.Repeat("c", 63)
		got := detectIOCType(v)
		if got == "hash" {
			t.Errorf("detectIOCType(63桁16進数) = %q, want not hash", got)
		}
	})

	// 65 桁: ハッシュとして認識されない
	t.Run("65桁16進数はhashでない", func(t *testing.T) {
		v := strings.Repeat("d", 65)
		got := detectIOCType(v)
		if got == "hash" {
			t.Errorf("detectIOCType(65桁16進数) = %q, want not hash", got)
		}
	})
}
