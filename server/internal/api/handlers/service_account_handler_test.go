package handlers

import (
	"testing"
)

// maskClientID のユニットテスト
// maskClientID は maskIntegrationKey と同じロジックを使用している
func TestMaskClientID(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			// 通常の sa_ プレフィックス付き client_id
			name:  "sa_プレフィックス付きID",
			input: "sa_0102030405060708090a0b",
			want:  "*********************0a0b",
		},
		{
			// ちょうど4文字: すべてマスク
			name:  "4文字（境界値）",
			input: "abcd",
			want:  "****",
		},
		{
			// 5文字: 先頭1文字のみマスク
			name:  "5文字",
			input: "12345",
			want:  "*2345",
		},
		{
			// 1文字: すべてマスク
			name:  "1文字",
			input: "x",
			want:  "****",
		},
		{
			// 空文字: すべてマスク
			name:  "空文字列",
			input: "",
			want:  "****",
		},
		{
			// 末尾4文字の確認
			name:  "末尾4文字が保持されること",
			input: "longclientidvalue_abcd",
			want:  "******************abcd",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := maskClientID(tc.input)
			if got != tc.want {
				t.Errorf("maskClientID(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// maskClientID の長さ不変性テスト: 出力長は max(4, 入力長) と一致する
func TestMaskClientID_OutputLength(t *testing.T) {
	cases := []struct {
		input   string
		wantLen int
	}{
		{"", 4},
		{"a", 4},
		{"abcd", 4},
		{"abcde", 5},
		{"sa_abcdef123456", 15},
	}
	for _, tc := range cases {
		got := maskClientID(tc.input)
		if len(got) != tc.wantLen {
			t.Errorf("maskClientID(%q): len=%d, want %d", tc.input, len(got), tc.wantLen)
		}
	}
}
