package handlers

import (
	"testing"
)

// maskIntegrationKey のユニットテスト
func TestMaskIntegrationKey(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  string
	}{
		{
			// 通常の長いキー: 末尾4文字だけ残す
			name:  "通常の長いキー",
			input: "abcdefgh1234",
			want:  "********1234",
		},
		{
			// ちょうど5文字: 先頭1文字をマスク
			name:  "5文字のキー",
			input: "ab123",
			want:  "*b123",
		},
		{
			// ちょうど4文字: すべてマスク
			name:  "4文字のキー（境界値）",
			input: "abcd",
			want:  "****",
		},
		{
			// 3文字: すべてマスク
			name:  "3文字以下のキー",
			input: "abc",
			want:  "****",
		},
		{
			// 空文字: すべてマスク
			name:  "空文字列",
			input: "",
			want:  "****",
		},
		{
			// PagerDutyのような実際のキー形式
			name:  "PagerDuty形式の長いキー",
			input: "R01T3ZXYZ1234ABCD",
			want:  "*************ABCD",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := maskIntegrationKey(tc.input)
			if got != tc.want {
				t.Errorf("maskIntegrationKey(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

// maskIntegrationKey の末尾4文字保持を確認する追加テスト
func TestMaskIntegrationKey_LastFourAlwaysVisible(t *testing.T) {
	key := "supersecretkey9999"
	result := maskIntegrationKey(key)

	// 末尾4文字は必ず見える
	if result[len(result)-4:] != "9999" {
		t.Errorf("末尾4文字が正しくありません: got %q", result[len(result)-4:])
	}
	// マスク部分はすべて '*'
	for i, ch := range result[:len(result)-4] {
		if ch != '*' {
			t.Errorf("インデックス %d の文字が '*' ではありません: %c", i, ch)
		}
	}
}
