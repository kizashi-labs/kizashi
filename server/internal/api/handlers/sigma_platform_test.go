package handlers

import (
	"reflect"
	"testing"
)

// TestSigmaPlatformsFromLogsource pins the platform derivation for UI-imported
// Sigma rules.
//
// `POST /api/v1/rules/import/sigma` used to insert without the platform column, so
// every imported rule took the schema DEFAULT ARRAY['windows','linux','darwin'].
// RuleEngine.platformMatchesEvent reads an all-OS list as "universal" and skips the
// OS gate entirely, so Windows-only rules ran against Linux events — the gate was
// inert for the whole UI-imported corpus. internal/sync/sigmahq.go's inferPlatforms
// had been deriving this correctly all along; only this path was missing it.
func TestSigmaPlatformsFromLogsource(t *testing.T) {
	cases := []struct {
		name      string
		logsource map[string]string
		want      []string
		why       string
	}{
		{
			name:      "windows",
			logsource: map[string]string{"product": "windows", "service": "security"},
			want:      []string{"windows"},
			why:       "Windows専用ルールをLinuxイベントに当てない",
		},
		{
			name:      "linux",
			logsource: map[string]string{"product": "linux", "category": "process_creation"},
			want:      []string{"linux"},
		},
		{
			name:      "macos は SigmaHQ の綴り",
			logsource: map[string]string{"product": "macos"},
			want:      []string{"macos"},
		},
		{
			name:      "darwin も macos として扱う",
			logsource: map[string]string{"product": "darwin"},
			want:      []string{"macos"},
			why:       "エージェントは runtime.GOOS を報告するため darwin で届く",
		},
		{
			name:      "大文字小文字と空白を無視する",
			logsource: map[string]string{"product": "  Windows  "},
			want:      []string{"windows"},
		},
		{
			name:      "product 無し（カテゴリのみ）は既定に委ねる",
			logsource: map[string]string{"category": "process_creation"},
			want:      nil,
			why: "SigmaHQ のカテゴリ限定ルールは実際にクロスプラットフォーム。" +
				"OS を推測すると本物の検知を落とす",
		},
		{
			name:      "logsource 自体が無い",
			logsource: nil,
			want:      nil,
		},
		{
			name:      "知らない product も既定に委ねる",
			logsource: map[string]string{"product": "zeek"},
			want:      nil,
			why:       "フェイルオープン。稀なクロスOS誤検知の方が、静かに検知を落とすよりまし",
		},
	}

	for _, tc := range cases {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			got := sigmaPlatforms(tc.logsource)
			if !reflect.DeepEqual(got, tc.want) {
				t.Errorf("sigmaPlatforms(%v) = %v, 期待 %v\n%s",
					tc.logsource, got, tc.want, tc.why)
			}
		})
	}
}
