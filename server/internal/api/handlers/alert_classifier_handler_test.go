package handlers

import (
	"sort"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// detectTactics のユニットテスト
//
// detectTactics は alert_classifier_handler.go で定義された純粋関数で、
// テキスト中のキーワードから MITRE ATT&CK タクティクス ID を検出する。
// DB 呼び出しが一切ないため、ハンドラのセットアップ不要でテスト可能。
// ─────────────────────────────────────────────────────────────────────────────

// TestDetectTactics_EmptyText は空文字列を渡したとき空スライスが返ることを確認する。
func TestDetectTactics_EmptyText(t *testing.T) {
	// 空テキストではタクティクスが検出されない
	got := detectTactics("")
	if len(got) != 0 {
		t.Errorf("detectTactics(\"\") = %v, 空スライスを期待しました", got)
	}
}

// TestDetectTactics_NoMatchingKeywords はマッチするキーワードがないときに空スライスを返すことを確認する。
func TestDetectTactics_NoMatchingKeywords(t *testing.T) {
	// 関係のないテキストではタクティクスが検出されない
	got := detectTactics("今日は晴れです。システムは正常稼働中です。")
	if len(got) != 0 {
		t.Errorf("detectTactics(無関係テキスト) = %v, 空スライスを期待しました", got)
	}
}

// TestDetectTactics_SingleTactic は単一タクティクスのキーワードが正しく検出されることを確認する。
func TestDetectTactics_SingleTactic(t *testing.T) {
	tests := []struct {
		name       string
		input      string
		wantTactic string
	}{
		{
			// TA0001: フィッシング系キーワード
			name:       "フィッシングキーワードはTA0001を検出",
			input:      "A phishing email was detected targeting the finance department",
			wantTactic: "TA0001",
		},
		{
			// TA0002: 実行系キーワード（powershell）
			name:       "PowerShellはTA0002を検出",
			input:      "Suspicious powershell command executed by user",
			wantTactic: "TA0002",
		},
		{
			// TA0003: 永続化系キーワード
			name:       "スケジュールタスクはTA0003を検出",
			input:      "New scheduled task created in Windows Task Scheduler",
			wantTactic: "TA0003",
		},
		{
			// TA0004: 権限昇格系キーワード
			name:       "mimikatzはTA0004を検出",
			input:      "mimikatz tool detected on endpoint workstation-01",
			wantTactic: "TA0004",
		},
		{
			// TA0005: 防御回避系キーワード
			name:       "base64エンコードはTA0005を検出",
			input:      "Payload is base64 encoded and obfuscated",
			wantTactic: "TA0005",
		},
		{
			// TA0006: 認証情報アクセス系
			name:       "LsassアクセスはTA0006を検出",
			input:      "Process attempted to read lsass memory",
			wantTactic: "TA0006",
		},
		{
			// TA0007: 探索系キーワード
			name:       "whoamiはTA0007を検出",
			input:      "whoami command executed on compromised host",
			wantTactic: "TA0007",
		},
		{
			// TA0008: 横断移動系キーワード
			name:       "PSExecはTA0008を検出",
			input:      "Lateral movement detected via psexec from host A to host B",
			wantTactic: "TA0008",
		},
		{
			// TA0009: 収集系キーワード
			name:       "ZIPアーカイブはTA0009を検出",
			input:      "Archive zip created containing sensitive documents",
			wantTactic: "TA0009",
		},
		{
			// TA0011: C2通信系キーワード
			name:       "C2ビーコンはTA0011を検出",
			input:      "DNS tunnel detected, possible c2 communication",
			wantTactic: "TA0011",
		},
		{
			// TA0040: 影響系キーワード
			name:       "ランサムウェアはTA0040を検出",
			input:      "ransomware activity detected: files being encrypted",
			wantTactic: "TA0040",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := detectTactics(tc.input)
			found := false
			for _, tac := range got {
				if tac == tc.wantTactic {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("detectTactics(%q): タクティクス %q が検出されませんでした。検出結果: %v",
					tc.input, tc.wantTactic, got)
			}
		})
	}
}

// TestDetectTactics_CaseInsensitive は大文字・小文字を問わずキーワードが検出されることを確認する。
func TestDetectTactics_CaseInsensitive(t *testing.T) {
	// 大文字 "POWERSHELL" でも TA0002 を検出できること
	got := detectTactics("Detected POWERSHELL execution in system32")
	found := false
	for _, tac := range got {
		if tac == "TA0002" {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("大文字のPOWERSHELLでTA0002が検出されませんでした: %v", got)
	}

	// 混合ケース "Mimikatz" でも TA0004 を検出できること
	got2 := detectTactics("Mimikatz detected in memory")
	found2 := false
	for _, tac := range got2 {
		if tac == "TA0004" {
			found2 = true
			break
		}
	}
	if !found2 {
		t.Errorf("混合ケースのMimikatzでTA0004が検出されませんでした: %v", got2)
	}
}

// TestDetectTactics_MultipleTactics は複数タクティクスが同時に検出されることを確認する。
func TestDetectTactics_MultipleTactics(t *testing.T) {
	// powershell (TA0002) + credential (TA0006) + ransomware (TA0040) の複合テキスト
	input := "powershell executed to dump credential hashes; ransomware payload deployed"
	got := detectTactics(input)

	want := map[string]bool{
		"TA0002": false,
		"TA0006": false,
		"TA0040": false,
	}
	for _, tac := range got {
		if _, ok := want[tac]; ok {
			want[tac] = true
		}
	}
	for tac, found := range want {
		if !found {
			t.Errorf("detectTactics: タクティクス %q が複合テキストで検出されませんでした。検出結果: %v",
				tac, got)
		}
	}
}

// TestDetectTactics_NoDuplicateTactics は同じタクティクスが複数回登場しても重複なく返されることを確認する。
func TestDetectTactics_NoDuplicateTactics(t *testing.T) {
	// "phishing" と "spearphish" は両方とも TA0001 に属するが、結果に重複してはならない
	input := "phishing campaign using spearphish attachment with macro"
	got := detectTactics(input)

	seen := make(map[string]int)
	for _, tac := range got {
		seen[tac]++
	}
	for tac, count := range seen {
		if count > 1 {
			t.Errorf("detectTactics: タクティクス %q が %d 回重複しています", tac, count)
		}
	}
}

// TestDetectTactics_ReturnedSliceIsNotNilWhenMatch はマッチがある場合に nil ではなくスライスが返ることを確認する。
func TestDetectTactics_ReturnedSliceIsNotNilWhenMatch(t *testing.T) {
	got := detectTactics("powershell base64 encoded command detected")
	if got == nil {
		t.Error("detectTactics: マッチがある場合、nil ではなくスライスを返すべきです")
	}
}

// TestDetectTactics_AllTacticsCanBeDetected は tacticsMap に含まれる全タクティクスが
// それぞれ代表キーワードで正しく検出できることを確認する。
func TestDetectTactics_AllTacticsCanBeDetected(t *testing.T) {
	// 各タクティクス ID と代表キーワードのペア
	pairs := []struct {
		tacticID string
		keyword  string
	}{
		{"TA0001", "phishing"},
		{"TA0002", "wscript"},
		{"TA0003", "autorun"},
		{"TA0004", "bypass uac"},
		{"TA0005", "obfuscat"},
		{"TA0006", "kerberos"},
		{"TA0007", "systeminfo"},
		{"TA0008", "psexec"},
		{"TA0009", "exfil"},
		{"TA0011", "cobalt"},
		{"TA0040", "wiper"},
	}

	for _, p := range pairs {
		t.Run(p.tacticID+"_"+p.keyword, func(t *testing.T) {
			got := detectTactics(p.keyword)
			found := false
			for _, tac := range got {
				if tac == p.tacticID {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("detectTactics(%q): %q が検出されませんでした。結果: %v",
					p.keyword, p.tacticID, got)
			}
		})
	}
}

// TestDetectTactics_ResultIsSorted は結果が決定論的（ソート可能）であることを確認するヘルパーテスト。
// tacticsMap は Go のマップなので反復順序は不定だが、ソートした後の内容は同一でなければならない。
func TestDetectTactics_ResultIsSorted(t *testing.T) {
	input := "phishing powershell credential"
	got1 := detectTactics(input)
	got2 := detectTactics(input)

	sort.Strings(got1)
	sort.Strings(got2)

	if len(got1) != len(got2) {
		t.Fatalf("同一入力で結果の長さが異なります: %d vs %d", len(got1), len(got2))
	}
	for i := range got1 {
		if got1[i] != got2[i] {
			t.Errorf("ソート後の結果[%d] が異なります: %q vs %q", i, got1[i], got2[i])
		}
	}
}
