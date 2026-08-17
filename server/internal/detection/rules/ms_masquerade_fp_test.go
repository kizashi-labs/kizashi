package rules

import (
	"context"
	"strings"
	"testing"
)

const msMasqueradeRule = "Binary Falsely Claiming Microsoft Authorship from User-Writable Path"

// TestMSMasqueradeExcludesVendorInstallPaths pins the tuning from migration 371.
//
// Migration 345 shipped this rule on the premise that "genuine Microsoft binaries
// execute from System32 / Program Files". That premise is false: a large share of
// Microsoft's own software installs into a vendor subtree under a user-writable
// root — Teams and OneDrive under %LOCALAPPDATA%\Microsoft\, the Defender platform
// under %ProgramData%\Microsoft\. The rule therefore fired on ordinary desktops.
//
// The FP soak on 2026-08-04 (PR #543) measured it as the single largest contributor
// to the gate breach: +20,999.86 /1000 hosts/day (35 alerts), 23.2% of a +90,598
// overshoot. The three offending processes are exactly the ones asserted below —
// they are declared in tests/fpsoak/profiles/office-pc.toml with
// company = "Microsoft Corporation".
//
// This test reads the rule as actually shipped (migration text, UPDATE applied),
// not a copy, so drift in either direction is caught.
func TestMSMasqueradeExcludesVendorInstallPaths(t *testing.T) {
	all, err := extractMigrationRules()
	if err != nil {
		t.Fatalf("マイグレーションからのルール抽出に失敗: %v", err)
	}
	var rule *DetectionRule
	for _, r := range all {
		if r.Name == msMasqueradeRule {
			rule = r
		}
	}
	if rule == nil {
		t.Fatalf("ルール %q がマイグレーションから見つかりません", msMasqueradeRule)
	}
	// Guard the extractor itself: if the $SIGMA$-quoted UPDATE in 371 is not
	// picked up, we would be testing 345's pre-fix body and every assertion below
	// would be meaningless.
	if !strings.Contains(rule.Content, "vendor_install") {
		t.Fatalf("マイグレーション371のUPDATEが反映されていません。" +
			"抽出器がドル引用タグ付きUPDATEを拾えていない可能性があります")
	}

	proc := func(image string) map[string]interface{} {
		return map[string]interface{}{
			"type": "process", "agent_id": "h", "platform": "windows",
			"Company": "Microsoft Corporation", "Image": image,
		}
	}

	cases := []struct {
		name  string
		image string
		fire  bool
	}{
		// ── 誤検知だったもの（発火してはいけない）──
		// いずれも tests/fpsoak/profiles/office-pc.toml に実在する定義。
		{"Teams (LOCALAPPDATA の Microsoft サブツリー)",
			`C:\Users\taro\AppData\Local\Microsoft\Teams\current\Teams.exe`, false},
		{"OneDrive (同上)",
			`C:\Users\taro\AppData\Local\Microsoft\OneDrive\OneDrive.exe`, false},
		{"Defender プラットフォーム (ProgramData の Microsoft サブツリー)",
			`C:\ProgramData\Microsoft\Windows Defender\Platform\4.18.24010.7-0\MsMpEng.exe`, false},
		{"Roaming の Microsoft サブツリー",
			`C:\Users\taro\AppData\Roaming\Microsoft\Windows\Start Menu\helper.exe`, false},

		// ── 本来の検知対象（発火しなければならない）──
		// 除外はベンダーのサブツリーに限る。素のドロップ先は従来どおり捕まえる。
		{"Temp 直下の Microsoft 詐称バイナリ",
			`C:\Users\taro\AppData\Local\Temp\svchost.exe`, true},
		{"Downloads の Microsoft 詐称バイナリ",
			`C:\Users\taro\Downloads\MicrosoftUpdate.exe`, true},
		{"Users\\Public の Microsoft 詐称バイナリ",
			`C:\Users\Public\lsass.exe`, true},
		{"Windows\\Temp の Microsoft 詐称バイナリ",
			`C:\Windows\Temp\werfault.exe`, true},
		{"ProgramData 直下（Microsoft サブツリー外）",
			`C:\ProgramData\Updater\svchost.exe`, true},
		{"ゴミ箱からの実行",
			`C:\$Recycle.Bin\S-1-5-21-1\taskhostw.exe`, true},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := NewRuleEngine()
			e.LoadRules([]*DetectionRule{sigmaRule("ms-masq", rule.Content)})
			m, err := e.Evaluate(context.Background(), proc(c.image))
			if err != nil {
				t.Fatalf("Evaluate: %v", err)
			}
			got := hasRule(m, "ms-masq")
			if got != c.fire {
				if c.fire {
					t.Errorf("発火すべきなのにしませんでした: %s\n"+
						"ベンダー除外が広すぎて本来の検知まで消しています", c.image)
				} else {
					t.Errorf("発火してはいけないのにしました: %s\n"+
						"Microsoft 自身のインストール先を誤検知しています（FPソークのゲート超過要因）", c.image)
				}
			}
		})
	}
}

// TestMSMasqueradeStillRequiresCompany keeps the absent-field property the rule
// documents: version-info is unavailable on plenty of hosts, and a rule that
// fires when CompanyName is simply missing would flag every binary under Temp.
func TestMSMasqueradeStillRequiresCompany(t *testing.T) {
	all, err := extractMigrationRules()
	if err != nil {
		t.Fatalf("抽出に失敗: %v", err)
	}
	var rule *DetectionRule
	for _, r := range all {
		if r.Name == msMasqueradeRule {
			rule = r
		}
	}
	if rule == nil {
		t.Fatalf("ルールが見つかりません")
	}
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{sigmaRule("ms-masq", rule.Content)})
	m, err := e.Evaluate(context.Background(), map[string]interface{}{
		"type": "process", "agent_id": "h", "platform": "windows",
		"Image": `C:\Users\taro\AppData\Local\Temp\svchost.exe`, // Company なし
	})
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	if hasRule(m, "ms-masq") {
		t.Error("Company が無い（VERSIONINFO 取得失敗）だけで発火しています。" +
			"Temp 配下の全バイナリが誤検知になります")
	}
}
