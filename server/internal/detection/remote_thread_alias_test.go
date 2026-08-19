package detection

import "testing"

// TestRemoteThreadImageAliases guards the injection field translation: SigmaHQ
// create_remote_thread / process_access rules match SourceImage / TargetImage
// (Sysmon EID8/EID10 names), but the Windows ETW thread sensor and the
// credential-access sensor emit source_image / target_image. Without the alias
// the enabled "Process Hollowing" rule (T1055.012) stays structurally inert.
func TestRemoteThreadImageAliases(t *testing.T) {
	flat := map[string]interface{}{
		"type":         "create_remote_thread",
		"source_image": `C:\Users\v\AppData\Local\Temp\evil.exe`,
		"target_image": `C:\Windows\System32\svchost.exe`,
		"source_pid":   "1234",
		"target_pid":   "5678",
	}
	addPipelineSigmaAliases(flat)

	if got, _ := flat["SourceImage"].(string); got != `C:\Users\v\AppData\Local\Temp\evil.exe` {
		t.Errorf("SourceImage alias missing/wrong: %q", got)
	}
	if got, _ := flat["TargetImage"].(string); got != `C:\Windows\System32\svchost.exe` {
		t.Errorf("TargetImage alias missing/wrong: %q", got)
	}
	if got, _ := flat["SourceProcessId"].(string); got != "1234" {
		t.Errorf("SourceProcessId alias missing/wrong: %q", got)
	}
	if got, _ := flat["TargetProcessId"].(string); got != "5678" {
		t.Errorf("TargetProcessId alias missing/wrong: %q", got)
	}
}

// The alias must also make SourceImage/TargetImage field-supported so the curate
// field-gate stops treating create_remote_thread rules as unsupported.
func TestRemoteThreadFieldsSupported(t *testing.T) {
	sup := SupportedSigmaFields()
	for _, f := range []string{"SourceImage", "TargetImage"} {
		if !sup[f] {
			t.Errorf("%s must be in SupportedSigmaFields (via source/target_image alias)", f)
		}
	}
}

// TestProcessHollowingRuleFiresOnRealEventShape drives the actual DB rule with the
// event shape observed in production, not just the alias map.
//
// なぜ要るか。上の2つは「エイリアスが張られていること」しか見ていない。今日までに
// 二度、**エイリアスは通っているのにルールは鳴らない**という形が見つかっている
// (docs/results/live-20260818-jp-duplicate-rules-inert.md)。フィールドが解決できる
// ことと、そのルールが実データで一致することは別である。
//
// 駆動に使うのは 2026-07-13 08:35 に計測用 Windows 機で実際に観測された
// create_remote_thread イベント（rtinject.exe → notepad.exe）。当時このルールは
// 0 発火だった——`rules` テーブルにリアルタイム発火経路が無かったためで、
// 結線は #647 と #671 で入った。以後この条件を満たすイベントは発生しておらず、
// 実 DB の発火数は 0 のままである。つまり **実データでは「直った」ことを
// 確かめられない**。ここで固定しておかないと、また壊れても気づけない。
func TestProcessHollowingRuleFiresOnRealEventShape(t *testing.T) {
	blocks := migrationSigmaBlocks(t)
	blk, ok := blocks["Process Hollowing via Suspicious Executable"]
	if !ok {
		t.Fatal(`"Process Hollowing via Suspicious Executable" が migration から取れない。` +
			"改名したなら、このテストが守っているのは名前ではなく " +
			"source_image/target_image → SourceImage/TargetImage の結線なので張り替えること")
	}

	fires := func(t *testing.T, sourceImage, targetImage string) bool {
		t.Helper()
		ev := NewSigmaEvaluator()
		if err := ev.LoadRule(blk.body); err != nil {
			t.Fatalf("LoadRule: %v", err)
		}
		event := map[string]interface{}{
			"type":         "create_remote_thread",
			"source_image": sourceImage,
			"target_image": targetImage,
			"source_pid":   "1234",
			"target_pid":   "5678",
		}
		addPipelineSigmaAliases(event)
		for _, m := range ev.EvaluateEvent(event) {
			if m.RuleTitle == "Process Hollowing via Suspicious Executable" {
				return true
			}
		}
		return false
	}

	// 実機で観測された形。ここが落ちたら、注入検知が本番で死んでいる。
	if !fires(t, `C:\Users\Administrator\rtpoc\rtinject.exe`, `C:\Windows\System32\notepad.exe`) {
		t.Error("実機で観測された create_remote_thread イベントで発火しなかった。" +
			"SourceImage/TargetImage のエイリアスか、ルールの選択条件が壊れている")
	}

	// 述語が仕事をしていることの確認。SourceImage が利用者書き込み可能な場所の
	// 外にあれば一致してはいけない——ここが通ってしまうなら、上の断言は
	// 「何にでも一致する」だけで意味が無い。
	if fires(t, `C:\Windows\System32\services.exe`, `C:\Windows\System32\notepad.exe`) {
		t.Error("SourceImage が System32 配下でも発火した。" +
			"SourceImage|startswith の絞り込みが効いていない")
	}

	// TargetImage 側も同様に効いていること。
	if fires(t, `C:\Users\Administrator\rtpoc\rtinject.exe`, `C:\Windows\System32\lsass.exe`) {
		t.Error("TargetImage が対象一覧に無い lsass.exe でも発火した。" +
			"TargetImage|endswith の絞り込みが効いていない")
	}
}
