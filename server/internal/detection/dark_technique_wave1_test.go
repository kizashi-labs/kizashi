package detection

import "testing"

// migration 384 が入れた 5 ルールが、**エージェントが実際に出す形のイベント**で
// 発火することを確かめる。
//
// なぜフィールド解決の検査だけでは足りないのか:
// TestMigrationSigmaFieldSupportInAPIEvaluator は「評価器がそのフィールド名を
// 知っているか」を見るもので、合成イベント（field_support.go のキッチンシンク）
// に対する判定である。**値が実際に届くか**は別問題で、そこが食い違うと
// 「検査は緑・永久に不発火」という最も見つけにくい壊れ方になる。
//
// 実際、第 1 波の候補 6 件のうち
// `SID-History Added to Account (Security Event 4765/4766)` はその判定で外した——
// `EventID` は既知の名前なのでフィールド検査は通るが、agent の購読述語が
// 4765/4766 を含まず、そもそも AuthEvent はワイヤ上に EventID を持たなかった
// （auth_parse.go のコメントが明言していた）。migration 384 のヘッダを参照。
//
// ★ 2026-08-14 に供給側を通して着地させた。proto に AuthEvent.event_id を足し、
// 購読述語に 4765/4766 を入れ、parse の default 落ちを塞ぎ、ingestion が
// event_id を平坦化し、alert_pipeline が **4765/4766 に限って** Sigma の EventID に
// 写す。ルールは builtin として入れてある
// （`SID-History Added to Account (Security Event 4765/4766)`）。
// 供給が通ったことは server/internal/detection/sid_history_test.go と
// agent/internal/platform/windows/auth_{parse,query}_test.go が固定する。
//
// **判定そのものは正しかった。** 当時ルールだけ先に入れていたら、フィールド検査は
// 緑のまま永久に不発火のルールが 1 件増えていた。順序を守った結果として、
// 直すべき場所が 3 層に分かれていることが最初から見えていた。
//
// ここで組み立てるイベントは、Windows の process_creation が実際に載せる
// フィールドだけを使う: image / command_line / integrity_level。いずれも
// agent/internal/platform/windows/process_collector.go が採取している
// （IntegrityLevel は tokenIntegrityLevel(token)）。
func TestDarkTechniqueWave1RulesFire(t *testing.T) {
	blocks := migrationSigmaBlocks(t)

	cases := []struct {
		title string
		event map[string]interface{}
		why   string
	}{
		{
			title: "SID-History Injection via Offensive Tooling",
			event: map[string]interface{}{
				"type":         "process",
				"image":        `C:\Users\v\mimikatz.exe`,
				"command_line": `mimikatz.exe "sid::add /sam:victim /new:S-1-5-21-1-2-3-512"`,
			},
			why: "T1134.005。CommandLine 単独のセレクタなので、これが落ちるなら別名表が壊れている",
		},
		{
			title: "Token Impersonation via Mimikatz token Module or CreateProcessWithToken",
			event: map[string]interface{}{
				"type":         "process",
				"image":        `C:\Users\v\mimikatz.exe`,
				"command_line": `mimikatz.exe "token::elevate" exit`,
			},
			why: "T1134.001/.002。main で完全に暗かった 2 技法のうちの 1 つ",
		},
		{
			title: "Domain or Group Policy Modification",
			event: map[string]interface{}{
				"type":         "process",
				"image":        `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"command_line": `powershell -c "Set-GPRegistryValue -Name 'Default Domain Policy' -Key HKLM\..."`,
			},
			why: "T1484.001/.002。ドメイン信頼関係の改変は main に該当セレクタが 1 つも無かった",
		},
		{
			title: "Desktop Wallpaper Defacement",
			event: map[string]interface{}{
				"type":         "process",
				"image":        `C:\Windows\System32\reg.exe`,
				"command_line": `reg add "HKCU\Control Panel\Desktop" /v Wallpaper /d C:\ransom.bmp /f`,
			},
			why: "T1491.001。レジストリ監視ではなくプロセス生成で見る設計なので、既存のテレメトリで足りる",
		},
		{
			title: "SYSTEM Integrity Process from User Profile Path",
			event: map[string]interface{}{
				"type":            "process",
				"image":           `C:\Users\v\AppData\Local\Temp\payload.exe`,
				"command_line":    `payload.exe`,
				"integrity_level": "System",
			},
			why: "T1548.002。integrity_level を使う唯一のルールで、これが落ちるなら別名が失われている",
		},
	}

	for _, tc := range cases {
		t.Run(tc.title, func(t *testing.T) {
			blk, ok := blocks[tc.title]
			if !ok {
				t.Fatalf("ルール %q が migration から消えている。改名したなら削除ではなく "+
					"このテストの参照先を張り替えること（守っているのは名前ではなく発火である）", tc.title)
			}

			ev := NewSigmaEvaluator()
			if err := ev.LoadRule(blk.body); err != nil {
				t.Fatalf("%s のロードに失敗: %v", blk.file, err)
			}

			event := make(map[string]interface{}, len(tc.event))
			for k, v := range tc.event {
				event[k] = v
			}
			addPipelineSigmaAliases(event)

			for _, m := range ev.EvaluateEvent(event) {
				if m.RuleTitle == tc.title {
					return
				}
			}
			t.Errorf("%q が発火しなかった。%s\n"+
				"フィールド解決の検査が緑でも、値が届かなければ永久に不発火である——"+
				"このテストはその差を見るために在る。\nイベント: %v", tc.title, tc.why, event)
		})
	}
}
