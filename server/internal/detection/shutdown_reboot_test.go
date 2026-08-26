package detection

import "testing"

// T1529 — 通常の再起動では鳴らないこと。
//
// FP ソークで `Unix System Shutdown or Reboot` が dev-machine と macbook に計 6 件
// (3599.98 件/1000ホスト/日) 出ていた。鳴っていたのは
//
//	shutdown -r now
//	shutdown -r +5 / -r +1
//
// で、OS 更新後の再起動そのものである。**マシンを再起動することは攻撃ではない。**
//
// ★ 判断の根拠は同技法の Windows 側にあった。T1529 のルールは 3 本あり
// (技法で横断検索し、存在しない技法での対照付きで確認)、migration 385 の
// `Forced System Shutdown or Reboot` は最初から強制フラグ (/f, /t 0) を要求して
// いた。**「T1529 で見るべきなのは強制・即時の停止である」という判断はリポジトリに
// 既にあり、Unix 側と builtin の 2 本だけがそれを持っていなかった。**
//
// 破壊的マルウェアやワイパーは後片付け (サービス停止・sync) を飛ばすために強制
// フラグを使い、管理者は逆にそれを避ける。そこが分かれ目である。
//
// ── テストが 2 本に分かれている理由 ──
//
// EvaluateEnvelope は **builtin しか評価しない**。Unix 側は rules テーブル由来
// (migration 386 → 428) なので別に読み込んで確かめる。T1552.003 (#746) と同じ分割で、
// 片方だけ見ると「DB 側が広いまま残っている」状態を見逃す。

func evalShutdown(image, cmd string) []EvalFinding {
	return EvaluateEnvelope("process", map[string]interface{}{
		"type":         "process",
		"image_path":   image,
		"process_name": image,
		"command_line": cmd,
		"action":       "create",
	})
}

// ── builtin 側 (Windows) ──

func TestT1529_Builtin_QuietOnOrdinaryReboot(t *testing.T) {
	const title = "Forced System Shutdown or Reboot"

	// 対照。実在する強制形が鳴らないなら、以下の沈黙チェックに意味が無い。
	if !firedTitleContains(evalShutdown(`C:\Windows\System32\shutdown.exe`, `shutdown /r /f /t 0`), title) {
		t.Fatal("対照が効いていない: 強制シャットダウンが鳴らないので、" +
			"以下の沈黙チェックが通っても意味が無い")
	}

	for _, c := range []struct{ cmd, why string }{
		{`shutdown /r /t 600`, "Windows Update の再起動（猶予あり）"},
		{`shutdown /r`, "管理者による再起動"},
		{`shutdown /s /t 60`, "計画停止"},
	} {
		if f := evalShutdown(`C:\Windows\System32\shutdown.exe`, c.cmd); firedTitleContains(f, title) {
			t.Errorf("通常の再起動で誤検知している (%s): %q → %v", c.why, c.cmd, titles(f))
		}
	}
}

func TestT1529_Builtin_StillFiresOnForced(t *testing.T) {
	const title = "Forced System Shutdown or Reboot"
	for _, cmd := range []string{
		`shutdown /r /f /t 0`, // attack_coverage_test.go:134,138 と同じ
		`shutdown /s /f`,
		`shutdown /r /t 0`,
	} {
		if f := evalShutdown(`C:\Windows\System32\shutdown.exe`, cmd); !firedTitleContains(f, title) {
			t.Errorf("強制シャットダウンが検知されなくなった: %q → %v", cmd, titles(f))
		}
	}
}

// ── DB 側 (Unix / migration 428) ──

func TestMigration428NarrowsUnixShutdownRule(t *testing.T) {
	const title = "Unix System Shutdown or Reboot"
	blk, ok := migrationSigmaBlocks(t)[title]
	if !ok {
		t.Fatalf("ルール %q が migration から消えている", title)
	}
	if blk.file != "428_narrow_unix_shutdown_rule.sql" {
		t.Fatalf("428 の UPDATE 本文ではなく %s を拾っている——"+
			"狭める前の本文を試していることになる", blk.file)
	}

	ev := NewSigmaEvaluator()
	if err := ev.LoadRule(blk.body); err != nil {
		t.Fatalf("%s のロードに失敗: %v", blk.file, err)
	}
	fires := func(image, cmd string) bool {
		event := map[string]interface{}{"type": "process", "image": image, "command_line": cmd}
		addPipelineSigmaAliases(event)
		for _, m := range ev.EvaluateEvent(event) {
			if m.RuleTitle == title {
				return true
			}
		}
		return false
	}

	if !fires("/sbin/reboot", "reboot -f") {
		t.Fatal("対照が効いていない: 強制再起動が鳴らないので、以下の沈黙チェックに意味が無い")
	}

	// tests/fpsoak/profiles/ の実コマンドそのもの。
	for _, c := range []struct{ image, cmd, why string }{
		{"/sbin/shutdown", "shutdown -r now", "dev-machine.toml / macbook.toml（誤検知していた形）"},
		{"/sbin/shutdown", "shutdown -r +5", "dev-machine.toml"},
		{"/sbin/shutdown", "shutdown -r +1", "macbook.toml"},
		{"/sbin/shutdown", "shutdown -h now", "管理者が電源を落とす"},
		{"/bin/systemctl", "systemctl reboot", "systemd 経由の通常再起動"},
	} {
		if fires(c.image, c.cmd) {
			t.Errorf("通常の再起動で誤検知している (%s): %q", c.why, c.cmd)
		}
	}

	for _, c := range []struct{ image, cmd string }{
		{"/sbin/reboot", "reboot -f"},
		{"/sbin/poweroff", "poweroff -f"},
		{"/sbin/halt", "halt -n"},
		{"/bin/systemctl", "systemctl --force reboot"},
	} {
		if !fires(c.image, c.cmd) {
			t.Errorf("強制シャットダウンが検知されなくなった: %q", c.cmd)
		}
	}
}
