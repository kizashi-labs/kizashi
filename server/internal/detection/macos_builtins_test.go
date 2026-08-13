package detection

import "testing"

// TestMacOSBuiltins verifies the macOS detection-content additions (⑦) fire on
// canonical macOS手口 and stay quiet on benign look-alikes, via the real
// EvaluateEnvelope oracle. macOS telemetry ships through the agent's ESF
// collectors, so these rules are live (not inert).

func evalMacProc(image, cmd string) []EvalFinding {
	return EvaluateEnvelope("process", map[string]interface{}{
		"type":         "process",
		"image_path":   image,
		"process_name": image,
		"command_line": cmd,
		"action":       "create",
	})
}

// ── T1497: virtualization / sandbox discovery ──

func TestMacOS_VMDiscovery_Fires(t *testing.T) {
	cases := []struct{ image, cmd string }{
		{"/usr/sbin/sysctl", "sysctl -n kern.hv_vmm_present"},
		{"/usr/sbin/sysctl", "sysctl kern.hv_support"},
		{"/bin/sh", `sh -c "sysctl -n machdep.cpu.features | grep -q VMM"`},
		{"/bin/sh", `sh -c "ioreg -l | grep -i hypervisor"`},
	}
	for _, c := range cases {
		if f := evalMacProc(c.image, c.cmd); !firedTitleContains(f, "macOS Virtualization/Sandbox Discovery") {
			t.Errorf("macOS VM判別が検知されるべき: %q → %v", c.cmd, titles(f))
		}
	}
}

// TestMacOS_VMDiscovery_QuietOnInventory は、このルールが 2026-08-13 に
// セレクタを入れ替えた理由そのものを固定する。
//
// **以下の 2 つは、入れ替え前は「検知されるべき」ケースとしてこのファイルに
// 書かれていた。** FP ソークに macOS プロファイルを足した初回計測
// (CI run 31694491473) で、これらが 3 台中 3 台で発火した——Jamf の定期棚卸しを
// そのまま拾っていたのであり、攻撃を拾っていたのではない。
//
// Mac のシリアル/UUID を読む正規の手段はこの 2 つしかなく、資産管理エージェントが
// 全台で実行する。**旧セレクタには攻撃と正規操作を分ける情報が無かった。**
// 分かれるのは「読んだ値を VM ベンダ文字列と突き合わせるか」で、それは姉妹ルール
// macOS Virtualization/Sandbox Evasion Checks が見ている (下のテスト)。
//
// ここを「発火すべき」に戻すなら、それは Jamf の棚卸しを毎回鳴らすという判断である。
func TestMacOS_VMDiscovery_QuietOnInventory(t *testing.T) {
	// 対照。このルールが「精度が高い」のか「そもそも存在しない」のかを、
	// 沈黙だけでは区別できない。実際、本 PR の作業中に description 内の ": " が
	// YAML を壊してルールが**コンパイルされずに消えた**が、下の沈黙チェックは
	// 全件通った。実在する陽性を 1 つ先に置いて、その状態を弾く。
	if f := evalMacProc("/usr/sbin/sysctl", "sysctl -n kern.hv_vmm_present"); !firedTitleContains(f, "macOS Virtualization/Sandbox Discovery") {
		t.Fatal("対照が効いていない: ルールが読み込まれていないか発火しない。" +
			"この状態では以下の沈黙チェックが通っても何も確かめたことにならない")
	}

	cases := []struct{ image, cmd, why string }{
		{"/usr/sbin/system_profiler", "system_profiler SPHardwareDataType -json", "Jamf の定期棚卸し (fpsoak macbook.toml)"},
		{"/usr/sbin/system_profiler", "system_profiler SPHardwareDataType", "旧セレクタが拾っていた形そのもの"},
		{"/usr/sbin/ioreg", "ioreg -rd1 -c IOPlatformExpertDevice", "シリアル/UUID 取得の正規手段"},
		{"/usr/sbin/ioreg", "ioreg -l | grep IOPlatformSerialNumber", "同上"},
		{"/usr/sbin/system_profiler", "system_profiler SPSoftwareDataType", "ソフトウェア棚卸し"},
	}
	for _, c := range cases {
		if f := evalMacProc(c.image, c.cmd); firedTitleContains(f, "macOS Virtualization/Sandbox Discovery") {
			t.Errorf("ハードウェア棚卸しで誤検知している (%s): %q → %v", c.why, c.cmd, titles(f))
		}
	}
}

// TestMacOS_VMEvasion_StillCoversVendorMatch は、上のセレクタ入れ替えで
// **T1497 の真陽性を落としていない**ことを見る。
//
// ATT&CK スコアカードの T1497/macOS ケース (attack_coverage_test.go:152) は
// `sh -c "ioreg -l | grep -i VMware"` で、これは姉妹ルール
// macOS Virtualization/Sandbox Evasion Checks (probe and vmvendor) が満たす。
// 誤検知を消すために検知能力を削っていないことは、FP 側の修正では必ず
// 別途確かめる必要がある——片方だけ見ると「静かになった」は改善と区別がつかない。
func TestMacOS_VMEvasion_StillCoversVendorMatch(t *testing.T) {
	cases := []string{
		`sh -c "ioreg -l | grep -i VMware"`,
		`sh -c "system_profiler SPHardwareDataType | grep -i Parallels"`,
		`sh -c "sysctl hw.model | grep -i VirtualBox"`,
	}
	for _, cmd := range cases {
		f := evalMacProc("/bin/sh", cmd)
		if !firedTitleContains(f, "macOS Virtualization/Sandbox Evasion Checks") {
			t.Errorf("VM ベンダ文字列との突き合わせは検知され続けるべき: %q → %v", cmd, titles(f))
		}
	}
}

// ── T1070.002: macOS log clearing ──

func TestMacOS_LogClearing_Fires(t *testing.T) {
	cases := []struct{ image, cmd string }{
		{"/usr/bin/log", "log erase --all"},
		{"/bin/rm", "rm -rf /private/var/log/asl"},
	}
	for _, c := range cases {
		if f := evalMacProc(c.image, c.cmd); !firedTitleContains(f, "macOS Log Clearing") {
			t.Errorf("macOS ログ消去が検知されるべき: %q → %v", c.cmd, titles(f))
		}
	}
}

func TestMacOS_LogClearing_QuietOnBenign(t *testing.T) {
	if f := evalMacProc("/usr/bin/log", "log show --predicate 'process == \"sshd\"'"); firedTitleContains(f, "macOS Log Clearing") {
		t.Error("log show は誤検知すべきでない")
	}
}

// ── T1548.006: TCC privacy tampering ──

func TestMacOS_TCCTampering_Fires(t *testing.T) {
	cases := []struct{ image, cmd string }{
		{"/usr/bin/tccutil", "tccutil reset All"},
		{"/usr/bin/sqlite3", "sqlite3 /Library/Application Support/com.apple.TCC/TCC.db 'select * from access'"},
	}
	for _, c := range cases {
		if f := evalMacProc(c.image, c.cmd); !firedTitleContains(f, "macOS TCC Privacy Protection Tampering") {
			t.Errorf("macOS TCC 改ざんが検知されるべき: %q → %v", c.cmd, titles(f))
		}
	}
}

func TestMacOS_TCCTampering_QuietOnBenign(t *testing.T) {
	if f := evalMacProc("/usr/bin/tccutil", "tccutil"); firedTitleContains(f, "macOS TCC Privacy Protection Tampering") {
		t.Error("引数なし tccutil は誤検知すべきでない")
	}
}
