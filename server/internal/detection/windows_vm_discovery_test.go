package detection

import (
	"strings"
	"testing"
)

// T1497 (Windows) — `Virtualization or Sandbox Discovery via WMIC Hardware Query`
//
// 2026-08-13 にこのルールの条件を狭めた理由を固定する。旧条件は `tool and query`
// で **WMI クラス名だけ**を見ており、FP ソークで `it-admin` に 2 件出ていた。
// 鳴っていたのは資産管理の日常操作である:
//
//	wmic /node:wks-NNNN computersystem get name,domain
//
// **分かれ目はクラスではなくプロパティにある。** 同じ computersystem クラスでも
//
//	get name,domain → ホスト名と AD ドメイン。仮想化の情報はゼロ
//	get model       → "VMware Virtual Platform" 等、ハイパーバイザが露出する
//
// T1497 が指すのは後者なので、`revealing_property` を要求する形にした。
//
// macOS 側と同じ構造の誤検知だが打ち手は違う。あちらは精密な姉妹ルールが既にあった
// のでセレクタごと入れ替えたが、Windows の T1497 は**この 1 本しか無い**
// （技法で横断検索し、対照付きで確認済み。TestT1497_RuleInventory を参照）。
// 素のプローブを拾う先が他に無いため、プロパティで絞る方を選んだ。

func evalWMIC(cmd string) []EvalFinding {
	return EvaluateEnvelope("process", map[string]interface{}{
		"type":         "process",
		"image_path":   `C:\Windows\System32\wbem\WMIC.exe`,
		"process_name": `C:\Windows\System32\wbem\WMIC.exe`,
		"command_line": cmd,
		"action":       "create",
	})
}

func firedWMICDiscovery(f []EvalFinding) bool {
	return firedTitleContains(f, "Virtualization or Sandbox Discovery via WMIC Hardware Query")
}

func TestWindows_VMDiscovery_QuietOnAssetInventory(t *testing.T) {
	// 対照。実在する攻撃形が鳴らないなら、以下の沈黙チェックは何も確かめていない。
	if !firedWMICDiscovery(evalWMIC(`wmic computersystem get model`)) {
		t.Fatal("対照が効いていない: ハイパーバイザが露出するクエリが鳴らないので、" +
			"以下の沈黙チェックが通っても意味が無い")
	}

	// tests/fpsoak/profiles/it-admin.toml の実コマンドそのもの。
	for _, c := range []struct{ cmd, why string }{
		{`wmic /node:wks-1234 computersystem get name,domain`, "資産管理がホスト名とドメインを引く（誤検知していた形）"},
		// csproduct を class に足した (2026-08-14) 影響で、プロパティで絞るという
		// このルールの設計が壊れていないことを固定する。
		//
		// ★ 実際に一度壊した。revealing_property の `product` が **csproduct 自身に
		// 当たる**ため、クラスに csproduct を足した瞬間に「csproduct を含む全コマンドが
		// 発火する」状態になっていた。部分文字列の衝突だけで、狭めたつもりの条件が
		// 実質 `tool and class` に戻る。`' product'` と先頭空白を要求して直した。
		{`wmic csproduct get name`, "csproduct でも name は汎用すぎるので足していない（意図した取りこぼし）"},
		{`wmic qfe list brief`, "更新プログラムの一覧"},
		{`wmic product get name,version`, "インストール済み製品の棚卸し"},
		{`wmic service where started=true get name,startmode`, "サービス一覧"},
	} {
		if firedWMICDiscovery(evalWMIC(c.cmd)) {
			t.Errorf("資産管理の日常操作で誤検知している (%s): %q → %v", c.why, c.cmd, titles(evalWMIC(c.cmd)))
		}
	}
}

func TestWindows_VMDiscovery_StillFiresOnRevealingQuery(t *testing.T) {
	// 狭めても落ちてはならない側。いずれもハイパーバイザの正体が露出する。
	for _, cmd := range []string{
		`wmic computersystem get model`,                                // attack_coverage_test.go:73 と同じ
		`wmic computersystem get manufacturer,model`,                   //
		`wmic bios get serialnumber`,                                   // VM のシリアルはベンダ接頭辞を持つ
		`wmic bios get smbiosbiosversion`,                              //
		`wmic baseboard get product,manufacturer`,                      // "Oracle Corporation VirtualBox"
		`wmic baseboard get product`,                                   // ' product' 単独。上は manufacturer でも当たるので分けて置く
		`wmic path win32_videocontroller get name | findstr /i vmware`, // クラスは対象外でも vmvendor 枝で拾う
		`wmic csproduct get uuid`,                                      // #753 で穴として残し、2026-08-14 に塞いだ分
		`wmic csproduct get identifyingnumber`,                         // VM のシリアル
		`wmic csproduct get vendor`,                                    // "VMware, Inc." 等
	} {
		if !firedWMICDiscovery(evalWMIC(cmd)) {
			t.Errorf("VM 判別が検知されなくなった: %q → %v", cmd, titles(evalWMIC(cmd)))
		}
	}
}

// TestT1497_RuleInventory は、この技法のルールが 3 本であることを固定する。
//
// T1552.003 では**同名別置きの 4 本目を取りこぼし**、狭めた直後の FP ソークで
// 新規アラートとして現れて初めて気づいた。同じ轍を踏まないよう、技法で横断的に
// 数えたうえで本数を固定する。技法の書き方は 2 通りある（builtin は YAML の
// `tags: attack.t1497`、migration 側は SQL の mitre_tags 列で本文には参照 URL のみ）
// ので、両方を見る。
func TestT1497_RuleInventory(t *testing.T) {
	want := map[string]bool{
		"Virtualization or Sandbox Discovery via WMIC Hardware Query": true, // windows / builtin
		"macOS Virtualization/Sandbox Discovery":                      true, // macOS / builtin
		"macOS Virtualization/Sandbox Evasion Checks":                 true, // macOS / builtin
	}

	got := map[string]bool{}
	collect := func(title, body string) {
		if isTechnique(body, "t1497", "T1497") {
			got[title] = true
		}
	}
	for _, y := range builtinSigmaRules {
		if m := ruleTitleRe.FindStringSubmatch(y); m != nil {
			collect(trimTitle(m[1]), y)
		}
	}
	for title, blk := range migrationSigmaBlocks(t) {
		collect(title, blk.body)
	}
	if len(got) == 0 {
		t.Fatal("対照が効いていない: T1497 のルールが 1 本も見つからない。検索が壊れている")
	}

	for title := range want {
		if !got[title] {
			t.Errorf("T1497 のルール %q が見つからない——削除したなら want からも外すこと", title)
		}
	}
	for title := range got {
		if !want[title] {
			t.Errorf("T1497 のルールが増えている: %q。"+
				"この技法は資産管理と語彙が重なり誤検知しやすいので、広い条件で足されて"+
				"いないか確認し、問題なければ want に追加すること"+
				"（沈黙テストも併せて更新する）", title)
		}
	}
}

// isTechnique は技法の 2 通りの書き方（YAML の attack.<slug> と、参照 URL の
// T####/### 形式）の両方を見る。片方だけ見ると取りこぼす——T1552.003 で実際に踏んだ。
func isTechnique(body, slug, id string) bool {
	return strings.Contains(strings.ToLower(body), "attack."+strings.ToLower(slug)) ||
		strings.Contains(body, strings.Replace(id, ".", "/", 1))
}

func trimTitle(s string) string { return strings.TrimSpace(s) }
