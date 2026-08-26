// このファイルに build tag を付けていないのは意図です。
//
// `//go:build windows` を付けると、Linux の CI では**1件も見えず、
// 検査は永久に緑**になります。中身は Windows のソースを文字として読む
// だけなので、どの OS でも走ります。sensor_start_test.go と同じ理由です。

package windows_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// ETW センサーの起動失敗が、黙って捨てられていないこと。
//
// 7本とも、失敗しても `slog.Warn` を1行書いて `return nil` していました。
// **サーバから見ると、その端末は何も起きていない端末とまったく同じ姿を
// します。** イベントが来ない、アラートも出ない、ハートビートは届く、
// 画面は緑。攻撃されていないことと、見えていないことの区別がつきません。
//
// いまは `etwSensorFailed` を通します。`internal/telemetry` に
// `ModeFailed` として記録され、ハートビートの `telemetry_mode` に載って
// サーバの `agents.telemetry_mode` に入ります。
//
// この検査が見るのは、**失敗の分岐がその報告を通っているか**だけです。
// 戻り値を変えるかどうか（Start がエラーを返すか）は運用の判断なので、
// ここでは見ません。

// etwSensors — 失敗を報告しなければならないファイルと、その面。
var etwSensors = map[string]string{
	"registry_etw.go":  "レジストリ改変（永続化）",
	"wmi_etw.go":       "WMI（永続化・横展開）",
	"pipe_etw.go":      "名前付きパイプ（C2・横展開）",
	"script_etw.go":    "スクリプトブロック（難読化 PowerShell）",
	"thread_etw.go":    "リモートスレッド生成（プロセスインジェクション）",
	"imageload_etw.go": "イメージロード（DLL サイドローディング）",
	"psmodule_etw.go":  "PowerShell モジュールログ",
}

// startFailureBranches returns, for one file, the if-error branches inside a
// Start method that end in `return nil`.
func startFailureBranches(t *testing.T, path string) []*ast.BlockStmt {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
	if err != nil {
		t.Fatalf("%s を読めません: %v", path, err)
	}

	var out []*ast.BlockStmt
	for _, decl := range f.Decls {
		fn, ok := decl.(*ast.FuncDecl)
		if !ok || fn.Name.Name != "Start" || fn.Body == nil {
			continue
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			ifs, ok := n.(*ast.IfStmt)
			if !ok || ifs.Body == nil {
				return true
			}
			// `if err := c.startETW(ctx); err != nil { … }` の形だけ。
			// 無効化の分岐 (`if !etwEnabled()`) は対象外です ——
			// あれは設定の選択で、失敗ではありません。
			if ifs.Init == nil {
				return true
			}
			endsInNil := false
			for _, st := range ifs.Body.List {
				ret, ok := st.(*ast.ReturnStmt)
				if !ok {
					continue
				}
				if len(ret.Results) == 1 {
					if id, ok := ret.Results[0].(*ast.Ident); ok && id.Name == "nil" {
						endsInNil = true
					}
				}
			}
			if endsInNil {
				out = append(out, ifs.Body)
			}
			return true
		})
	}
	return out
}

// calls reports whether a block calls the named function.
func calls(b *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(b, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// discoverETWFiles lists the *_etw.go files that actually have a Start method
// with a "failed, return nil" branch.
//
// **一覧を信じずに、ディレクトリから見つけます。** 一覧だけを回していた
// ときは、そこから1行消すだけで検査対象が6本に減り、**何も言わずに緑を
// 返しました**（変異で生き残りました）。ファイルを消す・改名する・
// 新しいセンサーを足す、のどれでも気づける形にします。
func discoverETWFiles(t *testing.T) map[string][]*ast.BlockStmt {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("ディレクトリを読めません: %v", err)
	}
	out := map[string][]*ast.BlockStmt{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, "_etw.go") ||
			strings.HasSuffix(name, "_test.go") {
			continue
		}
		if b := startFailureBranches(t, filepath.Join(".", name)); len(b) > 0 {
			out[name] = b
		}
	}
	return out
}

func TestEveryETWSensorReportsItsStartFailure(t *testing.T) {
	found := discoverETWFiles(t)

	// 走査が届いていること。**0件を検査して緑を返すのがいちばん高くつきます。**
	if len(found) < len(etwSensors) {
		t.Fatalf("失敗分岐を持つ *_etw.go が %d 個しか見つかりません（%d 本のはず）。"+
			"走査が届いていないか、センサーが消えました", len(found), len(etwSensors))
	}

	var missing []string
	for file, branches := range found {
		surface, listed := etwSensors[file]
		if !listed {
			t.Errorf("%s は Start の失敗分岐を持ちますが、etwSensors にありません。"+
				"新しいセンサーなら、どの面を見るのかを書いて足してください", file)
			surface = "(未記載)"
		}
		for _, b := range branches {
			if !calls(b, "etwSensorFailed") {
				missing = append(missing, file+"（"+surface+"）")
			}
		}
	}

	// 一覧が古くなっていないこと。直したセンサーの項目が残っていると、
	// **読んだ人はまだ壊れていると思います。**
	for file := range etwSensors {
		if _, ok := found[file]; !ok {
			t.Errorf("etwSensors に %s がありますが、実測に見当たりません。"+
				"消えた・改名したのなら一覧も直してください", file)
		}
	}

	if len(missing) > 0 {
		sort.Strings(missing)
		t.Errorf("起動に失敗しても、サーバに何も伝えないセンサーがあります。"+
			"その面は監視されていないのに、画面は緑のままです:\n  %s",
			strings.Join(missing, "\n  "))
	}
}

// ── 負の対照 ─────────────────────────────────────────────────────────────
//
// 判定を無効にする変異は、**違反する入力を食わせる検査でしか殺せません。**
// 実際に2件生き残りました。ここで合成したソースを通します。

func parseSource(t *testing.T, src string) *ast.File {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "x.go", src, 0)
	if err != nil {
		t.Fatalf("組み立てたソースを読めません: %v", err)
	}
	return f
}

func startBranchesOf(t *testing.T, src string) []*ast.BlockStmt {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "probe_etw.go")
	if err := os.WriteFile(path, []byte(src), 0o600); err != nil {
		t.Fatalf("書けません: %v", err)
	}
	_ = parseSource(t, src)
	return startFailureBranches(t, path)
}

const reportingSensor = `package windows

func (c *X) Start(ctx int) error {
	if err := c.startETW(ctx); err != nil {
		etwSensorFailed(sensorX, err)
		return nil
	}
	return nil
}
`

// 黙っているセンサー。**素の識別子で呼びます。**
//
// 最初は `slog.Warn(...)` にしていました。あれは SelectorExpr なので
// `calls` はもともと当たらず、**「何にでも当たる」ように壊しても結果が
// 変わりませんでした**（変異が生き残りました）。負の対照は、壊したときに
// 答えが変わる入力でなければ意味がありません。
const silentSensor = `package windows

func (c *X) Start(ctx int) error {
	if err := c.startETW(ctx); err != nil {
		warnOnly(err)
		return nil
	}
	return nil
}
`

func TestTheRuleFires(t *testing.T) {
	silent := startBranchesOf(t, silentSensor)
	if len(silent) != 1 {
		t.Fatalf("失敗分岐が %d 個。1個のはずです", len(silent))
	}
	if calls(silent[0], "etwSensorFailed") {
		t.Error("報告していない分岐を「報告している」と判定しました。" +
			"**この判定が壊れると、7本とも黙って通ります**")
	}

	reporting := startBranchesOf(t, reportingSensor)
	if len(reporting) != 1 {
		t.Fatalf("失敗分岐が %d 個。1個のはずです", len(reporting))
	}
	if !calls(reporting[0], "etwSensorFailed") {
		t.Error("報告している分岐を「していない」と判定しました。" +
			"逆向きに壊れると、直しても落ち続けます")
	}
}

// 無効化の分岐 (`if !etwEnabled() { return nil }`) を失敗として数えないこと。
// 数えると、7本とも「報告していない」と出て、**本物の違反が埋もれます。**
func TestTheDisabledBranchIsNotAFailure(t *testing.T) {
	const src = `package windows

func (c *X) Start(ctx int) error {
	if !etwEnabled() {
		return nil
	}
	if err := c.startETW(ctx); err != nil {
		etwSensorFailed(sensorX, err)
		return nil
	}
	return nil
}
`
	branches := startBranchesOf(t, src)
	if len(branches) != 1 {
		t.Errorf("失敗分岐が %d 個。無効化の分岐まで数えています", len(branches))
	}
}

// 報告の中身が、劣化として集約されること。
//
// `etwSensorFailed` が `ModeOff` を渡すようになると、`aggregate` は
// **設定の選択として無視します** —— 直す前とまったく同じ姿に戻り、
// しかもコードは「報告している」ように読めます。
func TestTheFailureIsRecordedAsFailedNotOff(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(".", "etw_status.go"))
	if err != nil {
		t.Fatalf("etw_status.go を読めません: %v", err)
	}
	src := string(b)
	if !strings.Contains(src, "telemetry.ModeFailed") {
		t.Error("etwSensorFailed が ModeFailed を使っていません。" +
			"ModeOff だと aggregate に無視され、報告した気になるだけです")
	}
	if strings.Contains(src, "telemetry.Set(sensor, telemetry.ModeOff") {
		t.Error("失敗を ModeOff として記録しています。" +
			"「無効にしてある」と「動かしたかったのに動いていない」は別です")
	}
}
