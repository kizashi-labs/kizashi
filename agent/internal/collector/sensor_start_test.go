package collector

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// 起動に失敗したセンサーが、成功を返す形。
//
//	func (c *ETWRegistryCollector) Start(ctx, out) error {
//	    if err := c.startETW(ctx); err != nil {
//	        slog.Warn("ETWレジストリ監視を開始できませんでした", "error", err)
//	        return nil          ← 呼び出し側は「起動した」と受け取ります
//	    }
//	    …
//	}
//
// **センサーが「入っている」と言い、入っていません。** Windows の ETW 系
// 7本がこの形でした。レジストリ・WMI・名前付きパイプ・スクリプトブロック・
// リモートスレッド・イメージロード・PowerShell モジュール —— living-off-
// the-land の検知が寄りかかっている面です。
//
// これがサーバから見てどうなるかが要点です。ETW の登録に失敗した端末は、
// 何も起きていない端末と**まったく同じ姿**をします。イベントが来ないので
// 一覧は短くならず、アラートも出ず、エージェントはハートビートを送り続け、
// 画面は緑のままです。**攻撃されていないことと、見えていないことの区別が
// つきません。**
//
// エージェントには報告する先があります —— internal/health.Reporter の
// SetCollectorStatus と、ハートビートに載る collector_status です。
// **本番からは一度も呼ばれていません**（`grep -v _test` で0件）。
// 劣化を伝える仕組みが作られていて、繋がっていません。
//
// この検査は数を固定するだけです。直し方（Start がエラーを返すのか、
// 劣化として報告して続けるのか）は運用に影響するので、
// docs/判断待ちの一覧.md に置いています。

// sensorNilOnFailure — `if err != nil { … return nil }` の形で、
// 関数が error を返すもの。ファイル:関数 で固定します。
//
// 行ではなくファイル:関数を鍵にするのは、行が編集で動くからです。
var sensorNilOnFailure = map[string]string{
	// 送信は失敗しているが、バッチはリングバッファに積み直してある。
	// **イベントは落ちていない**ので、呼び出し側が「送れた」と受け取って
	// 進んでよい。積むのにも失敗した場合はその error を返している
	// （すぐ上の分岐）。
	"internal/transport/grpc_client.go:SendEvents": "送信失敗はバッファに" +
		"積み直して吸収する。積めなかった場合だけ error を返す",
	"internal/platform/windows/registry_etw.go:Start": "ETW レジストリ監視。" +
		"開始できなくても成功を返します",
	"internal/platform/windows/wmi_etw.go:Start":       "ETW WMI 監視。同上",
	"internal/platform/windows/pipe_etw.go:Start":      "ETW 名前付きパイプ監視。同上",
	"internal/platform/windows/script_etw.go:Start":    "ETW スクリプトブロック監視。同上",
	"internal/platform/windows/thread_etw.go:Start":    "ETW リモートスレッド監視。同上",
	"internal/platform/windows/imageload_etw.go:Start": "ETW イメージロード監視。同上",
	"internal/platform/windows/psmodule_etw.go:Start":  "ETW PowerShell モジュール監視。同上",
	"internal/platform/darwin/auth_collector.go:Start": "macOS の log コマンドが無いとき。" +
		"コマンドが本当に無い環境はあるので、ここは劣化の報告が要ります",
	// device_collector_darwin.go:listDevices と
	// process_monitor_darwin.go:processListImpl はここにありました。
	// **どちらもエラーを返すようになったので、消しました。**
	// この検査が「もう成功を返していません」と言って落としました ——
	// 古い理由は、読んだ人にまだ壊れていると思わせます。
}

type sensorSite struct {
	key  string
	file string
	line int
	src  string
}

// returnsNilError reports whether ret puts nil where fn returns its error.
func returnsNilError(fn *ast.FuncDecl, ret *ast.ReturnStmt) bool {
	if fn.Type.Results == nil || len(ret.Results) == 0 {
		return false
	}
	pos, i := -1, 0
	for _, r := range fn.Type.Results.List {
		n := len(r.Names)
		if n == 0 {
			n = 1
		}
		if id, ok := r.Type.(*ast.Ident); ok && id.Name == "error" {
			pos = i
		}
		i += n
	}
	if pos < 0 || pos >= len(ret.Results) {
		return false
	}
	id, ok := ret.Results[pos].(*ast.Ident)
	return ok && id.Name == "nil"
}

// errChecked reports whether cond is an `err != nil` style test.
func errChecked(cond ast.Expr) bool {
	bin, ok := cond.(*ast.BinaryExpr)
	if !ok || bin.Op != token.NEQ {
		return false
	}
	lhs, ok := bin.X.(*ast.Ident)
	if !ok {
		return false
	}
	rhs, ok := bin.Y.(*ast.Ident)
	if !ok || rhs.Name != "nil" {
		return false
	}
	l := strings.ToLower(lhs.Name)
	return l == "err" || l == "e" || strings.HasSuffix(l, "err")
}

// findSensorSites walks root and returns every error-returning function whose
// `if err != nil` branch ends in a nil error.
//
// 走査は build tag を無視します。ETW のファイルはすべて `//go:build windows`
// なので、tag を尊重すると Linux の CI では**1件も見つからず、上限0が緑で
// 通ります。** parser はソースとして読むだけなので、この検査はどの OS でも
// 同じ数を返します。
func findSensorSites(t *testing.T, root string) []sensorSite {
	t.Helper()
	var out []sensorSite
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") ||
			strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		// **区切りは `/` に正規化する。** Windows の runner では
		// filepath.Rel が `internal\platform\windows\...` を返すため、
		// `platform/windows/` を探す下の検査が 1 件も見つけられず、
		// 「走査が build tag に引っかかっている」と誤報していた
		// （CI は 8/6 から発火しておらず、一度も走っていなかった）。
		rel = filepath.ToSlash(rel)
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				is, ok := n.(*ast.IfStmt)
				if !ok {
					return true
				}
				if !errChecked(is.Cond) {
					return true
				}
				for _, st := range is.Body.List {
					ret, ok := st.(*ast.ReturnStmt)
					if !ok || !returnsNilError(fn, ret) {
						continue
					}
					p := fset.Position(ret.Pos())
					out = append(out, sensorSite{
						key:  rel + ":" + fn.Name.Name,
						file: rel, line: p.Line,
						src: fn.Name.Name,
					})
				}
				return true
			})
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

// sensorProblems — 判定そのもの。測定値と理由リストだけで動きます。
func sensorProblems(sites []sensorSite, reasons map[string]string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range sites {
		seen[s.key] = true
		if _, ok := reasons[s.key]; !ok {
			out = append(out, fmt.Sprintf(
				"%s:%d %s が、失敗したのに nil (成功) を返しています。"+
					"呼び出し側はセンサーが動いていると受け取ります", s.file, s.line, s.src))
		}
	}
	for k := range reasons {
		if !seen[k] {
			out = append(out, fmt.Sprintf(
				"%s はもう成功を返していません。理由を消してください。"+
					"古い理由は、読んだ人にまだ壊れていると思わせます", k))
		}
	}
	sort.Strings(out)
	return out
}

func TestSensorsDoNotReportSuccessWhenTheyFailedToStart(t *testing.T) {
	sites := findSensorSites(t, "../..")
	if len(sites) < 5 {
		t.Fatalf("走査が届いていません: %d 箇所しか見つかりません", len(sites))
	}
	// build tag を尊重していないことの確認。Windows のファイルが見えて
	// いなければ、この検査は Linux では何も見ていません。
	var win bool
	for _, s := range sites {
		if strings.Contains(s.file, "platform/windows/") {
			win = true
		}
	}
	if !win {
		t.Fatal("Windows のファイルが1件も見つかりません。走査が build tag に" +
			"引っかかっています。この状態では Linux で常に緑になります")
	}
	for _, p := range sensorProblems(sites, sensorNilOnFailure) {
		t.Error(p)
	}
}

// 通常状態では上の判定は肯定側に入りません。直接動かします。
func TestTheSensorRuleFires(t *testing.T) {
	one := []sensorSite{{key: "a.go:Start", file: "a.go", line: 1, src: "Start"}}
	for _, c := range []struct {
		name    string
		sites   []sensorSite
		reasons map[string]string
		want    int
	}{
		{"理由あり", one, map[string]string{"a.go:Start": "なぜか"}, 0},
		{"理由なし", one, map[string]string{}, 1},
		{"理由が古い", nil, map[string]string{"a.go:Start": "なぜか"}, 1},
		{"両方ずれている", one, map[string]string{"b.go:Start": "なぜか"}, 2},
		{"どちらも空", nil, map[string]string{}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := sensorProblems(c.sites, c.reasons); len(got) != c.want {
				t.Errorf("問題 %d 件 (want %d): %v", len(got), c.want, got)
			}
		})
	}
}
