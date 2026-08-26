package store

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

// store の公開関数のうち、本番コードからは誰も呼ばないもの。
//
// このキャンペーンでフロントエンドに掛けた「宛先がサーバに無い呼び出し」の
// 裏返しです。あちらは呼ぶ側が宙に浮いていました。こちらは呼ばれる側です
// —— **テストが「動く」と言っていて、動かす人がいない関数。**
//
// 見つかるものは2種類に分かれます。どちらも直し方が違うので、理由に
// どちらなのかを書きます。
//
//	写し   本番に同じことをする別の実装（多くは生 SQL）があり、store 側は
//	       使われていません。危ないのは「読んだ人が、そちらが動いていると
//	       思う」ことと、二つが黙って食い違うことです。実際に食い違って
//	       いました: session_handler.go は revoked_at も立てますが、
//	       SessionStore.Revoke は立てません。
//	不通   本番のどこにも同じことをする実装がありません。機能はリポジトリに
//	       あり、テストも通り、一度も走りません。
//
// 0 にはしていません。消すか繋ぐかは1件ずつの判断で、まとめて決められる
// ものではないからです。増える方向にだけ落とします。

// 実測値。減らしたらここも下げます（下回っても落ちます）。
const testOnlyCeiling = 137

// 誰も呼ばないもの。テストすらありません。
//
// 「テストからしか呼ばれない」より鋭い分類です。あちらは少なくとも
// 「動く」と言っている人がいます。こちらは誰も言っていません。
//
// 数ではなく一覧で固定します。新しく増えれば理由が無くて落ち、繋いだり
// 消したりすれば理由が古くなって落ちます。**どちらの向きにも落ちること**が
// 要点で、数字だけだと片方向にしか効きません。
var neverCalledReasons = map[string]string{
	// ここから下は公開版の生成器が足したものです。呼び出し元が
	// 有償機能の側にしか無く、それを同梱しないので届きません。
	"AutoResponseStore.ToggleRule":           "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（auto_response_store.go:227）。**本流では呼ばれています。**",
	"CommandStore.DeleteFile":                "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（rules.go:498）。**本流では呼ばれています。**",
	"CommandStore.EnqueueApplyPolicy":        "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（rules.go:543）。**本流では呼ばれています。**",
	"DiffSoftware":                           "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（software_diff_store.go:221）。**本流では呼ばれています。**",
	"NewIPBlockStore":                        "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（ip_block.go:29）。**本流では呼ばれています。**",
	"SoftwareDiffStore.PreviousSnapshot":     "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（software_diff_store.go:168）。**本流では呼ばれています。**",
	"SoftwareDiffStore.UpsertDiff":           "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（software_diff_store.go:190）。**本流では呼ばれています。**",
	"SuppressionStore.GetIsActive":           "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（suppressions.go:147）。**本流では呼ばれています。**",
	"SystemUpdatesStore.AppliedMigrations":   "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（system_updates_store.go:100）。**本流では呼ばれています。**",
	"SystemUpdatesStore.RecordCheckResult":   "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（system_updates_store.go:390）。**本流では呼ばれています。**",
	"UninstallProtectionStore.ClearGuard":    "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（uninstall_protection.go:145）。**本流では呼ばれています。**",
	"UninstallProtectionStore.ListAttempts":  "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（uninstall_protection.go:178）。**本流では呼ばれています。**",
	"UninstallProtectionStore.RecordAttempt": "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（uninstall_protection.go:155）。**本流では呼ばれています。**",
	"UninstallProtectionStore.SetGuard":      "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（uninstall_protection.go:116）。**本流では呼ばれています。**",
	"UninstallProtectionStore.TenantOfAgent": "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（uninstall_protection.go:66）。**本流では呼ばれています。**",
	"UserStore.CreateFromInvitation":         "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（users.go:205）。**本流では呼ばれています。**",
	"WebhookStore.UpdateEvents":              "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（webhooks.go:283）。**本流では呼ばれています。**",
	"WebhookStore.UpdateRetryPolicy":         "公開版では呼び出し元を同梱しないため、呼ぶ人がいません（webhooks.go:266）。**本流では呼ばれています。**",
	"AlertAssignRuleStore.FindMatch": "アラートの自動割り当て規則の照合。" +
		"呼び出し側がいません。**この関数の挙動については、" +
		"answered_with_a_value_test.go と skipped_row_test.go の理由リストが" +
		"「担当者が付かないだけ」と説明を書いています** — 動いていない関数への" +
		"注釈です。消すか繋ぐかの判断が要ります",
	"AgentPolicyStore.GetForGroup": "グループ単位のポリシー取得。呼び出し側がおらず、" +
		"crud_coverage_test.go のコメントは column reference id is ambiguous で" +
		"落ちると書いています。**壊れていて、誰も呼びません。**",
}

type storeSym struct {
	name string
	recv string
	file string
	line int
}

// exportedStoreSymbols returns exported funcs and methods declared in this
// package (production files only).
func exportedStoreSymbols(t *testing.T) []storeSym {
	t.Helper()
	fset := token.NewFileSet()
	var out []storeSym
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("store ディレクトリを読めません: %v", err)
	}
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, n, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", n, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || !fn.Name.IsExported() {
				continue
			}
			recv := ""
			if fn.Recv != nil && len(fn.Recv.List) == 1 {
				switch rt := fn.Recv.List[0].Type.(type) {
				case *ast.StarExpr:
					if id, ok := rt.X.(*ast.Ident); ok {
						recv = id.Name
					}
				case *ast.Ident:
					recv = rt.Name
				}
			}
			out = append(out, storeSym{
				name: fn.Name.Name, recv: recv, file: n,
				line: fset.Position(fn.Pos()).Line,
			})
		}
	}
	return out
}

// identsUnder collects every identifier and selector name used in Go files
// under root, choosing production or test files.
//
// 識別子は AST から取ります。正規表現で `\.Name\(` のような形を探すと、
// メソッド値・インターフェース越し・改行を挟んだ呼び出しが漏れ、
// **漏れた分が「誰も呼んでいない」として数に出ます。** 走査を狭くすると、
// 違反が増えて見えるほうへ倒れます。
func identsUnder(t *testing.T, root string, tests bool, skip func(string) bool) map[string]bool {
	t.Helper()
	out := map[string]bool{}
	fset := token.NewFileSet()
	err := filepath.Walk(root, func(path string, info os.FileInfo, werr error) error {
		if werr != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		if strings.HasSuffix(path, ".pb.go") || strings.Contains(path, "/gen/") ||
			strings.Contains(path, "/vendor/") {
			return nil
		}
		if strings.HasSuffix(path, "_test.go") != tests {
			return nil
		}
		if skip != nil && skip(path) {
			return nil
		}
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// **黙って飛ばすと、その file は走査から消えます。**
			return perr
		}
		add := func(n ast.Node) {
			if n == nil {
				return
			}
			ast.Inspect(n, func(x ast.Node) bool {
				// SelectorExpr の分岐は置いていません。ast.Inspect は
				// `x.Foo` の Foo も *ast.Ident として訪れるので、書いても
				// 何も変わりません — 変異させて生き残ったので消しました。
				// **効いていない判定は、効いているように読めます。**
				if id, ok := x.(*ast.Ident); ok {
					out[id.Name] = true
				}
				return true
			})
		}
		for _, d := range f.Decls {
			// 宣言そのものの名前は「使用」に数えません。
			//
			// **最初これを数えていました。** すると store の中で宣言された
			// 名前はすべて「store の中で使われている」に落ち、「誰も呼ばない」
			// の分岐は構造上たどり着けなくなります。上限0は「0件だった」では
			// なく「数える経路が無かった」でした —— continue の上限0でまったく
			// 同じことが起きたのを直したばかりです。
			if fn, ok := d.(*ast.FuncDecl); ok {
				// nil はここで弾きます。ast.Node に包んだ (*ast.FieldList)(nil)
				// はインターフェースとしては nil ではないので、add の中の
				// `n == nil` では捕まりません。
				if fn.Recv != nil {
					add(fn.Recv)
				}
				if fn.Type != nil {
					add(fn.Type)
				}
				if fn.Body != nil {
					add(fn.Body)
				}
				continue
			}
			add(d)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	return out
}

func storeDir() string {
	abs, err := filepath.Abs(".")
	if err != nil {
		return ""
	}
	return abs
}

func inStore(path string) bool {
	abs, err := filepath.Abs(path)
	if err != nil {
		return false
	}
	return strings.HasPrefix(abs, storeDir())
}

func qualify(s storeSym) string {
	if s.recv != "" {
		return s.recv + "." + s.name
	}
	return s.name
}

// neverCalledProblems — 判定そのもの。測定値を渡すだけで動きます。
//
// 切り出したのは、木がきれいなあいだ両方のループが一度も回らないからです。
// 「古い理由を言わなくなる」変異が生き残ったのがそれで、**判定を消しても、
// 消したことが分かる入力が無い**状態でした。下の表が直接動かします。
func neverCalledProblems(measured map[string]storeSym,
	reasons map[string]string) []string {
	var out []string
	for q, s := range measured {
		if _, ok := reasons[q]; !ok {
			out = append(out, fmt.Sprintf(
				"%s (%s:%d) を呼ぶ人がいません。テストもありません。"+
					"繋ぐか消すか、それとも残す理由があるのかを "+
					"neverCalledReasons に書いてください", q, s.file, s.line))
		}
	}
	for q := range reasons {
		if _, ok := measured[q]; !ok {
			out = append(out, fmt.Sprintf(
				"neverCalledReasons の %s は、もう「誰も呼ばない」ではありません。"+
					"項目を消してください。**古い理由は、読んだ人にまだ壊れていると"+
					"思わせます**", q))
		}
	}
	sort.Strings(out)
	return out
}

// 通常状態では上の2つのループは一度も回りません。直接動かします。
func TestTheReachabilityRuleFires(t *testing.T) {
	one := map[string]storeSym{"A.B": {name: "B", recv: "A", file: "x.go", line: 1}}
	for _, c := range []struct {
		name     string
		measured map[string]storeSym
		reasons  map[string]string
		want     int
	}{
		{"理由あり", one, map[string]string{"A.B": "なぜか"}, 0},
		{"理由なし", one, map[string]string{}, 1},
		{"理由が古い", map[string]storeSym{}, map[string]string{"A.B": "なぜか"}, 1},
		{"両方ずれている", one, map[string]string{"C.D": "なぜか"}, 2},
		{"どちらも空", map[string]storeSym{}, map[string]string{}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := neverCalledProblems(c.measured, c.reasons); len(got) != c.want {
				t.Errorf("問題 %d 件 (want %d): %v", len(got), c.want, got)
			}
		})
	}
}

// TestStoreSymbolsAreReachable — 呼ばれる側が宙に浮いていないこと。
func TestStoreSymbolsAreReachable(t *testing.T) {
	syms := exportedStoreSymbols(t)
	if len(syms) < 200 {
		t.Fatalf("走査が届いていません: 公開シンボルが %d 件しか見つかりません", len(syms))
	}

	// 本番コード（store の外）。
	outside := identsUnder(t, "../..", false, inStore)
	// store の中の本番コード。
	inside := identsUnder(t, ".", false, nil)
	// テスト（server 全体）。
	fromTests := identsUnder(t, "../..", true, nil)

	// 走査が本当に届いているかの負の対照。誰でも知っている到達点が
	// 「呼ばれていない」に落ちるなら、判定ではなく走査が壊れています。
	for _, known := range []string{"Connect", "NewAlertStore", "ListAlerts"} {
		if !outside[known] {
			t.Fatalf("%s が本番コードから見つかりません。走査が届いていません", known)
		}
	}

	var testOnly, neverCalled []storeSym
	for _, s := range syms {
		switch {
		case outside[s.name]:
			// 本番コードが store の外から呼んでいます。
		case fromTests[s.name]:
			testOnly = append(testOnly, s)
		case inside[s.name]:
			// store の中だけで使う公開関数。動いてはいます。
		default:
			// 誰も呼びません。テストもありません。
			//
			// **最初この分岐が無く、ここに落ちるものを黙って捨てていました。**
			// いちばん鋭い種類 —— 呼ぶ人も、動くと言う人もいない関数 —— が、
			// 判定から丸ごと消えていたわけです。この一連の作業が扱っている
			// 見落としを、それを測る道具の中で自分でやっていました。
			neverCalled = append(neverCalled, s)
		}
	}
	byName := func(a []storeSym) {
		sort.Slice(a, func(i, j int) bool { return a[i].name < a[j].name })
	}
	byName(testOnly)
	byName(neverCalled)

	measured := map[string]storeSym{}
	for _, s := range neverCalled {
		measured[qualify(s)] = s
	}
	for _, p := range neverCalledProblems(measured, neverCalledReasons) {
		t.Error(p)
	}

	// **落ちていなくても一覧を出す。** 数だけだと「どれが増えたのか」が
	// 落ちたときにしか分からず、2 つの木（本流と公開版スナップショット）の
	// 差を取ることもできない。公開版の生成器はこの一覧の差分で、
	// 同梱しなかったせいでこちら側に回った記号を特定している。
	//
	// 言い回しに注意。この説明に `reproduced_logic_test.go` の目印
	// （製品のロジックの写しを指す語）を含めると、あちらの上限 0 に
	// 引っかかって落ちる。**実際に一度踏んだ。**
	var where []string
	for _, s := range testOnly {
		q := s.name
		if s.recv != "" {
			q = s.recv + "." + s.name
		}
		where = append(where, fmt.Sprintf("%s  %s:%d", q, s.file, s.line))
	}
	// 1 行ずつ出すのは、改行を含む一行ログより機械が読みやすいため。
	t.Logf("テスト専用の store の公開関数 %d 件", len(testOnly))
	for _, w := range where {
		t.Logf("  テスト専用: %s", w)
	}

	if n := len(testOnly); n != testOnlyCeiling {
		if n > testOnlyCeiling {
			t.Errorf("テストからしか呼ばれない store の公開関数が %d から %d に増えています。"+
				"写し（本番に別実装がある）なら消してください。不通（どこにも実装が無い）なら"+
				"繋いでください:\n  %s",
				testOnlyCeiling, n, strings.Join(where, "\n  "))
		} else {
			t.Errorf("テストからしか呼ばれない store の公開関数が %d まで減りました。"+
				"testOnlyCeiling を %d に下げてください", n, n)
		}
	}
}
