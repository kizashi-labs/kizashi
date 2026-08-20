package handlers

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

// 要求から離れる仕事が、テナントを落としていないこと。
//
// ## 何が起きるか
//
// ハンドラが `go func()` で続きを走らせるとき、`context.Background()` から
// 新しい ctx を作ります —— 要求の ctx は応答を返した時点で切れるからです。
// **そこでテナントが落ちます。**
//
// 落ちた ctx は `app.tenant_id` を張らないので、いまは RLS のエスケープ節
// が拾って**全テナントを見せます**:
//
//	テナント A が頼んだレポートに、B のアラートが入る
//	テナント A が始めた資産探索が、B の端末を数える
//
// **これは fail-closed 化を待たずに直すべき漏れです。** 抜け道を落とせば
// 0 行になって止まりますが、それは「止まる」であって「正しくなる」では
// ありません。
//
// ## この検査が留めること
//
// `context.Background()` / `context.TODO()` を使う関数を数え上げ、
// **全部が台帳にあること**だけを見ます。中で 4 表に触るかどうかまでは
// 追えません（store のメソッドを何段も経由します）ので、そこは人が
// 読んで理由を書きます。**新しく足したときに気づけること**が目的です。

// backgroundContexts は `context.Background()` を使う関数と、その扱いです。
//
// **`4 表に触りません` と書くときは、実際に読んでから書いてください。**
// 「調べていない」と「触らない」を同じ扱いにすると、抜け道を落とした
// ときに静かに壊れます。
var backgroundContexts = map[string]string{
	// ── テナントを持っていくもの ────────────────────────────
	"asset_discovery_handler.StartScan": "**要求のテナントを持っていきます。** " +
		"`agents` を数えるので、落とすと全テナントの端末を見ます",
	// Generate 自身は `context.Background()` を使いません（要求の ctx から
	// テナントを取り出して generateReport へ渡すだけ）。**台帳に書くのは
	// `context.Background()` を使う側だけです。**
	"reports_handler.generateReport": "**渡されたテナントを張ります。** " +
		"buildAlertSummary が alerts を、buildAgentStatus が agents を読みます",

	// ── 4 表に触らないもの（読んで確かめました）────────────
	"api_security_handler.StartScan":              "api_vulnerabilities のみ",
	"backup_handler.Create":                       "pg_dump を起動するだけ",
	"bas_handler.StartRun":                        "bas_runs のみ",
	"email_verification_handler.SendVerification": "メール送信。DB に触りません",
	"incidents_handler.Create":                    "soar_configs と外部の SOAR API のみ",
	"invitation_handler.Create":                   "メール送信。DB に触りません",
	"log_analysis_handler.CreateJob":              "audit_logs と log_analysis_jobs のみ",
	"password_reset_handler.RequestReset":         "メール送信。DB に触りません",
	"phishing_handler.CreateCampaign":             "phishing_recipients のみ",
	"rules_handler.SyncCommunity":                 "ルールの同期。4 表に触りません",
	"sandbox_handler.SubmitFile":                  "VirusTotal と sandbox_submissions のみ",
	"yara_handler.SyncStart":                      "ルールの同期。4 表に触りません",
	"uninstall_protection_handler.requestCtx":     "`c.Request` が nil のときの逃げ道。DB には使いません",
}

func backgroundContextFuncs(t *testing.T) []string {
	t.Helper()
	files, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}
	var found []string
	seen := map[string]bool{}
	for _, path := range files {
		if strings.HasSuffix(path, "_test.go") {
			continue
		}
		src, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("%s を読めません: %v", path, err)
		}
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, src, 0)
		if err != nil {
			t.Fatalf("%s: %v", path, err)
		}
		base := strings.TrimSuffix(filepath.Base(path), ".go")
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				pkg, ok := sel.X.(*ast.Ident)
				if !ok || pkg.Name != "context" {
					return true
				}
				if sel.Sel.Name != "Background" && sel.Sel.Name != "TODO" {
					return true
				}
				key := base + "." + fn.Name.Name
				if !seen[key] {
					seen[key] = true
					found = append(found, key)
				}
				return true
			})
		}
	}
	sort.Strings(found)
	return found
}

func TestEveryBackgroundContextIsAccountedFor(t *testing.T) {
	got := backgroundContextFuncs(t)
	if len(got) == 0 {
		t.Fatal("`context.Background()` を使う関数が1つも見つかりません。" +
			"**この検査は何も見ていません**")
	}
	for _, key := range got {
		if _, ok := backgroundContexts[key]; !ok {
			t.Errorf("%s が `context.Background()` を使っていますが、台帳に"+
				"ありません。**要求から離れた ctx はテナントを落とします** —— "+
				"4 表に触るなら store.WithTenant で持っていってください。"+
				"触らないなら、読んで確かめてから理由を書いてください", key)
		}
	}
}

// 逆向き。**消えた項目を残さない。**
//
// 残すと「直したのに台帳が古い」状態になり、次に読む人が実在しない
// 場所を探します。
func TestNoStaleBackgroundContextEntries(t *testing.T) {
	live := map[string]bool{}
	for _, key := range backgroundContextFuncs(t) {
		live[key] = true
	}
	var stale []string
	for key := range backgroundContexts {
		if !live[key] {
			stale = append(stale, key)
		}
	}
	sort.Strings(stale)
	for _, key := range stale {
		t.Errorf("%s を台帳に書いていますが、`context.Background()` を"+
			"使っていません。消してください", key)
	}
}

// **テナントを持っていくと書いた場所が、本当に持っていくこと。**
//
// 台帳の文言だけを直して配線を戻す、が起こりうるので、`store.WithTenant`
// が同じ関数にあることを見ます。
func TestTheOnesThatCarryTheTenantActuallyDo(t *testing.T) {
	carriers := []string{}
	for key, why := range backgroundContexts {
		if strings.Contains(why, "テナントを持っていきます") ||
			strings.Contains(why, "テナントを張ります") {
			carriers = append(carriers, key)
		}
	}
	sort.Strings(carriers)
	if len(carriers) == 0 {
		t.Fatal("テナントを持っていく項目が台帳に1つもありません。" +
			"**この検査は何も見ていません**")
	}

	for _, key := range carriers {
		parts := strings.SplitN(key, ".", 2)
		src, err := os.ReadFile(parts[0] + ".go")
		if err != nil {
			t.Errorf("%s: %v", key, err)
			continue
		}
		if !strings.Contains(string(src), "store.WithTenant(") &&
			!strings.Contains(string(src), "store.TenantFromContext(") {
			t.Errorf("%s は「テナントを持っていく」と書いてありますが、"+
				"%s.go に store.WithTenant も store.TenantFromContext も"+
				"ありません。**台帳の文言と配線がずれています**", key, parts[0])
		}
	}
}
