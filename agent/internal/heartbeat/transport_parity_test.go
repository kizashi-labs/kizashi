package heartbeat

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"
)

// **ハートビートの応答には経路が2つあり、運ぶものが違っていました。**
//
// `FallbackSender` は gRPC を先に試し、失敗したら HTTP に落ちます。
// つまり**同じ応答型が、経路によって別のものを運びます** —— そして
// それを突き合わせるものが、どこにもありませんでした。
//
// 実測 (2026-08-12)、`ShouldIsolate` を足す前:
//
//	フィールド              サーバ gRPC  端末 gRPC  サーバ HTTP  端末 HTTP
//	ConfigUpdateAvailable   ✗            ✓          ✗            ✗
//	LatestConfigVersion     ✗            ✓          ✗            ✗
//	PendingCommandCount     ✗            ✓          ✗            ✗
//	ShouldUnisolate         ✗            ✗          ✓            ✓
//
// **`ShouldUnisolate` は HTTP にしか無く**、gRPC が生きている通常時は
// 端末に届いていませんでした（直したのが前のコミットです）。
//
// **上の3つは、どのサーバも設定していませんでした。** 埋める先もあり
// ません —— コマンドは NATS から EventStream 経由で押し出す設計で
// 数えるキューが無く、設定は `GetConfig` が版 1 を固定で返すだけです。
// **この系が採っていない方式（端末が取りに行く形）の名残**だったので、
// 消しました (2026-08-12)。proto は触っていません。
//
// いまは 2 フィールドで、**理由つきの例外は0件**です。
//
// この検査は表そのものを留めます。**片側だけ足したら落ちます。**

const (
	respTypeFile = "heartbeat.go"
	httpReadFile = "http_sender.go"
	grpcReadFile = "../transport/grpc_client.go"
	httpSetFile  = "../../../server/internal/api/handlers/agents_handler.go"
	grpcSetFile  = "../../../server/internal/ingestion/handler.go"
)

// parity is what the two transports do with one field.
type parity struct {
	field                string
	httpRead, grpcRead   bool
	httpWrite, grpcWrite bool
}

func (p parity) String() string {
	return fmt.Sprintf("%s(端末 http=%v grpc=%v / サーバ http=%v grpc=%v)",
		p.field, p.httpRead, p.grpcRead, p.httpWrite, p.grpcWrite)
}

// **両方の経路が運ぶべきフィールド。** ここに無いものは理由が要ります。
//
// **いまは空です。空であることが規則です** —— 片方の経路にしか無い
// フィールドは、`FallbackSender` が gRPC を先に試す以上、「届く条件」と
// 「届かない条件」を作ります。理由を書くくらいなら、両方に足すか、
// 消すかのどちらかです。
var parityExceptions = map[string]string{}

func responseFields(t *testing.T) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, respTypeFile, nil, 0)
	if err != nil {
		t.Fatalf("%s を parse できません: %v", respTypeFile, err)
	}
	var out []string
	ast.Inspect(f, func(n ast.Node) bool {
		ts, ok := n.(*ast.TypeSpec)
		if !ok || ts.Name.Name != "HeartbeatResponse" {
			return true
		}
		st, ok := ts.Type.(*ast.StructType)
		if !ok {
			return true
		}
		for _, fld := range st.Fields.List {
			for _, name := range fld.Names {
				out = append(out, name.Name)
			}
		}
		return false
	})
	sort.Strings(out)
	return out
}

func mentions(t *testing.T, path, needle string) bool {
	t.Helper()
	src, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s を読めません: %v", path, err)
	}
	// **コメントは落とします。** 説明の中の名前を「運んでいる」と
	// 読み違えないためです。
	var code strings.Builder
	for _, line := range strings.Split(string(src), "\n") {
		if i := strings.Index(line, "//"); i >= 0 {
			line = line[:i]
		}
		code.WriteString(line)
		code.WriteByte('\n')
	}
	return strings.Contains(code.String(), needle)
}

// jsonKey turns ShouldIsolate into should_isolate.
func jsonKey(field string) string {
	var b strings.Builder
	for i, r := range field {
		if r >= 'A' && r <= 'Z' {
			if i > 0 {
				b.WriteByte('_')
			}
			b.WriteRune(r + 32)
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func transportParity(t *testing.T) []parity {
	t.Helper()
	var out []parity
	for _, f := range responseFields(t) {
		key := jsonKey(f)
		out = append(out, parity{
			field:     f,
			httpRead:  mentions(t, httpReadFile, f),
			grpcRead:  mentions(t, grpcReadFile, f),
			httpWrite: mentions(t, httpSetFile, `"`+key+`"`),
			grpcWrite: mentions(t, grpcSetFile, "x-edr-"+strings.ReplaceAll(key, "_", "-")),
		})
	}
	return out
}

// parityProblems is the judgement, apart from the scan because on a passing
// tree it never pushes.
func parityProblems(rows []parity, exceptions map[string]string) []string {
	var out []string
	for _, r := range rows {
		if _, excused := exceptions[r.field]; excused {
			continue
		}
		if !r.httpRead || !r.grpcRead || !r.httpWrite || !r.grpcWrite {
			out = append(out, fmt.Sprintf(
				"%s が片方の経路にしかありません。**`FallbackSender` は "+
					"gRPC を先に試すので、片側だけだと、届く条件と届かない"+
					"条件が入れ替わります**", r))
		}
	}
	sort.Strings(out)
	return out
}

// staleParityExceptions — 消えたフィールドの理由。
func staleParityExceptions(rows []parity, exceptions map[string]string) []string {
	seen := map[string]bool{}
	for _, r := range rows {
		seen[r.field] = true
	}
	var out []string
	for f := range exceptions {
		if !seen[f] {
			out = append(out, f)
		}
	}
	sort.Strings(out)
	return out
}

// 実測 (2026-08-12): 5 → どのサーバも設定していなかった3つを消して 2。
//
// main 取り込みで `UninstallGuard` が入って 3。**取り込んだ時点では
// HTTP にしか無く、この検査が落ちました** —— `FallbackSender` は gRPC を
// 先に試すので、gRPC が生きている通常時（つまりほぼ全ての端末）に保護
// 設定は一度も届きません。アンインストールの検証は通信が切れた状態でも
// 走るため、必要になってから取りに行くことはできず、事前に置いてある
// ことが前提の機能です。gRPC 側にも載せて 4 経路すべてを埋めました。
const heartbeatResponseFields = 3

func TestBothTransportsCarryTheSameHeartbeatResponse(t *testing.T) {
	rows := transportParity(t)
	if len(rows) != heartbeatResponseFields {
		t.Errorf("`HeartbeatResponse` のフィールドが %d 個です"+
			"（留めているのは %d）", len(rows), heartbeatResponseFields)
	}
	for _, p := range parityProblems(rows, parityExceptions) {
		t.Error(p)
	}
	for _, f := range staleParityExceptions(rows, parityExceptions) {
		t.Errorf("%s の理由が残っていますが、そのフィールドはもうありません",
			f)
	}
	for _, r := range rows {
		t.Logf("%s", r)
	}
	if len(parityExceptions) != 0 {
		t.Errorf("理由つきの例外が %d 件あります。**片方の経路にしか"+
			"無いフィールドは、届く条件と届かない条件を作ります** —— "+
			"両方に足すか、消すかのどちらかにしてください: %v",
			len(parityExceptions), parityExceptions)
	}
}

// 判定と鍵の作り方が動くこと。通る木では何も push しません。
func TestTheParityRuleActuallyFires(t *testing.T) {
	full := parity{field: "X", httpRead: true, grpcRead: true, httpWrite: true, grpcWrite: true}
	if got := parityProblems([]parity{full}, nil); len(got) != 0 {
		t.Errorf("両方揃っているのに %d 件挙げています: %v", len(got), got)
	}
	for _, c := range []struct {
		name string
		p    parity
	}{
		{"端末 http が読まない", parity{field: "X", grpcRead: true, httpWrite: true, grpcWrite: true}},
		{"端末 grpc が読まない", parity{field: "X", httpRead: true, httpWrite: true, grpcWrite: true}},
		{"サーバ http が設定しない", parity{field: "X", httpRead: true, grpcRead: true, grpcWrite: true}},
		{"サーバ grpc が設定しない", parity{field: "X", httpRead: true, grpcRead: true, httpWrite: true}},
	} {
		if got := parityProblems([]parity{c.p}, nil); len(got) != 1 {
			t.Errorf("%s: %d件 (want 1)", c.name, len(got))
		}
	}
	if got := parityProblems([]parity{{field: "X"}}, map[string]string{"X": "理由"}); len(got) != 0 {
		t.Errorf("理由のあるものを挙げています: %v", got)
	}
	if got := staleParityExceptions([]parity{{field: "X"}}, map[string]string{"Y": "理由"}); len(got) != 1 {
		t.Errorf("消えたフィールドの理由を挙げていません: %v", got)
	}

	for _, c := range []struct{ in, want string }{
		{"ShouldIsolate", "should_isolate"},
		{"ConfigUpdateAvailable", "config_update_available"},
		{"PendingCommandCount", "pending_command_count"},
	} {
		if got := jsonKey(c.in); got != c.want {
			t.Errorf("jsonKey(%s) = %s, want %s", c.in, got, c.want)
		}
	}
}

// 走査が本物を読めていること。**5 つとも false なら、片側だけの
// フィールドも「両方に無い」で揃って見えます。**
func TestTheParityScanReadsRealFiles(t *testing.T) {
	rows := transportParity(t)
	byName := map[string]parity{}
	for _, r := range rows {
		byName[r.field] = r
	}
	for _, f := range []string{"ShouldIsolate", "ShouldUnisolate"} {
		r, ok := byName[f]
		if !ok {
			t.Errorf("%s が見つかりません", f)
			continue
		}
		if !r.httpRead || !r.grpcRead || !r.httpWrite || !r.grpcWrite {
			t.Errorf("%s を読めていません: %s", f, r)
		}
	}
	// コメントの中の名前を数えないこと。
	if mentions(t, respTypeFile, "この行は絶対に無い文字列") {
		t.Error("在りもしない文字列を見つけています")
	}
}
