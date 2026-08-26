package isolation

import (
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// 隔離経路の集約が守られているかを機械的に確かめる。
//
// このテストが存在する理由は、経路を 1 つずつ塞ぐ試みが 3 回失敗したこと。
// detection のルールベース経路に安全弁を入れ（#729）、プレイブック経路が
// 素通しだと分かり、最後に修復エンジンが NATS へ直接 publish していて実機で
// 端末を隔離した。毎回「これで全部」と考えていて、毎回そうではなかった。
//
// 人が気をつけることでは足りない。新しい経路が増えたときに落ちるものが要る。

// 隔離コマンドを NATS へ送出してよい場所。
//
// store.CommandStore が唯一の送出口で、cmd/ingestion はその購読側。
// ここを増やすときは、なぜ Gatekeeper を通せないのかを PR に書くこと。
var allowedDispatchFiles = map[string]bool{
	filepath.Join("internal", "store", "rules.go"): true,
	filepath.Join("cmd", "ingestion", "main.go"):   true,
}

// CommandStore の隔離メソッドを直接呼んでよい場所。
//
// Gatekeeper を経由しない呼び出しは、response_actions への記録と安全弁の両方を
// 飛ばす。実際にそれで起きたのが 2026-08-13 の事故。
var allowedCommanderCallers = map[string]bool{
	filepath.Join("internal", "isolation", "isolation.go"): true,
	filepath.Join("internal", "store", "rules.go"):         true,
}

var (
	// commands.<agent>.isolate / .unisolate の組み立て。
	// 文字列連結と fmt.Sprintf の両方を拾う。
	//
	// (?:un)? であって un? ではない。後者は「u に n が続くかもしれない」という
	// 意味で .isolate に一致せず、実際に事故を起こした
	// fmt.Sprintf("commands.%s.isolate", ...) を素通ししていた。
	// TestGateCatchesTheHistoricalBypass がこれを捕まえた。
	dispatchSubjectRe = regexp.MustCompile(`"commands\.[^"]*\.(?:un)?isolate|\.(?:un)?isolate"`)
	// CommandSender の隔離メソッド呼び出し。
	commanderCallRe = regexp.MustCompile(`\.(Isolate|Unisolate)Endpoint\(`)
)

// serverGoFiles walks the server module and yields non-test .go files,
// as paths relative to the module root.
func serverGoFiles(t *testing.T) map[string]string {
	t.Helper()
	root := filepath.Join("..", "..")
	out := map[string]string{}
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// vendor と生成物は対象外。
			if name := d.Name(); name == "vendor" || name == "testdata" || name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		out[rel] = string(b)
		return nil
	})
	if err != nil {
		t.Fatalf("walk server module: %v", err)
	}
	if len(out) < 200 {
		t.Fatalf("走査できた .go が %d 本しかない。walk が壊れている疑いがある"+
			"（少なすぎる走査は「違反ゼロ」に見えてしまう）", len(out))
	}
	return out
}

// 隔離コマンドを NATS へ直接送出している場所が増えていないこと。
func TestNoUnauthorisedIsolationDispatch(t *testing.T) {
	for rel, src := range serverGoFiles(t) {
		if allowedDispatchFiles[rel] {
			continue
		}
		if loc := dispatchSubjectRe.FindString(src); loc != "" {
			t.Errorf("%s が隔離コマンドを直接組み立てている（%q）。\n"+
				"隔離は internal/isolation.Gatekeeper を経由すること。"+
				"直接送出は response_actions への記録と安全弁の両方を飛ばす。\n"+
				"どうしても必要なら allowedDispatchFiles に追加し、理由を PR に書くこと。",
				rel, loc)
		}
	}
}

// CommandStore の隔離メソッドを Gatekeeper 以外から呼んでいないこと。
func TestNoUnauthorisedCommanderCall(t *testing.T) {
	for rel, src := range serverGoFiles(t) {
		if allowedCommanderCallers[rel] {
			continue
		}
		if loc := commanderCallRe.FindString(src); loc != "" {
			t.Errorf("%s が %s を直接呼んでいる。\n"+
				"隔離は internal/isolation.Gatekeeper を経由すること。",
				rel, strings.TrimSuffix(loc, "("))
		}
	}
}

// ゲート自身が、実際に起きた欠陥を捕まえられること。
//
// 「違反ゼロ」を報告するテストは、検出できないだけでも同じ結果を出す。
// 2026-08-13 に端末を隔離した remediation/engine.go の元コードと、正しい
// 送出口である store/rules.go の書き方を、両方とも拾えることを確かめる。
// ここが落ちたら、上の 2 つのテストは何も守っていない。
func TestGateCatchesTheHistoricalBypass(t *testing.T) {
	for _, tc := range []struct {
		name string
		src  string
	}{
		{"remediation が使っていた fmt.Sprintf 形式",
			"subject := fmt.Sprintf(\"commands.%s.isolate\", agentID)"},
		{"解除側も同じ形",
			"subject := fmt.Sprintf(\"commands.%s.unisolate\", agentID)"},
		{"store が使っている文字列連結形式",
			"return s.nc.Publish(\"commands.\"+agentID+\".isolate\", data)"},
		{"連結形式の解除",
			"return s.nc.Publish(\"commands.\"+agentID+\".unisolate\", data)"},
	} {
		if !dispatchSubjectRe.MatchString(tc.src) {
			t.Errorf("%s を検出できない: %q", tc.name, tc.src)
		}
	}

	// 無関係な行を拾わないこと。誤検出が続くと allowlist が膨らみ、
	// 最後には本物の違反も許可された場所に紛れる。
	for _, benign := range []string{
		`case "isolate":`,
		`ActionType: "isolate",`,
		`slog.Info("endpoint isolated", "agent", agentID)`,
	} {
		if dispatchSubjectRe.MatchString(benign) {
			t.Errorf("無関係な行を検出している: %q", benign)
		}
	}

	if !commanderCallRe.MatchString("h.Commander.IsolateEndpoint(ctx, id, reason, \"\", actionID)") {
		t.Error("CommandStore の直接呼び出しを検出できない")
	}
	if !commanderCallRe.MatchString("e.commander.UnisolateEndpoint(ctx, agentID, reason, \"\")") {
		t.Error("解除側の直接呼び出しを検出できない")
	}
}

// 状態語彙が store 側とずれていないこと。
//
// isolation は import の向きを保つために store の定数を参照していない。
// 参照しない代わりに、ずれたら落ちるようにしておく。
func TestStatusVocabularyMatchesStore(t *testing.T) {
	src, err := os.ReadFile(filepath.Join("..", "store", "response_actions.go"))
	if err != nil {
		t.Fatalf("read store/response_actions.go: %v", err)
	}
	for _, want := range []string{statusPending, statusDispatched, statusFailure, statusSuppressed} {
		if !strings.Contains(string(src), `"`+want+`"`) {
			t.Errorf("status %q が store/response_actions.go に無い。"+
				"語彙がずれると CHECK 制約違反で記録だけが静かに落ちる", want)
		}
	}
}

// migration 431 が 'suppressed' を CHECK に入れていること。
//
// 定数だけ足して CHECK を忘れると、抑止の記録が全て 23514 で落ちる。
// そして記録の失敗はログに出るだけなので、隔離は動いているように見える。
func TestSuppressedStatusIsAllowedByMigration(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("..", "..", "migrations",
		"431_response_actions_suppressed_status.sql"))
	if err != nil {
		t.Fatalf("read migration 431: %v", err)
	}
	if !strings.Contains(string(b), "'suppressed'") {
		t.Error("migration 431 が 'suppressed' を CHECK 制約に入れていない")
	}
}
