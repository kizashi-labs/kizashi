// このファイルに build tag を付けていないのは意図です。
// ソースを文字として読むだけなので、どの OS でも走ります。
// answered_with_a_value_test.go と同じ理由です。

package agentcontract

import (
	"fmt"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// 製品のロジックを**書き写した**検査ヘルパー —— の agent 側です。
//
// サーバ側に同じ見張りがあり（`server/internal/store/
// reproduced_logic_test.go`）、`server/internal` 全体で 40 → 0 に
// しました。**agent 側は 0 でした** —— 実測 (2026-08-12)、印を持つ
// コメントは1件だけで、それは写しではなく
// 「以前の懸念が再現する」という別の意味の文でした（言い換えました）。
//
// **0 だから見張らない、にはしません。** サーバ側で 40 件を作れた
// のと同じ手が agent 側でも使えます。ここは 0 から始めます。
//
// ── この見張りが見つけられないもの ──────────────────────────────
//
// **写しだと名乗っているものしか数えられません。** サーバ側の 40 件は
// たまたま全部が「再現する」「テスト専用」と自称していましたが、
// 何も書かずに本物と同じ判定を組み直した検査は、この数に入りません。
// 数が 0 であることは「自称する写しが無い」という意味で、
// 「写しが無い」という意味ではありません。
const agentReproducedHelperCeiling = 0

// **`internal/` だけにすると `cmd/` が落ちます。** 落ちたことは件数が
// 下がる形で現れるので、下がったことを「直った」と読み違えます。
const agentReproductionRoot = "../.."

// 写しだと名乗っている印。サーバ側と同じ語を使います。
//
// **片方だけ痩せると、その言い方で書かれた写しが数から消えます。**
// 揃っていることは testdata の見本ではなく、下の
// TestTheAgentMarkerListIsNotNarrowed が語そのものを確かめます。
var agentReproductionMarkers = []string{"テスト専用", "再現する", "テスト内ヘルパー"}

// **0件を検査して緑を返すのがいちばん高くつきます。**
// 上限が 0 なので、走査が空でも件数の判定は文句を言いません。
//
// 実測 (2026-08-12): 99 ファイル。**床は現在値より少し下に置きます** ——
// ぴったりにすると、検査を1本消しただけで落ちます。
//
// 判定を切り出してあるのは、`if scanned < 0` に潰す変異を殺せるように
// するためです（変異が生き残りました）。
const minAgentScan = 90

func agentScanReached(scanned, floor int) bool {
	return scanned >= floor
}

type agentReproduction struct {
	file string
	line int
	text string
}

func TestNoLogicIsReproducedInAgentTests(t *testing.T) {
	var found []agentReproduction
	scanned := 0
	fset := token.NewFileSet()

	err := filepath.WalkDir(agentReproductionRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		name := d.Name()
		if !strings.HasSuffix(name, "_test.go") {
			return nil
		}
		// この検査自身の説明が写しに数えられないようにします。
		if name == "reproduced_logic_test.go" {
			return nil
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		scanned++
		f, parseErr := parser.ParseFile(fset, path, src, parser.ParseComments)
		if parseErr != nil {
			t.Errorf("%s を解析できません: %v", path, parseErr)
			return nil
		}
		rel := filepath.ToSlash(strings.TrimPrefix(path, agentReproductionRoot+string(filepath.Separator)))
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if !hasAgentMarker(c.Text) {
					continue
				}
				found = append(found, agentReproduction{
					file: rel,
					line: fset.Position(c.Pos()).Line,
					text: strings.TrimSpace(strings.TrimPrefix(c.Text, "//")),
				})
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("走査できません: %v", err)
	}

	if !agentScanReached(scanned, minAgentScan) {
		t.Fatalf("走査が届いていません: %d ファイルしか見えません（床 %d）",
			scanned, minAgentScan)
	}

	if msg := agentReproductionComplaint(len(found), agentReproducedHelperCeiling); msg != "" {
		t.Error(msg)
		for _, r := range found {
			t.Logf("  %s:%d %s", r.file, r.line, r.text)
		}
		return
	}
	t.Logf("写したヘルパー: %d 件（上限どおり）、%d ファイルを走査", len(found), scanned)
}

// agentReproductionComplaint は上限の判定そのものです。
//
// **切り出してあるのは、判定を無効にする変異を殺せるようにするため**です。
// 判定が検査の中に埋まっていると、`if false` に潰しても違反する入力を
// 食わせられず、変異が生き残ります。
func agentReproductionComplaint(actual, ceiling int) string {
	if actual > ceiling {
		return fmt.Sprintf("製品のロジックを写した検査ヘルパーが %d から %d に"+
			"増えています。**写しを試しても、製品の側は無傷のまま壊せます**",
			ceiling, actual)
	}
	if actual < ceiling {
		return fmt.Sprintf("写しが %d まで減りました。上限を %d に下げてください。"+
			"**下げないと、次に増えた分がこの差に隠れます。**", actual, actual)
	}
	return ""
}

func hasAgentMarker(s string) bool {
	for _, m := range agentReproductionMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// 上限の判定が、両方向に効くこと。
func TestTheAgentReproductionCeilingComplainsBothWays(t *testing.T) {
	if msg := agentReproductionComplaint(5, 5); msg != "" {
		t.Errorf("上限ちょうどで文句を言っています: %s", msg)
	}
	if agentReproductionComplaint(6, 5) == "" {
		t.Error("**上限を超えても黙っています。** 増えた分が隠れます")
	}
	if agentReproductionComplaint(4, 5) == "" {
		t.Error("**上限を下回っても黙っています。** 下げないと、" +
			"次に増えた分がその差に隠れます")
	}
	if agentReproducedHelperCeiling < 0 {
		t.Fatal("上限が負です")
	}
}

// **印の一覧が痩せていないこと。**
//
// 上限が 0 なので、数え方を狭める変異は件数の判定では殺せません
// （0 のままです）。印そのものを確かめます。
func TestTheAgentMarkerListIsNotNarrowed(t *testing.T) {
	for _, marker := range []string{"テスト専用", "再現する", "テスト内ヘルパー"} {
		if !hasAgentMarker("// なにかを" + marker) {
			t.Errorf("印 %q を見つけられません。**狭めると、その言い方で"+
				"書かれた写しが数から消えます**", marker)
		}
	}
	if hasAgentMarker("// ふつうの注記") {
		t.Error("関係ない注記を写しに数えています")
	}
}

// 床の判定が効くこと。
func TestTheAgentScanFloorNoticesAnEmptyWalk(t *testing.T) {
	if agentScanReached(0, minAgentScan) {
		t.Error("**0 ファイルでも「届いた」と言っています。** 走査が壊れた日に、" +
			"写しが1つも無い姿と同じ緑を返します")
	}
	if agentScanReached(minAgentScan-1, minAgentScan) {
		t.Error("床を下回っても「届いた」と言っています")
	}
	if !agentScanReached(minAgentScan, minAgentScan) {
		t.Error("床ちょうどで「届いていない」と言っています")
	}
	if minAgentScan < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も通ります**")
	}
}
