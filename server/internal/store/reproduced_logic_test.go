package store_test

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

// 検査ファイルの中に、製品のロジックを**書き写した**ヘルパーが並んでいます。
//
//	// hasRolePure は HasRole メソッドの純粋なロジック部分を再現する
//	// ヘルパー（テスト専用）
//
// **写しを試しても、製品の側は無傷のまま壊せます。** 実測 (2026-08-11):
// `HasRole` の `>=` を `<=` に変えても、落ちる検査は1本もありませんでした
// —— viewer が tenant_admin の要件を満たし、tenant_admin が満たさなくなる、
// 権限判定のまるごとの反転です。
//
// もう1つの形があります。**製品にその規則が無いのに、検査だけが持って
// いる**場合です:
//
//	// incident_comments.go はDB依存のみのため、コメント本文の制約
//	// ロジックをテスト内ヘルパーとして定義する。
//
// このとき検査は「空白のみのコメントは無効」と言い、製品はそれを受け
// 入れます。**検査が緑であることが、その規則があることの証拠になりません。**
//
// ここは数を留めるだけです。**増えたら落ちます。減ったら下げてください**
// —— 下げないと、次に増えた分がその差に隠れます。
//
// 直し方は2つです:
//
//   - 製品側に純粋関数を切り出して、検査はそれを呼ぶ
//     （`RoleAtLeast` がその形にしました）
//   - 製品にその規則を足す
//     （コメント本文の上限は `internal/api/handlers` に足しました）
//
// **写しを消すだけにしないでください。** 消すと、そのロジックを試して
// いる検査が1本も無くなります。

// 実測です。
//
// **最初に数えたときは 13 でした。それは「テスト専用」という文字列だけを
// 数えていたからです。** 「再現する」「テスト内ヘルパー」と名乗っている
// ものを足したら 40 ありました。数え方を狭めると、数字は小さく、正しく
// 見えます。
//
// このうち2つを片付けて 38 です:
//
//   - `hasRolePure` → 製品側に `roleAtLeast` を切り出して、そちらを呼ぶ形に
//   - `isValidCommentBody` → 製品に規則が無かったので、規則の方を
//     `internal/api/handlers` に足した
//
// さらに3つ片付けて 35 です:
//
//   - `applyPrefsDefaults` → 製品側に `applyPreferenceDefaults` を切り出した
//   - `calcNotificationStats` → 集計は SQL の中なので、**Go の写しでは
//     何も試せません。** 本物の問い合わせを当てる検査に置き換えた
//   - `buildNotificationFilter` → 本物は handler にあり、**値が違いました**
//     （既定 20 対 50）。`clampNotificationPage` を切り出して、そちらを試す
//
// WHERE 句の組み立て3つを片付けて 32 です。**そのうち2つは、写しの方が
// 古くなっていました** —— incidents の `"active"`、audit の `UserID` と
// `Action` が、写しには存在しないまま「確かめた」ことになっていました。
//
// ライブレスポンスの2つを片付けて 30 です。**片方は、写しを本物に
// 向けたところで本物の側の欠陥が出ました** —— 終了コードが 0 でない
// コマンドが "completed" として保存され、コンソールは status だけを見る
// ので、失敗が成功として表示されていました。
//
// 一覧の絞り込み4つ（agents / device_events / fim_rules / dashboard）を
// 片付けて 26 です。**dashboard の写しだけは、繋ぐ先がありませんでした**
// —— 製品側にその形の組み立てが無く、消しました。**繋ぐ先がないものを
// 繋いだふりはしません。**
//
// webhook のイベント一覧を片付けて 25 です。**その写しは、送られるものとも
// 画面が出すものとも一致しない3つ目の一覧**でした。揃っていることを
// `internal/notification` の検査が確かめます。
//
// ポリシー・コマンド種別・タグの4つを片付けて 21 です。**コマンド種別の
// 分類は製品のどこにもなく、そのうえ `shell` を「読み取り専用（安全）」に
// 分類していました** —— 権限判定に繋がっていたら、そのまま穴になります。
//
// 一覧の絞り込み6つを片付けて 15 です。**そのうち3つは、繋ぐ先が
// ありませんでした**（コマンドキュー・レポート・対応アクション）——
// 製品側にその形の組み立てが無く、消しました。
//
// 数のうち1件は、写しではなくこの検査自身の説明文でした
// （`suppression_flags_test.go` で「テスト専用」の語を使っていました）。
// **印が語そのものなので、語を使った説明が1件に数えられます。** 直しました。
//
// プレイブックの条件・キャプチャの時刻・セッションのIP・レポート
// テンプレートの5つを片付けて 8 です。**うち3つは、Go の代入そのものを
// 検査の本文で試していました** —— `var x []T; if x == nil { x = []T{} }`
// を実行して、そのあと nil でないことを確かめる形です。
//
// **0 になりました。** 開始時 40 です。
//
// ここからは上限ではなく床です。**写しは1つも要りません** —— 直し方は
// 上の2つ（製品側に切り出す／製品に規則を足す）で、どちらもできない
// ものは繋ぐ先が無いので、消したうえで判断待ちの一覧に置きます。
//
// ── 走査を `server/internal` 全体に広げました (2026-08-12) ────────────
//
// **上の 40 → 0 は `internal/store` だけを見た数でした。** 広げたら
// 7 件出ました:
//
//   - `api/handlers` の頁送り3つ（`clampPage` / `clampPerPage` /
//     `quarantineOffset`）。本物はハンドラに直書きで、**同じ4行が
//     21 か所に散っていました。そのうち2か所には上限の行そのものが
//     ありませんでした** —— `/api/v1/vulnerabilities?per_page=0` が
//     200 の 0 件、`per_page=-1` が 500 でした。`pagination.go` に
//     切り出して全部をそちらへ向けました。
//   - `api/handlers` のプレイブック件数と IOC 深刻度。どちらも本物を
//     切り出して、検査はそちらを呼びます。**IOC の方は同じ4行が
//     同じファイルの中に2か所ありました。**
//   - `api/handlers` の CVSS の帯（critical は 9.0〜10.0 …）。
//     **製品にその対応付けはありません** —— NVD の `baseSeverity` を
//     そのまま使います。繋ぐ先が無いので消し、実在する規則
//     （`normalizeNVDSeverity`）の方に検査を置きました。
//   - `notification/email_send_test.go` は写しではなく継ぎ目でした。
//     印の語を避けて書き直しました。
//
// ── この見張りが見つけられないもの ──────────────────────────────
//
// **写しだと名乗っているものしか数えられません。** ここまでの 47 件は
// たまたま全部が自称していましたが、何も書かずに本物と同じ判定を
// 組み直した検査は数に入りません。**0 は「自称する写しが無い」であって
// 「写しが無い」ではありません。**
const reproducedHelperCeiling = 0

// 写しだと名乗っている印。日本語のコメントで統一されています。
var reproductionMarkers = []string{"テスト専用", "再現する", "テスト内ヘルパー"}

type reproduction struct {
	file string
	line int
	text string
}

// **走査が届いたかの判定。** 上限が 0 なので、走査が空でも件数の判定は
// 文句を言いません。届いていることを別に確かめます。
//
// 判定を切り出してあるのは、`if scanned < 0` に潰す変異を殺せるように
// するためです。走査は実際には届いているので、埋め込んだままだと検査は
// 緑を返し続けます（変異が生き残りました）。
const minReproductionScan = 200

func reproductionScanReached(scanned, floor int) bool {
	return scanned >= floor
}

// reproductionRoot — **`internal/store` だけでは足りません。**
//
// 上の 40 → 0 は、この1つのディレクトリだけを見た数でした。同じ形は
// 他の場所にもあります —— 走査を `server/internal` 全体に広げます。
// 狭い走査で 0 と言うのは、探していない場所を「無かった」と言うのと
// 同じです。
const reproductionRoot = ".."

func TestNoNewLogicIsReproducedInTests(t *testing.T) {
	var found []reproduction
	scanned := 0
	fset := token.NewFileSet()

	err := filepath.WalkDir(reproductionRoot, func(path string, d fs.DirEntry, err error) error {
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
		rel := filepath.ToSlash(strings.TrimPrefix(path, reproductionRoot+string(filepath.Separator)))
		for _, cg := range f.Comments {
			for _, c := range cg.List {
				if !hasMarker(c.Text) {
					continue
				}
				found = append(found, reproduction{
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

	// **0件を検査して緑を返すのがいちばん高くつきます。**
	if !reproductionScanReached(scanned, minReproductionScan) {
		t.Fatalf("走査が届いていません: %d ファイルしか見えません（床 %d）",
			scanned, minReproductionScan)
	}

	if msg := reproductionComplaint(len(found), reproducedHelperCeiling); msg != "" {
		t.Error(msg)
		for _, r := range found {
			t.Logf("  %s:%d %s", r.file, r.line, r.text)
		}
		return
	}
	t.Logf("写したヘルパー: %d 件（上限どおり）", len(found))
}

// reproductionComplaint は上限の判定そのものです。
//
// **切り出してあるのは、判定を無効にする変異を殺せるようにするため**です。
// 判定が検査の中に埋まっていると、`if false` に潰しても違反する入力を
// 食わせられず、変異が生き残ります（実際に2件生き残りました）。
func reproductionComplaint(actual, ceiling int) string {
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

func hasMarker(s string) bool {
	for _, m := range reproductionMarkers {
		if strings.Contains(s, m) {
			return true
		}
	}
	return false
}

// 上限の判定が、両方向に効くこと。
//
// **判定を無効にする変異は、違反する入力を食わせる検査でしか殺せません。**
func TestTheReproductionCeilingComplainsBothWays(t *testing.T) {
	if msg := reproductionComplaint(5, 5); msg != "" {
		t.Errorf("上限ちょうどで文句を言っています: %s", msg)
	}
	if reproductionComplaint(6, 5) == "" {
		t.Error("**上限を超えても黙っています。** 増えた分が隠れます")
	}
	if reproductionComplaint(4, 5) == "" {
		t.Error("**上限を下回っても黙っています。** 下げないと、" +
			"次に増えた分がその差に隠れます")
	}
	// **0 は正しい状態です。** ここを「全部片付いたら検査を消す」に
	// していましたが、消すと次に増えた1件が誰にも見えません。
	if reproducedHelperCeiling < 0 {
		t.Fatal("上限が負です")
	}
	// **印の一覧が痩せていないこと。** 数が 0 になったので、
	// 数え方を狭める変異は上限の判定では殺せません（0 のままです）。
	// 印そのものを確かめます。
	for _, marker := range []string{"テスト専用", "再現する", "テスト内ヘルパー"} {
		if !hasMarker("// なにかを" + marker) {
			t.Errorf("印 %q を見つけられません。**狭めると、その言い方で"+
				"書かれた写しが数から消えます**", marker)
		}
	}
	if hasMarker("// ふつうの注記") {
		t.Error("関係ない注記を写しに数えています")
	}
}

// 床の判定が効くこと。
func TestTheReproductionScanFloorNoticesAnEmptyWalk(t *testing.T) {
	if reproductionScanReached(0, minReproductionScan) {
		t.Error("**0 ファイルでも「届いた」と言っています。** 走査が壊れた日に、" +
			"写しが1つも無い姿と同じ緑を返します")
	}
	if reproductionScanReached(minReproductionScan-1, minReproductionScan) {
		t.Error("床を下回っても「届いた」と言っています")
	}
	if !reproductionScanReached(minReproductionScan, minReproductionScan) {
		t.Error("床ちょうどで「届いていない」と言っています")
	}
	if minReproductionScan < 1 {
		t.Fatal("床が 0 以下です。**どんな走査も通ります**")
	}
}
