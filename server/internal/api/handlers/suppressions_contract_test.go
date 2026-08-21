package handlers

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func boolPtr(b bool) *bool { return &b }

// **「有効にする」を押すと無効になる**——これが実際に起きていた壊れ方です。
//
// コンソールは `{"enabled": true}` を送っていましたが、Toggle は `is_active`
// しか読んでいませんでした。JSON に is_active が無いので bool のゼロ値 false が
// 入り、SetActive(false) が呼ばれます。画面には「更新しました」と出るので、
// **操作が成功したように見えて逆のことが起きます。**
//
// 画面は is_active を送るよう直しましたが、この API は SDK / edr-cli /
// 顧客のスクリプトからも呼ばれ、そちらは画面と同時には直りません。
// だからサーバ側でも両方を受けます。
func TestResolveActiveFlag(t *testing.T) {
	cases := []struct {
		name        string
		isActive    *bool
		enabled     *bool
		wantValue   bool
		wantPresent bool
	}{
		{"is_active=true", boolPtr(true), nil, true, true},
		{"is_active=false", boolPtr(false), nil, false, true},
		// ★ 以前のコンソールが送っていた形。ここが false になっていた。
		{"enabled=true（旧コンソール／SDK）", nil, boolPtr(true), true, true},
		{"enabled=false（旧コンソール／SDK）", nil, boolPtr(false), false, true},
		// 両方あれば is_active を採る（API の正式名）。
		{"両方あれば is_active が勝つ", boolPtr(true), boolPtr(false), true, true},
		{"両方あれば is_active が勝つ(逆)", boolPtr(false), boolPtr(true), false, true},
		// **省略は false ではない。** 呼び出し側が 400 を返すか現在値を保つ。
		{"どちらも省略", nil, nil, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, present := resolveActiveFlag(c.isActive, c.enabled)
			if present != c.wantPresent {
				t.Fatalf("present = %v, want %v", present, c.wantPresent)
			}
			if present && got != c.wantValue {
				t.Errorf("value = %v, want %v", got, c.wantValue)
			}
		})
	}
}

// 省略と明示的な false が**同じゼロ値に潰れない**こと。ポインタで受ける
// 理由そのもので、bool に戻した瞬間にこの検査が落ちます。
//
// Update ではこの区別が「無効のまま保つ」と「有効化する」の違いになります。
// 既定を true にすると、**無効にしてあったルールを名前だけ直して保存した
// 瞬間に有効化します**——運用者は何も有効化していないつもりです。
func TestActiveFlagDistinguishesOmittedFromFalse(t *testing.T) {
	var req struct {
		IsActive *bool `json:"is_active"`
		Enabled  *bool `json:"enabled"`
	}

	if err := json.Unmarshal([]byte(`{}`), &req); err != nil {
		t.Fatal(err)
	}
	if _, present := resolveActiveFlag(req.IsActive, req.Enabled); present {
		t.Error("省略された旗が「送られてきた」と判定されている——" +
			"Update では意図しない有効化に、Toggle では意図しない無効化になる")
	}

	req.IsActive, req.Enabled = nil, nil
	if err := json.Unmarshal([]byte(`{"is_active":false}`), &req); err != nil {
		t.Fatal(err)
	}
	v, present := resolveActiveFlag(req.IsActive, req.Enabled)
	if !present || v {
		t.Errorf("明示的な false が読めていない: value=%v present=%v", v, present)
	}
}

// ── ルート登録の検査 ─────────────────────────────────────────────────────────

// コンソールの編集フォームは `PUT /api/v1/suppressions/:id` を呼びますが、
// **そのルートは存在しませんでした**（保存は常に 404）。画面には
// 「更新に失敗しました」しか出ないので、原因がルートの欠落だとは分かりません。
//
// ここでは router.go のソースを読んで、コンソールが呼ぶ動詞がすべて
// 登録されていることを確かめます。ハンドラを実行するには DB が要るので、
// **登録されているかどうか**だけを、DB なしで留めます。
func TestConsoleSuppressionRoutesAreRegistered(t *testing.T) {
	path := filepath.Join("..", "router.go")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("router.go を読めません: %v", err)
	}
	src := string(b)

	// 抑制のグループだけを切り出す。ファイル全体を検索すると、
	// **別のリソースの PUT("/:id") を数えて緑になります。**
	const marker = `protected.Group("/suppressions")`
	i := strings.Index(src, marker)
	if i < 0 {
		t.Fatalf("router.go に %s が見つかりません。"+
			"グループの書き方が変わったのなら、この検査も直してください", marker)
	}
	block := src[i:]
	if j := strings.Index(block, "\n\t}\n"); j > 0 {
		block = block[:j]
	}

	// コンソール (frontend/app/suppressions/page.tsx) が呼ぶもの。
	want := []struct{ call, why string }{
		{`sup.GET("", `, "一覧"},
		{`sup.POST("", `, "作成"},
		{`sup.PUT("/:id", `, "編集の保存（これが無く 404 だった）"},
		{`sup.DELETE("/:id", `, "削除"},
		{`sup.PUT("/:id/toggle", `, "有効/無効の切り替え"},
	}
	for _, w := range want {
		if !strings.Contains(block, w.call) {
			t.Errorf("抑制ルールのルート %s が登録されていません（%s）。"+
				"コンソールはこれを呼ぶので、無いと 404 になります", w.call, w.why)
		}
	}
}

// コンソールが送るキーが、サーバの受け口に実在すること。
//
// この画面は **実装されていない API 契約を前提に書かれていた** ため、
// `pattern` / `field` / `match_type` を送っては ShouldBindJSON に捨てられ、
// conditions が空のルールを作り続けていました（＝一度も抑制しない）。
// 捨てられても 200 が返るので、画面からは成功に見えます。
func TestConsoleSendsKeysTheHandlerAccepts(t *testing.T) {
	page := filepath.Join("..", "..", "..", "..", "frontend", "app", "suppressions", "page.tsx")
	b, err := os.ReadFile(page)
	if err != nil {
		t.Skipf("コンソールのソースが読めないため省略します: %v", err)
	}

	// **注記は数えません。** この画面には「以前はこの語彙を送っていた」という
	// 説明が書かれることがあり、それを参照に数えると**直した直後から落ちます**
	// （internal/store/suppression_sources_test.go が同じ罠を踏んでいます）。
	var code []string
	for _, line := range strings.Split(string(b), "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(t, "//") || strings.HasPrefix(t, "*") || strings.HasPrefix(t, "/*") {
			continue
		}
		code = append(code, line)
	}
	src := strings.Join(code, "\n")

	if len(src) < 1000 {
		t.Fatalf("コメントを除いたコードが %d 文字しかありません——"+
			"**走査が届いていません**。0 件を検査して緑を返すのがいちばん高くつきます", len(src))
	}

	// **もう送ってはいけない語彙。** サーバのどの受け口にも無い。
	// `pattern` や `field` のような一般的な語は使いません——正規表現の検証など
	// 別の文脈で普通に現れるので、中身と関係なく落ちる検査になります。
	// `match_type` はこの想像上の契約にしか存在せず、印として一意です。
	for _, dead := range []string{"match_type", "match_field"} {
		if strings.Contains(src, dead) {
			t.Errorf("コンソールがまだ %q を送っています。"+
				"サーバは受け取らないので、この条件は保存されません", dead)
		}
	}

	// 実際に読まれる語彙。
	for _, live := range []string{"conditions", "is_active"} {
		if !strings.Contains(src, live) {
			t.Errorf("コンソールが %q を扱っていません", live)
		}
	}
}
