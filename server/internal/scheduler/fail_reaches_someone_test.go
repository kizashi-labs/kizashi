package scheduler

import (
	"errors"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
)

// fail が「数から消すための呼び出し」にならないための検査です。
//
// answered_with_a_value_test.go は、分岐にログ以外の呼び出しがあれば
// 「値で答えているだけではない」として数えません。fail はログ以外の
// 呼び出しなので、slog.Error を fail に書き換えるだけで107箇所が数から
// 消えます。それが許されるのは、fail が本当に別の行き先を持っている
// あいだだけです。
//
// この検査は、その行き先が実在することを確かめます。中身が slog だけに
// 戻ったら、107箇所は黙って数から消えたままになります。
//
// **本体は `internal/tick` に移りました (2026-08-12)。** この package の中に
// 置いたままだと、外の 37 のワーカーが同じ形で報告できません。ここが読む
// 先も一緒に移します —— **移した先を見に行かないと、この検査は「探したが
// 無かった」を「移した」と読み違えます**（実際、移した直後に落ちました。
// 落ちてくれたので気づけました）。

// fail と trackRun が持っていなければならないもの。
//
// 一覧にしてあるのは、逆向きに確かめるためです。`if !strings.Contains(…)`
// をそのまま並べると、探す文字列を "" にするだけで検査は何も言わなくなり、
// 木がきれいなあいだは骨抜きにしたことが分かりません。**「探したが無かった」
// と「探していない」が同じ形になります。**
//
// 実際、この検査を変異させたとき、その2つは生き残りました。判定を1つずつ
// 書いていたので、外す側を壊しても誰も気づけませんでした。
// **読む先。** `internal/scheduler/heartbeat.go` の `fail`/`trackRun` は
// いま1行の委譲なので、ここを見ても何も分かりません。
const tickSourcePath = "../tick/tick.go"

var failNeeds = []string{
	// **`slog.Error` です。`slog.` ではありません。**
	// この一覧が `slog.` だけだったので、`Error` を `Warn` に落とす変更が
	// 通りました —— **Warn は運用の設定で最初に切られる段**で、
	// 「回っているが何もできていない」がまた見えなくなります。
	"slog.Error",
	"st.add()", // この回が仕事を終えられなかったこと
}

var trackRunNeeds = []string{
	"metrics.SchedulerFailures",             // 何回諦めたか
	"metrics.SchedulerLastSuccessTimestamp", // 最後に終えられたのはいつか
}

func missingFrom(body string, needs []string) []string {
	var out []string
	for _, n := range needs {
		if !strings.Contains(body, n) {
			out = append(out, n)
		}
	}
	return out
}

func TestFailWritesSomewhereOtherThanTheLog(t *testing.T) {
	src, err := os.ReadFile(tickSourcePath)
	if err != nil {
		t.Fatalf("%s を読めません: %v", tickSourcePath, err)
	}
	body := funcBody(string(src), "Fail")
	if body == "" {
		t.Fatal("Fail の定義が見つかりません")
	}
	if missing := missingFrom(body, failNeeds); len(missing) > 0 {
		t.Errorf("fail が %v を持っていません。ログだけなら、呼び出し側が"+
			"受け取るものは何も変わらないまま、107箇所が数から消えます", missing)
	}

	track := funcBody(string(src), "Run")
	if track == "" {
		t.Fatal("Run の定義が見つかりません")
	}
	if missing := missingFrom(track, trackRunNeeds); len(missing) > 0 {
		t.Errorf("trackRun が %v に落としていません。"+
			"tick に記録しても、外から見えなければ同じことです", missing)
	}

	// 逆向きの確認。求めるものの一覧が骨抜きになっていると、上の2つは
	// どんな実装でも通ります。件数ではなく「何が足りないか」まで見ます
	// — 一覧から1項目落としても、数だけなら合ったままになるためです。
	for _, c := range []struct {
		name, stub string
		needs      []string
		want       []string
	}{
		{"fail がログしか書かない", "slog.Error(msg)", failNeeds, []string{"st.add()"}},
		{"fail が記録しかしない", "st.add()", failNeeds, []string{"slog.Error"}},
		{"fail が切られる段に書く", "slog.Warn(msg); st.add()", failNeeds, []string{"slog.Error"}},
		{"trackRun が失敗しか見ない",
			"metrics.SchedulerFailures.WithLabelValues(n).Add(1)", trackRunNeeds,
			[]string{"metrics.SchedulerLastSuccessTimestamp"}},
		{"trackRun が成功しか刻まない",
			"metrics.SchedulerLastSuccessTimestamp.WithLabelValues(n).Set(0)", trackRunNeeds,
			[]string{"metrics.SchedulerFailures"}},
	} {
		got := missingFrom(c.stub, c.needs)
		if strings.Join(got, ",") != strings.Join(c.want, ",") {
			t.Errorf("%s実装の不足 = %v, want %v。"+
				"求めるものの一覧から項目が落ちています", c.name, got, c.want)
		}
	}
}

// 記録した回で last_success を動かしていないこと。動かしてしまうと、
// 毎回失敗しているワーカーが健全なワーカーと同じ形になります。
func TestTrackRunDoesNotStampSuccessAfterAFailure(t *testing.T) {
	src, err := os.ReadFile(tickSourcePath)
	if err != nil {
		t.Fatalf("%s を読めません: %v", tickSourcePath, err)
	}
	body := funcBody(string(src), "Run")
	fi := strings.Index(body, "metrics.SchedulerFailures")
	si := strings.Index(body, "metrics.SchedulerLastSuccessTimestamp")
	if fi < 0 || si < 0 {
		t.Fatal("失敗と成功の記録が両方は見つかりません")
	}
	if si < fi {
		t.Error("成功時刻の更新が失敗の記録より前にあります。" +
			"諦めた回でも成功として刻まれます")
	}
	between := body[fi:si]
	if !strings.Contains(between, "return") {
		t.Error("失敗を記録した後に戻っていません。" +
			"諦めた回でも成功時刻が動きます")
	}
}

// **「ログを書いて戻るだけ」の上限はここにありました。**
// 上限（34）は「これ以上増やすな」しか言わず、いま在る 34 が届かなくて
// よいものかは誰も見ていませんでした。1つずつ読んで、5 か所を `fail` に
// 直し、残りに理由を書いた形が `bare_log_and_return_test.go` です。

// funcBody returns the body of a top-level func by name.
func funcBody(src, name string) string {
	m := regexp.MustCompile(`func ` + regexp.QuoteMeta(name) + `\(`).FindStringIndex(src)
	if m == nil {
		return ""
	}
	open := strings.Index(src[m[0]:], "{")
	if open < 0 {
		return ""
	}
	open += m[0]
	depth := 0
	for i := open; i < len(src); i++ {
		switch src[i] {
		case '{':
			depth++
		case '}':
			depth--
			if depth == 0 {
				return src[open : i+1]
			}
		}
	}
	return ""
}

// この package の1行の委譲が、本物を指し続けていること。
//
// **本体を `internal/tick` に移したので、上の検査はそちらを読みます。**
// すると `heartbeat.go` の `fail` が誰も見ていない場所になり、中身を
// `_ = tick.Failing(ctx)` に潰しても何も落ちませんでした
// （変異が生き残りました）。**移した先を見るようにしたら、移す前の場所が
// 見張られなくなった**わけです。
func TestTheSchedulerWrappersStillPointAtTheRealThing(t *testing.T) {
	src, err := os.ReadFile("heartbeat.go")
	if err != nil {
		t.Fatalf("heartbeat.go を読めません: %v", err)
	}
	for _, c := range []struct{ fn, needs string }{
		{"fail", "tick.Fail("},
		{"trackRun", "tick.Run("},
		{"failing", "tick.Failing("},
	} {
		body := funcBody(string(src), c.fn)
		if body == "" {
			t.Errorf("%s の定義が見つかりません", c.fn)
			continue
		}
		if !strings.Contains(body, c.needs) {
			t.Errorf("%s が %s を呼んでいません。**この package の %d 箇所が"+
				"何も報告しなくなります** —— 本体を見に行く検査は、"+
				"ここが本体を指していることまでは言いません",
				c.fn, c.needs, 28)
		}
	}
}

// **「テーブルが無い」だけが、書けなくてよい唯一の理由であること。**
//
// `version_checker` は `system_metadata` への書き込みを黙って捨てて
// いました（「任意のテーブルなので」という意図はコメントに書いて
// ありました）。**`_, _ =` はその区別をしません** —— DB が応答しない
// だけでも同じように黙り、管理画面のバージョン分布が古いまま残ります。
//
// いまは 42P01 だけを通します。**この判定が広がると、元の黙り方に
// 戻ります。**
func TestTableMissingIsOnly42P01(t *testing.T) {
	for _, c := range []struct {
		name string
		err  error
		want bool
	}{
		{"テーブルが無い", &pgconn.PgError{Code: "42P01"}, true},
		{"列が無い", &pgconn.PgError{Code: "42703"}, false},
		{"権限が無い", &pgconn.PgError{Code: "42501"}, false},
		{"時間切れ", &pgconn.PgError{Code: "57014"}, false},
		{"制約違反", &pgconn.PgError{Code: "23505"}, false},
		{"接続できない", errors.New("dial tcp: connection refused"), false},
		{"nil", nil, false},
	} {
		if got := tableMissing(c.err); got != c.want {
			t.Errorf("%s: tableMissing = %v, want %v。**true を返すと、"+
				"書けていないのに黙ります**", c.name, got, c.want)
		}
	}
}
