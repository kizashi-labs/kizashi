package suppression

import (
	"testing"
	"time"
)

// ルール管理 API の 3 観点。既存のテストは条件評価と DB 往復を厚く覆っていたが、
// **管理操作そのものの後始末**は誰も見ていなかった。2026-08-17 のブランチ棚卸しで
// `claude/test-suppression-coverage` から回収し、実装の実態に合わせて書き直した。

// UpdateRule は「更新された値」と「引き継ぐ値」を混ぜて 1 つの構造体に組み直す。
// 呼び出し側が渡す構造体には ID も HitCount も CreatedAt も入っていない（画面から
// 来るのは名前・条件・有効/無効だけ）ので、**引き継ぎを落とすと更新のたびに
// 抑制回数が 0 に戻り、作成日時が消える。** 静かに壊れる形で、UI からは
// 「更新できた」ように見える。
func TestUpdateRulePreservesIdentityAndHistory(t *testing.T) {
	e := NewEngine(nil)
	created := time.Now().Add(-time.Hour)
	e.rules = []*SuppressionRule{{
		ID: "id-1", Name: "old", Enabled: true, HitCount: 7, CreatedAt: created,
		Conditions: []Condition{{Field: "severity", Operator: "eq", Value: "low"}},
	}}

	// 画面から来る形: ID / HitCount / CreatedAt を持たない
	upd := &SuppressionRule{
		Name: "new", Enabled: false,
		Conditions: []Condition{{Field: "severity", Operator: "eq", Value: "high"}},
	}
	if err := e.UpdateRule("id-1", upd); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}

	got := e.GetRules()
	if len(got) != 1 {
		t.Fatalf("ルール数 = %d, want 1", len(got))
	}
	r := got[0]
	if r.Name != "new" || r.Enabled {
		t.Errorf("新しい値が適用されていません: %+v", r)
	}
	if r.ID != "id-1" {
		t.Errorf("ID が失われました: %q", r.ID)
	}
	if r.HitCount != 7 {
		t.Errorf("HitCount = %d, want 7 —— 更新で抑制回数が消えています", r.HitCount)
	}
	if !r.CreatedAt.Equal(created) {
		t.Errorf("CreatedAt = %v, want %v —— 更新で作成日時が消えています", r.CreatedAt, created)
	}
}

// UpdateRule に無い ID を渡しても何も起こらないこと。ループが空振りしたときに
// 追記へ倒れると、消したはずのルールが更新のたびに増える。
func TestUpdateRuleWithUnknownIDChangesNothing(t *testing.T) {
	e := NewEngine(nil)
	e.rules = []*SuppressionRule{{ID: "id-1", Name: "keep", Enabled: true}}

	if err := e.UpdateRule("no-such-id", &SuppressionRule{Name: "ghost"}); err != nil {
		t.Fatalf("UpdateRule: %v", err)
	}
	got := e.GetRules()
	if len(got) != 1 || got[0].Name != "keep" {
		t.Errorf("未知の ID で状態が変わりました: %+v", got)
	}
}

// TopRules は「よく効いているルール」を上から 5 件見せる。並びが逆だと
// **一度も効いていないルールが上位として表示される** ——「効いていないのに
// 消せない」と読まれる向きの誤りで、抑制の棚卸しを狂わせる。
//
// 実装は上位 5 件だけを選択ソートで前に出し、そのあと 5 件で切る。7 件与えて
// 「上位 5 件が降順で並ぶこと」と「6 件目以降が落ちること」を同時に留める。
func TestGetStatsTopRulesAreDescendingAndCappedAtFive(t *testing.T) {
	e := NewEngine(nil)
	for i, h := range []int64{10, 3, 50, 1, 25, 8, 40} {
		e.rules = append(e.rules, &SuppressionRule{
			ID:       string(rune('a' + i)),
			Name:     string(rune('a' + i)),
			Enabled:  true,
			HitCount: h,
		})
	}

	s := e.GetStats()
	if len(s.TopRules) != 5 {
		t.Fatalf("TopRules = %d 件, want 5 (上限)", len(s.TopRules))
	}
	for i, want := range []int64{50, 40, 25, 10, 8} {
		if s.TopRules[i].HitCount != want {
			t.Errorf("TopRules[%d].HitCount = %d, want %d (全体: %+v)",
				i, s.TopRules[i].HitCount, want, s.TopRules)
		}
	}
}

// HitCount が 0 のルールは TopRules に入らない。入れてしまうと、一度も効いて
// いないルールが「上位」の枠を埋めて、実際に効いているルールを押し出す。
func TestGetStatsCountsActiveAndSkipsUnhitRules(t *testing.T) {
	e := NewEngine(nil)
	e.rules = []*SuppressionRule{
		{ID: "a", Name: "hit", Enabled: true, HitCount: 3},
		{ID: "b", Name: "never-hit", Enabled: true, HitCount: 0},
		{ID: "c", Name: "disabled", Enabled: false, HitCount: 9},
	}

	s := e.GetStats()
	if s.TotalRules != 3 {
		t.Errorf("TotalRules = %d, want 3", s.TotalRules)
	}
	if s.ActiveRules != 2 {
		t.Errorf("ActiveRules = %d, want 2 (Enabled のみ)", s.ActiveRules)
	}
	for _, tr := range s.TopRules {
		if tr.RuleName == "never-hit" {
			t.Error("HitCount=0 のルールが TopRules に入っています")
		}
	}
}

// GetRules が返すのは **スライスのコピーであって、ルールのコピーではない。**
//
// doc コメントは "returns a copy of all rules" と書いているが、要素は
// `*SuppressionRule` の共有ポインタなので、返り値の中身を書き換えると
// エンジンの状態が変わる。**これは現状の仕様であって、ここではそれを
// 固定する** —— 深いコピーに変えるなら、このテストが「変えた」と言う。
//
// 呼び出し側が返り値を書き換えないことに依存しているので、書き換える
// 呼び出しを足すときはここを読むこと。
func TestGetRulesCopiesTheSliceButSharesTheRules(t *testing.T) {
	e := NewEngine(nil)
	e.rules = []*SuppressionRule{{ID: "a", Name: "a"}}

	got := e.GetRules()

	// スライスは独立: 要素を差し替えてもエンジンには波及しない。
	got[0] = &SuppressionRule{ID: "hacked", Name: "hacked"}
	if e.GetRules()[0].ID != "a" {
		t.Fatal("返り値のスライスを差し替えたらエンジンの状態が変わりました")
	}

	// ルール本体は共有: 中身を書き換えるとエンジンに波及する（現状の仕様）。
	e.GetRules()[0].Name = "mutated"
	if e.GetRules()[0].Name != "mutated" {
		t.Fatal("要素は共有ポインタのはずですが、書き換えが波及しませんでした —— " +
			"深いコピーに変えたのであれば、この検査ごと更新してください")
	}
}
