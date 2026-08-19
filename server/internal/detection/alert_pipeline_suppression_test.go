package detection

import (
	"context"
	"errors"
	"testing"
)

// 抑制エンジンが AlertPipeline に結線されていることを固定する。
//
// ★ これが繋がっていないと、運用者が UI で作った抑制ルールが**効かない**。
//
// 抑制エンジン自体は前からあり、server-detect の Engine は起動時から見ていた。
// ところが P4-6 (#647) で DB Sigma ルールの所有権が server-api に移り、
// リアルタイムのアラートはほぼ全部 AlertPipeline が作るようになった。
// **抑制を効かせる側と、アラートを作る側が入れ替わった**が、結線は移らなかった。
//
// この壊れ方の悪質さは「UI 上はルールが有効に見える」ことにある。hit_count が
// 増えないことに気づける運用者はまずいないので、抑制が効いていないという事実
// そのものが観測できない。

type fixedSuppressionLoader struct {
	rules []SuppressionRule
	err   error
}

func (l fixedSuppressionLoader) ListActiveSuppressions(context.Context) ([]SuppressionRule, error) {
	return l.rules, l.err
}

type countingHitCounter struct{ ids []string }

func (c *countingHitCounter) IncrHitCount(_ context.Context, id string) error {
	c.ids = append(c.ids, id)
	return nil
}

func matcherWith(t *testing.T, rules ...SuppressionRule) *SuppressionMatcher {
	t.Helper()
	m := NewSuppressionMatcher(fixedSuppressionLoader{rules: rules})
	if err := m.load(context.Background()); err != nil {
		t.Fatalf("抑制ルールのロードに失敗: %v", err)
	}
	return m
}

// insertAlert は pool を触る前に抑制を判定するので、pool 無しで検査できる。
// pool が nil のまま INSERT まで到達すれば panic するため、**抑制されなかった
// 場合にそれと分かる**——「素通りしたのに緑」にはならない。
func TestAlertPipeline_SuppressesWhenRuleMatches(t *testing.T) {
	hits := &countingHitCounter{}
	p := &AlertPipeline{}
	p.SetSuppressionMatcher(matcherWith(t, SuppressionRule{
		ID:       "rule-1",
		Name:     "運用: バックアップ用 rsync を抑制",
		RuleName: "Data Exfiltration",
	}), hits)

	_, err := p.insertAlert(context.Background(), insertAlertParams{
		AgentID:  "11111111-1111-1111-1111-111111111111",
		Hostname: "web-01",
		RuleName: "Data Exfiltration via curl/wget Upload (Linux)",
		Severity: 5,
		Title:    "[Sigma] Data Exfiltration via curl/wget Upload (Linux)",
		Status:   "open",
	})
	if !errors.Is(err, errAlertSuppressed) {
		t.Fatalf("抑制ルールに当たったのにアラートが作られている: err=%v", err)
	}
	if len(hits.ids) != 1 || hits.ids[0] != "rule-1" {
		t.Errorf("hit_count が加算されていない: %v。"+
			"運用者が「この抑制ルールは効いているのか」を確かめる唯一の数字である", hits.ids)
	}
}

// 抑制が未結線のときは今までどおり素通しすること（nil 安全）。
func TestAlertPipeline_NoMatcherIsNotSuppression(t *testing.T) {
	p := &AlertPipeline{}
	defer func() {
		// pool が nil なので INSERT で panic するのが期待動作。
		// **panic しなければ抑制されたということ**で、それは誤り。
		if recover() == nil {
			t.Error("matcher 未結線なのに抑制されている")
		}
	}()
	_, _ = p.insertAlert(context.Background(), insertAlertParams{RuleName: "何でもよい"})
}

// 当たらない抑制ルールでアラートを止めないこと。
//
// 空の conditions が全アラートを消す事故が過去にあり、matcher 側にガードが入って
// いる (suppression_matcher.go の matches)。結線した以上、その挙動が
// AlertPipeline 経由でも成り立つことをここで見る。
func TestAlertPipeline_NonMatchingAndEmptyRulesDoNotSuppress(t *testing.T) {
	for _, c := range []struct {
		why  string
		rule SuppressionRule
	}{
		{"ルール名が違う", SuppressionRule{ID: "r", Name: "別ルール", RuleName: "Mimikatz"}},
		{"ホストが違う", SuppressionRule{ID: "r", Name: "別ホスト", Hostname: "db-99"}},
		{"重大度の上限を超えている", SuppressionRule{ID: "r", Name: "低重大度のみ", SeverityMax: 2}},
		{"技法が違う", SuppressionRule{ID: "r", Name: "別技法", MITRETechnique: "T1003"}},
		{"conditions が空（全消しの事故を防ぐガード）", SuppressionRule{ID: "r", Name: "空"}},
	} {
		t.Run(c.why, func(t *testing.T) {
			p := &AlertPipeline{}
			p.SetSuppressionMatcher(matcherWith(t, c.rule), nil)
			defer func() {
				if recover() == nil {
					t.Errorf("当たらないはずの抑制ルールでアラートが消えている (%s)", c.why)
				}
			}()
			_, _ = p.insertAlert(context.Background(), insertAlertParams{
				Hostname:  "web-01",
				RuleName:  "Data Exfiltration via curl/wget Upload (Linux)",
				Severity:  7,
				MITRETech: "T1048",
			})
		})
	}
}

// 抑制は「失敗」ではないこと。
//
// errAlertSuppressed を普通のエラーとして扱うと、呼び出し側が warn ログを出し
// AlertInsertFailures を加算する。**抑制するたびに「アラート登録に失敗」が並ぶ**
// 状態は、本物の DB 障害を埋もれさせる。
func TestAlertPipeline_SuppressionIsDistinguishableFromFailure(t *testing.T) {
	if errors.Is(errAlertSuppressed, context.Canceled) {
		t.Fatal("対照が効いていない: errors.Is が何にでも真を返している")
	}
	p := &AlertPipeline{}
	p.SetSuppressionMatcher(matcherWith(t, SuppressionRule{
		ID: "r", Name: "抑制", RuleName: "Noisy",
	}), nil)
	_, err := p.insertAlert(context.Background(), insertAlertParams{RuleName: "Noisy Rule"})
	if err == nil {
		t.Fatal("抑制時は sentinel エラーを返すこと（呼び出し側が止まれない）")
	}
	if !errors.Is(err, errAlertSuppressed) {
		t.Errorf("抑制が通常のエラーと区別できない: %v", err)
	}
}
