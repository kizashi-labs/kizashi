package detection

import (
	"context"
	"strings"
	"testing"
)

// 抑制ルールの「広さ」判定。
//
// ★ これは #760 が作った新しいリスクへの手当てである。AlertPipeline に抑制を
// 結線するまで、運用者から見ると「抑制ルールを作っても何も止まらない」状態だった。
// 効かない原因は条件の狭さではなく結線の欠落だったが、そうとは分からないので
// **「効かないからもっと広くしてみる」**という調整が積み上がっている可能性がある。
// 結線した瞬間に、それが本当にアラートを消し始める。
//
// 判定は 2 箇所から使うので、ここで固定する:
//
//	SuppressionMatcher.load()    catch-all を弾き、wide を警告する（実行時）
//	edr-cli suppressions audit   デプロイ前に運用者が棚卸しする（人間向け）
//
// 別実装にすると「CLI では警告が出ないのにエンジンは弾く」が起きる。抑制は
// 「効いたり効かなかったりする」が最も分かりにくい機能なので、判定を分けない。

func TestClassifySuppression_CatchAll(t *testing.T) {
	// 対照。絞れているルールが catch-all と判定されるなら、以下は何も確かめていない。
	if b, why := ClassifySuppression(SuppressionRule{RuleName: "PowerShell"}); b == SuppressionCatchAll {
		t.Fatalf("対照が効いていない: 絞れているルールを catch-all と判定している (%s)", why)
	}

	for _, c := range []struct {
		why  string
		rule SuppressionRule
	}{
		{"条件がひとつも無い（過去に実際に全アラートを消した形）", SuppressionRule{}},
		{`mitre_technique="T" は前方一致で全技法に当たる`, SuppressionRule{MITRETechnique: "T"}},
		{`小文字の "t" でも同じ（比較前に大文字化される）`, SuppressionRule{MITRETechnique: "t"}},
		{"severity_max=10 は alerts の上限そのもので何も除外しない", SuppressionRule{SeverityMax: 10}},
		{"上限を超える値も同じ", SuppressionRule{SeverityMax: 99}},
		{"rule_name が 1 文字（部分文字列一致）", SuppressionRule{RuleName: "e"}},
		{"hostname が 1 文字（部分文字列一致）", SuppressionRule{Hostname: "a"}},
		{"前後の空白を除くと空", SuppressionRule{RuleName: "   "}},
		{"退化した条件をいくつ並べても絞れない", SuppressionRule{
			RuleName: "e", Hostname: "a", MITRETechnique: "T", SeverityMax: 10,
		}},
	} {
		t.Run(c.why, func(t *testing.T) {
			b, why := ClassifySuppression(c.rule)
			if b != SuppressionCatchAll {
				t.Errorf("catch-all と判定されない (%s): %v — 理由=%s", c.why, b, why)
			}
			if strings.TrimSpace(why) == "" {
				t.Error("理由が空。運用者はこれを読んでルールを残すか決める")
			}
		})
	}
}

// agent_id は完全一致なので、他がどれだけ緩くても被害は 1 台に閉じる。
// **退化した条件と一緒に書かれていても catch-all にしない**——この 1 行を落とすと、
// 「1 台だけ全部黙らせる」という正当な運用ができなくなる。
func TestClassifySuppression_AgentIDBoundsTheDamage(t *testing.T) {
	r := SuppressionRule{AgentID: "11111111-1111-1111-1111-111111111111", SeverityMax: 10}
	b, why := ClassifySuppression(r)
	if b != SuppressionNarrow {
		t.Errorf("agent_id で 1 台に閉じているのに %v と判定している: %s", b, why)
	}
}

func TestClassifySuppression_Wide(t *testing.T) {
	for _, c := range []struct {
		why  string
		rule SuppressionRule
	}{
		{"severity_max=7 は高重大度までフリート全体で落とす", SuppressionRule{SeverityMax: 7}},
		{"severity_max=9 も同じ", SuppressionRule{SeverityMax: 9}},
		{`rule_name="exe" は語をまたいで当たる`, SuppressionRule{RuleName: "exe"}},
		{`mitre_technique="T10" は T1003 / T1059 … 全てに前方一致する`, SuppressionRule{MITRETechnique: "T10"}},
		{"hostname 2 文字は接頭辞の群を切れない", SuppressionRule{Hostname: "dc"}},
	} {
		t.Run(c.why, func(t *testing.T) {
			b, why := ClassifySuppression(c.rule)
			if b != SuppressionWide {
				t.Errorf("wide と判定されない (%s): %v — 理由=%s", c.why, b, why)
			}
		})
	}
}

func TestClassifySuppression_Narrow(t *testing.T) {
	for _, c := range []struct {
		why  string
		rule SuppressionRule
	}{
		{"ルール名で絞る（一番よくある形）", SuppressionRule{RuleName: "Data Exfiltration via curl"}},
		{"技法をひとつ指定する", SuppressionRule{MITRETechnique: "T1003"}},
		{"ホスト群を接頭辞で指定する", SuppressionRule{Hostname: "backup-server"}},
		{"低ノイズ帯だけ落とす、意図の明確な運用", SuppressionRule{SeverityMax: 2}},
		{"1 台に限定する", SuppressionRule{AgentID: "11111111-1111-1111-1111-111111111111"}},
	} {
		t.Run(c.why, func(t *testing.T) {
			b, why := ClassifySuppression(c.rule)
			if b != SuppressionNarrow {
				t.Errorf("narrow と判定されない (%s): %v — 理由=%s", c.why, b, why)
			}
		})
	}
}

// catch-all はキャッシュに載せないこと。
//
// 載せたうえで matches() で拒む方式だと、Count() には現れるので運用者からは
// 「有効な抑制ルールが N 件ある」ように見える。**適用しないものを有効と数えない。**
func TestSuppressionLoad_DropsCatchAllKeepsWide(t *testing.T) {
	m := NewSuppressionMatcher(&fakeSuppLoader{rules: []SuppressionRule{
		{ID: "narrow", Name: "narrow", RuleName: "Data Exfiltration via curl"},
		{ID: "wide", Name: "wide", SeverityMax: 7},
		{ID: "catchall", Name: "catchall", MITRETechnique: "T"},
	}})
	m.RefreshNow(context.Background())

	if m.Count() != 2 {
		t.Fatalf("catch-all を落として wide を残す想定だが count=%d", m.Count())
	}

	// wide は適用される（警告に留める方針）。
	if supp, name, _ := m.IsSuppressed(&StoredAlert{RuleName: "何か", Severity: 5}, SuppressionContext{}); !supp || name != "wide" {
		t.Errorf("wide なルールが適用されていない: supp=%v name=%q。"+
			"「severity_max=2 で低ノイズ帯を落とす」のような意図の明確な運用まで"+
			"止めてしまう", supp, name)
	}

	// catch-all は残っていない。技法を持つがルール名も重大度も一致しないアラートで見る。
	if supp, name, _ := m.IsSuppressed(&StoredAlert{
		RuleName: "Mimikatz", Severity: 10, MITRETech: "T1003",
	}, SuppressionContext{}); supp && name == "catchall" {
		t.Error("catch-all なルールが適用されている——全アラートが消える")
	}
}

// wide を落とさないこと自体を固定する。
//
// 「広いから全部弾く」に倒すと、**測っていないものを勝手に止める**ことになる。
// この一連の作業で一貫して避けてきた行為なので、方針として固定しておく。
func TestSuppressionLoad_DoesNotDropWide(t *testing.T) {
	m := NewSuppressionMatcher(&fakeSuppLoader{rules: []SuppressionRule{
		{ID: "floor", Name: "低ノイズ帯", SeverityMax: 7},
	}})
	m.RefreshNow(context.Background())
	if m.Count() != 1 {
		t.Errorf("wide なルールが落とされている (count=%d)。警告に留める方針である", m.Count())
	}
}
