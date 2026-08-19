package commands

import (
	"testing"

	"github.com/edr-platform/server/internal/detection"
)

// CLI とエンジンが**同じ判定**を使っていることを固定する。
//
// 抑制は「効いたり効かなかったりする」が最も分かりにくい機能である。棚卸しの
// コマンドが「このルールは narrow です」と言ったのにエンジンが catch-all として
// 弾いていたら（あるいはその逆なら）、運用者は何を信じればいいか分からなくなる。
//
// 判定そのものは internal/detection 側のテストが押さえているので、ここで見るのは
// **API の JSON からエンジンのルール型への詰め替えが正しいか**である。ここがずれると
// 「同じ関数を呼んでいるのに違う答えが出る」——最も気づきにくい形になる。
func TestSuppressionRule_ToDetectionRule(t *testing.T) {
	api := suppressionRule{
		ID:   "11111111-1111-1111-1111-111111111111",
		Name: "バックアップ用 rsync を抑制",
		Conditions: suppressionCondition{
			RuleName:       "Data Exfiltration",
			Hostname:       "backup-server",
			SeverityMax:    5,
			MITRETechnique: "T1048",
			AgentID:        "22222222-2222-2222-2222-222222222222",
		},
	}
	got := api.toDetectionRule()

	for _, c := range []struct{ field, want, got string }{
		{"ID", api.ID, got.ID},
		{"Name", api.Name, got.Name},
		{"RuleName", api.Conditions.RuleName, got.RuleName},
		{"Hostname", api.Conditions.Hostname, got.Hostname},
		{"MITRETechnique", api.Conditions.MITRETechnique, got.MITRETechnique},
		{"AgentID", api.Conditions.AgentID, got.AgentID},
	} {
		if c.want != c.got {
			t.Errorf("%s が詰め替えで落ちている: want %q, got %q", c.field, c.want, c.got)
		}
	}
	if got.SeverityMax != api.Conditions.SeverityMax {
		t.Errorf("SeverityMax が詰め替えで落ちている: want %d, got %d",
			api.Conditions.SeverityMax, got.SeverityMax)
	}
}

// 詰め替えの穴は「全部空になる」形でも出る。**空のルールは catch-all と判定される**
// ので、詰め替えが壊れると全ルールが catch-all に見える——警告としては派手だが、
// 中身は何も見ていない。条件ごとに判定が変わることを確かめておく。
func TestSuppressionAudit_ClassificationFollowsConditions(t *testing.T) {
	cases := []struct {
		why  string
		cond suppressionCondition
		want detection.SuppressionBreadth
	}{
		{"ルール名で絞れている", suppressionCondition{RuleName: "Data Exfiltration via curl"}, detection.SuppressionNarrow},
		{"重大度だけで広い", suppressionCondition{SeverityMax: 8}, detection.SuppressionWide},
		{"技法の前方一致が全技法に当たる", suppressionCondition{MITRETechnique: "T"}, detection.SuppressionCatchAll},
		{"条件が空", suppressionCondition{}, detection.SuppressionCatchAll},
	}

	seen := map[detection.SuppressionBreadth]bool{}
	for _, c := range cases {
		got, why := detection.ClassifySuppression(suppressionRule{Conditions: c.cond}.toDetectionRule())
		if got != c.want {
			t.Errorf("%s: want %v, got %v（理由=%s）", c.why, c.want, got, why)
		}
		seen[got] = true
	}
	// 対照。全部同じ判定に潰れていたら、上の一致は何も証明していない。
	if len(seen) < 3 {
		t.Fatalf("対照が効いていない: 判定が %d 種類しか出ていない。"+
			"詰め替えが壊れて全ルールが同じ分類に潰れている可能性がある", len(seen))
	}
}
