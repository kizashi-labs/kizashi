package store_test

import (
	"context"
	"errors"
	"testing"

	"github.com/edr-platform/server/internal/detection"
	"github.com/edr-platform/server/internal/store"
)

// 抑制ルールの編集は、**画面から一度も成功したことがなかった。**
// `PUT /api/v1/suppressions/{id}` は画面が呼んでいるのにルートが無く 404 で、
// 作成と削除は通るので気づかれない。以下はその編集経路の回帰検査。
//
// ここで見るのは「保存できたか」ではなく **適用する側から見て何が変わったか**。
// 抑制は効いたり効かなかったりが最も分かりにくい機能で、保存の成功は
// 何の証拠にもならない。

// conditionsOf asks the production loader what the rule actually matches on.
func conditionsOf(t *testing.T, db *store.DB, id string) (detection.SuppressionRule, bool) {
	t.Helper()
	rules, err := detection.NewPoolSuppressionLoader(db.Pool()).
		ListActiveSuppressions(context.Background())
	if err != nil {
		t.Fatalf("ListActiveSuppressions: %v", err)
	}
	for _, r := range rules {
		if r.ID == id {
			return r, true
		}
	}
	return detection.SuppressionRule{}, false
}

// matchKeys is the comparable part of a loaded rule — what it matches on.
// ExpiresAt はポインタなので、そのまま == で比べると読み直すたびに
// 別物と判定されうる。ここで比べたいのは条件だけ。
type matchKeys struct {
	ruleName, hostname, agentID, tech, cmdline, parent string
	severityMax                                        int
}

func keysOf(r detection.SuppressionRule) matchKeys {
	return matchKeys{
		ruleName:    r.RuleName,
		hostname:    r.Hostname,
		agentID:     r.AgentID,
		tech:        r.MITRETechnique,
		cmdline:     r.CommandLine,
		parent:      r.ParentProcess,
		severityMax: r.SeverityMax,
	}
}

// 更新後、適用する側が見る条件が新しい内容に置き換わっていること。
//
// **消した条件が残る方が危ない。** 残れば抑制はより狭くなる…ように見えて、
// 運用者は「もう外した」と思っているので、実際に落ち続けるアラートを
// 誰も探さない。
func TestUpdateReplacesTheConditionsTheEngineSees(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()
	const name = "supupd-replace"
	cleanupRule(t, db, name)

	s := store.NewSuppressionStore(db)
	if err := s.Insert(ctx, &store.SuppressionRule{
		Name:       name,
		Conditions: store.SuppressionConditions{RuleName: "probe", Hostname: "ci-runner-"},
		DurationH:  24,
		IsActive:   true,
	}); err != nil {
		t.Fatalf("作成に失敗しました: %v", err)
	}
	id := idOf(t, db, name)

	if err := s.Update(ctx, &store.SuppressionRule{
		ID:         id,
		Name:       name,
		Conditions: store.SuppressionConditions{RuleName: "probe", MITRETechnique: "T1059"},
		IsActive:   true,
	}); err != nil {
		t.Fatalf("更新に失敗しました: %v", err)
	}

	got, ok := conditionsOf(t, db, id)
	if !ok {
		t.Fatal("更新後に適用対象から消えました")
	}
	if got.Hostname != "" {
		t.Errorf("外したはずの hostname が残っています: %q。"+
			"**運用者は対象を広げたつもりでいます**", got.Hostname)
	}
	if got.MITRETechnique != "T1059" {
		t.Errorf("追加した mitre_technique が反映されていません: %q", got.MITRETechnique)
	}
	if got.RuleName != "probe" {
		t.Errorf("触っていない rule_name が変わりました: %q", got.RuleName)
	}
}

// 読んで、名前だけ直して、書き戻す —— 画面の編集がやることそのもの。
// **条件がひとつも失われないこと。**
//
// store.SuppressionConditions に無いキーは List で読めず、書き戻しで消える。
// これは検知エンジンだけが知っている条件 (command_line_contains /
// parent_process) で実際に起きた穴で、静的な対応検査
// (TestSuppressionConditionKeysMatchTheReader) と両輪で塞いでいる。
func TestReadModifyWriteLosesNoCondition(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()
	const name = "supupd-roundtrip"
	cleanupRule(t, db, name)

	// 7 条件すべてを持つ行を直接作る（画面を経由しない、実際にあり得る状態）。
	if _, err := db.Pool().Exec(ctx, `
		INSERT INTO suppression_rules (name, description, conditions, duration_h)
		VALUES ($1, '', $2::jsonb, 24)`, name, `{
			"rule_name": "Data Exfiltration",
			"hostname": "ci-runner-",
			"agent_id": "11111111-1111-1111-1111-111111111111",
			"mitre_technique": "T1059",
			"severity_max": 3,
			"command_line_contains": "/opt/backup/nightly.sh",
			"parent_process": "cron"
		}`); err != nil {
		t.Fatalf("作成に失敗しました: %v", err)
	}
	id := idOf(t, db, name)
	before, ok := conditionsOf(t, db, id)
	if !ok {
		t.Fatal("作った直後に適用対象にありません。この検査の前提が崩れています")
	}

	s := store.NewSuppressionStore(db)
	rules, err := s.List(ctx, false)
	if err != nil {
		t.Fatalf("List: %v", err)
	}
	var target *store.SuppressionRule
	for _, r := range rules {
		if r.ID == id {
			target = r
			break
		}
	}
	if target == nil {
		t.Fatal("作ったルールが一覧に出てきません")
	}

	target.Name = name // 画面で名前だけ直したのと同じ
	if err := s.Update(ctx, target); err != nil {
		t.Fatalf("更新に失敗しました: %v", err)
	}

	after, ok := conditionsOf(t, db, id)
	if !ok {
		t.Fatal("更新後に適用対象から消えました")
	}
	if keysOf(after) != keysOf(before) {
		t.Errorf("名前を直しただけで条件が変わりました:\n  前: %+v\n  後: %+v\n"+
			"**画面から編集するたびに、画面が知らない条件が落ちます** —— "+
			"抑制が広がった分のアラートは届きません", before, after)
	}
}

// 更新でも旗は 2 つとも動くこと（Insert / SetActive と同じ約束）。
func TestUpdateWritesBothFlags(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()
	const name = "supupd-flags"
	cleanupRule(t, db, name)

	s := store.NewSuppressionStore(db)
	if err := s.Insert(ctx, &store.SuppressionRule{
		Name:       name,
		Conditions: store.SuppressionConditions{RuleName: "probe"},
		DurationH:  24,
		IsActive:   true,
	}); err != nil {
		t.Fatalf("作成に失敗しました: %v", err)
	}
	id := idOf(t, db, name)

	if err := s.Update(ctx, &store.SuppressionRule{
		ID:         id,
		Name:       name,
		Conditions: store.SuppressionConditions{RuleName: "probe"},
		IsActive:   false,
	}); err != nil {
		t.Fatalf("更新に失敗しました: %v", err)
	}

	if _, ok := conditionsOf(t, db, id); ok {
		t.Error("編集画面で無効にしたのに、まだ適用されます")
	}
	if enabled, isActive := flagsOfRule(t, db, id); enabled != isActive {
		t.Errorf("更新のあと旗が食い違っています: enabled=%v is_active=%v。"+
			"**書かなかった側の既定 TRUE が残ります**", enabled, isActive)
	}
}

// duration_h は 0 を「未指定」として既存値を残すこと。
// 送り手が持っていないだけの値で設定を潰さない。
func TestUpdateKeepsDurationWhenUnset(t *testing.T) {
	db := covTestDB(t)
	ctx := context.Background()
	const name = "supupd-duration"
	cleanupRule(t, db, name)

	s := store.NewSuppressionStore(db)
	if err := s.Insert(ctx, &store.SuppressionRule{
		Name:       name,
		Conditions: store.SuppressionConditions{RuleName: "probe"},
		DurationH:  72,
		IsActive:   true,
	}); err != nil {
		t.Fatalf("作成に失敗しました: %v", err)
	}
	id := idOf(t, db, name)

	if err := s.Update(ctx, &store.SuppressionRule{
		ID:         id,
		Name:       name,
		Conditions: store.SuppressionConditions{RuleName: "probe"},
		IsActive:   true,
		// DurationH は 0（画面が送らなかった）
	}); err != nil {
		t.Fatalf("更新に失敗しました: %v", err)
	}

	var got int
	if err := db.Pool().QueryRow(ctx,
		"SELECT duration_h FROM suppression_rules WHERE id=$1", id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != 72 {
		t.Errorf("duration_h = %d, want 72（未指定は既存値を残す）", got)
	}
}

// 存在しないルールへの更新を成功として返さないこと。
//
// **保存が通ったように見えて何も変わらないのが一番悪い。** 運用者は
// 保存した条件で抑制されていると信じたまま次の判断をする。
func TestUpdateOnAMissingRuleIsNotFound(t *testing.T) {
	db := covTestDB(t)
	s := store.NewSuppressionStore(db)

	err := s.Update(context.Background(), &store.SuppressionRule{
		ID:         "00000000-0000-0000-0000-0000000000ff",
		Name:       "supupd-missing",
		Conditions: store.SuppressionConditions{RuleName: "probe"},
		IsActive:   true,
	})
	if !errors.Is(err, store.ErrSuppressionNotFound) {
		t.Errorf("err = %v, want ErrSuppressionNotFound", err)
	}
}
