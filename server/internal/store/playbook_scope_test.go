package store

import (
	"encoding/json"
	"testing"
)

// A playbook's conditions decide which alerts it fires on. Its actions include
// isolating an endpoint from the network.
//
// ListActiveForAlert used to decode those conditions with
// `_ = json.Unmarshal(condJSON, &cond)`. Every filter below it treats its zero
// value as "not specified" — MinSeverity > 0, RuleName != "" — so a conditions
// blob that would not decode left cond at its zero value and the playbook
// matched *every alert on every host*. A playbook scoped to "severity 9+ on
// dc-*" became an unscoped one at the moment its scope stopped being readable,
// and the first thing it does may be isolate_endpoint.
//
// conditions is jsonb, so this is never malformed JSON. It is valid JSON of the
// wrong shape — an array where an object belongs, min_severity stored as the
// string "9" rather than 9 — which is what a hand-edited row, an older schema,
// or an import from another deployment leaves behind. None of it is visible
// from the console.
//
// The actions blob failed the other way: undecodable actions became an empty
// list, the playbook "ran" with zero actions, and RecordRun logged it as a
// success and incremented run_count. A playbook doing nothing at all, showing
// a rising run count.

// The zero value really does match everything. This is not a hypothetical about
// the old code — it is the live behaviour of matches(), and it is why a decode
// failure may not be allowed to produce a zero value.
func TestUnscopedConditionsMatchEverything(t *testing.T) {
	var zero PlaybookConditions
	if !zero.matches(1, "", "", "", "") {
		t.Fatal("前提が崩れています: ゼロ値の条件は全アラートにマッチするはずです")
	}
	if !zero.matches(10, "Some Rule", "dc-primary", "T1055", "open") {
		t.Error("ゼロ値の条件がマッチしませんでした")
	}
}

// Each filter has to be doing its own work. "The scope is respected" is the
// premise the rest of this file rests on, and a scope where one filter has
// quietly stopped applying is a playbook firing wider than the operator asked
// — the same failure as an unreadable scope, arrived at differently.
func TestEachConditionFilterNarrowsOnItsOwn(t *testing.T) {
	for _, tc := range []struct {
		name string
		cond PlaybookConditions
		// an alert the filter must reject, given everything else is unset
		severity                          int
		ruleName, hostname, mitre, status string
	}{
		{"min_severity", PlaybookConditions{MinSeverity: 9}, 8, "", "", "", ""},
		{"max_severity", PlaybookConditions{MaxSeverity: 3}, 4, "", "", "", ""},
		{"rule_name", PlaybookConditions{RuleName: "Mimikatz"}, 0, "Cobalt Strike", "", "", ""},
		{"hostname", PlaybookConditions{Hostname: "dc-"}, 0, "", "web-01", "", ""},
		{"mitre_technique", PlaybookConditions{MITRETechnique: "T1003"}, 0, "", "", "T1055", ""},
		{"status", PlaybookConditions{Status: "open"}, 0, "", "", "", "closed"},
	} {
		if tc.cond.matches(tc.severity, tc.ruleName, tc.hostname, tc.mitre, tc.status) {
			t.Errorf("%s フィルタが効いていません。指定より広い範囲でプレイブックが発火します: %+v",
				tc.name, tc.cond)
		}
	}

	// And each one accepts what it should, or "narrows" could just mean
	// "rejects everything".
	for _, tc := range []struct {
		name                              string
		cond                              PlaybookConditions
		severity                          int
		ruleName, hostname, mitre, status string
	}{
		{"min_severity", PlaybookConditions{MinSeverity: 9}, 9, "", "", "", ""},
		{"max_severity", PlaybookConditions{MaxSeverity: 3}, 3, "", "", "", ""},
		{"rule_name (部分一致・大小無視)", PlaybookConditions{RuleName: "mimikatz"}, 0, "Suspected Mimikatz Use", "", "", ""},
		{"hostname (部分一致)", PlaybookConditions{Hostname: "dc-"}, 0, "", "dc-primary", "", ""},
		{"mitre_technique", PlaybookConditions{MITRETechnique: "T1003"}, 0, "", "", "T1003.001", ""},
		{"status (完全一致)", PlaybookConditions{Status: "open"}, 0, "", "", "", "open"},
	} {
		if !tc.cond.matches(tc.severity, tc.ruleName, tc.hostname, tc.mitre, tc.status) {
			t.Errorf("%s フィルタが、合致すべきアラートを弾いています: %+v", tc.name, tc.cond)
		}
	}
}

// The headline: a playbook whose scope cannot be read is not a playbook that
// matches everything.
func TestAPlaybookWithUnreadableScopeDoesNotMatchEverything(t *testing.T) {
	scoped := `{"min_severity":9,"hostname":"dc-"}`
	actions := `[{"type":"isolate_endpoint"}]`

	// Sanity: while it is readable, the scope is respected.
	pb, err := playbookForAlert("p1", []byte(scoped), []byte(actions), 3, "", "web-01", "", "open")
	if err != nil {
		t.Fatalf("読める設定でエラーが返りました: %v", err)
	}
	if pb != nil {
		t.Fatal("前提が崩れています: 重大度3/web-01 は「重大度9以上・dc-」にマッチしません")
	}

	for _, tc := range []struct {
		name string
		cond string
	}{
		{"配列になっている", `["min_severity",9]`},
		{"数値が文字列になっている", `{"min_severity":"9"}`},
		{"オブジェクトが入れ子になっている", `{"min_severity":{"$gte":9}}`},
		{"文字列リテラル", `"min_severity=9"`},
	} {
		pb, err := playbookForAlert("p1", []byte(tc.cond), []byte(actions), 3, "", "web-01", "", "open")
		if err == nil {
			t.Errorf("%s: 条件を解釈できないのにエラーになりません", tc.name)
		}
		if pb != nil {
			t.Errorf("%s: 条件を読めないプレイブックが、重大度3のweb-01にマッチしました。"+
				"「重大度9以上・dc-のみ」という指定が読めなかっただけで、"+
				"全ホストの全アラートで isolate_endpoint が走ります", tc.name)
		}
	}
}

// The same for the actions blob, which fails in the opposite direction: a
// playbook that runs nothing while its run count climbs.
func TestAPlaybookWithUnreadableActionsIsNotRun(t *testing.T) {
	cond := `{"min_severity":1}`
	for _, tc := range []struct {
		name string
		act  string
	}{
		{"配列ではなくオブジェクト", `{"type":"notify"}`},
		{"型が文字列の配列", `["notify","isolate_endpoint"]`},
		{"severity が文字列", `[{"type":"create_incident","severity":"9"}]`},
	} {
		pb, err := playbookForAlert("p1", []byte(cond), []byte(tc.act), 9, "", "h", "", "open")
		if err == nil {
			t.Errorf("%s: アクションを解釈できないのにエラーになりません", tc.name)
		}
		if pb != nil {
			t.Errorf("%s: アクションを読めないプレイブックが実行対象になりました。"+
				"アクション0件で実行され、成功として記録され、run_count が増えます", tc.name)
		}
	}
}

// And a readable playbook still runs, or the checks above are just
// "everything is rejected".
func TestAReadablePlaybookStillMatches(t *testing.T) {
	pb, err := playbookForAlert("p1",
		[]byte(`{"min_severity":7,"hostname":"dc-"}`),
		[]byte(`[{"type":"isolate_endpoint"},{"type":"notify","message":"x"}]`),
		9, "Mimikatz", "dc-primary", "T1003", "open")
	if err != nil {
		t.Fatalf("読める設定でエラーが返りました: %v", err)
	}
	if pb == nil {
		t.Fatal("条件に合致するプレイブックがマッチしませんでした")
	}
	if len(pb.Actions) != 2 {
		t.Errorf("アクションが読めていません: %+v", pb.Actions)
	}
	if pb.Conditions.MinSeverity != 7 {
		t.Errorf("条件が読めていません: %+v", pb.Conditions)
	}
}

// An empty conditions object is the operator's own choice — "fire on
// everything" is a legitimate playbook — and must stay distinguishable from a
// blob that failed to decode. Rejecting it would turn a silent-failure fix into
// a silent outage for every deliberately unscoped playbook.
func TestADeliberatelyUnscopedPlaybookStillRuns(t *testing.T) {
	for _, cond := range []string{`{}`, `null`} {
		pb, err := playbookForAlert("p1", []byte(cond), []byte(`[{"type":"notify"}]`),
			1, "", "", "", "open")
		if err != nil {
			t.Errorf("conditions=%s: 意図的に無制限なプレイブックが拒否されました: %v", cond, err)
		}
		if pb == nil {
			t.Errorf("conditions=%s: 意図的に無制限なプレイブックがマッチしませんでした", cond)
		}
	}
}

// The console path is the mirror image: it must NOT hide the broken playbook,
// or the operator cannot repair what they cannot see. It reports the problem
// instead.
func TestTheConsolePathReportsTheBreakageInsteadOfHidingIt(t *testing.T) {
	var cond PlaybookConditions
	var actions []PlaybookAction

	// These two blobs decode PARTIALLY before failing: encoding/json fills the
	// fields it understands and then reports the one it does not. Without a
	// reset, the console would show 「重大度 ≥ 9」 as the scope of a playbook
	// whose scope it could not read — a half-decoded filter presented as the
	// real one, which is the same lie in a smaller size.
	msg := decodePlaybookConfig(
		[]byte(`{"min_severity":9,"hostname":{"glob":"dc-*"}}`),
		[]byte(`[{"type":"isolate_endpoint"},{"type":"notify","severity":"high"}]`),
		&cond, &actions)
	if msg == "" {
		t.Fatal("読めない設定が一覧で正常なプレイブックとして扱われています")
	}
	for _, want := range []string{"条件", "アクション"} {
		if !hasSub(msg, want) {
			t.Errorf("エラー文に %q が含まれていません: %s", want, msg)
		}
	}
	// And the half-decoded value must not be presented as a real scope.
	if cond != (PlaybookConditions{}) {
		t.Errorf("読めなかった条件が部分的に残っています: %+v。"+
			"コンソールには実際には効いていない絞り込みが表示されます", cond)
	}
	if actions != nil {
		t.Errorf("読めなかったアクションが部分的に残っています: %+v", actions)
	}

	// A healthy playbook carries no error.
	if msg := decodePlaybookConfig([]byte(`{"min_severity":9}`),
		[]byte(`[{"type":"notify"}]`), &cond, &actions); msg != "" {
		t.Errorf("正常なプレイブックにエラーが付いています: %s", msg)
	}
	if cond.MinSeverity != 9 || len(actions) != 1 {
		t.Errorf("正常なプレイブックの設定が読めていません: %+v %+v", cond, actions)
	}
}

// The fixtures above have to be valid jsonb, or they would be testing malformed
// JSON — a case Postgres rejects at write time and that therefore never reaches
// this code.
func TestTheFixturesAreValidJSON(t *testing.T) {
	for _, blob := range []string{
		`["min_severity",9]`, `{"min_severity":"9"}`, `{"min_severity":{"$gte":9}}`,
		`"min_severity=9"`, `{"type":"notify"}`, `["notify","isolate_endpoint"]`,
		`[{"type":"create_incident","severity":"9"}]`,
	} {
		if !json.Valid([]byte(blob)) {
			t.Errorf("fixture が JSON として不正です。jsonb 列には保存できないので"+
				"このケースは実際には起きません: %s", blob)
		}
	}
}

func hasSub(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ─── the loops ───────────────────────────────────────────────────────────────
//
// A rows.Err() failure needs a database that breaks partway through a result
// set, which no fixture here can arrange. It is pinned structurally instead,
// by TestEveryRowLoopInTheStoreChecksRowsErr in rows_err_contract_test.go,
// which covers this file along with every other one in the package.
//
// It is the failure with no symptom. The loop simply ends early and the short
// list is used as if it were the whole thing — playbooks that should have
// matched never run, and a history page shows fewer runs than happened. Nothing
// reports an error, because nobody asked for one.
