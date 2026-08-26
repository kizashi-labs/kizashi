package rules

import (
	"context"
	"fmt"
	"sort"
	"testing"
)

// logsource インデックスの安全性を機械的に担保するテスト群。
//
// このインデックスは「速くする」ためのものだが、失敗の仕方が危険である。
// 絞りすぎるとルールが評価されなくなり、外形は「検知能力の欠落」と区別がつかない
// (アラートが出ないだけで、エラーもログも出ない)。実際、導入時に既存テスト3件が
// 落ちて初めて、本コードベースでは logsource.category とイベント種別が
// 1:1 に対応していないことが分かった。
//
// したがって最重要のテストは「インデックスの有無で結果が変わらないこと」である。

func idxRule(id, category, field, value string) *DetectionRule {
	content := fmt.Sprintf(`
title: %s
logsource:
  category: %s
detection:
  sel:
    %s: '%s'
  condition: sel
`, id, category, field, value)
	if category == "" {
		content = fmt.Sprintf(`
title: %s
detection:
  sel:
    %s: '%s'
  condition: sel
`, id, field, value)
	}
	return &DetectionRule{ID: id, Name: id, Type: "sigma", Enabled: true, Severity: 50, Content: content}
}

func matchedIDs(t *testing.T, e *RuleEngine, evt map[string]interface{}) []string {
	t.Helper()
	ms, err := e.Evaluate(context.Background(), evt)
	if err != nil {
		t.Fatalf("Evaluate: %v", err)
	}
	ids := make([]string, 0, len(ms))
	for _, m := range ms {
		ids = append(ids, m.RuleID)
	}
	sort.Strings(ids)
	return ids
}

// 本テストの主眼。インデックスを切っても入れても、同じイベントに対して
// 同じルールが一致しなければならない。差が出たらそれは高速化ではなく検知の欠落である。
func TestLogsourceIndex_SameResultsWithAndWithout(t *testing.T) {
	rules := []*DetectionRule{
		idxRule("proc-1", "process_creation", "Image", `C:\Windows\System32\cmd.exe`),
		idxRule("img-1", "image_load", "ImageLoaded", `C:\Temp\evil.dll`),
		idxRule("net-1", "network_connection", "DestinationIp", "10.0.0.5"),
		idxRule("dns-1", "dns_query", "QueryName", "evil.example.com"),
		idxRule("file-1", "file_event", "TargetFilename", `C:\Temp\x.txt`),
		idxRule("nocat-1", "", "Image", `C:\Windows\System32\cmd.exe`),
		// 本コードベースでは category とイベント種別がクロスする。
		// ps_script のルールが process イベントで一致するケースを含める。
		idxRule("ps-1", "ps_script", "CommandLine", "Get-ChildItem -Recurse"),
		idxRule("crt-1", "create_remote_thread", "SourceImage", `C:\Temp\injector.exe`),
	}

	events := []map[string]interface{}{
		{"type": "process", "agent_id": "h", "platform": "windows", "Image": `C:\Windows\System32\cmd.exe`},
		{"type": "process", "agent_id": "h", "platform": "windows", "CommandLine": "Get-ChildItem -Recurse"},
		{"type": "process", "agent_id": "h", "platform": "windows", "SourceImage": `C:\Temp\injector.exe`},
		{"type": "image_load", "agent_id": "h", "platform": "windows", "ImageLoaded": `C:\Temp\evil.dll`},
		{"type": "network", "agent_id": "h", "platform": "windows", "DestinationIp": "10.0.0.5"},
		{"type": "dns", "agent_id": "h", "platform": "windows", "QueryName": "evil.example.com"},
		{"type": "file", "agent_id": "h", "platform": "windows", "TargetFilename": `C:\Temp\x.txt`},
		{"type": "script", "agent_id": "h", "platform": "windows", "CommandLine": "Get-ChildItem -Recurse"},
		// マッピングに無い種別。全ルール評価にフォールバックしなければならない。
		{"type": "tls_handshake", "agent_id": "h", "platform": "windows", "Image": `C:\Windows\System32\cmd.exe`},
		{"type": "未知の種別", "agent_id": "h", "platform": "windows", "Image": `C:\Windows\System32\cmd.exe`},
		// type が欠落したイベント。ここで絞ってはいけない。
		{"agent_id": "h", "platform": "windows", "Image": `C:\Windows\System32\cmd.exe`},
	}

	for i, evt := range events {
		off := NewRuleEngine()
		off.LoadRules(rules)
		off.SetLogsourceIndex(false)
		want := matchedIDs(t, off, evt)

		on := NewRuleEngine()
		on.LoadRules(rules)
		got := matchedIDs(t, on, evt)

		if fmt.Sprint(want) != fmt.Sprint(got) {
			t.Errorf("event[%d] (type=%v): インデックスの有無で結果が変わった\n  index無し: %v\n  index有り: %v",
				i, evt["type"], want, got)
		}
		if len(want) == 0 {
			t.Errorf("event[%d] (type=%v): どのルールにも一致しないテストデータでは差を検出できない", i, evt["type"])
		}
	}
}

// eventTypeCategories に載っていない category を持つルールは、
// 「どの種別に紐づくか不明」として常時評価に落ちなければならない。
// SigmaHQ 同期で新カテゴリが増えたときに黙って死蔵させないための保証。
func TestLogsourceIndex_UnknownCategoryIsAlwaysEvaluated(t *testing.T) {
	r := idxRule("unknown-cat", "antivirus", "Image", `C:\Temp\evil.exe`)
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{r})

	if knownCategories["antivirus"] {
		t.Fatal("前提が崩れている: antivirus が knownCategories に入っている")
	}
	for _, et := range []string{"process", "file", "dns", "image_load", "auth"} {
		evt := map[string]interface{}{"type": et, "agent_id": "h", "Image": `C:\Temp\evil.exe`}
		if got := matchedIDs(t, e, evt); len(got) != 1 {
			t.Errorf("type=%s: 未知 category のルールが評価されなかった (matched=%v)", et, got)
		}
	}
}

// マッピングに載せていない種別(auth 等)は全ルール評価にフォールバックする。
//
// 当初これらを `{}` として明示的に登録し「常時評価ルールのみ走る」設計にしていたが、
// 上の on/off 一致テストが tls_handshake で差を検出した。FlatMap は種別に関係なく
// フィールドを載せるので、「auth イベントに Image は来ない」と決めつけられない。
// 絞れる確信が無い種別は絞らない。
func TestLogsourceIndex_UnmappedTypesEvaluateEverything(t *testing.T) {
	e := NewRuleEngine()
	e.LoadRules([]*DetectionRule{
		idxRule("nocat", "", "User", "admin"),
		idxRule("proc", "process_creation", "User", "admin"),
	})
	for _, et := range []string{"auth", "memory", "tls_handshake", "process_stats", "service_installed"} {
		evt := map[string]interface{}{"type": et, "agent_id": "h", "User": "admin"}
		got := matchedIDs(t, e, evt)
		if len(got) != 2 {
			t.Errorf("type=%s: 未マッピング種別は全ルール評価のはず: matched=%v", et, got)
		}
	}
}

// インデックスが実際に評価対象を減らしていることの確認。
// 減っていなければ高速化になっていない(安全側に倒しすぎ)。
func TestLogsourceIndex_ActuallyNarrows(t *testing.T) {
	rules := make([]*DetectionRule, 0, 40)
	for i := 0; i < 20; i++ {
		rules = append(rules, idxRule(fmt.Sprintf("p%d", i), "process_creation", "Image", fmt.Sprintf(`C:\p%d.exe`, i)))
	}
	for i := 0; i < 20; i++ {
		rules = append(rules, idxRule(fmt.Sprintf("i%d", i), "image_load", "ImageLoaded", fmt.Sprintf(`C:\i%d.dll`, i)))
	}
	e := NewRuleEngine()
	e.LoadRules(rules)

	nImage := len(e.index.candidates("image_load"))
	nAll := len(e.index.all)
	if nImage >= nAll {
		t.Errorf("image_load の候補が絞れていない: %d / 全 %d", nImage, nAll)
	}
	if nImage != 20 {
		t.Errorf("image_load の候補は image_load ルール20件のはず: %d", nImage)
	}
}
