package ingestion

import "testing"

// **gRPC の経路にも突き合わせがあること。**
//
// 元はここに1つもありませんでした。`FallbackSender` は gRPC を先に試すので、
// **gRPC が生きている通常時、HTTP 側の `should_unisolate` は端末に
// 届きません** —— 直る条件（gRPC が落ちている）と直らない条件（gRPC は
// 生きていて指示だけが落ちた）が入れ替わっていました。
func TestIsolationHeadersGoBothWays(t *testing.T) {
	for _, c := range []struct {
		name, db, reported string
		want               string
	}{
		{"DB は隔離、端末は繋がっている", "isolated", "online", "x-edr-should-isolate"},
		{"DB は解除、端末は隔離中", "online", "isolated", "x-edr-should-unisolate"},
		{"どちらも隔離", "isolated", "isolated", ""},
		{"どちらも通常", "online", "online", ""},
	} {
		got := isolationHeaders(c.db, c.reported)
		if c.want == "" {
			if len(got) != 0 {
				t.Errorf("%s: %v を返しました（何も要りません）", c.name, got)
			}
			continue
		}
		if len(got) != 1 || got[0] != c.want {
			t.Errorf("%s: %v, want [%s]。**片方向だけだと、直る失敗と"+
				"直らない失敗ができます**", c.name, got, c.want)
		}
	}
}
