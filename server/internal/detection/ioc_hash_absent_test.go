package detection

import "testing"

// 「一致しなかった」と「照合するものが無かった」を数え分けること。
//
// ハッシュの無いイベントは、ハッシュ照合を素通りします。**既知マルウェア
// に当たらなかったのと、当てるものが届かなかったのが、どちらも一致0件に
// なります。**
//
// これは実際に起きていました。エージェントは実行ファイルのハッシュを
// 計算していましたが proto に載せておらず、受け側の `addHashes` は
// **届くものが無いまま動いていました。** 直したので届きますが、
// 届かない端末（読めないファイル、権限不足）は残ります。数が伸びて
// いるあいだ、ハッシュ照合は実質動いていません。

func matcherWithAHash(t *testing.T) (*IOCMatcher, *int) {
	t.Helper()
	m := &IOCMatcher{}
	m.byType = map[string]map[string]*IOCRecord{
		"hash": {"deadbeef": {Type: "hash", Value: "deadbeef"}},
	}
	n := 0
	orig := noteHashAbsent
	noteHashAbsent = func() { n++ }
	t.Cleanup(func() { noteHashAbsent = orig })
	return m, &n
}

func TestAProcessEventWithNoHashIsCounted(t *testing.T) {
	m, n := matcherWithAHash(t)

	if got := m.CheckEvent(map[string]interface{}{
		"event_type": "process", "process_name": "x.exe",
	}); len(got) != 0 {
		t.Errorf("一致しないはずです: %v", got)
	}
	if *n != 1 {
		t.Errorf("ハッシュ無しが %d 件しか数えられていません。"+
			"「当たらなかった」と「当てるものが無かった」が同じ形のままです", *n)
	}
}

// ハッシュがあって一致しなかったときは、数えないこと。
// **数えると、正常な不一致が欠落に混ざります。**
func TestAProcessEventWithAHashIsNotCounted(t *testing.T) {
	m, n := matcherWithAHash(t)

	m.CheckEvent(map[string]interface{}{
		"event_type": "process", "sha256": "cafebabe",
	})
	if *n != 0 {
		t.Errorf("ハッシュのあるイベントを欠落として %d 件数えています", *n)
	}
}

// ハッシュのある一致は、これまで通り出ること。
func TestAMatchingHashStillMatches(t *testing.T) {
	m, _ := matcherWithAHash(t)
	got := m.CheckEvent(map[string]interface{}{
		"event_type": "process", "sha256": "DEADBEEF",
	})
	if len(got) != 1 {
		t.Fatalf("一致しませんでした: %v", got)
	}
}

// ネットワークイベントにハッシュが無いのは当たり前なので、数えないこと。
// **全部数えると、当たり前の欠落が本物の欠落を埋めます。**
func TestANetworkEventIsNotCountedAsMissingAHash(t *testing.T) {
	m, n := matcherWithAHash(t)

	m.CheckEvent(map[string]interface{}{
		"event_type": "network", "dst_ip": "203.0.113.1",
	})
	if *n != 0 {
		t.Errorf("ネットワークイベントを欠落として %d 件数えています", *n)
	}
}
