package transport

import (
	"testing"

	"google.golang.org/grpc/metadata"
)

// **ハートビートの応答から、両方向の指示を読むこと。**
//
// この経路は元は何も読んでいませんでした。`FallbackSender` は gRPC を
// 先に試すので、**gRPC が生きている通常時、サーバの巻き戻しは端末に
// 届きません** —— 直る条件と直らない条件が入れ替わっていました。
func TestHeartbeatHeadersCarryBothDirections(t *testing.T) {
	for _, c := range []struct {
		name       string
		md         metadata.MD
		iso, uniso bool
	}{
		{"隔離しろ", metadata.Pairs("x-edr-should-isolate", "1"), true, false},
		{"解除しろ", metadata.Pairs("x-edr-should-unisolate", "1"), false, true},
		{"何も無い", metadata.Pairs("x-edr-keepalive", "1"), false, false},
		{"空", metadata.MD{}, false, false},
	} {
		if got := headerSaysIsolate(c.md); got != c.iso {
			t.Errorf("%s: isolate=%v, want %v。**読まないと、サーバは"+
				"「隔離済み」、端末は繋がったままです**", c.name, got, c.iso)
		}
		if got := headerSaysUnisolate(c.md); got != c.uniso {
			t.Errorf("%s: unisolate=%v, want %v", c.name, got, c.uniso)
		}
	}
}
