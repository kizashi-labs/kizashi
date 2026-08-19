//go:build linux && ebpf

package linux

import "testing"

// TestFileCollectorIsEBPFBackedUnderTag asserts the release build actually selects
// the eBPF file collector.
//
// The companion test in sensor_wiring_test.go checks that the implementation files
// are reachable under the release tag set. This one checks the result: that
// NewFileCollector returns the eBPF implementation rather than inotify.
//
// The distinction matters because the two failed independently on 2026-08-03. The
// deployed binary carried `-tags=ebpf` and still ran inotify, because it was built
// from a revision predating file_collector_select_ebpf.go — so `NewFileCollector`
// had only one definition and the tag changed nothing. File events then arrived
// with no pid or process name, and ransomware detection silently degraded to
// host-scoped counting. Nothing logged, because the fallback path that logs was
// never entered: there was no eBPF attempt to fall back FROM.
func TestFileCollectorIsEBPFBackedUnderTag(t *testing.T) {
	c := NewFileCollector()
	if _, ok := c.(*EBPFFileCollector); !ok {
		t.Fatalf("-tags ebpf ビルドで NewFileCollector が %T を返しました。"+
			"eBPF ファイルコレクタが選ばれていません＝ファイルイベントに pid/プロセス名が付かず、"+
			"ランサムウェア検知がプロセス特定不可のまま動きます（警告は出ません）", c)
	}
}
