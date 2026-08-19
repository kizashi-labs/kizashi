//go:build linux

package collector

import (
	"io/fs"
	"reflect"
	"testing"

	"github.com/edr-platform/agent/internal/telemetry"
)

// 走査ループの数え分け。
//
// **この端末では 74 件を列挙して 74 件とも走査でき、断られたものが
// ありません。** 実環境が必ず成功する条件では、数え分けの分岐を一度も
// 通れません —— 変異が1件生き残って分かりました。読み取りを差し替えて
// 通します。

func withMapsSkip(t *testing.T, skip skipReason) {
	t.Helper()
	orig := scanPidMapsStatsFn
	scanPidMapsStatsFn = func(int, string) ([]MemoryFinding, int, skipReason) {
		return nil, 0, skip
	}
	t.Cleanup(func() { scanPidMapsStatsFn = orig })
}

// 断られたプロセスが「断られた」として数えられること。
func TestDeniedProcessesLandInSkippedUnreadable(t *testing.T) {
	clearMemScanTelemetry(t)
	withMapsSkip(t, skipDenied)

	_, st := scanSuspiciousMemoryStats()
	if st.ProcessesEnumerated == 0 {
		t.Fatal("1件も列挙できていません")
	}
	if st.SkippedUnreadable == 0 {
		t.Fatalf("全部断られたのに SkippedUnreadable=0 (gone=%d scanned=%d)",
			st.SkippedGone, st.ProcessesScanned)
	}
	if st.SkippedGone != 0 {
		t.Errorf("断られたものが SkippedGone に %d 件入っています。"+
			"**プロセスは走査中に普通に終了するので、混ぜるとこの数は"+
			"「見えていない端末」の判定に使えません**", st.SkippedGone)
	}
	if st.ProcessesScanned != 0 {
		t.Errorf("開けていないのに %d 件を走査したことになっています", st.ProcessesScanned)
	}
}

// 終了していたプロセスが「終了していた」として数えられること。
func TestGoneProcessesLandInSkippedGone(t *testing.T) {
	clearMemScanTelemetry(t)
	withMapsSkip(t, skipGone)

	_, st := scanSuspiciousMemoryStats()
	if st.SkippedGone == 0 {
		t.Fatalf("全部終了していたのに SkippedGone=0 (unreadable=%d)", st.SkippedUnreadable)
	}
	if st.SkippedUnreadable != 0 {
		t.Errorf("終了しただけのものが SkippedUnreadable に %d 件入っています。"+
			"**健全な端末が毎周期赤くなります**", st.SkippedUnreadable)
	}
}

// 断られたときだけ、端末の外に出ること。
func TestOnlyDeniedProcessesTurnTheEndpointRed(t *testing.T) {
	clearMemScanTelemetry(t)

	withMapsSkip(t, skipGone)
	_, _ = ScanSuspiciousMemoryWithYARAStats(nil)
	if st, ok := memScanTelemetry(); ok {
		t.Errorf("終了しただけで %q になっています (%s)", st.Mode, st.Reason)
	}

	withMapsSkip(t, skipDenied)
	_, _ = ScanSuspiciousMemoryWithYARAStats(nil)
	st, ok := memScanTelemetry()
	if !ok || st.Mode != telemetry.ModeFailed {
		t.Fatalf("全部断られたのに telemetry = %+v (ok=%v)", st, ok)
	}
}

// 本物の走査が、分類を通っていること。
func TestScanPidMapsClassifiesAMissingPID(t *testing.T) {
	_, _, skip := scanPidMapsStats(1<<30, "nosuch")
	if skip != skipGone {
		t.Errorf("存在しない PID の skip = %v, want skipGone", skip)
	}
	// 自分自身は走査できること。**塞ぐ側だけ直して、読めるものまで
	// 落としていないこと。**
	_, regions, skip := scanPidMapsStats(1, "init")
	if skip == skipNone && regions == 0 {
		t.Error("走査できたのに領域が0件です")
	}
	if skip == skipDenied {
		t.Skip("この環境では PID 1 を開けません")
	}
}

// 既定が本物を指していること。差し替えられる作りにした分、要ります。
func TestTheDefaultMapsScannerIsTheRealOne(t *testing.T) {
	if reflect.ValueOf(scanPidMapsStatsFn).Pointer() != reflect.ValueOf(scanPidMapsStats).Pointer() {
		t.Error("scanPidMapsStatsFn が本物の実装を指していません")
	}
	// 分類の既定も本物であること。
	if classifySkip(fs.ErrNotExist) != skipGone {
		t.Error("classifySkip が終了を検出できていません")
	}
}
