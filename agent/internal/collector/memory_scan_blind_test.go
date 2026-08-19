package collector

import (
	"errors"
	"io/fs"
	"os"
	"testing"

	"github.com/edr-platform/agent/internal/telemetry"
)

// メモリスキャナは RWX / 非バック実行領域 —— **コード注入とシェルコード**
// を探します。開けなかったプロセスの中は見ていません。
//
// **その数は端末の中にしかありませんでした。** 出ていたのは
// `slog.Debug` の1行で、既定のログ水準では出ません。サーバから見ると、
// 注入されていない端末と、中を見られなかった端末が同じ姿です。
//
// そして数そのものが使えませんでした。`SkippedUnreadable` は
// 「断られた」と「もう居なかった」を1つに入れていました ——
// **プロセスは走査中に普通に終了する**ので、健全な端末でも毎周期
// ゼロになりません。ゼロにならない数では「見えていない端末」を
// 判定できず、実際どこも判定していませんでした。
//
// 効くのは Windows です。`MemoryScanStats` のコメントが言うとおり、
// **SeDebugPrivilege が無いとシステムプロセスはほぼ開けません。**
//
// （このコンテナ (uid=0, Linux) では 74 件を列挙して 74 件とも走査でき、
// 断られたものはありません。**動いている面を測って、そこが健全だと
// 分かったうえで、判定の作りだけを直しています。**）

func clearMemScanTelemetry(t *testing.T) {
	t.Helper()
	t.Cleanup(func() { telemetry.Forget(memScanSensor) })
	telemetry.Forget(memScanSensor)
}

func memScanTelemetry() (telemetry.SensorState, bool) {
	for _, s := range telemetry.Snapshot() {
		if s.Sensor == memScanSensor {
			return s, true
		}
	}
	return telemetry.SensorState{}, false
}

// 終了したプロセスと、断られたプロセスを分けること。
func TestClassifySkipSeparatesGoneFromDenied(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want skipReason
	}{
		{"走査できた", nil, skipNone},
		{"もう居ない", fs.ErrNotExist, skipGone},
		{"包まれた ENOENT", &fs.PathError{Op: "open", Err: fs.ErrNotExist}, skipGone},
		{"断られた", fs.ErrPermission, skipDenied},
		{"包まれた EACCES", &fs.PathError{Op: "open", Err: fs.ErrPermission}, skipDenied},
		// **分からない失敗は「正常」に倒しません。** 倒すと、見えて
		// いないことが健全と同じ姿になります。
		{"分からない失敗", errors.New("i/o error"), skipDenied},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := classifySkip(tc.err); got != tc.want {
				t.Errorf("classifySkip(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// 断られたプロセスがあることが、端末の外に出ること。
func TestDeniedProcessesAreReportedOffTheEndpoint(t *testing.T) {
	clearMemScanTelemetry(t)
	MemoryScanStats{ProcessesEnumerated: 200, ProcessesScanned: 4, SkippedUnreadable: 196}.report()

	st, ok := memScanTelemetry()
	if !ok {
		t.Fatal("196 件を開けていないのに telemetry に何もありません。" +
			"**サーバから見て、注入されていない端末と同じ姿です**")
	}
	if st.Mode != telemetry.ModeFailed {
		t.Errorf("mode = %q, want %q", st.Mode, telemetry.ModeFailed)
	}
	if st.Reason == "" {
		t.Error("理由が空です。件数が無いと、1件なのか全部なのか分かりません")
	}
}

// 1件も列挙できなかったことが、出ること。
//
// **所見0件と、走査0件は別です。**
func TestScanningNothingIsReported(t *testing.T) {
	clearMemScanTelemetry(t)
	MemoryScanStats{}.report()

	st, ok := memScanTelemetry()
	if !ok || st.Mode != telemetry.ModeFailed {
		t.Fatalf("1件も列挙できていないのに telemetry = %+v (ok=%v)", st, ok)
	}
}

// 終了したプロセスだけなら、赤くしないこと。
//
// **プロセスは走査中に普通に終了します。** ここを数えると、健全な端末が
// 毎周期赤くなり、本当に見えていない端末がその中に埋もれます。
func TestProcessesThatMerelyExitedAreNotABlindSpot(t *testing.T) {
	clearMemScanTelemetry(t)
	MemoryScanStats{ProcessesEnumerated: 200, ProcessesScanned: 190, SkippedGone: 10}.report()

	if st, ok := memScanTelemetry(); ok {
		t.Errorf("終了しただけのプロセス 10 件で %q になっています (%s)", st.Mode, st.Reason)
	}
}

// 健全なら、登録しないこと。
func TestAHealthyMemoryScanRegistersNothing(t *testing.T) {
	clearMemScanTelemetry(t)
	MemoryScanStats{ProcessesEnumerated: 74, ProcessesScanned: 74}.report()

	if st, ok := memScanTelemetry(); ok {
		t.Errorf("健全なのに %q として登録されています (%s)", st.Mode, st.Reason)
	}
}

// 開けるように戻ったら、登録も消えること。
// **直らない赤は、赤でないのと同じです。**
func TestARecoveredMemoryScanStopsReportingFailed(t *testing.T) {
	clearMemScanTelemetry(t)
	MemoryScanStats{ProcessesEnumerated: 200, SkippedUnreadable: 196}.report()
	if _, ok := memScanTelemetry(); !ok {
		t.Fatal("断られた時点で登録されていません")
	}

	MemoryScanStats{ProcessesEnumerated: 200, ProcessesScanned: 200}.report()
	if st, ok := memScanTelemetry(); ok {
		t.Errorf("開けるように戻ったのに %q のままです (%s)", st.Mode, st.Reason)
	}
}

// 数えた内訳が、ログに出ること。**2つに分けた意味がここに出ます。**
func TestTheSkipBreakdownIsLogged(t *testing.T) {
	args := MemoryScanStats{SkippedUnreadable: 3, SkippedGone: 7}.LogArgs()
	found := map[string]any{}
	for i := 0; i+1 < len(args); i += 2 {
		if k, ok := args[i].(string); ok {
			found[k] = args[i+1]
		}
	}
	if found["skipped_unreadable"] != 3 {
		t.Errorf("skipped_unreadable = %v, want 3", found["skipped_unreadable"])
	}
	if found["skipped_gone"] != 7 {
		t.Errorf("skipped_gone = %v, want 7。**分けた意味が読む人に届きません**",
			found["skipped_gone"])
	}
}

// 本物のスキャンが、report を通っていること。
//
// **`report` だけ検査して、呼ばれていなければ何も変わりません。**
func TestARealScanReportsItsCoverage(t *testing.T) {
	if _, err := os.Stat("/proc/self/maps"); err != nil {
		t.Skip("この環境に /proc がありません")
	}
	clearMemScanTelemetry(t)
	telemetry.Set(memScanSensor, telemetry.ModeFailed, "前の周期の残り")

	_, st := ScanSuspiciousMemoryWithYARAStats(nil)
	if st.ProcessesEnumerated == 0 {
		t.Fatal("1件も列挙できていません")
	}
	if st.SkippedUnreadable > 0 {
		t.Skipf("この環境では %d 件が開けません", st.SkippedUnreadable)
	}
	if state, ok := memScanTelemetry(); ok {
		t.Errorf("健全なスキャンのあとに %q が残っています (%s)。"+
			"**report が呼ばれていません**", state.Mode, state.Reason)
	}
}
