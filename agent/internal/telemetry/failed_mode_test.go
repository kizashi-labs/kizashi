package telemetry

import "testing"

// 起動に失敗したセンサーが、集約から消えないこと。
//
// `aggregate` は `ModeOff` を無視します —— 無効にしてあるのは設定の選択で、
// 劣化ではないからです。正しい判断ですが、**起動に失敗したセンサーを
// off として記録すると、同じ扱いで消えます。** 「無効にしてある」と
// 「動かしたかったのに動いていない」が同じ姿になります。
//
// これが要るのは Windows の ETW センサー7本です。登録に失敗しても
// Start は nil を返して続きます。サーバから見ると、その端末は
// **何も起きていない端末とまったく同じ**でした。

func TestAFailedSensorIsNotSwallowed(t *testing.T) {
	got := aggregate(map[string]SensorState{
		"process":      {Sensor: "process", Mode: ModeEBPF},
		"etw_registry": {Sensor: "etw_registry", Mode: ModeFailed, Reason: "access denied"},
	})
	if got != ModeFailed {
		t.Errorf("aggregate = %q, want %q。健全なセンサーが1本あれば、"+
			"落ちている面は報告されません", got, ModeFailed)
	}
}

// 失敗は、劣化より重いこと。
// poll は「劣った手段で見えている」、failed は「見えていない」です。
func TestFailedOutranksPoll(t *testing.T) {
	got := aggregate(map[string]SensorState{
		"network":      {Sensor: "network", Mode: ModePoll, Reason: "no ebpf tag"},
		"etw_registry": {Sensor: "etw_registry", Mode: ModeFailed, Reason: "access denied"},
	})
	if got != ModeFailed {
		t.Errorf("aggregate = %q, want %q", got, ModeFailed)
	}
}

// 無効にしてあるセンサーは、これまで通り無視されること。
// **失敗を数えるついでに、設定の選択まで劣化に数えないこと。**
// 数えると、意図的に切ってある端末が全部「劣化」になり、
// 本物の失敗がその中に埋もれます。
func TestDisabledSensorsAreStillIgnored(t *testing.T) {
	got := aggregate(map[string]SensorState{
		"process":      {Sensor: "process", Mode: ModeEBPF},
		"etw_registry": {Sensor: "etw_registry", Mode: ModeOff, Reason: "disabled"},
	})
	if got != ModeEBPF {
		t.Errorf("aggregate = %q, want %q", got, ModeEBPF)
	}
}

// 失敗しか無いときも failed であること（off に落ちないこと）。
func TestOnlyFailedSensorsReportFailed(t *testing.T) {
	got := aggregate(map[string]SensorState{
		"etw_registry": {Sensor: "etw_registry", Mode: ModeFailed, Reason: "x"},
		"etw_wmi":      {Sensor: "etw_wmi", Mode: ModeFailed, Reason: "y"},
	})
	if got != ModeFailed {
		t.Errorf("aggregate = %q, want %q", got, ModeFailed)
	}
}

// 何も登録されていなければ、これまで通り「未報告」であること。
//
// **健全な Windows / macOS の端末は、いまも何も登録しません。**
// ここが "off" に変わると、ポーリング系が元気に動いている端末まで
// 「何も集めていない」と読めます。
func TestNothingRegisteredIsStillUnreported(t *testing.T) {
	if got := aggregate(map[string]SensorState{}); got != "" {
		t.Errorf("aggregate = %q, want 空", got)
	}
}

// 失敗した理由が、記録に残ること。
// 「落ちている」だけでは、権限不足なのかプロバイダ不在なのか分かりません。
func TestTheReasonSurvives(t *testing.T) {
	Set("etw_registry", ModeFailed, "access denied")
	t.Cleanup(func() {
		mu.Lock()
		delete(sensors, "etw_registry")
		mu.Unlock()
	})

	for _, s := range Snapshot() {
		if s.Sensor == "etw_registry" {
			if s.Mode != ModeFailed {
				t.Errorf("mode = %q, want %q", s.Mode, ModeFailed)
			}
			if s.Reason != "access denied" {
				t.Errorf("reason = %q", s.Reason)
			}
			return
		}
	}
	t.Error("記録されていません")
}
