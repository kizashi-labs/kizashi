// Package telemetry records which collection mechanism each sensor is *actually*
// running on, as opposed to what the host is capable of.
//
// The distinction matters. Package protection already reports a host-capability
// tier (enforce/observe/poll) derived from kernel version, BTF and the LSM list —
// but that describes what the machine *could* do. It says nothing about what this
// particular binary ended up doing: an agent built without the "ebpf" tag, or one
// whose eBPF consumer was excluded by a build tag, silently degrades to /proc
// polling on a fully eBPF-capable host. The fleet view then shows those endpoints
// as eBPF-capable while they are in fact polling.
//
// That gap is not hypothetical: the Linux network connect-tracer and the fileless
// sensor were both dead code in every shipped build for months (see
// docs/検知率向上_20260726_prevention誤ゲートによるeBPF死角.md). Nothing surfaced it,
// because falling back to polling is a designed, silent normal path. This package
// makes the effective mode explicit so the degradation is visible instead.
package telemetry

import (
	"fmt"
	"sort"
	"sync"
)

// Mode is the mechanism a sensor is actually collecting with.
type Mode string

const (
	// ModeEBPF: the eBPF program loaded and attached — in-kernel capture.
	ModeEBPF Mode = "ebpf"

	// ModePoll: degraded to userspace polling (/proc, /proc/net). Structurally
	// blind to anything that does not survive until the next poll tick, and — for
	// the network sensor — to connection attempts that never establish.
	ModePoll Mode = "poll"

	// ModeOff: the sensor is not running at all (disabled by config, or the
	// platform has no implementation).
	ModeOff Mode = "off"

	// ModeFailed: the sensor was supposed to be running and could not start.
	//
	// **ModeOff とは別にしてあります。** off は選んだ結果で、failed は
	// 望んだのに届かなかった結果です。Aggregate は off を無視します
	// （設定の選択を劣化として数えないため）が、failed を無視すると
	// **起動に失敗したセンサーが「無効にしてある」と同じ姿**になります。
	//
	// これが要るのは Windows の ETW センサー7本です。登録に失敗しても
	// Start は nil を返して動き続けるので、サーバから見た端末は
	// **何も起きていない端末とまったく同じ**でした。イベントが来ない、
	// アラートも出ない、ハートビートは届く、画面は緑。
	// 攻撃されていないことと、見えていないことの区別がつきません。
	ModeFailed Mode = "failed"
)

// SensorState is one sensor's effective mode plus why it ended up there.
type SensorState struct {
	Sensor string
	Mode   Mode
	// Reason explains a non-eBPF mode in one human-readable line. Empty for
	// ModeEBPF, where there is nothing to explain.
	Reason string
}

var (
	mu      sync.RWMutex
	sensors = map[string]SensorState{}
)

// Set records a sensor's effective mode. Safe for concurrent use; collectors
// call it from their own goroutines as they settle into a mode.
func Set(sensor string, mode Mode, reason string) {
	mu.Lock()
	defer mu.Unlock()
	sensors[sensor] = SensorState{Sensor: sensor, Mode: mode, Reason: reason}
}

// Forget removes a sensor's entry.
//
// **失敗したまま登録が残ると、直っても赤いままです。** 一時的な理由で
// 落ちるセンサーがあります —— FIM は権限やマウントの都合で読めなかった
// ファイルを ModeFailed で登録しますが、それが解消したときに戻す口が
// 無いと、その端末は永久に「見えていない面がある」と表示され続けます。
//
// **直らない赤は、赤でないのと同じです。** 見る人が無視するようになり、
// 本当に落ちた端末がその中に埋もれます。
func Forget(sensor string) {
	mu.Lock()
	defer mu.Unlock()
	delete(sensors, sensor)
}

// Snapshot returns the recorded sensors ordered by name, for diagnostics.
func Snapshot() []SensorState {
	mu.RLock()
	defer mu.RUnlock()
	out := make([]SensorState, 0, len(sensors))
	for _, s := range sensors {
		out = append(out, s)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Sensor < out[j].Sensor })
	return out
}

// Aggregate reduces the per-sensor modes to the single value reported in the
// heartbeat. It is deliberately pessimistic: one degraded sensor makes the whole
// agent "poll", because a fleet view that rounds partial degradation up to "ebpf"
// would recreate exactly the blind spot this package exists to remove.
//
// Sensors in ModeOff are ignored — a disabled sensor is a configuration choice,
// not a degradation. If every recorded sensor is off, the result is ModeOff.
//
// An empty registry returns the empty string, meaning "not reported": today only
// the Linux collectors register, so Windows and macOS would otherwise report a
// misleading "off" for sensors that are in fact running happily on ETW/ESF. The
// heartbeat path skips empty values, so those agents simply say nothing here.
func Aggregate() Mode {
	mu.RLock()
	defer mu.RUnlock()
	return aggregate(sensors)
}

// aggregate is the pure form, kept separate so the reduction is unit-testable
// without touching package state.
func aggregate(in map[string]SensorState) Mode {
	if len(in) == 0 {
		return ""
	}
	// **失敗がいちばん重い。** 1本でも起動できていないなら、
	// 他が健全でもその端末には見えていない面があります。
	// poll より前に見るのは、poll は「劣った手段で見えている」で、
	// failed は「見えていない」だからです。
	for _, s := range in {
		if s.Mode == ModeFailed {
			return ModeFailed
		}
	}
	active := 0
	for _, s := range in {
		if s.Mode == ModeOff {
			continue
		}
		active++
		if s.Mode != ModeEBPF {
			return ModePoll
		}
	}
	if active == 0 {
		return ModeOff
	}
	return ModeEBPF
}

// String renders the snapshot as one log-friendly line, e.g.
// "network=poll(no ebpf tag) process=ebpf".
func String() string {
	s := ""
	for i, st := range Snapshot() {
		if i > 0 {
			s += " "
		}
		if st.Reason != "" {
			s += fmt.Sprintf("%s=%s(%s)", st.Sensor, st.Mode, st.Reason)
			continue
		}
		s += fmt.Sprintf("%s=%s", st.Sensor, st.Mode)
	}
	return s
}
