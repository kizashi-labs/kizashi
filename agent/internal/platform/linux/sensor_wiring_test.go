//go:build linux

package linux

import (
	"go/build/constraint"
	"os"
	"strings"
	"testing"
)

// TestEBPFSensorsAreReachableWithTheEBPFTagAlone guards the defect that left two
// sensors dead in every shipped Linux build for months.
//
// The eBPF network monitor was gated on `linux && ebpf && prevention`. Nothing sets
// `prevention` in the shipped build, so `-tags ebpf` silently compiled the stub and
// the agent degraded to /proc/net polling — which only ever sees ESTABLISHED
// sockets, making a port scan of closed ports (T1046) permanently undetectable. The
// binary reported `-tags=ebpf` the whole time, so nothing about it looked wrong.
//
// A build tag is invisible: no test fails, no log appears, and the capability is
// simply absent. This test makes the gating explicit — every file implementing an
// eBPF sensor must be reachable under the tag set the release actually uses.
//
// It also catches the second half of the same failure: on 2026-08-03 the deployed
// binary was built from a revision where the eBPF FILE collector did not yet exist,
// so `NewFileCollector` returned the inotify implementation unconditionally and file
// events carried no process attribution (ransomware detection ran host-scoped).
// A missing file fails this test the same way a wrong tag does.
func TestEBPFSensorsAreReachableWithTheEBPFTagAlone(t *testing.T) {
	// The tag set a release build uses. If this ever needs another tag to reach a
	// sensor, that sensor is not in the product.
	releaseTags := map[string]bool{"linux": true, "ebpf": true}

	for _, f := range []struct {
		file string
		why  string
	}{
		{"file_collector_select_ebpf.go", "eBPF ファイルコレクタの選択（pid 帰属＝ランサム検知の前提）"},
		{"file_ebpf_collector.go", "eBPF ファイルコレクタ本体"},
		{"network_ebpf_loader.go", "eBPF ネットワーク監視のロード（T1046 の前提）"},
		{"network_ebpf_bridge.go", "eBPF ネットワーク監視のブリッジ"},
		{"process_ebpf.go", "eBPF プロセス監視"},
	} {
		src, err := os.ReadFile(f.file)
		if err != nil {
			t.Errorf("%s (%s) が存在しません。リリースビルドにこのセンサーは入りません: %v", f.file, f.why, err)
			continue
		}
		expr, ok := buildConstraintOf(string(src))
		if !ok {
			// No constraint at all means it is always built — fine for this purpose.
			continue
		}
		if !expr.Eval(func(tag string) bool { return releaseTags[tag] }) {
			t.Errorf("%s (%s) は -tags ebpf のリリースビルドから到達できません。\n"+
				"未使用のタグの陰に隠れたセンサーは、警告もエラーも出さずに丸ごと欠落します。",
				f.file, f.why)
		}
	}
}

// buildConstraintOf returns the parsed //go:build line of a Go source file.
func buildConstraintOf(src string) (constraint.Expr, bool) {
	for _, line := range strings.Split(src, "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if constraint.IsGoBuild(line) {
			expr, err := constraint.Parse(line)
			if err != nil {
				return nil, false
			}
			return expr, true
		}
		// Constraints must precede the package clause; stop once code starts.
		if strings.HasPrefix(line, "package ") {
			return nil, false
		}
	}
	return nil, false
}

// TestEveryEBPFSensorRegistersATelemetryMode closes the hole that made the fleet's
// own degradation alarm blind to the sensor it most needed to watch.
//
// telemetry.Aggregate() is deliberately pessimistic — one degraded sensor turns the
// whole agent into "poll" — but it can only be pessimistic about sensors it has
// heard from. A collector that never calls telemetry.Set is not "unknown", it is
// ABSENT: the aggregate happily reports "ebpf" while that sensor runs blind.
//
// The file collector was in exactly that state. On 2026-08-03 it had fallen back to
// inotify (no process attribution, so ransomware detection could not name a process)
// and the endpoint still reported telemetry_mode=ebpf, so neither the fleet view nor
// the degradation alert had anything to fire on. The two sensors that DID register —
// process and network — are why anything was visible at all.
//
// This test asserts every sensor implementation reaches the registry, by requiring
// each one's source to mention its sensor constant. Crude on purpose: a stricter
// runtime check would need the eBPF programs to load, which no CI runner guarantees,
// and a sensor that never names its constant certainly never registers.
func TestEveryEBPFSensorRegistersATelemetryMode(t *testing.T) {
	for _, s := range []struct {
		constant string
		files    []string
		why      string
	}{
		{"telemetrySensorProcess", []string{"process_ebpf.go"}, "プロセス監視"},
		{"telemetrySensorNetwork", []string{"network_ebpf.go"}, "ネットワーク監視（T1046）"},
		{"telemetrySensorFile", []string{"file_ebpf_collector.go", "file_collector_select_noebpf.go"},
			"ファイル監視（ランサム検知の pid 帰属）"},
	} {
		found := false
		for _, f := range s.files {
			b, err := os.ReadFile(f)
			if err != nil {
				continue
			}
			if strings.Contains(string(b), s.constant) {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s (%s) がどこからも telemetry に登録されていません。\n"+
				"登録しないセンサーは集約値を悲観的にできないため、降格しても "+
				"telemetry_mode は ebpf のままになり、フリート表示にも降格アラートにも出ません。",
				s.constant, s.why)
		}
	}
}
