//go:build linux

package linux

import (
	"errors"
	"log/slog"

	"github.com/edr-platform/agent/internal/telemetry"
)

// Sensor names recorded in the telemetry mode registry. Kept as constants so the
// agent-side diagnostics and the heartbeat aggregate agree on spelling.
const (
	telemetrySensorProcess = "process"
	telemetrySensorNetwork = "network"
	telemetrySensorFile    = "file"
)

// errEBPFUnsupported is the reason recorded when the host never qualified for
// eBPF in the first place (old kernel / no BTF), as opposed to qualifying and
// then failing to load.
var errEBPFUnsupported = errors.New("eBPF非対応(カーネル要件未達 または ebpfタグ無しビルド)")

// degradeToPolling records the sensor's effective mode and says so out loud.
//
// This exists because the fallback used to be entirely silent: the collector
// swallowed the error and started the poller, so an endpoint running blind was
// indistinguishable from a healthy one in both logs and the fleet view. Two
// sensors sat dead in every shipped build for months behind exactly that silence
// (docs/検知率向上_20260726_prevention誤ゲートによるeBPF死角.md).
//
// impact is a short, sensor-specific note on what stops being detectable — the
// point is that a reader of the log sees the security consequence, not just that
// some subsystem changed mode.
func degradeToPolling(sensor string, cause error, impact string) {
	reason := "unknown"
	if cause != nil {
		reason = cause.Error()
	}
	telemetry.Set(sensor, telemetry.ModePoll, reason)
	slog.Warn("[telemetry] eBPFが使えずポーリングに降格しました — 検知能力が下がっています",
		"sensor", sensor,
		"mode", string(telemetry.ModePoll),
		"reason", reason,
		"impact", impact)
}
