package tamper

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"os"
	"time"
)

// DefaultInterval is how often the monitor re-checks its watched files and the
// supervising watchdog. Tampering with the agent is not a high-rate event, and
// each pass costs a SHA-256 over two small files, so a coarse interval is the
// right trade.
const DefaultInterval = 5 * time.Minute

// WatchdogPIDEnv carries the supervising watchdog's PID to the agent it starts.
//
// The alternative — having the agent locate the watchdog's PID file — couples the
// agent to a path the watchdog can change with a flag, and gets it wrong silently
// when it does. An environment variable is set once at spawn and cannot be
// rewritten by anything that isn't already inside the process.
const WatchdogPIDEnv = "EDR_WATCHDOG_PID"

// watched is one file the monitor fingerprints at start and re-checks on every
// pass.
type watched struct {
	path      string
	component string
	// tamperType distinguishes a modified binary from a modified config; both are
	// integrity failures but they mean different things to an analyst.
	tamperType string
}

// Monitor watches the agent's own on-disk files and its supervising watchdog, and
// reports changes as tamper findings.
//
// The baseline is taken in memory at start rather than read from a file on disk.
// That is the point: a stored baseline lives in the same directory as the thing
// it protects, so whoever can rewrite the binary can rewrite the baseline with
// it. An in-memory baseline cannot be reached without already being inside the
// process, at the cost of not surviving a restart — which is the case
// internal/integrity's start-up check covers.
type Monitor struct {
	interval    time.Duration
	report      func(Payload)
	files       []watched
	watchdogPID int

	baseline map[string]string
	// reported suppresses repeats. Without it a modified binary would emit a
	// finding on every pass for as long as the agent runs, and the fiftieth copy
	// tells an analyst nothing the first did not.
	reported map[string]bool
}

// NewMonitor returns a monitor that hands findings to report. A nil report is
// treated as a programming error by the caller, not silently tolerated here —
// callers construct this with a real sender.
func NewMonitor(report func(Payload)) *Monitor {
	return &Monitor{
		interval: DefaultInterval,
		report:   report,
		baseline: make(map[string]string),
		reported: make(map[string]bool),
	}
}

// SetInterval overrides the check interval. Values <= 0 are ignored so a bad
// config cannot turn the monitor into a busy loop.
func (m *Monitor) SetInterval(d time.Duration) {
	if d > 0 {
		m.interval = d
	}
}

// WatchBinary registers the running agent executable for integrity checking.
func (m *Monitor) WatchBinary(path string) {
	if path == "" {
		return
	}
	m.files = append(m.files, watched{path: path, component: ComponentBinary, tamperType: TypeBinaryModified})
}

// WatchConfig registers the agent config file for integrity checking.
//
// The config is worth watching separately from the binary: rewriting it to point
// the agent at a different server, or to disable collectors, defeats the agent
// without touching a byte of its code.
func (m *Monitor) WatchConfig(path string) {
	if path == "" {
		return
	}
	m.files = append(m.files, watched{path: path, component: ComponentConfig, tamperType: TypeConfigModified})
}

// WatchWatchdog registers the supervising watchdog PID for liveness checks.
// A pid <= 0 (the agent was started directly, e.g. in a container or during
// development) disables the check rather than reporting a missing watchdog that
// was never there.
func (m *Monitor) WatchWatchdog(pid int) {
	if pid > 0 {
		m.watchdogPID = pid
	}
}

// WatchdogPIDFromEnv reads the watchdog PID the supervisor passed down, returning
// 0 when the agent was not started by one.
func WatchdogPIDFromEnv() int {
	return parsePID(os.Getenv(WatchdogPIDEnv))
}

// Run takes the baseline and then checks on every interval until ctx is done.
// It blocks; callers run it in a goroutine.
func (m *Monitor) Run(ctx context.Context) {
	m.takeBaseline()

	if len(m.files) == 0 && m.watchdogPID == 0 {
		slog.Debug("[tamper] 監視対象が無いため自己保護モニタを起動しません")
		return
	}
	slog.Info("[tamper] 自己保護モニタを起動しました",
		"files", len(m.files),
		"watchdog_pid", m.watchdogPID,
		"interval", m.interval,
	)

	t := time.NewTicker(m.interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.checkOnce()
		}
	}
}

// takeBaseline fingerprints every watched file. A file that cannot be read is
// left out of the baseline and skipped on later passes — reporting it as
// "modified" would be wrong, and reporting it as missing is a separate finding
// this pass does not attempt.
func (m *Monitor) takeBaseline() {
	for _, w := range m.files {
		sum, err := hashFile(w.path)
		if err != nil {
			slog.Warn("[tamper] 監視対象のハッシュ取得に失敗しました。この対象は監視できません",
				"path", w.path, "error", err)
			continue
		}
		m.baseline[w.path] = sum
	}
}

// checkOnce runs one pass. Exported behaviour is through report.
func (m *Monitor) checkOnce() {
	for _, w := range m.files {
		want, ok := m.baseline[w.path]
		if !ok {
			continue // never fingerprinted — see takeBaseline
		}
		got, err := hashFile(w.path)
		if err != nil {
			// The file vanished or became unreadable while the agent runs. That is
			// itself worth reporting: deleting the binary out from under a running
			// agent is a real uninstall-by-force pattern.
			m.emitOnce(w.tamperType+":"+w.path, New(w.tamperType, w.component, false).
				WithPath(w.path).
				WithExpectedOnly(want).
				WithReason("監視対象のファイルを読み取れなくなりました（削除または権限変更の可能性）"))
			continue
		}
		if got == want {
			continue
		}
		m.emitOnce(w.tamperType+":"+w.path, New(w.tamperType, w.component, false).
			WithPath(w.path).
			WithHashes(want, got).
			WithReason("実行中に監視対象のファイルが変更されました"))
	}

	if m.watchdogPID > 0 && !processAlive(m.watchdogPID) {
		// Killing the supervisor first is the standard way to make killing the agent
		// stick, so this is reported even though the agent itself is still healthy.
		m.emitOnce(TypeWatchdogMissing, New(TypeWatchdogMissing, ComponentWatchdog, false).
			WithTarget(m.watchdogPID).
			WithReason("エージェントを監視しているウォッチドッグのプロセスが消滅しました"))
	}
}

// emitOnce reports a finding the first time its key is seen and stays quiet
// afterwards.
func (m *Monitor) emitOnce(key string, p Payload) {
	if m.reported[key] {
		return
	}
	m.reported[key] = true
	if m.report != nil {
		m.report(p)
	}
}

// WithExpectedOnly records the baseline digest when the current one cannot be
// computed (the file is gone or unreadable).
func (p Payload) WithExpectedOnly(expected string) Payload {
	p.ExpectedHash = expected
	return p
}

func hashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func parsePID(s string) int {
	if s == "" {
		return 0
	}
	pid := 0
	for _, r := range s {
		if r < '0' || r > '9' {
			return 0
		}
		pid = pid*10 + int(r-'0')
		if pid > 1<<31 {
			return 0
		}
	}
	return pid
}
