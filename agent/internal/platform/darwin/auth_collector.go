//go:build darwin

package darwin

import (
	"bufio"
	"context"
	"log/slog"
	"os/exec"
	"regexp"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
)

// DarwinAuthCollector monitors authentication events on macOS by subscribing to
// the unified logging system (`log stream`) for sshd / sudo / su activity. It
// emits AuthEvents for SSH logins, sudo/su privilege escalation, and their
// failures — the same telemetry class the Linux collector derives from
// /var/log/auth.log — feeding the server's brute-force detector and the
// authentication Sigma rules. macOS otherwise produced no auth telemetry at all
// (newPlatformAuthCollector returned nil).
//
// `log stream` follows only NEW log entries (like tail -f) and needs no special
// entitlement, matching the CGo-free, no-privilege posture of the other Darwin
// collectors (dns via tcpdump, process via ps).
type DarwinAuthCollector struct {
	cancel context.CancelFunc
}

// NewDarwinAuthCollector returns a macOS authentication-event collector.
func NewDarwinAuthCollector() *DarwinAuthCollector { return &DarwinAuthCollector{} }

// Start begins streaming auth events in a background goroutine. It returns nil
// immediately; if the `log` tool is unavailable the collector is a no-op.
func (c *DarwinAuthCollector) Start(ctx context.Context, out chan<- collector.AuthEvent) error {
	if _, err := exec.LookPath("log"); err != nil {
		sensorUnavailable(sensorAuth, "log コマンドが見つかりません", err)
		return nil
	}
	ctx, c.cancel = context.WithCancel(ctx)
	slog.Info("認証イベントを追尾します (log stream: sshd/sudo/su)")
	go c.stream(ctx, out)
	return nil
}

// Stop cancels the streaming goroutine (which terminates the `log` subprocess).
func (c *DarwinAuthCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *DarwinAuthCollector) stream(ctx context.Context, out chan<- collector.AuthEvent) {
	// log stream --style syslog --info --predicate '<auth processes>'
	// Emits only new entries; --info includes the informational level that
	// carries sudo COMMAND and sshd Accepted messages.
	cmd := exec.CommandContext(ctx, "log", "stream",
		"--style", "syslog",
		"--info",
		"--predicate", `process == "sshd" OR process == "sudo" OR process == "su" OR process == "login"`,
	)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		sensorUnavailable(sensorAuth, "log stream の stdout を取れません", err)
		return
	}
	if err := cmd.Start(); err != nil {
		sensorUnavailable(sensorAuth, "log stream を起動できません", err)
		return
	}
	defer func() { _ = cmd.Wait() }()

	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return
		default:
		}
		if evt, ok := parseDarwinAuthLine(scanner.Text()); ok {
			select {
			case out <- evt:
			case <-ctx.Done():
				return
			}
		}
	}
}

// macOS unified-log lines carry a "process[pid]:" tag. sudo/su include the pid,
// so every pattern allows an optional [pid]. The message bodies follow the
// standard OpenSSH / sudo formats, shared with the Linux syslog collector.
var (
	reDarwinSSHAccepted = regexp.MustCompile(`sshd\[\d+\]:\s+Accepted (\S+) for (\S+) from (\S+)`)
	reDarwinSSHFailed   = regexp.MustCompile(`sshd\[\d+\]:\s+Failed (?:password|publickey) for (?:invalid user )?(\S+) from (\S+)`)
	reDarwinSSHInvalid  = regexp.MustCompile(`sshd\[\d+\]:\s+Invalid user (\S+) from (\S+)`)
	reDarwinSudoFail    = regexp.MustCompile(`sudo\[\d+\]:\s*(\S+) :.*(incorrect password|authentication failure|command not allowed|NOT in the sudoers)`)
	reDarwinSudoCmd     = regexp.MustCompile(`sudo\[\d+\]:\s*(\S+) :.*COMMAND=`)
	reDarwinSuFail      = regexp.MustCompile(`su\[\d+\]:\s+FAILED su for (\S+)`)
	reDarwinSuOpen      = regexp.MustCompile(`su\[\d+\]:.*session opened for user (\S+)`)
)

// parseDarwinAuthLine maps a macOS unified-log line to an AuthEvent. Action
// strings match authAction() in cmd/agent (login|logout|privilege|failed).
// Returns ok=false for lines that are not security-relevant auth events.
func parseDarwinAuthLine(line string) (collector.AuthEvent, bool) {
	mk := func(user, action string, success bool, ip, method, reason string) (collector.AuthEvent, bool) {
		return collector.AuthEvent{
			ID:         uuid.New().String(),
			Timestamp:  time.Now(),
			Username:   user,
			Action:     action,
			Success:    success,
			SourceIP:   ip,
			AuthMethod: method,
			FailReason: reason,
		}, true
	}
	switch {
	case reDarwinSSHAccepted.MatchString(line):
		m := reDarwinSSHAccepted.FindStringSubmatch(line)
		return mk(m[2], "login", true, m[3], m[1], "")
	case reDarwinSSHFailed.MatchString(line):
		m := reDarwinSSHFailed.FindStringSubmatch(line)
		return mk(m[1], "failed", false, m[2], "password", "failed password")
	case reDarwinSSHInvalid.MatchString(line):
		m := reDarwinSSHInvalid.FindStringSubmatch(line)
		return mk(m[1], "failed", false, m[2], "password", "invalid user")
	case reDarwinSudoFail.MatchString(line):
		m := reDarwinSudoFail.FindStringSubmatch(line)
		return mk(m[1], "failed", false, "", "sudo", m[2])
	case reDarwinSudoCmd.MatchString(line):
		m := reDarwinSudoCmd.FindStringSubmatch(line)
		return mk(m[1], "privilege", true, "", "sudo", "")
	case reDarwinSuFail.MatchString(line):
		m := reDarwinSuFail.FindStringSubmatch(line)
		return mk(m[1], "failed", false, "", "su", "FAILED su")
	case reDarwinSuOpen.MatchString(line):
		m := reDarwinSuOpen.FindStringSubmatch(line)
		return mk(m[1], "privilege", true, "", "su", "")
	}
	return collector.AuthEvent{}, false
}
