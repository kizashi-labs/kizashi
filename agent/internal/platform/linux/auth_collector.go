//go:build linux

package linux

import (
	"bufio"
	"context"
	"io"
	"log/slog"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
)

// LinuxAuthCollector tails the system authentication log and emits AuthEvents for
// SSH logins, sudo/su privilege escalation, and their failures. These feed the
// server's brute-force detector (repeated failures) and authentication Sigma
// rules — a telemetry class Linux hosts otherwise lack entirely. It is read-only
// (follows an existing log), so it needs no special privilege beyond read access
// to the auth log (the agent runs as root).
type LinuxAuthCollector struct {
	cancel context.CancelFunc
}

// NewLinuxAuthCollector returns a collector that follows /var/log/auth.log
// (Debian/Ubuntu) or /var/log/secure (RHEL/Fedora).
func NewLinuxAuthCollector() *LinuxAuthCollector { return &LinuxAuthCollector{} }

// Start begins following the auth log in a background goroutine. It returns nil
// immediately; if no auth log exists the collector is a no-op.
func (c *LinuxAuthCollector) Start(ctx context.Context, out chan<- collector.AuthEvent) error {
	ctx, c.cancel = context.WithCancel(ctx)
	path := authLogPath()
	if path == "" {
		slog.Info("認証ログ(/var/log/auth.log|secure)が見つかりません。認証コレクタは無効です")
		return nil
	}
	slog.Info("認証イベントを追尾します", "path", path)
	go c.tail(ctx, path, out)
	return nil
}

// Stop cancels the tailing goroutine.
func (c *LinuxAuthCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func authLogPath() string {
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure"} {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p
		}
	}
	return ""
}

// tail follows path, emitting parsed AuthEvents. It seeks to EOF on open (only new
// lines are reported), polls once per second, and reopens on truncation/rotation.
func (c *LinuxAuthCollector) tail(ctx context.Context, path string, out chan<- collector.AuthEvent) {
	var f *os.File
	var r *bufio.Reader
	var offset int64

	open := func() bool {
		nf, err := os.Open(path)
		if err != nil {
			return false
		}
		if st, err := nf.Stat(); err == nil {
			_, _ = nf.Seek(0, io.SeekEnd)
			offset = st.Size()
		}
		f = nf
		r = bufio.NewReader(nf)
		return true
	}
	defer func() {
		if f != nil {
			_ = f.Close()
		}
	}()
	open()

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}

		if f == nil {
			open()
			continue
		}
		// Detect rotation/truncation: if the file shrank, reopen from the top.
		if st, err := os.Stat(path); err == nil {
			if st.Size() < offset {
				_ = f.Close()
				f = nil
				open()
				continue
			}
			offset = st.Size()
		}

		for {
			line, err := r.ReadString('\n')
			if len(line) > 0 {
				if evt, ok := parseAuthLine(strings.TrimRight(line, "\r\n")); ok {
					select {
					case out <- evt:
					case <-ctx.Done():
						return
					}
				}
			}
			if err != nil {
				break // EOF (or partial line): wait for the next tick
			}
		}
	}
}

var (
	reSSHAccepted = regexp.MustCompile(`sshd\[\d+\]:\s+Accepted (\S+) for (\S+) from (\S+)`)
	reSSHFailed   = regexp.MustCompile(`sshd\[\d+\]:\s+Failed password for (?:invalid user )?(\S+) from (\S+)`)
	reSSHInvalid  = regexp.MustCompile(`sshd\[\d+\]:\s+Invalid user (\S+) from (\S+)`)
	reSudoFail    = regexp.MustCompile(`sudo:\s+(\S+) :.*(authentication failure|command not allowed|NOT in the sudoers)`)
	reSudoCmd     = regexp.MustCompile(`sudo:\s+(\S+) :.*COMMAND=`)
	reSuFail      = regexp.MustCompile(`su(?:\[\d+\])?:\s+FAILED su for (\S+)`)
	reSuOpen      = regexp.MustCompile(`su(?:\[\d+\])?:.*session opened for user (\S+)`)
)

// parseAuthLine maps a syslog auth line to an AuthEvent. Action strings match
// authAction() in cmd/agent (login|logout|privilege|failed). Returns ok=false for
// lines that are not security-relevant auth events.
func parseAuthLine(line string) (collector.AuthEvent, bool) {
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
	case reSSHAccepted.MatchString(line):
		m := reSSHAccepted.FindStringSubmatch(line)
		return mk(m[2], "login", true, m[3], m[1], "")
	case reSSHFailed.MatchString(line):
		m := reSSHFailed.FindStringSubmatch(line)
		return mk(m[1], "failed", false, m[2], "password", "failed password")
	case reSSHInvalid.MatchString(line):
		m := reSSHInvalid.FindStringSubmatch(line)
		return mk(m[1], "failed", false, m[2], "password", "invalid user")
	case reSudoFail.MatchString(line):
		m := reSudoFail.FindStringSubmatch(line)
		return mk(m[1], "failed", false, "", "sudo", m[2])
	case reSudoCmd.MatchString(line):
		m := reSudoCmd.FindStringSubmatch(line)
		return mk(m[1], "privilege", true, "", "sudo", "")
	case reSuFail.MatchString(line):
		m := reSuFail.FindStringSubmatch(line)
		return mk(m[1], "failed", false, "", "su", "FAILED su")
	case reSuOpen.MatchString(line):
		m := reSuOpen.FindStringSubmatch(line)
		return mk(m[1], "privilege", true, "", "su", "")
	}
	return collector.AuthEvent{}, false
}
