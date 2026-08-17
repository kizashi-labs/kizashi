package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/edr-platform/agent/internal/config"
	"github.com/edr-platform/agent/internal/heartbeat"
	"github.com/edr-platform/agent/internal/uninstallguard"
)

// Exit codes for -verify-uninstall. The uninstall scripts branch on these, so
// they are part of the interface and must not be renumbered.
const (
	uninstallExitAuthorised = 0 // correct password, or no guard provisioned
	uninstallExitDenied     = 2 // guard installed and the password did not match
	uninstallExitError      = 3 // could not decide (unreadable guard, bad input)
)

// UninstallPasswordEnv carries the password to -verify-uninstall.
//
// An environment variable rather than a command-line flag: arguments are
// visible in the process list to every user on the box for as long as the
// derivation runs, which at 600k PBKDF2 iterations is a comfortable window to
// read them. Reading from stdin is also supported for interactive use.
const UninstallPasswordEnv = "EDR_UNINSTALL_PASSWORD"

// runVerifyUninstall implements `edr-agent -verify-uninstall`, the check the
// uninstall scripts must pass before they remove anything.
//
// Putting the decision in the agent binary rather than the shell script is
// deliberate. The script is a text file an attacker can edit — but editing it
// only bypasses the *packaged* uninstaller, and the point of this check is not
// to be unbypassable by root (see the uninstallguard package doc). It is to
// make the supported removal path require the SOC's secret, to make the digest
// expensive to attack offline, and to make every failed attempt visible. None
// of that is expressible in portable shell: PBKDF2 at 600k iterations is not
// something to reimplement in sh.
//
// It never blocks on a network call. An endpoint being decommissioned may
// legitimately have no route to the server, and an attacker will certainly have
// cut it — so the verdict comes from the on-disk guard, and the report to the
// server is best-effort afterwards.
func runVerifyUninstall(configPath string) int {
	dataDir := filepath.Dir(configPath)

	guard, err := uninstallguard.Load(dataDir)
	switch {
	case errors.Is(err, uninstallguard.ErrNoGuard):
		// Not provisioned: this endpoint predates the policy, or the tenant has
		// not set a password. Allowing the uninstall is the only defensible
		// behaviour — refusing would strand every agent enrolled before the
		// feature existed, with no password in existence that could free them.
		fmt.Fprintln(os.Stderr, "アンインストール保護は未設定です（許可）")
		return uninstallExitAuthorised
	case err != nil:
		// Corrupt guard. Deny: a damaged file must not be a cheaper bypass than
		// the password it replaces.
		fmt.Fprintf(os.Stderr, "アンインストール保護の設定を読めません: %v\n", err)
		fmt.Fprintln(os.Stderr, "保護が壊れている可能性があるため拒否します。管理コンソールから再配布してください。")
		return uninstallExitError
	}

	password, err := readUninstallPassword()
	if err != nil {
		fmt.Fprintf(os.Stderr, "パスワードを読み取れません: %v\n", err)
		return uninstallExitError
	}

	if err := guard.Verify(password); err != nil {
		if errors.Is(err, uninstallguard.ErrWrongPassword) {
			fmt.Fprintln(os.Stderr, "アンインストールパスワードが違います。")
			reportUninstallAttempt(configPath, false)
			return uninstallExitDenied
		}
		fmt.Fprintf(os.Stderr, "パスワードを検証できません: %v\n", err)
		return uninstallExitError
	}

	fmt.Fprintln(os.Stderr, "アンインストールを承認しました。")
	reportUninstallAttempt(configPath, true)
	return uninstallExitAuthorised
}

// readUninstallPassword takes the password from the environment, falling back
// to a single line on stdin so an operator can be prompted without the value
// ever entering their shell history or the process list.
func readUninstallPassword() (string, error) {
	if v, ok := os.LookupEnv(UninstallPasswordEnv); ok {
		return v, nil
	}
	stat, err := os.Stdin.Stat()
	if err != nil {
		return "", err
	}
	if stat.Mode()&os.ModeCharDevice != 0 {
		fmt.Fprint(os.Stderr, "アンインストールパスワード: ")
	}
	line, err := bufio.NewReader(os.Stdin).ReadString('\n')
	if err != nil && line == "" {
		return "", fmt.Errorf("標準入力からパスワードを読めません: %w", err)
	}
	return strings.TrimRight(line, "\r\n"), nil
}

// makeUninstallGuardApplier returns the heartbeat callback that persists guard
// material handed down by the server.
//
// It rewrites the file only when the material actually changed. Heartbeats run
// every 30 seconds on every endpoint in the fleet, and an unconditional write
// would mean a disk write per agent per interval — plus, on the agent's own
// data directory, a stream of file-modification events from its own file
// collector. (That exact self-feeding loop has bitten this agent before: a
// collector watching a directory the agent writes to generated 96% of one
// endpoint's file telemetry.)
func makeUninstallGuardApplier(configPath string) func(*heartbeat.UninstallGuardMaterial) error {
	dataDir := filepath.Dir(configPath)
	return func(m *heartbeat.UninstallGuardMaterial) error {
		if m == nil || m.SaltB64 == "" || m.DigestB64 == "" {
			return nil
		}
		next := &uninstallguard.Guard{
			Version:    m.Version,
			Algorithm:  m.Algorithm,
			Iterations: m.Iterations,
			SaltB64:    m.SaltB64,
			DigestB64:  m.DigestB64,
			UpdatedAt:  m.UpdatedAt,
		}

		if cur, err := uninstallguard.Load(dataDir); err == nil &&
			cur.SaltB64 == next.SaltB64 && cur.DigestB64 == next.DigestB64 {
			return nil // already current
		}

		if err := uninstallguard.Save(dataDir, next); err != nil {
			return err
		}
		slog.Info("アンインストール保護の設定を更新しました", "updated_at", next.UpdatedAt)
		return nil
	}
}

// uninstallAttemptReport is the body sent to the server.
type uninstallAttemptReport struct {
	AgentID    string    `json:"agent_id"`
	Authorised bool      `json:"authorised"`
	Hostname   string    `json:"hostname"`
	OccurredAt time.Time `json:"occurred_at"`
}

// reportUninstallAttempt tells the server that someone tried to remove this
// agent, and whether they had the password.
//
// Best-effort by design, with a short timeout. This runs while the uninstaller
// is waiting, and the report must never be able to hold up — or fail — a
// legitimate decommission. A failed refusal that nobody hears is still a
// refusal, which is the property that matters; the report is what turns it into
// an investigable event.
//
// A denied attempt is the more interesting of the two: it means someone tried
// to remove the sensor and did not have the SOC's secret.
func reportUninstallAttempt(configPath string, authorised bool) {
	mgr := config.NewManager(configPath)
	if err := mgr.Load(); err != nil {
		return // no readable config: nothing to report to
	}
	cfg := mgr.Get()
	if cfg == nil || cfg.Server.URL == "" || cfg.Agent.ID == "" {
		return
	}

	host, _ := os.Hostname()
	body, err := json.Marshal(uninstallAttemptReport{
		AgentID:    cfg.Agent.ID,
		Authorised: authorised,
		Hostname:   host,
		OccurredAt: time.Now().UTC(),
	})
	if err != nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	url := strings.TrimRight(cfg.Server.URL, "/") +
		"/api/v1/agents/" + cfg.Agent.ID + "/uninstall-attempt"
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	if err != nil {
		fmt.Fprintln(os.Stderr, "サーバへの通報に失敗しました（拒否の判断自体には影響しません）")
		return
	}
	defer resp.Body.Close()
}
