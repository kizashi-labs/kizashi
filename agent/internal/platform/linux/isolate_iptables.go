//go:build linux

package linux

import (
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"

	"github.com/edr-platform/agent/internal/collector"
)

// IPTablesIsolationManager implements collector.IsolationManager using iptables/nftables.
// Isolation rules are inserted at the TOP of INPUT/OUTPUT chains with high priority,
// overriding existing permissive rules. The EDR server IP is always whitelisted.
//
// SSH access during isolation is controlled by the EDR_ISOLATION_ALLOW_SSH environment
// variable. Set it to "true" in test/staging environments to retain SSH access. In
// production (default) SSH is blocked so the isolated host cannot be accessed remotely.
type IPTablesIsolationManager struct {
	mu          sync.RWMutex
	isolated    bool
	edrServerIP string
	useNFTables bool
	allowSSH    bool

	// run and runOut execute a firewall command. They exist so the startup
	// reconciliation below can be tested without a real firewall — the property
	// worth pinning is the exact argv, which cannot be checked by shelling out.
	run    func(name string, args ...string) error
	runOut func(name string, args ...string) ([]byte, error)
}

func NewIPTablesIsolationManager(edrServerIP string) *IPTablesIsolationManager {
	// Extract bare IP/hostname from a full URL (e.g. "http://1.2.3.4:9091" → "1.2.3.4").
	if u, err := url.Parse(edrServerIP); err == nil && u.Hostname() != "" {
		edrServerIP = u.Hostname()
	}
	m := &IPTablesIsolationManager{
		edrServerIP: edrServerIP,
		useNFTables: isNFTablesAvailable(),
		allowSSH:    os.Getenv("EDR_ISOLATION_ALLOW_SSH") == "true",
		run:         runCommand,
		runOut: func(name string, args ...string) ([]byte, error) {
			return exec.Command(name, args...).CombinedOutput()
		},
	}
	// Sync in-memory state with actual firewall state on startup.
	// Without this, a restarted agent incorrectly reports status=online
	// while isolation rules are still active.
	m.isolated = m.detectIsolationState()
	if m.isolated {
		slog.Warn("起動時に隔離ルールが検出されました。解除はサーバーからの指示を待ちます")
		m.reconcileSSHAccess()
	}
	return m
}

// reconcileSSHAccess brings an already-applied isolation chain in line with the
// current EDR_ISOLATION_ALLOW_SSH setting.
//
// allowSSH is read once, at construction, and is otherwise consulted only while
// BUILDING the chain. So a chain applied before the setting was turned on keeps
// dropping tcp/22 for as long as the isolation lasts, and restarting the agent
// does not change that — the startup path used to merely log that the server
// would handle it, which is exactly backwards: an operator turns this setting on
// *because* they can no longer reach the host, restarts the agent, and nothing
// happens. Worse, on a host that runs the EDR server itself in a container the
// server's unisolate command may never arrive, because the whitelisted server
// address does not match the post-DNAT container IP the OUTPUT filter sees.
//
// Releasing on startup is not an acceptable alternative: a compromised host
// could then restore its own connectivity just by killing the agent. So the
// chain is repaired in place instead — the accept rule is inserted at the top,
// ahead of the chain's trailing DROP, and nothing else about the isolation is
// weakened.
func (m *IPTablesIsolationManager) reconcileSSHAccess() {
	if !m.allowSSH {
		return
	}
	if m.useNFTables {
		out, err := m.runOut("nft", "list", "chain", "inet", "edr_isolate", "input")
		if err == nil && strings.Contains(string(out), "tcp dport 22 accept") {
			return
		}
		if err := m.run("nft", "insert", "rule", "inet", "edr_isolate", "input",
			"tcp", "dport", "22", "accept"); err != nil {
			slog.Error("既存の隔離ルールへのSSH許可追加に失敗しました", "error", err)
			return
		}
	} else {
		sshRule := []string{"EDR_ISOLATE", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"}
		if err := m.run("iptables", append([]string{"-C"}, sshRule...)...); err == nil {
			return // already allowed
		}
		// -I ... 1 puts the accept ahead of the trailing DROP; -A would land after it.
		if err := m.run("iptables", append([]string{"-I", "EDR_ISOLATE", "1"}, sshRule[1:]...)...); err != nil {
			slog.Error("既存の隔離ルールへのSSH許可追加に失敗しました", "error", err)
			return
		}
	}
	slog.Warn("EDR_ISOLATION_ALLOW_SSH=true のため、適用済みの隔離チェーンにSSH許可を追加しました")
}

// detectIsolationState checks whether isolation rules are currently active on the host.
func (m *IPTablesIsolationManager) detectIsolationState() bool {
	if m.useNFTables {
		return exec.Command("nft", "list", "table", "inet", "edr_isolate").Run() == nil
	}
	return exec.Command("iptables", "-L", "EDR_ISOLATE", "-n").Run() == nil
}

// Isolate blocks all traffic except EDR server + DNS + loopback.
func (m *IPTablesIsolationManager) Isolate(allowedIPs []string, allowedPorts []uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isolated {
		return nil
	}

	if m.useNFTables {
		return m.isolateNFTables(allowedIPs)
	}
	return m.isolateIPTables(allowedIPs)
}

func (m *IPTablesIsolationManager) isolateIPTables(allowedIPs []string) error {
	// Create EDR isolation chain
	rules := [][]string{
		// Create a dedicated chain for EDR isolation
		{"iptables", "-N", "EDR_ISOLATE"},
		{"ip6tables", "-N", "EDR_ISOLATE"},

		// Allow loopback
		{"iptables", "-A", "EDR_ISOLATE", "-i", "lo", "-j", "ACCEPT"},
		{"iptables", "-A", "EDR_ISOLATE", "-o", "lo", "-j", "ACCEPT"},

		// Allow established connections (so existing connections don't break mid-session)
		{"iptables", "-A", "EDR_ISOLATE", "-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "ACCEPT"},

		// Allow DNS (so EDR can resolve server hostname)
		{"iptables", "-A", "EDR_ISOLATE", "-p", "udp", "--dport", "53", "-j", "ACCEPT"},
		{"iptables", "-A", "EDR_ISOLATE", "-p", "tcp", "--dport", "53", "-j", "ACCEPT"},
	}

	// Allow SSH only in test/staging (EDR_ISOLATION_ALLOW_SSH=true)
	if m.allowSSH {
		rules = append(rules,
			[]string{"iptables", "-A", "EDR_ISOLATE", "-p", "tcp", "--dport", "22", "-j", "ACCEPT"},
		)
	}

	// Allow EDR server IP
	for _, ip := range append(allowedIPs, m.edrServerIP) {
		if ip == "" {
			continue
		}
		// Strip URL scheme/port if a full URL was accidentally passed.
		if u, err := url.Parse(ip); err == nil && u.Hostname() != "" {
			ip = u.Hostname()
		}
		rules = append(rules,
			[]string{"iptables", "-A", "EDR_ISOLATE", "-d", ip, "-j", "ACCEPT"},
			[]string{"iptables", "-A", "EDR_ISOLATE", "-s", ip, "-j", "ACCEPT"},
		)
	}

	// Drop everything else
	rules = append(rules,
		[]string{"iptables", "-A", "EDR_ISOLATE", "-j", "DROP"},
		// Jump to EDR_ISOLATE chain from INPUT and OUTPUT
		[]string{"iptables", "-I", "INPUT", "1", "-j", "EDR_ISOLATE"},
		[]string{"iptables", "-I", "OUTPUT", "1", "-j", "EDR_ISOLATE"},
		[]string{"iptables", "-I", "FORWARD", "1", "-j", "EDR_ISOLATE"},
	)

	for _, rule := range rules {
		if err := runCommand(rule[0], rule[1:]...); err != nil {
			// Attempt rollback
			_ = m.unisolateIPTables()
			return fmt.Errorf("iptables rule %v: %w", rule, err)
		}
	}

	m.isolated = true
	return nil
}

func (m *IPTablesIsolationManager) isolateNFTables(allowedIPs []string) error {
	// Build nftables ruleset
	allowed := strings.Builder{}
	for _, ip := range append(allowedIPs, m.edrServerIP) {
		if ip == "" {
			continue
		}
		// Strip URL scheme/port if a full URL was accidentally passed.
		if u, err := url.Parse(ip); err == nil && u.Hostname() != "" {
			ip = u.Hostname()
		}
		fmt.Fprintf(&allowed, "        ip daddr %s accept\n", ip)
		fmt.Fprintf(&allowed, "        ip saddr %s accept\n", ip)
	}

	sshRule := ""
	if m.allowSSH {
		sshRule = "        tcp dport 22 accept\n"
	}

	ruleset := fmt.Sprintf(`
table inet edr_isolate {
    chain input {
        type filter hook input priority -150; policy drop;
        iif lo accept
        ct state established,related accept
%s        udp dport 53 accept
        tcp dport 53 accept
%s
    }
    chain output {
        type filter hook output priority -150; policy drop;
        oif lo accept
        ct state established,related accept
        udp dport 53 accept
%s
    }
    chain forward {
        type filter hook forward priority -150; policy drop;
    }
}`, sshRule, allowed.String(), allowed.String())

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(ruleset)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft apply: %w, output: %s", err, string(out))
	}

	m.isolated = true
	return nil
}

// Unisolate removes all isolation rules.
// Always attempts cleanup regardless of the in-memory flag, because the agent
// may have restarted after a previous isolation and the flag would be wrong.
func (m *IPTablesIsolationManager) Unisolate() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.useNFTables {
		return m.unisolateNFTables()
	}
	return m.unisolateIPTables()
}

func (m *IPTablesIsolationManager) unisolateIPTables() error {
	// Errors are logged but not fatal — chain/rules may not exist if agent restarted.
	rules := [][]string{
		{"iptables", "-D", "INPUT", "-j", "EDR_ISOLATE"},
		{"iptables", "-D", "OUTPUT", "-j", "EDR_ISOLATE"},
		{"iptables", "-D", "FORWARD", "-j", "EDR_ISOLATE"},
		{"iptables", "-F", "EDR_ISOLATE"},
		{"iptables", "-X", "EDR_ISOLATE"},
	}
	for _, rule := range rules {
		if err := runCommand(rule[0], rule[1:]...); err != nil {
			slog.Debug("iptables解除スキップ（既にクリーンな可能性）", "rule", rule, "error", err)
		}
	}
	m.isolated = false
	return nil
}

func (m *IPTablesIsolationManager) unisolateNFTables() error {
	// edr_isolate table may not exist if agent restarted after isolation was applied.
	// Ignore "not found" errors to make Unisolate idempotent.
	err := runCommand("nft", "delete", "table", "inet", "edr_isolate")
	if err != nil {
		// runCommand embeds CombinedOutput in the error string; check for nft's
		// "No such file or directory" message which indicates the table is already gone.
		if strings.Contains(err.Error(), "No such file") || strings.Contains(err.Error(), "no such table") {
			m.isolated = false
			return nil
		}
		return fmt.Errorf("nft delete table: %w", err)
	}
	m.isolated = false
	return nil
}

func (m *IPTablesIsolationManager) IsIsolated() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isolated
}

// VerifyIsolation reads the actual firewall state instead of the in-memory flag.
//
// detectIsolationState は起動時にしか使われていなかった。適用直後に確かめれば、
// 「コマンドは成功したがルールが入っていない」を捕まえられる。
func (m *IPTablesIsolationManager) VerifyIsolation() (bool, error) {
	return m.detectIsolationState(), nil
}

func isNFTablesAvailable() bool {
	return exec.Command("nft", "--version").Run() == nil
}

// runCommand is a variable so tests can observe the order in which the
// quarantine path shells out. The ordering is the thing that broke — the hash
// was taken after the file had been made unreadable — and it cannot be checked
// by running the real commands as root, because root reads a mode-000 file
// happily.
var runCommand = func(name string, args ...string) error {
	out, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %v: %w (output: %s)", name, args, err, string(out))
	}
	return nil
}

// ─── Linux Process Manager ────────────────────────────────────

type LinuxProcessManager struct{}

func NewLinuxProcessManager() *LinuxProcessManager {
	return &LinuxProcessManager{}
}

func (m *LinuxProcessManager) Kill(pid uint32) error {
	return runCommand("kill", "-9", fmt.Sprintf("%d", pid))
}

// ─── Linux File Quarantine ────────────────────────────────────

type LinuxFileQuarantine struct {
	quarantineDir string
	mu            sync.Mutex
	index         map[string]*collector.QuarantinedFile
}

func NewLinuxFileQuarantine(dir string) *LinuxFileQuarantine {
	q := &LinuxFileQuarantine{
		quarantineDir: dir,
		index:         make(map[string]*collector.QuarantinedFile),
	}
	q.loadIndex()
	return q
}

func (q *LinuxFileQuarantine) indexPath() string {
	return filepath.Join(q.quarantineDir, "index.json")
}

func (q *LinuxFileQuarantine) saveIndex() {
	data, err := json.Marshal(q.index)
	if err != nil {
		return
	}
	_ = os.WriteFile(q.indexPath(), data, 0600)
}

func (q *LinuxFileQuarantine) loadIndex() {
	data, err := os.ReadFile(q.indexPath())
	if err != nil {
		return // file doesn't exist yet — normal on first run
	}
	_ = json.Unmarshal(data, &q.index)
}

func (q *LinuxFileQuarantine) Quarantine(path string) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	id := generateLinuxID()
	destPath := fmt.Sprintf("%s/%s.quarantine", q.quarantineDir, id)

	// Move file
	if err := runCommand("mv", path, destPath); err != nil {
		return "", fmt.Errorf("move to quarantine: %w", err)
	}

	// Hash the sample while it is still readable.
	//
	// This used to run after the chmod below, and computeLinuxHashes answers an
	// unreadable file with an empty FileHashes{} and no error, so the quarantine
	// entry was written with no hash at all and Quarantine still reported
	// success. Root bypasses mode 000, which is why it works wherever the agent
	// runs privileged and nowhere else. Verified directly: the same open()
	// succeeds at euid 0 and returns "permission denied" at euid 65534.
	//
	// The hash is the sample's identity — without it a responder cannot look the
	// file up, correlate it across endpoints, or prove which file was taken.
	hashes := computeLinuxHashes(destPath)
	if hashes.SHA256 == "" {
		slog.Warn("隔離ファイルのハッシュを取得できませんでした。検体の同定ができません",
			"quarantine_id", id, "original_path", path)
	}

	// Strip all permissions (chmod 000) - prevents accidental execution
	if err := runCommand("chmod", "000", destPath); err != nil {
		return "", fmt.Errorf("chmod quarantine file: %w", err)
	}

	// Change ownership to root
	_ = runCommand("chown", "root:root", destPath)

	q.index[id] = &collector.QuarantinedFile{
		ID:           id,
		OriginalPath: path,
		Hashes:       hashes,
	}
	q.saveIndex()

	return id, nil
}

func (q *LinuxFileQuarantine) Restore(quarantineID string, restorePath string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	entry, ok := q.index[quarantineID]
	if !ok {
		return fmt.Errorf("quarantine ID %s not found", quarantineID)
	}

	srcPath := fmt.Sprintf("%s/%s.quarantine", q.quarantineDir, quarantineID)
	dest := restorePath
	if dest == "" {
		dest = entry.OriginalPath
	}

	// Restore permissions before moving
	if err := runCommand("chmod", "644", srcPath); err != nil {
		return fmt.Errorf("restore permissions: %w", err)
	}

	if err := runCommand("mv", srcPath, dest); err != nil {
		return fmt.Errorf("restore file: %w", err)
	}

	delete(q.index, quarantineID)
	q.saveIndex()
	return nil
}

func (q *LinuxFileQuarantine) List() ([]collector.QuarantinedFile, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	result := make([]collector.QuarantinedFile, 0, len(q.index))
	for _, f := range q.index {
		result = append(result, *f)
	}
	return result, nil
}

func generateLinuxID() string {
	out, err := exec.Command("cat", "/proc/sys/kernel/random/uuid").Output()
	if err != nil {
		return fmt.Sprintf("%d", 0)
	}
	return strings.TrimSpace(string(out))
}
