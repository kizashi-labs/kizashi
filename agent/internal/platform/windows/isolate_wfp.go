//go:build windows

// Package windows implements network isolation using Windows Filtering Platform (WFP).
// When isolated, ALL outbound and inbound traffic is blocked except:
//   - Communication to the EDR server (configurable IPs/ports)
//   - Loopback traffic (127.0.0.0/8, ::1)
package windows

import (
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/edr-platform/agent/internal/collector"
)

// WFPIsolationManager implements collector.IsolationManager using
// Windows Filtering Platform via netsh advfirewall commands.
//
// Isolation strategy: scoped block rules with remoteip.
// Windows Firewall evaluates: explicit-block > explicit-allow > default-policy.
// By adding block rules scoped to all IP ranges EXCEPT the EDR server and loopback,
// those block rules override any existing allow rules (e.g. RDP) for non-EDR traffic,
// while EDR server traffic matches no block rule and is therefore allowed.
type WFPIsolationManager struct {
	mu         sync.RWMutex
	isolated   bool
	ruleNames  []string
	allowedIPs []string
	// listRules enumerates the isolation rules present on the system. Overridden in
	// tests so reconcile can be exercised without shelling out to netsh.
	listRules func() []string
}

const (
	isolateRulePrefix = "EDR-ISOLATE-"
)

// isolationRuleNameRe matches the deterministic names Isolate() assigns to its rules.
// It is matched against our own ASCII rule names rather than netsh's "Rule Name:"
// label, which is localised and therefore unparseable on a non-English host.
var isolationRuleNameRe = regexp.MustCompile(`EDR-ISOLATE-BLOCK-RANGE-\d+-(?:IN|OUT)`)

func NewWFPIsolationManager() *WFPIsolationManager {
	m := &WFPIsolationManager{listRules: existingIsolationRules}
	// Enumerating firewall rules is slow — measured 14.1s on a host with 626 rules
	// (`netsh show rule name=all`; per-rule lookups and the PowerShell equivalent
	// measured worse), so adopt in the background rather than blocking agent
	// startup. Until it finishes the manager reports not-isolated, which is exactly
	// the pre-existing behaviour, and the heartbeat picks up the corrected state on
	// its next tick.
	go m.reconcile()
	return m
}

// parseIsolationRuleNames extracts isolation rule names from `netsh advfirewall
// firewall show rule` output, deduplicated and sorted for determinism.
func parseIsolationRuleNames(out []byte) []string {
	matches := isolationRuleNameRe.FindAllString(string(out), -1)
	if len(matches) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(matches))
	names := make([]string, 0, len(matches))
	for _, name := range matches {
		if _, dup := seen[name]; dup {
			continue
		}
		seen[name] = struct{}{}
		names = append(names, name)
	}
	sort.Strings(names)
	return names
}

// existingIsolationRules returns the isolation rules currently present in the
// Windows Firewall. netsh exits non-zero when nothing matches, so the output is
// parsed regardless of exit status.
func existingIsolationRules() []string {
	out, _ := exec.Command("netsh", "advfirewall", "firewall", "show", "rule", "name=all").CombinedOutput()
	return parseIsolationRuleNames(out)
}

// reconcile adopts isolation rules that already exist on the system, so that
// IsIsolated() reports the truth after an agent restart.
//
// Isolate() writes PERSISTENT netsh rules but kept isolated/ruleNames in memory
// only. After a restart the manager believed it was not isolating: Unisolate()
// short-circuited on !m.isolated, rollback() iterated an empty ruleNames, and the
// block rules survived indefinitely — cutting the host off from everything except
// the EDR server, with no remote way back in. Observed 2026-08-01 on the Windows
// validation host, where RDP and SSM Session Manager were both dead for hours while
// the agent stayed online, and the six orphaned rules had to be deleted by hand over
// Live Response.
//
// Adopting them also re-arms the existing recovery path: the heartbeat then reports
// status=isolated, the server sees the DB says otherwise and replies
// ShouldUnisolate, and the agent clears the rules on its own.
//
// Runs on its own goroutine (see NewWFPIsolationManager), so the enumeration happens
// outside the lock and an Isolate() that lands first wins.
func (m *WFPIsolationManager) reconcile() {
	if m.listRules == nil {
		return
	}
	names := m.listRules()
	if len(names) == 0 {
		return
	}

	m.mu.Lock()
	defer m.mu.Unlock()
	if m.isolated {
		// A real Isolate() landed while we were enumerating; its ruleNames are
		// authoritative and ours may already be stale.
		return
	}
	m.isolated = true
	m.ruleNames = names
	slog.Warn("既存の隔離ファイアウォールルールを検出したため隔離状態を復元しました",
		"rules", len(names))
}

// ipToUint32 converts an IPv4 address to a 32-bit integer.
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32([]byte(ip))
}

// uint32ToIPStr converts a 32-bit integer to an IPv4 address string.
func uint32ToIPStr(n uint32) string {
	b := make(net.IP, 4)
	binary.BigEndian.PutUint32(b, n)
	return b.String()
}

type ipv4Range struct{ start, end uint32 }

// computeBlockRanges calculates IPv4 ranges to BLOCK, covering all addresses
// except loopback (127.0.0.0/8) and the specified allowed IPs.
// Returns ranges in "a.b.c.d-e.f.g.h" or "a.b.c.d" format for netsh remoteip.
func computeBlockRanges(allowedIPs []string) []string {
	// Always exclude loopback
	excluded := []ipv4Range{
		{ipToUint32(net.ParseIP("127.0.0.0")), ipToUint32(net.ParseIP("127.255.255.255"))},
	}

	for _, ipStr := range allowedIPs {
		ip := net.ParseIP(ipStr)
		if ip == nil {
			continue
		}
		v4 := ip.To4()
		if v4 == nil {
			continue
		}
		n := ipToUint32(v4)
		excluded = append(excluded, ipv4Range{n, n})
	}

	// Sort by start address
	sort.Slice(excluded, func(i, j int) bool {
		return excluded[i].start < excluded[j].start
	})

	// Merge overlapping or adjacent ranges
	merged := []ipv4Range{excluded[0]}
	for i := 1; i < len(excluded); i++ {
		last := &merged[len(merged)-1]
		if excluded[i].start <= last.end+1 {
			if excluded[i].end > last.end {
				last.end = excluded[i].end
			}
		} else {
			merged = append(merged, excluded[i])
		}
	}

	// Compute block ranges as the complement of the merged excluded ranges
	var blockRanges []string
	current := uint32(0)
	for _, r := range merged {
		if current < r.start {
			blockRanges = append(blockRanges,
				uint32ToIPStr(current)+"-"+uint32ToIPStr(r.start-1))
		}
		if r.end >= 0xFFFFFFFF {
			return blockRanges
		}
		current = r.end + 1
	}
	if current != 0 {
		blockRanges = append(blockRanges, uint32ToIPStr(current)+"-255.255.255.255")
	}
	return blockRanges
}

// Isolate applies Windows Firewall rules to block all IPv4 traffic
// except loopback (127.x.x.x) and the specified allowed IPs.
//
// Uses scoped block rules (remoteip-restricted) rather than a generic block-all,
// so that explicit-ALLOW rules for the EDR server are not overridden.
// Traffic from/to non-EDR IPs matches our block rules and is denied even if
// built-in allow rules (e.g. RemoteDesktop-UserMode-In-TCP) would otherwise permit it.
func (m *WFPIsolationManager) Isolate(allowedIPs []string, allowedPorts []uint16) error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if m.isolated {
		return nil
	}

	// Set default policy to allow BEFORE enabling the firewall.
	// This prevents a brief blockoutbound window on the Public profile
	// that would kill the existing gRPC connection to the EDR server.
	exec.Command("netsh", "advfirewall", "set", "allprofiles",
		"firewallpolicy", "allowinbound,allowoutbound").Run()
	exec.Command("netsh", "advfirewall", "set", "allprofiles", "state", "on").Run()

	// Compute block ranges: all IPv4 except EDR server IPs and loopback.
	blockRanges := computeBlockRanges(allowedIPs)

	for i, rangeStr := range blockRanges {
		inName := fmt.Sprintf("%sBLOCK-RANGE-%d-IN", isolateRulePrefix, i)
		outName := fmt.Sprintf("%sBLOCK-RANGE-%d-OUT", isolateRulePrefix, i)

		for _, nd := range []struct{ name, dir string }{{inName, "in"}, {outName, "out"}} {
			args := []string{
				"advfirewall", "firewall", "add", "rule",
				"name=" + nd.name,
				"action=block",
				"protocol=any",
				"dir=" + nd.dir,
				"enable=yes",
				"profile=any",
				"remoteip=" + rangeStr,
			}
			out, err := exec.Command("netsh", args...).CombinedOutput()
			if err != nil {
				m.rollback()
				return fmt.Errorf("add block rule %s: %w: %s", nd.name, err, out)
			}
			m.ruleNames = append(m.ruleNames, nd.name)
		}
	}

	m.isolated = true
	m.allowedIPs = allowedIPs
	return nil
}

// Unisolate removes all isolation firewall rules.
func (m *WFPIsolationManager) Unisolate() error {
	m.mu.Lock()
	defer m.mu.Unlock()

	if !m.isolated {
		return nil
	}

	return m.rollback()
}

func (m *WFPIsolationManager) IsIsolated() bool {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.isolated
}

// rollback removes all isolation rules and ensures default policy allows traffic.
func (m *WFPIsolationManager) rollback() error {
	var errs []string

	for _, name := range m.ruleNames {
		cmd := exec.Command("netsh", "advfirewall", "firewall", "delete", "rule", "name="+name)
		if err := cmd.Run(); err != nil {
			errs = append(errs, fmt.Sprintf("remove rule %s: %v", name, err))
		}
	}

	// Restore default policy to allow all
	cmd := exec.Command("netsh", "advfirewall", "set", "allprofiles",
		"firewallpolicy", "allowinbound,allowoutbound")
	if err := cmd.Run(); err != nil {
		errs = append(errs, fmt.Sprintf("restore policy: %v", err))
	}

	m.isolated = false
	m.ruleNames = nil
	m.allowedIPs = nil

	if len(errs) > 0 {
		return fmt.Errorf("rollback errors: %s", strings.Join(errs, "; "))
	}
	return nil
}

// ─── Windows File Quarantine ──────────────────────────────────

type WindowsFileQuarantine struct {
	quarantineDir string
	mu            sync.Mutex
	index         map[string]*collector.QuarantinedFile
}

func NewWindowsFileQuarantine(quarantineDir string) *WindowsFileQuarantine {
	q := &WindowsFileQuarantine{
		quarantineDir: quarantineDir,
		index:         make(map[string]*collector.QuarantinedFile),
	}
	q.loadIndex()
	return q
}

func (q *WindowsFileQuarantine) indexPath() string {
	return filepath.Join(q.quarantineDir, "index.json")
}

func (q *WindowsFileQuarantine) saveIndex() {
	data, err := json.Marshal(q.index)
	if err != nil {
		return
	}
	_ = os.WriteFile(q.indexPath(), data, 0600)
}

func (q *WindowsFileQuarantine) loadIndex() {
	data, err := os.ReadFile(q.indexPath())
	if err != nil {
		return
	}
	_ = json.Unmarshal(data, &q.index)
}

func (q *WindowsFileQuarantine) Quarantine(path string) (string, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	id := generateID()
	destPath := filepath.Join(q.quarantineDir, id+".quarantine")

	slog.Info("[quarantine] moving file", "src", path, "dst", destPath)

	// Move file to quarantine directory
	if err := moveFile(path, destPath); err != nil {
		return "", fmt.Errorf("move to quarantine: %w", err)
	}

	// Strip execute permission by renaming with non-executable extension
	// and setting restrictive ACL
	if err := setRestrictiveACL(destPath); err != nil {
		// Non-fatal - file is already moved
		_ = err
	}

	hashes := computeHashes(destPath)
	q.index[id] = &collector.QuarantinedFile{
		ID:            id,
		OriginalPath:  path,
		QuarantinedAt: time.Now(),
		Hashes:        hashes,
	}
	q.saveIndex()

	return id, nil
}

func (q *WindowsFileQuarantine) Restore(quarantineID string, restorePath string) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	entry, ok := q.index[quarantineID]
	if !ok {
		return fmt.Errorf("quarantine ID %s not found", quarantineID)
	}

	destPath := restorePath
	if destPath == "" {
		destPath = entry.OriginalPath
	}

	srcPath := q.quarantineDir + "\\" + quarantineID + ".quarantine"
	if err := moveFile(srcPath, destPath); err != nil {
		return fmt.Errorf("restore file: %w", err)
	}

	delete(q.index, quarantineID)
	q.saveIndex()
	return nil
}

func (q *WindowsFileQuarantine) List() ([]collector.QuarantinedFile, error) {
	q.mu.Lock()
	defer q.mu.Unlock()

	result := make([]collector.QuarantinedFile, 0, len(q.index))
	for _, f := range q.index {
		result = append(result, *f)
	}
	return result, nil
}

// ─── Stub helpers (implemented via syscall/x/sys in production) ──

func moveFile(src, dst string) error {
	if err := os.Rename(src, dst); err == nil {
		return nil
	}
	// Cross-device fallback: copy then delete.
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	if _, err = io.Copy(out, in); err != nil {
		os.Remove(dst)
		return err
	}
	out.Close()
	in.Close()
	return os.Remove(src)
}

func setRestrictiveACL(path string) error {
	// Remove all permissions except SYSTEM and Administrators
	return exec.Command("icacls", path, "/inheritance:r",
		"/grant:r", "SYSTEM:(F)",
		"/grant:r", "Administrators:(F)").Run()
}

func generateID() string {
	return fmt.Sprintf("%d", time.Now().UnixNano())
}

// ParseCIDR helper
func parseCIDR(s string) (*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(s)
	return ipnet, err
}
