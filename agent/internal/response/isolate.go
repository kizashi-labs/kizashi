package response

import (
	"context"
	"fmt"
	"log/slog"
	"os/exec"
	"runtime"
	"strings"
)

// NetworkIsolator provides cross-platform network isolation.
type NetworkIsolator struct {
	// exec runs a firewall command. It exists so tests can assert on the exact
	// argv the isolator would run against a host's firewall — the one property
	// worth pinning here is what is *not* run (a bare -F/-X/-P), and that cannot
	// be checked by executing iptables for real.
	exec func(ctx context.Context, name string, args ...string) ([]byte, error)
}

// NewNetworkIsolator creates a new NetworkIsolator.
func NewNetworkIsolator() *NetworkIsolator {
	return &NetworkIsolator{}
}

func (n *NetworkIsolator) run(ctx context.Context, name string, args ...string) ([]byte, error) {
	if n.exec != nil {
		return n.exec(ctx, name, args...)
	}
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

// Isolate blocks all network traffic except to the management server.
// managementIP is the IP that should remain accessible (the EDR server).
func (n *NetworkIsolator) Isolate(ctx context.Context, managementIP string) error {
	switch runtime.GOOS {
	case "linux":
		return n.isolateLinux(ctx, managementIP)
	case "darwin":
		return n.isolateDarwin(ctx, managementIP)
	case "windows":
		return n.isolateWindows(ctx, managementIP)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// Release removes network isolation.
func (n *NetworkIsolator) Release(ctx context.Context, managementIP string) error {
	switch runtime.GOOS {
	case "linux":
		return n.releaseLinux(ctx)
	case "darwin":
		return n.releaseDarwin(ctx)
	case "windows":
		return n.releaseWindows(ctx, managementIP)
	default:
		return fmt.Errorf("unsupported OS: %s", runtime.GOOS)
	}
}

// edrQuarantineChain is the dedicated iptables chain isolation lives in. Every
// rule this package adds goes inside it, and the only thing added outside it is
// one jump per built-in chain — so release removes exactly what isolate added.
const edrQuarantineChain = "EDR_QUARANTINE"

// isolateLinux blocks all traffic except loopback and managementIP.
//
// It does this in a dedicated chain rather than by flushing the filter table.
// The previous implementation opened with `iptables -F` and `-X`, which deletes
// every rule and user chain on the host — on any container host that means
// Docker's DOCKER / DOCKER-USER / DOCKER-FORWARD chains and all published-port
// rules disappear. Release could not put them back (it flushed again and set the
// policies to ACCEPT), so an isolated container host stayed broken until someone
// restarted the Docker daemon by hand, and its FORWARD policy came back as
// ACCEPT — weaker than Docker's own default of DROP. Since a single severity-9
// false positive is enough to trigger isolation, that turned one noisy alert into
// manual recovery of the host, and this platform's own deployment is exactly such
// a host.
//
// The policies are therefore left alone entirely. Traffic is dropped by the last
// rule of the quarantine chain instead, and the jumps are inserted at position 1
// so they take effect ahead of any pre-existing rule (Docker's included).
func (n *NetworkIsolator) isolateLinux(ctx context.Context, managementIP string) error {
	run := func(args ...string) error {
		out, err := n.run(ctx, "iptables", args...)
		if err != nil {
			return fmt.Errorf("iptables %s: %w: %s", strings.Join(args, " "), err, out)
		}
		return nil
	}

	// Start from a clean chain so repeated isolation does not stack duplicate
	// rules. -N fails when the chain exists, which is the normal re-isolate path.
	if err := run("-N", edrQuarantineChain); err != nil {
		if err := run("-F", edrQuarantineChain); err != nil {
			return n.isolateLinuxNFT(ctx, managementIP)
		}
	}

	rules := [][]string{
		{"-A", edrQuarantineChain, "-i", "lo", "-j", "ACCEPT"},
		{"-A", edrQuarantineChain, "-o", "lo", "-j", "ACCEPT"},
		{"-A", edrQuarantineChain, "-s", managementIP, "-j", "ACCEPT"},
		{"-A", edrQuarantineChain, "-d", managementIP, "-j", "ACCEPT"},
		// Everything the rules above did not accept is dropped here, inside the
		// chain — the built-in policies stay untouched.
		{"-A", edrQuarantineChain, "-j", "DROP"},
	}
	for _, r := range rules {
		if err := run(r...); err != nil {
			return n.isolateLinuxNFT(ctx, managementIP)
		}
	}

	// FORWARD is included so an isolated container host cannot keep routing its
	// containers' traffic. -C first: re-isolating must not stack jumps.
	for _, builtin := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		if err := run("-C", builtin, "-j", edrQuarantineChain); err == nil {
			continue // jump already present
		}
		if err := run("-I", builtin, "1", "-j", edrQuarantineChain); err != nil {
			return n.isolateLinuxNFT(ctx, managementIP)
		}
	}
	return nil
}

// isolateLinuxNFT uses nftables as fallback for Linux.
func (n *NetworkIsolator) isolateLinuxNFT(ctx context.Context, managementIP string) error {
	script := fmt.Sprintf(`
table inet edr_quarantine {
  chain input {
    type filter hook input priority 0; policy drop;
    iif "lo" accept
    ip saddr %s accept
    ip6 saddr ::1 accept
  }
  chain output {
    type filter hook output priority 0; policy drop;
    oif "lo" accept
    ip daddr %s accept
    ip6 daddr ::1 accept
  }
}`, managementIP, managementIP)

	cmd := exec.CommandContext(ctx, "nft", "-f", "-")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nftables isolation failed: %w: %s", err, out)
	}
	return nil
}

// releaseLinux removes iptables/nftables isolation rules.
//
// Only what isolateLinux added is removed: the three jumps, then the quarantine
// chain itself. Nothing else on the host is touched — no flush of the filter
// table, and no rewriting of the built-in policies (the old implementation did
// both, which destroyed Docker's rules and left FORWARD on ACCEPT).
func (n *NetworkIsolator) releaseLinux(ctx context.Context) error {
	var errs []string
	run := func(args ...string) ([]byte, error) {
		return n.run(ctx, "iptables", args...)
	}

	// Delete every jump, not just the first: a bug or a manual edit could have
	// left more than one, and a leftover jump keeps the host isolated.
	for _, builtin := range []string{"INPUT", "OUTPUT", "FORWARD"} {
		for i := 0; i < 8; i++ {
			if _, err := run("-C", builtin, "-j", edrQuarantineChain); err != nil {
				break // no jump left in this chain
			}
			if out, err := run("-D", builtin, "-j", edrQuarantineChain); err != nil {
				slog.Warn("隔離ジャンプの削除に失敗しました",
					"chain", builtin, "error", err, "output", string(out))
				errs = append(errs, fmt.Sprintf("-D %s: %s", builtin, err))
				break
			}
		}
	}

	// Flush before delete: iptables refuses to delete a non-empty chain. A chain
	// that was never created reports "No chain/target/match by that name", which
	// means there is nothing to release rather than a failure.
	for _, args := range [][]string{
		{"-F", edrQuarantineChain},
		{"-X", edrQuarantineChain},
	} {
		if out, err := run(args...); err != nil {
			if strings.Contains(string(out), "No chain/target/match by that name") {
				continue
			}
			slog.Warn("隔離チェーンの削除に失敗しました",
				"args", args, "error", err, "output", string(out))
			errs = append(errs, fmt.Sprintf("%v: %s", args, err))
		}
	}
	// Try nftables cleanup — both table names used across implementations.
	// "No such file" means the table was never created; treat as already clean.
	for _, table := range []string{"edr_quarantine", "edr_isolate"} {
		out, err := n.run(ctx, "nft", "delete", "table", "inet", table)
		if err != nil && !strings.Contains(string(out), "No such file") {
			slog.Warn("nftables解除コマンド失敗", "table", table, "error", err, "output", string(out))
			errs = append(errs, fmt.Sprintf("nft delete %s: %s", table, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("隔離解除で%d件のエラー: %s", len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// isolateDarwin uses pfctl on macOS.
func (n *NetworkIsolator) isolateDarwin(ctx context.Context, managementIP string) error {
	pfConf := fmt.Sprintf(`
block all
pass quick on lo0 all
pass quick from %s to any
pass quick from any to %s
`, managementIP, managementIP)

	cmd := exec.CommandContext(ctx, "pfctl", "-ef", "-")
	cmd.Stdin = strings.NewReader(pfConf)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("pfctl isolation failed: %w: %s", err, out)
	}
	// Enable pf
	exec.CommandContext(ctx, "pfctl", "-e").Run() //nolint:errcheck
	return nil
}

// releaseDarwin removes pf isolation on macOS.
func (n *NetworkIsolator) releaseDarwin(ctx context.Context) error {
	var errs []string
	for _, args := range [][]string{
		{"pfctl", "-F", "all"},
		{"pfctl", "-d"},
	} {
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			// "pf not enabled" means pf was never activated — already clean.
			if strings.Contains(string(out), "pf not enabled") || strings.Contains(string(out), "Device not configured") {
				continue
			}
			slog.Warn("pfctl解除コマンド失敗", "args", args, "error", err, "output", string(out))
			errs = append(errs, fmt.Sprintf("%v: %s", args, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("pfctl解除で%d件のエラー: %s", len(errs), strings.Join(errs, "; "))
	}
	return nil
}

// isolateWindows uses Windows Firewall (netsh) to block all traffic.
func (n *NetworkIsolator) isolateWindows(ctx context.Context, managementIP string) error {
	cmds := [][]string{
		// Block all inbound and outbound
		{"netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "blockinbound,blockoutbound"},
		// Allow management server inbound
		{"netsh", "advfirewall", "firewall", "add", "rule",
			"name=EDR_MGT_IN", "dir=in", "action=allow",
			"remoteip=" + managementIP, "protocol=any"},
		// Allow management server outbound
		{"netsh", "advfirewall", "firewall", "add", "rule",
			"name=EDR_MGT_OUT", "dir=out", "action=allow",
			"remoteip=" + managementIP, "protocol=any"},
	}

	for _, args := range cmds {
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		if out, err := cmd.CombinedOutput(); err != nil {
			return fmt.Errorf("netsh command failed %v: %w: %s", args, err, out)
		}
	}
	return nil
}

// releaseWindows restores Windows Firewall to default.
func (n *NetworkIsolator) releaseWindows(ctx context.Context, managementIP string) error {
	_ = managementIP
	var errs []string
	cmds := [][]string{
		{"netsh", "advfirewall", "firewall", "delete", "rule", "name=EDR_MGT_IN"},
		{"netsh", "advfirewall", "firewall", "delete", "rule", "name=EDR_MGT_OUT"},
		{"netsh", "advfirewall", "set", "allprofiles", "firewallpolicy", "allowinbound,allowoutbound"},
	}
	for _, args := range cmds {
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		if err != nil {
			// "No rules match" means the EDR rule was never added — already clean.
			if strings.Contains(string(out), "No rules match") {
				continue
			}
			slog.Warn("netsh解除コマンド失敗", "args", args, "error", err, "output", string(out))
			errs = append(errs, fmt.Sprintf("%v: %s", args, err))
		}
	}
	if len(errs) > 0 {
		return fmt.Errorf("ファイアウォール解除に失敗しました (Windows, %d件): %s", len(errs), strings.Join(errs, "; "))
	}
	return nil
}
