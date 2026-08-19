//go:build windows

// isolate_firewall_policy.go — preservation and restoration of the Windows
// Firewall default policy across an isolate/unisolate cycle.
//
// Isolate() has to relax the default policy before it enables the firewall and
// installs its scoped block rules (see isolate_wfp.go for why). Unisolate used
// to "restore" that policy by writing a hardcoded allowinbound,allowoutbound —
// which is not a restore at all. Windows ships with inbound BLOCKED on every
// profile, so a single isolate/unisolate cycle silently left the host accepting
// inbound connections on all three profiles, forever. A host that had the
// firewall switched off entirely came back with it switched on. Neither is what
// the operator configured, and nothing told them it had changed.
//
// The policy is therefore snapshotted before it is touched and written back
// afterwards. Two details matter:
//
//   - The snapshot is read from the registry, not from `netsh advfirewall show`.
//     netsh's output is localised — the same reason isolationRuleNameRe matches
//     our own ASCII rule names rather than netsh's "Rule Name:" label — so
//     parsing it breaks on a non-English host, which is exactly where a silent
//     firewall downgrade would be hardest to notice.
//
//   - The snapshot is persisted to disk. Isolation outlives the agent process
//     (the rules are in the firewall, not in memory), so an agent restart
//     between isolate and unisolate must not lose the only record of what the
//     policy used to be.
//
// When no snapshot is available the policy is left ALONE rather than forced to
// allow. Leaving isolation's relaxed policy in place is bad; writing an
// allow-inbound policy the operator never chose is worse, and it is what the
// previous code did unconditionally.
package windows

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"golang.org/x/sys/windows/registry"
)

const fwPolicyKeyRoot = `SYSTEM\CurrentControlSet\Services\SharedAccess\Parameters\FirewallPolicy`

// Windows' own defaults, applied when a value is absent from the registry.
// Absent means "Windows is using its default", so the snapshot records the
// effective policy and restore writes it explicitly. That materialises a
// previously-implicit setting, which changes the registry but not the behaviour.
const (
	fwDefaultEnabled  = 1 // firewall on
	fwDefaultInbound  = 1 // block
	fwDefaultOutbound = 0 // allow
)

// fwProfile is one Windows Firewall profile, named both as the registry subkey
// that holds its default policy and as the netsh token that sets it. What the
// registry calls StandardProfile is what netsh calls privateprofile.
type fwProfile struct {
	regKey string
	netsh  string
}

var fwProfiles = []fwProfile{
	{"DomainProfile", "domainprofile"},
	{"StandardProfile", "privateprofile"},
	{"PublicProfile", "publicprofile"},
}

// fwPolicy is the part of a profile's configuration Isolate() overwrites.
// Values mirror the registry encoding: 0 = allow, 1 = block; Enabled is 0/1.
type fwPolicy struct {
	Enabled      uint64 `json:"enabled"`
	Inbound      uint64 `json:"inbound"`
	Outbound     uint64 `json:"outbound"`
	NoExceptions uint64 `json:"no_exceptions"`
}

// fwSnapshot maps a profile's netsh token to the policy it had before isolation.
type fwSnapshot map[string]fwPolicy

// netshPolicyTokens renders the policy as the argument netsh's `set … firewallpolicy`
// expects. blockinboundalways is the distinct third inbound state Windows exposes
// (block, and ignore allow rules); collapsing it to blockinbound would quietly
// re-open every allow rule the operator had suppressed.
func (p fwPolicy) netshPolicyTokens() string {
	in := "allowinbound"
	if p.Inbound == 1 {
		in = "blockinbound"
		if p.NoExceptions == 1 {
			in = "blockinboundalways"
		}
	}
	out := "allowoutbound"
	if p.Outbound == 1 {
		out = "blockoutbound"
	}
	return in + "," + out
}

func (p fwPolicy) netshStateToken() string {
	if p.Enabled == 1 {
		return "on"
	}
	return "off"
}

// readFirewallPolicy snapshots the default policy of all three profiles.
func readFirewallPolicy() (fwSnapshot, error) {
	snap := make(fwSnapshot, len(fwProfiles))
	for _, p := range fwProfiles {
		k, err := registry.OpenKey(registry.LOCAL_MACHINE, fwPolicyKeyRoot+`\`+p.regKey, registry.QUERY_VALUE)
		if err != nil {
			// A missing profile key is normal on a machine that has never been
			// domain-joined; the profile still exists with Windows' defaults.
			snap[p.netsh] = fwPolicy{Enabled: fwDefaultEnabled, Inbound: fwDefaultInbound, Outbound: fwDefaultOutbound}
			continue
		}
		val := func(name string, def uint64) uint64 {
			v, _, err := k.GetIntegerValue(name)
			if err != nil {
				return def
			}
			return v
		}
		snap[p.netsh] = fwPolicy{
			Enabled:      val("EnableFirewall", fwDefaultEnabled),
			Inbound:      val("DefaultInboundAction", fwDefaultInbound),
			Outbound:     val("DefaultOutboundAction", fwDefaultOutbound),
			NoExceptions: val("DoNotAllowExceptions", 0),
		}
		_ = k.Close()
	}
	return snap, nil
}

// firewallPolicyStatePath is where the pre-isolation snapshot survives an agent
// restart. It sits alongside the agent's other Windows state under ProgramData.
func firewallPolicyStatePath() string {
	pd := os.Getenv("ProgramData")
	if pd == "" {
		pd = `C:\ProgramData`
	}
	return filepath.Join(pd, "EDRAgent", "isolation-firewall-policy.json")
}

func saveFirewallPolicy(snap fwSnapshot) error {
	path := firewallPolicyStatePath()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return fmt.Errorf("状態ディレクトリの作成に失敗しました: %w", err)
	}
	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("ポリシーの符号化に失敗しました: %w", err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("ポリシーの保存に失敗しました: %w", err)
	}
	return nil
}

// loadFirewallPolicy returns the persisted snapshot, or nil when there is none.
// A missing file is the normal case (no isolation in progress), not an error.
func loadFirewallPolicy() fwSnapshot {
	data, err := os.ReadFile(firewallPolicyStatePath())
	if err != nil {
		return nil
	}
	var snap fwSnapshot
	if err := json.Unmarshal(data, &snap); err != nil || len(snap) == 0 {
		return nil
	}
	return snap
}

func clearFirewallPolicyState() {
	_ = os.Remove(firewallPolicyStatePath())
}

// restoreFirewallPolicy writes each profile's saved policy back.
//
// Policy is set before state: turning a profile off first would drop the
// firewall for as long as the two commands take, and setting the policy of an
// already-off profile is harmless.
func restoreFirewallPolicy(snap fwSnapshot, run func(args ...string) error) []string {
	var errs []string
	for _, p := range fwProfiles {
		pol, ok := snap[p.netsh]
		if !ok {
			continue
		}
		if err := run("advfirewall", "set", p.netsh, "firewallpolicy", pol.netshPolicyTokens()); err != nil {
			errs = append(errs, fmt.Sprintf("restore %s policy: %v", p.netsh, err))
		}
		if err := run("advfirewall", "set", p.netsh, "state", pol.netshStateToken()); err != nil {
			errs = append(errs, fmt.Sprintf("restore %s state: %v", p.netsh, err))
		}
	}
	return errs
}
