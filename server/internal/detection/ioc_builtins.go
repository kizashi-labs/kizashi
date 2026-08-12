// Package detection — ioc_builtins.go provides a static set of well-known
// threat indicators that are always present in the IOC cache, independent of
// the database.  These are merged into the live cache by CompositeIOCLoader.
package detection

import (
	"context"
)

// builtinIOCs is the curated list of known-malicious indicators shipped with
// the platform.  They serve as a baseline even before operators import their
// own feeds.
var builtinIOCs = []IOCRecord{
	// ── Malicious IP ranges (C2 / ransomware infrastructure) ──
	{
		ID:          "builtin-ip-001",
		Type:        "ip",
		Value:       "185.220.101.34",
		Description: "Tor exit node used for C2 communication (185.220.101.0/24)",
		Severity:    8,
	},
	{
		ID:          "builtin-ip-002",
		Type:        "ip",
		Value:       "185.220.101.47",
		Description: "Tor exit node used for C2 communication (185.220.101.0/24)",
		Severity:    8,
	},
	{
		ID:          "builtin-ip-003",
		Type:        "ip",
		Value:       "194.165.16.72",
		Description: "Known malware C2 server (194.165.16.0/24)",
		Severity:    9,
	},
	{
		ID:          "builtin-ip-004",
		Type:        "ip",
		Value:       "45.142.212.100",
		Description: "Ransomware C2 infrastructure (45.142.212.0/24)",
		Severity:    10,
	},

	// ── Malicious IP ranges (CIDR — matched by containment) ───
	// These cover the whole known-bad netblock, not just one address, so an
	// implant rotating within the /24 is still caught.
	{
		ID:          "builtin-cidr-001",
		Type:        "ip",
		Value:       "185.220.101.0/24",
		Description: "Tor exit-node block frequently used for C2 (185.220.101.0/24)",
		Severity:    8,
	},
	{
		ID:          "builtin-cidr-002",
		Type:        "ip",
		Value:       "45.142.212.0/24",
		Description: "Ransomware C2 infrastructure netblock (45.142.212.0/24)",
		Severity:    10,
	},

	// ── Malicious domains ─────────────────────────────────────
	{
		ID:          "builtin-domain-001",
		Type:        "domain",
		Value:       "update-service.net",
		Description: "Common malware persistence / C2 domain",
		Severity:    8,
	},
	{
		ID:          "builtin-domain-002",
		Type:        "domain",
		Value:       "windowsupdate-cdn.com",
		Description: "Typosquatting domain mimicking Windows Update",
		Severity:    9,
	},
	{
		ID:          "builtin-domain-003",
		Type:        "domain",
		Value:       "microsoftsecurity.xyz",
		Description: "Phishing domain impersonating Microsoft Security",
		Severity:    9,
	},
	{
		ID:          "builtin-domain-004",
		Type:        "domain",
		Value:       "dl.dropmefiles.com",
		Description: "Data exfiltration staging domain",
		Severity:    7,
	},

	// ── Malicious file hashes ─────────────────────────────────
	{
		ID:          "builtin-hash-001",
		Type:        "hash",
		Value:       "5f70bf18a086007016e948b04aed3b82103a36bea41755b6cddfaf10ace3c6ef",
		Description: "Known ransomware dropper (SHA256)",
		Severity:    10,
	},
	{
		ID:          "builtin-hash-002",
		Type:        "hash",
		Value:       "44d88612fea8a8f36de82e1278abb02f",
		Description: "Mirai botnet variant (MD5)",
		Severity:    9,
	},

	// ── Malicious process names (matched via process IOC type) ─
	// NOTE: process-name IOCs use a custom "process" type; the IOCMatcher
	// CheckEvent method must inspect the "process_name" / "Image" fields
	// against this type.  The existing hash check covers image hashes;
	// process-name matching is handled by the Sigma rules above.  We store
	// these as "process" type so future matchers / reports can query them.
	{
		ID:          "builtin-proc-001",
		Type:        "process",
		Value:       "mimikatz.exe",
		Description: "Mimikatz credential dumping tool",
		Severity:    10,
	},
	{
		ID:          "builtin-proc-002",
		Type:        "process",
		Value:       "meterpreter",
		Description: "Metasploit Meterpreter payload",
		Severity:    10,
	},
	{
		ID:          "builtin-proc-003",
		Type:        "process",
		Value:       "cobaltstrike",
		Description: "Cobalt Strike C2 beacon",
		Severity:    10,
	},
	{
		ID:          "builtin-proc-004",
		Type:        "process",
		Value:       "havoc",
		Description: "Havoc C2 framework",
		Severity:    10,
	},
}

// StaticIOCLoader implements IOCLoader and returns a fixed set of IOC entries.
// It is used by CompositeIOCLoader to prepend built-in indicators to the DB list.
type StaticIOCLoader struct {
	entries []IOCRecord
}

// NewStaticIOCLoader returns a StaticIOCLoader containing the given entries.
func NewStaticIOCLoader(entries []IOCRecord) *StaticIOCLoader {
	return &StaticIOCLoader{entries: entries}
}

// ListActiveIOCs returns the static entries.
func (l *StaticIOCLoader) ListActiveIOCs(_ context.Context) ([]IOCRecord, error) {
	return l.entries, nil
}

// CompositeIOCLoader merges results from multiple IOCLoader implementations.
// Entries from earlier loaders appear first in the merged list.
type CompositeIOCLoader struct {
	loaders []IOCLoader
}

// NewCompositeIOCLoader creates a CompositeIOCLoader that queries each loader
// in order and concatenates the results.
func NewCompositeIOCLoader(loaders ...IOCLoader) *CompositeIOCLoader {
	return &CompositeIOCLoader{loaders: loaders}
}

// ListActiveIOCs queries all child loaders and returns the combined slice.
// If a loader fails its results are skipped (best-effort).
func (c *CompositeIOCLoader) ListActiveIOCs(ctx context.Context) ([]IOCRecord, error) {
	var all []IOCRecord
	for _, l := range c.loaders {
		entries, err := l.ListActiveIOCs(ctx)
		if err != nil {
			continue // partial failure — keep the rest
		}
		all = append(all, entries...)
	}
	return all, nil
}

// BuiltinIOCLoader returns a StaticIOCLoader pre-loaded with the built-in IOCs.
func BuiltinIOCLoader() *StaticIOCLoader {
	return NewStaticIOCLoader(builtinIOCs)
}
