//go:build linux || windows

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/edr-platform/agent/internal/scanner"
)

// memoryScanEnabled reports whether the periodic memory/injection scanner should
// run. It now defaults ON (opt-OUT): previously the entire memory-scan source was
// off unless EDR_MEMORY_SCAN=1, so fileless / injected implants (T1055 Process
// Injection, T1620 Reflective Loading) living only in RWX / unbacked-executable
// memory were never detected on a default install — despite the scanner, the
// curated in-memory YARA set, and the server-side "memory" finding all being
// built. Set EDR_MEMORY_SCAN to 0/false/no/off to disable (e.g. on latency-
// sensitive hosts or those with very high process counts). Legacy EDR_MEMORY_SCAN=1
// still enables it.
//
// Cost note (for reviewers): enumeration is a periodic (60s) region walk
// (VirtualQueryEx on Windows, /proc/<pid>/maps on Linux) and only RWX +
// unbacked-executable regions are YARA-scanned with a small curated ruleset, so
// steady-state overhead is bounded — but it is not zero, which is why this was
// originally opt-in.
func memoryScanEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv("EDR_MEMORY_SCAN"))) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// memoryYARARules is a small, memory-SPECIFIC ruleset for scanning RWX regions.
// Signatures are distinctive implant/loader strings that do not appear in ordinary
// JIT/executable memory, so they do not over-match (unlike the file-scanning HKTL
// set). Extend with vetted in-memory rules; keep conditions specific.
const memoryYARARules = `
rule InMemory_Test_Implant {
    meta: description = "test marker for the in-memory YARA path"
    strings:
        $s = "in_memory_implant_test"
    condition: any of them
}
rule InMemory_CobaltStrike_Beacon {
    meta: description = "Cobalt Strike beacon in-memory markers"
    strings:
        $a = "ReflectiveLoader"
        $b = "%s as %s\\%s: %d"
        $c = "beacon.x64.dll"
        $d = "beacon.dll"
    condition: any of them
}
rule InMemory_Meterpreter {
    meta: description = "Meterpreter in-memory markers"
    strings:
        $a = "metsrv.dll"
        $b = "stdapi_"
        $c = "ReflectiveLoader@"
        $d = "stdapi_railgun_api"
        $e = "core_channel_open"
        $f = "priv_passwd_get_sam_hashes"
    condition: any of them
}
rule InMemory_Mimikatz {
    meta: description = "Mimikatz credential-dumping tool in-memory markers"
    strings:
        $a = "sekurlsa::logonpasswords"
        $b = "kuhl_m_sekurlsa"
        $c = "lsadump::sam"
        $d = "kerberos::ptt"
        $e = "gentilkiwi"
    condition: any of them
}
rule InMemory_AMSI_Bypass {
    meta: description = "In-memory AMSI bypass (PowerShell) markers"
    strings:
        $a = "amsiInitFailed"
        $b = "System.Management.Automation.AmsiUtils"
    condition: any of them
}
rule InMemory_Kerberos_Abuse {
    meta: description = "Rubeus / Kerberoasting toolkit markers"
    strings:
        $a = "asreproast"
        $b = "kerberoast"
        $c = "Rubeus.Domain"
        $d = "createnetonly"
    condition: any of them
}
rule InMemory_SharpHound {
    meta: description = "SharpHound / BloodHound AD recon markers"
    strings:
        $a = "SharpHound"
        $b = "BloodHound"
        $c = "Sharphound.Client"
    condition: any of them
}
rule InMemory_Havoc_Demon {
    meta: description = "Havoc C2 Demon agent markers"
    strings:
        $a = "Demon.x64.dll"
        $b = "Demon.x86.dll"
        $c = "KaynLdr"
    condition: any of them
}
`

// memFindingKey identifies one suspicious region across scan cycles. The address
// range, size, perms and YARA verdict are all part of the identity: if a region
// grows, changes protection, or starts matching a curated rule, that is new
// information and must alert again rather than be suppressed as "already seen".
// ProcessName is included so a reused PID belonging to a different image cannot
// inherit the previous process's suppression state.
type memFindingKey struct {
	pid         int
	processName string
	address     string
	size        uint64
	perms       string
	yaraMatched bool
}

func memKeyOf(f collector.MemoryFinding) memFindingKey {
	return memFindingKey{
		pid: f.PID, processName: f.ProcessName, address: f.Address,
		size: f.Size, perms: f.Perms, yaraMatched: f.YARAMatched,
	}
}

// memFindingSuppressor turns the scanner from a state dump into a change
// detector: a region is reported the FIRST time it is seen and then stays quiet
// while it persists.
//
// Without it every still-present region is re-sent on every 60s tick. Measured on
// an idle Windows Server: the .NET/CLR JIT's RWX regions in a single running
// powershell.exe produced 10 findings per cycle — ~14,400 duplicate events per
// day per host, before any real detection. Allowlisting powershell.exe would fix
// the volume but blind exactly what this scanner exists to catch (T1059.001
// fileless PowerShell, T1055 injection, T1620 reflective loading all live in RWX
// memory inside powershell.exe), so suppression is the correct lever.
//
// Detection is not weakened: injected code appears as a region that was not there
// before, which is precisely what survives the filter. Regions that vanish are
// forgotten, so a region that reappears alerts again.
type memFindingSuppressor struct {
	seen map[memFindingKey]bool
}

func newMemFindingSuppressor() *memFindingSuppressor {
	return &memFindingSuppressor{seen: make(map[memFindingKey]bool)}
}

// filter returns the findings that are new since the previous cycle and the count
// suppressed as unchanged. It also rebuilds the tracked set from the current
// cycle, which prunes regions that are gone and processes that have exited — so
// the map stays bounded by what is live right now, not by everything ever seen.
func (s *memFindingSuppressor) filter(findings []collector.MemoryFinding) (fresh []collector.MemoryFinding, suppressed int) {
	current := make(map[memFindingKey]bool, len(findings))
	for _, f := range findings {
		k := memKeyOf(f)
		current[k] = true
		if s.seen[k] {
			suppressed++
			continue
		}
		fresh = append(fresh, f)
	}
	s.seen = current
	return fresh, suppressed
}

// runMemscanBench runs the memory scanner standalone for the #511 default-ON load
// review: N cycles, print the cost, exit. Retained as a fleet diagnostic.
//
// It exists because measuring the real cost otherwise requires deploying an
// enrolled agent and stopping the installed service on the host under test. This
// mode needs no config, no enrollment and no server connection, and sends no
// events — so it can be run next to a live agent without producing duplicate
// telemetry or spurious alerts.
//
// Fidelity notes for whoever reads the numbers:
//   - Back-to-back cycles (interval 0) run against a warm page cache and can
//     UNDERSTATE a cold 60s-interval scan; pass -memscan-bench-interval 60s for a
//     realistic steady-state figure.
//   - On Windows the real agent holds SeDebugPrivilege, which lets it open (and
//     therefore walk) system processes it would otherwise skip cheaply. Without
//     -memscan-bench-sedebug this bench UNDERSTATES the production cost; run it
//     both ways to see the spread.
func runMemscanBench(cycles int, interval time.Duration, seDebug bool, verbose bool) {
	priv := "対象外 (Windows専用)"
	if runtime.GOOS == "windows" {
		priv = "無効 — 本番エージェントより軽く出ます (-memscan-bench-sedebug で有効化)"
		if seDebug && benchEnableSeDebug() {
			priv = "有効化を試行 (本番エージェント相当の対象範囲)"
		}
	}

	ys := scanner.NewYARAScanner()
	_ = ys.LoadRules(memoryYARARules)
	yaraScan := func(data []byte) []string {
		var names []string
		for _, m := range ys.ScanBytes(data) {
			names = append(names, m.RuleName)
		}
		return names
	}

	fmt.Printf("=== メモリスキャン負荷計測 (#511) ===\n")
	fmt.Printf("os=%s/%s cycles=%d interval=%s SeDebugPrivilege=%s\n\n",
		runtime.GOOS, runtime.GOARCH, cycles, interval, priv)

	// Same suppressor the service uses, so the bench reports the events that
	// would actually be sent — the steady-state figure the default-ON decision
	// rests on — rather than the raw per-cycle region list.
	sup := newMemFindingSuppressor()

	var total, minD, maxD time.Duration
	var last collector.MemoryScanStats
	var lastFresh, lastSuppressed int
	for i := 1; i <= cycles; i++ {
		if i > 1 && interval > 0 {
			time.Sleep(interval)
		}
		all, st := collector.ScanSuspiciousMemoryWithYARAStats(yaraScan)
		findings, suppressed := sup.filter(all)
		lastFresh, lastSuppressed = len(findings), suppressed
		total += st.Duration
		if minD == 0 || st.Duration < minD {
			minD = st.Duration
		}
		if st.Duration > maxD {
			maxD = st.Duration
		}
		last = st
		fmt.Printf("cycle %2d: %5dms  procs enum=%d walk=%d allow=%d unread=%d  regions=%d  yara=%d(%.1fMiB)  findings raw=%d 候補=%d 送信=%d 抑制=%d  slowest=%s(pid %d) %dms\n",
			i, st.Duration.Milliseconds(),
			st.ProcessesEnumerated, st.ProcessesScanned, st.SkippedAllowlisted, st.SkippedUnreadable,
			st.RegionsExamined, st.RegionsYARAScanned, float64(st.BytesYARAScanned)/(1<<20),
			st.RawFindings, st.EmittedFindings, len(findings), suppressed,
			st.SlowestProcess, st.SlowestPID, st.SlowestDuration.Milliseconds())

		// Only the fresh set is listed: these are the events the server would
		// actually receive this cycle. After the first cycle this should be empty
		// on a quiet host — anything appearing later is a genuinely new region.
		if verbose {
			for _, f := range findings {
				fmt.Printf("    emit: pid=%-6d %-28s %s %-5s %7.1fKiB rwx=%-5v unbacked=%-5v yara=%-5v %s\n",
					f.PID, f.ProcessName, f.Address, f.Perms, float64(f.Size)/1024,
					f.RWX, f.Unbacked, f.YARAMatched, f.Reason)
			}
		}
	}

	avg := total / time.Duration(cycles)
	const prodInterval = 60 * time.Second
	fmt.Printf("\n=== 集計 ===\n")
	fmt.Printf("所要時間      : avg %dms / min %dms / max %dms\n",
		avg.Milliseconds(), minD.Milliseconds(), maxD.Milliseconds())
	// The decision number: what fraction of each production 60s period the
	// scanner is actually busy.
	fmt.Printf("60秒周期の占有率: avg %.2f%% / max %.2f%%\n",
		float64(avg)/float64(prodInterval)*100, float64(maxD)/float64(prodInterval)*100)
	fmt.Printf("対象プロセス  : 列挙=%d 走査=%d allowlist除外=%d 未オープン=%d\n",
		last.ProcessesEnumerated, last.ProcessesScanned, last.SkippedAllowlisted, last.SkippedUnreadable)
	fmt.Printf("領域          : 検査=%d YARA=%d\n", last.RegionsExamined, last.RegionsYARAScanned)
	fmt.Printf("最遅プロセス  : %s (pid %d) %dms\n",
		last.SlowestProcess, last.SlowestPID, last.SlowestDuration.Milliseconds())
	// The decision number for event volume: with first-sight suppression the last
	// cycle's fresh count is the steady state. Persistent benign regions cost one
	// event each at startup and nothing afterwards; a non-zero steady state means
	// regions are genuinely churning and deserves a look before default-ON.
	perDay := int64(lastFresh) * int64(24*time.Hour/prodInterval)
	fmt.Printf("定常イベント量: %d件/周 → 約%d件/日/台 (最終周: 送信=%d 抑制=%d)\n",
		lastFresh, perDay, lastFresh, lastSuppressed)
	fmt.Printf("  ※ 初回周期の %d 件は常駐領域の初回報告で、以降は抑制されます\n", last.EmittedFindings)
}

// runMemoryScanService runs M1 of the memory/injection detection design: it
// periodically scans process memory for RWX / unbacked-executable regions
// (injection/shellcode indicators) and emits each finding as a "memory" event.
// Region enumeration is per-OS: /proc/<pid>/maps on Linux, VirtualQueryEx on
// Windows (collector.ScanSuspiciousMemory).
//
// Findings are reported on first sight only (memFindingSuppressor), so a
// persistent benign region — a JIT's RWX pages — costs one event, not one per
// cycle forever.
//
// Defaults ON; opt out with EDR_MEMORY_SCAN=0/false/no/off (see
// memoryScanEnabled). Blocks until ctx is cancelled. Unsupported OSes get the
// no-op stub.
func runMemoryScanService(ctx context.Context, sender collector.EventSender, agentID, serverURL string) {
	if !memoryScanEnabled() {
		return
	}
	const interval = 60 * time.Second

	// Build a YARA matcher for RWX regions. IMPORTANT: use a CURATED in-memory
	// ruleset only — NOT the full server file-scanning set. The server's HKTL/PE
	// rules (HKTL_NET_GUID_*, PE-magic conditions, etc.) are written for scanning
	// files on disk and OVER-MATCH arbitrary executable memory in the pure-Go
	// engine, flooding false positives on every JIT/RWX page (observed live:
	// Node.js/networkd RWX pages matching dozens of APT rules). In-memory detection
	// needs memory-specific signatures (implant configs / shellcode patterns).
	ys := scanner.NewYARAScanner()
	_ = ys.LoadRules(memoryYARARules)
	_ = serverURL // reserved: a curated in-memory rule feed could be delivered here later
	yaraScan := func(data []byte) []string {
		var names []string
		for _, m := range ys.ScanBytes(data) {
			names = append(names, m.RuleName)
		}
		return names
	}
	slog.Info("[memscan] メモリスキャン(RWX/非バック実行領域 + メモリ内YARA)を起動しました", "interval", interval.String())

	// Per-cycle cost line (duration, processes walked vs skipped, regions
	// examined, slowest single process). Debug level deliberately: at the 60s
	// interval this would otherwise add ~1,440 log lines per day per host for a
	// figure nobody reads while the scanner behaves. Raise logging.level to debug
	// to diagnose a host whose scans look expensive. Cycle-local counters — the
	// service runs on a single goroutine, so no synchronisation is needed.
	var cycles int
	var cumulative, peak time.Duration

	// Report each region once, on first sight — see memFindingSuppressor.
	sup := newMemFindingSuppressor()

	scan := func() {
		all, st := collector.ScanSuspiciousMemoryWithYARAStats(yaraScan)
		findings, suppressed := sup.filter(all)
		cycles++
		cumulative += st.Duration
		if st.Duration > peak {
			peak = st.Duration
		}
		slog.Debug("[memscan] スキャン負荷計測", append(st.LogArgs(),
			"cycle", cycles,
			"avg_ms", cumulative.Milliseconds()/int64(cycles),
			"peak_ms", peak.Milliseconds(),
			"findings_new", len(findings),
			"findings_suppressed", suppressed)...)

		for _, f := range findings {
			slog.Warn("[memscan] 不審なメモリ領域を検出",
				"pid", f.PID, "process", f.ProcessName, "perms", f.Perms,
				"unbacked", f.Unbacked, "rwx", f.RWX, "addr", f.Address, "reason", f.Reason)
			if batch := collector.BuildMemoryEvent(agentID, f); batch != nil {
				_ = sender.SendEvents(ctx, batch)
			}
		}
	}

	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	scan()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			scan()
		}
	}
}
