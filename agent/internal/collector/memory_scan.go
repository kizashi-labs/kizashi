// memory_scan.go holds the OS-agnostic parts of the M1 memory/injection scanner
// (the per-OS region enumeration lives in memory_scan_{linux,windows}.go). See
// docs/design/メモリ・インジェクション検知設計.md.
package collector

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// MemoryFinding describes a suspicious memory region in a process — an
// injection/shellcode indicator (RWX or unbacked-executable).
type MemoryFinding struct {
	PID         int    `json:"pid"`
	ProcessName string `json:"process_name"`
	Address     string `json:"address"` // "<start>-<end>" hex
	Perms       string `json:"perms"`   // "rwxp" (linux) or "RWX"/"EXEC" (windows)
	Size        uint64 `json:"size"`
	Unbacked    bool   `json:"unbacked"`     // executable but not file/image-backed
	RWX         bool   `json:"rwx"`          // writable + executable
	YARAMatched bool   `json:"yara_matched"` // curated in-memory YARA rule hit
	Reason      string `json:"reason"`
}

// maxRegionScanBytes caps how much of a suspicious memory region is read and
// YARA-scanned (4 MiB) — enough to catch an implant header/body without reading
// gigabyte-sized heaps. Shared by every OS scanner so the read cost per region is
// bounded identically everywhere.
const maxRegionScanBytes = 4 << 20

// shouldContentScan reports whether a region's bytes should be read and passed to
// the in-memory YARA matcher.
//
// Only RWX (writable+executable) regions are content-scanned: they are the
// classic injected-shellcode shape, and unbacked read-execute pages are common
// enough in ordinary processes that reading all of them would multiply the scan
// cost for little signal.
//
// guarded excludes PAGE_GUARD regions (Windows). Reading a guard page is not a
// neutral observation — the guard exists so the owning process gets notified on
// access, and stack-growth guards in particular are load-bearing. Enumeration
// still reports the region; only the content read is skipped.
func shouldContentScan(rwx, guarded bool) bool {
	return rwx && !guarded
}

// MemoryScanStats reports what one scan cycle actually cost. It exists because
// the default-ON decision (#511) had to be made on measured overhead rather than
// estimates, and it stays because the same numbers are what diagnose a host whose
// scans turn out expensive — a fleet is not uniform, and process count and
// address-space size vary by orders of magnitude across roles.
//
// The counters distinguish work that was *attempted* from work that was
// *skipped*, because the two dominate on different hosts: on Windows most system
// processes cannot be opened without SeDebugPrivilege (SkippedUnreadable), while
// on a JIT-heavy host the allowlist does the culling (SkippedAllowlisted).
type MemoryScanStats struct {
	ProcessesEnumerated int // PIDs seen (/proc entries, Toolhelp snapshot)
	ProcessesScanned    int // PIDs whose regions were actually walked
	SkippedAllowlisted  int // JIT/managed-runtime allowlist hits
	SkippedUnreadable   int // open/read denied (no SeDebugPrivilege, process exited)
	RegionsExamined     int // memory regions inspected across all processes
	RegionsYARAScanned  int // regions whose bytes were read and YARA-scanned
	BytesYARAScanned    int64
	RawFindings         int // suspicious regions before the size-floor policy
	EmittedFindings     int // regions actually reported as events
	Duration            time.Duration

	// Slowest single process in the cycle — identifies the one address space
	// (huge heap, thousands of regions) that dominates the cycle cost, which the
	// totals alone cannot show.
	SlowestPID      int
	SlowestProcess  string
	SlowestDuration time.Duration
}

// observeProcess records one process's contribution to the cycle, keeping the
// slowest one seen. Called by each per-OS scanner.
func (s *MemoryScanStats) observeProcess(pid int, name string, regions int, d time.Duration) {
	s.ProcessesScanned++
	s.RegionsExamined += regions
	if d > s.SlowestDuration {
		s.SlowestPID, s.SlowestProcess, s.SlowestDuration = pid, name, d
	}
}

// LogArgs renders the stats as slog key/value pairs for the per-cycle load line.
func (s MemoryScanStats) LogArgs() []any {
	return []any{
		"duration_ms", s.Duration.Milliseconds(),
		"procs_enumerated", s.ProcessesEnumerated,
		"procs_scanned", s.ProcessesScanned,
		"skipped_allowlisted", s.SkippedAllowlisted,
		"skipped_unreadable", s.SkippedUnreadable,
		"regions_examined", s.RegionsExamined,
		"regions_yara_scanned", s.RegionsYARAScanned,
		"yara_bytes", s.BytesYARAScanned,
		"findings_raw", s.RawFindings,
		"findings_emitted", s.EmittedFindings,
		"slowest_pid", s.SlowestPID,
		"slowest_process", s.SlowestProcess,
		"slowest_ms", s.SlowestDuration.Milliseconds(),
	}
}

// Alerting size floors. Enumeration finds every RWX / unbacked-executable region,
// but reporting all of them floods false positives on healthy hosts: libffi
// closures and JIT trampolines are a single page, and anonymous executable
// mappings (dlopen thunks, GObject/ffi closures) are common and small. Genuine
// injected code — shellcode, Cobalt Strike beacons, reflective DLL bodies — is
// larger, and the distinctive ones carry a curated in-memory YARA signature.
const (
	// minRWXAlertBytes: an RWX region below this (a single page) with no YARA
	// match is treated as a benign trampoline/closure (e.g. libffi) and dropped.
	minRWXAlertBytes = 8 << 10 // 8 KiB
	// minUnbackedAlertBytes: a bare unbacked read-execute region (no write, no
	// YARA match) below this is the noisiest, lowest-signal class — dropped —
	// while large anonymous executable payloads are still surfaced.
	minUnbackedAlertBytes = 256 << 10 // 256 KiB
)

// shouldEmitMemoryFinding decides whether an enumerated region is reported as an
// alert. A curated in-memory YARA match (content confirmation) always wins;
// otherwise size gates cut the benign trampoline/closure/anon-exec classes that
// exist in ordinary healthy processes. Shared by every OS scanner.
func shouldEmitMemoryFinding(f MemoryFinding) bool {
	if f.YARAMatched {
		return true
	}
	if f.RWX {
		return f.Size >= minRWXAlertBytes
	}
	// unbacked non-RWX (read-execute)
	return f.Size >= minUnbackedAlertBytes
}

// memoryScanAllowlist holds process names that legitimately allocate RWX /
// unbacked-executable memory (JIT compilers / managed runtimes), to limit false
// positives. Holds both Linux /proc/comm names and lowercased Windows image
// names so both scanners can share it.
var memoryScanAllowlist = map[string]bool{
	"chrome": true, "chromium": true, "firefox": true, "msedge": true,
	"node": true, "java": true, "mono": true, "wine": true, "wineserver": true,
	"dotnet": true, "code": true, "discord": true, "slack": true,
	// Node/V8 renames its process via /proc/comm — Next.js runs as "next-server",
	// not "node", so the V8 JIT's RWX code space tripped the scanner on every
	// host running the frontend. Same runtime class as "node" above.
	"next-server": true,
	// Windows image names (lowercased)
	"chrome.exe": true, "msedge.exe": true, "firefox.exe": true, "node.exe": true,
	"java.exe": true, "dotnet.exe": true, "code.exe": true, "powershell_ise.exe": true,
}

// isMemoryScanAllowlisted reports whether a process name belongs to a known
// RWX / exec-anonymous-allocating runtime (JIT / managed runtime).
//
// It also matches the first whitespace-separated token: Linux /proc/comm caps a
// process title at 15 bytes, so Next.js's "next-server (v15.1.0)" arrives as
// "next-server (v" — the space-split base ("next-server") is what must match.
func isMemoryScanAllowlisted(name string) bool {
	if memoryScanAllowlist[name] {
		return true
	}
	if i := strings.IndexByte(name, ' '); i > 0 {
		return memoryScanAllowlist[name[:i]]
	}
	return false
}

// classifyRegion returns the reason string for a suspicious executable region.
func classifyRegion(rwx, unbacked bool) string {
	switch {
	case unbacked && rwx:
		return "RWXかつ非バック実行領域（floating code/シェルコードの可能性）"
	case unbacked:
		return "非バック実行領域（反射型DLL/floating codeの可能性）"
	default:
		return "RWX private実行領域（インジェクションの可能性）"
	}
}

// BuildMemoryEvent encodes a memory finding into an EventBatch using the same
// "type:<uuid>:<json>" event-ID wire format as process_block (no proto change).
// The server ingestion decodes the "memory:" prefix into event_type='memory'.
func BuildMemoryEvent(agentID string, f MemoryFinding) *v1.EventBatch {
	data, err := json.Marshal(f)
	if err != nil {
		return nil
	}
	eventID := fmt.Sprintf("memory:%s:%s", newEventID(), string(data))
	return &v1.EventBatch{
		AgentId: agentID,
		Events: []*v1.Event{{
			Id:        eventID,
			Timestamp: timestamppb.New(time.Now()),
			Type:      v1.EventType_EVENT_TYPE_LOG,
		}},
	}
}
