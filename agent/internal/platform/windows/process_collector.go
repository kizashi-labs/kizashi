//go:build windows

package windows

import (
	"context"
	"encoding/binary"
	"log/slog"
	"path/filepath"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

var (
	winKernel32                     = windows.NewLazySystemDLL("kernel32.dll")
	winProcCreateToolhelp32Snapshot = winKernel32.NewProc("CreateToolhelp32Snapshot")
	winProcProcess32FirstW          = winKernel32.NewProc("Process32FirstW")
	winProcProcess32NextW           = winKernel32.NewProc("Process32NextW")
	winProcReadProcessMemory        = winKernel32.NewProc("ReadProcessMemory")

	winNtdll                         = windows.NewLazySystemDLL("ntdll.dll")
	winProcNtQueryInformationProcess = winNtdll.NewProc("NtQueryInformationProcess")
)

// readProcessMemory reads n bytes from a remote process at address addr.
func readProcessMemory(handle windows.Handle, addr uintptr, n int) ([]byte, bool) {
	buf := make([]byte, n)
	var read uintptr
	r, _, _ := winProcReadProcessMemory.Call(
		uintptr(handle),
		addr,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(n),
		uintptr(unsafe.Pointer(&read)),
	)
	return buf, r != 0 && int(read) == n
}

// readParentPID reads InheritedFromUniqueProcessId from PROCESS_BASIC_INFORMATION.
// Offset 40 on 64-bit Windows. Returns 0 on failure.
func readParentPID(handle windows.Handle) uint32 {
	var pbi [48]byte
	var returnLen uint32
	ret, _, _ := winProcNtQueryInformationProcess.Call(
		uintptr(handle),
		0,
		uintptr(unsafe.Pointer(&pbi[0])),
		uintptr(len(pbi)),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if ret != 0 {
		return 0
	}
	ppid := binary.LittleEndian.Uint64(pbi[40:48])
	return uint32(ppid)
}

// readCommandLine reads the process command line from its PEB via NtQueryInformationProcess.
// Works for 64-bit processes on 64-bit Windows.
func readCommandLine(handle windows.Handle) string {
	// PROCESS_BASIC_INFORMATION (64-bit): PebBaseAddress is at offset 8
	var pbi [48]byte
	var returnLen uint32
	ret, _, _ := winProcNtQueryInformationProcess.Call(
		uintptr(handle),
		0, // ProcessBasicInformation
		uintptr(unsafe.Pointer(&pbi[0])),
		uintptr(len(pbi)),
		uintptr(unsafe.Pointer(&returnLen)),
	)
	if ret != 0 {
		return ""
	}

	// PebBaseAddress is at offset 8 in PROCESS_BASIC_INFORMATION (64-bit)
	pebBase := uintptr(binary.LittleEndian.Uint64(pbi[8:16]))
	if pebBase == 0 {
		return ""
	}

	// Read ProcessParameters pointer from PEB at offset 0x20
	ppBuf, ok := readProcessMemory(handle, pebBase+0x20, 8)
	if !ok {
		return ""
	}
	ppAddr := uintptr(binary.LittleEndian.Uint64(ppBuf))
	if ppAddr == 0 {
		return ""
	}

	// Read CommandLine UNICODE_STRING from RTL_USER_PROCESS_PARAMETERS at offset 0x70
	// UNICODE_STRING: Length(2) + MaxLength(2) + pad(4) + Buffer ptr(8) = 16 bytes
	clBuf, ok := readProcessMemory(handle, ppAddr+0x70, 16)
	if !ok {
		return ""
	}
	cmdLen := binary.LittleEndian.Uint16(clBuf[0:2])
	cmdBuf := uintptr(binary.LittleEndian.Uint64(clBuf[8:16]))
	if cmdLen == 0 || cmdBuf == 0 {
		return ""
	}

	// Read the UTF-16 command line string
	strBuf, ok := readProcessMemory(handle, cmdBuf, int(cmdLen))
	if !ok {
		return ""
	}

	// Convert UTF-16LE to string
	u16 := make([]uint16, cmdLen/2)
	for i := range u16 {
		u16[i] = binary.LittleEndian.Uint16(strBuf[i*2 : i*2+2])
	}
	return syscall.UTF16ToString(u16)
}

var seDebugOnce sync.Once

// EnableSeDebugPrivilege enables SeDebugPrivilege in the agent's process token.
//
// readCommandLine needs OpenProcess(PROCESS_VM_READ) to read a target's PEB.
// Without SeDebugPrivilege, that open is gated by the target's DACL, so the
// agent (even as LocalSystem) falls back to PROCESS_QUERY_LIMITED_INFORMATION
// for processes owned by other users (e.g. an interactive Administrator's
// powershell). The limited handle still yields image/PPID/username but
// ReadProcessMemory fails, leaving CommandLine empty — which silently disables
// every command-line-based detection rule. SeDebugPrivilege bypasses the DACL
// check so VM_READ succeeds for any process.
//
// LocalSystem holds the privilege but it is DISABLED by default; this enables
// it. Best-effort and idempotent (sync.Once): logs and continues on failure.
func EnableSeDebugPrivilege() {
	seDebugOnce.Do(func() {
		var tok windows.Token
		if err := windows.OpenProcessToken(windows.CurrentProcess(),
			windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY, &tok); err != nil {
			slog.Warn("SeDebugPrivilege: プロセストークンを開けません", "error", err)
			return
		}
		defer tok.Close()

		namePtr, err := windows.UTF16PtrFromString("SeDebugPrivilege")
		if err != nil {
			return
		}
		var luid windows.LUID
		if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
			slog.Warn("SeDebugPrivilege: LookupPrivilegeValue 失敗", "error", err)
			return
		}
		tp := windows.Tokenprivileges{PrivilegeCount: 1}
		tp.Privileges[0] = windows.LUIDAndAttributes{Luid: luid, Attributes: windows.SE_PRIVILEGE_ENABLED}
		// AdjustTokenPrivileges returns ERROR_NOT_ALL_ASSIGNED (as the error)
		// when the token does not hold the privilege at all.
		if err := windows.AdjustTokenPrivileges(tok, false, &tp, 0, nil, nil); err != nil {
			slog.Warn("SeDebugPrivilege を有効化できませんでした（command_line 取得が制限されます）", "error", err)
			return
		}
		slog.Info("SeDebugPrivilege を有効化しました")
	})
}

const (
	winTH32CS_SNAPPROCESS = 0x00000002
	winMAX_PATH           = 260
)

// winProcessEntry32W mirrors the PROCESSENTRY32W Win32 structure.
type winProcessEntry32W struct {
	DwSize              uint32
	CntUsage            uint32
	Th32ProcessID       uint32
	Th32DefaultHeapID   uintptr
	Th32ModuleID        uint32
	CntThreads          uint32
	Th32ParentProcessID uint32
	PcPriClassBase      int32
	DwFlags             uint32
	SzExeFile           [winMAX_PATH]uint16
}

// WindowsProcessCollector monitors processes using Toolhelp32 snapshots.
// It complements ETWProcessCollector (process_etw.go) with a poll-based fallback.
type WindowsProcessCollector struct {
	mu       sync.Mutex
	known    map[uint32]winProcInfo
	interval time.Duration
	cancel   context.CancelFunc
}

type winProcInfo struct {
	pid  uint32
	ppid uint32
	name string
	path string
}

// NewWindowsProcessCollector creates a Toolhelp32-based process collector.
func NewWindowsProcessCollector() *WindowsProcessCollector {
	return &WindowsProcessCollector{
		known:    make(map[uint32]winProcInfo),
		interval: 500 * time.Millisecond,
	}
}

// Start begins polling for process changes and emits events to out.
func (c *WindowsProcessCollector) Start(ctx context.Context, out chan<- collector.ProcessEvent) error {
	ctx, c.cancel = context.WithCancel(ctx)
	// Needed so readCommandLine can read the PEB of processes owned by other
	// users (see EnableSeDebugPrivilege). Idempotent across collectors.
	EnableSeDebugPrivilege()
	go c.poll(ctx, out)
	return nil
}

// Stop cancels the polling loop.
func (c *WindowsProcessCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

func (c *WindowsProcessCollector) poll(ctx context.Context, out chan<- collector.ProcessEvent) {
	// Seed known map AND emit "existing" events so the server-side chain engine
	// can build ancestry trees for processes that were running before agent start.
	c.mu.Lock()
	initial := c.takeSnapshot()
	for _, info := range initial {
		c.known[info.pid] = info
	}
	c.mu.Unlock()
	for _, info := range initial {
		evt := c.buildEvent(info, "existing")
		select {
		case out <- evt:
		case <-ctx.Done():
			return
		}
	}

	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			current := c.takeSnapshot()
			currentMap := make(map[uint32]winProcInfo, len(current))
			for _, info := range current {
				currentMap[info.pid] = info
			}

			c.mu.Lock()
			// Detect new processes; also re-emit when ppid was resolved 0→non-0
			// so the detection engine gets correct ppid+cmdline while still alive.
			for pid, info := range currentMap {
				known, existed := c.known[pid]
				if !existed || (known.ppid == 0 && info.ppid != 0) {
					evt := c.buildEvent(info, "create")
					select {
					case out <- evt:
					case <-ctx.Done():
						c.mu.Unlock()
						return
					default:
					}
				}
			}

			// Detect exited processes
			for pid, info := range c.known {
				if _, alive := currentMap[pid]; !alive {
					evt := collector.ProcessEvent{
						ID:          uuid.New().String(),
						Timestamp:   time.Now(),
						PID:         info.pid,
						PPID:        info.ppid,
						ProcessName: info.name,
						ImagePath:   info.path,
						Action:      "terminate",
					}
					select {
					case out <- evt:
					case <-ctx.Done():
						c.mu.Unlock()
						return
					default:
					}
				}
			}

			c.known = currentMap
			c.mu.Unlock()
		}
	}
}

// takeSnapshot enumerates all running processes via Toolhelp32.
func (c *WindowsProcessCollector) takeSnapshot() []winProcInfo {
	handle, _, _ := winProcCreateToolhelp32Snapshot.Call(winTH32CS_SNAPPROCESS, 0)
	if handle == uintptr(syscall.InvalidHandle) {
		return nil
	}
	defer windows.CloseHandle(windows.Handle(handle))

	var entry winProcessEntry32W
	entry.DwSize = uint32(unsafe.Sizeof(entry))

	var procs []winProcInfo
	ret, _, _ := winProcProcess32FirstW.Call(handle, uintptr(unsafe.Pointer(&entry)))
	for ret != 0 {
		name := syscall.UTF16ToString(entry.SzExeFile[:])
		ppid := entry.Th32ParentProcessID
		// Toolhelp32 reports ppid=0 for short-lived processes; resolve via
		// NtQueryInformationProcess while still inside the snapshot loop so
		// the process is most likely still alive.
		if ppid == 0 {
			if h, err := windows.OpenProcess(windows.PROCESS_QUERY_INFORMATION, false, entry.Th32ProcessID); err == nil {
				if p := readParentPID(h); p != 0 {
					ppid = p
				}
				windows.CloseHandle(h)
			} else if h2, err2 := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, entry.Th32ProcessID); err2 == nil {
				if p := readParentPID(h2); p != 0 {
					ppid = p
				}
				windows.CloseHandle(h2)
			}
		}
		procs = append(procs, winProcInfo{
			pid:  entry.Th32ProcessID,
			ppid: ppid,
			name: filepath.Base(name),
			path: name,
		})
		ret, _, _ = winProcProcess32NextW.Call(handle, uintptr(unsafe.Pointer(&entry)))
	}
	return procs
}

// buildEvent constructs a collector.ProcessEvent enriched with image path and hashes.
func (c *WindowsProcessCollector) buildEvent(info winProcInfo, action string) collector.ProcessEvent {
	evt := collector.ProcessEvent{
		ID:          uuid.New().String(),
		Timestamp:   time.Now(),
		PID:         info.pid,
		PPID:        info.ppid,
		ProcessName: info.name,
		ImagePath:   info.path,
		Action:      action,
	}

	// Open with full info access for image path, command line, and username
	handle, err := windows.OpenProcess(
		windows.PROCESS_QUERY_INFORMATION|windows.PROCESS_VM_READ,
		false,
		info.pid,
	)
	if err != nil {
		// Fallback to limited information (no command line)
		handle, err = windows.OpenProcess(
			windows.PROCESS_QUERY_LIMITED_INFORMATION,
			false,
			info.pid,
		)
		if err != nil {
			return evt
		}
	}
	defer windows.CloseHandle(handle)

	// Toolhelp32 returns PPID=0 for short-lived processes; NtQueryInformationProcess is authoritative.
	if evt.PPID == 0 {
		if ppid := readParentPID(handle); ppid != 0 {
			evt.PPID = ppid
		}
	}

	var buf [windows.MAX_PATH]uint16
	size := uint32(windows.MAX_PATH)
	if err := windows.QueryFullProcessImageName(handle, 0, &buf[0], &size); err == nil {
		fullPath := syscall.UTF16ToString(buf[:size])
		evt.ImagePath = fullPath
		evt.ProcessName = filepath.Base(fullPath)
		evt.Hashes = computeHashes(fullPath)
	}

	// Read command line from PEB
	evt.CommandLine = readCommandLine(handle)

	var token windows.Token
	if err := windows.OpenProcessToken(handle, windows.TOKEN_QUERY, &token); err == nil {
		defer token.Close()
		if user, err := token.GetTokenUser(); err == nil {
			if account, domain, _, err := user.User.Sid.LookupAccount(""); err == nil {
				evt.Username = domain + "\\" + account
			}
		}
		evt.IntegrityLevel = tokenIntegrityLevel(token)
		evt.LogonID = tokenLogonID(token)
	}

	// PE VERSIONINFO (renamed-binary / LOLBin Sigma rules). Best-effort from the
	// image on disk; empty when the file has no version resource.
	enrichVersionInfo(&evt)

	return evt
}
