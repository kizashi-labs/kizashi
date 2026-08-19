//go:build windows

package windows

import (
	"context"
	"crypto/md5"
	"crypto/sha1"
	"crypto/sha256"
	"fmt"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"syscall"
	"time"
	"unsafe"

	"sync/atomic"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
	"golang.org/x/sys/windows"
)

// ReadDirectoryChangesW flags
const (
	fileNotifyChangeFileName   = 0x00000001
	fileNotifyChangeDirName    = 0x00000002
	fileNotifyChangeAttributes = 0x00000004
	fileNotifyChangeSize       = 0x00000008
	fileNotifyChangeLastWrite  = 0x00000010
	fileNotifyChangeSecurity   = 0x00000100

	fileActionAdded          = 0x00000001
	fileActionRemoved        = 0x00000002
	fileActionModified       = 0x00000003
	fileActionRenamedOldName = 0x00000004
	fileActionRenamedNewName = 0x00000005
)

// fileNotifyInformation mirrors the Win32 FILE_NOTIFY_INFORMATION structure.
type fileNotifyInformation struct {
	NextEntryOffset uint32
	Action          uint32
	FileNameLength  uint32
	FileName        [1]uint16
}

// WindowsFileCollector implements collector.FileCollector using ReadDirectoryChangesW.
type WindowsFileCollector struct {
	monitored []string
	filter    *collector.PathFilter
	handles   []windows.Handle
	dropped   atomic.Uint64 // events lost to a saturated send queue
}

// NewWindowsFileCollector creates a new Windows file change collector.
func NewWindowsFileCollector() *WindowsFileCollector {
	return &WindowsFileCollector{}
}

// SetPaths configures monitored and excluded paths. Excluded paths are enforced in
// watchDirectory before an event is hashed or emitted.
func (c *WindowsFileCollector) SetPaths(monitored, excluded []string) {
	c.monitored = monitored
	c.filter = collector.NewPathFilter(excluded)
}

// Start begins watching filesystem changes using ReadDirectoryChangesW.
func (c *WindowsFileCollector) Start(ctx context.Context, out chan<- collector.FileEvent) error {
	paths := c.monitored
	if len(paths) == 0 {
		// Default high-value paths to watch on Windows
		systemRoot := os.Getenv("SystemRoot")
		if systemRoot == "" {
			systemRoot = `C:\Windows`
		}
		programData := os.Getenv("ProgramData")
		if programData == "" {
			programData = `C:\ProgramData`
		}
		paths = []string{
			systemRoot + `\System32`,
			systemRoot + `\SysWOW64`,
			programData,
			`C:\Users`,
			`C:\Temp`,
		}
	}

	for _, path := range paths {
		path := path // capture for goroutine
		go c.watchDirectory(ctx, path, out)
	}

	return nil
}

func (c *WindowsFileCollector) watchDirectory(ctx context.Context, dirPath string, out chan<- collector.FileEvent) {
	pathPtr, err := windows.UTF16PtrFromString(dirPath)
	if err != nil {
		return
	}

	handle, err := windows.CreateFile(
		pathPtr,
		windows.FILE_LIST_DIRECTORY,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OVERLAPPED,
		0,
	)
	if err != nil {
		return
	}
	defer windows.CloseHandle(handle)

	c.handles = append(c.handles, handle)

	buf := make([]byte, 65536)
	const watchFlags = fileNotifyChangeFileName | fileNotifyChangeDirName |
		fileNotifyChangeAttributes | fileNotifyChangeSize | fileNotifyChangeLastWrite

	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		var bytesReturned uint32
		err := windows.ReadDirectoryChanges(
			handle,
			&buf[0],
			uint32(len(buf)),
			true, // watch subtree
			watchFlags,
			&bytesReturned,
			nil,
			0,
		)
		if err != nil {
			// Handle may have been closed on shutdown
			return
		}

		if bytesReturned == 0 {
			continue
		}

		offset := uint32(0)
		for offset < bytesReturned {
			info := (*fileNotifyInformation)(unsafe.Pointer(&buf[offset]))

			// Decode UTF-16 filename
			nameLen := info.FileNameLength / 2
			nameSlice := (*[32767]uint16)(unsafe.Pointer(&info.FileName[0]))[:nameLen:nameLen]
			name := syscall.UTF16ToString(nameSlice)
			fullPath := filepath.Join(dirPath, name)

			// Enforce excluded_paths BEFORE hashing. The agent's own spool lives
			// under C:\ProgramData\EDRAgent\quarantine\buffer, which is inside the
			// default C:\ProgramData watch root (subtree=true) — hashing those
			// writes and emitting them re-enters the spool and amplifies without
			// bound. See collector.SelfExclusions.
			if !c.filter.Excluded(fullPath) {
				action := winActionToString(info.Action)
				evt := collector.FileEvent{
					ID:        uuid.New().String(),
					Timestamp: time.Now(),
					Path:      fullPath,
					Action:    action,
				}

				if action == "create" || action == "modify" {
					evt.Hashes = windowsHashFile(fullPath)
					if fi, err := os.Stat(fullPath); err == nil {
						evt.FileSize = fi.Size()
					}
				}

				// Never drop silently: a burst is exactly when the queue backs up, and
				// a burst is exactly what the ransomware detector needs. See EmitFile.
				collector.EmitFile(ctx, out, evt, &c.dropped)
			}

			if info.NextEntryOffset == 0 {
				break
			}
			offset += info.NextEntryOffset
		}
	}
}

// Stop cancels all directory watch handles.
func (c *WindowsFileCollector) Stop() error {
	for _, h := range c.handles {
		windows.CloseHandle(h)
	}
	c.handles = nil
	return nil
}

// windowsHashFile computes MD5/SHA1/SHA256 of a file (up to 50 MB).
func windowsHashFile(path string) collector.FileHashes {
	const maxSize = 50 * 1024 * 1024
	f, err := os.Open(filepath.Clean(path))
	if err != nil {
		// 空のハッシュと「ハッシュを取れなかった」は、イベントに載ると
		// 同じ姿になります。**サーバのハッシュ IOC 照合は、一致しなかった
		// のではなく、照合するものが無かったのに黙って通します。**
		// スキーマを変えずにできる最低限として、まず記録します。
		slog.Debug("ファイルのハッシュを取れませんでした。"+
			"このイベントはハッシュ無しで送られ、ハッシュ IOC には当たりません",
			"path", path, "error", err)
		return collector.FileHashes{}
	}
	defer f.Close()

	h1 := md5.New()
	h2 := sha1.New()
	h3 := sha256.New()
	w := io.MultiWriter(h1, h2, h3)

	if _, err := io.Copy(w, io.LimitReader(f, maxSize)); err != nil {
		slog.Debug("ファイルを読み切れませんでした。"+
			"このイベントはハッシュ無しで送られ、ハッシュ IOC には当たりません",
			"path", path, "error", err)
		return collector.FileHashes{}
	}

	return collector.FileHashes{
		MD5:    fmt.Sprintf("%x", h1.Sum(nil)),
		SHA1:   fmt.Sprintf("%x", h2.Sum(nil)),
		SHA256: fmt.Sprintf("%x", h3.Sum(nil)),
	}
}

func winActionToString(action uint32) string {
	switch action {
	case fileActionAdded:
		return "create"
	case fileActionRemoved:
		return "delete"
	case fileActionModified:
		return "modify"
	case fileActionRenamedOldName, fileActionRenamedNewName:
		return "rename"
	default:
		return "modify"
	}
}
