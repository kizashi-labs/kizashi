//go:build windows

package windows

import (
	"context"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
	"golang.org/x/sys/windows"
	"golang.org/x/sys/windows/registry"
)

var (
	modAdvapi32                 = windows.NewLazySystemDLL("advapi32.dll")
	procRegNotifyChangeKeyValue = modAdvapi32.NewProc("RegNotifyChangeKeyValue")
)

const (
	regNotifyChangeName    = 0x00000001
	regNotifyChangeLastSet = 0x00000004
)

// sensitiveRegKeys are registry paths commonly targeted by malware.
var sensitiveRegKeys = []struct {
	root registry.Key
	path string
	name string
}{
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKLM Run"},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce`, "HKLM RunOnce"},
	{registry.CURRENT_USER, `SOFTWARE\Microsoft\Windows\CurrentVersion\Run`, "HKCU Run"},
	{registry.LOCAL_MACHINE, `SYSTEM\CurrentControlSet\Services`, "Services"},
	{registry.LOCAL_MACHINE, `SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon`, "Winlogon"},
}

// WindowsRegistryCollector monitors sensitive registry keys using RegNotifyChangeKeyValue.
type WindowsRegistryCollector struct {
	cancel context.CancelFunc
}

// NewWindowsRegistryCollector creates a new registry change collector.
func NewWindowsRegistryCollector() *WindowsRegistryCollector {
	return &WindowsRegistryCollector{}
}

// Start begins monitoring all sensitive registry keys and emits events to out.
func (c *WindowsRegistryCollector) Start(ctx context.Context, out chan<- collector.RegistryEvent) error {
	ctx, c.cancel = context.WithCancel(ctx)
	for _, k := range sensitiveRegKeys {
		go c.watch(ctx, k.root, k.path, k.name, out)
	}
	return nil
}

// Stop cancels all watchers.
func (c *WindowsRegistryCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	return nil
}

// watch monitors a single registry key using RegNotifyChangeKeyValue with an event handle.
func (c *WindowsRegistryCollector) watch(ctx context.Context, root registry.Key, path, displayName string, out chan<- collector.RegistryEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
		}

		key, err := registry.OpenKey(root, path, registry.NOTIFY|registry.QUERY_VALUE|registry.ENUMERATE_SUB_KEYS)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
			}
			continue
		}

		// Create a manual-reset event for the async notification
		// CreateEvent(secAttrs, manualReset uint32, initialState uint32, name *uint16)
		notifyEvent, err := windows.CreateEvent(nil, 1, 0, nil)
		if err != nil {
			key.Close()
			select {
			case <-ctx.Done():
				return
			case <-time.After(time.Second):
			}
			continue
		}

		// Register for change notifications asynchronously
		procRegNotifyChangeKeyValue.Call(
			uintptr(key),
			1, // watchSubtree = true
			uintptr(regNotifyChangeName|regNotifyChangeLastSet),
			uintptr(notifyEvent),
			1, // asynchronous = true
		)

		// Wait for the notification event or context cancellation
		handles := []windows.Handle{notifyEvent}
		result, waitErr := windows.WaitForMultipleObjects(handles, false, windows.INFINITE)

		windows.CloseHandle(notifyEvent)
		key.Close()

		if waitErr != nil || result != windows.WAIT_OBJECT_0 {
			select {
			case <-ctx.Done():
				return
			default:
			}
			continue
		}

		// A change was detected - emit an event
		evt := collector.RegistryEvent{
			ID:        uuid.New().String(),
			Timestamp: time.Now(),
			KeyPath:   regRootName(root) + `\` + path,
			Action:    "modify",
		}

		select {
		case out <- evt:
		case <-ctx.Done():
			return
		default:
		}
	}
}

// regRootName returns a human-readable name for a registry root key.
func regRootName(root registry.Key) string {
	switch root {
	case registry.LOCAL_MACHINE:
		return `HKEY_LOCAL_MACHINE`
	case registry.CURRENT_USER:
		return `HKEY_CURRENT_USER`
	case registry.CLASSES_ROOT:
		return `HKEY_CLASSES_ROOT`
	case registry.USERS:
		return `HKEY_USERS`
	default:
		return `HKEY_UNKNOWN`
	}
}
