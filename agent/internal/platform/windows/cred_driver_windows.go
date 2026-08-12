//go:build windows && prevention

package windows

import (
	"context"
	"encoding/binary"
	"fmt"
	"time"

	syswin "golang.org/x/sys/windows"
)

var (
	ioctlSetLsassPID = ctl(0x80a) // PREV_IOCTL_BASE(0x800)+10
	ioctlSetCred     = ctl(0x80b) // +11
	ioctlGetCred     = ctl(0x80c) // +12
)

// CredDecision is one handle-open to lsass requesting PROCESS_VM_READ, pulled
// from the driver's credential-access ring (mirrors C PREV_TAMPER_DECISION).
type CredDecision struct {
	TargetPID int    // lsass PID
	SenderPID int    // the process that opened the handle
	Enforced  bool   // true = PROCESS_VM_READ was stripped
	Access    uint32 // the originally requested DesiredAccess
}

// CredClient is the user-mode client of the KizashiPrevention driver's
// credential-access detection (M3). It registers the lsass PID to watch, flips
// the enforce switch, and pulls the driver's decisions. Mirrors TamperClient.
type CredClient struct {
	h       syswin.Handle
	enforce bool
}

// NewCredClient returns a client with no open handle yet.
func NewCredClient() *CredClient { return &CredClient{h: syswin.InvalidHandle} }

// Start opens the driver control device (error if the driver is not loaded).
func (c *CredClient) Start() error {
	h, err := syswin.CreateFile(
		syswin.StringToUTF16Ptr(devicePath),
		syswin.GENERIC_READ|syswin.GENERIC_WRITE, 0, nil,
		syswin.OPEN_EXISTING, 0, 0)
	if err != nil {
		return fmt.Errorf("open %s (driver loaded?): %w", devicePath, err)
	}
	c.h = h
	return nil
}

// Close releases the device handle.
func (c *CredClient) Close() error {
	if c.h != syswin.InvalidHandle {
		err := syswin.CloseHandle(c.h)
		c.h = syswin.InvalidHandle
		return err
	}
	return nil
}

func (c *CredClient) ioctl(code uint32, in, out []byte) (uint32, error) {
	var ret uint32
	var inP, outP *byte
	if len(in) > 0 {
		inP = &in[0]
	}
	if len(out) > 0 {
		outP = &out[0]
	}
	err := syswin.DeviceIoControl(c.h, code, inP, uint32(len(in)), outP, uint32(len(out)), &ret, nil)
	return ret, err
}

// SetEnforce flips the cred enforce switch (C PREV_TAMPER_CONFIG; fail-open when
// false — VM_READ opens are recorded but not stripped).
func (c *CredClient) SetEnforce(on bool) error {
	c.enforce = on
	buf := make([]byte, 8)
	if on {
		binary.LittleEndian.PutUint32(buf[0:], 1)
	}
	_, err := c.ioctl(ioctlSetCred, buf, nil)
	return err
}

// WatchLsass registers the lsass PID to watch (C PREV_PROTECT { Pid, Mode }).
// Pass pid 0 to disable.
func (c *CredClient) WatchLsass(pid uint32, mode uint8) error {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[0:], pid)
	binary.LittleEndian.PutUint32(buf[4:], uint32(mode))
	_, err := c.ioctl(ioctlSetLsassPID, buf, nil)
	return err
}

// Run polls the driver's cred ring every 500ms and forwards each decision on out
// until ctx is cancelled (C PREV_TAMPER_DECISION = 4×u32 = 16 bytes).
func (c *CredClient) Run(ctx context.Context, out chan<- CredDecision) {
	buf := make([]byte, 16)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				n, err := c.ioctl(ioctlGetCred, nil, buf)
				if err != nil || n < 16 {
					break // ring empty (NO_MORE_ENTRIES) or short read
				}
				d := CredDecision{
					TargetPID: int(binary.LittleEndian.Uint32(buf[0:])),
					SenderPID: int(binary.LittleEndian.Uint32(buf[4:])),
					Enforced:  binary.LittleEndian.Uint32(buf[8:]) == 1,
					Access:    binary.LittleEndian.Uint32(buf[12:]),
				}
				select {
				case out <- d:
				case <-ctx.Done():
					return
				}
			}
		}
	}
}
