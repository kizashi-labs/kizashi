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
	ioctlSetTamper  = ctl(0x805)
	ioctlProtectPID = ctl(0x806)
	ioctlGetTamper  = ctl(0x807)
)

// TamperDecision is one handle-open attempt against the protected agent process,
// pulled from the driver's tamper ring (mirrors C PREV_TAMPER_DECISION).
type TamperDecision struct {
	TargetPID int
	SenderPID int
	Enforced  bool   // true = dangerous access was stripped
	Access    uint32 // the originally requested DesiredAccess
}

// TamperClient is the user-mode client of the KizashiPrevention driver's tamper
// protection (ObRegisterCallbacks). It registers the agent PID to protect, flips
// the enforce/disarm switches, and pulls the driver's tamper decisions. The
// Windows counterpart of the Linux eBPF LSM task_kill TamperRunner.
type TamperClient struct {
	h       syswin.Handle
	enforce bool
	disarm  bool
}

// NewTamperClient returns a client with no open handle yet.
func NewTamperClient() *TamperClient { return &TamperClient{h: syswin.InvalidHandle} }

// Start opens the driver control device (error if the driver is not loaded).
func (t *TamperClient) Start() error {
	h, err := syswin.CreateFile(
		syswin.StringToUTF16Ptr(devicePath),
		syswin.GENERIC_READ|syswin.GENERIC_WRITE, 0, nil,
		syswin.OPEN_EXISTING, 0, 0)
	if err != nil {
		return fmt.Errorf("open %s (driver loaded?): %w", devicePath, err)
	}
	t.h = h
	return nil
}

// Close releases the device handle.
func (t *TamperClient) Close() error {
	if t.h != syswin.InvalidHandle {
		err := syswin.CloseHandle(t.h)
		t.h = syswin.InvalidHandle
		return err
	}
	return nil
}

func (t *TamperClient) ioctl(code uint32, in, out []byte) (uint32, error) {
	var ret uint32
	var inP, outP *byte
	if len(in) > 0 {
		inP = &in[0]
	}
	if len(out) > 0 {
		outP = &out[0]
	}
	err := syswin.DeviceIoControl(t.h, code, inP, uint32(len(in)), outP, uint32(len(out)), &ret, nil)
	return ret, err
}

// pushConfig sends the current enforce+disarm state (C PREV_TAMPER_CONFIG).
func (t *TamperClient) pushConfig() error {
	buf := make([]byte, 8)
	if t.enforce {
		binary.LittleEndian.PutUint32(buf[0:], 1)
	}
	if t.disarm {
		binary.LittleEndian.PutUint32(buf[4:], 1)
	}
	_, err := t.ioctl(ioctlSetTamper, buf, nil)
	return err
}

// SetEnforce flips the tamper enforce switch (fail-open when false).
func (t *TamperClient) SetEnforce(on bool) error { t.enforce = on; return t.pushConfig() }

// SetDisarm temporarily allows kills (operator stop/update escape hatch).
func (t *TamperClient) SetDisarm(on bool) error { t.disarm = on; return t.pushConfig() }

// ProtectPID registers the PID to protect (C PREV_PROTECT { Pid, Mode }).
func (t *TamperClient) ProtectPID(pid uint32, mode uint8) error {
	buf := make([]byte, 8)
	binary.LittleEndian.PutUint32(buf[0:], pid)
	binary.LittleEndian.PutUint32(buf[4:], uint32(mode))
	_, err := t.ioctl(ioctlProtectPID, buf, nil)
	return err
}

// Run polls the driver's tamper ring every 500ms and forwards each decision on
// out until ctx is cancelled (C PREV_TAMPER_DECISION = 4×u32 = 16 bytes).
func (t *TamperClient) Run(ctx context.Context, out chan<- TamperDecision) {
	buf := make([]byte, 16)
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			for {
				n, err := t.ioctl(ioctlGetTamper, nil, buf)
				if err != nil || n < 16 {
					break // ring empty (NO_MORE_ENTRIES) or short read
				}
				d := TamperDecision{
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
