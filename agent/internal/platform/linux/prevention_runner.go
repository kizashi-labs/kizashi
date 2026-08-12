//go:build linux && ebpf && prevention

package linux

import (
	"context"
	"fmt"

	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"github.com/cilium/ebpf/rlimit"
)

// PreventionRunner is the long-lived eBPF LSM exec-prevention service used by the
// agent (Ph2). Unlike the one-shot Ph0 PoC loader (LoadAndRunPreventionLSM), it
// separates load+attach from blocklist updates so the blocklist can be refreshed
// from server rules while the program stays attached, and exposes audit/enforce
// switching. Build/run only with `-tags "ebpf prevention"` on an lsm=bpf host.
type PreventionRunner struct {
	objs *PreventionLSMObjects
	lk   link.Link
	rd   *ringbuf.Reader
}

// NewPreventionRunner returns an unstarted runner.
func NewPreventionRunner() *PreventionRunner { return &PreventionRunner{} }

// Start loads the eBPF LSM objects, attaches to bprm_check_security, and opens
// the decision ring buffer. Returns an error on hosts without BPF LSM support
// (no CONFIG_BPF_LSM / lsm=bpf), which the caller treats as "prevention
// unavailable" and skips — the agent keeps running in observe mode.
func (p *PreventionRunner) Start() error {
	if err := rlimit.RemoveMemlock(); err != nil {
		return fmt.Errorf("remove memlock: %w", err)
	}
	objs := &PreventionLSMObjects{}
	if err := LoadPreventionLSMObjects(objs, nil); err != nil {
		return fmt.Errorf("load eBPF LSM objects: %w", err)
	}
	lk, err := link.AttachLSM(link.LSMOptions{Program: objs.CheckExec})
	if err != nil {
		objs.Close()
		return fmt.Errorf("attach lsm/bprm_check_security: %w", err)
	}
	rd, err := ringbuf.NewReader(objs.PreventionEvents)
	if err != nil {
		lk.Close()
		objs.Close()
		return fmt.Errorf("open ring buffer: %w", err)
	}
	p.objs = objs
	p.lk = lk
	p.rd = rd
	return nil
}

// SetEnforce switches between audit (false: report only, exec allowed) and
// enforce (true: exec denied with -EPERM). Ph2 keeps this false.
func (p *PreventionRunner) SetEnforce(enforce bool) error {
	v := uint8(0)
	if enforce {
		v = 1
	}
	return p.objs.PreventionConfig.Put(uint32(0), v)
}

// UpdateBlocklist replaces the blocked-path set with entries (absolute path →
// per-path mode: PathModeAudit or PathModeEnforce). Clears existing entries
// first so removed rules stop matching.
func (p *PreventionRunner) UpdateBlocklist(entries map[string]uint8) error {
	// Collect current keys, then delete (deleting during iteration is unsafe).
	var key [preventionMaxPathLen]byte
	var stale [][preventionMaxPathLen]byte
	it := p.objs.BlockedPaths.Iterate()
	for it.Next(&key, nil) {
		stale = append(stale, key) // array copy
	}
	if err := it.Err(); err != nil {
		return fmt.Errorf("iterate blocklist: %w", err)
	}
	for _, k := range stale {
		_ = p.objs.BlockedPaths.Delete(k)
	}
	for pth, mode := range entries {
		var k [preventionMaxPathLen]byte
		copy(k[:], pth) // truncates at 256, rest stays zero (matches bpf key layout)
		if err := p.objs.BlockedPaths.Put(k, mode); err != nil {
			return fmt.Errorf("put blocklist entry %q: %w", pth, err)
		}
	}
	return nil
}

// Run streams decisions to out until ctx is cancelled, then returns. Close must
// still be called to release the link and objects.
func (p *PreventionRunner) Run(ctx context.Context, out chan<- PreventionDecision) {
	go func() {
		<-ctx.Done()
		p.rd.Close()
	}()
	for {
		record, err := p.rd.Read()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		dec, ok := parsePreventionEvent(record.RawSample)
		if !ok {
			continue
		}
		select {
		case out <- dec:
		case <-ctx.Done():
			return
		}
	}
}

// Close detaches the LSM program and releases resources.
func (p *PreventionRunner) Close() {
	if p.rd != nil {
		p.rd.Close()
	}
	if p.lk != nil {
		p.lk.Close()
	}
	if p.objs != nil {
		p.objs.Close()
	}
}
