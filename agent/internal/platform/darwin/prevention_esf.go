//go:build darwin && esf && prevention && cgo

// macOS pre-execution prevention via Apple's Endpoint Security Framework (ESF)
// AUTH_EXEC — the macOS counterpart of the Linux eBPF LSM and Windows driver
// prevention paths. For each execve the kernel asks AUTH_EXEC; we DENY blocklisted
// images (enforce) or ALLOW and record (audit / fail-open). Same audit→enforce /
// fail-open / per-path-mode model.
//
// SCAFFOLD: builds only on macOS (CGO_ENABLED=1, ESF SDK) and runs only with the
// com.apple.developer.endpoint-security.client entitlement (Apple approval — see
// docs/macOS-ESF-entitlement申請キット.md). Gated behind the `prevention` tag so the
// default build is unaffected. NOT compiled/verified on non-macOS.
package darwin

/*
#cgo LDFLAGS: -framework EndpointSecurity -framework Foundation
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdlib.h>
// <bsm/libbsm.h> declares audit_token_to_pid(); without it modern clang
// (C99+) rejects the implicit declaration as an error, breaking the esf build.
#include <bsm/libbsm.h>

// esfAuthExecDecision is implemented in Go (//export): returns 1 to DENY, 0 to
// ALLOW. Its prototype must match cgo's _cgo_export.h — path is char*, not
// const char*, or clang reports "conflicting types". We cast away const at the
// call site (Go only reads it via C.GoString).
extern int esfAuthExecDecision(char* path, uint32_t pid);

// startAuthESFClient builds the AUTH_EXEC ES client in C. The handler is an
// Objective-C block (es_handler_block_t), which cgo cannot represent, so it must
// not cross the Go/C boundary; we create the client here and return only the
// es_client_t*. es_respond_auth_result must be called for every AUTH message.
static es_new_client_result_t startAuthESFClient(es_client_t **client) {
    return es_new_client(client, ^(es_client_t *c, const es_message_t *message) {
        if (!message) return;
        if (message->event_type == ES_EVENT_TYPE_AUTH_EXEC) {
            const es_process_t *proc = message->event.exec.target;
            char *path = (char*)((proc && proc->executable) ? proc->executable->path.data : "");
            uint32_t pid = proc ? audit_token_to_pid(proc->audit_token) : 0;
            int deny = esfAuthExecDecision(path, pid);
            es_auth_result_t r = deny ? ES_AUTH_RESULT_DENY : ES_AUTH_RESULT_ALLOW;
            es_respond_auth_result(c, message, r, false);
        }
        es_release_message(message);
    });
}
*/
import "C"

import (
	"context"
	"strings"
	"sync"
)

// Per-path mode (mirrors Linux/Windows PathModeAudit/Enforce).
const (
	PathModeAudit   uint8 = 1
	PathModeEnforce uint8 = 2
)

// PreventionDecision mirrors the Linux/Windows decision shape.
type PreventionDecision struct {
	PID      int
	Filename string
	Enforced bool
}

// PreventionRunner is the macOS ESF AUTH_EXEC prevention client.
type PreventionRunner struct {
	client *C.es_client_t

	mu        sync.RWMutex
	blocklist map[string]uint8 // path (suffix) → mode
	enforce   bool

	decisions chan PreventionDecision
}

// activePreventionRunner lets the C AUTH callback reach the runner (the block
// can't capture Go state directly). One prevention client per process.
var activePreventionRunner *PreventionRunner

// NewPreventionRunner returns a runner with an empty blocklist (fail-open).
func NewPreventionRunner() *PreventionRunner {
	return &PreventionRunner{
		blocklist: map[string]uint8{},
		decisions: make(chan PreventionDecision, 64),
	}
}

// Start creates the ESF client and subscribes to AUTH_EXEC. Returns an error if
// the entitlement is missing / the binary is unsigned (agent then stays observe).
func (r *PreventionRunner) Start() error {
	var client *C.es_client_t
	res := C.startAuthESFClient(&client)
	if res != C.ES_NEW_CLIENT_RESULT_SUCCESS {
		return &esfError{code: int(res)}
	}
	r.client = client
	activePreventionRunner = r
	events := []C.es_event_type_t{C.ES_EVENT_TYPE_AUTH_EXEC}
	C.es_subscribe(client, &events[0], C.uint32_t(len(events)))
	return nil
}

// Close tears down the ESF client.
func (r *PreventionRunner) Close() error {
	if r.client != nil {
		C.es_delete_client(r.client)
		r.client = nil
	}
	activePreventionRunner = nil
	return nil
}

// SetEnforce flips the global enforce switch (fail-open when false).
func (r *PreventionRunner) SetEnforce(on bool) error {
	r.mu.Lock()
	r.enforce = on
	r.mu.Unlock()
	return nil
}

// UpdateBlocklist replaces the blocklist (path suffix → mode).
func (r *PreventionRunner) UpdateBlocklist(entries map[string]uint8) error {
	cp := make(map[string]uint8, len(entries))
	for k, v := range entries {
		cp[k] = v
	}
	r.mu.Lock()
	r.blocklist = cp
	r.mu.Unlock()
	return nil
}

// Run forwards queued decisions on out until ctx is cancelled.
func (r *PreventionRunner) Run(ctx context.Context, out chan<- PreventionDecision) {
	for {
		select {
		case <-ctx.Done():
			return
		case d := <-r.decisions:
			select {
			case out <- d:
			case <-ctx.Done():
				return
			}
		}
	}
}

// decide checks path against the blocklist (case-insensitive suffix); returns
// (deny, matched). deny only when enforcing and the rule is enforce-eligible.
func (r *PreventionRunner) decide(path string) (deny, matched bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	lower := strings.ToLower(path)
	for suffix, mode := range r.blocklist {
		if strings.HasSuffix(lower, strings.ToLower(suffix)) {
			return r.enforce && mode == PathModeEnforce, true
		}
	}
	return false, false
}

//export esfAuthExecDecision
func esfAuthExecDecision(path *C.char, pid C.uint32_t) C.int {
	r := activePreventionRunner
	if r == nil {
		return 0 // fail-open: allow if no runner
	}
	p := C.GoString(path)
	deny, matched := r.decide(p)
	if matched {
		select {
		case r.decisions <- PreventionDecision{PID: int(pid), Filename: p, Enforced: deny}:
		default: // drop on overflow
		}
	}
	if deny {
		return 1
	}
	return 0
}
