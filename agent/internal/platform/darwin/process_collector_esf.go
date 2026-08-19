//go:build darwin && esf && cgo

// Package darwin provides macOS-specific process monitoring using Apple's
// Endpoint Security Framework (ESF).
//
// # Prerequisites
//
// ESF requires:
//  1. CGo enabled (CGO_ENABLED=1)
//  2. Apple entitlement: com.apple.developer.endpoint-security.client
//  3. Application signed with the entitlement (requires Apple approval)
//  4. macOS 10.15 (Catalina) or later
//
// # Build
//
//	CGO_ENABLED=1 GOOS=darwin go build -tags esf ./cmd/agent
//
// # Entitlement setup
//
//	codesign --entitlements agent/deploy/entitlements.plist --sign "Developer ID" agent
//
// # ESF API reference
//
// https://developer.apple.com/documentation/endpointsecurity
package darwin

/*
// EndpointSecurity は framework ではなくライブラリとして提供される
// (libEndpointSecurity.tbd)。`-framework EndpointSecurity` は
// `ld: framework 'EndpointSecurity' not found` で落ちる——Xcode 15.4 の
// MacOSX.sdk には EndpointSecurity.framework ディレクトリ自体が無く、
// ヘッダは usr/include/EndpointSecurity/ にある。Apple のドキュメントも
// libEndpointSecurity.tbd へのリンクを指示している。
// ヘッダは usr/include/EndpointSecurity/ にある。
// audit_token_to_pid() の実体は libbsm にあるので -lbsm も要る
// (ヘッダだけ include してあり、コンパイルは通ってリンクで落ちていた)。
#cgo LDFLAGS: -lEndpointSecurity -lbsm -framework Foundation
#include <EndpointSecurity/EndpointSecurity.h>
#include <stdlib.h>
// <bsm/libbsm.h> declares audit_token_to_pid(); without it modern clang
// (C99+) rejects the implicit declaration as an error, breaking the esf build.
#include <bsm/libbsm.h>

// esfProcessEventCallback is implemented in Go (//export). Its prototype must
// match the one cgo emits in _cgo_export.h — the string params are char*, not
// const char*, or clang reports "conflicting types for 'esfProcessEventCallback'".
// We cast away const at the call sites below (Go only reads them via C.GoString).
extern void esfProcessEventCallback(uint32_t pid, uint32_t ppid,
    char* name, char* path, char* username, int isCreate);

// startESFClient builds the ES client in C. The Endpoint Security handler is an
// Objective-C block (es_handler_block_t) — a type cgo cannot represent, so it
// must never cross the Go/C boundary (passing it back via unsafe.Pointer is what
// produced the "incompatible type 'es_handler_block_t'" build error). We create
// the client here and hand Go only the plain es_client_t*.
static es_new_client_result_t startESFClient(es_client_t **client) {
    return es_new_client(client, ^(es_client_t *c, const es_message_t *message) {
        if (!message) return;
        switch (message->event_type) {
        case ES_EVENT_TYPE_NOTIFY_EXEC: {
            const es_process_t *proc = message->event.exec.target;
            if (!proc) break;
            uint32_t pid = audit_token_to_pid(proc->audit_token);
            uint32_t ppid = proc->ppid;
            char *path = (char*)proc->executable->path.data;
            esfProcessEventCallback(pid, ppid, path, path, (char*)"", 1);
            break;
        }
        case ES_EVENT_TYPE_NOTIFY_EXIT: {
            const es_process_t *proc = message->process;
            if (!proc) break;
            uint32_t pid = audit_token_to_pid(proc->audit_token);
            uint32_t ppid = proc->ppid;
            char *name = (char*)proc->executable->path.data;
            esfProcessEventCallback(pid, ppid, name, (char*)"", (char*)"", 0);
            break;
        }
        default: break;
        }
        es_release_message(message);
    });
}
*/
import "C"

import (
	"context"
	"sync"
	"time"

	"github.com/edr-platform/agent/internal/collector"
	"github.com/google/uuid"
)

// esfEventChan is the channel used by the C callback to deliver events.
var esfEventChan chan esfRawEvent
var esfOnce sync.Once

type esfRawEvent struct {
	pid      uint32
	ppid     uint32
	name     string
	path     string
	username string
	isCreate bool
}

//export esfProcessEventCallback
func esfProcessEventCallback(pid, ppid C.uint32_t, name, path, username *C.char, isCreate C.int) {
	evt := esfRawEvent{
		pid:      uint32(pid),
		ppid:     uint32(ppid),
		name:     C.GoString(name),
		path:     C.GoString(path),
		username: C.GoString(username),
		isCreate: isCreate != 0,
	}
	select {
	case esfEventChan <- evt:
	default: // バッファフル時はドロップ
	}
}

// ESFProcessCollector monitors processes on macOS using Endpoint Security Framework.
// This implementation requires Apple's ESF entitlement.
type ESFProcessCollector struct {
	client *C.es_client_t
	cancel context.CancelFunc
}

// DarwinProcessCollector is an alias so the rest of the agent code can use
// the same type name regardless of build tag.
type DarwinProcessCollector = ESFProcessCollector

func NewDarwinProcessCollector() *ESFProcessCollector {
	return &ESFProcessCollector{}
}

func (c *ESFProcessCollector) Start(ctx context.Context, out chan<- collector.ProcessEvent) error {
	esfOnce.Do(func() {
		esfEventChan = make(chan esfRawEvent, 4096)
	})

	// ESクライアントを作成（ハンドラのblockはC側で完結させGoへ渡さない）
	var client *C.es_client_t
	result := C.startESFClient(&client)
	if result != C.ES_NEW_CLIENT_RESULT_SUCCESS {
		return &esfError{code: int(result)}
	}
	c.client = client

	// 監視するイベントを登録
	events := []C.es_event_type_t{
		C.ES_EVENT_TYPE_NOTIFY_EXEC,
		C.ES_EVENT_TYPE_NOTIFY_EXIT,
	}
	C.es_subscribe(client, &events[0], C.uint32_t(len(events)))

	ctx, c.cancel = context.WithCancel(ctx)
	go c.forward(ctx, out)
	return nil
}

func (c *ESFProcessCollector) Stop() error {
	if c.cancel != nil {
		c.cancel()
	}
	if c.client != nil {
		C.es_delete_client(c.client)
		c.client = nil
	}
	return nil
}

func (c *ESFProcessCollector) forward(ctx context.Context, out chan<- collector.ProcessEvent) {
	for {
		select {
		case <-ctx.Done():
			return
		case raw := <-esfEventChan:
			action := "terminate"
			if raw.isCreate {
				action = "create"
			}
			hashes := collector.FileHashes{}
			if raw.isCreate && raw.path != "" {
				hashes = hashBinary(raw.path)
			}
			evt := collector.ProcessEvent{
				ID:          uuid.New().String(),
				Timestamp:   time.Now(),
				PID:         raw.pid,
				PPID:        raw.ppid,
				ProcessName: raw.name,
				ImagePath:   raw.path,
				Username:    raw.username,
				Hashes:      hashes,
				Action:      action,
			}
			select {
			case out <- evt:
			case <-ctx.Done():
				return
			}
		}
	}
}

type esfError struct{ code int }

func (e *esfError) Error() string {
	switch e.code {
	case 1:
		return "ESF: entitlement が付与されていません (com.apple.developer.endpoint-security.client)"
	case 2:
		return "ESF: コード署名が無効です"
	default:
		return "ESF: クライアント作成失敗 (code=" + string(rune('0'+e.code)) + ")"
	}
}
