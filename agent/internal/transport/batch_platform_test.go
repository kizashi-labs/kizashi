package transport

import (
	"runtime"
	"testing"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// The detection server scopes OS-specific rules using EventBatch.Platform
// (ingestion/handler.go → platformString → the RuleEngine's platform gate, #356).
// No collector ever set that field: a repo-wide search for Platform_PLATFORM_*
// under agent/ returned nothing, so every event reached the server as "unknown"
// and the gate fell through its fail-open branch — a no-op since the day it
// shipped. Observed 2026-07-02 as "Local System Accounts Discovery - Linux"
// firing on a Windows host's `net user`.
//
// The stamp lives in SendEvents, not at the dozen batch construction sites,
// because a per-site stamp is exactly what drifts: the next collector added
// would forget it and silently reopen the hole.

func TestBatchPlatformMatchesHostOS(t *testing.T) {
	got := batchPlatform()
	want := map[string]v1.Platform{
		"windows": v1.Platform_PLATFORM_WINDOWS,
		"linux":   v1.Platform_PLATFORM_LINUX,
		"darwin":  v1.Platform_PLATFORM_DARWIN,
	}[runtime.GOOS]
	if want == v1.Platform_PLATFORM_UNSPECIFIED {
		// A platform we do not name must stay UNSPECIFIED so the server fails OPEN.
		if got != v1.Platform_PLATFORM_UNSPECIFIED {
			t.Errorf("未知の GOOS %q で %v を返しました。UNSPECIFIED でなければ "+
				"サーバ側が誤った OS でルールをゲートします", runtime.GOOS, got)
		}
		return
	}
	if got != want {
		t.Errorf("batchPlatform() = %v, want %v (GOOS=%s)", got, want, runtime.GOOS)
	}
}

// A batch that already carries a platform must not be rewritten — the field is
// part of the wire format and a caller that sets it deliberately (a replayed
// batch, a test fixture) owns the value.
func TestBatchPlatformDoesNotOverwriteExplicitValue(t *testing.T) {
	batch := &v1.EventBatch{AgentId: "a", Platform: v1.Platform_PLATFORM_DARWIN}
	if batch.GetPlatform() == v1.Platform_PLATFORM_UNSPECIFIED {
		batch.Platform = batchPlatform() // mirrors SendEvents' guard
	}
	if batch.GetPlatform() != v1.Platform_PLATFORM_DARWIN {
		t.Errorf("明示指定された platform が上書きされました: %v", batch.GetPlatform())
	}
}

// The offline spool serialises batches with protojson and replays them after
// reconnect. bufferBatch is only reachable from inside SendEvents, so the stamp
// is applied before serialisation — this pins that the value survives the
// round-trip rather than being silently dropped on replay.
func TestBatchPlatformSurvivesBufferRoundTrip(t *testing.T) {
	batch := &v1.EventBatch{AgentId: "agent-1", Platform: batchPlatform()}
	raw, err := protojson.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	var back v1.EventBatch
	if err := protojson.Unmarshal(raw, &back); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if back.GetPlatform() != batch.GetPlatform() {
		t.Errorf("バッファ往復で platform が失われました: %v → %v",
			batch.GetPlatform(), back.GetPlatform())
	}
}
