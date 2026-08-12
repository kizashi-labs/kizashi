package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"runtime"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// EventSender is the subset of transport.GRPCClient used by ResourceCollector.
// Defining it as an interface keeps the collector package free of an import cycle
// (transport already imports collector).
type EventSender interface {
	SendEvents(ctx context.Context, batch *v1.EventBatch) error
}

// ResourceCollector collects host CPU, memory, and disk usage every interval
// and ships the data to the server as an EVENT_TYPE_LOG event whose JSON payload
// is stored in the event ID field (the proto has no generic/raw event payload).
type ResourceCollector struct {
	sender   EventSender
	agentID  string
	interval time.Duration
}

// resourceSnapshot holds the raw numbers collected in one tick.
type resourceSnapshot struct {
	CPUPercent float64 `json:"cpu_pct"`
	MemMB      float64 `json:"mem_mb"`
	DiskFreeGB float64 `json:"disk_free_gb"`
}

// NewResourceCollector creates a ResourceCollector that reports every 30 seconds.
func NewResourceCollector(sender EventSender, agentID string) *ResourceCollector {
	return &ResourceCollector{
		sender:   sender,
		agentID:  agentID,
		interval: 30 * time.Second,
	}
}

// Run blocks until ctx is cancelled, collecting and sending resource metrics every interval.
func (rc *ResourceCollector) Run(ctx context.Context) {
	ticker := time.NewTicker(rc.interval)
	defer ticker.Stop()

	// Seed the CPU sampler with an initial reading so the first delta is valid.
	prevIdle, prevTotal := readCPUStat()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := rc.collect(prevIdle, prevTotal)
			// Update previous CPU counters for next delta.
			prevIdle, prevTotal = readCPUStat()

			if err := rc.send(ctx, snap); err != nil {
				slog.Warn("[resource_collector] send failed", "error", err)
			}
		}
	}
}

// collect gathers a resource snapshot.
func (rc *ResourceCollector) collect(prevIdle, prevTotal uint64) resourceSnapshot {
	snap := resourceSnapshot{}

	// ── CPU ──────────────────────────────────────────────────
	idle, total := readCPUStat()
	if prevTotal > 0 && total > prevTotal {
		deltaTotal := total - prevTotal
		deltaIdle := idle - prevIdle
		if deltaTotal > 0 {
			snap.CPUPercent = float64(deltaTotal-deltaIdle) / float64(deltaTotal) * 100.0
		}
	}

	// ── Memory (stdlib runtime.MemStats) ─────────────────────
	var ms runtime.MemStats
	runtime.ReadMemStats(&ms)
	// HeapSys is the total memory obtained from the OS for the heap.
	// For a host-level view we also add stack and other non-heap areas.
	totalBytes := ms.Sys
	snap.MemMB = float64(totalBytes) / (1024 * 1024)

	// ── Disk ─────────────────────────────────────────────────
	snap.DiskFreeGB = readDiskFreeGB()

	return snap
}

// send serialises the snapshot and ships it to the server.
func (rc *ResourceCollector) send(ctx context.Context, snap resourceSnapshot) error {
	data, err := json.Marshal(snap)
	if err != nil {
		return fmt.Errorf("marshal resource snapshot: %w", err)
	}

	// There is no generic/log payload in the v1.Event oneof, so we encode the
	// resource type and JSON into the event ID field. The server can decode
	// EVENT_TYPE_LOG events where no typed payload is set.
	eventID := fmt.Sprintf("resource_usage:%s:%s", newEventID(), string(data))

	evt := &v1.Event{
		Id:        eventID,
		Timestamp: timestamppb.New(time.Now()),
		Type:      v1.EventType_EVENT_TYPE_LOG,
	}

	batch := &v1.EventBatch{
		AgentId: rc.agentID,
		Events:  []*v1.Event{evt},
	}

	return rc.sender.SendEvents(ctx, batch)
}

// ── UUID helper ───────────────────────────────────────────────

func newEventID() string {
	return uuid.New().String()
}
