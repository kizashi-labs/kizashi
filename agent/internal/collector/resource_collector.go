package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"github.com/google/uuid"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/edr-platform/agent/internal/hostmetrics"
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

// 測定そのものは差し替えられるようにしてあります。
//
// **実機で成功してしまうと、失敗したときの分岐を一度も通れません。**
// 変異検査で実際に露見しました —— 「測れたかを見ずに値を載せる」ように
// 壊しても、Linux では Statfs が成功するので何も変わりませんでした。
// 判定が働いていないことと、判定が要らないことが同じ姿になります。
var (
	readDiskFreeGBFn = readDiskFreeGB
	readCPUStatFn    = readCPUStat
	hostMemoryFn     = hostmetrics.Memory
)

// resourceSnapshot holds the raw numbers collected in one tick.
type resourceSnapshot struct {
	// nil は「測れなかった」です。**0 ではありません。**
	//
	// CPU の 0% は「アイドル」、ディスクの 0 GB は「満杯」で、どちらも
	// 測定値として最も強い主張になります。測っていない端末が
	// 「異常なし」や「即対応」に化けるので、欄ごと落とします。
	CPUPercent *float64 `json:"cpu_pct,omitempty"`
	// MemMB is the ENDPOINT's memory in use.
	//
	// **以前は `runtime.MemStats.Sys`（エージェント自身の Go ランタイムが
	// OS から取った量）でした。** コメントは「For a host-level view」と
	// 書いてありましたが、host-level ではありません。測れていないのでは
	// なく、別のものを測っていました。
	MemMB      *float64 `json:"mem_mb,omitempty"`
	DiskFreeGB *float64 `json:"disk_free_gb,omitempty"`
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
	prevIdle, prevTotal := readCPUStatFn()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			snap := rc.collect(prevIdle, prevTotal)
			// Update previous CPU counters for next delta.
			prevIdle, prevTotal = readCPUStatFn()

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
	idle, total := readCPUStatFn()
	if prevTotal > 0 && total > prevTotal {
		deltaTotal := total - prevTotal
		deltaIdle := idle - prevIdle
		if deltaTotal > 0 && deltaIdle <= deltaTotal {
			pct := float64(deltaTotal-deltaIdle) / float64(deltaTotal) * 100.0
			snap.CPUPercent = &pct
		}
	}

	// ── Memory (the endpoint's, not the agent's) ─────────────
	if used, _, ok := hostMemoryFn(); ok {
		snap.MemMB = &used
	}

	// ── Disk ─────────────────────────────────────────────────
	if gb, ok := readDiskFreeGBFn(); ok {
		snap.DiskFreeGB = &gb
	}

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
