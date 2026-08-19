// Package collector provides event collection components for the EDR agent.
// process_stats_collector.go collects per-process CPU and memory usage every 30s
// and ships a snapshot to the server as an EVENT_TYPE_LOG event with the prefix
// "process_stats:<uuid>:<json>" — the same encoding pattern used by resource_collector.go.
package collector

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// ProcessStatEntry holds stats for one running process.
//
// **MemMB がポインタなのは、測れなかったことを表すためです。**
// `mem_mb` が JSON に出ないことが「測っていない」の表現で、0.0 は
// 「常駐メモリが無い」という測定値です。画面はすでに欠けた値を `—`
// として出します。
type ProcessStatEntry struct {
	PID    int      `json:"pid"`
	Name   string   `json:"name"`
	CPUPct float64  `json:"cpu_pct"`
	MemMB  *float64 `json:"mem_mb,omitempty"`
}

// ProcessStatsCollector periodically collects per-process CPU and memory stats.
// It maintains delta state between ticks to compute accurate CPU percentages.
type ProcessStatsCollector struct {
	sender     EventSender
	agentID    string
	interval   time.Duration
	prevCPUMap map[int]uint64 // pid → previous total cpu jiffies
	prevTotal  uint64         // previous total system cpu jiffies
}

// NewProcessStatsCollector creates a collector that reports every 30 seconds.
func NewProcessStatsCollector(sender EventSender, agentID string) *ProcessStatsCollector {
	return &ProcessStatsCollector{
		sender:     sender,
		agentID:    agentID,
		interval:   30 * time.Second,
		prevCPUMap: make(map[int]uint64),
	}
}

// Run blocks until ctx is cancelled, collecting and sending snapshots every interval.
func (c *ProcessStatsCollector) Run(ctx context.Context) {
	ticker := time.NewTicker(c.interval)
	defer ticker.Stop()

	// Seed initial CPU state so the first delta is valid.
	rawStats, totalCPU, err := readProcessStatsRaw()
	if err == nil {
		c.prevTotal = totalCPU
		for _, s := range rawStats {
			c.prevCPUMap[s.pid] = s.cpuTotal
		}
	}

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			entries := c.collect()
			if len(entries) == 0 {
				continue
			}
			if err := c.send(ctx, entries); err != nil {
				slog.Warn("[process_stats] 送信失敗", "error", err)
			}
		}
	}
}

// collect reads current process stats and computes CPU% using stored deltas.
func (c *ProcessStatsCollector) collect() []ProcessStatEntry {
	rawStats, totalCPU, err := readProcessStatsRaw()
	if err != nil {
		slog.Warn("[process_stats] 収集失敗", "error", err)
		return nil
	}

	deltaTotal := totalCPU - c.prevTotal
	if deltaTotal == 0 {
		deltaTotal = 1
	}

	entries := make([]ProcessStatEntry, 0, len(rawStats))
	newPrevMap := make(map[int]uint64, len(rawStats))

	for _, s := range rawStats {
		prevCPU := c.prevCPUMap[s.pid]
		var deltaCPU uint64
		if s.cpuTotal >= prevCPU {
			deltaCPU = s.cpuTotal - prevCPU
		}
		cpuPct := float64(deltaCPU) / float64(deltaTotal) * 100.0
		if cpuPct > 100.0 {
			cpuPct = 100.0
		}
		newPrevMap[s.pid] = s.cpuTotal
		entries = append(entries, ProcessStatEntry{
			PID:    s.pid,
			Name:   s.name,
			CPUPct: cpuPct,
			MemMB:  memMB(s.memKB, s.mem),
		})
	}

	c.prevCPUMap = newPrevMap
	c.prevTotal = totalCPU
	return entries
}

// send serialises entries and ships them to the server.
func (c *ProcessStatsCollector) send(ctx context.Context, entries []ProcessStatEntry) error {
	data, err := json.Marshal(entries)
	if err != nil {
		return fmt.Errorf("marshal process stats: %w", err)
	}
	eventID := fmt.Sprintf("process_stats:%s:%s", newEventID(), string(data))
	evt := &v1.Event{
		Id:        eventID,
		Timestamp: timestamppb.New(time.Now()),
		Type:      v1.EventType_EVENT_TYPE_LOG,
	}
	batch := &v1.EventBatch{
		AgentId: c.agentID,
		Events:  []*v1.Event{evt},
	}
	return c.sender.SendEvents(ctx, batch)
}
