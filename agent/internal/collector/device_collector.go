// Package collector provides event collection components for the EDR agent.
// device_collector.go implements USB/external device monitoring via polling.
// No cgo, no WMI, no system_profiler — pure stdlib only.
// Platform-specific device enumeration is in device_collector_linux.go,
// device_collector_windows.go, and device_collector_darwin.go.
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

// DeviceInfo holds the stable identity attributes of a device.
type DeviceInfo struct {
	// ID is the platform-specific device path or identifier (e.g. "1-1.2" on Linux).
	ID        string
	Name      string
	Type      string // "usb", "storage", "input", "network"
	VendorID  string
	ProductID string
}

// DeviceCollector polls for USB/external device connections and disconnections
// by comparing the current device set against the previously known set.
// The poll interval defaults to 10 seconds (low overhead since it only reads
// /sys virtual files or drive letter existence — no disk I/O).
type DeviceCollector struct {
	sender   EventSender
	agentID  string
	interval time.Duration
	// known maps device ID → DeviceInfo from the last successful poll.
	known map[string]DeviceInfo
}

// NewDeviceCollector creates a DeviceCollector with a 10-second poll interval.
// Pass interval <= 0 to use the default.
func NewDeviceCollector(sender EventSender, agentID string, interval time.Duration) *DeviceCollector {
	if interval <= 0 {
		interval = 10 * time.Second
	}
	return &DeviceCollector{
		sender:   sender,
		agentID:  agentID,
		interval: interval,
		known:    make(map[string]DeviceInfo),
	}
}

// Run blocks until ctx is cancelled, polling for device changes every interval.
// It performs an initial seeding scan that does not emit events, then emits
// connected/disconnected events for deltas on every subsequent tick.
func (dc *DeviceCollector) Run(ctx context.Context) {
	// Seed the known map without emitting events.
	initial, err := listDevices()
	if err != nil {
		slog.Warn("[device] 初期デバイス一覧の取得に失敗しました", "error", err)
	} else {
		for _, d := range initial {
			dc.known[d.ID] = d
		}
	}

	ticker := time.NewTicker(dc.interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			dc.poll(ctx)
		}
	}
}

// poll compares the current device list with dc.known and emits events.
func (dc *DeviceCollector) poll(ctx context.Context) {
	current, err := listDevices()
	if err != nil {
		slog.Warn("[device] デバイス一覧の取得に失敗しました", "error", err)
		return
	}

	currentMap := make(map[string]DeviceInfo, len(current))
	for _, d := range current {
		currentMap[d.ID] = d
	}

	// Detect newly connected devices.
	for id, d := range currentMap {
		if _, known := dc.known[id]; !known {
			dc.emitEvent(ctx, "connected", d)
		}
	}

	// Detect disconnected devices.
	for id, d := range dc.known {
		if _, exists := currentMap[id]; !exists {
			dc.emitEvent(ctx, "disconnected", d)
		}
	}

	dc.known = currentMap
}

// deviceEventPayload is JSON-serialised into the event ID field, following the
// same "type:<uuid>:<json>" pattern used by resource_collector and fim_collector.
type deviceEventPayload struct {
	Action    string `json:"action"`
	DeviceID  string `json:"device_id"`
	Name      string `json:"name,omitempty"`
	VendorID  string `json:"vendor_id,omitempty"`
	ProductID string `json:"product_id,omitempty"`
	Type      string `json:"type,omitempty"`
}

// emitEvent constructs and sends a single device connection/disconnection event.
func (dc *DeviceCollector) emitEvent(ctx context.Context, action string, d DeviceInfo) {
	payload := deviceEventPayload{
		Action:    action,
		DeviceID:  d.ID,
		Name:      d.Name,
		VendorID:  d.VendorID,
		ProductID: d.ProductID,
		Type:      d.Type,
	}
	data, err := json.Marshal(payload)
	if err != nil {
		slog.Warn("[device] イベントのシリアライズに失敗しました", "device_id", d.ID, "error", err)
		return
	}

	eventID := fmt.Sprintf("device_event:%s:%s", newEventID(), string(data))

	evt := &v1.Event{
		Id:        eventID,
		Timestamp: timestamppb.New(time.Now()),
		Type:      v1.EventType_EVENT_TYPE_LOG,
	}

	batch := &v1.EventBatch{
		AgentId: dc.agentID,
		Events:  []*v1.Event{evt},
	}

	if err := dc.sender.SendEvents(ctx, batch); err != nil {
		slog.Warn("[device] イベント送信失敗",
			"device_id", d.ID,
			"action", action,
			"error", err,
		)
	} else {
		slog.Info("[device] デバイスイベントを検出しました",
			"device_id", d.ID,
			"name", d.Name,
			"action", action,
		)
	}
}
