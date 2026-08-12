// Package health provides health status reporting for the EDR agent.
package health

import (
	"context"
	"encoding/json"
	"log/slog"
	"os"
	"runtime"
	"sync"
	"sync/atomic"
	"time"
)

// Status represents the current health state of the agent.
type Status struct {
	AgentID           string            `json:"agent_id"`
	Hostname          string            `json:"hostname"`
	OS                string            `json:"os"`
	Arch              string            `json:"arch"`
	Version           string            `json:"version"`
	UptimeSeconds     int64             `json:"uptime_seconds"`
	EventsTotal       uint64            `json:"events_total"`
	EventsPerMin      float64           `json:"events_per_min"`
	DroppedEvents     uint64            `json:"dropped_events"`
	ConnectedToServer bool              `json:"connected_to_server"`
	LastHeartbeat     time.Time         `json:"last_heartbeat"`
	CollectorStatus   map[string]string `json:"collector_status"`
	MemoryMB          float64           `json:"memory_mb"`
	Goroutines        int               `json:"goroutines"`
	ErrorCount        uint64            `json:"error_count"`
	LastError         string            `json:"last_error"`
	Timestamp         time.Time         `json:"timestamp"`
}

// Reporter collects and reports agent health metrics.
type Reporter struct {
	mu              sync.RWMutex
	agentID         string
	hostname        string
	version         string
	startTime       time.Time
	eventsTotal     atomic.Uint64
	droppedEvents   atomic.Uint64
	errorCount      atomic.Uint64
	lastError       string
	connectedToSrv  atomic.Bool
	lastHeartbeat   atomic.Value // stores time.Time
	collectorStatus map[string]string
	// Rate tracking
	lastEventCount uint64
	lastRateCheck  time.Time
	eventsPerMin   float64
}

// NewReporter creates a new health Reporter.
func NewReporter(agentID, version string) *Reporter {
	hostname, _ := os.Hostname()
	r := &Reporter{
		agentID:         agentID,
		hostname:        hostname,
		version:         version,
		startTime:       time.Now(),
		collectorStatus: make(map[string]string),
		lastRateCheck:   time.Now(),
	}
	r.lastHeartbeat.Store(time.Time{})
	return r
}

// RecordEvent increments the event counter.
func (r *Reporter) RecordEvent() {
	r.eventsTotal.Add(1)
}

// RecordDropped increments the dropped event counter.
func (r *Reporter) RecordDropped() {
	r.droppedEvents.Add(1)
}

// RecordError records an error.
func (r *Reporter) RecordError(msg string) {
	r.errorCount.Add(1)
	r.mu.Lock()
	r.lastError = msg
	r.mu.Unlock()
	slog.Error("agent error recorded", "msg", msg)
}

// SetConnected updates the server connection status.
func (r *Reporter) SetConnected(connected bool) {
	r.connectedToSrv.Store(connected)
}

// RecordHeartbeat records a successful heartbeat.
func (r *Reporter) RecordHeartbeat() {
	r.lastHeartbeat.Store(time.Now())
}

// SetCollectorStatus updates the status of a named collector.
func (r *Reporter) SetCollectorStatus(name, status string) {
	r.mu.Lock()
	r.collectorStatus[name] = status
	r.mu.Unlock()
}

// GetStatus returns the current health status snapshot.
func (r *Reporter) GetStatus() Status {
	r.mu.RLock()
	collectorCopy := make(map[string]string, len(r.collectorStatus))
	for k, v := range r.collectorStatus {
		collectorCopy[k] = v
	}
	lastErr := r.lastError
	r.mu.RUnlock()

	// Compute events per minute
	now := time.Now()
	total := r.eventsTotal.Load()
	elapsed := now.Sub(r.lastRateCheck).Minutes()
	if elapsed >= 1 {
		r.eventsPerMin = float64(total-r.lastEventCount) / elapsed
		r.lastEventCount = total
		r.lastRateCheck = now
	}

	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)

	lastHB, _ := r.lastHeartbeat.Load().(time.Time)

	return Status{
		AgentID:           r.agentID,
		Hostname:          r.hostname,
		OS:                runtime.GOOS,
		Arch:              runtime.GOARCH,
		Version:           r.version,
		UptimeSeconds:     int64(time.Since(r.startTime).Seconds()),
		EventsTotal:       total,
		EventsPerMin:      r.eventsPerMin,
		DroppedEvents:     r.droppedEvents.Load(),
		ConnectedToServer: r.connectedToSrv.Load(),
		LastHeartbeat:     lastHB,
		CollectorStatus:   collectorCopy,
		MemoryMB:          float64(memStats.HeapAlloc) / 1024 / 1024,
		Goroutines:        runtime.NumGoroutine(),
		ErrorCount:        r.errorCount.Load(),
		LastError:         lastErr,
		Timestamp:         now,
	}
}

// LogStatus logs the current health status at Info level.
func (r *Reporter) LogStatus() {
	s := r.GetStatus()
	slog.Info("agent health",
		"agent_id", s.AgentID,
		"uptime_s", s.UptimeSeconds,
		"events_total", s.EventsTotal,
		"events_per_min", s.EventsPerMin,
		"dropped", s.DroppedEvents,
		"connected", s.ConnectedToServer,
		"memory_mb", s.MemoryMB,
		"goroutines", s.Goroutines,
		"errors", s.ErrorCount,
	)
}

// WriteStatusFile writes the current status as JSON to a file.
func (r *Reporter) WriteStatusFile(path string) error {
	s := r.GetStatus()
	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0644)
}

// RunPeriodic starts a goroutine that logs health status at the given interval.
func (r *Reporter) RunPeriodic(ctx context.Context, interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.LogStatus()
		}
	}
}
