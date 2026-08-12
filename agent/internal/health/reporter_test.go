package health

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// ─── NewReporter ──────────────────────────────────────────────

func TestNewReporter_InitialValues(t *testing.T) {
	tests := []struct {
		name    string
		agentID string
		version string
	}{
		{"basic agent", "agent-001", "1.0.0"},
		{"empty id", "", "0.0.1"},
		{"long version", "agent-xyz", "1.2.3-alpha+build.999"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReporter(tc.agentID, tc.version)
			if r == nil {
				t.Fatal("NewReporter returned nil")
			}

			s := r.GetStatus()
			if s.AgentID != tc.agentID {
				t.Errorf("AgentID = %q, want %q", s.AgentID, tc.agentID)
			}
			if s.Version != tc.version {
				t.Errorf("Version = %q, want %q", s.Version, tc.version)
			}
			if s.EventsTotal != 0 {
				t.Errorf("EventsTotal = %d, want 0", s.EventsTotal)
			}
			if s.DroppedEvents != 0 {
				t.Errorf("DroppedEvents = %d, want 0", s.DroppedEvents)
			}
			if s.ErrorCount != 0 {
				t.Errorf("ErrorCount = %d, want 0", s.ErrorCount)
			}
			if s.ConnectedToServer {
				t.Error("ConnectedToServer should be false initially")
			}
		})
	}
}

// ─── RecordEvent ─────────────────────────────────────────────

func TestRecordEvent(t *testing.T) {
	tests := []struct {
		name      string
		callCount int
		wantTotal uint64
	}{
		{"single event", 1, 1},
		{"five events", 5, 5},
		{"zero events", 0, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReporter("a1", "1.0")
			for i := 0; i < tc.callCount; i++ {
				r.RecordEvent()
			}
			s := r.GetStatus()
			if s.EventsTotal != tc.wantTotal {
				t.Errorf("EventsTotal = %d, want %d", s.EventsTotal, tc.wantTotal)
			}
		})
	}
}

// ─── RecordDropped ────────────────────────────────────────────

func TestRecordDropped(t *testing.T) {
	tests := []struct {
		name        string
		callCount   int
		wantDropped uint64
	}{
		{"one drop", 1, 1},
		{"ten drops", 10, 10},
		{"no drops", 0, 0},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReporter("a1", "1.0")
			for i := 0; i < tc.callCount; i++ {
				r.RecordDropped()
			}
			s := r.GetStatus()
			if s.DroppedEvents != tc.wantDropped {
				t.Errorf("DroppedEvents = %d, want %d", s.DroppedEvents, tc.wantDropped)
			}
		})
	}
}

// ─── RecordError ─────────────────────────────────────────────

func TestRecordError(t *testing.T) {
	tests := []struct {
		name          string
		errors        []string
		wantCount     uint64
		wantLastError string
	}{
		{"single error", []string{"disk full"}, 1, "disk full"},
		{"multiple errors", []string{"err1", "err2", "err3"}, 3, "err3"},
		{"empty error msg", []string{""}, 1, ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReporter("a1", "1.0")
			for _, msg := range tc.errors {
				r.RecordError(msg)
			}
			s := r.GetStatus()
			if s.ErrorCount != tc.wantCount {
				t.Errorf("ErrorCount = %d, want %d", s.ErrorCount, tc.wantCount)
			}
			if s.LastError != tc.wantLastError {
				t.Errorf("LastError = %q, want %q", s.LastError, tc.wantLastError)
			}
		})
	}
}

// ─── SetConnected ─────────────────────────────────────────────

func TestSetConnected(t *testing.T) {
	tests := []struct {
		name      string
		connected bool
	}{
		{"connected true", true},
		{"connected false", false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReporter("a1", "1.0")
			r.SetConnected(tc.connected)
			s := r.GetStatus()
			if s.ConnectedToServer != tc.connected {
				t.Errorf("ConnectedToServer = %v, want %v", s.ConnectedToServer, tc.connected)
			}
		})
	}
}

func TestSetConnected_Toggle(t *testing.T) {
	r := NewReporter("a1", "1.0")

	r.SetConnected(true)
	if s := r.GetStatus(); !s.ConnectedToServer {
		t.Error("expected ConnectedToServer=true after first set")
	}

	r.SetConnected(false)
	if s := r.GetStatus(); s.ConnectedToServer {
		t.Error("expected ConnectedToServer=false after toggle")
	}
}

// ─── RecordHeartbeat ──────────────────────────────────────────

func TestRecordHeartbeat(t *testing.T) {
	tests := []struct {
		name string
	}{
		{"records a heartbeat timestamp"},
		{"second heartbeat updates timestamp"},
		{"initial state has zero timestamp"},
	}

	t.Run(tests[0].name, func(t *testing.T) {
		r := NewReporter("a1", "1.0")
		before := time.Now()
		r.RecordHeartbeat()
		after := time.Now()
		s := r.GetStatus()
		if s.LastHeartbeat.Before(before) || s.LastHeartbeat.After(after) {
			t.Errorf("LastHeartbeat %v not between %v and %v", s.LastHeartbeat, before, after)
		}
	})

	t.Run(tests[1].name, func(t *testing.T) {
		r := NewReporter("a1", "1.0")
		r.RecordHeartbeat()
		first := r.GetStatus().LastHeartbeat
		time.Sleep(2 * time.Millisecond)
		r.RecordHeartbeat()
		second := r.GetStatus().LastHeartbeat
		if !second.After(first) {
			t.Error("second heartbeat should be after the first")
		}
	})

	t.Run(tests[2].name, func(t *testing.T) {
		r := NewReporter("a1", "1.0")
		s := r.GetStatus()
		if !s.LastHeartbeat.IsZero() {
			t.Errorf("expected zero LastHeartbeat before any RecordHeartbeat call, got %v", s.LastHeartbeat)
		}
	})
}

// ─── SetCollectorStatus ───────────────────────────────────────

func TestSetCollectorStatus(t *testing.T) {
	tests := []struct {
		name       string
		collectors map[string]string
	}{
		{"single collector", map[string]string{"process": "running"}},
		{"multiple collectors", map[string]string{"process": "running", "network": "stopped", "file": "error"}},
		{"update existing", map[string]string{"process": "stopped"}},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := NewReporter("a1", "1.0")
			for name, status := range tc.collectors {
				r.SetCollectorStatus(name, status)
			}
			s := r.GetStatus()
			for name, wantStatus := range tc.collectors {
				if got := s.CollectorStatus[name]; got != wantStatus {
					t.Errorf("CollectorStatus[%q] = %q, want %q", name, got, wantStatus)
				}
			}
		})
	}
}

// ─── GetStatus — structural checks ───────────────────────────

func TestGetStatus_OSAndArch(t *testing.T) {
	r := NewReporter("agent-test", "2.0")
	s := r.GetStatus()

	if s.OS == "" {
		t.Error("OS should not be empty")
	}
	if s.Arch == "" {
		t.Error("Arch should not be empty")
	}
	if s.Goroutines <= 0 {
		t.Errorf("Goroutines = %d, want > 0", s.Goroutines)
	}
	if s.Timestamp.IsZero() {
		t.Error("Timestamp should not be zero")
	}
}

func TestGetStatus_UptimeIncreases(t *testing.T) {
	r := NewReporter("agent-test", "1.0")
	s1 := r.GetStatus()
	time.Sleep(10 * time.Millisecond)
	s2 := r.GetStatus()

	// Uptime should be >= 0 and should not decrease.
	if s2.UptimeSeconds < s1.UptimeSeconds {
		t.Errorf("uptime decreased: was %d, now %d", s1.UptimeSeconds, s2.UptimeSeconds)
	}
}

func TestGetStatus_MemoryMBIsPositive(t *testing.T) {
	r := NewReporter("agent-test", "1.0")
	s := r.GetStatus()
	if s.MemoryMB < 0 {
		t.Errorf("MemoryMB = %.2f, should be >= 0", s.MemoryMB)
	}
}

// ─── WriteStatusFile ─────────────────────────────────────────

func TestWriteStatusFile(t *testing.T) {
	tests := []struct {
		name    string
		agentID string
		version string
	}{
		{"basic write", "write-agent", "1.0.0"},
		{"empty agent id", "", "0.1"},
		{"with events", "evt-agent", "3.0"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "status.json")
			r := NewReporter(tc.agentID, tc.version)
			if tc.name == "with events" {
				r.RecordEvent()
				r.RecordEvent()
				r.RecordDropped()
			}

			if err := r.WriteStatusFile(path); err != nil {
				t.Fatalf("WriteStatusFile error: %v", err)
			}

			data, err := os.ReadFile(path)
			if err != nil {
				t.Fatalf("ReadFile error: %v", err)
			}

			var s Status
			if err := json.Unmarshal(data, &s); err != nil {
				t.Fatalf("Unmarshal error: %v", err)
			}

			if s.AgentID != tc.agentID {
				t.Errorf("AgentID = %q, want %q", s.AgentID, tc.agentID)
			}
			if s.Version != tc.version {
				t.Errorf("Version = %q, want %q", s.Version, tc.version)
			}
		})
	}
}

func TestWriteStatusFile_InvalidPath(t *testing.T) {
	r := NewReporter("a1", "1.0")
	err := r.WriteStatusFile("/nonexistent/deeply/nested/path/status.json")
	if err == nil {
		t.Error("expected error for invalid path, got nil")
	}
}

// ─── Concurrent safety ────────────────────────────────────────

func TestReporter_ConcurrentAccess(t *testing.T) {
	r := NewReporter("concurrent-agent", "1.0")
	done := make(chan struct{})

	// Writer goroutines
	for i := 0; i < 5; i++ {
		go func(i int) {
			for j := 0; j < 100; j++ {
				r.RecordEvent()
				r.RecordDropped()
				r.SetConnected(j%2 == 0)
				r.SetCollectorStatus("collector", "running")
			}
			done <- struct{}{}
		}(i)
	}

	// Reader goroutine
	go func() {
		for j := 0; j < 200; j++ {
			_ = r.GetStatus()
		}
		done <- struct{}{}
	}()

	for i := 0; i < 6; i++ {
		<-done
	}
	// No race condition = test passes (run with -race flag for full verification)
}
