package xdr

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestXDREngineIngestAndCorrelate(t *testing.T) {
	engine := NewEngine(nil)

	now := time.Now()
	// Add endpoint event
	engine.IngestEvent(XDREvent{
		ID: "e1", Domain: DomainEndpoint, Type: "process",
		Timestamp: now, Severity: 85,
		Data: map[string]interface{}{"process_name": "mimikatz.exe"},
	})
	// Add identity event
	engine.IngestEvent(XDREvent{
		ID: "e2", Domain: DomainIdentity, Type: "auth_anomaly",
		Timestamp: now, Severity: 70,
		Data: map[string]interface{}{"user": "admin"},
	})

	incidents, err := engine.Correlate(context.Background())
	if err != nil {
		t.Fatalf("Correlate failed: %v", err)
	}

	found := false
	for _, inc := range incidents {
		if inc.Title == "クロスドメイン横断的移動" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected lateral movement incident to be detected")
	}
}

func TestXDREngineStats(t *testing.T) {
	engine := NewEngine(nil)
	engine.IngestEvent(XDREvent{
		ID: "e1", Domain: DomainEndpoint, Type: "process",
		Timestamp: time.Now(), Severity: 50,
	})
	stats := engine.Stats()
	if stats["buffered_events"].(int) != 1 {
		t.Errorf("expected 1 buffered event, got %v", stats["buffered_events"])
	}
}

func TestXDREngineGetRecentEvents(t *testing.T) {
	engine := NewEngine(nil)
	for i := 0; i < 5; i++ {
		engine.IngestEvent(XDREvent{
			ID:        fmt.Sprintf("e%d", i),
			Domain:    DomainNetwork,
			Timestamp: time.Now(),
		})
	}
	events := engine.GetRecentEvents(3)
	if len(events) != 3 {
		t.Errorf("expected 3 events, got %d", len(events))
	}
}
