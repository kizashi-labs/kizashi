package handlers

import (
	"testing"
	"time"

	"github.com/edr-platform/server/internal/store"
)

func TestJobToMap_RequiredFields_Present(t *testing.T) {
	now := time.Now()
	j := &store.ReportJobRow{
		ID:          "job-1",
		Type:        "alert_summary",
		Status:      "pending",
		RequestedBy: "user-abc",
		RequestedAt: now,
	}
	m := jobToMap(j)

	for _, key := range []string{"id", "type", "status", "requested_by", "requested_at"} {
		if _, ok := m[key]; !ok {
			t.Errorf("jobToMap missing key %q", key)
		}
	}
	if m["id"] != "job-1" {
		t.Errorf("id = %v, want job-1", m["id"])
	}
	if m["type"] != "alert_summary" {
		t.Errorf("type = %v, want alert_summary", m["type"])
	}
}

func TestJobToMap_CompletedAt_NilOmitted(t *testing.T) {
	j := &store.ReportJobRow{ID: "j", Type: "t", Status: "pending", RequestedBy: "u", RequestedAt: time.Now()}
	m := jobToMap(j)
	if _, ok := m["completed_at"]; ok {
		t.Error("completed_at should be absent when nil")
	}
}

func TestJobToMap_CompletedAt_PresentWhenSet(t *testing.T) {
	now := time.Now()
	j := &store.ReportJobRow{
		ID: "j", Type: "t", Status: "completed",
		RequestedBy: "u", RequestedAt: now, CompletedAt: &now,
	}
	m := jobToMap(j)
	if _, ok := m["completed_at"]; !ok {
		t.Error("completed_at should be present when set")
	}
}

func TestJobToMap_ErrorField_OmittedWhenEmpty(t *testing.T) {
	j := &store.ReportJobRow{ID: "j", Type: "t", Status: "pending", RequestedBy: "u", RequestedAt: time.Now()}
	m := jobToMap(j)
	if _, ok := m["error"]; ok {
		t.Error("error key should be absent when empty")
	}
}

func TestJobToMap_ErrorField_PresentWhenSet(t *testing.T) {
	j := &store.ReportJobRow{
		ID: "j", Type: "t", Status: "failed",
		RequestedBy: "u", RequestedAt: time.Now(), Error: "timeout",
	}
	m := jobToMap(j)
	if m["error"] != "timeout" {
		t.Errorf("error = %v, want \"timeout\"", m["error"])
	}
}

func TestJobToMap_DownloadURL_OnlyWhenCompleted(t *testing.T) {
	now := time.Now()
	// Not completed — no download_url
	j := &store.ReportJobRow{ID: "job-9", Type: "t", Status: "pending", RequestedBy: "u", RequestedAt: now}
	m := jobToMap(j)
	if _, ok := m["download_url"]; ok {
		t.Error("download_url should not appear for non-completed jobs")
	}

	// Completed — download_url should be present
	j.Status = "completed"
	j.CompletedAt = &now
	m = jobToMap(j)
	url, ok := m["download_url"]
	if !ok {
		t.Error("download_url should appear for completed jobs")
	}
	if url != "/api/v1/reports/job-9" {
		t.Errorf("download_url = %v, want /api/v1/reports/job-9", url)
	}
}
