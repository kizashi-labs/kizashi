package handlers

import "testing"

// ─── buildSlackTestPayload ───────────────────────────────────────────────────

func TestBuildSlackTestPayload_HasAttachments(t *testing.T) {
	got := buildSlackTestPayload()
	if _, ok := got["attachments"]; !ok {
		t.Error("buildSlackTestPayload: missing 'attachments' key")
	}
}

func TestBuildSlackTestPayload_NonEmpty(t *testing.T) {
	got := buildSlackTestPayload()
	if len(got) == 0 {
		t.Error("buildSlackTestPayload: returned empty map")
	}
}

// ─── buildTeamsTestPayload ───────────────────────────────────────────────────

func TestBuildTeamsTestPayload_HasType(t *testing.T) {
	got := buildTeamsTestPayload()
	if v, ok := got["@type"]; !ok || v != "MessageCard" {
		t.Errorf("buildTeamsTestPayload: @type = %v, want 'MessageCard'", got["@type"])
	}
}

func TestBuildTeamsTestPayload_HasSections(t *testing.T) {
	got := buildTeamsTestPayload()
	if _, ok := got["sections"]; !ok {
		t.Error("buildTeamsTestPayload: missing 'sections' key")
	}
}

// ─── buildGenericTestPayload ─────────────────────────────────────────────────

func TestBuildGenericTestPayload_HasEvent(t *testing.T) {
	got := buildGenericTestPayload()
	if v, ok := got["event"]; !ok || v != "test" {
		t.Errorf("buildGenericTestPayload: event = %v, want 'test'", got["event"])
	}
}

func TestBuildGenericTestPayload_HasSource(t *testing.T) {
	got := buildGenericTestPayload()
	if v, ok := got["source"]; !ok || v != "edr-platform" {
		t.Errorf("buildGenericTestPayload: source = %v, want 'edr-platform'", got["source"])
	}
}
