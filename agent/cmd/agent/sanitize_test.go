package main

import (
	"testing"
	"unicode/utf8"

	v1 "github.com/edr-platform/proto/agent/v1"
	"google.golang.org/protobuf/proto"
)

// TestSanitizeEventStrings guards the fix for invalid-UTF8 batch poisoning:
// Linux eBPF argv / inotify filenames can carry arbitrary bytes, and proto3 string
// fields require valid UTF-8. Before the fix, one such field made the WHOLE batch
// fail to marshal (wire + disk buffer), dropping clean events and looping reconnect.
// (Surfaced by deploy/robustness/run-robustness.sh: half-open/burst markers vanished.)
func TestSanitizeEventStrings(t *testing.T) {
	bad := "cat /tmp/staged\xff\xfe\x80.bin" // invalid UTF-8 bytes mid-string

	events := []*v1.Event{
		{Type: v1.EventType_EVENT_TYPE_PROCESS, Payload: &v1.Event_Process{Process: &v1.ProcessEvent{
			ProcessName: "ca\xfft", CommandLine: bad, ImagePath: "/usr/bin/c\x80t",
			Username: "ro\xffot", EnvVars: []string{"K=\xffV", "OK=1"},
		}}},
		{Type: v1.EventType_EVENT_TYPE_FILE, Payload: &v1.Event_File{File: &v1.FileEvent{
			Path: "/home/u/staged/\xfffile", OldPath: "\x80old", ProcessName: "cp\xff",
		}}},
		{Type: v1.EventType_EVENT_TYPE_DNS, Payload: &v1.Event_Dns{Dns: &v1.DnsEvent{Query: "ex\xfffil.example"}}},
	}

	// Pre-condition: the unsanitized batch must FAIL to marshal (proves the hazard).
	if _, err := proto.Marshal(&v1.EventBatch{AgentId: "a", Events: events}); err == nil {
		t.Fatal("expected unsanitized batch to fail proto marshal (invalid UTF-8), but it succeeded")
	}

	for _, e := range events {
		sanitizeEventStrings(e)
	}

	// Every string field must now be valid UTF-8.
	p := events[0].GetProcess()
	for name, s := range map[string]string{
		"ProcessName": p.ProcessName, "CommandLine": p.CommandLine,
		"ImagePath": p.ImagePath, "Username": p.Username,
	} {
		if !utf8.ValidString(s) {
			t.Errorf("process %s still invalid UTF-8: %q", name, s)
		}
	}
	for _, ev := range p.EnvVars {
		if !utf8.ValidString(ev) {
			t.Errorf("env var still invalid UTF-8: %q", ev)
		}
	}
	// CommandLine retains the readable ASCII (only the bad bytes are dropped).
	if want := "cat /tmp/staged.bin"; p.CommandLine != want {
		t.Errorf("CommandLine = %q, want %q", p.CommandLine, want)
	}

	// Post-condition: the whole batch now marshals (the actual bug = batch-level failure).
	if _, err := proto.Marshal(&v1.EventBatch{AgentId: "a", Events: events}); err != nil {
		t.Fatalf("sanitized batch must marshal, got: %v", err)
	}
}
