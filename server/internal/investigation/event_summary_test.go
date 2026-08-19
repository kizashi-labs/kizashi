package investigation

import (
	"strings"
	"testing"
)

// extractRelevantFields builds the one-line summary of each event that the AI
// investigator is shown. It read names internal/ingestion does not write, so
// the model was asked to judge events it could barely see. Reproduced before
// this change, against the exact payloads normalizeEventData produces:
//
//	process  -> "pid=4242"
//	dns      -> "query=evil-c2.example.com"
//	registry -> five distinct summaries across six calls on ONE event
//	wide      -> 2522 characters, unbounded
//
// The process line is the whole of it: no binary, no user, and no command
// line — for the event type most alerts are about, and with the encoded
// PowerShell payload that is the finding itself withheld. The prompt carries up
// to fifteen events per type, so the unbounded generic branch also lets one
// wide event crowd the rest of the timeline out of the model's context.

// ingestionProcess is the payload internal/ingestion writes for a process event.
func ingestionProcess() map[string]interface{} {
	return map[string]interface{}{
		"process_name": "powershell.exe", "pid": 4242, "ppid": 1000,
		"command_line": `powershell -enc SQBFAFgAaQBuAHYAbwBrAGUA`,
		"image_path":   `C:\Windows\System32\powershell.exe`,
		"username":     "CORP\\alice", "sha256": "abc123",
		"action": "PROCESS_ACTION_START",
	}
}

// TestAProcessSummaryCarriesTheCommandLine is the core gate.
func TestAProcessSummaryCarriesTheCommandLine(t *testing.T) {
	got := extractRelevantFields("process", ingestionProcess())

	for _, want := range []string{
		`SQBFAFgAaQBuAHYAbwBrAGUA`, // the encoded command — the finding itself
		`C:\Windows\System32\powershell.exe`,
		"CORP\\alice",
		"4242",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q is missing %q. The model is asked to judge a "+
				"process it cannot see.", got, want)
		}
	}
}

// TestALongCommandLineIsTruncatedNotDropped. The old guard dropped a command
// line of 120 characters or more, so the more heavily encoded a command was —
// the reason it is being investigated — the more certain it was to be hidden.
func TestALongCommandLineIsTruncatedNotDropped(t *testing.T) {
	m := ingestionProcess()
	long := "powershell -enc " + strings.Repeat("QUJDREVG", 200) // ~1.6 KB
	m["command_line"] = long

	got := extractRelevantFields("process", m)
	if !strings.Contains(got, "cmd=") {
		t.Fatalf("a long command line was dropped entirely: %q", got)
	}
	if !strings.Contains(got, "powershell -enc QUJDREVG") {
		t.Errorf("the start of the command is missing: %q", got)
	}
	if len(got) > 600 {
		t.Errorf("summary is %d chars — a single event is crowding out the rest "+
			"of the timeline in the prompt", len(got))
	}
	if !strings.Contains(got, "truncated") {
		t.Error("the summary does not say the command line was cut short, so the " +
			"model may reason about a command that appears to end where it does not")
	}
}

// TestADNSSummaryCarriesTheAnswer. Ingestion writes the resolved addresses as
// "answers"; nothing writes "response", so the address a suspicious domain
// resolved to never reached the model.
func TestADNSSummaryCarriesTheAnswer(t *testing.T) {
	got := extractRelevantFields("dns", map[string]interface{}{
		"query": "evil-c2.example.com", "query_type": "A",
		"answers": []string{"203.0.113.9"}, "process_name": "powershell.exe",
	})
	if !strings.Contains(got, "evil-c2.example.com") {
		t.Errorf("summary %q is missing the query", got)
	}
	if !strings.Contains(got, "203.0.113.9") {
		t.Errorf("summary %q is missing the resolved address, so the model cannot "+
			"connect the domain to the outbound connection beside it", got)
	}
}

// TestAFileSummaryReadsThePathEventsCarry.
func TestAFileSummaryReadsThePathEventsCarry(t *testing.T) {
	got := extractRelevantFields("file", map[string]interface{}{
		"path": `C:\Users\alice\report.docx`, "operation": "FILE_ACTION_MODIFY",
		"process_name": "powershell.exe", "pid": 4242, "sha256": "def456",
	})
	for _, want := range []string{`C:\Users\alice\report.docx`, "FILE_ACTION_MODIFY", "def456"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q is missing %q", got, want)
		}
	}
}

// TestANetworkSummaryIsUnchanged. Network was the one branch whose names
// already matched; the shared reader must not have broken it.
func TestANetworkSummaryIsUnchanged(t *testing.T) {
	got := extractRelevantFields("network", map[string]interface{}{
		"src_ip": "10.0.0.5", "dst_ip": "203.0.113.9", "dst_port": 443,
		"protocol": "tcp", "pid": 4242, "process_name": "powershell.exe",
	})
	for _, want := range []string{"203.0.113.9:443", "tcp", "powershell.exe"} {
		if !strings.Contains(got, want) {
			t.Errorf("summary %q is missing %q", got, want)
		}
	}
}

// TestTheGenericSummaryIsDeterministic. Registry, auth, image_load and script
// all reach the generic branch, which took five keys in Go map order: the same
// event summarised twice gave different fields, so a registry persistence event
// could reach the model without its Run key on one call and without the payload
// path on the next.
func TestTheGenericSummaryIsDeterministic(t *testing.T) {
	registry := map[string]interface{}{
		"key_path":     `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"keyPath":      `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		"value_name":   "Updater",
		"value_data":   `C:\Users\alice\evil.exe`,
		"operation":    "REGISTRY_ACTION_SET",
		"pid":          4242,
		"process_name": "powershell.exe",
	}

	first := extractRelevantFields("registry", registry)
	for i := 0; i < 200; i++ {
		if got := extractRelevantFields("registry", registry); got != first {
			t.Fatalf("iteration %d differs from the first summary of the same event:\n"+
				"  %q\n  %q\nThe model's input depends on Go's map iteration order.",
				i, first, got)
		}
	}

	// And the fields that make it a persistence event have to survive.
	for _, want := range []string{
		`HKCU\Software\Microsoft\Windows\CurrentVersion\Run`,
		`C:\Users\alice\evil.exe`,
		"REGISTRY_ACTION_SET",
	} {
		if !strings.Contains(first, want) {
			t.Errorf("summary %q is missing %q — without it the event is not "+
				"recognisable as Run-key persistence", first, want)
		}
	}

	// keyPath is written only so the Sigma alias layer can find the value under a
	// Sysmon name. Emitting it too spends a slot repeating the previous field.
	if strings.Contains(first, "keyPath=") {
		t.Errorf("summary %q repeats key_path under its alias spelling", first)
	}
}

// TestTheGenericSummaryStaysBounded is the floor: a wide event must not fill
// the prompt on its own.
func TestTheGenericSummaryStaysBounded(t *testing.T) {
	wide := map[string]interface{}{}
	for _, k := range []string{"a", "b", "c", "d", "e", "f", "g", "h", "i", "j", "k", "l"} {
		wide[k] = strings.Repeat("x", 500)
	}
	got := extractRelevantFields("something_new", wide)

	if n := strings.Count(got, "="); n > genericSummaryLimit {
		t.Errorf("%d fields emitted, limit is %d", n, genericSummaryLimit)
	}
	if !strings.Contains(got, "truncated") {
		t.Error("long values are not truncated")
	}
	if len(got) > 2000 {
		t.Errorf("summary is %d chars; the prompt carries up to fifteen of these "+
			"per event type", len(got))
	}
	// Deterministic here too, and in a readable order.
	if !strings.HasPrefix(got, "a=") {
		t.Errorf("summary does not start at the first key in sorted order: %q",
			got[:minInt(40, len(got))])
	}
}

func minInt(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// TestAnEmptyValueIsNotEmitted keeps the summary readable: "op=" tells the model
// nothing and costs one of the eight slots.
func TestAnEmptyValueIsNotEmitted(t *testing.T) {
	got := extractRelevantFields("registry", map[string]interface{}{
		"key_path": "HKLM\\Run", "value_name": "", "value_data": nil,
	})
	if strings.Contains(got, "value_name=") || strings.Contains(got, "value_data=") {
		t.Errorf("summary %q emits empty fields", got)
	}
	if !strings.Contains(got, "HKLM\\Run") {
		t.Errorf("summary %q lost the key that was set", got)
	}
}
