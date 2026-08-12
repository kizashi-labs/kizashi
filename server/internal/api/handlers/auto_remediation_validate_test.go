package handlers

import "testing"

// ─── validActionTypes ────────────────────────────────────────────────────────

func TestValidActionTypes_ContainsAllExpected(t *testing.T) {
	expected := []string{
		"kill_process",
		"block_ip",
		"delete_file",
		"isolate_agent",
		"collect_forensics",
	}
	for _, action := range expected {
		if !validActionTypes[action] {
			t.Errorf("validActionTypes に %q が含まれていません", action)
		}
	}
}

func TestValidActionTypes_ExactlyFiveEntries(t *testing.T) {
	if len(validActionTypes) != 5 {
		t.Errorf("validActionTypes は5エントリのはず、got %d", len(validActionTypes))
	}
}

func TestValidActionTypes_InvalidTypesNotPresent(t *testing.T) {
	invalids := []string{"", "reboot", "shutdown", "KILL_PROCESS", "killProcess"}
	for _, action := range invalids {
		if validActionTypes[action] {
			t.Errorf("validActionTypes に %q が含まれてはいけません", action)
		}
	}
}

func TestValidActionTypes_CaseSensitive(t *testing.T) {
	if validActionTypes["Kill_Process"] || validActionTypes["BLOCK_IP"] {
		t.Error("validActionTypes は大文字小文字を区別するべきです")
	}
}
