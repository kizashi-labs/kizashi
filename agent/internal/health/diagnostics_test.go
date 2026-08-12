package health

import (
	"context"
	"runtime"
	"testing"
)

// ─── DiagnosticResult structure ───────────────────────────────

func TestDiagnosticResult_Fields(t *testing.T) {
	dr := DiagnosticResult{
		Name:    "test_check",
		OK:      true,
		Message: "all good",
		Latency: "5ms",
	}

	if dr.Name != "test_check" {
		t.Errorf("Name = %q, want %q", dr.Name, "test_check")
	}
	if !dr.OK {
		t.Error("OK should be true")
	}
	if dr.Message != "all good" {
		t.Errorf("Message = %q, want %q", dr.Message, "all good")
	}
	if dr.Latency != "5ms" {
		t.Errorf("Latency = %q, want %q", dr.Latency, "5ms")
	}
}

// ─── RunDiagnostics — always-present checks ───────────────────

func TestRunDiagnostics_AlwaysReturnsResults(t *testing.T) {
	tests := []struct {
		name       string
		serverAddr string
	}{
		{"unreachable server", "127.0.0.1:19999"},
		{"invalid address", "not-a-real-host:9999"},
		{"empty address", ""},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
			results := RunDiagnostics(ctx, tc.serverAddr)

			if len(results) == 0 {
				t.Fatal("RunDiagnostics returned no results")
			}
		})
	}
}

func TestRunDiagnostics_OSCheckPresent(t *testing.T) {
	ctx := context.Background()
	results := RunDiagnostics(ctx, "127.0.0.1:19999")

	var osCheck *DiagnosticResult
	for i := range results {
		if results[i].Name == "os_support" {
			osCheck = &results[i]
			break
		}
	}

	if osCheck == nil {
		t.Fatal("os_support check not found in results")
	}

	// On a supported OS (linux/darwin/windows) this must be true.
	goos := runtime.GOOS
	supported := goos == "linux" || goos == "darwin" || goos == "windows"
	if osCheck.OK != supported {
		t.Errorf("os_support.OK = %v but GOOS=%q; want %v", osCheck.OK, goos, supported)
	}
	if osCheck.Message == "" {
		t.Error("os_support.Message should not be empty")
	}
}

func TestRunDiagnostics_ConnectivityCheckPresent(t *testing.T) {
	ctx := context.Background()
	// Use a port that should definitely be unreachable.
	results := RunDiagnostics(ctx, "127.0.0.1:19998")

	var connCheck *DiagnosticResult
	for i := range results {
		if results[i].Name == "server_connectivity" {
			connCheck = &results[i]
			break
		}
	}

	if connCheck == nil {
		t.Fatal("server_connectivity check not found in results")
	}
	// We expect it to be false because the port is closed.
	if connCheck.OK {
		t.Log("server_connectivity was OK (something is listening on :19998); skipping assertion")
	}
	if connCheck.Message == "" {
		t.Error("server_connectivity.Message should not be empty")
	}
}

func TestRunDiagnostics_MemoryCheckPresent(t *testing.T) {
	ctx := context.Background()
	results := RunDiagnostics(ctx, "127.0.0.1:19997")

	var memCheck *DiagnosticResult
	for i := range results {
		if results[i].Name == "memory_usage" {
			memCheck = &results[i]
			break
		}
	}

	if memCheck == nil {
		t.Fatal("memory_usage check not found in results")
	}
	// In test runs heap is well below 512MB.
	if !memCheck.OK {
		t.Logf("memory_usage.OK = false (heap: %s); may indicate high memory usage", memCheck.Message)
	}
	if memCheck.Message == "" {
		t.Error("memory_usage.Message should not be empty")
	}
}

func TestRunDiagnostics_WritePermissionsCheckPresent(t *testing.T) {
	ctx := context.Background()
	results := RunDiagnostics(ctx, "127.0.0.1:19996")

	var writeCheck *DiagnosticResult
	for i := range results {
		if results[i].Name == "write_permissions" {
			writeCheck = &results[i]
			break
		}
	}

	if writeCheck == nil {
		t.Fatal("write_permissions check not found in results")
	}
	// In CI/test environments, we should be able to write to temp dir.
	if !writeCheck.OK {
		t.Logf("write_permissions.OK = false: %s", writeCheck.Message)
	}
	if writeCheck.Message == "" {
		t.Error("write_permissions.Message should not be empty")
	}
}

func TestRunDiagnostics_UniqueNames(t *testing.T) {
	ctx := context.Background()
	results := RunDiagnostics(ctx, "127.0.0.1:19995")

	seen := make(map[string]int)
	for _, r := range results {
		seen[r.Name]++
	}
	for name, count := range seen {
		if count > 1 {
			t.Errorf("diagnostic check %q appears %d times (want 1)", name, count)
		}
	}
}

func TestRunDiagnostics_ContextCancelled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	// Even with a cancelled context the function should return (not hang).
	results := RunDiagnostics(ctx, "127.0.0.1:19994")

	// We still expect at least the OS and memory checks which don't use the context.
	if len(results) == 0 {
		t.Error("expected at least some results even with cancelled context")
	}
}
