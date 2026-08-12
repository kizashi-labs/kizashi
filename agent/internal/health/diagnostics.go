package health

import (
	"context"
	"fmt"
	"net"
	"os"
	"runtime"
	"time"
)

// DiagnosticResult holds the result of a single diagnostic check.
type DiagnosticResult struct {
	Name    string `json:"name"`
	OK      bool   `json:"ok"`
	Message string `json:"message"`
	Latency string `json:"latency,omitempty"`
}

// RunDiagnostics performs a full suite of self-diagnostic checks.
func RunDiagnostics(ctx context.Context, serverAddr string) []DiagnosticResult {
	var results []DiagnosticResult

	// 1. OS check
	results = append(results, DiagnosticResult{
		Name:    "os_support",
		OK:      runtime.GOOS == "linux" || runtime.GOOS == "darwin" || runtime.GOOS == "windows",
		Message: fmt.Sprintf("OS: %s/%s", runtime.GOOS, runtime.GOARCH),
	})

	// 2. Server connectivity
	start := time.Now()
	conn, err := net.DialTimeout("tcp", serverAddr, 5*time.Second)
	latency := time.Since(start)
	if err != nil {
		results = append(results, DiagnosticResult{
			Name:    "server_connectivity",
			OK:      false,
			Message: fmt.Sprintf("Cannot reach server %s: %v", serverAddr, err),
		})
	} else {
		conn.Close()
		results = append(results, DiagnosticResult{
			Name:    "server_connectivity",
			OK:      true,
			Message: fmt.Sprintf("Server %s reachable", serverAddr),
			Latency: latency.String(),
		})
	}

	// 3. Disk space
	var stat diskStat
	if err := getDiskStat("/", &stat); err == nil {
		freeGB := float64(stat.Free) / 1024 / 1024 / 1024
		ok := freeGB > 0.5 // Need at least 500MB
		results = append(results, DiagnosticResult{
			Name:    "disk_space",
			OK:      ok,
			Message: fmt.Sprintf("Free disk: %.1f GB", freeGB),
		})
	}

	// 4. Memory
	var memStats runtime.MemStats
	runtime.ReadMemStats(&memStats)
	heapMB := float64(memStats.HeapAlloc) / 1024 / 1024
	results = append(results, DiagnosticResult{
		Name:    "memory_usage",
		OK:      heapMB < 512, // Alert if using more than 512MB
		Message: fmt.Sprintf("Heap: %.1f MB", heapMB),
	})

	// 5. Permissions (can write to temp dir)
	tmpFile := fmt.Sprintf("%s/edr-diag-%d", os.TempDir(), time.Now().UnixNano())
	if f, err := os.Create(tmpFile); err != nil {
		results = append(results, DiagnosticResult{
			Name:    "write_permissions",
			OK:      false,
			Message: "Cannot write to temp directory: " + err.Error(),
		})
	} else {
		f.Close()
		os.Remove(tmpFile)
		results = append(results, DiagnosticResult{
			Name:    "write_permissions",
			OK:      true,
			Message: "Write permissions OK",
		})
	}

	return results
}
