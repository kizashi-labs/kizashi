package forensics

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"runtime"
	"strconv"
	"time"
)

// JobRequest is the NATS message from the server, delivered to the agent via
// the gRPC CollectArtifact command's target field as JSON.
type JobRequest struct {
	JobID     string `json:"job_id"`
	Type      string `json:"type"`
	ProcessID int    `json:"process_id"`
}

// Collector executes forensics jobs and submits results.
type Collector struct {
	serverURL string
	agentID   string
	authToken string
	client    *http.Client
}

// New creates a Collector that submits results to serverURL.
func New(serverURL, agentID, authToken string) *Collector {
	return &Collector{
		serverURL: serverURL,
		agentID:   agentID,
		authToken: authToken,
		client:    &http.Client{Timeout: 120 * time.Second},
	}
}

// Execute runs a forensics job and submits the result to the server.
func (c *Collector) Execute(ctx context.Context, req *JobRequest) error {
	var data []byte
	var err error

	switch req.Type {
	case "process_list":
		data, err = c.collectProcessList()
	case "memory_dump":
		data, err = c.collectMemoryDump(req.ProcessID)
	case "artifact_collect":
		data, err = c.collectArtifacts()
	default:
		return fmt.Errorf("unknown job type: %s", req.Type)
	}

	if err != nil {
		return fmt.Errorf("collect %s: %w", req.Type, err)
	}

	return c.submitResult(ctx, req.JobID, data)
}

// collectProcessList returns a JSON list of running processes.
func (c *Collector) collectProcessList() ([]byte, error) {
	type ProcessInfo struct {
		PID     int    `json:"pid"`
		Name    string `json:"name"`
		PPID    int    `json:"ppid"`
		User    string `json:"user"`
		CmdLine string `json:"cmdline"`
	}

	var processes []ProcessInfo

	if runtime.GOOS == "linux" {
		entries, err := os.ReadDir("/proc")
		if err != nil {
			return nil, err
		}
		for _, entry := range entries {
			if !entry.IsDir() {
				continue
			}
			pid, err := strconv.Atoi(entry.Name())
			if err != nil {
				continue
			}
			name := ""
			if commBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/comm", pid)); err == nil {
				name = string(bytes.TrimSpace(commBytes))
			}
			cmdline := ""
			if cmdBytes, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", pid)); err == nil {
				cmdline = string(bytes.ReplaceAll(cmdBytes, []byte{0}, []byte{' '}))
			}
			processes = append(processes, ProcessInfo{
				PID:     pid,
				Name:    name,
				CmdLine: cmdline,
			})
		}
	} else {
		// Stub for Windows/macOS
		processes = append(processes, ProcessInfo{
			PID:  os.Getpid(),
			Name: "edr-agent",
		})
	}

	return json.Marshal(map[string]interface{}{
		"collected_at": time.Now(),
		"platform":     runtime.GOOS,
		"processes":    processes,
	})
}

// collectMemoryDump creates a minimal process memory dump.
// Full implementation requires platform-specific APIs (ptrace on Linux,
// MiniDumpWriteDump on Windows).
func (c *Collector) collectMemoryDump(pid int) ([]byte, error) {
	if pid <= 0 {
		return nil, fmt.Errorf("invalid PID: %d", pid)
	}

	if runtime.GOOS == "linux" {
		if _, err := os.Stat(fmt.Sprintf("/proc/%d", pid)); os.IsNotExist(err) {
			return nil, fmt.Errorf("process %d not found", pid)
		}
		// Read memory maps as a lightweight alternative to a full dump.
		maps, err := os.ReadFile(fmt.Sprintf("/proc/%d/maps", pid))
		if err != nil {
			return nil, fmt.Errorf("read memory maps: %w", err)
		}
		return json.Marshal(map[string]interface{}{
			"collected_at": time.Now(),
			"pid":          pid,
			"platform":     runtime.GOOS,
			"type":         "memory_maps",
			"data":         string(maps),
		})
	}

	// Stub for other platforms
	return json.Marshal(map[string]interface{}{
		"collected_at": time.Now(),
		"pid":          pid,
		"platform":     runtime.GOOS,
		"note":         "full memory dump requires platform-specific implementation",
	})
}

// collectArtifacts collects common forensics artifacts.
func (c *Collector) collectArtifacts() ([]byte, error) {
	hostname, _ := os.Hostname()
	artifacts := map[string]interface{}{
		"collected_at": time.Now(),
		"platform":     runtime.GOOS,
		"hostname":     hostname,
	}

	if runtime.GOOS == "linux" {
		for _, path := range []string{
			"/etc/passwd", "/etc/hosts", "/etc/crontab",
		} {
			data, err := os.ReadFile(path)
			if err == nil {
				artifacts[path] = string(data)
			}
		}
		if data, err := os.ReadFile("/var/log/lastlog"); err == nil {
			artifacts["lastlog_size"] = len(data)
		}
	} else if runtime.GOOS == "windows" {
		artifacts["note"] = "Windows artifact collection requires additional implementation"
	}

	return json.Marshal(artifacts)
}

// submitResult POSTs the collected data to the server.
func (c *Collector) submitResult(ctx context.Context, jobID string, data []byte) error {
	url := fmt.Sprintf("%s/api/v1/forensics/jobs/%s/result", c.serverURL, jobID)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	if c.authToken != "" {
		req.Header.Set("Authorization", "Bearer "+c.authToken)
	}

	resp, err := c.client.Do(req)
	if err != nil {
		return fmt.Errorf("submit result: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 300 {
		return fmt.Errorf("server returned %d", resp.StatusCode)
	}
	return nil
}

// ParseRequest parses a forensics job message (JSON-encoded JobRequest).
func ParseRequest(data []byte) (*JobRequest, error) {
	var req JobRequest
	return &req, json.Unmarshal(data, &req)
}
