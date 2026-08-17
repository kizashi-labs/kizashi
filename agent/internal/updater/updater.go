// Package updater implements agent self-update functionality.
// The updater checks the server for newer agent binaries, downloads and verifies
// them, then signals the watchdog to perform the actual restart.
package updater

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/edr-platform/agent/internal/buildvariant"
)

// UpdateInfo describes an available agent update.
type UpdateInfo struct {
	Version     string `json:"version"`
	URL         string `json:"url"`
	Checksum    string `json:"checksum"` // "sha256:<hex>"
	ForceUpdate bool   `json:"force_update"`
}

// Updater checks and applies agent self-updates.
type Updater struct {
	serverURL      string
	agentID        string
	currentVersion string
	dataDir        string
	httpClient     *http.Client
}

// New creates a new Updater.
func New(serverURL, agentID, currentVersion, dataDir string) *Updater {
	return &Updater{
		serverURL:      strings.TrimRight(serverURL, "/"),
		agentID:        agentID,
		currentVersion: currentVersion,
		dataDir:        dataDir,
		httpClient: &http.Client{
			Timeout: 30 * time.Second,
		},
	}
}

// Check queries the server to see if a newer agent version is available.
// Returns nil, nil if the agent is already up to date.
func (u *Updater) Check(ctx context.Context) (*UpdateInfo, error) {
	// platform/arch let the server advertise the correct per-platform binary and
	// derive its checksum (avoids checksum/URL mismatch on non-linux agents).
	//
	// variant keeps an enforcing agent enforcing. Without it the server always
	// advertised the default telemetry-only binary, so an endpoint installed
	// with the eBPF/LSM build would quietly downgrade to the non-enforcing one
	// at its next self-update — prevention gone, no error raised. Empty for the
	// default build, so servers predating this parameter behave as before.
	url := fmt.Sprintf("%s/api/v1/agents/%s/update-check?version=%s&platform=%s&arch=%s&variant=%s",
		u.serverURL, u.agentID, u.currentVersion, runtime.GOOS, runtime.GOARCH,
		buildvariant.Name)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("build update-check request: %w", err)
	}

	resp, err := u.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("update-check request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNoContent {
		// Up to date
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("update-check: server returned %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err != nil {
		return nil, fmt.Errorf("read update-check response: %w", err)
	}

	// If the server responded with {"up_to_date": true}, no update needed.
	var raw map[string]interface{}
	if err := json.Unmarshal(body, &raw); err == nil {
		if upToDate, ok := raw["up_to_date"].(bool); ok && upToDate {
			return nil, nil
		}
	}

	var info UpdateInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return nil, fmt.Errorf("parse update-check response: %w", err)
	}

	if info.Version == "" {
		return nil, nil
	}

	return &info, nil
}

// Apply downloads the new binary, verifies its checksum, writes it to disk,
// and creates a .update-pending marker file. The watchdog handles the restart.
func (u *Updater) Apply(ctx context.Context, info *UpdateInfo) error {
	// Resolve download URL: may be relative (e.g. "/downloads/edr-agent-linux-amd64")
	downloadURL := info.URL
	if strings.HasPrefix(downloadURL, "/") {
		downloadURL = u.serverURL + downloadURL
	}

	// Download to a temp file first
	tmpFile, err := os.CreateTemp(u.dataDir, "edr-agent-download-*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpPath := tmpFile.Name()
	defer func() {
		// Clean up the temp file on any error path (file may already be removed on success)
		if _, statErr := os.Stat(tmpPath); statErr == nil {
			_ = os.Remove(tmpPath)
		}
	}()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, downloadURL, nil)
	if err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("build download request: %w", err)
	}

	// Use a longer timeout for the actual binary download
	dlClient := &http.Client{Timeout: 10 * time.Minute}
	resp, err := dlClient.Do(req)
	if err != nil {
		_ = tmpFile.Close()
		return fmt.Errorf("download binary: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		_ = tmpFile.Close()
		return fmt.Errorf("download binary: server returned %d", resp.StatusCode)
	}

	// Stream download while computing SHA-256
	h := sha256.New()
	written, err := io.Copy(io.MultiWriter(tmpFile, h), resp.Body)
	_ = tmpFile.Close()
	if err != nil {
		return fmt.Errorf("stream download: %w", err)
	}
	if written == 0 {
		return fmt.Errorf("downloaded binary is empty")
	}

	// Verify checksum — expected format: "sha256:<hex>"
	gotHex := fmt.Sprintf("%x", h.Sum(nil))
	expected := info.Checksum
	expected = strings.TrimPrefix(expected, "sha256:")
	if !strings.EqualFold(gotHex, expected) {
		return fmt.Errorf("checksum mismatch: got sha256:%s, want sha256:%s", gotHex, expected)
	}

	// Move to final destination: {dataDir}/edr-agent.new
	newBinPath := filepath.Join(u.dataDir, "edr-agent.new")
	if runtime.GOOS == "windows" {
		newBinPath = filepath.Join(u.dataDir, "edr-agent.new.exe")
	}

	if err := os.Rename(tmpPath, newBinPath); err != nil {
		// Rename may fail across device boundaries; fall back to copy
		if err2 := copyFile(tmpPath, newBinPath); err2 != nil {
			return fmt.Errorf("install new binary: %w (rename: %v, copy: %v)", err, err, err2)
		}
	}

	// Make executable on Unix
	if runtime.GOOS != "windows" {
		if err := os.Chmod(newBinPath, 0755); err != nil {
			return fmt.Errorf("chmod new binary: %w", err)
		}
	}

	// Write the .update-pending marker file so the watchdog knows to swap binaries
	markerPath := filepath.Join(u.dataDir, ".update-pending")
	markerContent := fmt.Sprintf(`{"new_binary":%q,"version":%q,"timestamp":%q}`,
		newBinPath, info.Version, time.Now().UTC().Format(time.RFC3339))
	if err := os.WriteFile(markerPath, []byte(markerContent), 0644); err != nil {
		return fmt.Errorf("write update-pending marker: %w", err)
	}

	return nil
}

// copyFile copies src to dst (used as rename fallback across devices).
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()

	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()

	if _, err := io.Copy(out, in); err != nil {
		return err
	}
	return out.Sync()
}
