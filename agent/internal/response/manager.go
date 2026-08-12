package response

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
)

// Manager handles incoming response commands from the server.
type Manager struct {
	isolator       *NetworkIsolator
	processKiller  *ProcessKiller
	fileQuarantine *FileQuarantine
	managementIP   string
}

// NewManager creates a new response Manager using the default file-quarantine
// directory (/var/edr/quarantine).
func NewManager(managementIP string) (*Manager, error) {
	return NewManagerWithQuarantineDir(managementIP, "")
}

// NewManagerWithQuarantineDir is like NewManager but allows overriding the
// file-quarantine directory. An empty dir falls back to the default. This is
// primarily a testability seam: tests and non-root environments can point the
// quarantine dir at a writable location (e.g. t.TempDir()) instead of the
// default /var/edr/quarantine, which requires privileges to create.
func NewManagerWithQuarantineDir(managementIP, quarantineDir string) (*Manager, error) {
	fq, err := NewFileQuarantine(quarantineDir)
	if err != nil {
		return nil, fmt.Errorf("検疫マネージャー初期化失敗: %w", err)
	}
	return &Manager{
		isolator:       NewNetworkIsolator(),
		processKiller:  NewProcessKiller(),
		fileQuarantine: fq,
		managementIP:   managementIP,
	}, nil
}

// ExecuteCommand dispatches and executes a server command.
func (m *Manager) ExecuteCommand(ctx context.Context, cmdType string, payload []byte) error {
	slog.Info("executing response command", "type", cmdType)

	switch cmdType {
	case "isolate_network":
		var p struct {
			ManagementIP string `json:"management_ip"`
		}
		if err := json.Unmarshal(payload, &p); err != nil || p.ManagementIP == "" {
			p.ManagementIP = m.managementIP
		}
		if err := m.isolator.Isolate(ctx, p.ManagementIP); err != nil {
			return fmt.Errorf("network isolation failed: %w", err)
		}
		slog.Info("network isolation applied", "management_ip", p.ManagementIP)

	case "release_network":
		if err := m.isolator.Release(ctx, m.managementIP); err != nil {
			return fmt.Errorf("network release failed: %w", err)
		}
		slog.Info("network isolation released")

	case "kill_process":
		var p struct {
			PID  int    `json:"pid"`
			Name string `json:"name"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("invalid kill_process payload: %w", err)
		}
		if p.PID > 0 {
			if err := m.processKiller.KillByPID(ctx, p.PID); err != nil {
				return fmt.Errorf("kill by PID failed: %w", err)
			}
			slog.Info("process killed", "pid", p.PID)
		} else if p.Name != "" {
			killed, err := m.processKiller.KillByName(ctx, p.Name)
			if err != nil {
				return fmt.Errorf("kill by name failed: %w", err)
			}
			slog.Info("processes killed by name", "name", p.Name, "count", len(killed))
		}

	case "quarantine_file":
		var p struct {
			FilePath string `json:"file_path"`
		}
		if err := json.Unmarshal(payload, &p); err != nil {
			return fmt.Errorf("invalid quarantine_file payload: %w", err)
		}
		result, err := m.fileQuarantine.Quarantine(ctx, p.FilePath)
		if err != nil {
			return fmt.Errorf("file quarantine failed: %w", err)
		}
		slog.Info("file quarantined", "original", result.OriginalPath, "sha256", result.SHA256)

	default:
		slog.Warn("unknown response command", "type", cmdType)
	}

	return nil
}
