package agentconfig

// Manages configuration profiles that can be pushed to agents.

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// AgentConfig holds the configuration settings for an agent.
type AgentConfig struct {
	CollectionIntervalSec int      `json:"collection_interval_sec"`
	EnableProcessMonitor  bool     `json:"enable_process_monitor"`
	EnableNetworkMonitor  bool     `json:"enable_network_monitor"`
	EnableFileMonitor     bool     `json:"enable_file_monitor"`
	EnableRegistryMonitor bool     `json:"enable_registry_monitor"`
	FileMonitorPaths      []string `json:"file_monitor_paths"`
	ExcludedProcesses     []string `json:"excluded_processes"`
	MaxEventsPerMin       int      `json:"max_events_per_min"`
	LogLevel              string   `json:"log_level"`
	HeartbeatIntervalSec  int      `json:"heartbeat_interval_sec"`
}

// Profile represents an agent configuration profile.
type Profile struct {
	ID          string      `json:"id"`
	Name        string      `json:"name"`
	Description string      `json:"description"`
	OSType      string      `json:"os_type"` // windows/linux/macos/all
	Config      AgentConfig `json:"config"`
	IsDefault   bool        `json:"is_default"`
	CreatedAt   time.Time   `json:"created_at"`
	UpdatedAt   time.Time   `json:"updated_at"`
}

// Store manages agent configuration profiles in the database.
type Store struct {
	pool *pgxpool.Pool
}

// NewStore creates a new Store.
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// CreateProfile creates a new agent configuration profile.
func (s *Store) CreateProfile(ctx context.Context, profile *Profile) (*Profile, error) {
	if profile.ID == "" {
		profile.ID = uuid.New().String()
	}
	now := time.Now().UTC()
	profile.CreatedAt = now
	profile.UpdatedAt = now

	if profile.OSType == "" {
		profile.OSType = "all"
	}

	configJSON, err := json.Marshal(profile.Config)
	if err != nil {
		return nil, fmt.Errorf("marshaling config: %w", err)
	}

	if s.pool == nil {
		return profile, nil
	}

	_, err = s.pool.Exec(ctx, `
		INSERT INTO agent_config_profiles (id, name, description, os_type, config, is_default, created_at, updated_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`, profile.ID, profile.Name, profile.Description, profile.OSType,
		configJSON, profile.IsDefault, profile.CreatedAt, profile.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("inserting profile: %w", err)
	}

	// If this is default, unset other defaults for same OS type
	if profile.IsDefault {
		_, _ = s.pool.Exec(ctx, `
			UPDATE agent_config_profiles
			SET is_default = false
			WHERE os_type = $1 AND id != $2
		`, profile.OSType, profile.ID)
	}

	return profile, nil
}

// GetProfile retrieves a profile by ID.
func (s *Store) GetProfile(ctx context.Context, id string) (*Profile, error) {
	if s.pool == nil {
		return nil, fmt.Errorf("profile %s not found", id)
	}

	var p Profile
	var configJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, COALESCE(description,''), os_type, config, is_default, created_at, updated_at
		FROM agent_config_profiles WHERE id = $1
	`, id).Scan(&p.ID, &p.Name, &p.Description, &p.OSType,
		&configJSON, &p.IsDefault, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		return nil, fmt.Errorf("profile %s not found: %w", id, err)
	}

	if err := json.Unmarshal(configJSON, &p.Config); err != nil {
		slog.Warn("agentconfig: failed to unmarshal config", "id", id, "error", err)
	}
	return &p, nil
}

// ListProfiles returns all profiles.
func (s *Store) ListProfiles(ctx context.Context) ([]*Profile, error) {
	if s.pool == nil {
		return DefaultProfiles(), nil
	}

	rows, err := s.pool.Query(ctx, `
		SELECT id, name, COALESCE(description,''), os_type, config, is_default, created_at, updated_at
		FROM agent_config_profiles
		ORDER BY created_at ASC
	`)
	if err != nil {
		slog.Warn("agentconfig: failed to list profiles, returning defaults", "error", err)
		return DefaultProfiles(), nil
	}
	defer rows.Close()

	var profiles []*Profile
	for rows.Next() {
		var p Profile
		var configJSON []byte
		if err := rows.Scan(&p.ID, &p.Name, &p.Description, &p.OSType,
			&configJSON, &p.IsDefault, &p.CreatedAt, &p.UpdatedAt); err == nil {
			if err2 := json.Unmarshal(configJSON, &p.Config); err2 != nil {
				slog.Warn("agentconfig: failed to unmarshal config", "id", p.ID)
			}
			profiles = append(profiles, &p)
		}
	}
	if len(profiles) == 0 {
		return DefaultProfiles(), nil
	}
	return profiles, nil
}

// UpdateProfile updates an existing profile.
func (s *Store) UpdateProfile(ctx context.Context, id string, updates *Profile) (*Profile, error) {
	if s.pool == nil {
		updates.ID = id
		return updates, nil
	}

	configJSON, err := json.Marshal(updates.Config)
	if err != nil {
		return nil, fmt.Errorf("marshaling config: %w", err)
	}

	now := time.Now().UTC()
	_, err = s.pool.Exec(ctx, `
		UPDATE agent_config_profiles
		SET name=$2, description=$3, os_type=$4, config=$5, is_default=$6, updated_at=$7
		WHERE id=$1
	`, id, updates.Name, updates.Description, updates.OSType,
		configJSON, updates.IsDefault, now)
	if err != nil {
		return nil, fmt.Errorf("updating profile: %w", err)
	}

	if updates.IsDefault {
		_, _ = s.pool.Exec(ctx, `
			UPDATE agent_config_profiles
			SET is_default = false
			WHERE os_type = $1 AND id != $2
		`, updates.OSType, id)
	}

	updates.ID = id
	updates.UpdatedAt = now
	return updates, nil
}

// DeleteProfile deletes a profile by ID.
func (s *Store) DeleteProfile(ctx context.Context, id string) error {
	if s.pool == nil {
		return nil
	}
	_, err := s.pool.Exec(ctx, `DELETE FROM agent_config_profiles WHERE id = $1`, id)
	return err
}

// GetDefaultProfile returns the default profile for a given OS type.
func (s *Store) GetDefaultProfile(ctx context.Context, osType string) (*Profile, error) {
	if s.pool == nil {
		for _, p := range DefaultProfiles() {
			if p.OSType == osType || p.OSType == "all" {
				return p, nil
			}
		}
		return nil, fmt.Errorf("no default profile found for %s", osType)
	}

	var p Profile
	var configJSON []byte
	err := s.pool.QueryRow(ctx, `
		SELECT id, name, COALESCE(description,''), os_type, config, is_default, created_at, updated_at
		FROM agent_config_profiles
		WHERE is_default = true AND (os_type = $1 OR os_type = 'all')
		ORDER BY CASE WHEN os_type = $1 THEN 0 ELSE 1 END
		LIMIT 1
	`, osType).Scan(&p.ID, &p.Name, &p.Description, &p.OSType,
		&configJSON, &p.IsDefault, &p.CreatedAt, &p.UpdatedAt)
	if err != nil {
		// Fall back to in-memory defaults
		for _, dp := range DefaultProfiles() {
			if dp.OSType == osType {
				return dp, nil
			}
		}
		return nil, fmt.Errorf("no default profile found for %s", osType)
	}

	if err := json.Unmarshal(configJSON, &p.Config); err != nil {
		slog.Warn("agentconfig: failed to unmarshal default profile config", "error", err)
	}
	return &p, nil
}

// PushToAgent publishes a configuration profile to a specific agent via NATS.
func (s *Store) PushToAgent(ctx context.Context, agentID, profileID string, natsConn *nats.Conn) error {
	profile, err := s.GetProfile(ctx, profileID)
	if err != nil {
		return fmt.Errorf("getting profile: %w", err)
	}

	payload, err := json.Marshal(map[string]interface{}{
		"agent_id":   agentID,
		"profile_id": profileID,
		"config":     profile.Config,
		"pushed_at":  time.Now().UTC(),
	})
	if err != nil {
		return fmt.Errorf("marshaling payload: %w", err)
	}

	topic := fmt.Sprintf("agent.config.%s", agentID)
	if natsConn != nil {
		if err := natsConn.Publish(topic, payload); err != nil {
			return fmt.Errorf("publishing to NATS topic %s: %w", topic, err)
		}
		slog.Info("agentconfig: pushed config to agent", "agent_id", agentID, "profile_id", profileID)
	} else {
		slog.Warn("agentconfig: NATS not connected, config push skipped", "agent_id", agentID)
	}
	return nil
}

// ListAgentsByOSType queries the database for agents with a given OS type.
func (s *Store) ListAgentsByOSType(ctx context.Context, osType string) ([]string, error) {
	if s.pool == nil {
		return nil, nil
	}
	// 列名は os ではなく os_type。os は存在しないため、この関数は 42703
	// (column "os" does not exist) を返し続けていた＝PushProfileAll は常に 500。
	rows, err := s.pool.Query(ctx, `
		SELECT id::text FROM agents WHERE os_type = $1 OR $1 = 'all'
	`, osType)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	return ids, nil
}

// DefaultProfiles returns sensible default profiles for each supported OS type.
func DefaultProfiles() []*Profile {
	now := time.Now().UTC()
	return []*Profile{
		{
			ID:          "default-windows-profile",
			Name:        "Windows Default",
			Description: "Standard configuration for Windows endpoints",
			OSType:      "windows",
			IsDefault:   true,
			CreatedAt:   now,
			UpdatedAt:   now,
			Config: AgentConfig{
				CollectionIntervalSec: 60,
				EnableProcessMonitor:  true,
				EnableNetworkMonitor:  true,
				EnableFileMonitor:     true,
				EnableRegistryMonitor: true,
				FileMonitorPaths: []string{
					"C:\\Windows\\System32",
					"C:\\Windows\\SysWOW64",
					"C:\\Users\\*\\AppData\\Roaming",
					"C:\\ProgramData",
				},
				ExcludedProcesses: []string{
					"svchost.exe",
					"System",
					"Registry",
					"smss.exe",
				},
				MaxEventsPerMin:      1000,
				LogLevel:             "info",
				HeartbeatIntervalSec: 30,
			},
		},
		{
			ID:          "default-linux-profile",
			Name:        "Linux Default",
			Description: "Standard configuration for Linux endpoints",
			OSType:      "linux",
			IsDefault:   true,
			CreatedAt:   now,
			UpdatedAt:   now,
			Config: AgentConfig{
				CollectionIntervalSec: 60,
				EnableProcessMonitor:  true,
				EnableNetworkMonitor:  true,
				EnableFileMonitor:     true,
				EnableRegistryMonitor: false, // No registry on Linux
				FileMonitorPaths: []string{
					"/etc",
					"/usr/bin",
					"/usr/sbin",
					"/tmp",
					"/var/tmp",
				},
				ExcludedProcesses: []string{
					"kworker",
					"ksoftirqd",
					"kthreadd",
				},
				MaxEventsPerMin:      1000,
				LogLevel:             "info",
				HeartbeatIntervalSec: 30,
			},
		},
		{
			ID:          "default-macos-profile",
			Name:        "macOS Default",
			Description: "Standard configuration for macOS endpoints",
			OSType:      "macos",
			IsDefault:   true,
			CreatedAt:   now,
			UpdatedAt:   now,
			Config: AgentConfig{
				CollectionIntervalSec: 60,
				EnableProcessMonitor:  true,
				EnableNetworkMonitor:  true,
				EnableFileMonitor:     true,
				EnableRegistryMonitor: false, // No registry on macOS
				FileMonitorPaths: []string{
					"/Applications",
					"/Library",
					"/Users/*/Library/LaunchAgents",
					"/tmp",
				},
				ExcludedProcesses: []string{
					"kernel_task",
					"launchd",
					"mds_stores",
				},
				MaxEventsPerMin:      1000,
				LogLevel:             "info",
				HeartbeatIntervalSec: 30,
			},
		},
	}
}
