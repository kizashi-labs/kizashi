// Package sync provides integrations with external security tools.
package sync

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// WazuhConfig holds connection parameters for a Wazuh Manager.
type WazuhConfig struct {
	ManagerURL string // e.g. https://wazuh-manager:55000
	Username   string
	Password   string
	MinLevel   int  // minimum alert level to import (default 7)
	SkipTLS    bool // skip TLS verification (self-signed certs)
}

// WazuhClient authenticates and calls the Wazuh Manager REST API.
type WazuhClient struct {
	cfg    WazuhConfig
	http   *http.Client
	token  string
	expiry time.Time
}

func NewWazuhClient(cfg WazuhConfig) *WazuhClient {
	transport := &http.Transport{
		// G402: 設定でゲート済み（既定 false=検証）。Wazuh Manager が自己署名証明書の
		// 場合に限り SkipTLS=true を明示的に有効化する。
		TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12, InsecureSkipVerify: cfg.SkipTLS}, //nolint:gosec
	}
	return &WazuhClient{
		cfg:  cfg,
		http: &http.Client{Timeout: 15 * time.Second, Transport: transport},
	}
}

// authenticate obtains or refreshes a JWT from the Wazuh Manager.
func (c *WazuhClient) authenticate(ctx context.Context) error {
	if time.Now().Before(c.expiry) && c.token != "" {
		return nil
	}

	creds := base64.StdEncoding.EncodeToString(
		[]byte(c.cfg.Username + ":" + c.cfg.Password))

	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.cfg.ManagerURL+"/security/user/authenticate", nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Basic "+creds)

	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("wazuh auth: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("wazuh auth: status %d", resp.StatusCode)
	}

	var result struct {
		Data struct {
			Token string `json:"token"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return err
	}
	c.token = result.Data.Token
	c.expiry = time.Now().Add(14 * time.Minute) // Wazuh tokens expire in 15min
	return nil
}

func (c *WazuhClient) get(ctx context.Context, path string, out interface{}) error {
	if err := c.authenticate(ctx); err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.cfg.ManagerURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)

	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("wazuh GET %s: status %d — %s", path, resp.StatusCode, string(body))
	}
	return json.Unmarshal(body, out)
}

// ─── Agent Sync ───────────────────────────────────────────────

type wazuhAgent struct {
	ID            string `json:"id"`
	Name          string `json:"name"`
	IP            string `json:"ip"`
	Status        string `json:"status"` // active / disconnected / never_connected / pending
	Version       string `json:"version"`
	LastKeepAlive string `json:"lastKeepAlive"`
	OS            struct {
		Name     string `json:"name"`
		Version  string `json:"version"`
		Arch     string `json:"arch"`
		Platform string `json:"platform"`
	} `json:"os"`
	RegisterIP string `json:"registerIP"`
}

// SyncAgents pulls all agents from Wazuh and upserts them into our agents table.
func (c *WazuhClient) SyncAgents(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	var result struct {
		Data struct {
			AffectedItems []wazuhAgent `json:"affected_items"`
			TotalItems    int          `json:"total_affected_items"`
		} `json:"data"`
	}
	if err := c.get(ctx, "/agents?limit=500&status=active,disconnected,pending", &result); err != nil {
		return 0, err
	}

	count := 0
	for _, wa := range result.Data.AffectedItems {
		if wa.ID == "000" {
			continue // skip manager itself
		}

		status := mapWazuhStatus(wa.Status)
		// os.platform is a distribution id ("ubuntu", "centos", "amzn", …),
		// not an OS family — writing it straight to agents.os_type violates
		// agents_os_type_check for every non-Windows host.
		osType := NormalizeOSType(wa.OS.Platform, wa.OS.Name)
		osVersion := strings.TrimSpace(wa.OS.Name + " " + wa.OS.Version)
		version := strings.TrimPrefix(wa.Version, "Wazuh v")

		var lastSeen *time.Time
		if wa.LastKeepAlive != "" && wa.LastKeepAlive != "unknown" {
			t, err := time.Parse(time.RFC3339, wa.LastKeepAlive)
			if err == nil {
				lastSeen = &t
			}
		}

		ip := SanitizeIP(wa.IP)

		// agents.hostname has no UNIQUE constraint (multi-tenant deployments
		// can legitimately hold the same hostname twice), so `ON CONFLICT
		// (hostname)` fails with 42P10 on every row — this sync used to be a
		// silent no-op. Upsert as UPDATE-then-INSERT instead.
		// os_type is only overwritten when we actually resolved one, so an
		// unrecognised platform never downgrades a known OS to 'unknown'.
		// 'isolated' is a containment state Wazuh knows nothing about — its
		// active/disconnected mapping must never lift a quarantine.
		tag, err := pool.Exec(ctx, `
			UPDATE agents SET
				ip_addresses  = ARRAY[$2::inet],
				os_type       = CASE WHEN $3 <> 'unknown' THEN $3 ELSE os_type END,
				os_version    = $4,
				agent_version = $5,
				status        = CASE WHEN status = 'isolated' THEN 'isolated' ELSE $6 END,
				last_seen     = $7,
				source        = 'wazuh',
				updated_at    = NOW()
			WHERE hostname = $1`,
			wa.Name, ip, osType, osVersion, version, status, lastSeen)
		if err != nil {
			slog.Warn("Wazuhエージェント同期エラー", "agent", wa.Name, "error", err)
			continue
		}
		if tag.RowsAffected() == 0 {
			_, err = pool.Exec(ctx, `
				INSERT INTO agents (hostname, ip_addresses, os_type, os_version, agent_version, status, last_seen, source)
				VALUES ($1, ARRAY[$2::inet], $3, $4, $5, $6, $7, 'wazuh')`,
				wa.Name, ip, osType, osVersion, version, status, lastSeen)
			if err != nil {
				slog.Warn("Wazuhエージェント登録エラー", "agent", wa.Name, "error", err)
				continue
			}
		}
		count++
	}
	return count, nil
}

func mapWazuhStatus(s string) string {
	switch s {
	case "active":
		return "online"
	case "disconnected":
		return "offline"
	default:
		return "offline"
	}
}

// ─── Vulnerability Sync ───────────────────────────────────────

type wazuhVuln struct {
	CVEID        string  `json:"cve"`
	Name         string  `json:"name"`
	Version      string  `json:"version"`
	Architecture string  `json:"architecture"`
	Severity     string  `json:"severity"`
	CVSS3Score   float64 `json:"cvss3_score"`
	Title        string  `json:"title"`
	Condition    string  `json:"condition"`
	Status       string  `json:"status"`
}

// SyncVulnerabilities pulls vulnerability data for all agents.
func (c *WazuhClient) SyncVulnerabilities(ctx context.Context, pool *pgxpool.Pool) (int, error) {
	// Get agent list first
	var agentsResult struct {
		Data struct {
			AffectedItems []wazuhAgent `json:"affected_items"`
		} `json:"data"`
	}
	if err := c.get(ctx, "/agents?limit=500&status=active", &agentsResult); err != nil {
		return 0, err
	}

	count := 0
	for _, wa := range agentsResult.Data.AffectedItems {
		if wa.ID == "000" {
			continue
		}

		// Get our internal agent ID by hostname
		var agentID string
		_ = pool.QueryRow(ctx,
			`SELECT id::text FROM agents WHERE hostname = $1 LIMIT 1`, wa.Name).
			Scan(&agentID)
		if agentID == "" {
			continue
		}

		var vulnResult struct {
			Data struct {
				AffectedItems []wazuhVuln `json:"affected_items"`
			} `json:"data"`
		}
		path := fmt.Sprintf("/vulnerability/%s?limit=200&status=valid", wa.ID)
		if err := c.get(ctx, path, &vulnResult); err != nil {
			continue
		}

		for _, v := range vulnResult.Data.AffectedItems {
			sev := normalizeSeverity(v.Severity)
			_, err := pool.Exec(ctx, `
				INSERT INTO vulnerabilities
					(agent_id, cve_id, title, severity, cvss_score, affected_package, affected_version, status, source)
				VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, 'open', 'wazuh')
				ON CONFLICT (agent_id, cve_id, affected_package) DO UPDATE SET
					severity      = EXCLUDED.severity,
					cvss_score    = EXCLUDED.cvss_score,
					title         = EXCLUDED.title,
					updated_at    = NOW()
				`,
				agentID, v.CVEID,
				firstNonEmpty(v.Title, v.CVEID),
				sev, v.CVSS3Score, v.Name, v.Version)
			if err == nil {
				count++
			}
		}
	}
	return count, nil
}

func normalizeSeverity(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium", "moderate":
		return "medium"
	default:
		return "low"
	}
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

// ─── Wazuh Syncer (background loop) ──────────────────────────

// WazuhSyncer runs periodic syncs against a Wazuh Manager.
type WazuhSyncer struct {
	client *WazuhClient
	pool   *pgxpool.Pool
}

func NewWazuhSyncer(cfg WazuhConfig, pool *pgxpool.Pool) *WazuhSyncer {
	return &WazuhSyncer{client: NewWazuhClient(cfg), pool: pool}
}

// Run starts the sync loop. Call in a goroutine.
func (s *WazuhSyncer) Run(ctx context.Context) {
	agentTicker := time.NewTicker(5 * time.Minute)
	vulnTicker := time.NewTicker(1 * time.Hour)
	defer agentTicker.Stop()
	defer vulnTicker.Stop()

	// Run immediately on start
	s.syncAgents(ctx)

	for {
		select {
		case <-ctx.Done():
			return
		case <-agentTicker.C:
			s.syncAgents(ctx)
		case <-vulnTicker.C:
			s.syncVulns(ctx)
		}
	}
}

func (s *WazuhSyncer) syncAgents(ctx context.Context) {
	sctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	n, err := s.client.SyncAgents(sctx, s.pool)
	if err != nil {
		slog.Warn("Wazuhエージェント同期失敗", "error", err)
	} else {
		slog.Info("Wazuhエージェント同期完了", "count", n)
	}
}

func (s *WazuhSyncer) syncVulns(ctx context.Context) {
	sctx, cancel := context.WithTimeout(ctx, 120*time.Second)
	defer cancel()
	n, err := s.client.SyncVulnerabilities(sctx, s.pool)
	if err != nil {
		slog.Warn("Wazuh脆弱性同期失敗", "error", err)
	} else {
		slog.Info("Wazuh脆弱性同期完了", "count", n)
	}
}

// ─── Alert Ingest (webhook format) ────────────────────────────

// WazuhAlertPayload is the JSON structure Wazuh POSTs to our webhook.
type WazuhAlertPayload struct {
	Timestamp string `json:"timestamp"`
	Rule      struct {
		Level       int      `json:"level"`
		Description string   `json:"description"`
		ID          string   `json:"id"`
		Groups      []string `json:"groups"`
		MITRE       struct {
			Attack    []string `json:"attack"`
			Tactic    []string `json:"tactic"`
			Technique []string `json:"technique"`
		} `json:"mitre"`
	} `json:"rule"`
	Agent struct {
		ID   string `json:"id"`
		Name string `json:"name"`
		IP   string `json:"ip"`
	} `json:"agent"`
	Manager struct {
		Name string `json:"name"`
	} `json:"manager"`
	ID       string                 `json:"id"`
	FullLog  string                 `json:"full_log"`
	Location string                 `json:"location"`
	Data     map[string]interface{} `json:"data"`
}

// WazuhLevelToSeverity converts Wazuh alert level (0-15) to our severity (1-4).
func WazuhLevelToSeverity(level int) int {
	switch {
	case level >= 12:
		return 4 // critical
	case level >= 10:
		return 3 // high
	case level >= 7:
		return 2 // medium
	default:
		return 1 // low
	}
}

// MarshalWazuhData serialises the Data map for storage.
func MarshalWazuhData(data map[string]interface{}) []byte {
	b, _ := json.Marshal(data)
	if b == nil {
		return []byte("{}")
	}
	return b
}

// FormatWazuhPayload pretty-prints for storage in raw_data.
func FormatWazuhPayload(p *WazuhAlertPayload) []byte {
	b, _ := json.MarshalIndent(p, "", "  ")
	return b
}

// BuildIngestBody is a helper used by IngestHandler to avoid import cycles.
func BuildIngestBody(p *WazuhAlertPayload) []byte {
	buf := &bytes.Buffer{}
	_ = json.NewEncoder(buf).Encode(p)
	return buf.Bytes()
}
