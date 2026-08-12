package store

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AgentStore handles agent database operations.
type AgentStore struct {
	pool *pgxpool.Pool
}

func NewAgentStore(db *DB) *AgentStore {
	return &AgentStore{pool: db.Pool()}
}

type AgentRow struct {
	ID             string     `json:"id"`
	Hostname       string     `json:"hostname"`
	OSType         string     `json:"os_type"`
	OSVersion      string     `json:"os_version"`
	AgentVersion   string     `json:"agent_version"`
	IPAddresses    []string   `json:"ip_addresses"`
	Status         string     `json:"status"`
	LastSeen       *time.Time `json:"last_seen,omitempty"`
	EnrolledAt     time.Time  `json:"enrolled_at"`
	GroupID        *string    `json:"group_id,omitempty"`
	PolicyID       *string    `json:"policy_id,omitempty"`
	ConfigVersion  int        `json:"config_version"`
	TLSThumbprint  *string    `json:"tls_thumbprint,omitempty"`
	Tags           []string   `json:"tags"`
	IsolatedAt     *time.Time `json:"isolated_at,omitempty"`
	IsolatedReason *string    `json:"isolated_reason,omitempty"`
	IsolatedBy     *string    `json:"isolated_by,omitempty"`
}

// UpsertAgent creates or updates an agent record.
func (s *AgentStore) UpsertAgent(ctx context.Context, a *AgentRow) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (
			id, hostname, os_type, os_version, agent_version,
			ip_addresses, status, last_seen, tls_thumbprint, updated_at
		) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW(), $8, NOW())
		ON CONFLICT (id) DO UPDATE SET
			hostname       = EXCLUDED.hostname,
			os_type        = CASE WHEN EXCLUDED.os_type != '' THEN EXCLUDED.os_type ELSE agents.os_type END,
			os_version     = EXCLUDED.os_version,
			agent_version  = EXCLUDED.agent_version,
			ip_addresses   = EXCLUDED.ip_addresses,
			status         = CASE WHEN agents.status = 'isolated' THEN 'isolated' ELSE EXCLUDED.status END,
			last_seen      = NOW(),
			tls_thumbprint = EXCLUDED.tls_thumbprint,
			updated_at     = NOW()`,
		a.ID, a.Hostname, a.OSType, a.OSVersion, a.AgentVersion,
		a.IPAddresses, a.Status, a.TLSThumbprint,
	)
	return err
}

// UpdateLastSeen upserts the agent's last_seen timestamp and IP list.
// If the agent does not exist yet (e.g. not formally enrolled), it is
// auto-created with minimal info so it appears in the endpoint list.
// hostname is the real hostname if known; if empty the agent ID is used
// as a placeholder. On conflict, the hostname is only updated when the
// caller provides a real hostname (non-empty, not equal to the agent ID).
// normalizeOSType keeps only the values agents.os_type's CHECK constraint
// accepts. Agents report runtime.GOOS, which on an unsupported platform
// (freebsd, openbsd, …) would otherwise reach the UPDATE and fail the whole
// heartbeat with a constraint violation. Unknown values become "" so the caller
// treats them as "not reported" and preserves whatever is already stored.
func normalizeOSType(osType string) string {
	switch osType {
	case "windows", "linux", "darwin":
		return osType
	default:
		return ""
	}
}

// agentVersion, osVersion and osType are updated when non-empty.
// osType must be "linux", "windows" or "darwin" (the agents.os_type CHECK
// constraint); anything else is treated as unreported. An unreported osType
// falls back to "linux" for the INSERT branch only — on conflict the stored
// value is kept rather than overwritten with the fallback. Correcting os_type
// on conflict matters because a Windows host that first appeared via a
// heartbeat (no formal enrollment) was otherwise pinned to the fallback
// forever, showing up as Linux in the endpoint list.
// (migration 244 が特定エージェントの os_type を UUID 直書きで手当てしていたのは
//
//	この「後から正しく申告しても既存行が直らない」挙動が原因だった。)
func (s *AgentStore) UpdateLastSeen(ctx context.Context, agentID, hostname string, ips []string, agentVersion, osVersion, osType string) error {
	if hostname == "" {
		hostname = agentID
	}
	// os_type は 2 通りに使い分ける。
	//
	//   $7 (insertOSType): 新規行用。agents.os_type は NOT NULL + CHECK
	//     ('windows','linux','darwin') なので、未申告でも何か入れる必要がある。
	//   $6 (osType):       既存行の更新用。空なら現在値を保持する。
	osType = normalizeOSType(osType)
	insertOSType := osType
	if insertOSType == "" {
		insertOSType = "linux"
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO agents (id, hostname, os_type, ip_addresses, status, last_seen, enrolled_at, updated_at)
		VALUES ($1::uuid, $3, $7, $2::inet[], 'online', NOW(), NOW(), NOW())
		ON CONFLICT (id) DO UPDATE SET
			last_seen     = NOW(),
			hostname      = CASE WHEN $3 != $1::text THEN $3 ELSE agents.hostname END,
			ip_addresses  = $2::inet[],
			status        = CASE WHEN agents.status = 'isolated' THEN 'isolated' ELSE 'online' END,
			agent_version = CASE WHEN $4 != '' THEN $4 ELSE agents.agent_version END,
			os_version    = CASE WHEN $5 != '' THEN $5 ELSE agents.os_version END,
			os_type       = CASE WHEN $6 != '' THEN $6 ELSE agents.os_type END,
			updated_at    = NOW()`,
		agentID, ips, hostname, agentVersion, osVersion, osType, insertOSType,
	)
	return err
}

// UpdateProtectionMode records the agent's reported kernel-protection tier
// (enforce/observe/poll). No-op for empty mode or unknown agent. Kept separate
// from UpdateLastSeen so the heartbeat path can call it independently without
// changing that method's widely-used signature.
func (s *AgentStore) UpdateProtectionMode(ctx context.Context, agentID, mode string) error {
	if mode == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE agents SET protection_mode = $2, updated_at = NOW() WHERE id = $1::uuid`,
		agentID, mode)
	return err
}

// UpdateTelemetryMode records which collection mechanism the agent's sensors are
// actually running on (ebpf/poll/off). No-op for empty mode or unknown agent.
//
// Distinct from UpdateProtectionMode: that stores host capability, this stores
// what the agent ended up doing. An eBPF-capable host that degraded to polling
// reports protection_mode=observe alongside telemetry_mode=poll, and only the
// latter reveals that the endpoint is collecting blind. Empty is skipped so
// platforms that do not report a mode (Windows/macOS today) leave the column
// NULL rather than overwriting it with a misleading value.
func (s *AgentStore) UpdateTelemetryMode(ctx context.Context, agentID, mode string) error {
	if mode == "" {
		return nil
	}
	_, err := s.pool.Exec(ctx,
		`UPDATE agents SET telemetry_mode = $2, updated_at = NOW() WHERE id = $1::uuid`,
		agentID, mode)
	return err
}

// UpdateMetrics records the agent's reported CPU (%) and memory (MB) usage from
// its heartbeat. Kept separate from UpdateLastSeen (same rationale as
// UpdateProtectionMode) so the heartbeat path can call it without changing that
// method's widely-used signature. Powers the fleet health alerter.
func (s *AgentStore) UpdateMetrics(ctx context.Context, agentID string, cpuUsage, memoryUsageMB float64) error {
	_, err := s.pool.Exec(ctx,
		`UPDATE agents
		    SET cpu_usage = $2, memory_usage_mb = $3, metrics_updated_at = NOW()
		  WHERE id = $1::uuid`,
		agentID, cpuUsage, memoryUsageMB)
	return err
}

// ProtectionModeSummary returns a count of agents grouped by their reported
// kernel-protection tier. Agents that have not reported a mode (NULL — older
// agents or not-yet-seen) are bucketed under "unreported".
func (s *AgentStore) ProtectionModeSummary(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(protection_mode, ''), 'unreported') AS mode, COUNT(*)
		FROM agents
		GROUP BY 1`)
	if err != nil {
		return nil, fmt.Errorf("protection_mode summary: %w", err)
	}
	defer rows.Close()

	out := map[string]int{}
	for rows.Next() {
		var mode string
		var n int
		if err := rows.Scan(&mode, &n); err != nil {
			return nil, err
		}
		out[mode] = n
	}
	return out, rows.Err()
}

// ProtectionModeByOS returns protection-mode counts grouped by OS type so the
// fleet readiness can be broken down per platform (Linux eBPF LSM / Windows
// driver / macOS ESF report the same enforce/observe/poll tiers). Outer key is
// os_type ("unknown" when unset), inner key is the mode (with "unreported" for
// agents that have not reported one yet).
func (s *AgentStore) ProtectionModeByOS(ctx context.Context) (map[string]map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(os_type, ''), 'unknown') AS os,
		       COALESCE(NULLIF(protection_mode, ''), 'unreported') AS mode,
		       COUNT(*)
		FROM agents
		GROUP BY 1, 2`)
	if err != nil {
		return nil, fmt.Errorf("protection_mode by os: %w", err)
	}
	defer rows.Close()

	out := map[string]map[string]int{}
	for rows.Next() {
		var os, mode string
		var n int
		if err := rows.Scan(&os, &mode, &n); err != nil {
			return nil, err
		}
		if out[os] == nil {
			out[os] = map[string]int{}
		}
		out[os][mode] = n
	}
	return out, rows.Err()
}

// TelemetryModeByOS returns effective-collection-mode counts grouped by OS type.
// Same shape as ProtectionModeByOS, and meant to be read next to it: that one
// answers "could this fleet do in-kernel collection", this one answers "is it
// actually doing it". A Linux row with a large "poll" count on eBPF-capable
// hosts is the degradation this exists to surface.
//
// Inner key is the mode, with "unreported" covering both NULL and empty — today
// that is every Windows/macOS agent, since only the Linux collectors register a
// mode.
func (s *AgentStore) TelemetryModeByOS(ctx context.Context) (map[string]map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT COALESCE(NULLIF(os_type, ''), 'unknown') AS os,
		       COALESCE(NULLIF(telemetry_mode, ''), 'unreported') AS mode,
		       COUNT(*)
		FROM agents
		GROUP BY 1, 2`)
	if err != nil {
		return nil, fmt.Errorf("telemetry_mode by os: %w", err)
	}
	defer rows.Close()

	out := map[string]map[string]int{}
	for rows.Next() {
		var os, mode string
		var n int
		if err := rows.Scan(&os, &mode, &n); err != nil {
			return nil, err
		}
		if out[os] == nil {
			out[os] = map[string]int{}
		}
		out[os][mode] = n
	}
	return out, rows.Err()
}

// GetAgentByID retrieves a single agent.
// AnomalousAgent is one row of the UEBA behavioral-anomaly board.
type AnomalousAgent struct {
	AgentID    string  `json:"agent_id"`
	Hostname   string  `json:"hostname"`
	OSType     string  `json:"os_type"`
	MaxAnomaly float64 `json:"max_anomaly"` // peak anomaly_score (0–1) in window
	AvgAnomaly float64 `json:"avg_anomaly"`
	AlertCount int     `json:"alert_count"`
}

// AnomalousAgentsBoard returns the agents whose recent alerts (last 7 days) carry
// the highest behavioral-anomaly scores (UEBA + Isolation Forest, stamped onto
// alerts.anomaly_score by the detection engine), ordered by peak anomaly. This
// surfaces the previously-unused anomaly_score as a fleet UEBA risk board.
func (s *AgentStore) AnomalousAgentsBoard(ctx context.Context, limit int) ([]AnomalousAgent, error) {
	if limit <= 0 || limit > 100 {
		limit = 10
	}
	rows, err := s.pool.Query(ctx, `
		SELECT a.agent_id::text,
		       COALESCE(ag.hostname, ''),
		       COALESCE(ag.os_type, ''),
		       MAX(a.anomaly_score),
		       AVG(a.anomaly_score),
		       COUNT(*)
		FROM alerts a
		JOIN agents ag ON ag.id = a.agent_id
		WHERE a.anomaly_score > 0
		  AND a.created_at >= NOW() - INTERVAL '7 days'
		GROUP BY a.agent_id, ag.hostname, ag.os_type
		ORDER BY MAX(a.anomaly_score) DESC, COUNT(*) DESC
		LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("anomalous agents board: %w", err)
	}
	defer rows.Close()

	out := []AnomalousAgent{}
	for rows.Next() {
		var r AnomalousAgent
		if err := rows.Scan(&r.AgentID, &r.Hostname, &r.OSType, &r.MaxAnomaly, &r.AvgAnomaly, &r.AlertCount); err != nil {
			return nil, err
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *AgentStore) GetAgentByID(ctx context.Context, id string) (*AgentRow, error) {
	row := s.pool.QueryRow(ctx, `
		SELECT id, hostname, os_type,
			   COALESCE(os_version, ''), COALESCE(agent_version, ''),
			   COALESCE(ip_addresses::text[], '{}'), status, last_seen, enrolled_at,
			   group_id, policy_id, COALESCE(config_version, 0), tls_thumbprint,
			   COALESCE(tags, '{}'), isolated_at, isolated_reason, isolated_by
		FROM agents WHERE id = $1`, id)

	var a AgentRow
	err := row.Scan(
		&a.ID, &a.Hostname, &a.OSType, &a.OSVersion, &a.AgentVersion,
		&a.IPAddresses, &a.Status, &a.LastSeen, &a.EnrolledAt,
		&a.GroupID, &a.PolicyID, &a.ConfigVersion, &a.TLSThumbprint,
		&a.Tags, &a.IsolatedAt, &a.IsolatedReason, &a.IsolatedBy,
	)
	if err != nil {
		return nil, err
	}
	return &a, nil
}

// AgentBelongsToTenant reports whether the given agent exists AND belongs to
// tenantID. It is used as an application-layer defense-in-depth check on
// response-action endpoints (isolate/kill/quarantine/scan) so cross-tenant
// access is blocked even if PostgreSQL RLS is not (yet) enforcing — e.g. while
// the app still connects as a superuser/BYPASSRLS role, or for command paths
// that never touch the RLS-protected agents row. The explicit
// "AND tenant_id = $2" filter does not rely on RLS. An empty tenantID means
// single-tenant mode; callers should skip the check in that case.
func (s *AgentStore) AgentBelongsToTenant(ctx context.Context, agentID, tenantID string) (bool, error) {
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS(SELECT 1 FROM agents WHERE id = $1 AND tenant_id::text = $2)`,
		agentID, tenantID,
	).Scan(&exists)
	return exists, err
}

// IsolateAgent marks an agent as isolated and records the reason.
func (s *AgentStore) IsolateAgent(ctx context.Context, agentID, reason, by string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE agents
		SET status = 'isolated',
			isolated_at = NOW(),
			isolated_reason = $2,
			isolated_by = $3,
			updated_at = NOW()
		WHERE id = $1`,
		agentID, reason, by,
	)
	return err
}

// DeleteAgent permanently removes an agent record.
func (s *AgentStore) DeleteAgent(ctx context.Context, id string) error {
	tag, err := s.pool.Exec(ctx, "DELETE FROM agents WHERE id = $1", id)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("エージェントが見つかりません")
	}
	return nil
}

// UpdateAgentMeta updates an agent's tags and group assignment.
func (s *AgentStore) UpdateAgentMeta(ctx context.Context, id string, tags []string, groupID *string) error {
	if tags == nil {
		tags = []string{}
	}
	_, err := s.pool.Exec(ctx, `
		UPDATE agents SET tags = $2, group_id = $3, updated_at = NOW()
		WHERE id = $1`,
		id, tags, groupID,
	)
	return err
}

// UnisolateAgent restores normal agent status.
func (s *AgentStore) UnisolateAgent(ctx context.Context, agentID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE agents
		SET status = 'online',
			isolated_at = NULL,
			isolated_reason = NULL,
			isolated_by = NULL,
			updated_at = NOW()
		WHERE id = $1`,
		agentID,
	)
	return err
}

// ListAgents returns all agents with optional filtering.
func (s *AgentStore) ListAgents(ctx context.Context, filter AgentFilter) ([]*AgentRow, int, error) {
	var conditions []string
	var args []interface{}
	i := 1

	if filter.OSType != "" {
		conditions = append(conditions, fmt.Sprintf("os_type = $%d", i))
		args = append(args, filter.OSType)
		i++
	}
	if filter.Status != "" {
		conditions = append(conditions, fmt.Sprintf("status = $%d", i))
		args = append(args, filter.Status)
		i++
	}
	if filter.GroupID != "" {
		conditions = append(conditions, fmt.Sprintf("group_id = $%d", i))
		args = append(args, filter.GroupID)
		i++
	}
	if filter.Search != "" {
		conditions = append(conditions, fmt.Sprintf(
			"(hostname ILIKE $%d OR EXISTS (SELECT 1 FROM unnest(ip_addresses) ip WHERE ip::text ILIKE $%d))",
			i, i,
		))
		args = append(args, "%"+filter.Search+"%")
		i++
	}

	where := ""
	if len(conditions) > 0 {
		where = "WHERE " + strings.Join(conditions, " AND ")
	}

	var total int
	if err := s.pool.QueryRow(ctx, "SELECT COUNT(*) FROM agents "+where, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	listQuery := `
		SELECT id, hostname, os_type,
			   COALESCE(os_version, ''), COALESCE(agent_version, ''),
			   COALESCE(ip_addresses::text[], '{}'), status, last_seen, enrolled_at,
			   group_id, policy_id, COALESCE(config_version, 0), tls_thumbprint,
			   COALESCE(tags, '{}'), isolated_at, isolated_reason, isolated_by
		FROM agents ` + where + `
		ORDER BY last_seen DESC NULLS LAST
		LIMIT $` + fmt.Sprintf("%d", i) + ` OFFSET $` + fmt.Sprintf("%d", i+1)

	args = append(args, filter.Limit, filter.Offset)
	rows, err := s.pool.Query(ctx, listQuery, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var agents []*AgentRow
	for rows.Next() {
		var a AgentRow
		if err := rows.Scan(
			&a.ID, &a.Hostname, &a.OSType, &a.OSVersion, &a.AgentVersion,
			&a.IPAddresses, &a.Status, &a.LastSeen, &a.EnrolledAt,
			&a.GroupID, &a.PolicyID, &a.ConfigVersion, &a.TLSThumbprint,
			&a.Tags, &a.IsolatedAt, &a.IsolatedReason, &a.IsolatedBy,
		); err != nil {
			return nil, 0, fmt.Errorf("agents scan: %w", err)
		}
		agents = append(agents, &a)
	}

	return agents, total, nil
}

// ExpiringAgentRow holds the subset of agent fields needed by the cert renewer.
type ExpiringAgentRow struct {
	ID           string
	Hostname     string
	CertNotAfter time.Time
}

// ListExpiringAgents returns agents whose cert expires within the given number of days.
func (s *AgentStore) ListExpiringAgents(ctx context.Context, withinDays int) ([]*ExpiringAgentRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id::text, hostname, cert_not_after
		FROM agents
		WHERE cert_not_after IS NOT NULL
		  AND cert_not_after < NOW() + make_interval(days => $1)
		  -- 'inactive'(30日以上未確認の退役扱い)も 'offline' 同様に対象外。
		  -- 戻ってこないホストの証明書失効を警告し続けても意味がない。
		  AND status NOT IN ('offline', 'inactive')
		ORDER BY cert_not_after`,
		withinDays,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*ExpiringAgentRow
	for rows.Next() {
		var r ExpiringAgentRow
		if err := rows.Scan(&r.ID, &r.Hostname, &r.CertNotAfter); err != nil {
			continue
		}
		out = append(out, &r)
	}
	return out, nil
}

// UpdateCertExpiry stores the cert expiry date for an agent.
func (s *AgentStore) UpdateCertExpiry(ctx context.Context, agentID string, notAfter time.Time) error {
	_, err := s.pool.Exec(ctx,
		"UPDATE agents SET cert_not_after = $2, updated_at = NOW() WHERE id = $1",
		agentID, notAfter,
	)
	return err
}

// SetRenewalToken stores a one-time renewal token for an agent, valid for ttl duration.
func (s *AgentStore) SetRenewalToken(ctx context.Context, agentID, token string, ttl time.Duration) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE agents
		SET cert_renewal_token = $2,
		    cert_renewal_expires = NOW() + $3::INTERVAL,
		    updated_at = NOW()
		WHERE id = $1`,
		agentID, token, ttl.String(),
	)
	return err
}

// consumeRenewalToken atomically validates and clears the renewal token.
// Returns an error if the token is missing, expired, or does not match.
func (s *AgentStore) consumeRenewalToken(ctx context.Context, agentID, token string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE agents
		SET cert_renewal_token = NULL,
		    cert_renewal_expires = NULL,
		    updated_at = NOW()
		WHERE id = $1
		  AND cert_renewal_token = $2
		  AND cert_renewal_expires > NOW()`,
		agentID, token,
	)
	if err != nil {
		return fmt.Errorf("renewal token DB error: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("無効または期限切れの更新トークンです")
	}
	return nil
}

// SignCSR verifies the enrollment token and signs the agent's CSR with the server CA.
// If enrollToken starts with "renew:", the remainder is treated as a one-time renewal
// token issued by the cert renewer scheduler. The token is validated against the DB and
// consumed atomically; a fresh certificate is then signed for the same agentID.
func (s *AgentStore) SignCSR(ctx context.Context, enrollToken, agentID, csrPEM string) (signedCert, caCert string, err error) {
	// ─── Verify enrollment token ───────────────────────────────
	if strings.HasPrefix(enrollToken, "renew:") {
		renewalToken := strings.TrimPrefix(enrollToken, "renew:")
		if err := s.consumeRenewalToken(ctx, agentID, renewalToken); err != nil {
			return "", "", fmt.Errorf("証明書更新トークン検証失敗: %w", err)
		}
	} else {
		var storedToken string
		err = s.pool.QueryRow(ctx,
			"SELECT value FROM settings WHERE key = 'enrollment_token'",
		).Scan(&storedToken)
		if err != nil {
			return "", "", fmt.Errorf("トークン検証失敗: %w", err)
		}
		if storedToken != enrollToken {
			return "", "", fmt.Errorf("無効な登録トークンです")
		}
	}

	// ─── Load CA certificate and key ──────────────────────────
	caCertFile := os.Getenv("CA_CERT_FILE")
	caKeyFile := os.Getenv("CA_KEY_FILE")
	if caCertFile == "" {
		caCertFile = "/certs/ca.crt"
	}
	if caKeyFile == "" {
		caKeyFile = "/certs/ca.key"
	}

	caCertPEM, err := os.ReadFile(caCertFile)
	if err != nil {
		return "", "", fmt.Errorf("CA証明書の読み込みに失敗しました: %w", err)
	}
	caKeyPEM, err := os.ReadFile(caKeyFile)
	if err != nil {
		return "", "", fmt.Errorf("CA秘密鍵の読み込みに失敗しました: %w", err)
	}

	// Parse CA certificate
	caCertBlock, _ := pem.Decode(caCertPEM)
	if caCertBlock == nil {
		return "", "", fmt.Errorf("CA証明書のデコードに失敗しました")
	}
	caX509, err := x509.ParseCertificate(caCertBlock.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("CA証明書のパースに失敗しました: %w", err)
	}

	// Parse CA private key
	caKeyBlock, _ := pem.Decode(caKeyPEM)
	if caKeyBlock == nil {
		return "", "", fmt.Errorf("CA秘密鍵のデコードに失敗しました")
	}
	caKey, err := x509.ParsePKCS8PrivateKey(caKeyBlock.Bytes)
	if err != nil {
		// Try PKCS1 format
		caKey, err = x509.ParsePKCS1PrivateKey(caKeyBlock.Bytes)
		if err != nil {
			return "", "", fmt.Errorf("CA秘密鍵のパースに失敗しました: %w", err)
		}
	}

	// ─── Parse agent CSR ──────────────────────────────────────
	csrBlock, _ := pem.Decode([]byte(csrPEM))
	if csrBlock == nil {
		return "", "", fmt.Errorf("CSRのデコードに失敗しました")
	}
	agentCSR, err := x509.ParseCertificateRequest(csrBlock.Bytes)
	if err != nil {
		return "", "", fmt.Errorf("CSRのパースに失敗しました: %w", err)
	}
	if err := agentCSR.CheckSignature(); err != nil {
		return "", "", fmt.Errorf("CSRの署名検証に失敗しました: %w", err)
	}

	// ─── Sign the CSR ─────────────────────────────────────────
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", "", fmt.Errorf("シリアル番号の生成に失敗しました: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   agentID, // Agent ID is the CN — used for auth in EventStream
			Organization: []string{"EDR Agent"},
		},
		NotBefore:             time.Now().Add(-1 * time.Minute),
		NotAfter:              time.Now().Add(5 * 365 * 24 * time.Hour), // 5 years
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caX509, agentCSR.PublicKey, caKey)
	if err != nil {
		return "", "", fmt.Errorf("証明書の署名に失敗しました: %w", err)
	}

	signedCertPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER}))
	return signedCertPEM, string(caCertPEM), nil
}

type AgentFilter struct {
	OSType  string
	Status  string
	GroupID string
	Search  string
	Limit   int
	Offset  int
}

// ─── Agent Groups ──────────────────────────────────────────────

type AgentGroup struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	AgentCount  int       `json:"agent_count"`
	CreatedAt   time.Time `json:"created_at"`
}

func (s *AgentStore) ListGroups(ctx context.Context) ([]*AgentGroup, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT ag.id, ag.name, ag.description, ag.created_at,
		       COUNT(a.id) AS agent_count
		FROM agent_groups ag
		LEFT JOIN agents a ON a.group_id = ag.id
		GROUP BY ag.id
		ORDER BY ag.name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var groups []*AgentGroup
	for rows.Next() {
		var g AgentGroup
		if err := rows.Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt, &g.AgentCount); err != nil {
			continue
		}
		groups = append(groups, &g)
	}
	return groups, nil
}

func (s *AgentStore) CreateGroup(ctx context.Context, name, description string) (*AgentGroup, error) {
	var g AgentGroup
	err := s.pool.QueryRow(ctx, `
		INSERT INTO agent_groups (name, description)
		VALUES ($1, $2)
		RETURNING id, name, description, created_at`,
		name, description,
	).Scan(&g.ID, &g.Name, &g.Description, &g.CreatedAt)
	if err != nil {
		return nil, err
	}
	return &g, nil
}

func (s *AgentStore) UpdateGroup(ctx context.Context, id, name, description string) error {
	tag, err := s.pool.Exec(ctx, `
		UPDATE agent_groups SET name = $2, description = $3
		WHERE id = $1`,
		id, name, description,
	)
	if err != nil {
		return err
	}
	if tag.RowsAffected() == 0 {
		return fmt.Errorf("グループが見つかりません")
	}
	return nil
}

func (s *AgentStore) DeleteGroup(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, "DELETE FROM agent_groups WHERE id = $1", id)
	return err
}

// ResolveAgentOfflineAlerts resolves any open "agent offline" alerts for the
// given agent. Called when a heartbeat is received so stale offline alerts are
// automatically closed when the agent comes back online.
func (s *AgentStore) ResolveAgentOfflineAlerts(ctx context.Context, agentID string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE alerts
		SET status = 'resolved', updated_at = NOW()
		WHERE agent_id = $1
		  AND title LIKE '%オフライン%'
		  AND status = 'open'`,
		agentID,
	)
	return err
}
