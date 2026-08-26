package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Vulnerability represents a tracked CVE on an endpoint.
type Vulnerability struct {
	ID              string    `json:"id"`
	AgentID         *string   `json:"agent_id,omitempty"`
	AgentHostname   string    `json:"agent_hostname,omitempty"`
	CVEID           string    `json:"cve_id"`
	Title           string    `json:"title"`
	Description     string    `json:"description,omitempty"`
	Severity        string    `json:"severity"` // critical|high|medium|low
	CVSSScore       *float64  `json:"cvss_score,omitempty"`
	AffectedPackage string    `json:"affected_package,omitempty"`
	AffectedVersion string    `json:"affected_version,omitempty"`
	FixedVersion    string    `json:"fixed_version,omitempty"`
	Status          string    `json:"status"` // open|mitigated|patched|accepted
	DetectedAt      time.Time `json:"detected_at"`
	UpdatedAt       time.Time `json:"updated_at"`
	Notes           string    `json:"notes,omitempty"`
}

// VulnFilter controls listing.
type VulnFilter struct {
	AgentID  string
	Severity string
	Status   string
	Search   string
	Limit    int
	Offset   int
}

// VulnStore manages vulnerability persistence.
type VulnStore struct {
	pool *pgxpool.Pool
}

func NewVulnStore(db *DB) *VulnStore {
	return &VulnStore{pool: db.Pool()}
}

// vulnListWhere builds the WHERE clause and arguments for List.
//
// **切り出してあるのは、検査が本物を呼べるようにするためです。**
// 検査ファイルには同じ組み立ての写しが置いてあり、そちらだけが試されて
// いました。公開はしません —— `List` からしか使わないので、公開すると
// `TestStoreSymbolsAreReachable` の数が増えます。
func vulnListWhere(f VulnFilter) (string, []interface{}) {
	where := "WHERE 1=1"
	args := []interface{}{}
	i := 1

	if f.AgentID != "" {
		where += fmt.Sprintf(" AND v.agent_id = $%d::uuid", i)
		args = append(args, f.AgentID)
		i++
	}
	if f.Severity != "" {
		where += fmt.Sprintf(" AND v.severity = $%d", i)
		args = append(args, f.Severity)
		i++
	}
	if f.Status != "" {
		where += fmt.Sprintf(" AND v.status = $%d", i)
		args = append(args, f.Status)
		i++
	}
	if f.Search != "" {
		where += fmt.Sprintf(" AND (v.cve_id ILIKE $%d OR v.title ILIKE $%d OR v.affected_package ILIKE $%d)", i, i, i)
		args = append(args, "%"+f.Search+"%")
		i++
	}

	return where, args
}

// clampVulnLimit は件数を 1〜200 に収めます。
//
// **この救済は `vulnListWhere` の中に書いてありました。** あの関数は
// `VulnFilter` を値で受け取るので、`f.Limit = 50` は写しの上に書かれ、
// 呼び出し側には届きません。実測 (2026-08-12):
// `/api/v1/vulnerabilities?per_page=0` は **200 の 0 件**で、
// `total` だけが 120 と出ていました —— 救済があるように見えて、
// 効いていませんでした。
func clampVulnLimit(limit int) int {
	if limit < 1 || limit > maxVulnLimit {
		return defaultVulnLimit
	}
	return limit
}

const (
	defaultVulnLimit = 50
	maxVulnLimit     = 200
)

func (s *VulnStore) List(ctx context.Context, f VulnFilter) ([]*Vulnerability, int, error) {
	f.Limit = clampVulnLimit(f.Limit)
	where, args := vulnListWhere(f)
	i := len(args) + 1

	var total int
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	err := s.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM vulnerabilities v "+where, countArgs...,
	).Scan(&total)
	if err != nil {
		return nil, 0, err
	}

	args = append(args, f.Limit, f.Offset)
	rows, err := s.pool.Query(ctx, `
		SELECT v.id, v.agent_id::text, COALESCE(a.hostname,''),
		       v.cve_id, v.title, COALESCE(v.description,''),
		       v.severity, v.cvss_score,
		       COALESCE(v.affected_package,''), COALESCE(v.affected_version,''), COALESCE(v.fixed_version,''),
		       v.status, v.detected_at, v.updated_at, COALESCE(v.notes,'')
		FROM vulnerabilities v
		LEFT JOIN agents a ON a.id = v.agent_id
		`+where+fmt.Sprintf(`
		ORDER BY
		  CASE v.severity WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
		  v.detected_at DESC
		LIMIT $%d OFFSET $%d`, i, i+1),
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var vulns []*Vulnerability
	for rows.Next() {
		v := &Vulnerability{}
		var agentID *string
		if err := rows.Scan(
			&v.ID, &agentID, &v.AgentHostname,
			&v.CVEID, &v.Title, &v.Description,
			&v.Severity, &v.CVSSScore,
			&v.AffectedPackage, &v.AffectedVersion, &v.FixedVersion,
			&v.Status, &v.DetectedAt, &v.UpdatedAt, &v.Notes,
		); err != nil {
			continue
		}
		v.AgentID = agentID
		vulns = append(vulns, v)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if vulns == nil {
		vulns = []*Vulnerability{}
	}
	return vulns, total, nil
}

func agentIDArg(s *string) interface{} {
	if s == nil || *s == "" {
		return nil
	}
	return *s
}

func (s *VulnStore) Insert(ctx context.Context, v *Vulnerability) (string, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO vulnerabilities
		  (agent_id, cve_id, title, description, severity, cvss_score,
		   affected_package, affected_version, fixed_version, status, notes)
		VALUES ($1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id`,
		agentIDArg(v.AgentID),
		v.CVEID, v.Title, v.Description, v.Severity, v.CVSSScore,
		v.AffectedPackage, v.AffectedVersion, v.FixedVersion,
		v.Status, v.Notes,
	).Scan(&id)
	return id, err
}

func (s *VulnStore) UpdateStatus(ctx context.Context, id, status, notes string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE vulnerabilities
		SET status=$2, notes=$3, updated_at=NOW()
		WHERE id=$1`,
		id, status, notes,
	)
	return err
}

func (s *VulnStore) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx,
		"DELETE FROM vulnerabilities WHERE id=$1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}

// Get returns a single vulnerability by ID.
func (s *VulnStore) Get(ctx context.Context, id string) (*Vulnerability, error) {
	v := &Vulnerability{}
	var agentID *string
	err := s.pool.QueryRow(ctx, `
		SELECT v.id, v.agent_id::text, COALESCE(a.hostname,''),
		       v.cve_id, v.title, COALESCE(v.description,''),
		       v.severity, v.cvss_score,
		       COALESCE(v.affected_package,''), COALESCE(v.affected_version,''), COALESCE(v.fixed_version,''),
		       v.status, v.detected_at, v.updated_at, COALESCE(v.notes,'')
		FROM vulnerabilities v
		LEFT JOIN agents a ON a.id = v.agent_id
		WHERE v.id = $1`, id,
	).Scan(
		&v.ID, &agentID, &v.AgentHostname,
		&v.CVEID, &v.Title, &v.Description,
		&v.Severity, &v.CVSSScore,
		&v.AffectedPackage, &v.AffectedVersion, &v.FixedVersion,
		&v.Status, &v.DetectedAt, &v.UpdatedAt, &v.Notes,
	)
	if err != nil {
		return nil, err
	}
	v.AgentID = agentID
	return v, nil
}

// Stats returns severity breakdown counts.
func (s *VulnStore) Stats(ctx context.Context) (map[string]int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT severity, COUNT(*) FROM vulnerabilities
		WHERE status = 'open'
		GROUP BY severity`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := map[string]int{"critical": 0, "high": 0, "medium": 0, "low": 0}
	for rows.Next() {
		var sev string
		var cnt int
		if err := rows.Scan(&sev, &cnt); err == nil {
			out[sev] = cnt
		}
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}
