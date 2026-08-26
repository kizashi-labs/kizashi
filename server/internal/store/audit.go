package store

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// AuditLog represents a single admin/mutation action.
type AuditLog struct {
	ID         string                 `json:"id"`
	Timestamp  time.Time              `json:"timestamp"`
	UserID     string                 `json:"user_id"`
	UserEmail  string                 `json:"user_email"`
	Action     string                 `json:"action"`
	ResourceID string                 `json:"resource_id,omitempty"`
	IPAddress  string                 `json:"ip_address,omitempty"`
	StatusCode int                    `json:"status_code"`
	Details    map[string]interface{} `json:"details,omitempty"`
}

// AuditStore handles audit log DB operations.
type AuditStore struct {
	pool *pgxpool.Pool
}

func NewAuditStore(db *DB) *AuditStore {
	return &AuditStore{pool: db.Pool()}
}

// Insert persists an audit log entry (non-blocking; caller may use a goroutine).
func (s *AuditStore) Insert(ctx context.Context, entry *AuditLog) error {
	var detailsVal interface{}
	if entry.Details != nil {
		b, _ := json.Marshal(entry.Details)
		if len(b) > 0 {
			detailsVal = string(b)
		}
	}
	_, err := s.pool.Exec(ctx, `
		INSERT INTO audit_logs
		       (user_id, user_email, action, resource_id, ip_address, status_code, details)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		entry.UserID,
		entry.UserEmail,
		entry.Action,
		entry.ResourceID,
		entry.IPAddress,
		entry.StatusCode,
		detailsVal,
	)
	return err
}

// AuditFilter holds optional filters for listing audit logs.
type AuditFilter struct {
	UserID     string // exact match on user_id
	UserEmail  string // partial match on user_email
	Action     string // exact match on action (e.g. "login")
	Method     string // HTTP method prefix: GET, POST, PUT, DELETE
	OnlyErrors bool   // only status_code >= 400
}

// List returns audit logs newest-first with pagination and optional filters.
// auditListWhere builds the WHERE clause and arguments for List.
//
// **切り出してあるのは、検査が本物を呼べるようにするためです。**
// 公開はしません —— `List` からしか使わないので、公開すると
// `TestStoreSymbolsAreReachable` の数が1つ増えます。
// 検査ファイルには `buildAuditWhere` という写しが置いてありましたが、
// **`UserID` と `Action` の絞り込みがありません** —— 5つのうち2つが、
// 写しには存在しないまま「確かめた」ことになっていました。
func auditListWhere(f AuditFilter) (string, []interface{}) {
	conds := []string{"1=1"}
	args := []interface{}{}

	if f.UserID != "" {
		conds = append(conds, fmt.Sprintf("user_id = $%d", len(args)+1))
		args = append(args, f.UserID)
	}
	if f.UserEmail != "" {
		// 書き込み時の user_email は空なので、読むときに解決した email
		// （users との JOIN）に対しても効かせる。呼び出し側の FROM 句は
		// `audit_logs a LEFT JOIN users u` である前提。
		conds = append(conds, fmt.Sprintf("COALESCE(NULLIF(a.user_email,''), u.email, '') ILIKE $%d", len(args)+1))
		args = append(args, "%"+f.UserEmail+"%")
	}
	if f.Action != "" {
		conds = append(conds, fmt.Sprintf("action = $%d", len(args)+1))
		args = append(args, f.Action)
	}
	if f.Method != "" {
		conds = append(conds, fmt.Sprintf("action ILIKE $%d", len(args)+1))
		args = append(args, f.Method+"%")
	}
	if f.OnlyErrors {
		// **値を取らない条件です。** 番号は進めません。
		conds = append(conds, "status_code >= 400")
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

func (s *AuditStore) List(ctx context.Context, limit, offset int, f AuditFilter) ([]*AuditLog, int, error) {
	where, args := auditListWhere(f)
	idx := len(args) + 1

	var total int
	countArgs := make([]interface{}, len(args))
	copy(countArgs, args)
	if err := s.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM audit_logs a LEFT JOIN users u ON u.id::text = a.user_id "+where,
		countArgs...).Scan(&total); err != nil {
		return nil, 0, err
	}

	args = append(args, limit, offset)
	// user_email は書き込み時に埋まらない（HTTP middleware はコンテキストに email を
	// 持たない）ので、**読むときに users から引く**。過去の行にも効く。
	// user_id は TEXT で、env フォールバック時代の 'admin' など UUID でない値も
	// 入っているため、u.id::text と突き合わせる。
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT a.id, a.timestamp, COALESCE(a.user_id,''),
		       COALESCE(NULLIF(a.user_email,''), u.email, ''),
		       a.action, COALESCE(a.resource_id,''), COALESCE(a.ip_address,''),
		       a.status_code, COALESCE(a.details,'{}')
		FROM audit_logs a
		LEFT JOIN users u ON u.id::text = a.user_id
		%s
		ORDER BY a.timestamp DESC
		LIMIT $%d OFFSET $%d`, where, idx, idx+1),
		args...,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var logs []*AuditLog
	for rows.Next() {
		var l AuditLog
		var detailsJSON string
		if err := rows.Scan(
			&l.ID, &l.Timestamp, &l.UserID, &l.UserEmail,
			&l.Action, &l.ResourceID, &l.IPAddress,
			&l.StatusCode, &detailsJSON,
		); err != nil {
			continue
		}
		_ = json.Unmarshal([]byte(detailsJSON), &l.Details)
		logs = append(logs, &l)
	}
	// 部分結果を完全な一覧として返さない（scan_truncation_guard_test.go 参照）
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return logs, total, nil
}
