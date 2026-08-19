package support

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// Ticket はサポートチケットの1行。
type Ticket struct {
	ID             string     `json:"id"`
	TenantID       *string    `json:"tenant_id,omitempty"`
	CreatedBy      *string    `json:"created_by,omitempty"`
	CreatedByName  string     `json:"created_by_name,omitempty"`
	AssignedTo     *string    `json:"assigned_to,omitempty"`
	AssignedToName string     `json:"assigned_to_name,omitempty"`
	Title          string     `json:"title"`
	Description    string     `json:"description"`
	Category       string     `json:"category"`
	Priority       string     `json:"priority"`
	Status         string     `json:"status"`
	CommentCount   int        `json:"comment_count"`
	ResolvedAt     *time.Time `json:"resolved_at,omitempty"`
	ClosedAt       *time.Time `json:"closed_at,omitempty"`
	CreatedAt      time.Time  `json:"created_at"`
	UpdatedAt      time.Time  `json:"updated_at"`
}

// Comment はチケットコメントの1行。
type Comment struct {
	ID         string    `json:"id"`
	TicketID   string    `json:"ticket_id"`
	AuthorID   *string   `json:"author_id,omitempty"`
	AuthorName string    `json:"author_name,omitempty"`
	Body       string    `json:"body"`
	IsInternal bool      `json:"is_internal"`
	CreatedAt  time.Time `json:"created_at"`
}

// TicketFilter はチケット一覧の絞り込み条件。
type TicketFilter struct {
	Status   string
	Priority string
	Category string
	Search   string
}

// Store はサポートチケット関連の DB 操作をまとめる。
type Store struct {
	pool *pgxpool.Pool
}

// NewStore は Store を返す。
func NewStore(pool *pgxpool.Pool) *Store {
	return &Store{pool: pool}
}

// ─── チケット CRUD ────────────────────────────────────────────────────────────

// ListTickets はフィルタに従いチケット一覧を返す。
func (s *Store) ListTickets(ctx context.Context, f TicketFilter, isAdmin bool, userID string) ([]*Ticket, error) {
	where := "WHERE 1=1"
	args := []any{}
	n := 1

	if !isAdmin {
		where += " AND t.created_by = $1"
		args = append(args, userID)
		n++
	}
	if f.Status != "" {
		where += " AND t.status = $" + itoa(n)
		args = append(args, f.Status)
		n++
	}
	if f.Priority != "" {
		where += " AND t.priority = $" + itoa(n)
		args = append(args, f.Priority)
		n++
	}
	if f.Category != "" {
		where += " AND t.category = $" + itoa(n)
		args = append(args, f.Category)
		n++
	}
	if f.Search != "" {
		where += " AND (t.title ILIKE $" + itoa(n) + " OR t.description ILIKE $" + itoa(n) + ")"
		args = append(args, "%"+f.Search+"%")
	}

	rows, err := s.pool.Query(ctx, `
		SELECT t.id, t.tenant_id, t.created_by,
		       COALESCE(cu.full_name, cu.email, '不明') AS created_by_name,
		       t.assigned_to,
		       COALESCE(au.full_name, au.email, '') AS assigned_to_name,
		       t.title, t.description, t.category::text, t.priority::text, t.status::text,
		       (SELECT COUNT(*) FROM ticket_comments c WHERE c.ticket_id = t.id) AS comment_count,
		       t.resolved_at, t.closed_at, t.created_at, t.updated_at
		FROM support_tickets t
		LEFT JOIN users cu ON cu.id = t.created_by
		LEFT JOIN users au ON au.id = t.assigned_to
		`+where+`
		ORDER BY
		  CASE t.priority WHEN 'critical' THEN 1 WHEN 'high' THEN 2 WHEN 'medium' THEN 3 ELSE 4 END,
		  t.updated_at DESC`,
		args...,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Ticket
	for rows.Next() {
		tk := &Ticket{}
		if err := rows.Scan(
			&tk.ID, &tk.TenantID, &tk.CreatedBy, &tk.CreatedByName,
			&tk.AssignedTo, &tk.AssignedToName,
			&tk.Title, &tk.Description, &tk.Category, &tk.Priority, &tk.Status,
			&tk.CommentCount, &tk.ResolvedAt, &tk.ClosedAt, &tk.CreatedAt, &tk.UpdatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, tk)
	}
	return out, rows.Err()
}

// GetTicket は ID でチケットを取得する。
func (s *Store) GetTicket(ctx context.Context, id string) (*Ticket, error) {
	tk := &Ticket{}
	err := s.pool.QueryRow(ctx, `
		SELECT t.id, t.tenant_id, t.created_by,
		       COALESCE(cu.full_name, cu.email, '不明') AS created_by_name,
		       t.assigned_to,
		       COALESCE(au.full_name, au.email, '') AS assigned_to_name,
		       t.title, t.description, t.category::text, t.priority::text, t.status::text,
		       (SELECT COUNT(*) FROM ticket_comments c WHERE c.ticket_id = t.id) AS comment_count,
		       t.resolved_at, t.closed_at, t.created_at, t.updated_at
		FROM support_tickets t
		LEFT JOIN users cu ON cu.id = t.created_by
		LEFT JOIN users au ON au.id = t.assigned_to
		WHERE t.id = $1`, id,
	).Scan(
		&tk.ID, &tk.TenantID, &tk.CreatedBy, &tk.CreatedByName,
		&tk.AssignedTo, &tk.AssignedToName,
		&tk.Title, &tk.Description, &tk.Category, &tk.Priority, &tk.Status,
		&tk.CommentCount, &tk.ResolvedAt, &tk.ClosedAt, &tk.CreatedAt, &tk.UpdatedAt,
	)
	if err != nil {
		return nil, err
	}
	return tk, nil
}

// CreateTicket は新規チケットを作成する。
func (s *Store) CreateTicket(ctx context.Context, tk *Ticket) (*Ticket, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO support_tickets (tenant_id, created_by, title, description, category, priority)
		VALUES ($1, $2, $3, $4, $5::ticket_category, $6::ticket_priority)
		RETURNING id`,
		tk.TenantID, tk.CreatedBy, tk.Title, tk.Description, tk.Category, tk.Priority,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	return s.GetTicket(ctx, id)
}

// UpdateTicket はチケットのステータス・優先度・担当者を更新する。
func (s *Store) UpdateTicket(ctx context.Context, id string, status, priority string, assignedTo *string) (*Ticket, error) {
	q := `UPDATE support_tickets SET updated_at = NOW()`
	args := []any{}
	n := 1

	if status != "" {
		q += ", status = $" + itoa(n) + "::ticket_status"
		args = append(args, status)
		n++
		if status == "resolved" {
			q += ", resolved_at = NOW()"
		} else if status == "closed" {
			q += ", closed_at = NOW()"
		}
	}
	if priority != "" {
		q += ", priority = $" + itoa(n) + "::ticket_priority"
		args = append(args, priority)
		n++
	}
	if assignedTo != nil {
		q += ", assigned_to = $" + itoa(n)
		args = append(args, *assignedTo)
		n++
	}

	args = append(args, id)
	q += " WHERE id = $" + itoa(n)

	if _, err := s.pool.Exec(ctx, q, args...); err != nil {
		return nil, err
	}
	return s.GetTicket(ctx, id)
}

// ─── コメント ─────────────────────────────────────────────────────────────────

// ListComments はチケットのコメント一覧を返す。
func (s *Store) ListComments(ctx context.Context, ticketID string, includeInternal bool) ([]*Comment, error) {
	where := "WHERE c.ticket_id = $1"
	if !includeInternal {
		where += " AND c.is_internal = FALSE"
	}
	rows, err := s.pool.Query(ctx, `
		SELECT c.id, c.ticket_id, c.author_id,
		       COALESCE(u.full_name, u.email, 'サポート') AS author_name,
		       c.body, c.is_internal, c.created_at
		FROM ticket_comments c
		LEFT JOIN users u ON u.id = c.author_id
		`+where+`
		ORDER BY c.created_at ASC`,
		ticketID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var out []*Comment
	for rows.Next() {
		cm := &Comment{}
		if err := rows.Scan(&cm.ID, &cm.TicketID, &cm.AuthorID, &cm.AuthorName,
			&cm.Body, &cm.IsInternal, &cm.CreatedAt,
		); err != nil {
			return nil, err
		}
		out = append(out, cm)
	}
	return out, rows.Err()
}

// AddComment はコメントを追加する。
func (s *Store) AddComment(ctx context.Context, cm *Comment) (*Comment, error) {
	var id string
	err := s.pool.QueryRow(ctx, `
		INSERT INTO ticket_comments (ticket_id, author_id, body, is_internal)
		VALUES ($1, $2, $3, $4) RETURNING id`,
		cm.TicketID, cm.AuthorID, cm.Body, cm.IsInternal,
	).Scan(&id)
	if err != nil {
		return nil, err
	}
	cm.ID = id
	return cm, nil
}

// ─── 統計 ─────────────────────────────────────────────────────────────────────

// Stats はチケット統計を返す。
type Stats struct {
	Open        int     `json:"open"`
	InProgress  int     `json:"in_progress"`
	Resolved    int     `json:"resolved"`
	Closed      int     `json:"closed"`
	Critical    int     `json:"critical"`
	High        int     `json:"high"`
	AvgResolveh float64 `json:"avg_resolve_hours"`
}

// GetStats はステータス別チケット数を返す。
func (s *Store) GetStats(ctx context.Context) (*Stats, error) {
	st := &Stats{}
	if err := s.pool.QueryRow(ctx, `
			SELECT
			  COUNT(*) FILTER (WHERE status = 'open')        AS open,
			  COUNT(*) FILTER (WHERE status = 'in_progress') AS in_progress,
			  COUNT(*) FILTER (WHERE status = 'resolved')    AS resolved,
			  COUNT(*) FILTER (WHERE status = 'closed')      AS closed,
			  COUNT(*) FILTER (WHERE priority = 'critical')  AS critical,
			  COUNT(*) FILTER (WHERE priority = 'high')      AS high,
			  COALESCE(AVG(EXTRACT(EPOCH FROM (resolved_at - created_at))/3600)
			    FILTER (WHERE resolved_at IS NOT NULL), 0)   AS avg_resolve_hours
			FROM support_tickets`,
	).Scan(&st.Open, &st.InProgress, &st.Resolved, &st.Closed,
		&st.Critical, &st.High, &st.AvgResolveh); err != nil {
		return nil, fmt.Errorf("数えられませんでした: %w", err)
	}
	return st, nil
}

func itoa(n int) string {
	return string(rune('0' + n)) // 1〜9 の範囲で十分
}
