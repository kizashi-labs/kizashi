package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// IPBlockEntry represents a single IP/CIDR block or allow-list entry.
type IPBlockEntry struct {
	ID          string     `json:"id"`
	IPOrCIDR    string     `json:"ip_or_cidr"`
	EntryType   string     `json:"entry_type"`
	Description string     `json:"description,omitempty"`
	HitCount    int        `json:"hit_count"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
	AddedBy     *string    `json:"added_by,omitempty"`
	CreatedAt   time.Time  `json:"created_at"`
	IsExpired   bool       `json:"is_expired"`
}

// IPBlockStore handles persistence of IP block/allow list entries.
type IPBlockStore struct {
	pool *pgxpool.Pool
}

func NewIPBlockStore(db *DB) *IPBlockStore {
	return &IPBlockStore{pool: db.Pool()}
}

// List returns every IP block/allow entry, most recently created first.
func (s *IPBlockStore) List(ctx context.Context) ([]*IPBlockEntry, int, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, ip_or_cidr, entry_type, COALESCE(description,''), hit_count,
		       expires_at, added_by::text, created_at,
		       (expires_at IS NOT NULL AND expires_at < NOW()) AS is_expired
		FROM ip_block_entries
		ORDER BY created_at DESC`,
	)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []*IPBlockEntry
	for rows.Next() {
		e := &IPBlockEntry{}
		var addedBy *string
		if err := rows.Scan(
			&e.ID, &e.IPOrCIDR, &e.EntryType, &e.Description, &e.HitCount,
			&e.ExpiresAt, &addedBy, &e.CreatedAt, &e.IsExpired,
		); err != nil {
			continue
		}
		e.AddedBy = addedBy
		entries = append(entries, e)
	}
	if entries == nil {
		entries = []*IPBlockEntry{}
	}
	return entries, len(entries), rows.Err()
}

// Insert adds a new IP block/allow entry. Returns a unique-violation error if
// the same ip_or_cidr + entry_type pair already exists.
func (s *IPBlockStore) Insert(ctx context.Context, e *IPBlockEntry) error {
	return s.pool.QueryRow(ctx, `
		INSERT INTO ip_block_entries (ip_or_cidr, entry_type, description, expires_at, added_by)
		VALUES ($1, $2, $3, $4, $5::uuid)
		RETURNING id, created_at`,
		e.IPOrCIDR, e.EntryType, e.Description, e.ExpiresAt, nilIfEmpty(e.AddedBy),
	).Scan(&e.ID, &e.CreatedAt)
}

// Delete removes an IP block/allow entry by ID.
func (s *IPBlockStore) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx, "DELETE FROM ip_block_entries WHERE id = $1", id)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("not found")
	}
	return nil
}
