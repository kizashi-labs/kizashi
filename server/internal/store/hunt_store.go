package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// SavedHunt represents a saved threat hunting search.
type SavedHunt struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Params      json.RawMessage `json:"params"`
	CreatedBy   string          `json:"created_by"`
	CreatedAt   time.Time       `json:"created_at"`
	LastRun     *time.Time      `json:"last_run,omitempty"`
	RunCount    int             `json:"run_count"`
}

// HuntStore manages saved threat hunts.
type HuntStore struct {
	pool *pgxpool.Pool
}

// NewHuntStore creates a new HuntStore.
func NewHuntStore(db *DB) *HuntStore {
	return &HuntStore{pool: db.Pool()}
}

// List returns all saved hunts.
func (s *HuntStore) List(ctx context.Context) ([]*SavedHunt, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT id, name, description, params, created_by, created_at, last_run, run_count
		FROM saved_hunts ORDER BY created_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var hunts []*SavedHunt
	for rows.Next() {
		h := &SavedHunt{}
		if err := rows.Scan(&h.ID, &h.Name, &h.Description, &h.Params,
			&h.CreatedBy, &h.CreatedAt, &h.LastRun, &h.RunCount); err != nil {
			continue
		}
		hunts = append(hunts, h)
	}
	if hunts == nil {
		hunts = []*SavedHunt{}
	}
	return hunts, rows.Err()
}

// Create saves a new hunt.
func (s *HuntStore) Create(ctx context.Context, h *SavedHunt) (*SavedHunt, error) {
	out := &SavedHunt{}
	err := s.pool.QueryRow(ctx, `
		INSERT INTO saved_hunts (name, description, params, created_by)
		VALUES ($1, $2, $3, $4)
		RETURNING id, name, description, params, created_by, created_at, last_run, run_count`,
		h.Name, h.Description, h.Params, h.CreatedBy,
	).Scan(&out.ID, &out.Name, &out.Description, &out.Params,
		&out.CreatedBy, &out.CreatedAt, &out.LastRun, &out.RunCount)
	return out, err
}

// Delete removes a saved hunt.
func (s *HuntStore) Delete(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `DELETE FROM saved_hunts WHERE id=$1::uuid`, id)
	return err
}

// RecordRun updates last_run and increments run_count.
//
// **error を返します。** 以前は返り値が無く、書けなくても呼び出し側は
// 何も知りませんでした —— **どう答えるかは store が決めることでは
// ありません。** このメソッドを呼ぶハンドラは「記録しました」と
// 答えるので、書けていないなら答えを変える必要があります。
func (s *HuntStore) RecordRun(ctx context.Context, id string) error {
	_, err := s.pool.Exec(ctx, `
		UPDATE saved_hunts SET last_run=NOW(), run_count=run_count+1 WHERE id=$1::uuid`, id)
	return err
}
