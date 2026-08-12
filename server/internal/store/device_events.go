package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// DeviceEvent mirrors a row in the device_events table.
type DeviceEvent struct {
	ID         string  `json:"id"`
	AgentID    string  `json:"agent_id"`
	Action     string  `json:"action"`
	DeviceID   string  `json:"device_id"`
	DeviceName string  `json:"device_name"`
	DeviceType string  `json:"device_type"`
	VendorID   string  `json:"vendor_id"`
	ProductID  string  `json:"product_id"`
	RawData    *string `json:"raw_data,omitempty"`
	CreatedAt  string  `json:"created_at"`
}

// DeviceEventStore handles device_events database operations.
type DeviceEventStore struct {
	pool *pgxpool.Pool
}

// NewDeviceEventStore creates a new DeviceEventStore backed by the given pool.
func NewDeviceEventStore(pool *pgxpool.Pool) *DeviceEventStore {
	return &DeviceEventStore{pool: pool}
}

// DeviceEventFilter holds optional filter criteria for listing device events.
type DeviceEventFilter struct {
	AgentID    string
	Action     string
	DeviceType string
	Since      *time.Time
	Until      *time.Time
	Limit      int
	Offset     int
}

// List returns device events matching the filter with total count for pagination.
func (s *DeviceEventStore) List(ctx context.Context, f DeviceEventFilter) ([]*DeviceEvent, int, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	if f.Limit > 500 {
		f.Limit = 500
	}

	where := "WHERE 1=1"
	args := []interface{}{}
	idx := 1

	if f.AgentID != "" {
		where += fmt.Sprintf(" AND agent_id = $%d", idx)
		args = append(args, f.AgentID)
		idx++
	}
	if f.Action != "" {
		where += fmt.Sprintf(" AND action = $%d", idx)
		args = append(args, f.Action)
		idx++
	}
	if f.DeviceType != "" {
		where += fmt.Sprintf(" AND device_type = $%d", idx)
		args = append(args, f.DeviceType)
		idx++
	}
	if f.Since != nil {
		where += fmt.Sprintf(" AND created_at >= $%d", idx)
		args = append(args, *f.Since)
		idx++
	}
	if f.Until != nil {
		where += fmt.Sprintf(" AND created_at <= $%d", idx)
		args = append(args, *f.Until)
		idx++
	}

	var total int
	if err := s.pool.QueryRow(ctx,
		"SELECT COUNT(*) FROM device_events "+where, args...,
	).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("device_events count: %w", err)
	}

	args = append(args, f.Limit, f.Offset)
	rows, err := s.pool.Query(ctx, fmt.Sprintf(`
		SELECT id, agent_id, action, device_id,
		       COALESCE(device_name,''), COALESCE(device_type,''),
		       COALESCE(vendor_id,''), COALESCE(product_id,''),
		       raw_data::text, created_at
		FROM device_events
		%s
		ORDER BY created_at DESC
		LIMIT $%d OFFSET $%d`,
		where, idx, idx+1,
	), args...)
	if err != nil {
		return nil, 0, fmt.Errorf("device_events list: %w", err)
	}
	defer rows.Close()

	var events []*DeviceEvent
	for rows.Next() {
		var e DeviceEvent
		var createdAt time.Time
		var rawData *string
		if err := rows.Scan(
			&e.ID, &e.AgentID, &e.Action, &e.DeviceID,
			&e.DeviceName, &e.DeviceType,
			&e.VendorID, &e.ProductID,
			&rawData, &createdAt,
		); err != nil {
			continue
		}
		e.CreatedAt = createdAt.Format(time.RFC3339)
		e.RawData = rawData
		events = append(events, &e)
	}
	if events == nil {
		events = []*DeviceEvent{}
	}
	return events, total, nil
}

// DeviceEventStatRow holds one row of the stats aggregation.
type DeviceEventStatRow struct {
	Action     string `json:"action"`
	DeviceType string `json:"device_type"`
	Count      int    `json:"count"`
}

// Stats returns device event counts grouped by (action, device_type) in the
// last 24 hours (or since the provided since time).
func (s *DeviceEventStore) Stats(ctx context.Context, since time.Time) ([]DeviceEventStatRow, error) {
	rows, err := s.pool.Query(ctx, `
		SELECT action,
		       COALESCE(device_type, '') AS device_type,
		       COUNT(*)::int AS count
		FROM device_events
		WHERE created_at >= $1
		GROUP BY action, device_type
		ORDER BY count DESC
	`, since)
	if err != nil {
		return nil, fmt.Errorf("device_events stats: %w", err)
	}
	defer rows.Close()

	var result []DeviceEventStatRow
	for rows.Next() {
		var r DeviceEventStatRow
		if err := rows.Scan(&r.Action, &r.DeviceType, &r.Count); err != nil {
			continue
		}
		result = append(result, r)
	}
	if result == nil {
		result = []DeviceEventStatRow{}
	}
	return result, nil
}

// Insert stores a new device event.  Called by the gRPC ingest layer when it
// parses a "device_event:…" envelope from an agent batch.
func (s *DeviceEventStore) Insert(ctx context.Context, e *DeviceEvent) error {
	_, err := s.pool.Exec(ctx, `
		INSERT INTO device_events
		    (agent_id, action, device_id, device_name, device_type, vendor_id, product_id, raw_data)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8::jsonb)`,
		e.AgentID, e.Action, e.DeviceID,
		nullStr(e.DeviceName), nullStr(e.DeviceType),
		nullStr(e.VendorID), nullStr(e.ProductID),
		e.RawData,
	)
	if err != nil {
		return fmt.Errorf("device_events insert: %w", err)
	}
	return nil
}

// nullStr converts an empty string to nil so pgx stores NULL rather than "".
func nullStr(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
