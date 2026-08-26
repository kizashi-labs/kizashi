package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PacketCapture represents a packet capture job tied to an agent.
type PacketCapture struct {
	ID              string     `json:"id"`
	AgentID         string     `json:"agent_id"`
	Name            string     `json:"name"`
	Status          string     `json:"status"`
	Filter          string     `json:"filter"`
	InterfaceName   string     `json:"interface_name"`
	MaxPackets      int        `json:"max_packets"`
	MaxSizeMB       int        `json:"max_size_mb"`
	DurationSeconds int        `json:"duration_seconds"`
	FilePath        *string    `json:"file_path,omitempty"`
	FileSizeBytes   *int64     `json:"file_size_bytes,omitempty"`
	PacketCount     *int       `json:"packet_count,omitempty"`
	ErrorMsg        *string    `json:"error_msg,omitempty"`
	StartedAt       *time.Time `json:"started_at,omitempty"`
	CompletedAt     *time.Time `json:"completed_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	CreatedBy       *string    `json:"created_by,omitempty"`
}

// PacketCaptureStore manages packet_captures records.
type PacketCaptureStore struct {
	pool *pgxpool.Pool
}

// NewPacketCaptureStore creates a new PacketCaptureStore backed by the provided pool.
func NewPacketCaptureStore(pool *pgxpool.Pool) *PacketCaptureStore {
	return &PacketCaptureStore{pool: pool}
}

const packetCaptureColumns = `id, agent_id, name, status, filter, interface_name, max_packets, max_size_mb, duration_seconds, file_path, file_size_bytes, packet_count, error_msg, started_at, completed_at, created_at, created_by`

func (s *PacketCaptureStore) scan(row interface{ Scan(dest ...any) error }) (PacketCapture, error) {
	var pc PacketCapture
	err := row.Scan(
		&pc.ID, &pc.AgentID, &pc.Name, &pc.Status,
		&pc.Filter, &pc.InterfaceName, &pc.MaxPackets, &pc.MaxSizeMB, &pc.DurationSeconds,
		&pc.FilePath, &pc.FileSizeBytes, &pc.PacketCount, &pc.ErrorMsg,
		&pc.StartedAt, &pc.CompletedAt, &pc.CreatedAt, &pc.CreatedBy,
	)
	return pc, err
}

// List returns packet captures for a given agent, newest first.
func (s *PacketCaptureStore) List(ctx context.Context, agentID string) ([]PacketCapture, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT `+packetCaptureColumns+`
		 FROM packet_captures
		 WHERE agent_id=$1
		 ORDER BY created_at DESC`,
		agentID,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var result []PacketCapture
	for rows.Next() {
		pc, err := s.scan(rows)
		if err != nil {
			return nil, err
		}
		result = append(result, pc)
	}
	if result == nil {
		result = []PacketCapture{}
	}
	return result, rows.Err()
}

// Create inserts a new packet capture record.
func (s *PacketCaptureStore) Create(ctx context.Context, pc PacketCapture) (PacketCapture, error) {
	row := s.pool.QueryRow(ctx,
		`INSERT INTO packet_captures
		 (agent_id, name, status, filter, interface_name, max_packets, max_size_mb, duration_seconds, created_by)
		 VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)
		 RETURNING `+packetCaptureColumns,
		pc.AgentID, pc.Name, pc.Status, pc.Filter, pc.InterfaceName,
		pc.MaxPackets, pc.MaxSizeMB, pc.DurationSeconds, pc.CreatedBy,
	)
	return s.scan(row)
}

// Get retrieves a single packet capture by ID.
func (s *PacketCaptureStore) Get(ctx context.Context, id string) (PacketCapture, error) {
	row := s.pool.QueryRow(ctx,
		`SELECT `+packetCaptureColumns+`
		 FROM packet_captures WHERE id=$1`, id,
	)
	pc, err := s.scan(row)
	if err != nil {
		return pc, fmt.Errorf("packet capture not found: %w", err)
	}
	return pc, nil
}

// UpdateStatus updates the status and result fields of a packet capture.
func (s *PacketCaptureStore) UpdateStatus(ctx context.Context, id, status string, filePath *string, fileSize *int64, packetCount *int, errorMsg *string) error {
	startedAt, completedAt := captureTimestampsFor(status, time.Now().UTC())

	_, err := s.pool.Exec(ctx,
		`UPDATE packet_captures
		 SET status=$1, file_path=$2, file_size_bytes=$3, packet_count=$4, error_msg=$5,
		     started_at=COALESCE(started_at, $6), completed_at=$7
		 WHERE id=$8`,
		status, filePath, fileSize, packetCount, errorMsg, startedAt, completedAt, id,
	)
	return err
}

// captureTimestampsFor derives the started/completed timestamps a status change
// implies.
//
// **切り出してあるのは、検査が本物を呼べるようにするためです。** 検査
// ファイルには、この2つの分岐を検査の本文で書き直したものが置いてあり、
// **製品を1行も通らずに**「running は開始時刻を設定する」と確かめて
// いました。
//
// 終了時刻が入らないと、取得の終わったキャプチャが**いつまでも
// 「実行中」に見えます。** 開始時刻が入らないと、始まったことが
// 分かりません。now は呼び出し側から渡します（検査を時刻に依存させない
// ため）。
func captureTimestampsFor(status string, now time.Time) (startedAt, completedAt *time.Time) {
	switch status {
	case "running":
		return &now, nil
	case "completed", "failed", "cancelled":
		return nil, &now
	}
	return nil, nil
}

// Delete removes a packet capture record by ID.
func (s *PacketCaptureStore) Delete(ctx context.Context, id string) error {
	result, err := s.pool.Exec(ctx,
		`DELETE FROM packet_captures WHERE id=$1`, id,
	)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return fmt.Errorf("packet capture not found")
	}
	return nil
}
