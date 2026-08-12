package store

import (
	"context"
	"log/slog"
	"time"
)

// NotificationHistoryEntry records a sent notification.
type NotificationHistoryEntry struct {
	ID          string    `json:"id"`
	ChannelID   string    `json:"channel_id"`
	ChannelName string    `json:"channel_name"`
	ChannelType string    `json:"channel_type"`
	Subject     string    `json:"subject"`
	Body        string    `json:"body"`
	Status      string    `json:"status"` // sent / failed
	ErrorMsg    string    `json:"error,omitempty"`
	SentAt      time.Time `json:"sent_at"`
}

// NotificationHistoryStore persists notification send history.
type NotificationHistoryStore struct {
	db *DB
}

func NewNotificationHistoryStore(db *DB) *NotificationHistoryStore {
	return &NotificationHistoryStore{db: db}
}

// Insert records a notification attempt.
func (s *NotificationHistoryStore) Insert(ctx context.Context, e *NotificationHistoryEntry) error {
	_, err := s.db.Pool().Exec(ctx, `
		INSERT INTO notification_history
			(channel_id, channel_name, channel_type, subject, body, status, error_msg, sent_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
		e.ChannelID, e.ChannelName, e.ChannelType, e.Subject, e.Body, e.Status, e.ErrorMsg)
	return err
}

// List returns recent notification history, newest first.
func (s *NotificationHistoryStore) List(ctx context.Context, limit, offset int) ([]*NotificationHistoryEntry, int, error) {
	var total int
	if err := s.db.Pool().QueryRow(ctx, `SELECT COUNT(*) FROM notification_history`).Scan(&total); err != nil {
		return nil, 0, err
	}
	rows, err := s.db.Pool().Query(ctx, `
		SELECT id::text, COALESCE(channel_id::text,''), COALESCE(channel_name,''),
		       COALESCE(channel_type,''), COALESCE(subject,''), COALESCE(body,''),
		       status, COALESCE(error_msg,''), sent_at
		FROM notification_history
		ORDER BY sent_at DESC
		LIMIT $1 OFFSET $2`, limit, offset)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var entries []*NotificationHistoryEntry
	for rows.Next() {
		e := &NotificationHistoryEntry{}
		if err := rows.Scan(&e.ID, &e.ChannelID, &e.ChannelName, &e.ChannelType,
			&e.Subject, &e.Body, &e.Status, &e.ErrorMsg, &e.SentAt); err == nil {
			entries = append(entries, e)
		}
	}
	if entries == nil {
		entries = []*NotificationHistoryEntry{}
	}
	return entries, total, nil
}

// Stats returns aggregated send statistics for the last N days.
func (s *NotificationHistoryStore) Stats(ctx context.Context, days int) (map[string]interface{}, error) {
	// 間隔は make_interval(days => $1) で組む。`($1 || ' days')::INTERVAL` は
	// $1 を text 推論させるため、pgx が int の days を text OID へエンコードできず
	// ("unable to encode N into text format")、この 2 つのクエリは常に失敗して
	// 送信統計が 0 件固定になっていた。
	var sent, failed int
	if err := s.db.Pool().QueryRow(ctx, `
		SELECT
			COUNT(*) FILTER (WHERE status='sent'),
			COUNT(*) FILTER (WHERE status='failed')
		FROM notification_history
		WHERE sent_at >= NOW() - make_interval(days => $1)`, days).Scan(&sent, &failed); err != nil {
		slog.Warn("notification stats: 送信件数の集計に失敗", "error", err)
	}

	type channelRow struct {
		Name  string `json:"name"`
		Count int    `json:"count"`
	}
	rows, err := s.db.Pool().Query(ctx, `
		SELECT COALESCE(channel_name,'unknown'), COUNT(*)
		FROM notification_history
		WHERE sent_at >= NOW() - make_interval(days => $1)
		GROUP BY 1 ORDER BY 2 DESC LIMIT 10`, days)
	if err != nil {
		slog.Warn("notification stats: チャネル別集計に失敗", "error", err)
	}
	var byChannel []channelRow
	if rows != nil {
		defer rows.Close()
		for rows.Next() {
			var r channelRow
			if err := rows.Scan(&r.Name, &r.Count); err == nil {
				byChannel = append(byChannel, r)
			}
		}
	}
	if byChannel == nil {
		byChannel = []channelRow{}
	}

	return map[string]interface{}{
		"sent":       sent,
		"failed":     failed,
		"by_channel": byChannel,
	}, nil
}
