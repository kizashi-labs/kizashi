// Package natsstream owns the JetStream stream definitions shared by every
// service that bootstraps them.
//
// It exists because the definitions used to be written out twice — once in
// internal/ingestion (old nats.go API, AddStream) and once in cmd/detection
// (new jetstream API, CreateOrUpdateStream) — with a comment in one of them
// warning that "the two configs must stay identical, or whichever service
// starts second tries to mutate the first one's stream". A rule that has to be
// upheld by comment is a rule that gets broken; and the failure it produces is
// not a build error but a service that crashes at startup only when it loses a
// race, which is how it showed up in production.
//
// Both services now call Ensure. There is one table and one config.
package natsstream

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/nats-io/nats.go"
	"github.com/nats-io/nats.go/jetstream"
)

// Definition is one stream this platform requires.
type Definition struct {
	Name     string
	Subjects []string
	MaxAge   time.Duration
}

// Definitions is the authoritative list. Adding a stream here is the only place
// it needs to be added.
var Definitions = []Definition{
	{Name: "EVENTS", Subjects: []string{"events.>"}, MaxAge: 7 * 24 * time.Hour},
	{Name: "ALERTS", Subjects: []string{"alerts.>"}, MaxAge: 30 * 24 * time.Hour},
	{Name: "COMMANDS", Subjects: []string{"commands.>"}, MaxAge: 1 * time.Hour},
}

// Config renders a definition into the JetStream config. Every field that is
// not per-stream lives here, so two services cannot disagree about it.
func (d Definition) Config() jetstream.StreamConfig {
	return jetstream.StreamConfig{
		Name:      d.Name,
		Subjects:  d.Subjects,
		Storage:   jetstream.FileStorage,
		Retention: jetstream.LimitsPolicy,
		MaxAge:    d.MaxAge,
		MaxBytes:  -1, // no per-stream limit; the server manages storage
		Replicas:  1,
		// Dedupe window for publishes carrying Nats-Msg-Id.
		Duplicates: 5 * time.Minute,
	}
}

// Ensure creates or updates every required stream. Safe to call concurrently
// from several services — that is the normal case at boot.
func Ensure(ctx context.Context, nc *nats.Conn) error {
	js, err := jetstream.New(nc)
	if err != nil {
		return fmt.Errorf("JetStream コンテキストの取得に失敗しました: %w", err)
	}
	for _, d := range Definitions {
		if err := ensureOne(ctx, js, d); err != nil {
			return err
		}
	}
	return nil
}

// StreamManager is the slice of jetstream.JetStream that Ensure needs. Declared
// so the race handling below can be tested without a broker.
type StreamManager interface {
	CreateOrUpdateStream(ctx context.Context, cfg jetstream.StreamConfig) (jetstream.Stream, error)
	UpdateStream(ctx context.Context, cfg jetstream.StreamConfig) (jetstream.Stream, error)
}

func ensureOne(ctx context.Context, js StreamManager, d Definition) error {
	cfg := d.Config()
	_, err := js.CreateOrUpdateStream(ctx, cfg)

	// CreateOrUpdateStream is Update-then-Create, so two services bootstrapping
	// the same stream at once race: this one sees ErrStreamNotFound from the
	// update, the other creates the stream in between, and the create leg comes
	// back ErrStreamNameAlreadyInUse. That is not a failure — the stream we
	// wanted now exists — but treating it as one crashed detection at startup
	// whenever ingestion won the race.
	if errors.Is(err, jetstream.ErrStreamNameAlreadyInUse) {
		_, err = js.UpdateStream(ctx, cfg)
	}
	if err != nil {
		return fmt.Errorf("stream %s: %w", d.Name, err)
	}
	slog.Info("NATSストリームを確認/作成しました", "name", d.Name)
	return nil
}
