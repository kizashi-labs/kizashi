package investigation

import (
	"context"
	"github.com/edr-platform/server/internal/metrics"
	"log/slog"

	"github.com/nats-io/nats.go"
)

const (
	// TriggerSubject is the NATS subject on which investigation trigger messages
	// are published.  The message body is the plain-text alert ID.
	TriggerSubject = "edr.investigation.trigger"
)

// Subscriber listens on the NATS TriggerSubject and calls InvestigateAlert for
// each received alert ID.
type Subscriber struct {
	inv *Investigator
	nc  *nats.Conn
}

// NewSubscriber creates a new Subscriber.
func NewSubscriber(inv *Investigator, nc *nats.Conn) *Subscriber {
	return &Subscriber{inv: inv, nc: nc}
}

// Start subscribes to TriggerSubject and processes messages until ctx is
// cancelled.  It blocks until the subscription is drained.
func (s *Subscriber) Start(ctx context.Context) {
	if s.inv == nil || !s.inv.IsConfigured() {
		slog.Info("investigation subscriber: no AI key configured, subscriber will not start")
		return
	}

	sub, err := s.nc.Subscribe(TriggerSubject, func(msg *nats.Msg) {
		alertID := string(msg.Data)
		if alertID == "" {
			return
		}
		slog.Info("investigation subscriber: received trigger", "alert_id", alertID)

		// Investigate in a separate goroutine to avoid blocking the NATS dispatcher.
		go func(id string) {
			result, err := s.inv.InvestigateAlert(context.Background(), id)
			if err != nil {
				slog.Warn("investigation subscriber: investigation failed",
					"alert_id", id, "error", err)
				return
			}
			if result != nil {
				slog.Info("investigation subscriber: investigation stored",
					"alert_id", id, "model", result.Model)
			}
		}(alertID)
	})
	if err != nil {
		metrics.BackgroundFailed("investigation_subscriber", err, "investigation subscriber: subscribe failed")
		return
	}
	slog.Info("investigation subscriber: listening", "subject", TriggerSubject)

	<-ctx.Done()
	_ = sub.Unsubscribe()
	slog.Info("investigation subscriber: stopped")
}
