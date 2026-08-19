package scheduler

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/edr-platform/server/internal/store"
	"github.com/google/uuid"
	"github.com/nats-io/nats.go"
)

const (
	// renewWithinDays triggers renewal when fewer than this many days remain.
	renewWithinDays = 30
	// renewalTokenTTL is how long the one-time renewal token is valid.
	renewalTokenTTL = 7 * 24 * time.Hour
)

// AgentCertRenewer checks for expiring agent mTLS certificates daily and
// sends a cert_renew command to each affected agent via NATS.
type AgentCertRenewer struct {
	agentStore *store.AgentStore
	nc         *nats.Conn
}

// NewAgentCertRenewer creates a new AgentCertRenewer.
func NewAgentCertRenewer(agentStore *store.AgentStore, nc *nats.Conn) *AgentCertRenewer {
	return &AgentCertRenewer{agentStore: agentStore, nc: nc}
}

// Run starts the renewer: first check after 2 minutes, then every 24 hours.
// Designed to be called as a goroutine.
func (r *AgentCertRenewer) Run(ctx context.Context) {
	timer := time.NewTimer(2 * time.Minute)
	defer timer.Stop()
	ticker := time.NewTicker(24 * time.Hour)
	defer ticker.Stop()

	slog.Info("エージェント証明書更新チェッカーを起動しました", "renew_within_days", renewWithinDays)

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			trackRun(ctx, "agent_cert_renewer", r.checkAndRenew)
		case <-ticker.C:
			trackRun(ctx, "agent_cert_renewer", r.checkAndRenew)
		}
	}
}

func (r *AgentCertRenewer) checkAndRenew(ctx context.Context) {
	slog.Info("エージェント証明書の有効期限チェックを開始します")

	expiring, err := r.agentStore.ListExpiringAgents(ctx, renewWithinDays)
	if err != nil {
		fail(ctx, err, "期限切れエージェント一覧の取得に失敗しました")
		return
	}
	if len(expiring) == 0 {
		slog.Info("証明書更新が必要なエージェントはありません")
		return
	}

	slog.Info("証明書更新対象のエージェント", "count", len(expiring))

	for _, agent := range expiring {
		r.renewAgent(ctx, agent)
	}
}

func (r *AgentCertRenewer) renewAgent(ctx context.Context, agent *store.ExpiringAgentRow) {
	daysLeft := int(time.Until(agent.CertNotAfter).Hours() / 24)

	// Generate a one-time renewal token.
	token := uuid.New().String()
	if err := r.agentStore.SetRenewalToken(ctx, agent.ID, token, renewalTokenTTL); err != nil {
		fail(ctx, err, "renewal tokenの保存に失敗しました", "agent_id", agent.ID)
		return
	}

	// Publish the cert_renew command via NATS so the ingestion bridge relays
	// it to the agent's gRPC EventStream.
	subject := fmt.Sprintf("commands.%s.cert_renew", agent.ID)
	payload, _ := json.Marshal(map[string]interface{}{
		"agent_id":      agent.ID,
		"renewal_token": token,
	})
	if r.nc != nil {
		if err := r.nc.Publish(subject, payload); err != nil {
			fail(ctx, err, "cert_renewコマンドのNATS publishに失敗しました",
				"agent_id", agent.ID)
			return
		}
	}

	slog.Info("cert_renewコマンドを送信しました",
		"agent_id", agent.ID,
		"hostname", agent.Hostname,
		"days_left", daysLeft,
		"cert_expires", agent.CertNotAfter.Format(time.RFC3339),
	)
}
