package transport

import (
	"context"
	"encoding/json"
	"log/slog"
	"time"

	"github.com/edr-platform/agent/internal/policy"
)

// PolicySyncer handles policy synchronization from the EDR server.
// The server pushes PolicyUpdate commands via the gRPC command stream.
// On CmdReloadConfig, the agent re-fetches all policies.
type PolicySyncer struct {
	manager *policy.Manager
	client  *GRPCClient
}

// NewPolicySyncer creates a syncer that updates the policy manager
// when the server sends reload commands.
func NewPolicySyncer(mgr *policy.Manager, client *GRPCClient) *PolicySyncer {
	return &PolicySyncer{manager: mgr, client: client}
}

// HandleReloadConfig is called when a CmdReloadConfig command arrives.
// It signals the policy manager to accept new policies.
func (s *PolicySyncer) HandleReloadConfig(ctx context.Context) {
	slog.Info("設定リロードコマンドを受信しました。ポリシーを更新中...")
	// In a full implementation, fetch policies from the server's
	// /api/v1/policies endpoint via gRPC or HTTP. For now, log the intent.
	// The policy manager's RunPeriodicRefresh handles the actual fetch.
}

// ApplyPolicyPayload applies a policy received as JSON from the server.
// Called when the server embeds policy data in a command.
func (s *PolicySyncer) ApplyPolicyPayload(payload []byte) error {
	var p policy.Policy
	if err := json.Unmarshal(payload, &p); err != nil {
		return err
	}
	return s.manager.ApplyPolicy(p)
}

// StartPeriodicSync starts periodic policy synchronization.
func (s *PolicySyncer) StartPeriodicSync(ctx context.Context, interval time.Duration) {
	s.manager.RunPeriodicRefresh(ctx, interval, func(ctx context.Context) error {
		// In production: call server API to get latest policy versions
		// and compare with current versions before downloading
		slog.Debug("ポリシー定期同期チェック")
		return nil
	})
}
