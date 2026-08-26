package main

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// serviceInstallStarter is the platform-agnostic handle to the service-install
// sensor. Only Windows provides a real implementation (System EventID 7045);
// other platforms return nil from the factory. It emits service_installed
// findings (T1543.003) directly through the event sender.
type serviceInstallStarter interface {
	Start(ctx context.Context, agentID string, sender collector.EventSender) error
	Stop() error
}
