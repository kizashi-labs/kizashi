package main

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// eventLogClearStarter is the platform-agnostic handle to the audit-log-clear
// sensor. Only Windows provides a real implementation (Security EventID 1102 /
// System EventID 104); other platforms return nil from the factory. It emits
// eventlog_cleared findings (T1070.001) directly through the event sender.
type eventLogClearStarter interface {
	Start(ctx context.Context, agentID string, sender collector.EventSender) error
	Stop() error
}
