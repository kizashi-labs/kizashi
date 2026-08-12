package main

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// namedPipeStarter is the platform-agnostic handle to the named-pipe creation
// sensor. Only Windows provides a real implementation (Microsoft-Windows-Kernel-
// File ETW); other platforms return nil from the factory. It emits pipe_created
// findings directly through the event sender.
type namedPipeStarter interface {
	Start(ctx context.Context, agentID string, sender collector.EventSender) error
	Stop() error
}
