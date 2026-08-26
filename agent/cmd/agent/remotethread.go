package main

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// remoteThreadStarter is the platform-agnostic handle to the CreateRemoteThread
// injection sensor. Only Windows provides a real implementation (Kernel-Process
// ETW ThreadStart); other platforms return nil from the factory. It emits
// create_remote_thread findings directly through the event sender.
type remoteThreadStarter interface {
	Start(ctx context.Context, agentID string, sender collector.EventSender) error
	Stop() error
}
