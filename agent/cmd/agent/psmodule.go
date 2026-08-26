package main

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// psModuleStarter is the platform-agnostic handle to the PowerShell Module
// Logging (4103) sensor. Only Windows provides a real implementation (Microsoft-
// Windows-PowerShell ETW); other platforms return nil from the factory. It emits
// ps_module findings directly through the event sender.
type psModuleStarter interface {
	Start(ctx context.Context, agentID string, sender collector.EventSender) error
	Stop() error
}
