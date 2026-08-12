package main

import (
	"context"

	"github.com/edr-platform/agent/internal/collector"
)

// wmiActivityStarter is the platform-agnostic handle to the WMI-Activity sensor.
// Only Windows provides a real implementation (Microsoft-Windows-WMI-Activity
// ETW); other platforms return nil from the factory. It emits wmi_activity
// findings directly through the event sender.
type wmiActivityStarter interface {
	Start(ctx context.Context, agentID string, sender collector.EventSender) error
	Stop() error
}
