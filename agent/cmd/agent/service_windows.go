//go:build windows

package main

import (
	"log/slog"

	"golang.org/x/sys/windows/svc"
)

type edrWindowsSvc struct {
	cancel func()
}

func (s *edrWindowsSvc) Execute(_ []string, r <-chan svc.ChangeRequest, changes chan<- svc.Status) (bool, uint32) {
	changes <- svc.Status{State: svc.Running, Accepts: svc.AcceptStop | svc.AcceptShutdown}
	for c := range r {
		switch c.Cmd {
		case svc.Stop, svc.Shutdown:
			changes <- svc.Status{State: svc.StopPending}
			s.cancel()
			return false, 0
		}
	}
	return false, 0
}

// startWindowsServiceIfNeeded registers with the Windows Service Control Manager
// when the process is started as a service. It is a no-op in interactive mode.
func startWindowsServiceIfNeeded(cancel func()) {
	ok, err := svc.IsWindowsService()
	if err != nil || !ok {
		return
	}
	go func() {
		if err := svc.Run("EDRAgent", &edrWindowsSvc{cancel: cancel}); err != nil {
			slog.Error("Windows SCM dispatcher error", "error", err)
		}
	}()
}
