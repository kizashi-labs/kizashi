package graceful

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"syscall"
	"time"
)

// Runner defines something that can be run and stopped.
type Runner interface {
	Shutdown(ctx context.Context) error
}

// WaitForShutdown blocks until SIGINT or SIGTERM, then calls Shutdown on all runners.
func WaitForShutdown(timeout time.Duration, runners ...Runner) {
	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)

	sig := <-quit
	slog.Info("shutdown signal received", "signal", sig)

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	for _, r := range runners {
		if err := r.Shutdown(ctx); err != nil {
			slog.Error("shutdown error", "err", err)
		}
	}

	slog.Info("server shut down cleanly")
}
