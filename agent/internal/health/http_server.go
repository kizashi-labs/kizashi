package health

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"time"
)

// HTTPServer exposes a local HTTP health endpoint for the agent.
// This is useful for monitoring systems (Kubernetes liveness probes, etc.)
type HTTPServer struct {
	reporter   *Reporter
	serverAddr string
	port       int
}

// NewHTTPServer creates an agent HTTP health server.
func NewHTTPServer(reporter *Reporter, serverAddr string, port int) *HTTPServer {
	return &HTTPServer{
		reporter:   reporter,
		serverAddr: serverAddr,
		port:       port,
	}
}

// Run starts the HTTP health server.
func (s *HTTPServer) Run(ctx context.Context) {
	mux := http.NewServeMux()

	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		status := s.reporter.GetStatus()
		w.Header().Set("Content-Type", "application/json")
		if !status.ConnectedToServer {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(status)
	})

	mux.HandleFunc("/metrics", func(w http.ResponseWriter, r *http.Request) {
		status := s.reporter.GetStatus()
		w.Header().Set("Content-Type", "text/plain")
		fmt.Fprintf(w, "edr_events_total %d\n", status.EventsTotal)
		fmt.Fprintf(w, "edr_dropped_events %d\n", status.DroppedEvents)
		fmt.Fprintf(w, "edr_connected %d\n", boolToInt(status.ConnectedToServer))
		fmt.Fprintf(w, "edr_error_count %d\n", status.ErrorCount)
		fmt.Fprintf(w, "edr_memory_mb %.2f\n", status.MemoryMB)
		fmt.Fprintf(w, "edr_goroutines %d\n", status.Goroutines)
		fmt.Fprintf(w, "edr_uptime_seconds %d\n", status.UptimeSeconds)
	})

	mux.HandleFunc("/diagnostics", func(w http.ResponseWriter, r *http.Request) {
		results := RunDiagnostics(r.Context(), s.serverAddr)
		w.Header().Set("Content-Type", "application/json")
		allOK := true
		for _, r := range results {
			if !r.OK {
				allOK = false
				break
			}
		}
		if !allOK {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(w).Encode(map[string]interface{}{
			"ok":     allOK,
			"checks": results,
			"time":   time.Now().UTC(),
		})
	})

	srv := &http.Server{
		Addr:         fmt.Sprintf("127.0.0.1:%d", s.port),
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		<-ctx.Done()
		shutCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Shutdown(shutCtx)
	}()

	slog.Info("agent health server starting", "addr", srv.Addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		slog.Error("agent health server error", "err", err)
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}
