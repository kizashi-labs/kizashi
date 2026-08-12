// Package health provides Kubernetes-style liveness and readiness HTTP probes
// for the plain net/http services (detection, ingestion). The API server has its
// own gin-based equivalents (internal/api/handlers/health_handler.go); this gives
// the worker services the same operational contract:
//
//   - liveness  (/healthz): is the process alive? Cheap, no dependency checks — a
//     transient DB/NATS blip must NOT cause the orchestrator to kill the process.
//   - readiness (/readyz): can the service serve traffic? Pings the DB and checks
//     the NATS connection; returns 503 when a critical dependency is down so the
//     orchestrator stops routing to (but does not restart) the instance.
//
// Before this, detection/ingestion exposed only a "/health" that returned 200
// unconditionally — a false-ready signal that kept a DB/NATS-disconnected worker
// in rotation, silently dropping events.
package health

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/nats-io/nats.go"
)

// readyTimeout bounds the dependency checks so a hung DB can't hang the probe.
const readyTimeout = 3 * time.Second

// Pinger is the subset of *pgxpool.Pool the readiness probe needs. An interface so
// the probe is unit-testable without a real database.
type Pinger interface {
	Ping(ctx context.Context) error
}

// LivenessHandler reports process liveness — always 200 while the process runs.
// It deliberately performs no dependency checks.
func LivenessHandler() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]any{"status": "alive"})
	}
}

// ReadinessHandler reports whether the service can serve traffic. It pings the DB
// and checks the NATS connection, returning 503 (naming the failing dependency)
// when either is down. A nil pool or nil nc skips that check (e.g. a service wired
// without one).
func ReadinessHandler(pool Pinger, nc *nats.Conn) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), readyTimeout)
		defer cancel()

		body := map[string]any{"status": "ready"}
		ready := true

		if pool != nil {
			if err := pool.Ping(ctx); err != nil {
				body["database"] = "error: " + err.Error()
				ready = false
			} else {
				body["database"] = "ok"
			}
		}
		if nc != nil {
			if nc.IsConnected() {
				body["nats"] = "ok"
			} else {
				body["nats"] = "disconnected"
				ready = false
			}
		}

		if !ready {
			body["status"] = "not_ready"
			writeJSON(w, http.StatusServiceUnavailable, body)
			return
		}
		writeJSON(w, http.StatusOK, body)
	}
}

func writeJSON(w http.ResponseWriter, code int, body map[string]any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(body)
}
