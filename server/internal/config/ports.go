package config

// Well-known port numbers for the EDR Platform services.
// These constants are the single source of truth for port assignments.
// Keep in sync with:
//   - docker-compose.yml environment variables
//   - agent/internal/config/config.go ServerConfig.GRPCPort default
//   - docs/server-installation.md network requirements table
const (
	// DefaultAPIHTTPPort is the REST API / WebSocket port.
	DefaultAPIHTTPPort = 8080

	// DefaultAPIGRPCPort is the gRPC port on the API service (enrollment, commands).
	DefaultAPIGRPCPort = 9090

	// DefaultIngestionGRPCPort is the gRPC port on the Ingestion service
	// (event streaming from agents to server).
	DefaultIngestionGRPCPort = 9091

	// DefaultIngestionMetricsPort is the Prometheus metrics scrape port
	// on the Ingestion service.
	DefaultIngestionMetricsPort = 8082

	// DefaultFrontendPort is the Next.js frontend port.
	DefaultFrontendPort = 3000

	// DefaultPostgresPort is the TimescaleDB/PostgreSQL port.
	DefaultPostgresPort = 5432

	// DefaultNATSPort is the NATS client connection port.
	DefaultNATSPort = 4222

	// DefaultNATSMonitorPort is the NATS HTTP monitoring port.
	DefaultNATSMonitorPort = 8222

	// DefaultPrometheusPort is the external Prometheus port
	// (mapped to 9090 inside the container; offset externally to avoid
	// conflict with DefaultAPIGRPCPort on the host).
	DefaultPrometheusExternalPort = 9095

	// DefaultGrafanaPort is the Grafana dashboard external port
	// (mapped to 3000 inside the container; offset to avoid conflict
	// with DefaultFrontendPort on the host).
	DefaultGrafanaExternalPort = 3001
)
