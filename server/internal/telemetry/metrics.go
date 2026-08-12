// Package telemetry provides OpenTelemetry helpers for tracing and metrics.
package telemetry

import (
	"context"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/metric"
	"go.opentelemetry.io/otel/metric/noop"
)

// InitMetrics initializes the global OTel MeterProvider.
//
// If OTEL_EXPORTER_OTLP_ENDPOINT is set, an OTLP gRPC exporter is used.
// Otherwise a no-op provider is installed so all otel.Meter() calls remain
// valid without panicking.
//
// To enable full OTLP metrics export, add the following packages and
// uncomment the OTLP section below:
//
//	go get go.opentelemetry.io/otel/sdk/metric
//	go get go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetricgrpc
//
// Returns a shutdown function that must be called on application exit.
func InitMetrics(_ context.Context, _ string) (func(context.Context) error, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		// No exporter configured — use no-op provider.
		mp := noop.NewMeterProvider()
		otel.SetMeterProvider(mp)
		return func(_ context.Context) error { return nil }, nil
	}

	// ── OTLP export (uncomment after adding sdk/metric dependency) ──
	//
	// exporter, err := otlpmetricgrpc.New(ctx,
	//     otlpmetricgrpc.WithEndpoint(endpoint),
	//     otlpmetricgrpc.WithInsecure(),
	// )
	// if err != nil {
	//     return nil, fmt.Errorf("create OTLP metric exporter: %w", err)
	// }
	// res, _ := resource.New(ctx, resource.WithAttributes(semconv.ServiceName(serviceName)))
	// mp := sdkmetric.NewMeterProvider(
	//     sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exporter,
	//         sdkmetric.WithInterval(30*time.Second))),
	//     sdkmetric.WithResource(res),
	// )
	// otel.SetMeterProvider(mp)
	// return mp.Shutdown, nil

	// Fallback until OTLP metric packages are added.
	noopMP := noop.NewMeterProvider()
	otel.SetMeterProvider(noopMP)
	return func(_ context.Context) error { return nil }, nil
}

// Meter returns a named OTel meter from the global provider.
// Use this in service packages to record custom metrics.
func Meter(name string) metric.Meter {
	return otel.GetMeterProvider().Meter(name)
}
