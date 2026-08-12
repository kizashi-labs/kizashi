// Package telemetry provides OpenTelemetry tracing helpers.
package telemetry

import (
	"context"
	"os"
	"strconv"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracegrpc"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	semconv "go.opentelemetry.io/otel/semconv/v1.21.0"
	"go.opentelemetry.io/otel/trace"
)

// InitTracer initializes the global OTEL tracer provider.
//
// Environment variables:
//
//	OTEL_EXPORTER_OTLP_ENDPOINT  — gRPC endpoint (e.g. "jaeger:4317").
//	                               If unset, a no-op provider is installed.
//	OTEL_SAMPLE_RATIO            — fraction of traces to sample (0.0–1.0).
//	                               Defaults to 1.0 (always sample).
//	SERVICE_VERSION              — version string attached to every span.
//	DEPLOYMENT_ENV               — environment tag ("production", "staging", etc.)
//
// The returned shutdown function must be called on application exit to flush
// and close the provider.
func InitTracer(ctx context.Context, serviceName string) (func(context.Context) error, error) {
	endpoint := os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT")
	if endpoint == "" {
		noop := sdktrace.NewTracerProvider()
		otel.SetTracerProvider(noop)
		return func(_ context.Context) error { return noop.Shutdown(ctx) }, nil
	}

	exporter, err := otlptracegrpc.New(ctx,
		otlptracegrpc.WithEndpoint(endpoint),
		otlptracegrpc.WithInsecure(),
	)
	if err != nil {
		return nil, err
	}

	// Build resource attributes.
	attrs := []attribute.KeyValue{
		semconv.ServiceName(serviceName),
	}
	if v := os.Getenv("SERVICE_VERSION"); v != "" {
		attrs = append(attrs, semconv.ServiceVersion(v))
	}
	if e := os.Getenv("DEPLOYMENT_ENV"); e != "" {
		attrs = append(attrs, semconv.DeploymentEnvironment(e))
	}

	res, err := resource.New(ctx,
		resource.WithAttributes(attrs...),
		resource.WithHost(),
		resource.WithOS(),
		resource.WithProcess(),
	)
	if err != nil {
		// resource.New returns partial errors for optional detectors — still usable.
		res, _ = resource.New(ctx, resource.WithAttributes(attrs...))
	}

	// Sampler: TraceIDRatioBased (defaults to 1.0 = always).
	ratio := 1.0
	if r := os.Getenv("OTEL_SAMPLE_RATIO"); r != "" {
		if v, err := strconv.ParseFloat(r, 64); err == nil && v >= 0 && v <= 1 {
			ratio = v
		}
	}
	sampler := sdktrace.ParentBased(sdktrace.TraceIDRatioBased(ratio))

	tp := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
		sdktrace.WithSampler(sampler),
	)
	otel.SetTracerProvider(tp)

	return tp.Shutdown, nil
}

// Tracer returns a named tracer from the global provider.
// Callers can use this to create child spans inside handlers or services.
func Tracer(name string) trace.Tracer {
	return otel.Tracer(name)
}

// StartSpan is a convenience wrapper that starts a named child span and
// returns the derived context along with the span.
//
//	ctx, span := telemetry.StartSpan(ctx, "store.QueryAlerts")
//	defer span.End()
func StartSpan(ctx context.Context, spanName string, opts ...trace.SpanStartOption) (context.Context, trace.Span) {
	return otel.Tracer("edr-api").Start(ctx, spanName, opts...)
}
