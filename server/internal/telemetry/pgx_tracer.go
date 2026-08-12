package telemetry

import (
	"context"
	"strings"

	"github.com/jackc/pgx/v5"
	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

// pgxSpanKey is the context key used to store the active DB span.
type pgxSpanKey struct{}

// PgxTracer implements pgx.QueryTracer, pgx.BatchTracer, and pgx.CopyFromTracer.
// It creates an OTEL child span for every SQL statement executed through pgx.
// When no OTEL exporter is configured the global provider is a no-op, so this
// tracer has effectively zero overhead.
type PgxTracer struct {
	tracer trace.Tracer
}

// NewPgxTracer creates a PgxTracer that instruments pgx queries with OTEL spans.
// Attach it to pgxpool.Config.ConnConfig.Tracer before opening the pool.
func NewPgxTracer() *PgxTracer {
	return &PgxTracer{tracer: otel.Tracer("edr-pgx")}
}

// ── QueryTracer ───────────────────────────────────────────────────────────────

func (t *PgxTracer) TraceQueryStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryStartData) context.Context {
	spanName := "db." + sqlVerb(data.SQL)
	ctx, span := t.tracer.Start(ctx, spanName,
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("db.system", "postgresql"),
			attribute.String("db.statement", sanitizeSQL(data.SQL)),
		),
	)
	return context.WithValue(ctx, pgxSpanKey{}, span)
}

func (t *PgxTracer) TraceQueryEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceQueryEndData) {
	span, _ := ctx.Value(pgxSpanKey{}).(trace.Span)
	if span == nil {
		return
	}
	if data.Err != nil {
		span.RecordError(data.Err)
		span.SetStatus(codes.Error, data.Err.Error())
	} else {
		span.SetAttributes(attribute.Int("db.rows_affected", int(data.CommandTag.RowsAffected())))
	}
	span.End()
}

// ── BatchTracer ───────────────────────────────────────────────────────────────

func (t *PgxTracer) TraceBatchStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceBatchStartData) context.Context {
	ctx, span := t.tracer.Start(ctx, "db.batch",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("db.system", "postgresql"),
			attribute.Int("db.batch.size", data.Batch.Len()),
		),
	)
	return context.WithValue(ctx, pgxSpanKey{}, span)
}

func (t *PgxTracer) TraceBatchQuery(_ context.Context, _ *pgx.Conn, _ pgx.TraceBatchQueryData) {}

func (t *PgxTracer) TraceBatchEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceBatchEndData) {
	span, _ := ctx.Value(pgxSpanKey{}).(trace.Span)
	if span == nil {
		return
	}
	if data.Err != nil {
		span.RecordError(data.Err)
		span.SetStatus(codes.Error, data.Err.Error())
	}
	span.End()
}

// ── CopyFromTracer ────────────────────────────────────────────────────────────

func (t *PgxTracer) TraceCopyFromStart(ctx context.Context, _ *pgx.Conn, data pgx.TraceCopyFromStartData) context.Context {
	ctx, span := t.tracer.Start(ctx, "db.copy_from",
		trace.WithSpanKind(trace.SpanKindClient),
		trace.WithAttributes(
			attribute.String("db.system", "postgresql"),
			attribute.String("db.table", data.TableName.Sanitize()),
		),
	)
	return context.WithValue(ctx, pgxSpanKey{}, span)
}

func (t *PgxTracer) TraceCopyFromEnd(ctx context.Context, _ *pgx.Conn, data pgx.TraceCopyFromEndData) {
	span, _ := ctx.Value(pgxSpanKey{}).(trace.Span)
	if span == nil {
		return
	}
	if data.Err != nil {
		span.RecordError(data.Err)
		span.SetStatus(codes.Error, data.Err.Error())
	} else {
		span.SetAttributes(attribute.Int64("db.rows_copied", data.CommandTag.RowsAffected()))
	}
	span.End()
}

// ── Helpers ───────────────────────────────────────────────────────────────────

// sqlVerb extracts the first keyword (SELECT, INSERT, UPDATE, DELETE, …)
// from a SQL statement to use as the span name suffix.
func sqlVerb(sql string) string {
	sql = strings.TrimSpace(sql)
	if idx := strings.IndexAny(sql, " \t\n"); idx > 0 {
		return strings.ToLower(sql[:idx])
	}
	if len(sql) > 12 {
		return strings.ToLower(sql[:12])
	}
	return strings.ToLower(sql)
}

// sanitizeSQL truncates long statements to avoid excessive span attribute size.
func sanitizeSQL(sql string) string {
	const maxLen = 512
	sql = strings.TrimSpace(sql)
	if len(sql) > maxLen {
		return sql[:maxLen] + "…"
	}
	return sql
}
