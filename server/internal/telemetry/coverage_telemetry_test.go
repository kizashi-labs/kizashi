package telemetry

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
)

func TestPgxTracer_Traces(t *testing.T) {
	tr := NewPgxTracer()
	ctx := context.Background()
	c1 := tr.TraceQueryStart(ctx, nil, pgx.TraceQueryStartData{SQL: "SELECT 1", Args: []any{1}})
	tr.TraceQueryEnd(c1, nil, pgx.TraceQueryEndData{})
	c2 := tr.TraceBatchStart(ctx, nil, pgx.TraceBatchStartData{Batch: &pgx.Batch{}})
	tr.TraceBatchQuery(c2, nil, pgx.TraceBatchQueryData{})
	tr.TraceBatchEnd(c2, nil, pgx.TraceBatchEndData{})
	c3 := tr.TraceCopyFromStart(ctx, nil, pgx.TraceCopyFromStartData{})
	tr.TraceCopyFromEnd(c3, nil, pgx.TraceCopyFromEndData{})
	_ = Tracer("cov")
	_, span := StartSpan(ctx, "cov-span")
	span.End()
	_ = Meter("cov")
}
