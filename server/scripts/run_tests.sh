#!/bin/bash
# Run all server tests.
# Usage:
#   ./scripts/run_tests.sh              — unit tests + benchmarks
#   TEST_DB_URL=... ./scripts/run_tests.sh  — also run integration tests
set -e

cd "$(dirname "$0")/.."

echo "=== Running ML Unit Tests ==="
go test ./internal/ml/... -v -count=1 -timeout 60s

echo ""
echo "=== Running Handler Tests ==="
go test ./internal/api/handlers/... -v -count=1 -timeout 60s

echo ""
echo "=== Running Benchmarks (ML) ==="
go test ./internal/ml/... -bench=. -benchmem -count=1 -run='^$' -timeout 120s

echo ""
echo "=== Running Handler Benchmarks ==="
go test ./internal/api/handlers/... -bench=BenchmarkHealthHandler -benchmem -count=1 -run='^$' -timeout 60s

echo ""
echo "=== Running Race Detector (ML) ==="
# Race detector requires CGO. Skip gracefully if not available.
if CGO_ENABLED=1 go env CGO_ENABLED >/dev/null 2>&1 && command -v gcc >/dev/null 2>&1; then
  CGO_ENABLED=1 go test -race ./internal/ml/... -count=1 -timeout 120s
else
  echo "(Race detector skipped: CGO/gcc not available — run on Linux/macOS CI)"
fi

if [ -n "$TEST_DB_URL" ]; then
  echo ""
  echo "=== Running API Integration Tests (TEST_DB_URL is set) ==="
  go test -tags=integration ./internal/api/... -v -count=1 -timeout 120s
else
  echo ""
  echo "(Skipping API integration tests: TEST_DB_URL not set)"
fi

echo ""
echo "All tests passed!"
