package handlers

import (
	"net/http"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SecurityDWHandler struct{ pool *pgxpool.Pool }

func NewSecurityDWHandler(pool *pgxpool.Pool) *SecurityDWHandler {
	return &SecurityDWHandler{pool: pool}
}

func (h *SecurityDWHandler) ListDatasets(c *gin.Context) {
	datasets := []gin.H{
		{"id": uuid.New(), "name": "アラートデータセット", "source_type": "alerts_db", "status": "active", "row_count": 2847391, "size_bytes": int64(1.2e9), "retention_days": 365, "last_ingested_at": time.Now().Add(-5 * time.Minute)},
		{"id": uuid.New(), "name": "エンドポイントテレメトリ", "source_type": "endpoint_events", "status": "active", "row_count": 847293847, "size_bytes": int64(450e9), "retention_days": 90, "last_ingested_at": time.Now().Add(-1 * time.Minute)},
		{"id": uuid.New(), "name": "ネットワークフロー", "source_type": "network_flows", "status": "active", "row_count": 123456789, "size_bytes": int64(89e9), "retention_days": 180, "last_ingested_at": time.Now().Add(-2 * time.Minute)},
		{"id": uuid.New(), "name": "脆弱性スキャン結果", "source_type": "vuln_scans", "status": "active", "row_count": 456123, "size_bytes": int64(2.3e8), "retention_days": 730, "last_ingested_at": time.Now().Add(-1 * time.Hour)},
	}
	c.JSON(http.StatusOK, gin.H{"datasets": datasets, "total": len(datasets)})
}

func (h *SecurityDWHandler) ExecuteQuery(c *gin.Context) {
	var req gin.H
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid request"})
		return
	}
	queryID := uuid.New()
	c.JSON(http.StatusOK, gin.H{
		"query_id": queryID, "status": "running",
		"message":           "クエリを実行中です",
		"estimated_seconds": 3,
	})
}

func (h *SecurityDWHandler) GetQueryResult(c *gin.Context) {
	id := c.Param("id")
	c.JSON(http.StatusOK, gin.H{
		"query_id": id, "status": "completed",
		"rows_returned": 1247, "execution_ms": 2341,
		"result_preview": []gin.H{
			{"timestamp": time.Now().Add(-1 * time.Hour), "alert_type": "malware", "severity": "critical", "count": 3},
			{"timestamp": time.Now().Add(-2 * time.Hour), "alert_type": "network_anomaly", "severity": "high", "count": 12},
		},
	})
}

func (h *SecurityDWHandler) GetStats(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{
		"total_datasets": 4, "total_rows": int64(974053563),
		"total_size_bytes": int64(542.5e9),
		"queries_today":    47, "avg_query_ms": 1823,
		"ingestion_rate_per_sec": 12847,
	})
}
