package handlers

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/sandbox"
	"github.com/edr-platform/server/internal/virustotal"
)

// SandboxHandler manages malware sandbox submissions backed by VirusTotal.
//
// 設定:
//
//	VIRUSTOTAL_API_KEY — VirusTotal API v3 キー
//	未設定の場合、SubmitFile はジョブをキューに追加し、
//	GetResult は "pending" ステータスを返します。
type SandboxHandler struct {
	pool *pgxpool.Pool
	vt   *virustotal.Client     // nil when VIRUSTOTAL_API_KEY is not set
	dyn  *sandbox.DynamicClient // external detonation backend; inert without SANDBOX_URL
}

// NewSandboxHandler creates a new SandboxHandler.
func NewSandboxHandler(pool *pgxpool.Pool) *SandboxHandler {
	return &SandboxHandler{
		pool: pool,
		vt:   virustotal.New(),
		dyn:  sandbox.NewDynamicClient(),
	}
}

func (h *SandboxHandler) ensureTable(ctx context.Context) {
	if h.pool == nil {
		return
	}
	_, _ = h.pool.Exec(ctx, `CREATE TABLE IF NOT EXISTS sandbox_submissions (
	  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
	  file_hash TEXT NOT NULL,
	  file_name TEXT NOT NULL,
	  agent_id UUID,
	  status TEXT NOT NULL DEFAULT 'queued',
	  verdict TEXT,
	  score INT,
	  result JSONB,
	  submitted_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
	  completed_at TIMESTAMPTZ
	)`)
}

// SubmitFile queues a file for sandbox analysis and immediately calls VirusTotal
// if an API key is configured. The result is stored in the database.
// POST /api/v1/sandbox/submit
func (h *SandboxHandler) SubmitFile(c *gin.Context) {
	ctx := c.Request.Context()
	h.ensureTable(ctx)

	var body struct {
		FileHash string  `json:"file_hash" binding:"required"`
		FileName string  `json:"file_name" binding:"required"`
		AgentID  *string `json:"agent_id"`
	}
	if err := c.ShouldBindJSON(&body); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "無効なリクエストボディ"})
		return
	}
	if body.FileHash == "" || body.FileName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "file_hash と file_name は必須です"})
		return
	}

	submissionID := uuid.New().String()
	if h.pool != nil {
		_, err := h.pool.Exec(ctx,
			`INSERT INTO sandbox_submissions (id, file_hash, file_name, agent_id, status)
			 VALUES ($1,$2,$3,$4,'queued')`,
			submissionID, body.FileHash, body.FileName, body.AgentID,
		)
		if err != nil {
			slog.Warn("sandbox: insert submission failed", "error", err)
		}
	}

	// VirusTotal APIキーが設定されている場合はバックグラウンドで即時解析
	if h.vt != nil {
		vtCtx, vtCancel := context.WithTimeout(context.Background(), 5*time.Minute)
		go func() {
			defer vtCancel()
			h.runVirusTotal(vtCtx, submissionID, body.FileHash)
		}()
	}

	vtConfigured := h.vt != nil
	c.JSON(http.StatusAccepted, gin.H{
		"submission_id":          submissionID,
		"status":                 "queued",
		"estimated_time_seconds": 30,
		"virustotal_enabled":     vtConfigured,
	})
}

// runVirusTotal calls VirusTotal and updates the submission in the DB.
func (h *SandboxHandler) runVirusTotal(ctx context.Context, submissionID, fileHash string) {
	report, err := h.vt.LookupHash(ctx, fileHash)
	if err != nil {
		slog.Warn("sandbox: virustotal lookup failed", "hash", fileHash, "error", err)
		if h.pool != nil {
			if _, execErr := h.pool.Exec(ctx,
				`UPDATE sandbox_submissions SET status='error', completed_at=NOW() WHERE id=$1`,
				submissionID); execErr != nil {
				slog.Warn("sandbox: error ステータス更新に失敗しました", "id", submissionID, "error", execErr)
			}
		}
		return
	}

	resultJSON, marshalErr := json.Marshal(report)
	if marshalErr != nil {
		slog.Warn("sandbox: レポートのシリアライズに失敗しました", "id", submissionID, "error", marshalErr)
		resultJSON = []byte("{}")
	}
	if h.pool != nil {
		if _, execErr := h.pool.Exec(ctx,
			`UPDATE sandbox_submissions
			 SET status='completed', verdict=$2, score=$3, result=$4, completed_at=NOW()
			 WHERE id=$1`,
			submissionID, report.Verdict, report.Score, string(resultJSON),
		); execErr != nil {
			slog.Warn("sandbox: completed ステータス更新に失敗しました", "id", submissionID, "error", execErr)
		}
	}
}

// maxAnalyzeBytes caps uploaded file size for static analysis (32 MiB).
const maxAnalyzeBytes = 32 << 20

// AnalyzeUpload runs LOCAL static analysis over an uploaded file and returns a
// verdict synchronously — no external service, no execution, works offline and on
// unknown samples (the gap the hash-only VirusTotal path leaves). Embedded IOCs
// are correlated against the local threat-intel DB. POST /api/v1/sandbox/analyze
// (multipart/form-data, field "file").
func (h *SandboxHandler) AnalyzeUpload(c *gin.Context) {
	ctx := c.Request.Context()
	h.ensureTable(ctx)

	fh, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "multipart フィールド 'file' が必要です"})
		return
	}
	if fh.Size > maxAnalyzeBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "ファイルが大きすぎます(最大32MiB)"})
		return
	}
	f, err := fh.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ファイルを開けません"})
		return
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxAnalyzeBytes))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ファイル読み取りに失敗しました"})
		return
	}

	v := sandbox.AnalyzeStatic(fh.Filename, data)

	// Correlate embedded IOCs with the local threat-intel DB; a known-bad indicator
	// inside the file is a strong signal, so escalate the verdict.
	knownBad := h.correlateIOCs(ctx, v)
	if len(knownBad) > 0 {
		v.Score += 40
		if v.Score > 100 {
			v.Score = 100
		}
		v.Verdict = "malicious"
		v.Reasons = append(v.Reasons, "埋め込み IOC が脅威インテリで既知の悪性: "+strings.Join(knownBad, ", "))
	}

	resultJSON, _ := json.Marshal(gin.H{"static": v, "known_bad_iocs": knownBad})
	submissionID := uuid.New().String()
	if h.pool != nil {
		if _, err := h.pool.Exec(ctx,
			`INSERT INTO sandbox_submissions (id, file_hash, file_name, status, verdict, score, result, completed_at)
			 VALUES ($1,$2,$3,'completed',$4,$5,$6,NOW())`,
			submissionID, v.SHA256, fh.Filename, v.Verdict, v.Score, string(resultJSON),
		); err != nil {
			slog.Warn("sandbox: static submission insert failed", "error", err)
		}
	}

	c.JSON(http.StatusOK, gin.H{
		"submission_id":  submissionID,
		"analysis":       "static",
		"static":         v,
		"known_bad_iocs": knownBad,
	})
}

// correlateIOCs returns the subset of the file's embedded IOCs that appear as
// enabled entries in the local ioc_entries table (best-effort).
func (h *SandboxHandler) correlateIOCs(ctx context.Context, v sandbox.StaticVerdict) []string {
	if h.pool == nil {
		return nil
	}
	candidates := make([]string, 0, len(v.URLs)+len(v.IPs)+len(v.Domains))
	candidates = append(candidates, v.URLs...)
	candidates = append(candidates, v.IPs...)
	candidates = append(candidates, v.Domains...)
	if len(candidates) == 0 {
		return nil
	}
	var exists bool
	if err := h.pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name='ioc_entries')`).Scan(&exists); err != nil || !exists {
		return nil
	}
	rows, err := h.pool.Query(ctx,
		`SELECT value FROM ioc_entries WHERE value = ANY($1) AND enabled = true`, candidates)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var hits []string
	for rows.Next() {
		var val string
		if rows.Scan(&val) == nil {
			hits = append(hits, val)
		}
	}
	return hits
}

// Detonate submits an uploaded file to the external dynamic sandbox for
// detonation and returns a job id to poll. When no external backend is configured
// (SANDBOX_URL unset) it degrades to local static analysis so the endpoint still
// returns a useful verdict. POST /api/v1/sandbox/detonate (multipart, field "file").
func (h *SandboxHandler) Detonate(c *gin.Context) {
	ctx := c.Request.Context()
	h.ensureTable(ctx)

	fh, err := c.FormFile("file")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "multipart フィールド 'file' が必要です"})
		return
	}
	if fh.Size > maxAnalyzeBytes {
		c.JSON(http.StatusRequestEntityTooLarge, gin.H{"error": "ファイルが大きすぎます(最大32MiB)"})
		return
	}
	f, err := fh.Open()
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ファイルを開けません"})
		return
	}
	defer func() { _ = f.Close() }()
	data, err := io.ReadAll(io.LimitReader(f, maxAnalyzeBytes))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ファイル読み取りに失敗しました"})
		return
	}

	// No external backend → fall back to local static analysis.
	if h.dyn == nil || !h.dyn.Configured() {
		v := sandbox.AnalyzeStatic(fh.Filename, data)
		c.JSON(http.StatusOK, gin.H{
			"analysis": "static_fallback",
			"note":     "動的サンドボックス未設定(SANDBOX_URL)。ローカル静的解析にフォールバックしました。",
			"static":   v,
		})
		return
	}

	jobID, err := h.dyn.Submit(ctx, fh.Filename, data)
	if err != nil {
		slog.Warn("sandbox: dynamic submit failed", "error", err)
		c.JSON(http.StatusBadGateway, gin.H{"error": "動的サンドボックスへの投入に失敗しました"})
		return
	}
	submissionID := uuid.New().String()
	if h.pool != nil {
		if _, err := h.pool.Exec(ctx,
			`INSERT INTO sandbox_submissions (id, file_hash, file_name, status, result)
			 VALUES ($1,$2,$3,'running',$4)`,
			submissionID, "", fh.Filename, `{"backend":"dynamic","job_id":"`+jobID+`"}`,
		); err != nil {
			slog.Warn("sandbox: dynamic submission insert failed", "error", err)
		}
	}
	c.JSON(http.StatusAccepted, gin.H{
		"submission_id": submissionID,
		"analysis":      "dynamic",
		"job_id":        jobID,
		"status":        "running",
	})
}

// DetonateReport polls the external sandbox for a detonation report.
// GET /api/v1/sandbox/detonate/:jobId
func (h *SandboxHandler) DetonateReport(c *gin.Context) {
	if h.dyn == nil || !h.dyn.Configured() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "動的サンドボックス未設定(SANDBOX_URL)"})
		return
	}
	jobID := c.Param("jobId")
	rep, err := h.dyn.Report(c.Request.Context(), jobID)
	if err != nil {
		c.JSON(http.StatusBadGateway, gin.H{"error": "レポート取得に失敗しました", "detail": err.Error()})
		return
	}
	c.JSON(http.StatusOK, rep)
}

// GetResult returns the analysis result for a submission.
// GET /api/v1/sandbox/:submissionId
func (h *SandboxHandler) GetResult(c *gin.Context) {
	ctx := c.Request.Context()
	h.ensureTable(ctx)

	submissionID := c.Param("submissionId")
	if h.pool == nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "データベース未接続"})
		return
	}

	var (
		id          string
		fileHash    string
		fileName    string
		status      string
		verdict     *string
		score       *int
		resultJSON  *string
		submittedAt time.Time
		completedAt *time.Time
	)
	err := h.pool.QueryRow(ctx,
		`SELECT id, file_hash, file_name, status, verdict, score, result, submitted_at, completed_at
		 FROM sandbox_submissions WHERE id=$1`, submissionID,
	).Scan(&id, &fileHash, &fileName, &status, &verdict, &score, &resultJSON,
		&submittedAt, &completedAt)

	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "提出物が見つかりません"})
		return
	}

	resp := gin.H{
		"submission_id": id,
		"file_hash":     fileHash,
		"file_name":     fileName,
		"status":        status,
		"submitted_at":  submittedAt.Format(time.RFC3339),
	}
	if verdict != nil {
		resp["verdict"] = *verdict
	}
	if score != nil {
		resp["score"] = *score
	}
	if completedAt != nil {
		resp["completed_at"] = completedAt.Format(time.RFC3339)
	}

	// VirusTotal のレポートを展開
	if resultJSON != nil && *resultJSON != "" {
		var report virustotal.FileReport
		if err := json.Unmarshal([]byte(*resultJSON), &report); err == nil {
			resp["detection_count"] = report.DetectionCount
			resp["total_engines"] = report.TotalEngines
			resp["signatures"] = report.Signatures
			resp["network_indicators"] = report.NetworkIndicators
			resp["meaningful_name"] = report.MeaningfulName
			resp["type_description"] = report.TypeDescription
			if report.FirstSeen != nil {
				resp["first_seen"] = report.FirstSeen.Format(time.RFC3339)
			}
			if report.LastAnalysis != nil {
				resp["last_analysis"] = report.LastAnalysis.Format(time.RFC3339)
			}
		}
	}

	c.JSON(http.StatusOK, resp)
}

// ListSubmissions lists sandbox submissions with optional filters.
// GET /api/v1/sandbox/submissions
func (h *SandboxHandler) ListSubmissions(c *gin.Context) {
	ctx := c.Request.Context()
	h.ensureTable(ctx)

	agentID := c.Query("agent_id")
	verdict := c.Query("verdict")
	status := c.Query("status")
	limit, _ := strconv.Atoi(c.DefaultQuery("limit", "50"))
	offset, _ := strconv.Atoi(c.DefaultQuery("offset", "0"))
	if limit <= 0 || limit > 200 {
		limit = 50
	}

	if h.pool == nil {
		c.JSON(http.StatusOK, gin.H{"submissions": []interface{}{}, "total": 0})
		return
	}

	query := `SELECT id, file_hash, file_name, agent_id, status, verdict, score,
	                 submitted_at, completed_at
	          FROM sandbox_submissions WHERE 1=1`
	args := []interface{}{}
	i := 1
	if agentID != "" {
		query += ` AND agent_id=$` + strconv.Itoa(i)
		args = append(args, agentID)
		i++
	}
	if verdict != "" {
		query += ` AND verdict=$` + strconv.Itoa(i)
		args = append(args, verdict)
		i++
	}
	if status != "" {
		query += ` AND status=$` + strconv.Itoa(i)
		args = append(args, status)
		i++
	}
	query += ` ORDER BY submitted_at DESC LIMIT $` + strconv.Itoa(i) +
		` OFFSET $` + strconv.Itoa(i+1)
	args = append(args, limit, offset)

	rows, err := h.pool.Query(ctx, query, args...)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{"submissions": []interface{}{}, "total": 0})
		return
	}
	defer rows.Close()

	type submission struct {
		ID          string  `json:"id"`
		FileHash    string  `json:"file_hash"`
		FileName    string  `json:"file_name"`
		AgentID     *string `json:"agent_id"`
		Status      string  `json:"status"`
		Verdict     *string `json:"verdict"`
		Score       *int    `json:"score"`
		SubmittedAt string  `json:"submitted_at"`
		CompletedAt *string `json:"completed_at"`
	}

	var result []submission
	for rows.Next() {
		var s submission
		var submittedAt time.Time
		var completedAt *time.Time
		if err := rows.Scan(
			&s.ID, &s.FileHash, &s.FileName, &s.AgentID, &s.Status,
			&s.Verdict, &s.Score, &submittedAt, &completedAt,
		); err != nil {
			continue
		}
		s.SubmittedAt = submittedAt.Format(time.RFC3339)
		if completedAt != nil {
			t := completedAt.Format(time.RFC3339)
			s.CompletedAt = &t
		}
		result = append(result, s)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("row iteration error", "error", err)
	}
	if result == nil {
		result = []submission{}
	}
	c.JSON(http.StatusOK, gin.H{"submissions": result, "total": len(result)})
}

// GetStats returns sandbox submission statistics.
// GET /api/v1/sandbox/stats
func (h *SandboxHandler) GetStats(c *gin.Context) {
	ctx := c.Request.Context()
	h.ensureTable(ctx)

	if h.pool == nil {
		c.JSON(http.StatusOK, gin.H{
			"submissions_today":  0,
			"submissions_week":   0,
			"verdicts":           gin.H{"malicious": 0, "benign": 0, "suspicious": 0},
			"virustotal_enabled": h.vt != nil,
		})
		return
	}

	var today, week, malicious, benign, suspicious, unknown int
	err := h.pool.QueryRow(ctx,
		`SELECT
		  COUNT(*) FILTER (WHERE submitted_at >= NOW() - INTERVAL '1 day'),
		  COUNT(*) FILTER (WHERE submitted_at >= NOW() - INTERVAL '7 days'),
		  COUNT(*) FILTER (WHERE verdict='malicious'),
		  COUNT(*) FILTER (WHERE verdict='benign' OR verdict='undetected'),
		  COUNT(*) FILTER (WHERE verdict='suspicious'),
		  COUNT(*) FILTER (WHERE verdict='unknown' OR verdict IS NULL)
		 FROM sandbox_submissions`,
	).Scan(&today, &week, &malicious, &benign, &suspicious, &unknown)
	if err != nil {
		c.JSON(http.StatusOK, gin.H{
			"submissions_today":  0,
			"submissions_week":   0,
			"verdicts":           gin.H{},
			"virustotal_enabled": h.vt != nil,
		})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"submissions_today": today,
		"submissions_week":  week,
		"verdicts": gin.H{
			"malicious":  malicious,
			"benign":     benign,
			"suspicious": suspicious,
			"unknown":    unknown,
		},
		"virustotal_enabled": h.vt != nil,
	})
}
