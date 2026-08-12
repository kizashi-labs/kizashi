package scheduler

import (
	"context"
	"github.com/edr-platform/server/internal/detection"
	"log/slog"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

// ComplianceScorer periodically calculates compliance scores and stores history.
type ComplianceScorer struct {
	pool *pgxpool.Pool
}

func NewComplianceScorer(pool *pgxpool.Pool) *ComplianceScorer {
	return &ComplianceScorer{pool: pool}
}

func (s *ComplianceScorer) Run(ctx context.Context) {
	// Run every 6 hours
	ticker := time.NewTicker(6 * time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			s.calculate(ctx)
		}
	}
}

func (s *ComplianceScorer) calculate(ctx context.Context) {
	// 1. Check if compliance_scores table exists. If not, return.
	var exists bool
	err := s.pool.QueryRow(ctx,
		`SELECT EXISTS (
			SELECT 1 FROM information_schema.tables
			WHERE table_schema = 'public' AND table_name = 'compliance_scores'
		)`).Scan(&exists)
	if err != nil || !exists {
		slog.Warn("コンプライアンススコアテーブルが存在しません、スキップします")
		return
	}

	// 2. Calculate MITRE score:
	//    アラートが触れた ATT&CK タクティクの種類数 / 14 * 100
	//
	// 以前は alerts.mitre_tags を unnest していたが、alerts にその列は無く
	// (実在するのは mitre_technique と ai_mitre_tags)、クエリは毎回
	// "column mitre_tags does not exist" で失敗していた。err は握って
	// coveredTactics=0 にするだけなので、MITRE スコアは常に 0 だった。
	//
	// スコアは 14 で割る = タクティク数が分母なので、テクニックをそのまま
	// 数えるのではなくタクティクへ写してから数える。写像は kill-chain 相関が
	// 使っているものを共有する (detection.TacticForTechnique)。scorer 側で
	// 別表を持つと、片方だけ更新されて数字が食い違う。
	coveredTactics := 0
	rows, err := s.pool.Query(ctx, `
		SELECT DISTINCT mitre_technique FROM alerts
		WHERE mitre_technique IS NOT NULL AND mitre_technique != ''
	`)
	if err != nil {
		slog.Error("MITREスコア計算エラー", "error", err)
	} else {
		tactics := map[string]struct{}{}
		for rows.Next() {
			var tech string
			if err := rows.Scan(&tech); err != nil {
				continue
			}
			// 未知のテクニックは "unknown" が返る。タクティクとして数えない。
			if tactic := detection.TacticForTechnique(tech); tactic != "" && tactic != "unknown" {
				tactics[tactic] = struct{}{}
			}
		}
		if err := rows.Err(); err != nil {
			slog.Error("MITREスコア計算エラー", "error", err)
		}
		rows.Close()
		coveredTactics = len(tactics)
	}
	const totalTactics = 14
	if coveredTactics > totalTactics {
		coveredTactics = totalTactics
	}
	mitreScore := float64(coveredTactics) / float64(totalTactics) * 100.0

	// 3. Calculate CIS score:
	//    Count enabled rules / 18 * 100, cap at 95
	var enabledRules int
	err = s.pool.QueryRow(ctx,
		`SELECT COUNT(*) FROM rules WHERE enabled = TRUE`).Scan(&enabledRules)
	if err != nil {
		slog.Error("CISスコア計算エラー", "error", err)
		enabledRules = 0
	}
	cisScore := float64(enabledRules) / 18.0 * 100.0
	if cisScore > 95.0 {
		cisScore = 95.0
	}

	// 4. Calculate NIST CSF score (5 Functions: Identify / Protect / Detect / Respond / Recover)
	//
	// ID (Identify): オンラインエージェント率 → アセット把握度
	var totalAgents, onlineAgents int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM agents`).Scan(&totalAgents)
	_ = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM agents WHERE last_seen >= NOW() - INTERVAL '10 minutes'`,
	).Scan(&onlineAgents)
	identifyScore := 0.0
	if totalAgents > 0 {
		identifyScore = float64(onlineAgents) / float64(totalAgents) * 100.0
	}

	// PR (Protect): 有効ルール率
	var totalRules int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM rules`).Scan(&totalRules)
	protectScore := 0.0
	if totalRules > 0 {
		protectScore = float64(enabledRules) / float64(totalRules) * 100.0
	}

	// DE (Detect): アラート検知率（直近7日でアラートが存在すれば上昇）
	var alertCount, recentAlerts int
	_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM alerts`).Scan(&alertCount)
	_ = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM alerts WHERE created_at >= NOW() - INTERVAL '7 days'`,
	).Scan(&recentAlerts)
	detectScore := 40.0
	if alertCount > 0 {
		detectScore = 70.0
	}
	if recentAlerts > 0 {
		detectScore = 85.0
	}

	// RS (Respond): アラート解決率
	var resolvedAlerts int
	_ = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM alerts WHERE status IN ('resolved','closed')`,
	).Scan(&resolvedAlerts)
	respondScore := 0.0
	if alertCount > 0 {
		respondScore = float64(resolvedAlerts) / float64(alertCount) * 100.0
	}

	// RC (Recover): バックアップ設定の有無をbackup_schedulesテーブルで確認
	var backupCount int
	_ = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema='public' AND table_name='backup_schedules'`).Scan(&backupCount)
	recoverScore := 30.0
	if backupCount > 0 {
		var scheduledBackups int
		_ = s.pool.QueryRow(ctx, `SELECT COUNT(*) FROM backup_schedules WHERE enabled = true`).Scan(&scheduledBackups)
		if scheduledBackups > 0 {
			recoverScore = 80.0
		} else {
			recoverScore = 50.0
		}
	}

	// NIST CSF 総合スコア (各ファンクションを均等に重み付け)
	nistScore := (identifyScore + protectScore + detectScore + respondScore + recoverScore) / 5.0

	// 5. ISO 27001 score: 監査ログ・インシデント管理・ポリシー策定を考慮
	var auditLogCount int
	_ = s.pool.QueryRow(ctx, `
		SELECT COUNT(*) FROM information_schema.tables
		WHERE table_schema='public' AND table_name='audit_logs'`).Scan(&auditLogCount)
	var recentAuditLogs int
	if auditLogCount > 0 {
		_ = s.pool.QueryRow(ctx, `
			SELECT COUNT(*) FROM audit_logs WHERE created_at >= NOW() - INTERVAL '30 days'`,
		).Scan(&recentAuditLogs)
	}

	// ISO 27001スコア算出ロジック
	iso27001Score := 40.0
	if recentAuditLogs > 0 {
		iso27001Score += 20.0 // A.12.4 監査ログ
	}
	if enabledRules > 0 {
		iso27001Score += 15.0 // A.12.6 技術的脆弱性管理
	}
	if resolvedAlerts > 0 {
		iso27001Score += 15.0 // A.16 情報セキュリティインシデント管理
	}
	if onlineAgents > 0 {
		iso27001Score += 10.0 // A.8 資産管理
	}
	if iso27001Score > 95.0 {
		iso27001Score = 95.0
	}

	type frameworkScore struct {
		framework string
		score     float64
		details   string
	}

	scores := []frameworkScore{
		{
			framework: "mitre",
			score:     mitreScore,
			details:   `{"covered_tactics":` + itoa(coveredTactics) + `,"total_tactics":14}`,
		},
		{
			framework: "cis",
			score:     cisScore,
			details:   `{"enabled_rules":` + itoa(enabledRules) + `,"benchmark_controls":18}`,
		},
		{
			framework: "nist",
			score:     nistScore,
			details: `{"identify":` + fmtScore(identifyScore) +
				`,"protect":` + fmtScore(protectScore) +
				`,"detect":` + fmtScore(detectScore) +
				`,"respond":` + fmtScore(respondScore) +
				`,"recover":` + fmtScore(recoverScore) + `}`,
		},
		{
			framework: "iso27001",
			score:     iso27001Score,
			details: `{"audit_logs_30d":` + itoa(recentAuditLogs) +
				`,"enabled_rules":` + itoa(enabledRules) +
				`,"resolved_alerts":` + itoa(resolvedAlerts) + `}`,
		},
	}

	// 5. 組織全体スコアを履歴テーブルへ書く。
	//
	// 以前は compliance_scores に入れようとしていたが、あちらは
	// agent_id NOT NULL / UNIQUE(agent_id, framework) の**エージェント単位**の
	// テーブルで、agent_id を渡していなかったため 4 フレームワークとも
	// 毎回 NOT NULL 制約違反で落ちていた (一度も保存されたことがない)。
	// agent_id を埋めても UNIQUE 制約で 2 行目が入らず履歴にならないため、
	// 用途ごとにテーブルを分けた (migration 367)。
	for _, fs := range scores {
		_, err = s.pool.Exec(ctx, `
			INSERT INTO compliance_score_history (framework, score, details, calculated_at)
			VALUES ($1, $2, $3::jsonb, NOW())
		`, fs.framework, fs.score, fs.details)
		if err != nil {
			slog.Error("コンプライアンススコア保存エラー", "framework", fs.framework, "error", err)
		}
	}

	// 6. Keep only last 30 days of history
	_, err = s.pool.Exec(ctx, `
		DELETE FROM compliance_score_history
		WHERE calculated_at < NOW() - INTERVAL '30 days'
	`)
	if err != nil {
		slog.Error("コンプライアンス履歴クリーンアップエラー", "error", err)
	}

	slog.Info("コンプライアンススコアを計算しました",
		"mitre", mitreScore,
		"cis", cisScore,
		"nist", nistScore,
		"iso27001", iso27001Score,
		"agents_total", totalAgents,
		"agents_online", onlineAgents,
		"rules_enabled", enabledRules,
		"alerts_resolved", resolvedAlerts,
	)
}

// fmtScore formats a float64 score as a 2-decimal JSON number string.
func fmtScore(f float64) string {
	// 簡易フォーマット: 整数部分 + 小数点以下2桁
	i := int(f)
	frac := int((f - float64(i)) * 100)
	if frac < 0 {
		frac = -frac
	}
	s := itoa(i) + "."
	if frac < 10 {
		s += "0"
	}
	s += itoa(frac)
	return s
}

// itoa is a minimal integer-to-string helper to avoid importing strconv.
func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	neg := false
	if i < 0 {
		neg = true
		i = -i
	}
	buf := [20]byte{}
	pos := len(buf)
	for i > 0 {
		pos--
		buf[pos] = byte('0' + i%10)
		i /= 10
	}
	if neg {
		pos--
		buf[pos] = '-'
	}
	return string(buf[pos:])
}
