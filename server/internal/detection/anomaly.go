package detection

import (
	"context"
	"fmt"
	"log/slog"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
)

const (
	zScoreThreshold = 3.0 // これ以上でアラート生成
	baselineWindow  = 7   // ベースライン計算の日数
	minSampleCount  = 3   // 最低サンプル数 (これ未満はスキップ)

	// anomalyMaxSeverity は頻度異常アラートの severity 上限。
	// z スコアをそのまま severity に写像すると、低分散ベースライン
	// (例: WmiPrvSE が数日間ほぼ一定の少数回) に対する良性の活動バースト
	// でも z が数十に発散し severity=10 になる。severity>=AUTO_ISOLATE_MIN_SEVERITY
	// だと頻度異常だけで端末を自動隔離し得るため危険。純粋な統計的頻度異常は
	// 情報提供レベルの弱い信号 (新規ソフト/初回起動/バースト) であり、
	// auto-isolate 閾値(既定9)より十分低い中程度に頭打ちさせる。
	anomalyMaxSeverity = 5

	// anomalyScoreZCeiling は z スコアを alerts.anomaly_score (0–1) へ写像する
	// ときの上限。
	//
	// alerts.anomaly_score は「0–1 の正規化スコア」という契約で、engine の
	// enrichAnomalyScore も UEBA リスク(0–100)を /100 して入れている。一方この
	// 検知器は生の z スコアをそのまま入れていたため、低分散ベースラインで z が
	// 数百に発散すると UI が `score * 100` を「%」として描画して 60786% のような
	// 値になっていた(検証EC2 2026-07-31 で実測)。
	//
	// z は zScoreThreshold(=3) 超で発報するので、3 を下限、10 を「振り切り」と
	// みなして [3, 10] を (0, 1] に写像する。生の z は description と
	// anomaly_scores テーブルに残るため、精度の高い値が失われることはない。
	anomalyScoreZCeiling = 10.0
)

// normalizeZScore は z スコアを alerts.anomaly_score の契約である 0–1 に写像する。
// zScoreThreshold 以下は 0、anomalyScoreZCeiling 以上は 1。
func normalizeZScore(z float64) float64 {
	if z <= zScoreThreshold {
		return 0
	}
	return math.Min((z-zScoreThreshold)/(anomalyScoreZCeiling-zScoreThreshold), 1)
}

// AnomalyDetector はプロセス実行パターンの外れ値を検出します
type AnomalyDetector struct {
	pool       *pgxpool.Pool
	alertStore AlertSaver
}

// AlertSaver は検知エンジンへの依存を最小化するインターフェース
type AlertSaver interface {
	SaveAlert(ctx context.Context, alert *StoredAlert) error
}

// NewAnomalyDetector は新しい AnomalyDetector を返します。
func NewAnomalyDetector(pool *pgxpool.Pool, alertStore AlertSaver) *AnomalyDetector {
	return &AnomalyDetector{
		pool:       pool,
		alertStore: alertStore,
	}
}

// Run は hourly goroutine として実行します。
// 1時間ごとにベースライン更新 → 異常スコア計算 → アラート生成
func (d *AnomalyDetector) Run(ctx context.Context) {
	// 起動直後に一度実行する
	d.runOnce(ctx)

	ticker := time.NewTicker(1 * time.Hour)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.runOnce(ctx)
		}
	}
}

func (d *AnomalyDetector) runOnce(ctx context.Context) {
	if err := d.UpdateBaselines(ctx); err != nil {
		slog.Error("プロセスベースライン更新エラー", "error", err)
	}
	if err := d.DetectAnomalies(ctx); err != nil {
		slog.Error("異常検知エラー", "error", err)
	}
}

// UpdateBaselines は過去7日の events テーブルからプロセスベースラインを更新します。
// events テーブルの raw_data JSONB から process_name を取得します。
// process_name カラムが存在しない場合（raw_data に含まれない場合）は空の結果を返してエラーにしません。
func (d *AnomalyDetector) UpdateBaselines(ctx context.Context) error {
	_, err := d.pool.Exec(ctx, `
		INSERT INTO process_baselines (agent_id, process_name, hour_of_day, exec_count, avg_count, std_dev, updated_at)
		SELECT
		    agent_id,
		    process_name,
		    hour::SMALLINT AS hour_of_day,
		    COUNT(*) AS exec_count,
		    COUNT(*)::FLOAT / $1::float AS avg_count,
		    COALESCE(STDDEV(daily_count), 0) AS std_dev,
		    NOW() AS updated_at
		FROM (
		    SELECT
		        agent_id,
		        process_name,
		        EXTRACT(HOUR FROM timestamp) AS hour,
		        DATE(timestamp) AS day,
		        COUNT(*) AS daily_count
		    FROM (
		        SELECT
		            agent_id,
		            time AS timestamp,
		            NULLIF(TRIM(raw_data->>'process_name'), '') AS process_name
		        FROM events
		        -- make_interval(days => $1) は $1 を int として使う。以前の
		        -- ($1 || ' days')::INTERVAL は $1 を text 推論させ、pgx が int の
		        -- baselineWindow を text OID にエンコードできず実行時失敗していた
		        -- ("unable to encode 7 into text format")。int 単一文脈に統一。
		        --
		        -- event_type の絞り込みは検知側(DetectAnomalies)と必ず一致させること。
		        -- 片方だけ絞ると INNER JOIN が空振りして検知が黙って止まる。
		        WHERE event_type = 'process'
		          AND time >= NOW() - make_interval(days => $1)
		    ) raw
		    WHERE process_name IS NOT NULL AND process_name != ''
		    GROUP BY agent_id, process_name, hour, day
		) sub
		GROUP BY agent_id, process_name, hour
		ON CONFLICT (agent_id, process_name, hour_of_day) DO UPDATE
		SET
		    exec_count = EXCLUDED.exec_count,
		    avg_count  = EXCLUDED.avg_count,
		    std_dev    = EXCLUDED.std_dev,
		    updated_at = NOW()
	`, baselineWindow)
	if err != nil {
		// process_name が raw_data に存在しない場合などは無視する
		slog.Warn("UpdateBaselines: SQLエラー (無視します)", "error", err)
		return nil
	}

	slog.Info("プロセスベースラインを更新しました")
	return nil
}

// anomalyRow は DetectAnomalies のクエリ結果を格納します。
type anomalyRow struct {
	agentID     string
	processName string
	actualCount int
	avgCount    float64
	stdDev      float64
	hourOfDay   int
}

// DetectAnomalies は直近1時間のプロセス実行をベースラインと比較します。
// Zスコア = (実測値 - 平均) / 標準偏差
// Zスコア > zScoreThreshold でアラート生成
func (d *AnomalyDetector) DetectAnomalies(ctx context.Context) error {
	currentHour := time.Now().Hour()

	// 直近1時間のプロセス実行数をカウントし、ベースラインと結合する
	rows, err := d.pool.Query(ctx, `
		SELECT
		    recent.agent_id,
		    recent.process_name,
		    recent.actual_count,
		    b.avg_count,
		    b.std_dev,
		    $1::SMALLINT AS hour_of_day
		FROM (
		    SELECT
		        agent_id,
		        NULLIF(TRIM(raw_data->>'process_name'), '') AS process_name,
		        COUNT(*) AS actual_count
		    FROM events
		    -- event_type の絞り込みは必須。process_name は process だけでなく
		    -- image_load / registry / file / network も持つため、これが無いと
		    -- 「プロセス実行回数の異常」が実際には「そのプロセス名を含む任意の
		    -- イベント数」になる。実機(2026-08-05)では image_load 経由で DLL 名が
		    -- 流入し、kernel32.dll / crypt32.dll といった名前で
		    -- 「異常なプロセス実行パターン」アラートが1件ずつ量産されていた。
		    WHERE event_type = 'process'
		      AND time >= NOW() - INTERVAL '1 hour'
		      AND NULLIF(TRIM(raw_data->>'process_name'), '') IS NOT NULL
		    GROUP BY agent_id, process_name
		) recent
		INNER JOIN process_baselines b
		    ON b.agent_id    = recent.agent_id
		   AND b.process_name = recent.process_name
		   AND b.hour_of_day  = $1::SMALLINT
		WHERE recent.actual_count > $2
	`, currentHour, minSampleCount)
	if err != nil {
		// process_name が raw_data に存在しない / テーブルが空の場合は無視する
		slog.Warn("DetectAnomalies: クエリエラー (無視します)", "error", err)
		return nil
	}
	defer rows.Close()

	var candidates []anomalyRow
	for rows.Next() {
		var r anomalyRow
		if err := rows.Scan(
			&r.agentID,
			&r.processName,
			&r.actualCount,
			&r.avgCount,
			&r.stdDev,
			&r.hourOfDay,
		); err != nil {
			slog.Warn("DetectAnomalies: 行スキャンエラー", "error", err)
			continue
		}
		candidates = append(candidates, r)
	}
	if err := rows.Err(); err != nil {
		slog.Warn("DetectAnomalies: 行イテレーションエラー", "error", err)
	}

	for _, r := range candidates {
		zScore := d.calcZScore(float64(r.actualCount), r.avgCount, r.stdDev)

		if zScore <= zScoreThreshold {
			continue
		}

		// anomaly_scores に記録
		if err := d.saveAnomalyScore(ctx, r, zScore); err != nil {
			slog.Warn("異常スコアの保存に失敗しました",
				"agent_id", r.agentID,
				"process", r.processName,
				"error", err,
			)
		}

		// アラートを生成する。
		// severity は zScore に応じて上げるが anomalyMaxSeverity で頭打ちにする
		// (頻度異常は情報提供レベルの弱い信号であり、単独で auto-isolate 帯に
		// 達してはならない。詳細は anomalyMaxSeverity のコメント参照)。
		severity := int(math.Min(anomalyMaxSeverity, zScore))
		if severity < 1 {
			severity = 1
		}

		description := fmt.Sprintf(
			"プロセス '%s' のエージェント %s における実行回数が異常です。"+
				"直近1時間の実行数: %d, 期待値(平均): %.2f, 標準偏差: %.2f, Zスコア: %.2f (時間帯: %02d時台)",
			r.processName, r.agentID, r.actualCount, r.avgCount, r.stdDev, zScore, r.hourOfDay,
		)

		alert := &StoredAlert{
			ID:      generateAlertID(),
			AgentID: r.agentID,
			// RuleID は空: alerts.rule_id は uuid 型。非UUID文字列を入れると
			// INSERT が 22P02 で失敗しアラートが保存されない(engine と同じ規約)。
			// 検知器の識別は RuleName が担う。
			RuleName:    "ML異常検知",
			Severity:    severity,
			Status:      "open",
			Title:       "異常なプロセス実行パターン: " + r.processName,
			Description: description,
			// alerts.anomaly_score は 0–1 の契約。生の z は description と
			// anomaly_scores テーブルに残る。
			AnomalyScore: normalizeZScore(zScore),
			CreatedAt:    time.Now(),
			UpdatedAt:    time.Now(),
		}

		if err := d.alertStore.SaveAlert(ctx, alert); err != nil {
			slog.Error("異常検知アラートの保存に失敗しました",
				"agent_id", r.agentID,
				"process", r.processName,
				"error", err,
			)
			continue
		}

		slog.Info("異常なプロセス実行パターンを検出しました",
			"agent_id", r.agentID,
			"process_name", r.processName,
			"actual_count", r.actualCount,
			"avg_count", r.avgCount,
			"z_score", zScore,
			"severity", severity,
		)
	}

	return nil
}

// calcZScore は Zスコアを計算します。
// std_dev == 0 かつ actual > avg の場合は zScoreThreshold + 1 を返します。
func (d *AnomalyDetector) calcZScore(actual, avg, stdDev float64) float64 {
	if stdDev > 0 {
		return (actual - avg) / stdDev
	}
	// 標準偏差が 0 の場合: 実測値が平均より大きければ確実に異常
	if actual > avg {
		return zScoreThreshold + 1
	}
	return 0
}

// saveAnomalyScore は anomaly_scores テーブルに異常スコアを記録します。
func (d *AnomalyDetector) saveAnomalyScore(ctx context.Context, r anomalyRow, zScore float64) error {
	_, err := d.pool.Exec(ctx, `
		INSERT INTO anomaly_scores (agent_id, process_name, z_score, hour_of_day, event_count, detected_at)
		VALUES ($1::UUID, $2, $3, $4, $5, NOW())
	`, r.agentID, r.processName, zScore, r.hourOfDay, r.actualCount)
	return err
}
