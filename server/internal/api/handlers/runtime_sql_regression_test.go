package handlers_test

// 実行時に必ず失敗していた SQL の再発防止。
//
// これらは「テーブルは在るが列名が違う」「型が違う」種類の取り違えで、
// 呼び出し側が Scan の戻り値を捨てているため 0 やゼロ値が返るだけだった。
// 実 DB に当てて初めて分かる。
//
// 個別のエンドポイントを叩くのではなく、各ハンドラが実際に発行する SQL を
// そのままここに並べて実 DB で実行する。列名を取り違えたまま戻すと、
// このテストが `does not exist` で落ちる。
//
// エンドポイント経由にしないのは、ほとんどの経路が空データでも 200 を返す
// ため「壊れていること」をレスポンスから判定できないため。

import (
	"context"
	"strings"
	"testing"
)

func TestRuntimeSQL_QueriesMatchSchema(t *testing.T) {
	pool := testPool(t)
	ctx := context.Background()

	// 各エントリは「そのハンドラが発行する SQL」をパラメータだけ固定値に
	// 置き換えたもの。件数は問わない — 実行できることだけを見る。
	cases := []struct {
		name  string
		query string
	}{
		{
			// api_security_handler.Stats — api_endpoints に risk_level /
			// enabled 列は無い。リスクは risk_score (0-100)。
			"api_security/stats",
			`SELECT COUNT(*), COUNT(*) FILTER (WHERE risk_score > 50) FROM api_endpoints`,
		},
		{
			// compliance_handler / ops_report_handler — IOC の実表は ioc_entries。
			"ioc/count",
			`SELECT COUNT(*) FROM ioc_entries WHERE is_active`,
		},
		{
			// compliance_handler — playbooks の有効フラグは is_active。
			"compliance/playbooks",
			`SELECT COUNT(*), COUNT(*) FILTER (WHERE is_active) FROM playbooks`,
		},
		{
			// compliance_handler — rules に category 列は無い (種別は type)。
			"compliance/rule-types",
			`SELECT COALESCE(type, 'general'), COUNT(*) FROM rules WHERE enabled GROUP BY type`,
		},
		{
			// timeline_handler — audit_logs の列は resource_id。
			"timeline/audit",
			`SELECT COALESCE(action,'') ||
			        CASE WHEN resource_id IS NOT NULL THEN ' ' || resource_id ELSE '' END
			 FROM audit_logs LIMIT 1`,
		},
		{
			// vendor_risk_handler — vendor_assessments の時刻列は assessed_at。
			"vendor/assessments",
			`SELECT va.id::text, va.vendor_id::text, COALESCE(v.name,''), va.overall_score,
			        va.status, COALESCE(va.findings,''), va.assessed_at
			 FROM vendor_assessments va
			 LEFT JOIN third_party_vendors v ON v.id = va.vendor_id
			 ORDER BY va.assessed_at DESC LIMIT 200`,
		},
		{
			// network_traffic_handler — nta_detections の時刻列は detected_at。
			"nta/recent",
			`SELECT COUNT(*) FROM nta_detections WHERE detected_at > NOW()-INTERVAL '24 hours'`,
		},
		{
			// network_map_handler — network_connections の時刻列は time。
			"network_map/peers",
			`SELECT DISTINCT agent_id, dst_ip, COUNT(*) FROM network_connections
			 WHERE "time" > NOW() - INTERVAL '24 hours'
			 GROUP BY agent_id, dst_ip LIMIT 2000`,
		},
		{
			// threat_hunt_automator — 列は dst_ip / time (remote_ip / timestamp は無い)。
			"hunt/ioc-connection",
			`SELECT agent_id FROM network_connections
			 WHERE dst_ip='198.51.100.9'::inet AND "time" >= NOW() - INTERVAL '24 hours' LIMIT 1`,
		},
		{
			// detectionmetrics — events の列は event_id / time、
			// alerts が持つのは event_ids (配列)。
			"detectionmetrics/mttd",
			`SELECT EXTRACT(EPOCH FROM AVG(a.created_at - e.first_seen)) / 60.0
			 FROM alerts a
			 JOIN LATERAL (
				SELECT MIN("time") AS first_seen FROM events
				WHERE event_id = ANY(a.event_ids::uuid[])
			 ) e ON e.first_seen IS NOT NULL
			 WHERE a.created_at > NOW() - INTERVAL '7 days'
			   AND a.event_ids IS NOT NULL AND array_length(a.event_ids, 1) > 0`,
		},
		{
			// detectionmetrics — rules に mitre_tactic 列は無い (mitre_tags 配列)。
			"detectionmetrics/mitre",
			`SELECT tag, COUNT(DISTINCT r.id)
			 FROM rules r, unnest(COALESCE(r.mitre_tags, '{}')) AS tag
			 WHERE r.enabled = true GROUP BY tag`,
		},
		{
			// predictive_analytics_handler — alerts.severity は数値 (1-10)。
			"predictive/severity-bands",
			`SELECT COUNT(*) FILTER (WHERE severity >= 9),
			        COUNT(*) FILTER (WHERE severity BETWEEN 7 AND 8),
			        COUNT(*) FILTER (WHERE severity BETWEEN 4 AND 6)
			 FROM alerts WHERE created_at >= NOW() - INTERVAL '30 days'`,
		},
		{
			// soc_metrics_handler — users に display_name / username 列は無い
			// (実列は full_name / email)。
			"soc_metrics/analysts",
			`SELECT COALESCE(a.assigned_to::text,''), COALESCE(u.full_name, u.email, 'Unknown'), COUNT(*)
			 FROM alerts a LEFT JOIN users u ON u.id::text = a.assigned_to::text
			 WHERE a.assigned_to IS NOT NULL GROUP BY 1, 2`,
		},
		{
			// insider_threat_handler / ueba_advanced_handler — 同上。
			// ueba_anomalies.username に対応するのは users.email。
			"ueba/user-join",
			`SELECT COALESCE(u.id::text, ua.username), ua.username, COALESCE(u.email,'')
			 FROM ueba_anomalies ua LEFT JOIN users u ON u.email = ua.username
			 GROUP BY ua.username, u.id, u.email, u.role`,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := pool.Query(ctx, tc.query)
			if err != nil {
				t.Fatalf("クエリが実スキーマで実行できない: %v\n%s", err, strings.TrimSpace(tc.query))
			}
			defer rows.Close()
			for rows.Next() {
				// 行の中身は問わない。Scan せずに読み進めるだけで、
				// 列の型不一致も含めて実行時エラーが rows.Err() に出る。
			}
			if err := rows.Err(); err != nil {
				t.Fatalf("行の読み出しに失敗: %v\n%s", err, strings.TrimSpace(tc.query))
			}
		})
	}
}
