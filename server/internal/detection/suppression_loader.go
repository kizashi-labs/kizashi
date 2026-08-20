package detection

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5/pgxpool"
)

// PoolSuppressionLoader loads active suppression rules straight from a pgx pool.
//
// ここに置いてある理由。抑制ルールを読む SQL は cmd/detection/adapter.go にしか
// 無く、server-api 側から同じものを読むには**同じクエリをもう 1 箇所に書く**しか
// なかった。列の追加や `is_active` の意味を変えたときに片方だけ直る形で、この
// リポジトリが繰り返し踏んできた「二重管理」そのものである
// （検知ルールの二重管理と同じ構図: docs/検知ルールの二重管理とデプロイ.md）。
//
// 実装を 1 つにして、cmd/detection の storeAdapter はこれに委譲する。
// 両プロセスが同じ行・同じ解釈を見ることが、抑制では特に重要になる——
// 「片方のプロセスでは抑制されるがもう片方では出る」は、運用者からは
// 「抑制が効いたり効かなかったりする」としか見えない。
type PoolSuppressionLoader struct {
	pool *pgxpool.Pool
}

// NewPoolSuppressionLoader returns a SuppressionLoader backed by pool.
func NewPoolSuppressionLoader(pool *pgxpool.Pool) *PoolSuppressionLoader {
	return &PoolSuppressionLoader{pool: pool}
}

// ListActiveSuppressions satisfies SuppressionLoader. It returns every active,
// non-expired suppression rule for the in-memory cache.
// ListActiveSuppressions returns the rules that actually suppress alerts.
//
// **フラグは 2 つある。** is_active は画面の一覧が、enabled は
// internal/suppression.Engine の API が書く。どちらも既定は TRUE なので、
// 片方だけ見ると、もう片方で off にしたルールが適用され続ける。
// 実測 (2026-08-11): enabled=false の 1 件が、is_active だけを見る
// 問い合わせでは 1 件として返っていた。
//
// どちらか一方でも off なら抑制しない。**抑制しない方向に倒す** ——
// 余計に届いたアラートは消せるが、落ちたアラートは戻らない。
func (l *PoolSuppressionLoader) ListActiveSuppressions(ctx context.Context) ([]SuppressionRule, error) {
	if l == nil || l.pool == nil {
		return nil, nil
	}
	rows, err := l.pool.Query(ctx, `
		SELECT id::text, name,
		       COALESCE(conditions->>'rule_name', ''),
		       COALESCE(conditions->>'hostname', ''),
		       COALESCE(conditions->>'hostname_regex', ''),
		       COALESCE((conditions->>'severity_max')::int, 0),
		       COALESCE(conditions->>'mitre_technique', ''),
		       COALESCE(conditions->>'agent_id', ''),
		       COALESCE(conditions->>'command_line_contains', ''),
		       COALESCE(conditions->>'parent_process', ''),
		       expires_at
		FROM suppression_rules
		WHERE is_active = TRUE
		  AND COALESCE(enabled, TRUE) = TRUE
		  AND (expires_at IS NULL OR expires_at > NOW())`)
	if err != nil {
		return nil, fmt.Errorf("ListActiveSuppressions: %w", err)
	}
	defer rows.Close()

	var rules []SuppressionRule
	for rows.Next() {
		var r SuppressionRule
		if err := rows.Scan(
			&r.ID, &r.Name,
			&r.RuleName, &r.Hostname, &r.HostnameRegex, &r.SeverityMax,
			&r.MITRETechnique, &r.AgentID,
			&r.CommandLine, &r.ParentProcess,
			&r.ExpiresAt,
		); err == nil {
			rules = append(rules, r)
		}
	}
	return rules, rows.Err()
}
