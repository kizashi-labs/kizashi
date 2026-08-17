package detection

// DB からの Sigma ルール読み込み経路 (P4-6)。
//
// ここは長らく no-op だった。以前あったクエリは
// 「yara_rules (type='sigma') と custom_alert_rules を UNION する」形で、
// **両方の枝が成立していなかった**:
//
//   - yara_rules に type 列も is_active 列も無い。このテーブルは migration
//     041 / 085 / 174 がそれぞれ違うスキーマで CREATE TABLE IF NOT EXISTS して
//     おり、実際に効いているのは最初の 041 だけ。type を作る migration は無い
//   - custom_alert_rules に rule_yaml 列も無い。条件を conditions jsonb で持つ
//     構造化テーブルで、Sigma YAML は保持していない
//
// UNION の片方が失敗すればクエリ全体が失敗するので、この関数は DB から
// Sigma ルールを 1 件も読めていなかった。しかも失敗を Debug ログに落として
// nil を返すため、「読み込み 0 件」が正常動作に見えていた。そこで一度、
// 「有効な供給元が存在しない」として経路ごと畳んだ。
//
// ★ その判断は供給元の一覧を取り違えていた。**`rules` テーブルという正しい
// 供給元が最初から存在する。** 読んでいなかっただけである。これが P4-6:
//
//   - `rules` を読むのは server-detect の RuleEngine だけで、そのコンシューマは
//     慢性的にラグしている (EVENTS JetStream の ack floor 固着)
//   - 追いついている server-api の AlertPipeline は builtin しか読まない
//
// 結果、`rules` テーブルのルールは **どちらの経路でも実質リアルタイム未発火**
// だった。2026-07-14 に Windows 実機で確定している: エージェントは
// create_remote_thread を正しく送っているのに、sev9/auto_isolate のルール
// 「Process Hollowing via Suspicious Executable」が 337 件中 0 件しか出ない。
// ルールも平坦化も両 Sigma 実装も正しく、**どの表をどのパイプラインが読むか
// という結線だけ**が壊れていた。
//
// 本ファイルはその結線である。`rules` の enabled な Sigma を AlertPipeline 側の
// SigmaEvaluator にも読み込む。
//
// custom_alert_rules は Sigma ではなく構造化ルールとして
// CustomRuleEvaluator (custom_rules.go) が評価する。こちらは別経路。

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/edr-platform/server/internal/metrics"
)

// dbSigmaRulesEnvVar is the kill switch. Loading the `rules` table into the
// real-time path roughly doubles the number of Sigma rules evaluated per event,
// and the rows are not all under this repository's control — SigmaHQ sync writes
// there too. An operator who sees the api server struggling must be able to shed
// that load without waiting for a rebuild, so the switch is an env var read at
// load time rather than a build tag.
const dbSigmaRulesEnvVar = "EDR_SIGMA_DB_RULES"

// dbSigmaRulesEnabled reports whether the `rules` table should be loaded.
// Default ON: the whole point of P4-6 is that these rules never fire.
func dbSigmaRulesEnabled() bool {
	switch strings.ToLower(strings.TrimSpace(os.Getenv(dbSigmaRulesEnvVar))) {
	case "0", "false", "no", "off":
		return false
	}
	return true
}

// loadSigmaRulesFromPoolTyped loads the enabled Sigma rules from the `rules`
// table into e.
//
// Callers pass the pool as interface{} so the SigmaEvaluator API does not carry
// a pgx dependency; the assertion happens here. A pool of the wrong type is not
// an error to swallow — it means the caller wired something else — but it must
// not take the api server down either, so it is logged and skipped.
func loadSigmaRulesFromPoolTyped(e *SigmaEvaluator, pool interface{}) error {
	if !dbSigmaRulesEnabled() {
		slog.Warn("sigma_db: DB 由来の Sigma ルールは環境変数で無効化されています",
			"env", dbSigmaRulesEnvVar)
		return nil
	}
	if pool == nil {
		slog.Debug("sigma_db: pool が nil のため DB ルールは読み込みません")
		return nil
	}
	p, ok := pool.(*pgxpool.Pool)
	if !ok {
		slog.Warn("sigma_db: pool が *pgxpool.Pool ではないため DB ルールは読み込みません",
			"type", fmt.Sprintf("%T", pool))
		return nil
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// `enabled = true` alone is the right predicate: migration 292 established
	// the quarantined ⟹ disabled invariant with a CHECK constraint, so a rule the
	// FP monitor has quarantined cannot be enabled. Filtering on curate_state as
	// well would silently diverge from what server-detect's RuleStore.ListEnabled
	// evaluates, and the two engines disagreeing about which rules exist is the
	// class of bug this file is fixing.
	// mitre_tags comes along because for 65 of the migration-shipped Sigma rules
	// the attribution lives ONLY in that column — the YAML has an empty `tags:`.
	// See LoadRuleWithFallbackTags for why dropping it would also break
	// cross-engine deduplication, not just the alert's MITRE field.
	rows, err := p.Query(ctx, `
		SELECT name, content, COALESCE(mitre_tags, '{}'), COALESCE(severity, 0),
		       COALESCE(platform, '{}')
		  FROM rules
		 WHERE enabled = true
		   AND type = 'sigma'
		 ORDER BY name`)
	if err != nil {
		return err
	}
	defer rows.Close()

	// Builtins win a title collision. Both sources ship rules under the same
	// title with DIFFERENT matching logic (CLAUDE.md's dual-source section), so
	// loading both would evaluate two rules that report as one — the alert would
	// name a rule whose YAML nobody can find. Preferring the builtin keeps the
	// api server's behaviour on a colliding title exactly what it was before this
	// change, which is what makes the rest of the diff reviewable.
	existing := e.LoadedTitles()

	var loaded, failed, skipped int
	var failedNames []string
	for rows.Next() {
		var name, content string
		var mitreTags, platform []string
		var severity int
		if err := rows.Scan(&name, &content, &mitreTags, &severity, &platform); err != nil {
			failed++
			continue
		}
		title := sigmaTitleOf(content)
		if title == "" {
			title = name
		}
		if existing[title] {
			skipped++
			continue
		}
		// platform comes along because server-detect gated these rules on it and
		// this engine is now their only evaluator (SetDBSigmaEvaluation). Dropping
		// the column would silently remove OS scoping — a macOS-only rule would
		// start matching Linux telemetry, which is exactly what was measured on a
		// benign fleet before this was wired.
		if err := e.loadDBRule(content, sigmaTagsFromColumn(mitreTags), severity, platform); err != nil {
			failed++
			if len(failedNames) < 20 {
				failedNames = append(failedNames, name)
			}
			slog.Warn("sigma_db: DB ルールのコンパイルに失敗しました(未評価)",
				"rule", name, "error", err)
			continue
		}
		existing[title] = true
		loaded++
	}
	if err := rows.Err(); err != nil {
		return err
	}

	// Logged at Info with the counts split out, deliberately mirroring
	// server-detect's "Sigmaルールをロードしました compiled=N failed=M". A silent
	// zero here is precisely how the previous version hid a total failure for
	// months; a number that can be read off the startup log is the difference
	// between "no rules matched" and "no rules loaded".
	slog.Info("sigma_db: rules テーブルの Sigma ルールを読み込みました",
		"loaded", loaded, "failed", failed, "skipped_builtin_collision", skipped,
		"total_rules", e.RuleCount(), "failed_rules", strings.Join(failedNames, ","))

	// edr_rules_loaded was only ever written by cmd/detection, so on the api
	// server it read a flat 0 — indistinguishable from "loaded nothing", which is
	// precisely the state this file was in. Publishing the api's compiled count
	// makes the difference visible on the api's own /metrics.
	metrics.RulesLoaded.Store(int64(e.RuleCount()))
	return nil
}

// sigmaTagsFromColumn converts the `rules.mitre_tags` column form ("T1055.012")
// into the Sigma tag form ("attack.t1055.012") that parseMITRETechFromTags reads.
// Values already in Sigma form pass through, and anything that is not a technique
// ID (the column also carries tactic names in places) is dropped rather than
// turned into a tag that resolves to no technique.
func sigmaTagsFromColumn(tags []string) []string {
	out := make([]string, 0, len(tags))
	for _, t := range tags {
		s := strings.ToLower(strings.TrimSpace(t))
		if s == "" {
			continue
		}
		if strings.HasPrefix(s, "attack.") {
			out = append(out, s)
			continue
		}
		if len(s) > 1 && s[0] == 't' && s[1] >= '0' && s[1] <= '9' {
			out = append(out, "attack."+s)
		}
	}
	return out
}

// sigmaTitleOf pulls the `title:` out of a Sigma document without a full parse.
// Used only for collision detection before compiling; a rule whose title cannot
// be read this way still gets compiled, it just falls back to the row's name.
func sigmaTitleOf(content string) string {
	for _, line := range strings.Split(content, "\n") {
		t := strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(t, "title:"); ok {
			return strings.TrimSpace(strings.Trim(strings.TrimSpace(rest), `"'`))
		}
	}
	return ""
}
