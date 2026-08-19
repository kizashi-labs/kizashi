package detection

import (
	"fmt"
	"strings"
)

// 抑制ルールの「広さ」の判定。
//
// ── なぜこれが要るか ──
//
// 2026-08-14 まで、AlertPipeline は抑制ルールを見ていなかった（#760 で結線した）。
// リアルタイムのアラートはほぼ全部そちらが作るので、**運用者から見ると抑制ルールを
// 作っても何も止まらなかった**。この状態が続くと自然に起きることがある:
//
//	「効かないので、もっと広い条件にしてみる」
//
// 効かない原因は条件の狭さではなく結線の欠落だったので、広げても当然効かない。
// つまり **本番には「効かない前提で広げられたルール」が残っている可能性がある**。
// 結線した瞬間に、それが本当にアラートを消し始める。
//
// これは #760 が作った新しいリスクである。抑制が効くようになったこと自体は正しいが、
// 「効かない前提で溜まった設定が一斉に有効になる」副作用は測っていない。
// FP ソークの環境には抑制ルールが 0 件なので、そこでは何も見えない。
//
// ── 判定を 1 箇所に置く理由 ──
//
// この分類は 2 箇所から使う:
//
//	SuppressionMatcher.load()    catch-all を弾き、wide を警告する（実行時）
//	edr-cli suppressions audit   デプロイ前に運用者が棚卸しする（人間向け）
//
// 別々に実装すると「CLI では警告が出ないのにエンジンは弾く」（あるいは逆）が起きる。
// 抑制は「効いたり効かなかったりする」が最も分かりにくい機能なので、
// **人が見る判断とエンジンが下す判断を同じコードにする**。

// SuppressionBreadth はひとつの抑制ルールがどれだけ広く当たり得るかの分類。
type SuppressionBreadth int

const (
	// SuppressionNarrow は対象を絞れているルール。
	SuppressionNarrow SuppressionBreadth = iota
	// SuppressionWide は当たり得るが、絞り込みの手掛かりを 1 つも持たないルール。
	// 適用はするが警告する。
	SuppressionWide
	// SuppressionCatchAll は事実上すべてのアラートに当たるルール。**適用しない**。
	SuppressionCatchAll
)

func (b SuppressionBreadth) String() string {
	switch b {
	case SuppressionNarrow:
		return "narrow"
	case SuppressionWide:
		return "wide"
	case SuppressionCatchAll:
		return "catch-all"
	default:
		return "unknown"
	}
}

// maxAlertSeverity is the upper bound the alerts table enforces
// (migrations/001_init_schema.sql: CHECK (severity BETWEEN 1 AND 10)).
// A SeverityMax at or above it excludes nothing.
const maxAlertSeverity = 10

// minCommandLineFragment is the shortest command-line substring treated as a
// real condition. Command lines are long free-form strings, so a short fragment
// matches almost everything — the same failure mode as a one-character rule_name,
// but reached at a longer length.
const minCommandLineFragment = 8

// ClassifySuppression returns how broadly a rule can match, with a human-readable
// reason. The reason is written for the operator who has to decide whether to keep
// the rule, so it says what the rule will swallow — not which check tripped.
//
// 判定の骨組みは 2 段:
//
//   - **退化した条件** … 書かれてはいるが何も絞れないもの。1 文字の部分文字列、
//     全技法に前方一致する "T"、上限そのものの severity_max=10 など。
//     すべての条件が退化していれば catch-all で、これは条件ゼロと同じ意味を持つ。
//   - **具体的な条件** … 実際に絞れるもの。ひとつも無ければ wide。
//
// 閾値は「その条件が現実の値集合をどれだけ割るか」で決めてある。RuleName と
// Hostname は部分文字列一致、MITRETechnique は前方一致、AgentID は完全一致——
// 一致の仕方が違うので、同じ文字数でも絞り込みの強さは違う。
func ClassifySuppression(r SuppressionRule) (SuppressionBreadth, string) {
	ruleName := strings.TrimSpace(r.RuleName)
	hostname := strings.TrimSpace(r.Hostname)
	tech := strings.ToUpper(strings.TrimSpace(r.MITRETechnique))
	agentID := strings.TrimSpace(r.AgentID)
	cmdline := strings.TrimSpace(r.CommandLine)
	parent := strings.TrimSpace(r.ParentProcess)

	var populated, degenerate []string

	if ruleName != "" {
		populated = append(populated, "rule_name")
		// 部分文字列一致。1 文字はほぼ全てのルール名に含まれる。
		if len(ruleName) <= 1 {
			degenerate = append(degenerate,
				fmt.Sprintf("rule_name=%q は 1 文字の部分文字列で、ほぼ全てのルール名に含まれる", ruleName))
		}
	}
	if hostname != "" {
		populated = append(populated, "hostname")
		if len(hostname) <= 1 {
			degenerate = append(degenerate,
				fmt.Sprintf("hostname=%q は 1 文字の部分文字列で、ほぼ全てのホスト名に含まれる", hostname))
		}
	}
	if tech != "" {
		populated = append(populated, "mitre_technique")
		// 前方一致。"T" は技法を持つ全アラートに当たる。
		if tech == "T" {
			degenerate = append(degenerate,
				`mitre_technique="T" は前方一致なので、技法を持つ全アラートに当たる`)
		}
	}
	if cmdline != "" {
		populated = append(populated, "command_line_contains")
		// 部分文字列一致。コマンドラインは長い自由文字列なので、短い断片は
		// 事実上どのコマンドにも含まれる（"e" や "-" や "exe" など）。
		// rule_name より閾値を上げてあるのはそのため。
		if len(cmdline) < minCommandLineFragment {
			degenerate = append(degenerate,
				fmt.Sprintf("command_line_contains=%q は %d 文字未満の断片で、ほぼ全てのコマンドラインに含まれる",
					cmdline, minCommandLineFragment))
		}
	}
	if parent != "" {
		populated = append(populated, "parent_process")
		// 後方一致。".exe" のような拡張子だけの指定は Windows の全プロセスに当たる。
		if len(parent) <= 1 || strings.HasPrefix(parent, ".") {
			degenerate = append(degenerate,
				fmt.Sprintf("parent_process=%q は後方一致として絞り込みにならない", parent))
		}
	}
	if r.SeverityMax > 0 {
		populated = append(populated, "severity_max")
		if r.SeverityMax >= maxAlertSeverity {
			degenerate = append(degenerate,
				fmt.Sprintf("severity_max=%d は alerts の上限（%d）以上なので、何も除外しない",
					r.SeverityMax, maxAlertSeverity))
		}
	}
	if agentID != "" {
		populated = append(populated, "agent_id")
		// 完全一致なので退化し得ない。
	}

	if len(populated) == 0 {
		return SuppressionCatchAll, "条件がひとつも書かれていない。全てのアラートを消す"
	}
	if len(degenerate) == len(populated) {
		return SuppressionCatchAll,
			"書かれている条件が全て絞り込みにならない: " + strings.Join(degenerate, " / ")
	}

	// 具体的な条件がひとつでもあれば narrow。無ければ wide。
	if specific := specificConditions(ruleName, hostname, tech, agentID, r.SeverityMax); len(specific) > 0 {
		return SuppressionNarrow, "絞り込み: " + strings.Join(specific, " / ")
	}

	var why []string
	if len(degenerate) > 0 {
		why = append(why, degenerate...)
	}
	why = append(why, "絞り込みになる条件がひとつも無い（対象="+strings.Join(populated, ",")+"）")
	return SuppressionWide, strings.Join(why, " / ")
}

// specificConditions lists the conditions that genuinely narrow the match.
//
// 閾値の根拠:
//
//	agent_id         完全一致。1 台に閉じるので、他がどれだけ緩くても被害は 1 台
//	rule_name  >=4   部分文字列。3 文字以下は語をまたいで当たる（"exe" 等）
//	hostname   >=3   部分文字列。ホスト名は接頭辞で群を成すので 3 文字で群を切れる
//	mitre      >=5   前方一致。"T1003" は 1 技法だが "T10" は T1003/T1059/… に当たる
//	severity   1..3  低ノイズ帯だけを落とす、意図の明確な運用。7 以上は wide 扱い
func specificConditions(ruleName, hostname, tech, agentID string, severityMax int) []string {
	var out []string
	if agentID != "" {
		out = append(out, "agent_id（1 台に限定）")
	}
	if len(ruleName) >= 4 {
		out = append(out, fmt.Sprintf("rule_name=%q", ruleName))
	}
	if len(hostname) >= 3 {
		out = append(out, fmt.Sprintf("hostname=%q", hostname))
	}
	if len(tech) >= 5 {
		out = append(out, fmt.Sprintf("mitre_technique=%q", tech))
	}
	if severityMax >= 1 && severityMax <= 3 {
		out = append(out, fmt.Sprintf("severity_max=%d（低ノイズ帯のみ）", severityMax))
	}
	return out
}
