package commands

import (
	"fmt"
	"os"
	"sort"

	"github.com/edr-platform/server/internal/detection"
	"github.com/spf13/cobra"
)

// 抑制ルールの棚卸し。
//
// ★ なぜこのコマンドが要るか。
//
// 2026-08-14 まで、リアルタイムのアラートを作る server-api の AlertPipeline は
// 抑制ルールを見ていなかった（#760 で結線した）。**運用者から見ると「抑制ルールを
// 作っても何も止まらない」状態**で、しかも UI 上はルールが有効に見えるので、
// 効いていないこと自体が分からなかった。
//
// この状態が続くと自然に起きることがある:
//
//	「効かないので、もっと広い条件にしてみる」
//
// 効かない原因は条件の狭さではなく結線の欠落だったので、広げても当然効かない。
// つまり **本番には「効かない前提で広げられたルール」が残っている可能性がある**。
// 結線した瞬間、それが本当にアラートを消し始める。
//
// このコマンドは、それをデプロイ前に人が確認するためのものである。判定は
// エンジンと**同じ関数**（detection.ClassifySuppression）を使う。別実装にすると
// 「CLI では警告が出ないのにエンジンは弾く」（あるいは逆）が起きる。
//
// 読み取り専用である。何を消すかの判断は人が持つ。

type suppressionCondition struct {
	RuleName       string `json:"rule_name,omitempty"`
	Hostname       string `json:"hostname,omitempty"`
	SeverityMax    int    `json:"severity_max,omitempty"`
	MITRETechnique string `json:"mitre_technique,omitempty"`
	AgentID        string `json:"agent_id,omitempty"`
}

type suppressionRule struct {
	ID         string               `json:"id"`
	Name       string               `json:"name"`
	Conditions suppressionCondition `json:"conditions"`
	IsActive   bool                 `json:"is_active"`
	HitCount   int                  `json:"hit_count"`
	ExpiresAt  *string              `json:"expires_at"`
}

type suppressionsResponse struct {
	Data  []suppressionRule `json:"data"`
	Total int               `json:"total"`
}

// toDetectionRule converts the API shape into the engine's rule type so the
// classification is literally the same code path the engine runs.
func (r suppressionRule) toDetectionRule() detection.SuppressionRule {
	return detection.SuppressionRule{
		ID:             r.ID,
		Name:           r.Name,
		RuleName:       r.Conditions.RuleName,
		Hostname:       r.Conditions.Hostname,
		SeverityMax:    r.Conditions.SeverityMax,
		MITRETechnique: r.Conditions.MITRETechnique,
		AgentID:        r.Conditions.AgentID,
	}
}

func newSuppressionsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "suppressions",
		Short: "抑制ルールの棚卸し",
		Long: `抑制ルールを一覧し、どれだけ広く当たり得るかを判定します。

判定はサーバの検知エンジンと同じ関数を使います:

  narrow     対象を絞れている
  wide       当たり得るが絞り込みの手掛かりが無い。エンジンは適用するが警告する
  catch-all  事実上すべてのアラートに当たる。エンジンは適用しない

例:
  edr-cli suppressions audit
  edr-cli suppressions audit --only wide,catch-all
  edr-cli suppressions audit -o json`,
	}

	var onlyFlag []string
	auditCmd := &cobra.Command{
		Use:   "audit",
		Short: "抑制ルールの広さを判定して一覧",
		Long: `抑制ルールを取得し、広さで分類して表示します。読み取り専用です。

デプロイ前の確認に使ってください。特に、抑制が効いていなかった期間に
「効かないので広げてみた」ルールが残っていないかを見ます。`,
		RunE: func(cmd *cobra.Command, args []string) error {
			var resp suppressionsResponse
			if err := apiGet("/api/v1/suppressions", &resp); err != nil {
				return err
			}

			want := map[string]bool{}
			for _, o := range onlyFlag {
				want[o] = true
			}

			type row struct {
				rule    suppressionRule
				breadth detection.SuppressionBreadth
				why     string
			}
			var rows []row
			counts := map[detection.SuppressionBreadth]int{}
			for _, r := range resp.Data {
				b, why := detection.ClassifySuppression(r.toDetectionRule())
				counts[b]++
				if len(want) > 0 && !want[b.String()] {
					continue
				}
				rows = append(rows, row{r, b, why})
			}

			// 広い順。運用者が最初に見るべきものを上に置く。
			sort.SliceStable(rows, func(i, j int) bool { return rows[i].breadth > rows[j].breadth })

			if outputFmt == "json" {
				out := make([]map[string]interface{}, 0, len(rows))
				for _, r := range rows {
					out = append(out, map[string]interface{}{
						"id": r.rule.ID, "name": r.rule.Name,
						"breadth": r.breadth.String(), "reason": r.why,
						"is_active": r.rule.IsActive, "hit_count": r.rule.HitCount,
						"conditions": r.rule.Conditions,
					})
				}
				printJSON(out)
				return nil
			}

			headers := []string{"BREADTH", "ACTIVE", "HITS", "NAME", "理由"}
			var table [][]string
			for _, r := range rows {
				active := "✓"
				if !r.rule.IsActive {
					active = "✗"
				}
				table = append(table, []string{
					r.breadth.String(), active,
					fmt.Sprintf("%d", r.rule.HitCount), r.rule.Name, r.why,
				})
			}
			if outputFmt == "csv" {
				printCSV(headers, table)
				return nil
			}
			printTable(headers, table)

			fmt.Printf("\n合計 %d 件: narrow %d / wide %d / catch-all %d\n",
				resp.Total,
				counts[detection.SuppressionNarrow],
				counts[detection.SuppressionWide],
				counts[detection.SuppressionCatchAll])

			// hit_count が 0 のまま残っているものは、**効いていないのか、当たる
			// アラートが無いのか区別が付かない**。#760 以前は前者が常に真だったので、
			// この数字を「効いている証拠」として読めるようになったのは結線以降である。
			var neverHit int
			for _, r := range resp.Data {
				if r.IsActive && r.HitCount == 0 {
					neverHit++
				}
			}
			if neverHit > 0 {
				fmt.Printf("うち有効で hit_count=0: %d 件"+
					"（#760 で結線するまで抑制は api 側で効いていませんでした。"+
					"結線後もこの数字が動かないルールは、条件が実際のアラートと"+
					"合っていない可能性があります）\n", neverHit)
			}
			if counts[detection.SuppressionCatchAll] > 0 {
				fmt.Fprintf(os.Stderr,
					"\n⚠ catch-all が %d 件あります。エンジンはこれらを適用しません"+
						"（全アラートが消えるため）。条件を見直してください。\n",
					counts[detection.SuppressionCatchAll])
			}
			return nil
		},
	}
	auditCmd.Flags().StringSliceVar(&onlyFlag, "only", nil,
		"表示する広さを絞る: narrow, wide, catch-all（カンマ区切り）")

	cmd.AddCommand(auditCmd)
	return cmd
}
