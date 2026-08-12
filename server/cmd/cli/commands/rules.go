package commands

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

type Rule struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Severity string `json:"severity"`
	Enabled  bool   `json:"enabled"`
	HitCount int    `json:"hit_count"`
}

type RulesResponse struct {
	Data  []Rule `json:"data"`
	Total int    `json:"total"`
}

func newRulesCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rules",
		Short: "検知ルール管理",
		Long:  "Sigma/YARAルールの一覧・有効化・無効化・エクスポートを行います。",
	}

	// rules list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "ルール一覧を表示",
		RunE: func(cmd *cobra.Command, args []string) error {
			var resp RulesResponse
			if err := apiGet("/api/v1/rules?limit=200", &resp); err != nil {
				return err
			}
			headers := []string{"ID", "NAME", "TYPE", "SEVERITY", "ENABLED", "HITS"}
			var rows [][]string
			for _, r := range resp.Data {
				enabled := "✓"
				if !r.Enabled {
					enabled = "✗"
				}
				rows = append(rows, []string{
					r.ID[:8] + "…",
					r.Name,
					r.Type,
					r.Severity,
					enabled,
					fmt.Sprintf("%d", r.HitCount),
				})
			}
			printOutput(headers, rows, resp)
			fmt.Printf("\n合計: %d 件\n", resp.Total)
			return nil
		},
	}

	// rules enable
	enableCmd := &cobra.Command{
		Use:   "enable <id>",
		Short: "ルールを有効化",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]bool{"enabled": true}
			if err := apiPatch("/api/v1/rules/"+args[0], body, nil); err != nil {
				return err
			}
			fmt.Printf("✓ ルール %s を有効化しました\n", args[0])
			return nil
		},
	}

	// rules disable
	disableCmd := &cobra.Command{
		Use:   "disable <id>",
		Short: "ルールを無効化",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]bool{"enabled": false}
			if err := apiPatch("/api/v1/rules/"+args[0], body, nil); err != nil {
				return err
			}
			fmt.Printf("✓ ルール %s を無効化しました\n", args[0])
			return nil
		},
	}

	// rules delete
	deleteCmd := &cobra.Command{
		Use:   "delete <id>",
		Short: "ルールを削除",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			confirm, _ := cmd.Flags().GetBool("yes")
			if !confirm {
				fmt.Printf("ルール %s を削除しますか? [y/N]: ", args[0])
				var answer string
				fmt.Scan(&answer)
				if answer != "y" && answer != "Y" {
					fmt.Println("キャンセルしました")
					return nil
				}
			}
			if err := apiDelete("/api/v1/rules/" + args[0]); err != nil {
				return err
			}
			fmt.Printf("✓ ルール %s を削除しました\n", args[0])
			return nil
		},
	}
	deleteCmd.Flags().BoolP("yes", "y", false, "確認をスキップ")

	// rules export
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "ルールをエクスポート",
		RunE: func(cmd *cobra.Command, args []string) error {
			var resp struct {
				Content string `json:"content"`
			}
			format, _ := cmd.Flags().GetString("format")
			if err := apiGet("/api/v1/rules/export?format="+format, &resp); err != nil {
				// Fallback: list rules as JSON
				var listResp RulesResponse
				if err2 := apiGet("/api/v1/rules?limit=1000", &listResp); err2 != nil {
					return err2
				}
				printJSON(listResp.Data)
				return nil
			}
			fmt.Print(resp.Content)
			return nil
		},
	}
	exportCmd.Flags().String("format", "sigma", "エクスポート形式: sigma, json")

	// rules import
	importCmd := &cobra.Command{
		Use:   "import <file>",
		Short: "ファイルからルールをインポート",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			data, err := os.ReadFile(args[0])
			if err != nil {
				return fmt.Errorf("ファイルの読み込みに失敗しました: %w", err)
			}
			body := map[string]string{"content": string(data), "format": "sigma"}
			var result map[string]interface{}
			if err := apiPost("/api/v1/rules/import", body, &result); err != nil {
				return err
			}
			printJSON(result)
			return nil
		},
	}

	cmd.AddCommand(listCmd, enableCmd, disableCmd, deleteCmd, exportCmd, importCmd)
	return cmd
}
