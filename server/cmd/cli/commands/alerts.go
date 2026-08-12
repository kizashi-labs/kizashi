package commands

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

type Alert struct {
	ID        string    `json:"id"`
	Title     string    `json:"title"`
	Severity  string    `json:"severity"`
	Status    string    `json:"status"`
	Hostname  string    `json:"hostname"`
	RuleName  string    `json:"rule_name"`
	CreatedAt time.Time `json:"created_at"`
}

type AlertsResponse struct {
	Data  []Alert `json:"data"`
	Total int     `json:"total"`
}

func newAlertsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "alerts",
		Short: "アラート管理",
		Long:  "セキュリティアラートの一覧・詳細・ステータス変更を行います。",
	}

	// alerts list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "アラート一覧を表示",
		RunE: func(cmd *cobra.Command, args []string) error {
			severity, _ := cmd.Flags().GetString("severity")
			status, _ := cmd.Flags().GetString("status")
			limit, _ := cmd.Flags().GetInt("limit")

			path := fmt.Sprintf("/api/v1/alerts?limit=%d", limit)
			if severity != "" {
				path += "&severity=" + severity
			}
			if status != "" {
				path += "&status=" + status
			}

			var resp AlertsResponse
			if err := apiGet(path, &resp); err != nil {
				return err
			}

			headers := []string{"ID", "TITLE", "SEVERITY", "STATUS", "HOSTNAME", "CREATED"}
			var rows [][]string
			for _, a := range resp.Data {
				title := a.Title
				if len(title) > 40 {
					title = title[:37] + "..."
				}
				rows = append(rows, []string{
					a.ID[:8] + "…",
					title,
					a.Severity,
					a.Status,
					a.Hostname,
					a.CreatedAt.Format("01-02 15:04"),
				})
			}
			printOutput(headers, rows, resp)
			fmt.Printf("\n合計: %d 件\n", resp.Total)
			return nil
		},
	}
	listCmd.Flags().String("severity", "", "重大度フィルタ: critical, high, medium, low")
	listCmd.Flags().String("status", "", "ステータスフィルタ: open, investigating, resolved, false_positive")
	listCmd.Flags().Int("limit", 50, "表示件数")

	// alerts resolve
	resolveCmd := &cobra.Command{
		Use:   "resolve <id>",
		Short: "アラートを解決済みにする",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]string{"status": "resolved"}
			if err := apiPatch("/api/v1/alerts/"+args[0], body, nil); err != nil {
				return err
			}
			fmt.Printf("✓ アラート %s を解決済みにしました\n", args[0])
			return nil
		},
	}

	// alerts false-positive
	fpCmd := &cobra.Command{
		Use:   "false-positive <id>",
		Short: "アラートを誤検知としてマーク",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]string{"status": "false_positive"}
			if err := apiPatch("/api/v1/alerts/"+args[0], body, nil); err != nil {
				return err
			}
			fmt.Printf("✓ アラート %s を誤検知としてマークしました\n", args[0])
			return nil
		},
	}

	// alerts export
	exportCmd := &cobra.Command{
		Use:   "export",
		Short: "アラートをエクスポート",
		RunE: func(cmd *cobra.Command, args []string) error {
			severity, _ := cmd.Flags().GetString("severity")
			path := "/api/v1/alerts?limit=10000"
			if severity != "" {
				path += "&severity=" + severity
			}
			var resp AlertsResponse
			if err := apiGet(path, &resp); err != nil {
				return err
			}
			headers := []string{"id", "title", "severity", "status", "hostname", "rule_name", "created_at"}
			var rows [][]string
			for _, a := range resp.Data {
				rows = append(rows, []string{
					a.ID, a.Title, a.Severity, a.Status, a.Hostname, a.RuleName,
					a.CreatedAt.Format(time.RFC3339),
				})
			}
			printOutput(headers, rows, resp.Data)
			return nil
		},
	}
	exportCmd.Flags().String("severity", "", "重大度フィルタ")

	cmd.AddCommand(listCmd, resolveCmd, fpCmd, exportCmd)
	return cmd
}
