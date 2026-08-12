package commands

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "システム状態を確認",
		Long:  "EDR APIサーバーの稼働状態・バージョン・DB接続状態を表示します。",
		RunE: func(cmd *cobra.Command, args []string) error {
			var health struct {
				Status  string `json:"status"`
				DB      string `json:"db"`
				Version string `json:"version"`
				NATS    string `json:"nats"`
			}
			if err := apiGet("/health", &health); err != nil {
				return fmt.Errorf("サーバーに接続できません (%s): %w", baseURL(), err)
			}
			fmt.Printf("Server:  %s\n", baseURL())
			fmt.Printf("Status:  %s\n", colorHealthStatus(health.Status))
			fmt.Printf("DB:      %s\n", colorHealthStatus(health.DB))
			fmt.Printf("NATS:    %s\n", colorHealthStatus(health.NATS))
			fmt.Printf("Version: %s\n", health.Version)
			return nil
		},
	}
}

func colorHealthStatus(s string) string {
	switch s {
	case "ok", "healthy", "connected":
		return "✓ " + s
	case "":
		return "— unknown"
	default:
		return "✗ " + s
	}
}
