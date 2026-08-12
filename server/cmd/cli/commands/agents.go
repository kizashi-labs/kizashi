package commands

import (
	"fmt"
	"strings"
	"time"

	"github.com/spf13/cobra"
)

type Agent struct {
	ID         string    `json:"id"`
	Hostname   string    `json:"hostname"`
	OS         string    `json:"os"`
	IPAddress  string    `json:"ip_address"`
	Status     string    `json:"status"`
	Version    string    `json:"version"`
	LastSeenAt time.Time `json:"last_seen_at"`
}

type AgentsResponse struct {
	Data  []Agent `json:"data"`
	Total int     `json:"total"`
}

func newAgentsCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "agents",
		Short: "エージェント管理",
		Long:  "エンドポイントエージェントの一覧・詳細・隔離操作を行います。",
	}

	// agents list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "エージェント一覧を表示",
		RunE: func(cmd *cobra.Command, args []string) error {
			status, _ := cmd.Flags().GetString("status")
			path := "/api/v1/agents?limit=100"
			if status != "" {
				path += "&status=" + status
			}
			var resp AgentsResponse
			if err := apiGet(path, &resp); err != nil {
				return err
			}
			headers := []string{"ID", "HOSTNAME", "OS", "IP", "STATUS", "VERSION", "LAST_SEEN"}
			var rows [][]string
			for _, a := range resp.Data {
				rows = append(rows, []string{
					a.ID[:8] + "…",
					a.Hostname,
					a.OS,
					a.IPAddress,
					colorStatus(a.Status),
					a.Version,
					a.LastSeenAt.Format("2006-01-02 15:04"),
				})
			}
			printOutput(headers, rows, resp)
			fmt.Printf("\n合計: %d 台\n", resp.Total)
			return nil
		},
	}
	listCmd.Flags().String("status", "", "ステータスでフィルタ: online, offline, isolated")

	// agents get
	getCmd := &cobra.Command{
		Use:   "get <id>",
		Short: "エージェント詳細を表示",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			var agent Agent
			if err := apiGet("/api/v1/agents/"+args[0], &agent); err != nil {
				return err
			}
			printJSON(agent)
			return nil
		},
	}

	// agents isolate
	isolateCmd := &cobra.Command{
		Use:   "isolate <id>",
		Short: "エージェントをネットワーク隔離",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiPost("/api/v1/agents/"+args[0]+"/isolate", nil, nil); err != nil {
				return err
			}
			fmt.Printf("✓ エージェント %s を隔離しました\n", args[0])
			return nil
		},
	}

	// agents unisolate
	unisolateCmd := &cobra.Command{
		Use:   "unisolate <id>",
		Short: "エージェントの隔離を解除",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := apiPost("/api/v1/agents/"+args[0]+"/unisolate", nil, nil); err != nil {
				return err
			}
			fmt.Printf("✓ エージェント %s の隔離を解除しました\n", args[0])
			return nil
		},
	}

	// agents stats
	statsCmd := &cobra.Command{
		Use:   "stats",
		Short: "エージェント統計を表示",
		RunE: func(cmd *cobra.Command, args []string) error {
			var resp AgentsResponse
			if err := apiGet("/api/v1/agents?limit=1", &resp); err != nil {
				return err
			}
			fmt.Printf("総エージェント数: %d\n", resp.Total)
			return nil
		},
	}

	cmd.AddCommand(listCmd, getCmd, isolateCmd, unisolateCmd, statsCmd)
	return cmd
}

func colorStatus(s string) string {
	switch strings.ToLower(s) {
	case "online":
		return "● online"
	case "offline":
		return "○ offline"
	case "isolated":
		return "⊘ isolated"
	default:
		return s
	}
}
