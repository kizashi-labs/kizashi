package commands

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

func newBackupCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "backup",
		Short: "バックアップ管理",
		Long:  "設定・データのバックアップ作成・一覧・復元を行います。",
	}

	// backup create
	createCmd := &cobra.Command{
		Use:   "create",
		Short: "バックアップを作成",
		RunE: func(cmd *cobra.Command, args []string) error {
			fmt.Println("バックアップを作成中...")
			var result map[string]interface{}
			if err := apiPost("/api/v1/admin/backup", nil, &result); err != nil {
				return err
			}
			fmt.Printf("✓ バックアップを作成しました\n")
			printJSON(result)
			return nil
		},
	}

	// backup list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "バックアップ一覧を表示",
		RunE: func(cmd *cobra.Command, args []string) error {
			var resp struct {
				Backups []struct {
					ID        string    `json:"id"`
					Filename  string    `json:"filename"`
					SizeBytes int64     `json:"size_bytes"`
					CreatedAt time.Time `json:"created_at"`
				} `json:"backups"`
			}
			if err := apiGet("/api/v1/admin/backup", &resp); err != nil {
				return err
			}
			headers := []string{"ID", "FILENAME", "SIZE", "CREATED"}
			var rows [][]string
			for _, b := range resp.Backups {
				rows = append(rows, []string{
					b.ID,
					b.Filename,
					fmt.Sprintf("%.1f MB", float64(b.SizeBytes)/1024/1024),
					b.CreatedAt.Format("2006-01-02 15:04"),
				})
			}
			printTable(headers, rows)
			return nil
		},
	}

	// backup restore
	restoreCmd := &cobra.Command{
		Use:   "restore <backup-id>",
		Short: "バックアップから復元",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			confirm, _ := cmd.Flags().GetBool("yes")
			if !confirm {
				fmt.Printf("バックアップ %s から復元しますか? この操作は元に戻せません。 [y/N]: ", args[0])
				var answer string
				fmt.Scan(&answer)
				if answer != "y" && answer != "Y" {
					fmt.Println("キャンセルしました")
					return nil
				}
			}
			body := map[string]string{"backup_id": args[0]}
			var result map[string]interface{}
			if err := apiPost("/api/v1/admin/backup/restore", body, &result); err != nil {
				return err
			}
			fmt.Printf("✓ バックアップ %s から復元しました\n", args[0])
			return nil
		},
	}
	restoreCmd.Flags().BoolP("yes", "y", false, "確認をスキップ")

	cmd.AddCommand(createCmd, listCmd, restoreCmd)
	return cmd
}
