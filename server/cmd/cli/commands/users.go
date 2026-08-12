package commands

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

type User struct {
	ID          string     `json:"id"`
	Email       string     `json:"email"`
	FullName    string     `json:"full_name"`
	Role        string     `json:"role"`
	IsActive    bool       `json:"is_active"`
	CreatedAt   time.Time  `json:"created_at"`
	LastLoginAt *time.Time `json:"last_login_at"`
}

type UsersResponse struct {
	Data  []User `json:"data"`
	Total int    `json:"total"`
}

func newUsersCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "users",
		Short: "ユーザー管理",
		Long:  "ユーザーの一覧・招待・ロール変更・無効化を行います。",
	}

	// users list
	listCmd := &cobra.Command{
		Use:   "list",
		Short: "ユーザー一覧を表示",
		RunE: func(cmd *cobra.Command, args []string) error {
			var resp UsersResponse
			if err := apiGet("/api/v1/admin/users", &resp); err != nil {
				return err
			}
			headers := []string{"ID", "EMAIL", "NAME", "ROLE", "ACTIVE", "LAST_LOGIN"}
			var rows [][]string
			for _, u := range resp.Data {
				lastLogin := "—"
				if u.LastLoginAt != nil {
					lastLogin = u.LastLoginAt.Format("2006-01-02 15:04")
				}
				active := "✓"
				if !u.IsActive {
					active = "✗"
				}
				rows = append(rows, []string{
					u.ID[:8] + "…",
					u.Email,
					u.FullName,
					u.Role,
					active,
					lastLogin,
				})
			}
			printOutput(headers, rows, resp)
			fmt.Printf("\n合計: %d 人\n", resp.Total)
			return nil
		},
	}

	// users invite
	inviteCmd := &cobra.Command{
		Use:   "invite <email>",
		Short: "ユーザーを招待",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			role, _ := cmd.Flags().GetString("role")
			body := map[string]string{"email": args[0], "role": role}
			var result map[string]interface{}
			if err := apiPost("/api/v1/admin/invitations", body, &result); err != nil {
				return err
			}
			fmt.Printf("✓ %s に招待メールを送信しました (role: %s)\n", args[0], role)
			if url, ok := result["invite_url"].(string); ok {
				fmt.Printf("  招待URL: %s\n", url)
			}
			return nil
		},
	}
	inviteCmd.Flags().String("role", "analyst", "ロール: admin, analyst, viewer")

	// users deactivate
	deactivateCmd := &cobra.Command{
		Use:   "deactivate <id>",
		Short: "ユーザーを無効化",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]bool{"is_active": false}
			if err := apiPatch("/api/v1/admin/users/"+args[0], body, nil); err != nil {
				return err
			}
			fmt.Printf("✓ ユーザー %s を無効化しました\n", args[0])
			return nil
		},
	}

	// users set-role
	setRoleCmd := &cobra.Command{
		Use:   "set-role <id> <role>",
		Short: "ユーザーのロールを変更",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			body := map[string]string{"role": args[1]}
			if err := apiPatch("/api/v1/admin/users/"+args[0], body, nil); err != nil {
				return err
			}
			fmt.Printf("✓ ユーザー %s のロールを %s に変更しました\n", args[0], args[1])
			return nil
		},
	}

	cmd.AddCommand(listCmd, inviteCmd, deactivateCmd, setRoleCmd)
	return cmd
}
