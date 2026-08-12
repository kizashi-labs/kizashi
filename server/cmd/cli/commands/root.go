package commands

import (
	"os"

	"github.com/spf13/cobra"
)

var (
	serverURL string
	token     string
	outputFmt string
)

var rootCmd = &cobra.Command{
	Use:   "edr-cli",
	Short: "Kizashi CLI",
	Long: `edr-cli は Kizashi の管理用コマンドラインインターフェースです。

エージェント管理、アラート操作、ルール管理などをコマンドラインから実行できます。

設定:
  SERVER_URL 環境変数または --server フラグでAPIサーバーを指定してください。
  EDR_TOKEN 環境変数または --token フラグで認証トークンを指定してください。

例:
  edr-cli agents list
  edr-cli alerts list --severity critical
  edr-cli rules export --format sigma`,
	Version: "1.0.0",
}

func Execute() error {
	return rootCmd.Execute()
}

func init() {
	defaultURL := os.Getenv("EDR_SERVER_URL")
	if defaultURL == "" {
		defaultURL = "http://localhost:8080"
	}
	defaultToken := os.Getenv("EDR_TOKEN")

	rootCmd.PersistentFlags().StringVar(&serverURL, "server", defaultURL, "EDR API サーバーURL ($EDR_SERVER_URL)")
	rootCmd.PersistentFlags().StringVar(&token, "token", defaultToken, "認証トークン ($EDR_TOKEN)")
	rootCmd.PersistentFlags().StringVarP(&outputFmt, "output", "o", "table", "出力フォーマット: table, json, csv")

	// Register sub-commands
	rootCmd.AddCommand(
		newAgentsCmd(),
		newAlertsCmd(),
		newRulesCmd(),
		newUsersCmd(),
		newBackupCmd(),
		newStatusCmd(),
	)
}

// baseURL returns the configured server URL
func baseURL() string { return serverURL }

// authToken returns the configured auth token
func authToken() string { return token }

// outFmt returns the output format
func outFmt() string { return outputFmt }
