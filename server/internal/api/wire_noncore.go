// wire_noncore.go — 公開版スタブ。
//
// 本流の同名ファイルは Free 版が同梱しないサーバ側配線（ハンドラ構築・
// スケジューラ起動・結線）の束。この版は何も配線しない。NoncoreDeps の
// フィールド名と型は本流と一致させること（main.go のリテラルが参照する。
// すべてコア型なのでこの版でも解決できる）。
package api

import (
	"context"

	tenantcrypto "github.com/edr-platform/server/internal/crypto"
	"github.com/edr-platform/server/internal/detection"
	"github.com/edr-platform/server/internal/email"
	"github.com/edr-platform/server/internal/isolation"
	"github.com/edr-platform/server/internal/ml"
	"github.com/edr-platform/server/internal/notification"
	"github.com/edr-platform/server/internal/remediation"
	"github.com/edr-platform/server/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

// NoncoreDeps — フィールド名・型は本流と一致必須。
type NoncoreDeps struct {
	EarlyRemediationEngine *remediation.Engine
	JwtSecret              string
	MlEngine               *ml.BehavioralEngine
	Gatekeeper             *isolation.Gatekeeper
	Pipeline               *detection.AlertPipeline
	BuildDate              string
	Commit                 string
	Version                string
	UpdateLatestVersion    string
	Dispatcher             *notification.Dispatcher
	UserPrefsStore         *store.UserPreferencesStore
	DbURL                  string
	TenantEncryptor        *tenantcrypto.Encryptor
	UserStore              *store.UserStore
	Mailer                 *email.Sender
	FrontendURL            string
	ApiKeyStore            *store.APIKeyStore
	NotifPrefStore         *store.NotificationPrefStore
	BaseURL                string
	SuppressionStore       *store.SuppressionStore
	QuarantineStore        *store.QuarantineStore
	IocStore               *store.IOCStore
	Commander              *store.CommandStore
	AlertStore             *store.AlertStore
	AgentStore             *store.AgentStore
	Db                     *store.DB
	AnthropicKey           string
	Nc                     *nats.Conn
	Pool                   *pgxpool.Pool
}

// WireNoncore はこの版では何もしない。
func (h *Handlers) WireNoncore(_ context.Context, _ NoncoreDeps) {}
