package api

import (
	"context"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"

	"github.com/edr-platform/server/internal/email"
	"github.com/edr-platform/server/internal/license"
	"github.com/edr-platform/server/internal/store"
)

// ─── 公開版向けの差し替え（scripts/public-snapshot/overlay） ──────────────
//
// 本流の同名ファイルは有償版だけのハンドラを構築して Handlers に結線する。
// 公開版はその実装パッケージ（internal/billing, internal/mdm, internal/aiassist,
// …）を同梱しないので、ここでは何もしない。
//
// **構造体のフィールド名は本流と一致させること。** cmd/api/main.go は版によらず
// 同一で、この struct をフィールド名で組み立てているため、ここが食い違うと公開版
// だけがコンパイルできなくなる——それは今回の分割で無くそうとしている失敗の形
// そのものなので、フィールドの増減は本流と同時に反映する。
type CommercialDeps struct {
	Pool         *pgxpool.Pool
	NATS         *nats.Conn
	AlertStore   *store.AlertStore
	AgentStore   *store.AgentStore
	LicenseMgr   *license.Manager
	Mailer       *email.Sender
	JWTSecret    string
	FrontendURL  string
	IngestToken  string
	ClaudeKey    string
	AnthropicKey string
	Version      string

	AgentLatestVersion  string
	AgentLatestURL      string
	AgentLatestChecksum string
	AgentBinDir         string
}

// WireCommercial is a no-op in the open source edition.
func (h *Handlers) WireCommercial(_ context.Context, _ CommercialDeps) {}
