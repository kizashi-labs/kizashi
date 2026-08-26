// siem_noncore.go — 公開版スタブ。
//
// 本流の同名ファイルは SIEM 転送の結線。この版は SIEM 連携を同梱しないため
// 何も配線しない。
package main

import (
	"context"

	"github.com/edr-platform/server/internal/detection"
	"github.com/edr-platform/server/internal/store"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/nats-io/nats.go"
)

func wireSIEMForwarder(_ context.Context, _ *store.DB, _ *nats.Conn, _ *detection.Engine) {}

func wireNoncoreDetectors(_ context.Context, _ *pgxpool.Pool, _ *nats.Conn) {}
