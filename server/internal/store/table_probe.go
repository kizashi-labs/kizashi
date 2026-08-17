package store

import (
	"context"
	"log/slog"

	"github.com/jackc/pgx/v5/pgxpool"
)

// TableIsThere reports whether the named table exists.
//
// **確認そのものに失敗したら true を返します。**
//
// この確認は、まだマイグレーションが当たっていない機能を 500 やパニックに
// しないために置かれています。ところが実測 (2026-08-12) では、
// `internal/api/handlers` の 79 個と、それ以外の 24 個 —— 合わせて 103 個
// すべてが、**確認そのものの失敗を「無い」と同じに扱っていました**:
//
//	return err == nil && exists
//	return exists                 // err はログだけ、あるいは捨てる
//	_ = pool.QueryRow(...).Scan(&ok)
//
// **DB に届かないだけで「その機能は使われていません」と同じ姿になります。**
// HTTP の一覧なら空、バックグラウンドの仕事なら**何もしないまま正常終了**
// です。後者は誰も見ていないので、止まっていることに気づく手掛かりが
// ありません。
//
// true を返すのは、**本物のクエリに答えさせる**ためです:
//
//   - DB が落ちている → 本物のクエリが失敗し、その呼び出し側の失敗時の
//     扱い（error を返す、ログを出す）が動きます
//   - テーブルが本当に無い → 本物のクエリが 42P01 を返します。HTTP 側は
//     `absent()` がそれを見分けて空を返します
//
// **どちらに転んでも、正しい方の答えが出ます。**
//
// なお `information_schema` は必ず在るので、この確認が 42P01 を返すことは
// ありません。ここでの err は「見に行けなかった」だけです。
func TableIsThere(ctx context.Context, pool *pgxpool.Pool, name string) bool {
	var exists bool
	err := pool.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM information_schema.tables WHERE table_name=$1)`,
		name).Scan(&exists)
	if err != nil {
		slog.Warn("テーブルの存在確認に失敗しました。**「無い」とは答えません**",
			"table", name, "error", err)
	}
	return ProbeAnswer(exists, err)
}

// ProbeAnswer は、確認の結果をどう答えるかの判断そのものです。
//
// **切り出してあるのは、DB の無いところでも両側を試せるようにするため**
// です。埋め込んだままだと「本当に無いときは false」を試すのに DB が要り、
// `return exists` を `return true` に潰す変異が生き残ります。
func ProbeAnswer(exists bool, err error) bool {
	if err != nil {
		// **見に行けなかっただけです。「無い」とは答えません。**
		return true
	}
	return exists
}
