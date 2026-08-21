package store

import (
	"errors"
	"testing"
)

// 確認そのものの失敗を「無い」と答えないこと。
//
// ## なぜここに要るのか
//
// この判定を留めていたのは `internal/api/handlers/table_probe_test.go`
// でしたが、**上流はそのファイルを公開版に同梱しないと決めました**
// （#74 が `scripts/mutations/NOT_SHIPPED.txt` に足しています）。
// 戻しても次の同期で消えます。**公開版が自分で持つ必要があります。**
//
// ## 何が起きるか
//
// `TableIsThere` は、まだマイグレーションが当たっていない機能を 500 や
// パニックにしないために置かれています。**確認そのものに失敗したときに
// 「無い」と答えると、DB に届かないだけで「その機能は使われていません」と
// 同じ姿になります。**
//
// HTTP の一覧なら空、バックグラウンドの仕事なら**何もしないまま正常終了**
// です。後者は誰も見ていないので、止まっていることに気づく手掛かりが
// ありません。
//
// `ProbeAnswer` が切り出してあるのは、まさにこの両側を DB 無しで試せる
// ようにするためです（table_probe.go のコメント）。**切り出した意味を
// 使う検査がここです。**
func TestAProbeFailureIsNotAnAbsence(t *testing.T) {
	boom := errors.New("見に行けませんでした")

	for _, tc := range []struct {
		name   string
		exists bool
		err    error
		want   bool
		why    string
	}{
		{
			name: "確認が失敗したら在る側に倒す（走査できた値に関わらず）",
			// **`exists` は false のままです。** 確認が失敗したので、
			// この変数は何も測れていません。**その値で答えると、
			// 「見に行けなかった」が「無い」になります。**
			exists: false, err: boom, want: true,
			why: "DB に届かないだけで、その機能が使われていないのと同じ姿になります",
		},
		{
			name:   "確認が失敗したら在る側に倒す（走査できた値が true でも）",
			exists: true, err: boom, want: true,
			why: "失敗したときの答えは、走査できた値に依存してはいけません",
		},
		{
			name:   "本当に無いなら、無いと答える",
			exists: false, err: nil, want: false,
			why: "常に true を返すと、移行前の画面が本物のクエリで 500 になります",
		},
		{
			name:   "本当に在るなら、在ると答える",
			exists: true, err: nil, want: true,
			why: "在る表を「無い」と答えると、機能が丸ごと消えます",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := ProbeAnswer(tc.exists, tc.err); got != tc.want {
				t.Errorf("ProbeAnswer(exists=%v, err=%v) = %v, want %v。\n  %s",
					tc.exists, tc.err, got, tc.want, tc.why)
			}
		})
	}
}
