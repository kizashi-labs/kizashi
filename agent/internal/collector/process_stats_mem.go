package collector

// memState — 常駐メモリの読み取り結果が「何であるか」。
//
// **0 MB は測定値です。** 読めなかったことをそれで表すと、消えた直後の
// プロセスや読めなかったプロセスが「メモリを使っていない生きたプロセス」
// として一覧に載ります。前回そこは直しました —— ただし、直し方が
// **行ごと落とす**でした。
//
// それが次の穴になりました。**メモリが読めなかったことを理由に、
// 同じ行で読めていた CPU まで捨てています。**
//
//	このコンテナで測った実数 (2026-08-11, uid=0):
//	  /proc の PID          75
//	  processListImpl       75 件
//	  readProcessStatsRaw    8 件   ← 89% が消えます
//	  落ちた理由            VmRSS 行が無い 67 件（stat は全件読めています）
//
// 67 件はカーネルスレッドです。**VmRSS 行が無いのは失敗ではありません**
// —— ユーザ空間を持たないという事実で、CPU は普通に回っています。
//
// この一覧は `CryptoMinerScorer` (T1496) の入力です。**snapshot に出ない
// PID は、CPU を焼き続けても永久に検知されません。** そして届いた側には、
// 全部入りの snapshot と 75 分の 8 の snapshot を見分ける手立てが
// ありません。
type memState int

const (
	// memUnknown — 読めませんでした。**0 ではありません。**
	memUnknown memState = iota
	// memMeasured — 数値が取れました。
	memMeasured
	// memNoUserSpace — ユーザ空間を持たない（カーネルスレッド）。
	// VmRSS 行が無いのは事実であって、読み取りの失敗ではありません。
	memNoUserSpace
)

// memMB converts a raw kB reading to the value that goes on the wire.
//
// **測れなかったものは、フィールドごと出しません。** `mem_mb` が無い
// ことが「測っていない」の表現です（proto3 の optional と同じ約束で、
// 画面はすでに `—` を出します）。カーネルスレッドも同じ扱いにします
// —— 「ユーザ空間が無い」は「0 MB 使っている」とは別のことです。
func memMB(kb uint64, st memState) *float64 {
	if st != memMeasured {
		return nil
	}
	v := float64(kb) / 1024.0
	return &v
}
