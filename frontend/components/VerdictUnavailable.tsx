'use client'

import { AlertTriangle } from 'lucide-react'

/**
 * 「この操作の結果は出ていません」。
 *
 * 空の状態を出すコンポーネントは既にありますが、これは用途が違います。
 * 空は「まだ何も無い」、これは「あなたが今聞いたことに答えられなかった」。
 *
 * ルールのテスト、IOC の照会、接続確認 — どれも利用者が質問を投げて
 * 答えを待つ操作です。ここで失敗を黙って飲み込んで「MATCHED」や
 * 「接続成功」を返すと、答えられなかったことが答えとして表示されます。
 * 判定は出さず、出せなかったと言うのがこのコンポーネントの役目です。
 */
export function VerdictUnavailable({ what, detail }: { what: string; detail?: string }) {
  return (
    <div className="rounded-xl p-4 border border-amber-700/50 bg-amber-950/30">
      <div className="flex items-center gap-2 text-sm font-semibold text-amber-300 mb-1">
        <AlertTriangle className="w-4 h-4 shrink-0" />
        {what}を実行できませんでした
      </div>
      <p className="text-xs text-amber-200/70">
        サーバから結果が返っていません。判定は出ていません。
      </p>
      {detail && (
        <p className="text-[11px] text-amber-200/50 mt-2 font-mono break-all">{detail}</p>
      )}
    </div>
  )
}

export default VerdictUnavailable
