'use client'

import { AlertTriangle } from 'lucide-react'

// 画面全体は動いているが、一部だけ届いていないときの帯。
//
// DataUnavailable は「この画面のデータが取れていない」と言います。集約する
// クエリは、そこまで単純ではありません。4本のうち1本だけが落ちて、残り3本の
// 数字は本物です。全部を疑わせるのも、全部を信じさせるのも間違っています。
//
// ここは落ちた部分の名前だけを並べます。

export interface PartialDataNoticeProps {
  /** 届かなかった部分の名前。空なら何も描画しない。 */
  missing?: string[]
  className?: string
}

export function PartialDataNotice({ missing, className = '' }: PartialDataNoticeProps) {
  if (!missing || missing.length === 0) return null

  return (
    <div
      role="alert"
      className={`flex items-start gap-3 rounded-xl border border-amber-500/40 bg-amber-950/25 p-4 ${className}`}
    >
      <div className="w-8 h-8 bg-amber-500/10 rounded-lg flex items-center justify-center shrink-0">
        <AlertTriangle className="w-4 h-4 text-amber-400" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-amber-300">
          この画面の一部を取得できませんでした
        </p>
        <p className="text-xs text-[#8899aa] mt-0.5 leading-relaxed break-words">
          {missing.join('、')}
          {' '}
          は取得できていません。該当する数字は 0 と表示されますが、実際の値ではありません。
        </p>
      </div>
    </div>
  )
}
