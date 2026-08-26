'use client'

import { useRef, useState } from 'react'
import { useMutationState, useQueryClient } from '@tanstack/react-query'
import { AlertTriangle, X } from 'lucide-react'

// 保存が失敗したことを画面上で伝える帯。
//
// PageDataUnavailable の書き込み版です。あちらは読み取りの失敗を拾いますが、
// 保存の失敗は同じ仕組みでは拾えません。react-query のクエリキャッシュには
// 出てこないからです。
//
// そして書き込みは、失敗が見えないと読み取りより重くなります。読めなかった
// 画面は「0件」で止まりますが、保存できなかった画面は操作が済んだ形で
// 残ります。閉じたダイアログ、入ったトグル、消えた行 —— どれもサーバには
// 届いていません。
//
// 対象は「この画面を開いてから出した保存」だけです。react-query は失敗した
// mutation を数分キャッシュに残すので、単に status === 'error' を集めると、
// 前に見ていた画面の失敗が今の画面の帯として出ます。
//
// **その「開いてから」を時刻で測ってはいけません。** submittedAt と
// Date.now() はどちらもミリ秒で、前の画面の失敗とこの画面の mount が同じ
// ミリ秒に入ると区別がつきません。境目がどちらに落ちるかは機械の速さ次第
// なので、**検査は落ちるときと通るときがあり、通ったほうが正しく見えます。**
// 実際 tests/components/PageSaveFailed.test.tsx の「この画面を開く前の失敗は
// 出さない」は、前の画面の失敗を作ってすぐ mount するので、同じミリ秒に
// 入りえます。
//
// 代わりに mutationId で測ります。MutationCache は build のたびに
// `++mutationId` を振るので、**この QueryClient の中で単調増加し、
// 再利用されません。** mount した時点の最大値より大きいものが「この画面を
// 開いてから作られた mutation」で、これは時計を見ていないので機械の速さで
// 答えが変わりません。

function messageOf(e: unknown): string {
  if (e instanceof Error) return e.message
  if (typeof e === 'string') return e
  return ''
}

export interface PageSaveFailedProps {
  /** 「ルール」「割り当て」など。省略時は「変更」。 */
  what?: string
  className?: string
}

export function PageSaveFailed({ what, className = '' }: PageSaveFailedProps) {
  const qc = useQueryClient()

  // 画面を開いた時点でキャッシュにあった mutation の最大 id。useRef の
  // 初期値式は毎描画で評価されてしまうので、一度だけ入れます。
  const openedAfter = useRef<number | null>(null)
  if (openedAfter.current === null) {
    openedAfter.current = qc
      .getMutationCache()
      .getAll()
      .reduce((max, m) => Math.max(max, m.mutationId), 0)
  }

  // 閉じたときも同じ物差しで覚えます。時刻で覚えると、閉じたのと同じ
  // ミリ秒に出た次の失敗が、出ないまま消えます。
  const [dismissedThrough, setDismissedThrough] = useState(0)
  const since = Math.max(openedAfter.current, dismissedThrough)

  const failures = useMutationState({
    filters: { status: 'error' },
    select: m => ({ error: m.state.error as unknown, id: m.mutationId }),
  })
    .filter(f => f.id > since)
    .sort((a, b) => a.id - b.id)

  if (failures.length === 0) return null

  const latest = failures[failures.length - 1]
  const detail = messageOf(latest.error)
  const subject = what ? `${what}を` : ''

  return (
    <div
      role="alert"
      className={`flex items-start gap-3 rounded-xl border border-red-500/40 bg-red-950/30 p-4 ${className}`}
    >
      <div className="w-8 h-8 bg-red-500/10 rounded-lg flex items-center justify-center shrink-0">
        <AlertTriangle className="w-4 h-4 text-red-400" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-red-300">{subject}保存できませんでした</p>
        <p className="text-xs text-[#8899aa] mt-0.5 leading-relaxed">
          画面の表示は変わっていても、サーバには反映されていません。
          {failures.length > 1 && `（${failures.length}件の保存が失敗しています）`}
        </p>
        {detail && <p className="text-xs text-[#5a6a7a] mt-1 break-words">{detail}</p>}
      </div>
      <button
        onClick={() => setDismissedThrough(latest.id)}
        aria-label="閉じる"
        className="text-[#5a6a7a] hover:text-white shrink-0 transition-colors"
      >
        <X className="w-4 h-4" />
      </button>
    </div>
  )
}
