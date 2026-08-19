'use client'

import { AlertTriangle, RefreshCw } from 'lucide-react'

// サーバは、読み取りに失敗したときに 200 と空のリストを返すのをやめました。
// ただし画面側は data が undefined になったとき `?? []` / `?? 0` で
// そのまま 0件・0 を描画します。つまりサーバが正直になっても、
// 運用担当の目には以前と同じ「該当なし」が映ります。
//
// SOC にとって「脆弱性0件」「未対応アラート0件」は行動を決める情報です。
// それが「取得できなかった」であることは、画面の中で言われなければ
// 伝わりません。ログにも、トーストにも、10秒後には消えます。
//
// BackendPendingBanner が「このページのAPIはまだありません」と正直に
// 言うのと同じ考え方で、こちらは「今この数字は取れていません」と言います。

export interface DataUnavailableProps {
  /** useQuery の error。複数のクエリを持つ画面では errors を使う。 */
  error?: unknown
  /** 画面が複数のクエリを持つ場合。1つでも失敗していれば表示する。 */
  errors?: unknown[]
  /** 「脆弱性」「アラート」など、取れなかったものの名前。 */
  what?: string
  /** 再試行。渡されたときだけボタンを出す。 */
  onRetry?: () => void
  className?: string
}

/**
 * 取得に失敗したことを画面上で伝える帯。
 *
 * エラーが無ければ何も描画しないので、一覧の上に一行置いておけば足ります。
 */
export function DataUnavailable({
  error,
  errors,
  what,
  onRetry,
  className = '',
}: DataUnavailableProps) {
  const all = [...(errors ?? []), ...(error !== undefined ? [error] : [])]
  const failed = all.filter(Boolean)
  if (failed.length === 0) return null

  const subject = what ? `${what}を` : 'データを'
  const detail = messageOf(failed[0])

  return (
    <div
      role="alert"
      className={`flex items-start gap-3 rounded-xl border border-red-500/40 bg-red-950/30 p-4 ${className}`}
    >
      <div className="w-8 h-8 bg-red-500/10 rounded-lg flex items-center justify-center shrink-0">
        <AlertTriangle className="w-4 h-4 text-red-400" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-red-300">
          {subject}取得できませんでした
        </p>
        <p className="text-xs text-[#8899aa] mt-0.5 leading-relaxed">
          この画面に表示されている件数は実際の値ではありません。
          {failed.length > 1 && `（${failed.length}件の取得が失敗しています）`}
        </p>
        {detail && (
          <p className="text-xs text-[#5a6a7a] mt-1 break-words">{detail}</p>
        )}
      </div>
      {onRetry && (
        <button
          onClick={onRetry}
          className="flex items-center gap-1.5 text-xs text-red-300 hover:text-white border border-red-500/40 rounded-lg px-3 py-1.5 shrink-0 transition-colors"
        >
          <RefreshCw className="w-3 h-3" />
          再試行
        </button>
      )}
    </div>
  )
}

function messageOf(e: unknown): string {
  if (e instanceof Error) return e.message
  if (typeof e === 'string') return e
  return ''
}
