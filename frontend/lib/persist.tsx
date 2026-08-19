'use client'

import { useCallback, useState } from 'react'
import { AlertTriangle } from 'lucide-react'
import { apiFetch } from './api'

// 画面の変更をサーバに保存する。
//
// これまで多くの管理画面はこう書かれていました:
//
//   setConfig(prev => ({ ...prev, enabled: !prev.enabled }))
//   apiFetch('/api/v1/admin/geo-blocking/config', { method: 'PUT', ... })
//     .catch(() => {})
//
// ローカルの状態を先に変え、保存の失敗は捨てます。画面はトグルが入った
// 状態になり、成功したときと区別がつきません。そして
// /api/v1/admin/geo-blocking/config にはルートが存在しないので、この保存は
// 毎回失敗していました。管理者はジオブロッキングを有効にしたつもりで、
// 有効になっていません。
//
// この形の書き込みはツリー全体で80箇所あり、うち33箇所は今回のように
// サーバ側にルートが1本も無い宛先へ送られていました。
//
// persist は成功したときだけ true を返します。呼び出し側はその時だけ
// ローカルの状態を進め、失敗は saveError として画面に出します。

function messageOf(e: unknown): string {
  if (e instanceof Error) return e.message
  return String(e)
}

export interface Persist {
  /** 保存に成功したら true。失敗したら false を返し saveError を立てる。 */
  persist: (what: string, path: string, init?: RequestInit) => Promise<boolean>
  /** 直近の保存失敗。成功すると消える。 */
  saveError: string | null
  clearSaveError: () => void
}

export function usePersist(): Persist {
  const [saveError, setSaveError] = useState<string | null>(null)

  const persist = useCallback(
    async (what: string, path: string, init?: RequestInit): Promise<boolean> => {
      try {
        await apiFetch(path, init)
        setSaveError(null)
        return true
      } catch (e) {
        setSaveError(`${what}を保存できませんでした: ${messageOf(e)}`)
        return false
      }
    },
    []
  )

  return { persist, saveError, clearSaveError: () => setSaveError(null) }
}

/**
 * useMutation を使っている画面用。
 *
 * こちらの典型はこう書かれていました:
 *
 *   useMutation({
 *     mutationFn: (id) => apiFetch(`/…/${id}/toggle`, { method: 'POST' })
 *       .catch(() => null),
 *     onSuccess: () => qc.invalidateQueries(...),
 *   })
 *
 * `.catch(() => null)` が失敗を成功に変えるので、react-query の isError も
 * onError も一生発火しません。ボタンは押せて、成功として扱われます。
 * catch を外せば error が立つので、それをこの帯に渡します。
 */
export function saveErrorOf(
  what: string,
  ...mutations: Array<{ error?: unknown } | undefined>
): string | null {
  for (const m of mutations) {
    if (m?.error) return `${what}を保存できませんでした: ${messageOf(m.error)}`
  }
  return null
}

/**
 * 保存に失敗したことを画面上で伝える帯。
 *
 * エラーが無ければ何も描画しないので、ページの先頭に一行置けば足ります。
 */
export function SaveFailed({ error }: { error: string | null }) {
  if (!error) return null
  return (
    <div
      role="alert"
      className="mb-4 flex items-start gap-2 rounded-lg border border-amber-500/40 bg-amber-500/10 px-4 py-3"
    >
      <AlertTriangle className="mt-0.5 h-4 w-4 shrink-0 text-amber-400" />
      <div>
        <p className="text-sm text-amber-300">{error}</p>
        <p className="mt-0.5 text-xs text-amber-200/60">
          画面の表示は変わっていません。この操作は反映されていません。
        </p>
      </div>
    </div>
  )
}
