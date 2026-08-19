'use client'

import { useEffect, useState } from 'react'
import { useQueryClient } from '@tanstack/react-query'
import { DataUnavailable } from './DataUnavailable'

/**
 * いま画面に出ているクエリのうち、失敗しているもののエラー。
 *
 * 「いま出ている」は observer 数で決めます。TanStack のキャッシュには前に
 * 見ていた画面のクエリも失敗したまま残るので、単に status==='error' を
 * 集めると、無関係な画面の失敗を今の画面の帯として出してしまいます。
 * observer が居るクエリだけが、この瞬間に誰かが購読しているクエリです。
 */
export function useActiveQueryErrors(): unknown[] {
  const qc = useQueryClient()
  const [errors, setErrors] = useState<unknown[]>([])

  useEffect(() => {
    const cache = qc.getQueryCache()
    const read = () =>
      setErrors(
        cache
          .getAll()
          .filter(q => q.getObserversCount() > 0 && q.state.status === 'error')
          .map(q => q.state.error)
          .filter(Boolean)
      )
    read()
    return cache.subscribe(read)
  }, [qc])

  return errors
}

export interface PageDataUnavailableProps {
  /** 「脆弱性」「アラート」など。省略時は「データ」。 */
  what?: string
  className?: string
}

/**
 * ページ単位の「取得できませんでした」の帯。
 *
 * クエリごとの配線が要らないので、どのページにも一行で置けます。取得に
 * 失敗しているクエリが1つも無ければ何も描画しません。
 *
 * 個別のクエリだけを対象にしたいときは DataUnavailable を直接使ってください。
 */
export function PageDataUnavailable({ what, className }: PageDataUnavailableProps) {
  const errors = useActiveQueryErrors()
  const qc = useQueryClient()
  return (
    <DataUnavailable
      errors={errors}
      what={what}
      onRetry={() => {
        void qc.refetchQueries({ type: 'active' })
      }}
      className={className}
    />
  )
}
