'use client'

import { useState } from 'react'
import { usePlan } from '@/lib/usePlan'
import { X, ArrowRight, AlertTriangle, Zap } from 'lucide-react'
import Link from 'next/link'

/**
 * Freeプランでエージェント数が上限に近づいたときに表示するアップグレード誘導バナー。
 *
 * 表示条件:
 *  - plan === 'free'
 *  - agentUsed >= 4（上限5台のうち4台以上使用中）
 *
 * 閉じてもページリロードで再表示（sessionStorage で一時非表示のみ）。
 */
export function UpgradeBanner() {
  const { plan, agentUsed, agentLimit, isNearFreeLimit, isAtFreeLimit, isLoading } = usePlan()
  const [dismissed, setDismissed] = useState(
    () => typeof window !== 'undefined' && sessionStorage.getItem('upgrade_banner_dismissed') === '1'
  )

  if (isLoading || !isNearFreeLimit || dismissed) return null

  const remaining = agentLimit - agentUsed
  const isAt = isAtFreeLimit

  const dismiss = () => {
    sessionStorage.setItem('upgrade_banner_dismissed', '1')
    setDismissed(true)
  }

  return (
    <div className={`relative flex items-center gap-3 px-4 py-2.5 text-sm ${
      isAt
        ? 'bg-red-950/60 border-b border-red-700/50'
        : 'bg-orange-950/50 border-b border-orange-700/40'
    }`}>
      {/* アイコン */}
      <div className={`shrink-0 flex items-center justify-center w-6 h-6 rounded-full ${
        isAt ? 'bg-red-600/30' : 'bg-orange-500/30'
      }`}>
        {isAt
          ? <AlertTriangle className="w-3.5 h-3.5 text-red-400" />
          : <Zap className="w-3.5 h-3.5 text-orange-400" />
        }
      </div>

      {/* メッセージ */}
      <span className={`flex-1 min-w-0 ${isAt ? 'text-red-200' : 'text-orange-200'}`}>
        {isAt ? (
          <>
            <strong>Freeプランのエージェント上限（{agentLimit}台）に達しました。</strong>
            {' '}新しいエンドポイントを追加するにはアップグレードが必要です。
          </>
        ) : (
          <>
            <strong>Freeプランのエージェント数が上限に近づいています</strong>
            {' '}（現在 {agentUsed}/{agentLimit} 台 — あと{remaining}台）。
          </>
        )}
      </span>

      {/* アップグレードボタン */}
      <Link
        href="/admin/license"
        className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-bold
                    shrink-0 transition-colors ${
          isAt
            ? 'bg-red-600 hover:bg-red-500 text-white'
            : 'bg-orange-500 hover:bg-orange-400 text-white'
        }`}
      >
        Liteプランへアップグレード
        <ArrowRight className="w-3 h-3" />
      </Link>

      {/* 価格の補足 */}
      <span className="hidden md:block text-[10px] shrink-0 text-[#5a6a7a]">
        Liteプラン ¥500/台/月〜（最小5台）
      </span>

      {/* 閉じるボタン */}
      <button
        onClick={dismiss}
        className="shrink-0 text-falcon-subtle hover:text-white transition-colors ml-1"
        title="今は閉じる（セッション中のみ非表示）"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}
