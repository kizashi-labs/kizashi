'use client'

import { usePathname } from 'next/navigation'
import { Construction } from 'lucide-react'

import { isBackendPending, isPartiallyPending } from '@/lib/backend-pending'

export default function BackendPendingBanner() {
  const pathname = usePathname()
  if (!pathname) return null

  const full = isBackendPending(pathname)
  const partial = isPartiallyPending(pathname)
  if (!full && !partial) return null

  return (
    <div className="bg-amber-500/10 border-b border-amber-500/30 px-4 py-2 flex items-center gap-2">
      <Construction className="w-4 h-4 text-amber-400 shrink-0" />
      <p className="text-xs text-amber-300">
        {full
          ? 'この画面のバックエンドは準備中です。データの表示・保存はまだ行われません（実装後に自動的に有効になります）。'
          : 'この画面の一部機能はバックエンド準備中のため、表示・保存されない項目があります。'}
      </p>
    </div>
  )
}
