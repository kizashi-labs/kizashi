'use client'

import Link from 'next/link'
import { Shield, Home, Bell, Cpu, Search, Activity } from 'lucide-react'

export default function NotFound() {
  return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-6">
      <div className="text-center max-w-lg w-full">
        {/* Shield icon */}
        <div className="w-20 h-20 rounded-2xl bg-linear-to-br from-red-600 to-red-800 flex items-center justify-center mx-auto mb-6 shadow-lg shadow-red-900/30">
          <Shield className="w-10 h-10 text-white" />
        </div>

        {/* Large 404 */}
        <p className="text-8xl font-black font-mono text-zinc-800 mb-4 tracking-tighter select-none">
          404
        </p>

        {/* Title & message */}
        <h1 className="text-2xl font-bold text-zinc-100 mb-3">ページが見つかりません</h1>
        <p className="text-sm text-zinc-400 mb-8 leading-relaxed">
          お探しのページは存在しないか、移動された可能性があります。
        </p>

        {/* Primary action */}
        <Link
          href="/admin/dashboard"
          className="inline-flex items-center gap-2 px-5 py-2.5 bg-red-600 hover:bg-red-500 text-white text-sm font-medium rounded-lg transition-colors mb-8"
        >
          <Home className="w-4 h-4" />
          ダッシュボードへ
        </Link>

        {/* Quick links */}
        <div className="border-t border-zinc-800 pt-6">
          <p className="text-xs text-zinc-500 uppercase tracking-wider mb-4">クイックリンク</p>
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <Link
              href="/alerts"
              className="flex flex-col items-center gap-1.5 p-3 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 hover:bg-zinc-800 transition-all group"
            >
              <Bell className="w-4 h-4 text-zinc-500 group-hover:text-zinc-300 transition-colors" />
              <span className="text-xs text-zinc-400 group-hover:text-zinc-200 transition-colors">アラート</span>
            </Link>
            <Link
              href="/endpoints"
              className="flex flex-col items-center gap-1.5 p-3 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 hover:bg-zinc-800 transition-all group"
            >
              <Cpu className="w-4 h-4 text-zinc-500 group-hover:text-zinc-300 transition-colors" />
              <span className="text-xs text-zinc-400 group-hover:text-zinc-200 transition-colors">エンドポイント</span>
            </Link>
            <Link
              href="/threat-hunting"
              className="flex flex-col items-center gap-1.5 p-3 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 hover:bg-zinc-800 transition-all group"
            >
              <Search className="w-4 h-4 text-zinc-500 group-hover:text-zinc-300 transition-colors" />
              <span className="text-xs text-zinc-400 group-hover:text-zinc-200 transition-colors">脅威ハンティング</span>
            </Link>
            <Link
              href="/status"
              className="flex flex-col items-center gap-1.5 p-3 rounded-lg bg-zinc-900 border border-zinc-800 hover:border-zinc-700 hover:bg-zinc-800 transition-all group"
            >
              <Activity className="w-4 h-4 text-zinc-500 group-hover:text-zinc-300 transition-colors" />
              <span className="text-xs text-zinc-400 group-hover:text-zinc-200 transition-colors">システム状態</span>
            </Link>
          </div>
        </div>
      </div>
    </div>
  )
}
