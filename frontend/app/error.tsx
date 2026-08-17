'use client'

import { useEffect } from 'react'
import { AlertTriangle, RefreshCw, Home } from 'lucide-react'
import Link from 'next/link'

export default function Error({
  error,
  reset,
}: {
  error: Error & { digest?: string }
  reset: () => void
}) {
  useEffect(() => {
    console.error(error)
  }, [error])

  const truncatedMessage = error?.message
    ? error.message.length > 200
      ? error.message.slice(0, 200) + '…'
      : error.message
    : null

  return (
    <div className="min-h-screen bg-zinc-950 flex items-center justify-center p-6">
      <div className="text-center max-w-md w-full">
        {/* Icon */}
        <div className="w-20 h-20 rounded-2xl bg-linear-to-br from-orange-600 to-orange-800 flex items-center justify-center mx-auto mb-6 shadow-lg shadow-orange-900/30">
          <AlertTriangle className="w-10 h-10 text-white" />
        </div>

        {/* Title */}
        <h1 className="text-2xl font-bold text-zinc-100 mb-3">エラーが発生しました</h1>
        <p className="text-sm text-zinc-400 mb-5 leading-relaxed">
          予期しないエラーが発生しました。再試行するか、ダッシュボードに戻ってください。
        </p>

        {/* Error message */}
        {truncatedMessage && (
          <div className="mb-5 text-left bg-zinc-900 border border-zinc-800 rounded-lg px-4 py-3">
            <p className="text-xs text-zinc-500 font-mono break-all leading-relaxed">
              {truncatedMessage}
            </p>
          </div>
        )}

        {/* Error digest */}
        {error?.digest && (
          <p className="text-xs text-zinc-600 font-mono mb-6">
            エラーID: {error.digest}
          </p>
        )}

        {/* Actions */}
        <div className="flex items-center justify-center gap-3">
          <button
            onClick={reset}
            className="flex items-center gap-2 px-4 py-2.5 bg-zinc-800 hover:bg-zinc-700 border border-zinc-700 hover:border-zinc-600 text-zinc-300 hover:text-zinc-100 text-sm font-medium rounded-lg transition-colors"
          >
            <RefreshCw className="w-4 h-4" />
            再試行
          </button>
          <Link
            href="/admin/dashboard"
            className="flex items-center gap-2 px-4 py-2.5 bg-red-600 hover:bg-red-500 text-white text-sm font-medium rounded-lg transition-colors"
          >
            <Home className="w-4 h-4" />
            ダッシュボードへ
          </Link>
        </div>
      </div>
    </div>
  )
}
