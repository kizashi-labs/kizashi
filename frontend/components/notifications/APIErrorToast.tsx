'use client'

import { useEffect, useState, useCallback } from 'react'
import { registerRateLimitHandler, registerServerErrorHandler } from '@/lib/api'
import { AlertTriangle, X, Clock } from 'lucide-react'

interface RateLimitToast {
  id: number
  message: string
  retryAfter?: number
  expiresAt: number
  kind?: 'rate-limit' | 'server-error'
}

let _toastId = 0

export function APIErrorToast() {
  const [toasts, setToasts] = useState<RateLimitToast[]>([])

  const dismiss = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  useEffect(() => {
    // サーバがデータを返せなかったとき。以前は 200 と空のリストが返って
    // いたので、画面には「0件」と出るだけで何も起きていないように見えました。
    registerServerErrorHandler(message => {
      const id = ++_toastId
      setToasts(prev => [...prev.slice(-2), {
        id, message, expiresAt: Date.now() + 10_000, kind: 'server-error',
      }])
      setTimeout(() => dismiss(id), 10_000)
    })

    registerRateLimitHandler((message, retryAfter) => {
      const id = ++_toastId
      const toast: RateLimitToast = {
        id,
        message,
        retryAfter,
        expiresAt: Date.now() + (retryAfter ?? 60) * 1000,
        kind: 'rate-limit',
      }
      setToasts(prev => [...prev.slice(-2), toast]) // max 3 toasts
      // Auto-dismiss after retryAfter seconds (max 30s display)
      const displayDuration = Math.min((retryAfter ?? 60) * 1000, 30_000)
      setTimeout(() => dismiss(id), displayDuration)
    })
  }, [dismiss])

  if (toasts.length === 0) return null

  return (
    <div className="fixed bottom-20 right-4 z-[200] flex flex-col gap-2 max-w-sm">
      {toasts.map(toast => (
        <RateLimitToastItem key={toast.id} toast={toast} onDismiss={() => dismiss(toast.id)} />
      ))}
    </div>
  )
}

function RateLimitToastItem({
  toast,
  onDismiss,
}: {
  toast: RateLimitToast
  onDismiss: () => void
}) {
  const [remaining, setRemaining] = useState(
    Math.max(0, Math.ceil((toast.expiresAt - Date.now()) / 1000))
  )

  useEffect(() => {
    if (!toast.retryAfter) return
    const interval = setInterval(() => {
      const r = Math.max(0, Math.ceil((toast.expiresAt - Date.now()) / 1000))
      setRemaining(r)
      if (r === 0) clearInterval(interval)
    }, 1000)
    return () => clearInterval(interval)
  }, [toast.expiresAt, toast.retryAfter])

  return (
    <div
      className="bg-[#1a1a2e] border border-orange-500/40 rounded-xl shadow-2xl p-4 flex items-start gap-3 animate-in slide-in-from-right-5"
      role="alert"
    >
      <div className="w-8 h-8 bg-orange-500/10 rounded-lg flex items-center justify-center shrink-0">
        <AlertTriangle className="w-4 h-4 text-orange-400" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-semibold text-orange-300 mb-0.5">
          {toast.kind === 'server-error' ? 'データを取得できません' : 'レート制限'}
        </p>
        <p className="text-xs text-[#7d92b0] leading-relaxed">{toast.message}</p>
        {toast.retryAfter && remaining > 0 && (
          <div className="flex items-center gap-1.5 mt-2">
            <Clock className="w-3 h-3 text-[#3d5068]" />
            <span className="text-xs text-[#3d5068]">残り {remaining}秒</span>
          </div>
        )}
        {/* Progress bar */}
        {toast.retryAfter && (
          <div className="mt-2 h-1 bg-[#1e2d42] rounded-full overflow-hidden">
            <div
              className="h-full bg-orange-500/60 rounded-full transition-all duration-1000"
              style={{ width: `${(remaining / (toast.retryAfter ?? 1)) * 100}%` }}
            />
          </div>
        )}
      </div>
      <button
        onClick={onDismiss}
        className="w-6 h-6 flex items-center justify-center text-[#3d5068] hover:text-white transition-colors shrink-0"
        aria-label="閉じる"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}
