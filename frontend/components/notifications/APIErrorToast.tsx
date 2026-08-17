'use client'

import { useEffect, useState, useCallback } from 'react'
import { registerRateLimitHandler } from '@/lib/api'
import { AlertTriangle, X, Clock } from 'lucide-react'

interface RateLimitToast {
  id: number
  message: string
  retryAfter?: number
  expiresAt: number
}

let _toastId = 0

export function APIErrorToast() {
  const [toasts, setToasts] = useState<RateLimitToast[]>([])

  const dismiss = useCallback((id: number) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  useEffect(() => {
    registerRateLimitHandler((message, retryAfter) => {
      const id = ++_toastId
      const toast: RateLimitToast = {
        id,
        message,
        retryAfter,
        expiresAt: Date.now() + (retryAfter ?? 60) * 1000,
      }
      setToasts(prev => [...prev.slice(-2), toast]) // max 3 toasts
      // Auto-dismiss after retryAfter seconds (max 30s display)
      const displayDuration = Math.min((retryAfter ?? 60) * 1000, 30_000)
      setTimeout(() => dismiss(id), displayDuration)
    })
  }, [dismiss])

  if (toasts.length === 0) return null

  return (
    <div className="fixed bottom-20 right-4 z-200 flex flex-col gap-2 max-w-sm">
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
        <p className="text-sm font-semibold text-orange-300 mb-0.5">レート制限</p>
        <p className="text-xs text-falcon-muted leading-relaxed">{toast.message}</p>
        {toast.retryAfter && remaining > 0 && (
          <div className="flex items-center gap-1.5 mt-2">
            <Clock className="w-3 h-3 text-falcon-subtle" />
            <span className="text-xs text-falcon-subtle">残り {remaining}秒</span>
          </div>
        )}
        {/* Progress bar */}
        {toast.retryAfter && (
          <div className="mt-2 h-1 bg-falcon-border rounded-full overflow-hidden">
            <div
              className="h-full bg-orange-500/60 rounded-full transition-all duration-1000"
              style={{ width: `${(remaining / (toast.retryAfter ?? 1)) * 100}%` }}
            />
          </div>
        )}
      </div>
      <button
        onClick={onDismiss}
        className="w-6 h-6 flex items-center justify-center text-falcon-subtle hover:text-white transition-colors shrink-0"
        aria-label="閉じる"
      >
        <X className="w-3.5 h-3.5" />
      </button>
    </div>
  )
}
