'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import Link from 'next/link'
import { X, ShieldAlert, ShieldX, AlertTriangle, Info } from 'lucide-react'

interface AlertPayload {
  ID:        string
  Hostname:  string
  RuleName:  string
  Severity:  number
  Title:     string
  Status:    string
  CreatedAt: string
}

interface Toast {
  id:        string
  alert:     AlertPayload
  expiresAt: number
}

const MAX_TOASTS   = 5
const TOAST_TTL_MS = 8000

function severityConfig(sev: number) {
  if (sev >= 4) return { label: 'CRITICAL', icon: ShieldX,      border: 'border-red-700',    bg: 'bg-red-900/30',    text: 'text-red-400',    bar: 'bg-red-500' }
  if (sev >= 3) return { label: 'HIGH',     icon: ShieldAlert,  border: 'border-orange-700', bg: 'bg-orange-900/30', text: 'text-orange-400', bar: 'bg-orange-500' }
  if (sev >= 2) return { label: 'MEDIUM',   icon: AlertTriangle, border: 'border-yellow-700', bg: 'bg-yellow-900/20', text: 'text-yellow-400', bar: 'bg-yellow-500' }
  return          { label: 'LOW',      icon: Info,          border: 'border-blue-700',   bg: 'bg-blue-900/20',   text: 'text-blue-400',   bar: 'bg-blue-500' }
}

interface ToastItemProps {
  toast: Toast
  onClose: (id: string) => void
}

function ToastItem({ toast, onClose }: ToastItemProps) {
  const cfg = severityConfig(toast.alert.Severity)
  const Icon = cfg.icon
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    // Animate in
    requestAnimationFrame(() => setVisible(true))
    // Auto-close
    const tid = setTimeout(() => onClose(toast.id), TOAST_TTL_MS)
    return () => clearTimeout(tid)
  }, [toast.id, onClose])

  return (
    <div
      className={`
        w-80 rounded-lg border shadow-lg overflow-hidden
        transition-all duration-300
        ${cfg.border} ${cfg.bg}
        ${visible ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-8'}
      `}
    >
      {/* Severity bar (auto-drain) */}
      <div className="h-0.5 w-full bg-[#1e2d42]">
        <div
          className={`h-full ${cfg.bar}`}
          style={{
            animation: `toast-drain ${TOAST_TTL_MS}ms linear forwards`,
          }}
        />
      </div>

      <div className="flex items-start gap-3 px-3 py-3">
        <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${cfg.text}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5 mb-0.5">
            <span className={`text-[10px] font-bold font-mono ${cfg.text}`}>{cfg.label}</span>
            <span className="text-[10px] text-[#5a6a7a] font-mono">{toast.alert.Hostname}</span>
          </div>
          <p className="text-sm text-[#e2e8f4] font-medium leading-snug truncate">{toast.alert.Title}</p>
          {toast.alert.RuleName && (
            <p className="text-[11px] text-[#5a6a7a] truncate mt-0.5">{toast.alert.RuleName}</p>
          )}
          <Link
            href={`/alerts/${toast.alert.ID}`}
            className="inline-block mt-1.5 text-[11px] text-blue-400 hover:text-blue-300 transition-colors"
            onClick={() => onClose(toast.id)}
          >
            詳細を確認 →
          </Link>
        </div>
        <button
          onClick={() => onClose(toast.id)}
          className="text-[#3d5068] hover:text-[#7d92b0] transition-colors shrink-0"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>

    </div>
  )
}

export function AlertToastContainer() {
  const [toasts, setToasts] = useState<Toast[]>([])
  const esRef = useRef<EventSource | null>(null)

  const closeToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  useEffect(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('edr_token') : null
    const url = token ? `/ws/alerts?token=${encodeURIComponent(token)}` : '/ws/alerts'
    const es = new EventSource(url)
    esRef.current = es

    // Stop auto-reconnecting on persistent errors (e.g. 404)
    es.onerror = () => {
      es.close()
      esRef.current = null
    }

    es.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data)
        if (msg.type !== 'alert') return
        const raw = msg.data ?? {}
        // Normalize: Go JSON tags produce lowercase; handle both cases.
        const alert: AlertPayload = {
          ID:        raw.ID        ?? raw.id        ?? '',
          Hostname:  raw.Hostname  ?? raw.agent_hostname ?? raw.hostname ?? '',
          RuleName:  raw.RuleName  ?? raw.rule_name ?? '',
          Severity:  raw.Severity  ?? raw.severity  ?? 0,
          Title:     raw.Title     ?? raw.title     ?? '',
          Status:    raw.Status    ?? raw.status    ?? '',
          CreatedAt: raw.CreatedAt ?? raw.created_at ?? '',
        }
        if (!alert.ID || !alert.Title) return

        setToasts(prev => {
          // Deduplicate by alert ID
          if (prev.some(t => t.alert.ID === alert.ID)) return prev
          const next = [
            ...prev,
            { id: `toast-${Date.now()}-${Math.random()}`, alert, expiresAt: Date.now() + TOAST_TTL_MS },
          ]
          // Keep only newest MAX_TOASTS
          return next.slice(-MAX_TOASTS)
        })
      } catch {
        // ignore malformed payloads
      }
    }

    return () => {
      es.close()
      esRef.current = null
    }
  }, [])

  if (toasts.length === 0) return null

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-2 items-end pointer-events-none">
      {toasts.map(t => (
        <div key={t.id} className="pointer-events-auto">
          <ToastItem toast={t} onClose={closeToast} />
        </div>
      ))}
    </div>
  )
}
