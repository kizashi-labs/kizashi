'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import { X, ShieldX, ShieldAlert, AlertTriangle, Info, Wifi, WifiOff, type LucideIcon } from 'lucide-react'
import { useRealtimeAlerts } from '@/lib/websocket'
import { useAuth } from '@/lib/auth'
import type { Alert } from '@/types/api'

// ─── Constants ────────────────────────────────────────────────────────────────

const MAX_BANNERS = 3
const AUTO_DISMISS_MS = 5000

// ─── Severity helpers ─────────────────────────────────────────────────────────

type SeverityLabel = 'critical' | 'high' | 'medium' | 'low'

function getSeverityLabel(severity: number): SeverityLabel {
  if (severity >= 9) return 'critical'
  if (severity >= 7) return 'high'
  if (severity >= 5) return 'medium'
  return 'low'
}

const SEVERITY_CONFIG: Record<SeverityLabel, {
  label: string
  icon: LucideIcon
  badgeCls: string
  leftBorder: string
  textCls: string
}> = {
  critical: {
    label: 'CRITICAL',
    icon: ShieldX,
    badgeCls: 'bg-red-900/60 text-red-300 border border-red-700/60',
    leftBorder: 'border-l-4 border-l-[#e8002d]',
    textCls: 'text-red-300',
  },
  high: {
    label: 'HIGH',
    icon: ShieldAlert,
    badgeCls: 'bg-orange-900/60 text-orange-300 border border-orange-700/60',
    leftBorder: 'border-l-4 border-l-orange-500',
    textCls: 'text-orange-300',
  },
  medium: {
    label: 'MEDIUM',
    icon: AlertTriangle,
    badgeCls: 'bg-amber-900/60 text-amber-300 border border-amber-700/60',
    leftBorder: 'border-l-4 border-l-amber-400',
    textCls: 'text-amber-300',
  },
  low: {
    label: 'LOW',
    icon: Info,
    badgeCls: 'bg-blue-900/60 text-blue-300 border border-blue-700/60',
    leftBorder: 'border-l-4 border-l-blue-500',
    textCls: 'text-blue-300',
  },
}

// ─── Banner item ──────────────────────────────────────────────────────────────

interface BannerEntry {
  id: string
  alert: Alert
}

interface BannerItemProps {
  entry: BannerEntry
  onDismiss: (id: string) => void
}

function BannerItem({ entry, onDismiss }: BannerItemProps) {
  const { alert } = entry
  const sevLabel = getSeverityLabel(alert.severity)
  const cfg = SEVERITY_CONFIG[sevLabel]
  const Icon = cfg.icon
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    // Animate in on next frame
    const raf = requestAnimationFrame(() => setVisible(true))
    // Auto-dismiss
    const timer = setTimeout(() => onDismiss(entry.id), AUTO_DISMISS_MS)
    return () => {
      cancelAnimationFrame(raf)
      clearTimeout(timer)
    }
  }, [entry.id, onDismiss])

  return (
    <div
      role="alert"
      aria-live="assertive"
      className={`
        w-80 rounded-lg border border-[#1e2d42] ${cfg.leftBorder}
        bg-[#0d1220] shadow-lg shadow-black/50
        overflow-hidden transition-all duration-300 ease-out
        ${visible ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-8'}
      `}
    >
      {/* Drain bar */}
      <div className="h-0.5 w-full bg-[#1e2d42]">
        <div
          className={`h-full ${
            sevLabel === 'critical' ? 'bg-[#e8002d]' :
            sevLabel === 'high'     ? 'bg-orange-500' :
            sevLabel === 'medium'   ? 'bg-amber-400' :
                                      'bg-blue-500'
          }`}
          style={{ animation: `banner-drain ${AUTO_DISMISS_MS}ms linear forwards` }}
        />
      </div>

      <div className="flex items-start gap-3 px-3 py-3">
        <Icon className={`w-4 h-4 mt-0.5 shrink-0 ${cfg.textCls}`} size={16} />
        <div className="flex-1 min-w-0">
          {/* Severity badge + hostname */}
          <div className="flex items-center gap-1.5 mb-1 flex-wrap">
            <span className={`text-[10px] font-bold font-mono px-1.5 py-0.5 rounded-sm ${cfg.badgeCls}`}>
              {cfg.label}
            </span>
            {alert.agent_hostname && (
              <span className="text-[10px] text-[#5a6a7a] font-mono truncate">
                {alert.agent_hostname}
              </span>
            )}
          </div>
          {/* Alert title */}
          <p className="text-sm text-[#e2e8f4] font-medium leading-snug truncate">
            {alert.title}
          </p>
        </div>

        {/* Dismiss button */}
        <button
          onClick={() => onDismiss(entry.id)}
          aria-label="閉じる"
          className="text-[#3d5068] hover:text-[#7d92b0] transition-colors shrink-0 mt-0.5"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  )
}

// ─── Connection indicator ─────────────────────────────────────────────────────

function ConnectionDot({ connected }: { connected: boolean }) {
  return (
    <div className="flex items-center gap-1.5" title={connected ? 'SSE接続中' : 'SSE未接続'}>
      {connected ? (
        <>
          <span className="w-2 h-2 rounded-full bg-green-400 animate-none" />
          <Wifi className="w-3 h-3 text-[#3d5068]" />
        </>
      ) : (
        <>
          <span className="w-2 h-2 rounded-full bg-[#5a6a7a]" />
          <WifiOff className="w-3 h-3 text-[#3d5068]" />
        </>
      )}
    </div>
  )
}

// ─── Main component ───────────────────────────────────────────────────────────

export function RealtimeBanner() {
  const { token } = useAuth()
  const { latestAlerts, connected } = useRealtimeAlerts(token)

  const [banners, setBanners] = useState<BannerEntry[]>([])
  // Track IDs we've already shown to avoid re-displaying on re-render
  const shownIds = useRef<Set<string>>(new Set())

  const dismiss = useCallback((id: string) => {
    setBanners(prev => prev.filter(b => b.id !== id))
  }, [])

  // Whenever latestAlerts gains a new entry, add a banner
  useEffect(() => {
    if (latestAlerts.length === 0) return
    const newest = latestAlerts[0]
    if (shownIds.current.has(newest.id)) return
    shownIds.current.add(newest.id)

    setBanners(prev => {
      const next: BannerEntry[] = [
        { id: `banner-${newest.id}-${Date.now()}`, alert: newest },
        ...prev,
      ]
      // Keep at most MAX_BANNERS, dropping oldest
      return next.slice(0, MAX_BANNERS)
    })
  }, [latestAlerts])

  return (
    <div className="fixed top-14 right-4 z-50 flex flex-col items-end gap-2 pointer-events-none">
      {/* Banner stack */}
      {banners.map(b => (
        <div key={b.id} className="pointer-events-auto">
          <BannerItem entry={b} onDismiss={dismiss} />
        </div>
      ))}

      {/* Drain animation keyframes injected once */}
      <style>{`
        @keyframes banner-drain {
          from { width: 100%; }
          to   { width: 0%; }
        }
      `}</style>
    </div>
  )
}
