'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import Link from 'next/link'
import { X, Cloud, AlertTriangle, ShieldAlert } from 'lucide-react'

// Suspicious event types that warrant a toast (mirrors server DefaultCloudRules)
const SUSPICIOUS_EVENTS = new Set([
  'DeleteTrail', 'StopLogging', 'CreateAccessKey', 'DeleteAccessKey',
  'PutUserPolicy', 'AttachRolePolicy', 'CreateVpc', 'AuthorizeSecurityGroupIngress',
  'DeleteBucket', 'PutBucketPolicy',
  // Azure equivalents
  'Microsoft.Authorization/roleAssignments/write',
  'Microsoft.KeyVault/vaults/delete',
  'Microsoft.Network/networkSecurityGroups/write',
  'Microsoft.Compute/virtualMachines/delete',
])

interface CloudEvent {
  id: string
  provider: string
  event_type: string
  event_time: string
  source_ip?: string
  region?: string
  resource?: string
  user_identity?: Record<string, unknown>
}

interface CloudToast {
  id: string
  event: CloudEvent
  suspicious: boolean
  expiresAt: number
}

const MAX_TOASTS   = 4
const TOAST_TTL_MS = 10000

function providerColor(provider: string) {
  if (provider === 'aws')   return { border: 'border-orange-700', bg: 'bg-orange-900/25', text: 'text-orange-400', label: 'AWS' }
  if (provider === 'azure') return { border: 'border-blue-700',   bg: 'bg-blue-900/25',   text: 'text-blue-400',   label: 'Azure' }
  return                           { border: 'border-slate-700',  bg: 'bg-slate-900/25',  text: 'text-slate-400',  label: provider.toUpperCase() }
}

interface ToastItemProps {
  toast: CloudToast
  onClose: (id: string) => void
}

function CloudToastItem({ toast, onClose }: ToastItemProps) {
  const cfg = providerColor(toast.event.provider)
  const Icon = toast.suspicious ? ShieldAlert : (toast.event.event_type.includes('Delete') ? AlertTriangle : Cloud)
  const [visible, setVisible] = useState(false)

  useEffect(() => {
    requestAnimationFrame(() => setVisible(true))
    const tid = setTimeout(() => onClose(toast.id), TOAST_TTL_MS)
    return () => clearTimeout(tid)
  }, [toast.id, onClose])

  const username = (() => {
    const uid = toast.event.user_identity
    if (!uid) return ''
    return (uid.username as string) || (uid.userName as string) || (uid.arn as string)?.split('/').pop() || ''
  })()

  return (
    <div
      className={`
        w-80 rounded-lg border shadow-lg overflow-hidden
        transition-all duration-300
        ${cfg.border} ${cfg.bg}
        ${visible ? 'opacity-100 translate-x-0' : 'opacity-0 translate-x-8'}
      `}
    >
      {/* Drain bar */}
      <div className="h-0.5 w-full bg-[#1e2d42]">
        <div
          className={`h-full ${toast.suspicious ? 'bg-red-500' : 'bg-orange-500'}`}
          style={{ animation: `toast-drain ${TOAST_TTL_MS}ms linear forwards` }}
        />
      </div>

      <div className="flex items-start gap-3 px-3 py-3">
        <Icon className={`w-4 h-4 mt-0.5 flex-shrink-0 ${toast.suspicious ? 'text-red-400' : cfg.text}`} />
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-1.5 mb-0.5">
            <span className={`text-[10px] font-bold font-mono ${cfg.text}`}>{cfg.label}</span>
            {toast.suspicious && (
              <span className="text-[10px] font-bold font-mono text-red-400 animate-pulse">⚠ SUSPICIOUS</span>
            )}
          </div>
          <p className="text-sm text-[#e2e8f4] font-medium leading-snug truncate">{toast.event.event_type}</p>
          <div className="flex flex-col gap-0.5 mt-0.5">
            {username && (
              <p className="text-[11px] text-[#5a6a7a] truncate">User: {username}</p>
            )}
            {toast.event.source_ip && (
              <p className="text-[11px] text-[#5a6a7a] truncate font-mono">IP: {toast.event.source_ip}</p>
            )}
            {toast.event.region && (
              <p className="text-[11px] text-[#5a6a7a] truncate">Region: {toast.event.region}</p>
            )}
          </div>
          {toast.suspicious && (
            <Link
              href="/settings/cloud"
              className="inline-block mt-1.5 text-[11px] text-red-400 hover:text-red-300 transition-colors"
              onClick={() => onClose(toast.id)}
            >
              クラウド監視を確認 →
            </Link>
          )}
        </div>
        <button
          onClick={() => onClose(toast.id)}
          className="text-[#3d5068] hover:text-[#7d92b0] transition-colors flex-shrink-0"
        >
          <X className="w-3.5 h-3.5" />
        </button>
      </div>
    </div>
  )
}

export function CloudAlertToastContainer() {
  const [toasts, setToasts] = useState<CloudToast[]>([])
  const esRef = useRef<EventSource | null>(null)

  const closeToast = useCallback((id: string) => {
    setToasts(prev => prev.filter(t => t.id !== id))
  }, [])

  useEffect(() => {
    const token = typeof window !== 'undefined' ? localStorage.getItem('edr_token') : null
    const url = token ? `/ws/cloud?token=${encodeURIComponent(token)}` : '/ws/cloud'
    const es = new EventSource(url)
    esRef.current = es

    // Stop auto-reconnecting on persistent errors (e.g. 401)
    es.onerror = () => {
      es.close()
      esRef.current = null
    }

    es.onmessage = (evt) => {
      try {
        const msg = JSON.parse(evt.data)
        if (msg.type !== 'cloud_event') return
        const event: CloudEvent = msg.data
        if (!event?.id || !event?.event_type) return

        const suspicious = SUSPICIOUS_EVENTS.has(event.event_type)

        setToasts(prev => {
          if (prev.some(t => t.event.id === event.id)) return prev
          const next = [
            ...prev,
            {
              id: `ctst-${Date.now()}-${Math.random()}`,
              event,
              suspicious,
              expiresAt: Date.now() + TOAST_TTL_MS,
            },
          ]
          return next.slice(-MAX_TOASTS)
        })
      } catch {
        // ignore malformed
      }
    }

    return () => {
      es.close()
      esRef.current = null
    }
  }, [])

  if (toasts.length === 0) return null

  return (
    <div className="fixed bottom-20 right-4 z-50 flex flex-col gap-2 items-end pointer-events-none">
      {toasts.map(t => (
        <div key={t.id} className="pointer-events-auto">
          <CloudToastItem toast={t} onClose={closeToast} />
        </div>
      ))}
    </div>
  )
}
