'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Monitor,
  Smartphone,
  Globe,
  MapPin,
  Clock,
  LogOut,
  ShieldAlert,
  CheckCircle2,
  AlertTriangle,
  RefreshCw,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

interface SessionItem {
  id: string
  device_info: {
    browser?: string
    os?: string
    user_agent?: string
  }
  ip_address: string
  created_at: string
  last_seen_at: string
  expires_at: string
  is_current: boolean
}

function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const minutes = Math.floor(diff / 60_000)
  if (minutes < 1) return 'たった今'
  if (minutes < 60) return `${minutes}分前`
  const hours = Math.floor(minutes / 60)
  if (hours < 24) return `${hours}時間前`
  const days = Math.floor(hours / 24)
  return `${days}日前`
}

function DeviceIcon({ os }: { os?: string }) {
  const lower = (os ?? '').toLowerCase()
  if (lower.includes('android') || lower.includes('ios') || lower.includes('iphone')) {
    return <Smartphone className="w-5 h-5 text-[#4a9eff]" />
  }
  return <Monitor className="w-5 h-5 text-[#4a9eff]" />
}

export default function SessionsPage() {
  const qc = useQueryClient()
  const [revokeError, setRevokeError] = useState<string | null>(null)
  const [revokeSuccess, setRevokeSuccess] = useState<string | null>(null)

  const { data: sessions, isLoading, isError } = useQuery<SessionItem[]>({
    queryKey: ['sessions'],
    queryFn: () => apiFetchList<SessionItem>('/api/v1/sessions'),
    refetchOnWindowFocus: false,
  })

  const revokeOne = useMutation({
    mutationFn: (id: string) =>
      apiFetch<{ message: string }>(`/api/v1/sessions/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['sessions'] })
      setRevokeError(null)
      setRevokeSuccess('セッションを失効させました')
      setTimeout(() => setRevokeSuccess(null), 4000)
    },
    onError: (err: Error) => {
      setRevokeSuccess(null)
      setRevokeError(err.message)
      setTimeout(() => setRevokeError(null), 5000)
    },
  })

  const revokeAll = useMutation({
    mutationFn: () =>
      apiFetch<{ message: string; revoked: number }>('/api/v1/sessions', { method: 'DELETE' }),
    onSuccess: (data) => {
      qc.invalidateQueries({ queryKey: ['sessions'] })
      setRevokeError(null)
      setRevokeSuccess(`他のセッションを ${data.revoked} 件すべて失効させました`)
      setTimeout(() => setRevokeSuccess(null), 4000)
    },
    onError: (err: Error) => {
      setRevokeSuccess(null)
      setRevokeError(err.message)
      setTimeout(() => setRevokeError(null), 5000)
    },
  })

  const otherSessionCount = (sessions ?? []).filter((s) => !s.is_current).length

  return (
    <div className="p-6 max-w-3xl space-y-6">
      <PageDataUnavailable />
      {/* Header */}
      <div>
        <h1 className="text-2xl font-bold text-white">アクティブセッション</h1>
        <p className="text-[#8899aa] text-sm mt-1">
          現在ログイン中のデバイスを確認し、不審なセッションを失効させることができます
        </p>
      </div>

      {/* Feedback banners */}
      {revokeSuccess && (
        <div className="flex items-center gap-3 bg-green-900/30 border border-green-700/50 rounded-lg px-4 py-3">
          <CheckCircle2 className="w-4 h-4 text-green-400 shrink-0" />
          <span className="text-green-300 text-sm">{revokeSuccess}</span>
        </div>
      )}
      {revokeError && (
        <div className="flex items-center gap-3 bg-red-900/30 border border-red-700/50 rounded-lg px-4 py-3">
          <AlertTriangle className="w-4 h-4 text-red-400 shrink-0" />
          <span className="text-red-300 text-sm">{revokeError}</span>
        </div>
      )}

      {/* Revoke-all button */}
      {otherSessionCount > 0 && (
        <div className="flex justify-end">
          <button
            onClick={() => revokeAll.mutate()}
            disabled={revokeAll.isPending}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-red-900/30 border border-red-700/50 text-red-300 text-sm font-medium hover:bg-red-900/50 hover:border-red-600 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
          >
            {revokeAll.isPending ? (
              <RefreshCw className="w-4 h-4 animate-spin" />
            ) : (
              <ShieldAlert className="w-4 h-4" />
            )}
            他の全セッションを失効 ({otherSessionCount})
          </button>
        </div>
      )}

      {/* Session list */}
      {isLoading ? (
        <div className="flex items-center justify-center py-16">
          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-blue-500" />
        </div>
      ) : isError ? (
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-8 text-center text-[#8899aa]">
          セッション一覧の取得に失敗しました
        </div>
      ) : !sessions || sessions.length === 0 ? (
        <div className="bg-[#111827] rounded-xl border border-[#1e2d42] p-8 text-center text-[#8899aa]">
          アクティブなセッションがありません
        </div>
      ) : (
        <div className="space-y-3">
          {sessions.map((session) => (
            <div
              key={session.id}
              className={`bg-[#111827] rounded-xl border p-5 transition-colors ${
                session.is_current
                  ? 'border-[#1e3a5f] ring-1 ring-[#1e4a7f]/50'
                  : 'border-[#1e2d42] hover:border-[#2a3d55]'
              }`}
            >
              <div className="flex items-start justify-between gap-4">
                {/* Left: device info */}
                <div className="flex items-start gap-4 min-w-0">
                  <div className="mt-0.5 p-2 rounded-lg bg-[#0d1829] border border-[#1e2d42] shrink-0">
                    <DeviceIcon os={session.device_info?.os} />
                  </div>

                  <div className="min-w-0 space-y-2">
                    {/* Device + current badge */}
                    <div className="flex flex-wrap items-center gap-2">
                      <span className="text-white font-medium text-sm truncate">
                        {session.device_info?.browser
                          ? `${session.device_info.browser}${session.device_info.os ? ` / ${session.device_info.os}` : ''}`
                          : session.device_info?.os
                          ? session.device_info.os
                          : '不明なデバイス'}
                      </span>
                      {session.is_current && (
                        <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-full bg-blue-900/40 border border-blue-700/50 text-blue-300 text-xs font-medium shrink-0">
                          <CheckCircle2 className="w-3 h-3" />
                          現在のセッション
                        </span>
                      )}
                    </div>

                    {/* Meta row */}
                    <div className="flex flex-wrap items-center gap-x-4 gap-y-1 text-xs text-[#8899aa]">
                      {session.ip_address && (
                        <span className="flex items-center gap-1">
                          <MapPin className="w-3.5 h-3.5 shrink-0" />
                          {session.ip_address}
                        </span>
                      )}
                      <span className="flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5 shrink-0" />
                        最終アクセス: {formatRelativeTime(session.last_seen_at)}
                      </span>
                      <span className="flex items-center gap-1">
                        <Globe className="w-3.5 h-3.5 shrink-0" />
                        ログイン: {formatRelativeTime(session.created_at)}
                      </span>
                    </div>

                    {/* User-agent fallback (truncated) */}
                    {session.device_info?.user_agent &&
                      !session.device_info?.browser &&
                      !session.device_info?.os && (
                        <p className="text-xs text-[#6677aa] truncate max-w-xs" title={session.device_info.user_agent}>
                          {session.device_info.user_agent}
                        </p>
                      )}
                  </div>
                </div>

                {/* Right: revoke button (hidden for current session) */}
                {!session.is_current && (
                  <button
                    onClick={() => revokeOne.mutate(session.id)}
                    disabled={revokeOne.isPending && revokeOne.variables === session.id}
                    className="shrink-0 flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0d1829] border border-[#1e2d42] text-[#8899aa] text-xs font-medium hover:border-red-700/60 hover:text-red-300 hover:bg-red-900/20 transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                    title="このセッションを失効させる"
                  >
                    {revokeOne.isPending && revokeOne.variables === session.id ? (
                      <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                    ) : (
                      <LogOut className="w-3.5 h-3.5" />
                    )}
                    失効
                  </button>
                )}
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  )
}
