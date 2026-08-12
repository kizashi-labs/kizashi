'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Shield, RefreshCw, Plus, AlertTriangle, CheckCircle, Clock, X, Globe,
} from 'lucide-react'
// ── Types ──────────────────────────────────────────────────────────────────────

interface CertEntry {
  id: string
  domain: string
  issuer: string
  expires_at: string
  days_remaining: number
  status: 'valid' | 'expiring_soon' | 'expired' | 'error'
  port: number
  last_checked: string
}

interface CertResponse {
  data: CertEntry[]
  total: number
}

// ── Mock data ──────────────────────────────────────────────────────────────────

const now = new Date()

function daysFromNow(days: number): string {
  const d = new Date(now.getTime() + days * 86400000)
  return d.toISOString()
}

const STATUS_CONFIG: Record<string, { label: string; classes: string }> = {
  valid: { label: '有効', classes: 'bg-green-500/20 text-green-400 border border-green-500/30' },
  expiring_soon: { label: '期限切れ間近', classes: 'bg-yellow-500/20 text-yellow-400 border border-yellow-500/30' },
  expired: { label: '期限切れ', classes: 'bg-red-500/20 text-red-400 border border-red-500/30' },
  error: { label: 'エラー', classes: 'bg-gray-500/20 text-gray-400 border border-gray-500/30' },
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function formatDate(iso: string) {
  if (iso === '—') return '—'
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric',
      month: '2-digit',
      day: '2-digit',
      hour: '2-digit',
      minute: '2-digit',
    })
  } catch {
    return iso
  }
}

function DaysBar({ days, status }: { days: number; status: CertEntry['status'] }) {
  if (status === 'error') {
    return <span className="text-[#8899aa] text-sm">—</span>
  }

  if (days < 0) {
    return (
      <span className="text-red-400 font-semibold text-sm">
        {days}日
      </span>
    )
  }

  const cap = Math.min(days, 365)
  const pct = (cap / 365) * 100

  let barColor = 'bg-green-500'
  let textColor = 'text-green-300'
  if (days < 14) {
    barColor = 'bg-red-500'
    textColor = 'text-red-300'
  } else if (days < 60) {
    barColor = 'bg-orange-500'
    textColor = 'text-orange-300'
  }

  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full ${barColor}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <span className={`text-sm font-medium whitespace-nowrap ${textColor}`}>
        {days}日
      </span>
    </div>
  )
}

// ── Main page ──────────────────────────────────────────────────────────────────

export default function CertMonitorPage() {
  const queryClient = useQueryClient()

  const [showAddModal, setShowAddModal] = useState(false)
  const [form, setForm] = useState({ domain: '', port: '443' })
  const [formError, setFormError] = useState('')

  const { data, isLoading, isFetching } = useQuery<CertResponse>({
    queryKey: ['certificates'],
    queryFn: async () => {
      try {
        return await apiFetch<CertResponse>('/api/v1/admin/certificates')
      } catch {
        return { data: [], total: 0 } as CertResponse
      }
    },
    staleTime: 60_000,
  })

  const addMutation = useMutation({
    mutationFn: (payload: { domain: string; port: number }) =>
      apiFetch<CertEntry>('/api/v1/admin/certificates', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['certificates'] })
      setShowAddModal(false)
      setForm({ domain: '', port: '443' })
      setFormError('')
    },
    onError: (err: Error) => {
      setFormError(err.message || '追加に失敗しました')
    },
  })

  const entries = data?.data ?? []

  const stats = {
    total: entries.length,
    valid: entries.filter((e) => e.status === 'valid').length,
    expiring: entries.filter((e) => e.status === 'expiring_soon').length,
    expired: entries.filter((e) => e.status === 'expired').length,
  }

  const urgentCount = entries.filter(
    (e) => e.days_remaining >= 0 && e.days_remaining <= 7 && e.status !== 'error',
  ).length

  function handleAddSubmit(e: React.FormEvent) {
    e.preventDefault()
    setFormError('')
    const port = parseInt(form.port, 10)
    if (!form.domain.trim()) {
      setFormError('ドメインを入力してください')
      return
    }
    if (isNaN(port) || port < 1 || port > 65535) {
      setFormError('有効なポート番号を入力してください (1–65535)')
      return
    }
    addMutation.mutate({ domain: form.domain.trim(), port })
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-white p-6">
      {/* ── Header ── */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <Shield className="w-7 h-7 text-blue-400" />
          <div>
            <h1 className="text-2xl font-bold text-white">TLS証明書モニター</h1>
            <p className="text-[#8899aa] text-sm mt-0.5">
              SSL/TLS証明書の有効期限を監視します
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => queryClient.invalidateQueries({ queryKey: ['certificates'] })}
            disabled={isFetching}
            className="flex items-center gap-2 px-3 py-2 rounded-lg border border-[#1e2d42] bg-[#0d1220] text-[#8899aa] hover:text-white hover:border-[#2a3f5f] transition-colors text-sm disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${isFetching ? 'animate-spin' : ''}`} />
            更新
          </button>
          <button
            onClick={() => setShowAddModal(true)}
            className="flex items-center gap-2 px-3 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white transition-colors text-sm font-medium"
          >
            <Plus className="w-4 h-4" />
            証明書を追加
          </button>
        </div>
      </div>

      {/* ── Warning banner ── */}
      {urgentCount > 0 && (
        <div className="mb-5 flex items-center gap-3 px-4 py-3 rounded-lg bg-red-900/30 border border-red-700/50 text-red-300">
          <AlertTriangle className="w-5 h-5 flex-shrink-0" />
          <span className="text-sm font-medium">
            ⚠ {urgentCount}件の証明書が7日以内に期限切れになります
          </span>
        </div>
      )}

      {/* ── Stats row ── */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-blue-900/30">
            <Globe className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <p className="text-[#8899aa] text-xs">証明書総数</p>
            <p className="text-2xl font-bold text-white">{stats.total}</p>
          </div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-green-900/30">
            <CheckCircle className="w-5 h-5 text-green-400" />
          </div>
          <div>
            <p className="text-[#8899aa] text-xs">有効</p>
            <p className="text-2xl font-bold text-green-300">{stats.valid}</p>
          </div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-orange-900/30">
            <Clock className="w-5 h-5 text-orange-400" />
          </div>
          <div>
            <p className="text-[#8899aa] text-xs">期限切れ間近 (≤30日)</p>
            <p className="text-2xl font-bold text-orange-300">{stats.expiring}</p>
          </div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-center gap-3">
          <div className="p-2 rounded-lg bg-red-900/30">
            <AlertTriangle className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <p className="text-[#8899aa] text-xs">期限切れ</p>
            <p className="text-2xl font-bold text-red-300">{stats.expired}</p>
          </div>
        </div>
      </div>

      {/* ── Certificate table ── */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {[
                  'ドメイン', '発行者', '有効期限', '残り日数', 'ステータス', 'ポート', '最終確認',
                ].map((h) => (
                  <th
                    key={h}
                    className="px-4 py-3 text-left text-[#8899aa] font-medium text-xs uppercase tracking-wide"
                  >
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {isLoading ? (
                Array.from({ length: 5 }).map((_, i) => (
                  <tr key={i} className="border-b border-[#1e2d42]/50">
                    {Array.from({ length: 7 }).map((_, j) => (
                      <td key={j} className="px-4 py-3">
                        <div className="h-4 bg-[#1e2d42] rounded animate-pulse w-24" />
                      </td>
                    ))}
                  </tr>
                ))
              ) : entries.length === 0 ? (
                <tr>
                  <td colSpan={7} className="px-4 py-12 text-center text-[#8899aa]">
                    証明書が登録されていません
                  </td>
                </tr>
              ) : (
                entries.map((cert) => (
                  <tr
                    key={cert.id}
                    className="border-b border-[#1e2d42]/50 hover:bg-[#0d1828]/60 transition-colors"
                  >
                    {/* Domain */}
                    <td className="px-4 py-3 font-mono text-white font-medium">
                      {cert.domain}
                    </td>

                    {/* Issuer */}
                    <td className="px-4 py-3 text-[#8899aa] max-w-[180px] truncate">
                      {cert.issuer}
                    </td>

                    {/* Expires At */}
                    <td className="px-4 py-3 text-[#8899aa] whitespace-nowrap">
                      {cert.expires_at === '—' ? '—' : formatDate(cert.expires_at)}
                    </td>

                    {/* Days Remaining */}
                    <td className="px-4 py-3">
                      <DaysBar days={cert.days_remaining} status={cert.status} />
                    </td>

                    {/* Status */}
                    <td className="px-4 py-3">
                      <span
                        className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium ${STATUS_CONFIG[cert.status].classes}`}
                      >
                        {STATUS_CONFIG[cert.status].label}
                      </span>
                    </td>

                    {/* Port */}
                    <td className="px-4 py-3 text-[#8899aa] font-mono">
                      {cert.port}
                    </td>

                    {/* Last Checked */}
                    <td className="px-4 py-3 text-[#8899aa] whitespace-nowrap">
                      {formatDate(cert.last_checked)}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Add Certificate Modal ── */}
      {showAddModal && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md mx-4 shadow-2xl">
            {/* Modal header */}
            <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
              <div className="flex items-center gap-2">
                <Shield className="w-5 h-5 text-blue-400" />
                <h2 className="text-base font-semibold text-white">証明書を追加</h2>
              </div>
              <button
                onClick={() => {
                  setShowAddModal(false)
                  setForm({ domain: '', port: '443' })
                  setFormError('')
                }}
                className="p-1 rounded hover:bg-[#1e2d42] text-[#8899aa] hover:text-white transition-colors"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            {/* Modal body */}
            <form onSubmit={handleAddSubmit} className="px-5 py-4 space-y-4">
              {formError && (
                <div className="flex items-center gap-2 text-sm text-red-300 bg-red-900/20 border border-red-700/40 rounded-lg px-3 py-2">
                  <AlertTriangle className="w-4 h-4 flex-shrink-0" />
                  {formError}
                </div>
              )}

              <div>
                <label className="block text-xs font-medium text-[#8899aa] mb-1.5">
                  ドメイン
                </label>
                <input
                  type="text"
                  placeholder="例: example.com"
                  value={form.domain}
                  onChange={(e) => setForm((f) => ({ ...f, domain: e.target.value }))}
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white placeholder-[#8899aa] text-sm focus:outline-none focus:border-blue-500 transition-colors"
                />
              </div>

              <div>
                <label className="block text-xs font-medium text-[#8899aa] mb-1.5">
                  ポート
                </label>
                <input
                  type="number"
                  placeholder="443"
                  min={1}
                  max={65535}
                  value={form.port}
                  onChange={(e) => setForm((f) => ({ ...f, port: e.target.value }))}
                  className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-lg text-white placeholder-[#8899aa] text-sm focus:outline-none focus:border-blue-500 transition-colors"
                />
              </div>

              <div className="flex justify-end gap-2 pt-1">
                <button
                  type="button"
                  onClick={() => {
                    setShowAddModal(false)
                    setForm({ domain: '', port: '443' })
                    setFormError('')
                  }}
                  className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#8899aa] hover:text-white hover:border-[#2a3f5f] transition-colors text-sm"
                >
                  キャンセル
                </button>
                <button
                  type="submit"
                  disabled={addMutation.isPending}
                  className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-500 text-white font-medium text-sm transition-colors disabled:opacity-50 disabled:cursor-not-allowed"
                >
                  {addMutation.isPending ? '追加中...' : '追加'}
                </button>
              </div>
            </form>
          </div>
        </div>
      )}
    </div>
  )
}
