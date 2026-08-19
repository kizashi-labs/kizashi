'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Shield, Globe, Activity, AlertTriangle, Play,
  Server, Network, Cloud, User, RefreshCw, ChevronRight
} from 'lucide-react'


import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

const DOMAIN_ICONS: Record<string, React.ReactNode> = {
  endpoint: <Server className="w-4 h-4" />,
  network: <Network className="w-4 h-4" />,
  cloud: <Cloud className="w-4 h-4" />,
  identity: <User className="w-4 h-4" />,
  email: <Globe className="w-4 h-4" />,
}

const DOMAIN_COLORS: Record<string, string> = {
  endpoint: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  network: 'bg-green-500/20 text-green-400 border-green-500/30',
  cloud: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  identity: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  email: 'bg-pink-500/20 text-pink-400 border-pink-500/30',
}

// ── Helpers ────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  const map: Record<string, string> = {
    critical: 'bg-red-500/20 text-red-400 border-red-500/30',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    low: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium border ${map[severity] ?? 'bg-gray-500/20 text-gray-400 border-gray-500/30'}`}>
      {severity}
    </span>
  )
}

function StatusBadge({ status }: { status: string }) {
  const map: Record<string, string> = {
    open: 'bg-red-500/20 text-red-400 border-red-500/30',
    investigating: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
    resolved: 'bg-green-500/20 text-green-400 border-green-500/30',
  }
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium border ${map[status] ?? 'bg-gray-500/20 text-gray-400 border-gray-500/30'}`}>
      {status}
    </span>
  )
}

export default function XDRPage() {
  const queryClient = useQueryClient()
  const [activeTab, setActiveTab] = useState<'incidents' | 'events'>('incidents')
  const [correlateMsg, setCorrelateMsg] = useState<{ ok: boolean; text: string } | null>(null)

  const EMPTY_STATS = { buffered_events: 0, rules: 0, domain_counts: {} }

  const { data: stats = EMPTY_STATS } = useQuery({
    queryKey: ['xdr-stats'],
    queryFn: () => apiFetch('/api/v1/admin/xdr/stats'),
    refetchInterval: 30000,
  })

  const { data: incidentsData, isLoading: loadingIncidents } = useQuery({
    queryKey: ['xdr-incidents'],
    queryFn: () => apiFetch('/api/v1/admin/xdr/correlate', { method: 'POST' }),
    refetchInterval: 60000,
  })

  const { data: eventsData = { events: [] } } = useQuery({
    queryKey: ['xdr-events'],
    queryFn: () => apiFetch('/api/v1/admin/xdr/events?limit=50'),
    refetchInterval: 15000,
  })

  const correlateMutation = useMutation({
    mutationFn: () =>
      apiFetch<{ incidents: { id: string }[]; count: number }>('/api/v1/admin/xdr/correlate', { method: 'POST' })
        .catch(() => ({ incidents: [], count: 0 })),
    onSuccess: (data) => {
      queryClient.setQueryData(['xdr-incidents'], data)
      const count = (data as { incidents: any[] }).incidents?.length ?? 0
      setCorrelateMsg({ ok: true, text: `相関分析完了 — ${count} 件のインシデントを検出` })
      setTimeout(() => setCorrelateMsg(null), 4000)
    },
    onError: () => {
      setCorrelateMsg({ ok: false, text: '相関分析に失敗しました' })
      setTimeout(() => setCorrelateMsg(null), 4000)
    },
  })

  const s = (stats || EMPTY_STATS) as typeof EMPTY_STATS
  const incidents = ((incidentsData || { incidents: [] }) as { incidents: any[] }).incidents || []
  const events = ((eventsData || { events: [] }) as { events: any[] }).events || []
  const domainCounts = (s.domain_counts || {}) as Record<string, number>

  return (
    <div className="p-6 space-y-6">
      <PageDataUnavailable />
      <PageSaveFailed />
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <Globe className="w-7 h-7 text-purple-400" />
            XDR — クロスドメイン検知
          </h1>
          <p className="text-gray-400 text-sm mt-1">エンドポイント・ネットワーク・クラウド・IDの横断的相関分析</p>
        </div>
        <div className="flex items-center gap-3">
          {correlateMsg && (
            <span className={`text-xs px-3 py-1.5 rounded-lg border ${correlateMsg.ok ? 'bg-green-900/30 text-green-400 border-green-700/40' : 'bg-red-900/30 text-red-400 border-red-700/40'}`}>
              {correlateMsg.text}
            </span>
          )}
          <button
            onClick={() => correlateMutation.mutate()}
            disabled={correlateMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 bg-purple-600 hover:bg-purple-700 text-white rounded-lg text-sm transition-colors disabled:opacity-50"
          >
            {correlateMutation.isPending
              ? <><RefreshCw className="w-4 h-4 animate-spin" /> 分析中...</>
              : <><Play className="w-4 h-4" /> 相関分析実行</>
            }
          </button>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
        {Object.entries(domainCounts).map(([domain, count]) => (
          <div key={domain} className="bg-gray-800 rounded-xl p-4 border border-gray-700">
            <div className={`inline-flex items-center gap-1.5 px-2 py-1 rounded-lg text-xs font-medium border mb-3 ${DOMAIN_COLORS[domain] || 'bg-gray-700 text-gray-400 border-gray-600'}`}>
              {DOMAIN_ICONS[domain]}
              {domain.charAt(0).toUpperCase() + domain.slice(1)}
            </div>
            <div className="text-2xl font-bold text-white">{(count as number).toLocaleString()}</div>
            <div className="text-xs text-gray-400">イベント数</div>
          </div>
        ))}
        <div className="bg-gray-800 rounded-xl p-4 border border-gray-700">
          <div className="inline-flex items-center gap-1.5 px-2 py-1 rounded-lg text-xs font-medium border mb-3 bg-red-500/20 text-red-400 border-red-500/30">
            <AlertTriangle className="w-4 h-4" />
            インシデント
          </div>
          <div className="text-2xl font-bold text-white">{incidents.length}</div>
          <div className="text-xs text-gray-400">検出数</div>
        </div>
      </div>

      {/* Domain Coverage Visualization */}
      <div className="bg-gray-800 rounded-xl p-5 border border-gray-700">
        <h2 className="text-sm font-semibold text-gray-300 mb-4">ドメインカバレッジ</h2>
        <div className="flex items-center justify-center gap-4 flex-wrap">
          {['endpoint', 'network', 'cloud', 'identity', 'email'].map((domain) => {
            const count = domainCounts[domain] || 0
            const active = count > 0
            return (
              <div key={domain} className={`flex flex-col items-center gap-2 p-4 rounded-xl border transition-all ${active ? `border-gray-600 bg-gray-700/50 ${DOMAIN_COLORS[domain]}` : 'border-gray-700 bg-gray-700/20 text-gray-600'}`}>
                <div className="w-10 h-10 rounded-full bg-gray-700 flex items-center justify-center">
                  {DOMAIN_ICONS[domain]}
                </div>
                <span className="text-xs font-medium capitalize">{domain}</span>
                <span className="text-xs opacity-75">{active ? `${count} events` : 'inactive'}</span>
              </div>
            )
          })}
          <div className="flex items-center text-purple-400">
            <ChevronRight className="w-6 h-6" />
            <Shield className="w-8 h-8 mx-1" />
            <ChevronRight className="w-6 h-6 rotate-180" />
          </div>
          <div className="flex flex-col items-center gap-2 p-4 rounded-xl border border-purple-500/30 bg-purple-500/10 text-purple-400">
            <div className="w-10 h-10 rounded-full bg-purple-500/20 flex items-center justify-center">
              <Shield className="w-5 h-5" />
            </div>
            <span className="text-xs font-medium">XDR Engine</span>
            <span className="text-xs opacity-75">{s.rules} rules</span>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
        <div className="flex border-b border-gray-700">
          {(['incidents', 'events'] as const).map((tab) => (
            <button
              key={tab}
              onClick={() => setActiveTab(tab)}
              className={`px-5 py-3 text-sm font-medium transition-colors ${activeTab === tab ? 'text-white border-b-2 border-purple-500 bg-gray-700/50' : 'text-gray-400 hover:text-white'}`}
            >
              {tab === 'incidents' ? `インシデント (${incidents.length})` : `イベント (${events.length})`}
            </button>
          ))}
        </div>

        <div className="p-4">
          {activeTab === 'incidents' && (
            <div className="space-y-3">
              {incidents.length === 0 ? (
                <div className="text-center py-8 text-gray-500">検出されたインシデントはありません</div>
              ) : incidents.map((inc: any) => (
                <div key={inc.id} className="bg-gray-700/50 rounded-lg p-4 border border-gray-600/50 hover:border-gray-500 transition-colors">
                  <div className="flex items-start justify-between mb-2">
                    <div className="flex items-center gap-2">
                      <AlertTriangle className="w-4 h-4 text-orange-400 shrink-0" />
                      <span className="text-sm font-semibold text-white">{inc.title}</span>
                    </div>
                    <div className="flex items-center gap-2">
                      <SeverityBadge severity={inc.severity} />
                      <StatusBadge status={inc.status} />
                    </div>
                  </div>
                  <p className="text-xs text-gray-400 mb-3">{inc.description}</p>
                  <div className="flex items-center gap-3 flex-wrap">
                    <div className="flex items-center gap-1">
                      {(inc.domains || []).map((d: string) => (
                        <span key={d} className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border ${DOMAIN_COLORS[d] || 'bg-gray-600 text-gray-300 border-gray-500'}`}>
                          {DOMAIN_ICONS[d]}
                          {d}
                        </span>
                      ))}
                    </div>
                    <span className="text-xs text-gray-500">信頼度: {inc.confidence}%</span>
                    <div className="flex gap-1 flex-wrap ml-auto">
                      {(inc.attack_tactics || []).map((t: string) => (
                        <span key={t} className="text-xs px-1.5 py-0.5 bg-red-500/10 text-red-400 rounded-sm">
                          {t}
                        </span>
                      ))}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}

          {activeTab === 'events' && (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-gray-400 border-b border-gray-700">
                    <th className="text-left py-2 pr-4">ドメイン</th>
                    <th className="text-left py-2 pr-4">タイプ</th>
                    <th className="text-left py-2 pr-4">深刻度</th>
                    <th className="text-left py-2 pr-4">詳細</th>
                    <th className="text-left py-2">時刻</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-gray-700/50">
                  {events.map((evt: any) => (
                    <tr key={evt.id} className="hover:bg-gray-700/30 transition-colors">
                      <td className="py-2 pr-4">
                        <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full border ${DOMAIN_COLORS[evt.domain] || 'bg-gray-600 text-gray-300 border-gray-500'}`}>
                          {DOMAIN_ICONS[evt.domain]}
                          {evt.domain}
                        </span>
                      </td>
                      <td className="py-2 pr-4 text-gray-300">{evt.type}</td>
                      <td className="py-2 pr-4"><SeverityBadge severity={evt.severity} /></td>
                      <td className="py-2 pr-4 text-gray-400 text-xs max-w-xs truncate">
                        {Object.entries(evt.data || {}).map(([k, v]) => `${k}: ${v}`).join(', ')}
                      </td>
                      <td className="py-2 text-gray-500 text-xs">
                        {new Date(evt.timestamp).toLocaleTimeString('ja-JP')}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}
