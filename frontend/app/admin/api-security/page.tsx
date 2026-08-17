'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { Lock, Loader2, CheckCircle, XCircle } from 'lucide-react'
// ── Types ──────────────────────────────────────────────────────────────────────

type HttpMethod = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
type RiskLevel = 'low' | 'medium' | 'high' | 'critical'
type EventType = 'auth_failure' | 'rate_limit' | 'injection' | 'anomaly' | 'scraping'

interface ApiSecurityStats {
  total_endpoints: number
  high_risk_endpoints: number
  events_24h: number
  auth_failures_24h: number
  rate_limited_24h: number
}

interface ApiEndpoint {
  id: string
  service: string
  method: HttpMethod
  path: string
  auth_required: boolean
  rate_limit: string
  risk_level: RiskLevel
  enabled: boolean
}

interface SecurityEvent {
  id: string
  service: string
  path: string
  event_type: EventType
  source_ip: string
  status_code: number
  risk_score: number
  timestamp: string
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const METHOD_CONFIG: Record<HttpMethod, string> = {
  GET:    'bg-blue-500/20 text-blue-300 border-blue-500/30',
  POST:   'bg-green-500/20 text-green-300 border-green-500/30',
  PUT:    'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
  PATCH:  'bg-orange-500/20 text-orange-300 border-orange-500/30',
  DELETE: 'bg-red-500/20 text-red-300 border-red-500/30',
}

const RISK_CONFIG: Record<RiskLevel, { label: string; cls: string }> = {
  low:      { label: '低',  cls: 'bg-green-500/15 text-green-300 border-green-500/30'    },
  medium:   { label: '中',  cls: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30' },
  high:     { label: '高',  cls: 'bg-orange-500/15 text-orange-300 border-orange-500/30' },
  critical: { label: '重大', cls: 'bg-red-500/15 text-red-300 border-red-500/30'           },
}

const EVENT_TYPE_CONFIG: Record<EventType, { label: string; cls: string }> = {
  auth_failure: { label: '認証失敗',        cls: 'bg-red-500/15 text-red-300 border-red-500/30'          },
  rate_limit:   { label: 'レート制限',      cls: 'bg-orange-500/15 text-orange-300 border-orange-500/30' },
  injection:    { label: 'インジェクション', cls: 'bg-red-600/15 text-red-400 border-red-600/30'           },
  anomaly:      { label: '異常',            cls: 'bg-yellow-500/15 text-yellow-300 border-yellow-500/30'  },
  scraping:     { label: 'スクレイピング',  cls: 'bg-blue-500/15 text-blue-300 border-blue-500/30'        },
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function RiskScoreBar({ score }: { score: number }) {
  const color = score >= 80 ? 'bg-red-500' : score >= 60 ? 'bg-orange-500' : score >= 40 ? 'bg-yellow-500' : 'bg-green-500'
  const textColor = score >= 80 ? 'text-red-400' : score >= 60 ? 'text-orange-400' : score >= 40 ? 'text-yellow-400' : 'text-green-400'
  return (
    <div className="flex items-center gap-2">
      <div className="w-20 h-2 bg-falcon-border rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color} transition-all`} style={{ width: `${score}%` }} />
      </div>
      <span className={`text-xs font-mono font-semibold ${textColor}`}>{score}</span>
    </div>
  )
}

// ── Page ──────────────────────────────────────────────────────────────────────

export default function ApiSecurityPage() {
  const [activeTab, setActiveTab] = useState<'endpoints' | 'events'>('endpoints')
  const [eventTypeFilter, setEventTypeFilter] = useState<EventType | 'all'>('all')

  const { data: stats, isLoading: statsLoading } = useQuery<ApiSecurityStats>({
    queryKey: ['api-security-stats'],
    queryFn: async () => {
      try { return await apiFetch('/api/v1/admin/api-security/stats') }
      catch { return {} as any }
    },
  })

  const { data: endpoints = [], isLoading: endpointsLoading } = useQuery<ApiEndpoint[]>({
    queryKey: ['api-security-endpoints'],
    queryFn: async () => {
      try { return await apiFetch('/api/v1/admin/api-security/endpoints') }
      catch { return [] }
    },
  })

  const { data: events = [], isLoading: eventsLoading } = useQuery<SecurityEvent[]>({
    queryKey: ['api-security-events', eventTypeFilter],
    queryFn: async () => {
      try {
        const params = eventTypeFilter !== 'all' ? `?event_type=${eventTypeFilter}` : ''
        return await apiFetch(`/api/v1/admin/api-security/events${params}`)
      } catch {
        return []
      }
    },
  })

  const EMPTY_STATS: ApiSecurityStats = { total_endpoints: 0, high_risk_endpoints: 0, events_24h: 0, auth_failures_24h: 0, rate_limited_24h: 0 }
  const displayStats = stats ?? EMPTY_STATS

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-lg bg-falcon-red/20 border border-falcon-red/30 flex items-center justify-center">
          <Lock className="w-5 h-5 text-falcon-red" />
        </div>
        <div>
          <h1 className="text-2xl font-bold text-white">APIセキュリティ監視</h1>
          <p className="text-sm text-falcon-muted">リアルタイムAPI脅威検知</p>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        {statsLoading
          ? Array.from({ length: 5 }).map((_, i) => (
              <div key={i} className="bg-falcon-surface border border-falcon-border rounded-xl p-4 animate-pulse">
                <div className="h-3 w-24 bg-falcon-border rounded-sm mb-3" />
                <div className="h-7 w-10 bg-falcon-border rounded-sm" />
              </div>
            ))
          : [
              { label: '総エンドポイント',     value: displayStats.total_endpoints,     color: 'text-falcon-muted'  },
              { label: '高リスク',            value: displayStats.high_risk_endpoints, color: 'text-red-400'    },
              { label: 'イベント(24h)',         value: displayStats.events_24h,          color: 'text-orange-400' },
              { label: '認証失敗(24h)',  value: displayStats.auth_failures_24h,   color: 'text-yellow-400' },
              { label: 'レート制限(24h)',   value: displayStats.rate_limited_24h,    color: 'text-blue-400'   },
            ].map(({ label, value, color }) => (
              <div key={label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
                <p className="text-xs text-falcon-muted mb-2">{label}</p>
                <p className={`text-2xl font-bold ${color}`}>{value}</p>
              </div>
            ))
        }
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-falcon-surface border border-falcon-border rounded-lg p-1 w-fit">
        {(['endpoints', 'events'] as const).map(tab => (
          <button
            key={tab}
            onClick={() => setActiveTab(tab)}
            className={`px-4 py-2 rounded-md text-sm font-medium transition-all ${
              activeTab === tab ? 'bg-falcon-border text-white' : 'text-falcon-muted hover:text-white'
            }`}
          >
            {tab === 'endpoints' ? 'APIエンドポイント' : 'セキュリティイベント'}
          </button>
        ))}
      </div>

      {/* Endpoints Tab */}
      {activeTab === 'endpoints' && (
        <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
          {endpointsLoading ? (
            <div className="flex items-center justify-center py-16 gap-2">
              <Loader2 className="w-5 h-5 text-falcon-red animate-spin" />
              <span className="text-sm text-falcon-muted">読込中...</span>
            </div>
          ) : (
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['サービス', 'メソッド', 'パス', '認証必須', 'レート制限', 'リスクレベル', '有効'].map(h => (
                    <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {endpoints.map(ep => (
                  <tr key={ep.id} className="border-b border-falcon-border/60 last:border-0 hover:bg-[#070d19]/50 transition-colors">
                    <td className="px-4 py-3 text-sm text-falcon-muted font-mono">{ep.service}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-bold ${METHOD_CONFIG[ep.method]}`}>
                        {ep.method}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-sm text-white font-mono">{ep.path}</td>
                    <td className="px-4 py-3 text-center">
                      {ep.auth_required
                        ? <CheckCircle className="w-4 h-4 text-green-400 inline" />
                        : <XCircle className="w-4 h-4 text-red-400 inline" />}
                    </td>
                    <td className="px-4 py-3 text-xs text-falcon-muted font-mono">{ep.rate_limit}</td>
                    <td className="px-4 py-3">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${RISK_CONFIG[ep.risk_level].cls}`}>
                        {RISK_CONFIG[ep.risk_level].label}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <div className={`w-8 h-4 rounded-full transition-colors ${ep.enabled ? 'bg-falcon-red' : 'bg-falcon-border'}`}>
                        <div className={`w-3 h-3 rounded-full bg-falcon-text mt-0.5 transition-transform ${ep.enabled ? 'translate-x-4' : 'translate-x-0.5'}`} />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </div>
      )}

      {/* Events Tab */}
      {activeTab === 'events' && (
        <div className="space-y-4">
          <div className="flex items-center gap-3">
            <select
              value={eventTypeFilter}
              onChange={e => setEventTypeFilter(e.target.value as EventType | 'all')}
              className="bg-falcon-surface border border-falcon-border rounded-lg px-3 py-2 text-sm text-falcon-muted focus:outline-hidden focus:border-falcon-red/50"
            >
              <option value="all">全イベントタイプ</option>
              {(Object.keys(EVENT_TYPE_CONFIG) as EventType[]).map(t => (
                <option key={t} value={t}>{EVENT_TYPE_CONFIG[t].label}</option>
              ))}
            </select>
            <span className="text-xs text-falcon-muted ml-auto">{events.length} 件</span>
          </div>

          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            {eventsLoading ? (
              <div className="flex items-center justify-center py-16 gap-2">
                <Loader2 className="w-5 h-5 text-falcon-red animate-spin" />
                <span className="text-sm text-falcon-muted">イベント読込中...</span>
              </div>
            ) : (
              <table className="w-full">
                <thead>
                  <tr className="border-b border-falcon-border">
                    {['サービス', 'パス', 'イベントタイプ', '送信元IP', 'ステータス', 'リスクスコア', 'タイムスタンプ'].map(h => (
                      <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {events.length === 0 ? (
                    <tr>
                      <td colSpan={7} className="px-4 py-10 text-center text-sm text-falcon-muted">イベントがありません。</td>
                    </tr>
                  ) : events.map(ev => (
                    <tr key={ev.id} className="border-b border-falcon-border/60 last:border-0 hover:bg-[#070d19]/50 transition-colors">
                      <td className="px-4 py-3 text-sm text-falcon-muted font-mono">{ev.service}</td>
                      <td className="px-4 py-3 text-sm text-white font-mono">{ev.path}</td>
                      <td className="px-4 py-3">
                        <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${EVENT_TYPE_CONFIG[ev.event_type].cls}`}>
                          {EVENT_TYPE_CONFIG[ev.event_type].label}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-falcon-muted font-mono">{ev.source_ip}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-mono font-semibold ${ev.status_code >= 500 ? 'text-red-400' : ev.status_code >= 400 ? 'text-orange-400' : 'text-green-400'}`}>
                          {ev.status_code}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <RiskScoreBar score={ev.risk_score} />
                      </td>
                      <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">{fmtDate(ev.timestamp)}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
          </div>
        </div>
      )}
    </div>
  )
}
