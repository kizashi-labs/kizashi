'use client'

import { useState, useEffect, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Network, CheckCircle, XCircle, AlertTriangle, RefreshCw,
  Plus, X, Clock, Activity, ArrowRight, Zap, ChevronDown,
  BarChart2, Database, Settings, Trash2,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ──────────────────────────────────────────────────────────────────

type IntegrationStatus = 'connected' | 'disconnected' | 'error' | 'degraded'
type IntegrationCategory = 'SIEM' | 'ITSM' | 'EDR' | 'Email' | 'Cloud' | 'Comms' | 'TI'

interface Integration {
  id: string
  name: string
  category: IntegrationCategory
  status: IntegrationStatus
  last_ping: string
  events_per_day: number
  description: string
  config: Record<string, string>
}

interface RoutingRule {
  id: string
  event_type: string
  condition: string
  target_integration: string
  action: string
  enabled: boolean
}

interface IntegrationLog {
  id: string
  timestamp: string
  integration_id: string
  integration_name: string
  event_type: string
  status: 'success' | 'failure'
  message: string
}

interface NatsStats {
  messages_per_sec: number
  pending_messages: number
  consumers: number
  stream_size_mb: number
}

// ── Helpers ────────────────────────────────────────────────────────────────

const STATUS_STYLE: Record<IntegrationStatus, { badge: string; dot: string; label: string }> = {
  connected: { badge: 'bg-green-900/30 text-green-400 border border-green-700/40', dot: 'bg-green-400', label: '接続中' },
  disconnected: { badge: 'bg-[#1e2d42] text-[#7d92b0]', dot: 'bg-[#3d5068]', label: '未接続' },
  error: { badge: 'bg-[#e8002d]/20 text-[#ff4d6d] border border-[#e8002d]/40', dot: 'bg-[#e8002d]', label: 'エラー' },
  degraded: { badge: 'bg-yellow-900/30 text-yellow-400 border border-yellow-700/40', dot: 'bg-yellow-400', label: '低下' },
}

const CATEGORY_COLOR: Record<IntegrationCategory, string> = {
  SIEM: 'text-blue-400 bg-blue-900/20 border-blue-700/30',
  ITSM: 'text-purple-400 bg-purple-900/20 border-purple-700/30',
  EDR: 'text-[#e8002d] bg-[#e8002d]/10 border-[#e8002d]/30',
  Email: 'text-orange-400 bg-orange-900/20 border-orange-700/30',
  Cloud: 'text-cyan-400 bg-cyan-900/20 border-cyan-700/30',
  Comms: 'text-green-400 bg-green-900/20 border-green-700/30',
  TI: 'text-yellow-400 bg-yellow-900/20 border-yellow-700/30',
}

function fmt(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function fmtNum(n: number) {
  return n >= 1000 ? `${(n / 1000).toFixed(1)}K` : String(n)
}

// ── Config Modal ───────────────────────────────────────────────────────────

function ConfigModal({ integration, onClose }: { integration: Integration; onClose: () => void }) {
  const [fields, setFields] = useState({ ...integration.config })
  const [saved, setSaved] = useState(false)

  const handleSave = () => {
    setSaved(true)
    setTimeout(() => { setSaved(false); onClose() }, 1500)
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <div>
            <h3 className="text-white font-semibold">{integration.name}</h3>
            <p className="text-[#7d92b0] text-xs mt-0.5">{integration.description}</p>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          <div className="flex items-center gap-3">
            <span className={`text-xs px-2 py-0.5 rounded-sm ${STATUS_STYLE[integration.status].badge}`}>
              {STATUS_STYLE[integration.status].label}
            </span>
            <span className="text-[#7d92b0] text-xs">最終確認: {fmt(integration.last_ping)}</span>
            <span className="text-[#7d92b0] text-xs ml-auto">{fmtNum(integration.events_per_day)} events/day</span>
          </div>
          {Object.entries(fields).map(([key, value]) => (
            <div key={key}>
              <label className="text-[#7d92b0] text-xs font-medium block mb-1">{key}</label>
              <input
                value={value}
                onChange={e => setFields(prev => ({ ...prev, [key]: e.target.value }))}
                className="w-full bg-[#161f33] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 font-mono"
              />
            </div>
          ))}
        </div>
        <div className="flex justify-end gap-2 px-5 pb-4">
          <button onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white transition-colors">
            キャンセル
          </button>
          <button
            onClick={handleSave}
            className={`px-4 py-2 text-sm rounded-sm font-medium transition-colors ${saved ? 'bg-green-700 text-white' : 'bg-[#e8002d] text-white hover:bg-[#c4001f]'}`}
          >
            {saved ? '保存しました' : '設定を保存'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Add Routing Rule Modal ─────────────────────────────────────────────────

function AddRuleModal({ integrations, onClose, onAdd }: {
  integrations: Integration[]
  onClose: () => void
  onAdd: (rule: Omit<RoutingRule, 'id'>) => void
}) {
  const [form, setForm] = useState({
    event_type: 'alert.critical',
    condition: 'always',
    target_integration: integrations[0]?.name ?? '',
    action: 'create_ticket',
    enabled: true,
  })

  const EVENT_TYPES = ['alert.critical', 'alert.high', 'alert.*', 'endpoint.compromised', 'ioc.match', 'malware.detected', 'user.anomaly', 'login.failed', 'network.anomaly']
  const ACTIONS = ['create_ticket', 'create_incident', 'send_notification', 'forward_event', 'enrich_hash', 'block_ip', 'isolate_endpoint']

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold">ルーティングルールを追加</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          {[
            { label: 'イベントタイプ', key: 'event_type', type: 'select', options: EVENT_TYPES },
            { label: '条件', key: 'condition', type: 'text' },
            { label: '対象インテグレーション', key: 'target_integration', type: 'select', options: integrations.map(i => i.name) },
            { label: 'アクション', key: 'action', type: 'select', options: ACTIONS },
          ].map(f => (
            <div key={f.key}>
              <label className="text-[#7d92b0] text-xs font-medium block mb-1">{f.label}</label>
              {f.type === 'select' ? (
                <select
                  value={form[f.key as keyof typeof form] as string}
                  onChange={e => setForm(prev => ({ ...prev, [f.key]: e.target.value }))}
                  className="w-full bg-[#161f33] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50"
                >
                  {f.options?.map(o => <option key={o} value={o}>{o}</option>)}
                </select>
              ) : (
                <input
                  value={form[f.key as keyof typeof form] as string}
                  onChange={e => setForm(prev => ({ ...prev, [f.key]: e.target.value }))}
                  className="w-full bg-[#161f33] border border-[#1e2d42] rounded-sm px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50"
                />
              )}
            </div>
          ))}
        </div>
        <div className="flex justify-end gap-2 px-5 pb-4">
          <button onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => { onAdd(form); onClose() }}
            className="px-4 py-2 text-sm rounded-sm font-medium bg-[#e8002d] text-white hover:bg-[#c4001f] transition-colors"
          >
            追加
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function OrchestrationPage() {
  const [selectedIntegration, setSelectedIntegration] = useState<Integration | null>(null)
  const [showAddRule, setShowAddRule] = useState(false)
  const [rules, setRules] = useState<RoutingRule[]>([])
  const [testResults, setTestResults] = useState<Record<string, 'pending' | 'success' | 'failure' | null>>({})
  const [testing, setTesting] = useState(false)
  const [filterCategory, setFilterCategory] = useState<IntegrationCategory | 'ALL'>('ALL')
  const queryClient = useQueryClient()

  const { data, isLoading } = useQuery<Integration[]>({
    queryKey: ['integrations'],
    queryFn: () => apiFetch('/api/v1/admin/integrations'),
    staleTime: 60_000,
    retry: false,
    throwOnError: false,
  })

  const integrations: Integration[] = data ?? []

  const { data: natsData } = useQuery<NatsStats>({
    queryKey: ['nats-stats'],
    queryFn: () => apiFetch('/api/v1/admin/nats/stats'),
    refetchInterval: 10_000,
    staleTime: 5_000,
    retry: false,
    throwOnError: false,
  })

  const EMPTY_NATS: NatsStats = { messages_per_sec: 0, pending_messages: 0, consumers: 0, stream_size_mb: 0 }
  const nats: NatsStats = natsData ?? EMPTY_NATS

  const handleTestAll = async () => {
    setTesting(true)
    const results: Record<string, 'pending' | 'success' | 'failure' | null> = {}
    for (const intg of integrations) {
      results[intg.id] = 'pending'
      setTestResults({ ...results })
      await new Promise(r => setTimeout(r, 300 + Math.random() * 400))
      results[intg.id] = intg.status === 'connected' ? 'success' : 'failure'
      setTestResults({ ...results })
    }
    setTesting(false)
  }

  const filtered = filterCategory === 'ALL' ? integrations : integrations.filter(i => i.category === filterCategory)
  const connectedCount = integrations.filter(i => i.status === 'connected').length
  const categories: IntegrationCategory[] = ['SIEM', 'ITSM', 'EDR', 'Email', 'Cloud', 'Comms', 'TI']

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-blue-900/30 border border-blue-700/40 flex items-center justify-center">
            <Network className="w-5 h-5 text-blue-400" />
          </div>
          <div>
            <h1 className="text-white text-xl font-bold">セキュリティオーケストレーション</h1>
            <p className="text-[#7d92b0] text-sm mt-0.5">Security Orchestration Hub — Integration Management</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={handleTestAll}
            disabled={testing}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] text-xs rounded-sm hover:border-[#2a3f5c] hover:text-white transition-colors disabled:opacity-50"
          >
            <Activity className={`w-3.5 h-3.5 ${testing ? 'animate-pulse' : ''}`} />
            全統合をテスト
          </button>
          <button
            onClick={() => queryClient.invalidateQueries({ queryKey: ['integrations'] })}
            className="flex items-center gap-1.5 px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] text-xs rounded-sm hover:border-[#2a3f5c] hover:text-white transition-colors"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isLoading ? 'animate-spin' : ''}`} />
            更新
          </button>
        </div>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <p className="text-[#7d92b0] text-xs">接続中の統合</p>
          <div className="flex items-baseline gap-1 mt-1">
            <span className="text-2xl font-bold text-green-400">{connectedCount}</span>
            <span className="text-[#7d92b0] text-xs">/ {integrations.length}</span>
          </div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <p className="text-[#7d92b0] text-xs">NATS メッセージ/秒</p>
          <p className="text-2xl font-bold text-blue-400 mt-1">{fmtNum(nats.messages_per_sec)}</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <p className="text-[#7d92b0] text-xs">保留中メッセージ</p>
          <p className={`text-2xl font-bold mt-1 ${nats.pending_messages > 1000 ? 'text-orange-400' : 'text-white'}`}>{fmtNum(nats.pending_messages)}</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <p className="text-[#7d92b0] text-xs">ルーティングルール</p>
          <p className="text-2xl font-bold text-white mt-1">{rules.filter(r => r.enabled).length}<span className="text-[#7d92b0] text-sm font-normal"> 有効</span></p>
        </div>
      </div>

      <div className="grid grid-cols-1 xl:grid-cols-3 gap-6">
        <div className="xl:col-span-2 space-y-6">
          {/* Integration Health Grid */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-white font-semibold text-sm">インテグレーション ヘルス</h2>
              <div className="flex gap-1 flex-wrap">
                <button
                  onClick={() => setFilterCategory('ALL')}
                  className={`px-2 py-1 text-xs rounded-sm transition-colors ${filterCategory === 'ALL' ? 'bg-[#1d2f4a] text-white' : 'text-[#7d92b0] hover:text-white'}`}
                >
                  ALL
                </button>
                {categories.map(cat => (
                  <button
                    key={cat}
                    onClick={() => setFilterCategory(cat)}
                    className={`px-2 py-1 text-xs rounded-sm transition-colors ${filterCategory === cat ? 'bg-[#1d2f4a] text-white' : 'text-[#7d92b0] hover:text-white'}`}
                  >
                    {cat}
                  </button>
                ))}
              </div>
            </div>

            <div className="grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 gap-3">
              {filtered.map(intg => {
                const st = STATUS_STYLE[intg.status]
                const testResult = testResults[intg.id]
                return (
                  <button
                    key={intg.id}
                    onClick={() => setSelectedIntegration(intg)}
                    className="bg-[#161f33] border border-[#1e2d42] rounded-lg p-3 text-left hover:border-[#2a3f5c] transition-all relative"
                  >
                    {/* Category badge */}
                    <div className={`inline-block text-[10px] px-1.5 py-0.5 rounded-sm border mb-2 font-medium ${CATEGORY_COLOR[intg.category]}`}>
                      {intg.category}
                    </div>
                    {/* Service name logo placeholder */}
                    <div className="w-8 h-8 rounded-sm bg-[#1e2d42] flex items-center justify-center mb-2 text-[10px] font-bold text-[#7d92b0]">
                      {intg.name.slice(0, 2).toUpperCase()}
                    </div>
                    <p className="text-white text-xs font-medium leading-tight">{intg.name}</p>
                    <div className="flex items-center gap-1 mt-1.5">
                      <span className={`w-1.5 h-1.5 rounded-full ${st.dot} ${intg.status === 'connected' ? 'animate-pulse' : ''}`} />
                      <span className={`text-[10px] px-1.5 py-0.5 rounded-sm ${st.badge}`}>{st.label}</span>
                    </div>
                    <p className="text-[#3d5068] text-[10px] mt-1">{fmt(intg.last_ping)}</p>
                    <p className="text-[#7d92b0] text-[10px]">{fmtNum(intg.events_per_day)}/day</p>
                    {/* Test result overlay */}
                    {testResult && (
                      <div className={`absolute top-2 right-2 w-4 h-4 rounded-full flex items-center justify-center ${testResult === 'pending' ? 'bg-yellow-900/50' : testResult === 'success' ? 'bg-green-900/50' : 'bg-[#e8002d]/20'}`}>
                        {testResult === 'pending' ? <RefreshCw className="w-2.5 h-2.5 text-yellow-400 animate-spin" />
                          : testResult === 'success' ? <CheckCircle className="w-2.5 h-2.5 text-green-400" />
                          : <XCircle className="w-2.5 h-2.5 text-[#ff4d6d]" />}
                      </div>
                    )}
                  </button>
                )
              })}
            </div>
          </div>

          {/* Data Flow Visualization */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <h2 className="text-white font-semibold text-sm mb-4">データフロー</h2>
            <div className="relative min-h-[280px] flex items-center justify-center">
              {/* Center */}
              <div className="absolute inset-0 flex items-center justify-center">
                <div className="w-32 h-16 bg-[#1d2f4a] border-2 border-[#e8002d]/60 rounded-xl flex flex-col items-center justify-center shadow-lg">
                  <Network className="w-5 h-5 text-[#e8002d] mb-1" />
                  <span className="text-white text-[10px] font-bold">EDR Platform</span>
                </div>
              </div>

              {/* Left: Data Sources */}
              <div className="absolute left-0 top-1/2 -translate-y-1/2">
                <div className="w-24 bg-[#161f33] border border-[#1e2d42] rounded-lg p-2 text-center">
                  <Database className="w-4 h-4 text-blue-400 mx-auto mb-1" />
                  <p className="text-white text-[10px] font-medium">Data Sources</p>
                  <p className="text-[#7d92b0] text-[9px]">Endpoints, Logs, Cloud</p>
                </div>
              </div>
              {/* Left arrow */}
              <div className="absolute left-[100px] top-1/2 -translate-y-1/2 flex items-center">
                <div className="w-16 h-0.5 bg-linear-to-r from-blue-400/50 to-[#1e2d42] relative overflow-hidden">
                  <div className="absolute w-2 h-2 rounded-full bg-blue-400 top-1/2 -translate-y-1/2 animate-[moveRight_2s_linear_infinite]" style={{ left: '0%', animation: 'flow-right 2s linear infinite' }} />
                </div>
                <ArrowRight className="w-3 h-3 text-blue-400 -ml-1" />
              </div>

              {/* Top: Detection */}
              <div className="absolute top-0 left-1/2 -translate-x-1/2">
                <div className="w-24 bg-[#161f33] border border-[#1e2d42] rounded-lg p-2 text-center">
                  <Zap className="w-4 h-4 text-yellow-400 mx-auto mb-1" />
                  <p className="text-white text-[10px] font-medium">Detection</p>
                  <p className="text-[#7d92b0] text-[9px]">SIEM, Rules, ML</p>
                </div>
              </div>
              {/* Top arrow */}
              <div className="absolute left-1/2 -translate-x-1/2 top-[72px] flex flex-col items-center">
                <div className="w-0.5 h-12 bg-linear-to-b from-yellow-400/50 to-[#1e2d42] relative">
                  <div className="absolute w-2 h-2 rounded-full bg-yellow-400 left-1/2 -translate-x-1/2" style={{ top: '0%', animation: 'flow-down 2s linear infinite 0.5s' }} />
                </div>
                <ArrowRight className="w-3 h-3 text-yellow-400 rotate-90" />
              </div>

              {/* Right: Response */}
              <div className="absolute right-0 top-1/2 -translate-y-1/2">
                <div className="w-24 bg-[#161f33] border border-[#1e2d42] rounded-lg p-2 text-center">
                  <Settings className="w-4 h-4 text-orange-400 mx-auto mb-1" />
                  <p className="text-white text-[10px] font-medium">Response</p>
                  <p className="text-[#7d92b0] text-[9px]">SOAR, Playbooks</p>
                </div>
              </div>
              {/* Right arrow */}
              <div className="absolute right-[100px] top-1/2 -translate-y-1/2 flex items-center">
                <ArrowRight className="w-3 h-3 text-orange-400 -mr-1" />
                <div className="w-16 h-0.5 bg-linear-to-r from-[#1e2d42] to-orange-400/50 relative overflow-hidden">
                  <div className="absolute w-2 h-2 rounded-full bg-orange-400 top-1/2 -translate-y-1/2" style={{ right: '0%', animation: 'flow-right 2s linear infinite 1s' }} />
                </div>
              </div>

              {/* Bottom: Reporting */}
              <div className="absolute bottom-0 left-1/2 -translate-x-1/2">
                <div className="w-24 bg-[#161f33] border border-[#1e2d42] rounded-lg p-2 text-center">
                  <BarChart2 className="w-4 h-4 text-green-400 mx-auto mb-1" />
                  <p className="text-white text-[10px] font-medium">Reporting</p>
                  <p className="text-[#7d92b0] text-[9px]">Dashboards, API</p>
                </div>
              </div>
              {/* Bottom arrow */}
              <div className="absolute left-1/2 -translate-x-1/2 bottom-[72px] flex flex-col items-center">
                <ArrowRight className="w-3 h-3 text-green-400 -rotate-90" />
                <div className="w-0.5 h-12 bg-linear-to-t from-green-400/50 to-[#1e2d42]" />
              </div>
            </div>
            <style>{`
              @keyframes flow-right { 0% { left: 0% } 100% { left: 100% } }
              @keyframes flow-down  { 0% { top:  0% } 100% { top:  100% } }
            `}</style>
          </div>

          {/* NATS Stats */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <h2 className="text-white font-semibold text-sm mb-3 flex items-center gap-2">
              <Activity className="w-4 h-4 text-blue-400" />
              NATS JetStream 統計
            </h2>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              {[
                { label: 'メッセージ/秒', value: fmtNum(nats.messages_per_sec), color: 'text-blue-400' },
                { label: 'ペンディング', value: fmtNum(nats.pending_messages), color: nats.pending_messages > 1000 ? 'text-orange-400' : 'text-white' },
                { label: 'コンシューマ', value: String(nats.consumers), color: 'text-green-400' },
                { label: 'ストリームサイズ', value: `${nats.stream_size_mb} MB`, color: 'text-purple-400' },
              ].map(s => (
                <div key={s.label} className="bg-[#161f33] border border-[#1e2d42] rounded-lg p-3">
                  <p className="text-[#7d92b0] text-xs">{s.label}</p>
                  <p className={`text-xl font-bold mt-1 ${s.color}`}>{s.value}</p>
                </div>
              ))}
            </div>
          </div>

          {/* Event Routing Rules */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-white font-semibold text-sm">イベント ルーティングルール</h2>
              <button
                onClick={() => setShowAddRule(true)}
                className="flex items-center gap-1 px-2 py-1 bg-[#e8002d] text-white text-xs rounded-sm hover:bg-[#c4001f] transition-colors"
              >
                <Plus className="w-3 h-3" />
                追加
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['イベントタイプ', '条件', '対象', 'アクション', '状態', '操作'].map(h => (
                      <th key={h} className="text-left py-2 px-3 text-[#7d92b0] font-medium">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {rules.map(rule => (
                    <tr key={rule.id} className="border-b border-[#1e2d42]/50 hover:bg-[#161f33] transition-colors">
                      <td className="py-2 px-3 font-mono text-[#e8002d]">{rule.event_type}</td>
                      <td className="py-2 px-3 font-mono text-[#7d92b0] max-w-[120px] truncate">{rule.condition}</td>
                      <td className="py-2 px-3 text-white">{rule.target_integration}</td>
                      <td className="py-2 px-3 text-[#7d92b0] font-mono">{rule.action}</td>
                      <td className="py-2 px-3">
                        <button
                          onClick={() => setRules(prev => prev.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r))}
                          className={`px-2 py-0.5 rounded-sm text-xs ${rule.enabled ? 'bg-green-900/30 text-green-400 border border-green-700/40' : 'bg-[#1e2d42] text-[#7d92b0]'}`}
                        >
                          {rule.enabled ? '有効' : '無効'}
                        </button>
                      </td>
                      <td className="py-2 px-3">
                        <button
                          onClick={() => setRules(prev => prev.filter(r => r.id !== rule.id))}
                          className="text-[#3d5068] hover:text-[#ff4d6d] transition-colors"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>
        </div>

        {/* Integration Logs */}
        <div className="space-y-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
            <h2 className="text-white font-semibold text-sm mb-3 flex items-center gap-2">
              <Clock className="w-4 h-4 text-[#7d92b0]" />
              インテグレーションログ
            </h2>
            <div className="space-y-2">
              {([] as { id: string; status: string; integration_name: string; action: string; timestamp: string; message: string; event_type: string }[]).map(log => (
                <div key={log.id} className="border border-[#1e2d42] rounded-lg p-2.5 hover:border-[#2a3f5c] transition-colors">
                  <div className="flex items-center gap-2">
                    {log.status === 'success'
                      ? <CheckCircle className="w-3.5 h-3.5 text-green-400 shrink-0" />
                      : <XCircle className="w-3.5 h-3.5 text-[#ff4d6d] shrink-0" />}
                    <span className="text-white text-xs font-medium truncate">{log.integration_name}</span>
                    <span className="text-[#3d5068] text-[10px] ml-auto font-mono">{fmt(log.timestamp)}</span>
                  </div>
                  <p className="text-[#7d92b0] text-[11px] mt-1 ml-5">{log.message}</p>
                  <p className="text-[#3d5068] text-[10px] ml-5 mt-0.5 font-mono">{log.event_type}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>

      {/* Modals */}
      {selectedIntegration && (
        <ConfigModal integration={selectedIntegration} onClose={() => setSelectedIntegration(null)} />
      )}
      {showAddRule && (
        <AddRuleModal
          integrations={integrations}
          onClose={() => setShowAddRule(false)}
          onAdd={rule => setRules(prev => [...prev, { ...rule, id: `r${Date.now()}` }])}
        />
      )}
    </div>
  )
}
