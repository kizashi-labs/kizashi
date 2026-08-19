'use client'

import { useState, useEffect, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Boxes, RefreshCw, X, ChevronRight, ChevronDown, ChevronUp,
  AlertTriangle, Shield, Activity, Server, Clock, Layers,
  Package, Tag, GitBranch, Search, Filter
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ── Types ───────────────────────────────────────────────────────

interface Vulnerability {
  cve_id: string
  severity: 'critical' | 'high' | 'medium' | 'low'
  description: string
  fixed_version: string | null
}

interface Workload {
  id: string
  name: string
  type: 'Deployment' | 'DaemonSet' | 'StatefulSet' | 'Job'
  namespace: string
  cluster: string
  image: string
  image_digest: string
  labels: Record<string, string>
  replicas_ready: number
  replicas_total: number
  risk_score: number
  vulnerability_count: number
  vulnerabilities: Vulnerability[]
  status: 'running' | 'pending' | 'failed'
  created_at: string
}

interface ContainerEvent {
  id: string
  workload_id: string
  workload_name: string
  cluster: string
  event_type: 'security' | 'runtime' | 'network' | 'policy'
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
  message: string
  details: Record<string, unknown>
  occurred_at: string
}

interface Cluster {
  id: string
  name: string
  workload_count: number
  namespace_count: number
  risk_critical: number
  risk_high: number
  risk_medium: number
  last_sync: string
}

interface ContainerStats {
  total_workloads: number
  running: number
  risk_high_count: number
  total_vulnerabilities: number
}

const EMPTY_STATS: ContainerStats = {
  total_workloads: 0,
  running: 0,
  risk_high_count: 0,
  total_vulnerabilities: 0,
}

// ── Helpers ──────────────────────────────────────────────────────

function formatRelativeTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  if (mins < 60) return `${mins}分前`
  const hours = Math.floor(mins / 60)
  if (hours < 24) return `${hours}時間前`
  return `${Math.floor(hours / 24)}日前`
}

function getRiskColor(score: number): string {
  if (score >= 80) return 'text-[#e8002d]'
  if (score >= 60) return 'text-orange-400'
  if (score >= 40) return 'text-yellow-400'
  return 'text-green-400'
}

function getRiskBgColor(score: number): string {
  if (score >= 80) return 'bg-[#e8002d]'
  if (score >= 60) return 'bg-orange-400'
  if (score >= 40) return 'bg-yellow-400'
  return 'bg-green-400'
}

function getSeverityStyle(severity: string): string {
  const map: Record<string, string> = {
    critical: 'bg-[#e8002d]/20 text-[#e8002d] border-[#e8002d]/30',
    high:     'bg-orange-500/20 text-orange-300 border-orange-500/30',
    medium:   'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
    low:      'bg-blue-500/20 text-blue-300 border-blue-500/30',
    info:     'bg-[#7d92b0]/20 text-[#7d92b0] border-[#7d92b0]/30',
  }
  return map[severity] ?? map.info
}

function getEventTypeStyle(type: string): string {
  const map: Record<string, string> = {
    security: 'bg-[#e8002d]/10 text-[#e8002d] border-[#e8002d]/20',
    runtime:  'bg-orange-500/10 text-orange-300 border-orange-500/20',
    network:  'bg-blue-500/10 text-blue-300 border-blue-500/20',
    policy:   'bg-purple-500/10 text-purple-300 border-purple-500/20',
  }
  return map[type] ?? map.security
}

function getStatusStyle(status: string): string {
  const map: Record<string, string> = {
    running: 'bg-green-500/20 text-green-300 border-green-500/30',
    pending: 'bg-yellow-500/20 text-yellow-300 border-yellow-500/30',
    failed:  'bg-[#e8002d]/20 text-[#e8002d] border-[#e8002d]/30',
  }
  return map[status] ?? ''
}

function getTypeStyle(type: string): string {
  const map: Record<string, string> = {
    Deployment:  'bg-blue-500/10 text-blue-300 border-blue-500/20',
    DaemonSet:   'bg-purple-500/10 text-purple-300 border-purple-500/20',
    StatefulSet: 'bg-teal-500/10 text-teal-300 border-teal-500/20',
    Job:         'bg-[#7d92b0]/10 text-[#7d92b0] border-[#7d92b0]/20',
  }
  return map[type] ?? ''
}

// ── Workload Detail Panel ────────────────────────────────────────

function WorkloadDetailPanel({ workload, onClose, events }: { workload: Workload; onClose: () => void; events: ContainerEvent[] }) {
  return (
    <div className="fixed inset-y-0 right-0 z-50 w-full max-w-lg bg-[#0d1220] border-l border-[#1e2d42] shadow-2xl flex flex-col">
      <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42] shrink-0">
        <div>
          <h2 className="text-white font-semibold text-base">{workload.name}</h2>
          <p className="text-xs text-[#7d92b0]">{workload.cluster} / {workload.namespace}</p>
        </div>
        <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
          <X className="w-5 h-5" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Basic Info */}
        <div className="space-y-3">
          <h3 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">基本情報</h3>
          <div className="grid grid-cols-2 gap-2 text-sm">
            <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
              <p className="text-[10px] text-[#7d92b0] mb-1">タイプ</p>
              <span className={`px-2 py-0.5 text-xs rounded-sm border ${getTypeStyle(workload.type)}`}>{workload.type}</span>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
              <p className="text-[10px] text-[#7d92b0] mb-1">ステータス</p>
              <span className={`px-2 py-0.5 text-xs rounded-sm border ${getStatusStyle(workload.status)}`}>{workload.status}</span>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
              <p className="text-[10px] text-[#7d92b0] mb-1">レプリカ</p>
              <p className="text-sm font-mono text-[#e2e8f4]">{workload.replicas_ready}/{workload.replicas_total}</p>
            </div>
            <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">
              <p className="text-[10px] text-[#7d92b0] mb-1">リスクスコア</p>
              <p className={`text-sm font-bold ${getRiskColor(workload.risk_score)}`}>{workload.risk_score}</p>
            </div>
          </div>
        </div>

        {/* Image */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">イメージ</h3>
          <div className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42] space-y-2">
            <p className="font-mono text-xs text-[#e2e8f4] break-all">{workload.image}</p>
            <p className="font-mono text-[10px] text-[#3d5068] break-all">{workload.image_digest}</p>
          </div>
        </div>

        {/* Labels */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">ラベル</h3>
          <div className="flex flex-wrap gap-1.5">
            {Object.entries(workload.labels).map(([k, v]) => (
              <span key={k} className="px-2 py-0.5 text-[10px] font-mono rounded-sm bg-[#1e2d42] text-[#7d92b0] border border-[#2a3f5a]">
                {k}={v}
              </span>
            ))}
          </div>
        </div>

        {/* Vulnerabilities */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">
            脆弱性 ({workload.vulnerabilities.length})
          </h3>
          {workload.vulnerabilities.length === 0 ? (
            <p className="text-xs text-[#7d92b0] bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">脆弱性なし</p>
          ) : (
            <div className="space-y-2">
              {workload.vulnerabilities.map(v => (
                <div key={v.cve_id} className="bg-[#070d19] rounded-lg p-3 border border-[#1e2d42] space-y-1.5">
                  <div className="flex items-center justify-between">
                    <span className="font-mono text-xs text-[#e2e8f4] font-semibold">{v.cve_id}</span>
                    <span className={`px-2 py-0.5 text-[10px] rounded-sm border uppercase font-bold ${getSeverityStyle(v.severity)}`}>
                      {v.severity}
                    </span>
                  </div>
                  <p className="text-xs text-[#7d92b0]">{v.description}</p>
                  {v.fixed_version && (
                    <p className="text-[10px] text-green-400">修正バージョン: {v.fixed_version}</p>
                  )}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Events Timeline */}
        <div className="space-y-2">
          <h3 className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">イベントタイムライン</h3>
          {events.filter(e => e.workload_id === workload.id).length === 0 ? (
            <p className="text-xs text-[#7d92b0] bg-[#070d19] rounded-lg p-3 border border-[#1e2d42]">イベントなし</p>
          ) : (
            <div className="space-y-2">
              {events.filter(e => e.workload_id === workload.id).map(ev => (
                <div key={ev.id} className="flex gap-3">
                  <div className="flex flex-col items-center">
                    <div className={`w-2 h-2 rounded-full shrink-0 mt-1 ${
                      ev.severity === 'critical' ? 'bg-[#e8002d]' :
                      ev.severity === 'high' ? 'bg-orange-400' :
                      ev.severity === 'medium' ? 'bg-yellow-400' : 'bg-blue-400'
                    }`} />
                    <div className="w-px flex-1 bg-[#1e2d42] mt-1" />
                  </div>
                  <div className="pb-3 flex-1 min-w-0">
                    <p className="text-xs text-[#e2e8f4]">{ev.message}</p>
                    <p className="text-[10px] text-[#7d92b0] mt-0.5">{formatRelativeTime(ev.occurred_at)}</p>
                  </div>
                </div>
              ))}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────

export default function ContainerMonitoringPage() {
  const [activeTab, setActiveTab] = useState<'workloads' | 'events' | 'clusters'>('workloads')
  const [selectedWorkload, setSelectedWorkload] = useState<Workload | null>(null)
  const [selectedCluster, setSelectedCluster] = useState<string | null>(null)
  const [filterCluster, setFilterCluster] = useState('')
  const [filterNamespace, setFilterNamespace] = useState('')
  const [filterStatus, setFilterStatus] = useState('')
  const [filterRisk, setFilterRisk] = useState('')
  const [filterEventSeverity, setFilterEventSeverity] = useState('')
  const [filterEventType, setFilterEventType] = useState('')
  const [filterEventCluster, setFilterEventCluster] = useState('')
  const [expandedEvents, setExpandedEvents] = useState<Set<string>>(new Set())
  const [eventRefresh, setEventRefresh] = useState(0)

  const queryClient = useQueryClient()

  // Auto-refresh events every 60s
  useEffect(() => {
    if (activeTab !== 'events') return
    const id = setInterval(() => setEventRefresh(n => n + 1), 60_000)
    return () => clearInterval(id)
  }, [activeTab])

  // ── Queries ──────────────────────────────────────────────────
  const { data: stats = EMPTY_STATS } = useQuery<ContainerStats>({
    queryKey: ['container-stats'],
    queryFn: () => apiFetch<ContainerStats>('/api/v1/containers/stats'),
    staleTime: 60_000,
  })

  const { data: workloads = [], isLoading: loadingWorkloads } = useQuery<Workload[]>({
    queryKey: ['container-workloads'],
    queryFn: () => apiFetchList<Workload>('/api/v1/containers/workloads'),
    staleTime: 60_000,
  })

  const { data: clusters = [] } = useQuery<Cluster[]>({
    queryKey: ['container-clusters'],
    queryFn: () => apiFetchList<Cluster>('/api/v1/containers/clusters'),
    staleTime: 60_000,
  })

  const { data: events = [], isLoading: loadingEvents } = useQuery<ContainerEvent[]>({
    queryKey: ['container-events', eventRefresh],
    queryFn: () => apiFetchList<ContainerEvent>('/api/v1/containers/events'),
    enabled: activeTab === 'events',
    staleTime: 0,
  })

  // Sync mutation
  const syncMutation = useMutation({
    mutationFn: () => apiFetch('/api/v1/containers/workloads/sync', { method: 'POST' }),
    onSuccess: () => queryClient.invalidateQueries({ queryKey: ['container-workloads'] }),
  })

  // ── Derived ──────────────────────────────────────────────────
  const displayStats = stats ?? EMPTY_STATS
  const namespaces = Array.from(new Set(workloads.map(w => w.namespace)))
  const clusterNames = Array.from(new Set(workloads.map(w => w.cluster)))

  const filteredWorkloads = workloads.filter(w => {
    if (filterCluster && w.cluster !== filterCluster) return false
    if (filterNamespace && w.namespace !== filterNamespace) return false
    if (filterStatus && w.status !== filterStatus) return false
    if (filterRisk === 'critical' && w.risk_score < 80) return false
    if (filterRisk === 'high' && (w.risk_score < 60 || w.risk_score >= 80)) return false
    if (filterRisk === 'medium' && (w.risk_score < 40 || w.risk_score >= 60)) return false
    if (filterRisk === 'low' && w.risk_score >= 40) return false
    if (selectedCluster && activeTab === 'clusters' && w.cluster !== selectedCluster) return false
    return true
  })

  const filteredEvents = events.filter(e => {
    if (filterEventSeverity && e.severity !== filterEventSeverity) return false
    if (filterEventType && e.event_type !== filterEventType) return false
    if (filterEventCluster && e.cluster !== filterEventCluster) return false
    return true
  })

  const toggleEventExpand = (id: string) => {
    setExpandedEvents(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  return (
    <div className="min-h-screen bg-[#070d19] text-[#e2e8f4]">
      <PageDataUnavailable />
      <PageSaveFailed />
      {selectedWorkload && (
        <>
          <div
            className="fixed inset-0 z-40 bg-black/40 backdrop-blur-sm"
            onClick={() => setSelectedWorkload(null)}
          />
          <WorkloadDetailPanel workload={selectedWorkload} onClose={() => setSelectedWorkload(null)} events={events} />
        </>
      )}

      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <div className="flex items-center gap-3 mb-1">
              <div className="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                <Boxes className="w-5 h-5 text-blue-400" />
              </div>
              <h1 className="text-2xl font-bold text-white">コンテナ監視</h1>
            </div>
            <p className="text-sm text-[#7d92b0] ml-12">Kubernetes ワークロードのセキュリティ監視</p>
          </div>
          <button
            onClick={() => syncMutation.mutate()}
            disabled={syncMutation.isPending}
            className="flex items-center gap-2 px-4 py-2 text-sm text-[#7d92b0] hover:text-white bg-[#0d1220] border border-[#1e2d42] hover:border-[#2a3f5a] rounded-lg transition-all disabled:opacity-50"
          >
            <RefreshCw className={`w-4 h-4 ${syncMutation.isPending ? 'animate-spin' : ''}`} />
            同期
          </button>
        </div>

        {/* Stats Row */}
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-4">
          {[
            { label: '総ワークロード', value: displayStats.total_workloads, icon: Boxes, color: 'text-blue-400' },
            { label: '実行中', value: displayStats.running, icon: Activity, color: 'text-green-400' },
            { label: 'リスク: 高', value: displayStats.risk_high_count, icon: AlertTriangle, color: 'text-orange-400' },
            { label: '脆弱性合計', value: displayStats.total_vulnerabilities, icon: Shield, color: 'text-[#e8002d]' },
          ].map(({ label, value, icon: Icon, color }) => (
            <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-xs text-[#7d92b0]">{label}</span>
                <Icon className={`w-4 h-4 ${color}`} />
              </div>
              <div className={`text-2xl font-bold ${color}`}>{value}</div>
            </div>
          ))}
        </div>

        {/* Tabs */}
        <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
          {([
            { key: 'workloads', label: 'ワークロード' },
            { key: 'events',    label: 'イベント' },
            { key: 'clusters',  label: 'クラスター' },
          ] as const).map(({ key, label }) => (
            <button
              key={key}
              onClick={() => setActiveTab(key)}
              className={`px-4 py-2 text-sm rounded-md font-medium transition-all ${
                activeTab === key
                  ? 'bg-[#1d2f4a] text-white'
                  : 'text-[#7d92b0] hover:text-[#e2e8f4]'
              }`}
            >
              {label}
            </button>
          ))}
        </div>

        {/* ── Tab: Workloads ─────────────────────────────────── */}
        {activeTab === 'workloads' && (
          <div className="space-y-4">
            {/* Filter Bar */}
            <div className="flex flex-wrap gap-3 p-4 bg-[#0d1220] border border-[#1e2d42] rounded-xl">
              <select
                className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                value={filterCluster}
                onChange={e => setFilterCluster(e.target.value)}
              >
                <option value="">全クラスター</option>
                {clusterNames.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
              <select
                className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                value={filterNamespace}
                onChange={e => setFilterNamespace(e.target.value)}
              >
                <option value="">全ネームスペース</option>
                {namespaces.map(n => <option key={n} value={n}>{n}</option>)}
              </select>
              <select
                className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                value={filterStatus}
                onChange={e => setFilterStatus(e.target.value)}
              >
                <option value="">全ステータス</option>
                <option value="running">Running</option>
                <option value="pending">Pending</option>
                <option value="failed">Failed</option>
              </select>
              <select
                className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                value={filterRisk}
                onChange={e => setFilterRisk(e.target.value)}
              >
                <option value="">全リスクレベル</option>
                <option value="critical">Critical (80+)</option>
                <option value="high">High (60-79)</option>
                <option value="medium">Medium (40-59)</option>
                <option value="low">Low (&lt;40)</option>
              </select>
              <span className="text-xs text-[#7d92b0] self-center ml-auto">
                {filteredWorkloads.length} / {workloads.length} 件
              </span>
            </div>

            {/* Workloads Table */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              {loadingWorkloads ? (
                <div className="p-8 text-center text-[#7d92b0] text-sm">読み込み中...</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[#1e2d42]">
                        {['ワークロード名', 'タイプ', 'ネームスペース', 'クラスター', 'イメージ', 'レプリカ', 'リスク', '脆弱性', 'ステータス'].map(h => (
                          <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wide whitespace-nowrap">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2d42]">
                      {filteredWorkloads.map(w => (
                        <tr
                          key={w.id}
                          className="hover:bg-[#0d1a2e] transition-colors cursor-pointer"
                          onClick={() => setSelectedWorkload(w)}
                        >
                          <td className="px-4 py-3">
                            <p className="text-sm font-medium text-[#e2e8f4]">{w.name}</p>
                          </td>
                          <td className="px-4 py-3">
                            <span className={`px-2 py-0.5 text-[10px] font-medium rounded-sm border ${getTypeStyle(w.type)}`}>
                              {w.type}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-xs text-[#7d92b0]">{w.namespace}</td>
                          <td className="px-4 py-3 text-xs text-[#7d92b0]">{w.cluster}</td>
                          <td className="px-4 py-3 max-w-[180px]">
                            <span className="font-mono text-[10px] text-[#7d92b0] truncate block" title={w.image}>
                              {w.image.length > 28 ? w.image.substring(0, 28) + '…' : w.image}
                            </span>
                          </td>
                          <td className="px-4 py-3 text-xs font-mono">
                            <span className={w.replicas_ready < w.replicas_total ? 'text-yellow-400' : 'text-green-400'}>
                              {w.replicas_ready}/{w.replicas_total}
                            </span>
                          </td>
                          <td className="px-4 py-3">
                            <div className="flex items-center gap-2">
                              <span className={`text-sm font-bold ${getRiskColor(w.risk_score)}`}>{w.risk_score}</span>
                              <div className="w-16 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                                <div
                                  className={`h-full rounded-full ${getRiskBgColor(w.risk_score)}`}
                                  style={{ width: `${w.risk_score}%` }}
                                />
                              </div>
                            </div>
                          </td>
                          <td className="px-4 py-3">
                            {w.vulnerability_count > 0 ? (
                              <span className="px-2 py-0.5 text-xs font-bold rounded-sm bg-[#e8002d]/20 text-[#e8002d] border border-[#e8002d]/30">
                                {w.vulnerability_count}
                              </span>
                            ) : (
                              <span className="px-2 py-0.5 text-xs rounded-sm bg-green-500/10 text-green-400 border border-green-500/20">0</span>
                            )}
                          </td>
                          <td className="px-4 py-3">
                            <span className={`px-2 py-0.5 text-[10px] rounded-sm border ${getStatusStyle(w.status)}`}>
                              {w.status}
                            </span>
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                  {filteredWorkloads.length === 0 && (
                    <div className="p-8 text-center text-[#7d92b0] text-sm">条件に一致するワークロードがありません</div>
                  )}
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Tab: Events ────────────────────────────────────── */}
        {activeTab === 'events' && (
          <div className="space-y-4">
            {/* Filter + LIVE */}
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-2">
                <div className="relative flex items-center gap-1.5 px-3 py-1.5 bg-[#1a6bff]/10 border border-[#1a6bff]/30 rounded-full">
                  <span className="absolute left-2.5 w-1.5 h-1.5 rounded-full bg-[#1a6bff] animate-ping" />
                  <span className="w-1.5 h-1.5 rounded-full bg-[#1a6bff]" />
                  <span className="text-xs font-bold text-[#1a6bff] ml-2">LIVE</span>
                </div>
                <span className="text-xs text-[#7d92b0]">60秒ごとに自動更新</span>
              </div>
              <select
                className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                value={filterEventSeverity}
                onChange={e => setFilterEventSeverity(e.target.value)}
              >
                <option value="">全重大度</option>
                <option value="critical">Critical</option>
                <option value="high">High</option>
                <option value="medium">Medium</option>
                <option value="low">Low</option>
              </select>
              <select
                className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                value={filterEventType}
                onChange={e => setFilterEventType(e.target.value)}
              >
                <option value="">全イベントタイプ</option>
                <option value="security">Security</option>
                <option value="runtime">Runtime</option>
                <option value="network">Network</option>
                <option value="policy">Policy</option>
              </select>
              <select
                className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#e2e8f4] focus:outline-hidden focus:border-[#1a6bff]"
                value={filterEventCluster}
                onChange={e => setFilterEventCluster(e.target.value)}
              >
                <option value="">全クラスター</option>
                {clusterNames.map(c => <option key={c} value={c}>{c}</option>)}
              </select>
              <button
                onClick={() => setEventRefresh(n => n + 1)}
                className="flex items-center gap-2 px-3 py-2 text-sm text-[#7d92b0] hover:text-white bg-[#0d1220] border border-[#1e2d42] hover:border-[#2a3f5a] rounded-lg transition-all ml-auto"
              >
                <RefreshCw className="w-3.5 h-3.5" />
                更新
              </button>
            </div>

            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
              {loadingEvents ? (
                <div className="p-8 text-center text-[#7d92b0] text-sm">読み込み中...</div>
              ) : filteredEvents.length === 0 ? (
                <div className="p-8 text-center text-[#7d92b0] text-sm">イベントがありません</div>
              ) : (
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-[#1e2d42]">
                        {['ワークロード', 'イベントタイプ', '重大度', 'メッセージ', '詳細', '発生時刻'].map(h => (
                          <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wide whitespace-nowrap">{h}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-[#1e2d42]">
                      {filteredEvents.map(ev => (
                        <>
                          <tr key={ev.id} className="hover:bg-[#0d1a2e] transition-colors">
                            <td className="px-4 py-3">
                              <p className="text-xs font-medium text-[#e2e8f4]">{ev.workload_name}</p>
                              <p className="text-[10px] text-[#3d5068]">{ev.cluster}</p>
                            </td>
                            <td className="px-4 py-3">
                              <span className={`px-2 py-0.5 text-[10px] font-medium rounded-sm border ${getEventTypeStyle(ev.event_type)}`}>
                                {ev.event_type}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <span className={`px-2 py-0.5 text-[10px] font-bold rounded-sm border uppercase ${getSeverityStyle(ev.severity)}`}>
                                {ev.severity}
                              </span>
                            </td>
                            <td className="px-4 py-3 max-w-[220px]">
                              <p className="text-xs text-[#e2e8f4] line-clamp-2">{ev.message}</p>
                            </td>
                            <td className="px-4 py-3">
                              <button
                                onClick={() => toggleEventExpand(ev.id)}
                                className="flex items-center gap-1 text-xs text-[#7d92b0] hover:text-white transition-colors"
                              >
                                {expandedEvents.has(ev.id) ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                                JSON
                              </button>
                            </td>
                            <td className="px-4 py-3 text-xs text-[#7d92b0] whitespace-nowrap">
                              {formatRelativeTime(ev.occurred_at)}
                            </td>
                          </tr>
                          {expandedEvents.has(ev.id) && (
                            <tr key={`${ev.id}-details`} className="bg-[#070d19]">
                              <td colSpan={6} className="px-4 py-3">
                                <pre className="text-[11px] font-mono text-[#7d92b0] overflow-x-auto whitespace-pre-wrap bg-[#0d1220] rounded-lg p-3 border border-[#1e2d42]">
                                  {JSON.stringify(ev.details, null, 2)}
                                </pre>
                              </td>
                            </tr>
                          )}
                        </>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          </div>
        )}

        {/* ── Tab: Clusters ──────────────────────────────────── */}
        {activeTab === 'clusters' && (
          <div className="space-y-4">
            {selectedCluster ? (
              <>
                <div className="flex items-center gap-3">
                  <button
                    onClick={() => setSelectedCluster(null)}
                    className="flex items-center gap-2 text-sm text-[#7d92b0] hover:text-white transition-colors"
                  >
                    <ChevronRight className="w-4 h-4 rotate-180" />
                    クラスター一覧へ戻る
                  </button>
                  <span className="text-[#3d5068]">/</span>
                  <span className="text-sm font-semibold text-white">{selectedCluster}</span>
                </div>
                {/* Cluster workloads drill-down */}
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
                  <div className="px-4 py-3 border-b border-[#1e2d42]">
                    <h3 className="text-sm font-semibold text-white">
                      {selectedCluster} のワークロード
                    </h3>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-[#1e2d42]">
                          {['名前', 'タイプ', 'ネームスペース', 'レプリカ', 'リスクスコア', '脆弱性', 'ステータス'].map(h => (
                            <th key={h} className="px-4 py-3 text-left text-xs font-semibold text-[#7d92b0] uppercase tracking-wide whitespace-nowrap">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#1e2d42]">
                        {workloads.filter(w => w.cluster === selectedCluster).map(w => (
                          <tr
                            key={w.id}
                            className="hover:bg-[#0d1a2e] transition-colors cursor-pointer"
                            onClick={() => setSelectedWorkload(w)}
                          >
                            <td className="px-4 py-3 text-sm font-medium text-[#e2e8f4]">{w.name}</td>
                            <td className="px-4 py-3">
                              <span className={`px-2 py-0.5 text-[10px] rounded-sm border ${getTypeStyle(w.type)}`}>{w.type}</span>
                            </td>
                            <td className="px-4 py-3 text-xs text-[#7d92b0]">{w.namespace}</td>
                            <td className="px-4 py-3 text-xs font-mono">
                              <span className={w.replicas_ready < w.replicas_total ? 'text-yellow-400' : 'text-green-400'}>
                                {w.replicas_ready}/{w.replicas_total}
                              </span>
                            </td>
                            <td className="px-4 py-3">
                              <div className="flex items-center gap-2">
                                <span className={`text-sm font-bold ${getRiskColor(w.risk_score)}`}>{w.risk_score}</span>
                                <div className="w-12 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                                  <div className={`h-full rounded-full ${getRiskBgColor(w.risk_score)}`} style={{ width: `${w.risk_score}%` }} />
                                </div>
                              </div>
                            </td>
                            <td className="px-4 py-3">
                              {w.vulnerability_count > 0 ? (
                                <span className="px-2 py-0.5 text-xs font-bold rounded-sm bg-[#e8002d]/20 text-[#e8002d] border border-[#e8002d]/30">{w.vulnerability_count}</span>
                              ) : (
                                <span className="px-2 py-0.5 text-xs rounded-sm bg-green-500/10 text-green-400 border border-green-500/20">0</span>
                              )}
                            </td>
                            <td className="px-4 py-3">
                              <span className={`px-2 py-0.5 text-[10px] rounded-sm border ${getStatusStyle(w.status)}`}>{w.status}</span>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </div>
              </>
            ) : (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
                {clusters.map(c => (
                  <div
                    key={c.id}
                    onClick={() => setSelectedCluster(c.name)}
                    className="bg-[#0d1220] border border-[#1e2d42] hover:border-[#2a3f5a] rounded-xl p-5 cursor-pointer transition-all group"
                  >
                    <div className="flex items-start justify-between mb-4">
                      <div className="flex items-center gap-3">
                        <div className="w-9 h-9 rounded-lg bg-blue-500/10 border border-blue-500/20 flex items-center justify-center">
                          <Server className="w-5 h-5 text-blue-400" />
                        </div>
                        <div>
                          <p className="text-white font-semibold text-sm">{c.name}</p>
                          <p className="text-xs text-[#7d92b0]">{c.workload_count} workloads · {c.namespace_count} namespaces</p>
                        </div>
                      </div>
                      <ChevronRight className="w-4 h-4 text-[#3d5068] group-hover:text-[#7d92b0] transition-colors" />
                    </div>

                    {/* Risk Summary Bar */}
                    <div className="mb-3">
                      <p className="text-xs text-[#7d92b0] mb-2">リスク分布</p>
                      <div className="flex gap-1 h-2 rounded-full overflow-hidden">
                        {c.risk_critical > 0 && (
                          <div
                            className="bg-[#e8002d] rounded-l-full"
                            style={{ width: `${(c.risk_critical / c.workload_count) * 100}%` }}
                            title={`Critical: ${c.risk_critical}`}
                          />
                        )}
                        {c.risk_high > 0 && (
                          <div
                            className="bg-orange-400"
                            style={{ width: `${(c.risk_high / c.workload_count) * 100}%` }}
                            title={`High: ${c.risk_high}`}
                          />
                        )}
                        {c.risk_medium > 0 && (
                          <div
                            className="bg-yellow-400"
                            style={{ width: `${(c.risk_medium / c.workload_count) * 100}%` }}
                            title={`Medium: ${c.risk_medium}`}
                          />
                        )}
                        <div className="flex-1 bg-green-500/40 rounded-r-full" />
                      </div>
                      <div className="flex gap-4 mt-2">
                        {[
                          { label: 'Critical', count: c.risk_critical, color: 'text-[#e8002d]' },
                          { label: 'High', count: c.risk_high, color: 'text-orange-400' },
                          { label: 'Medium', count: c.risk_medium, color: 'text-yellow-400' },
                        ].map(({ label, count, color }) => (
                          <div key={label} className="flex items-center gap-1">
                            <span className={`text-xs font-bold ${color}`}>{count}</span>
                            <span className="text-[10px] text-[#7d92b0]">{label}</span>
                          </div>
                        ))}
                      </div>
                    </div>

                    <div className="flex items-center gap-1.5 text-xs text-[#7d92b0] pt-3 border-t border-[#1e2d42]">
                      <Clock className="w-3.5 h-3.5" />
                      <span>最終同期: {formatRelativeTime(c.last_sync)}</span>
                    </div>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
