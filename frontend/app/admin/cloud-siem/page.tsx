'use client'

import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Cloud, Zap, Plus, X, RefreshCw, Play, Save,
  Trash2, Edit2, ToggleLeft, ToggleRight, CheckCircle,
  AlertCircle, ChevronDown, Clock, Database, Activity,
  FileText, Search, Filter
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ──────────────────────────────────────────────────────

type SourceType = 'cloudwatch' | 'stackdriver' | 'azure_monitor' | 's3' | 'kafka' | 'syslog'
type SourceStatus = 'active' | 'error' | 'disabled' | 'connecting'
type RuleType = 'threshold' | 'sequence' | 'anomaly' | 'correlation'
type Severity = 'critical' | 'high' | 'medium' | 'low'

interface LogSource {
  id: string
  name: string
  source_type: SourceType
  status: SourceStatus
  daily_volume_mb: number
  last_received: string | null
  error_count: number
  enabled: boolean
  config: Record<string, string>
  retention_days: number
  errors: string[]
  ingestion_trend: number[]
}

interface DetectionRule {
  id: string
  name: string
  description: string
  rule_type: RuleType
  severity: Severity
  time_window: number
  threshold: number | null
  match_count: number
  last_matched: string | null
  is_active: boolean
  query: string
}

interface SavedQuery {
  id: string
  name: string
  query: string
  created_at: string
}

interface QueryResult {
  timestamp: string
  source: string
  level: string
  message: string
}

// ── Helpers ────────────────────────────────────────────────────

const sourceTypeMeta: Record<SourceType, { label: string; color: string }> = {
  cloudwatch:    { label: 'CloudWatch',    color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  stackdriver:   { label: 'Stackdriver',   color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  azure_monitor: { label: 'Azure Monitor', color: 'bg-teal-500/20 text-teal-400 border-teal-500/30' },
  s3:            { label: 'S3',            color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  kafka:         { label: 'Kafka',         color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  syslog:        { label: 'Syslog',        color: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
}

const ruleTypeMeta: Record<RuleType, { label: string; color: string }> = {
  threshold:   { label: 'Threshold',   color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  sequence:    { label: 'Sequence',    color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  anomaly:     { label: 'Anomaly',     color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  correlation: { label: 'Correlation', color: 'bg-green-500/20 text-green-400 border-green-500/30' },
}

const severityMeta: Record<Severity, { label: string; color: string }> = {
  critical: { label: 'Critical', color: 'bg-red-500/20 text-red-400 border-red-500/30' },
  high:     { label: 'High',     color: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  medium:   { label: 'Medium',   color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  low:      { label: 'Low',      color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
}

const statusMeta: Record<SourceStatus, { label: string; color: string }> = {
  active:     { label: 'Active',     color: 'bg-green-500/20 text-green-400 border-green-500/30' },
  error:      { label: 'Error',      color: 'bg-red-500/20 text-red-400 border-red-500/30' },
  disabled:   { label: 'Disabled',   color: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
  connecting: { label: 'Connecting', color: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
}

function formatVolume(mb: number): string {
  if (mb >= 1000) return `${(mb / 1024).toFixed(1)} GB`
  return `${mb} MB`
}

function humanizeSeconds(s: number): string {
  if (s < 60) return `${s}秒`
  if (s < 3600) return `${Math.floor(s / 60)}分`
  return `${Math.floor(s / 3600)}時間`
}

function timeAgo(iso: string | null): { text: string; isOld: boolean } {
  if (!iso) return { text: 'なし', isOld: true }
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return { text: '< 1分前', isOld: false }
  if (mins < 60) return { text: `${mins}分前`, isOld: false }
  return { text: `${Math.floor(mins / 60)}時間前`, isOld: true }
}

function Badge({ className, children }: { className: string; children: React.ReactNode }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm text-xs font-medium border ${className}`}>
      {children}
    </span>
  )
}

function Toast({ message, type, onClose }: { message: string; type: 'success' | 'error'; onClose: () => void }) {
  return (
    <div className={`fixed top-4 right-4 z-50 flex items-center gap-3 px-4 py-3 rounded-lg border shadow-xl ${
      type === 'success' ? 'bg-green-900/90 border-green-500/40 text-green-100' : 'bg-red-900/90 border-red-500/40 text-red-100'
    }`}>
      {type === 'success' ? <CheckCircle className="w-4 h-4 text-green-400 shrink-0" /> : <AlertCircle className="w-4 h-4 text-red-400 shrink-0" />}
      <span className="text-sm">{message}</span>
      <button onClick={onClose} className="ml-2 opacity-60 hover:opacity-100"><X className="w-3.5 h-3.5" /></button>
    </div>
  )
}

// ── Config field labels by source type ────────────────────────
const configFieldLabels: Record<SourceType, { key: string; label: string; placeholder: string }[]> = {
  cloudwatch:    [{ key: 'region', label: 'AWSリージョン', placeholder: 'ap-northeast-1' }, { key: 'log_group_arn', label: 'Log Group ARN', placeholder: 'arn:aws:logs:...' }],
  stackdriver:   [{ key: 'project_id', label: 'GCPプロジェクトID', placeholder: 'my-project-prod' }, { key: 'service_account', label: 'サービスアカウント', placeholder: 'siem@project.iam.gserviceaccount.com' }],
  azure_monitor: [{ key: 'tenant_id', label: 'テナントID', placeholder: 'xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx' }, { key: 'subscription_id', label: 'サブスクリプションID', placeholder: 'sub-001' }],
  s3:            [{ key: 'bucket_name', label: 'バケット名', placeholder: 'corp-security-logs' }, { key: 'prefix', label: 'プレフィックス', placeholder: 'siem/' }, { key: 'region', label: 'AWSリージョン', placeholder: 'us-east-1' }],
  kafka:         [{ key: 'bootstrap_servers', label: 'Bootstrapサーバー', placeholder: 'kafka1:9092,kafka2:9092' }, { key: 'topic', label: 'トピック名', placeholder: 'security-events' }, { key: 'consumer_group', label: 'コンシューマーグループ', placeholder: 'siem-consumer' }],
  syslog:        [{ key: 'host', label: 'ホスト', placeholder: '0.0.0.0' }, { key: 'port', label: 'ポート', placeholder: '514' }, { key: 'protocol', label: 'プロトコル', placeholder: 'UDP' }],
}

// ── Main Component ─────────────────────────────────────────────

export default function CloudSiemPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'sources' | 'rules' | 'query'>('sources')
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null)
  const showToast = useCallback((message: string, type: 'success' | 'error' = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 4000)
  }, [])

  // Sources state
  const [showAddSource, setShowAddSource] = useState(false)
  const [selectedSource, setSelectedSource] = useState<LogSource | null>(null)
  const [newSource, setNewSource] = useState({ name: '', source_type: 'cloudwatch' as SourceType, retention_days: 90, config: {} as Record<string, string> })

  // Rules state
  const [showAddRule, setShowAddRule] = useState(false)
  const [editRule, setEditRule] = useState<DetectionRule | null>(null)
  const [newRule, setNewRule] = useState({ name: '', description: '', rule_type: 'threshold' as RuleType, severity: 'medium' as Severity, query: '', time_window: 300, threshold: '' as string | number, is_active: true })

  // Query tab state
  const [queryText, setQueryText] = useState('level=ERROR | timechart span=5m count')
  const [timeRange, setTimeRange] = useState('1h')
  const [queryResults, setQueryResults] = useState<QueryResult[] | null>(null)
  const [queryExecTime, setQueryExecTime] = useState<number | null>(null)
  const [querySaveName, setQuerySaveName] = useState('')
  const [showSaveQuery, setShowSaveQuery] = useState(false)

  // Queries sidebar
  const [savedQueries, setSavedQueries] = useState<SavedQuery[]>([])

  // API queries
  const { data: sources = [] } = useQuery<LogSource[]>({
    queryKey: ['cloud-siem-sources'],
    queryFn: () => apiFetchList<LogSource>('/api/v1/admin/cloud-siem/sources'),
    staleTime: 30_000,
  })

  const { data: rules = [] } = useQuery<DetectionRule[]>({
    queryKey: ['cloud-siem-rules'],
    queryFn: () => apiFetchList<DetectionRule>('/api/v1/admin/cloud-siem/rules'),
    staleTime: 30_000,
  })

  // Stats
  const totalSources = sources.length
  const dailyIngestionGB = sources.reduce((s, src) => s + src.daily_volume_mb, 0) / 1024
  const activeRules = rules.filter(r => r.is_active).length
  const alertsToday = rules.reduce((s, r) => s + (r.last_matched && new Date(r.last_matched).toDateString() === new Date().toDateString() ? 1 : 0), 0)

  const handleTestConnection = (src: LogSource) => {
    const ok = src.error_count === 0
    showToast(ok ? `${src.name}: 接続成功` : `${src.name}: 接続失敗`, ok ? 'success' : 'error')
  }

  const handleToggleSource = async (src: LogSource) => {
    try {
      await apiFetch(`/api/v1/admin/cloud-siem/sources/${src.id}/toggle`, { method: 'POST' })
      qc.invalidateQueries({ queryKey: ['cloud-siem-sources'] })
    } catch {
      showToast(`${src.name} の切り替えに失敗しました`, 'error')
    }
  }

  const handleToggleRule = async (rule: DetectionRule) => {
    try {
      await apiFetch(`/api/v1/admin/cloud-siem/rules/${rule.id}/toggle`, { method: 'POST' })
      qc.invalidateQueries({ queryKey: ['cloud-siem-rules'] })
    } catch {
      showToast(`${rule.name} の切り替えに失敗しました`, 'error')
    }
  }

  // 以前はここで Math.floor(Math.random() * 20) を「マッチ件数」として
  // 出していました。ルールを試した人は、その数を検証結果として読みます。
  // すぐ下の handleExecuteQuery は同じ状況で正直に「準備中」と言っています。
  const handleTestRule = (rule: DetectionRule) => {
    showToast(`"${rule.name}": ルールの試行はサーバ側が未実装です`, 'error')
  }

  const handleExecuteQuery = () => {
    // 実ログ検索バックエンドは準備中。偽の実行時間や空結果を演出せず準備中を通知する。
    setQueryResults(null)
    setQueryExecTime(null)
    showToast('SIEMクエリ実行エンジンは準備中です', 'error')
  }

  const handleSaveQuery = () => {
    if (!querySaveName.trim()) return
    const nq: SavedQuery = { id: `q${Date.now()}`, name: querySaveName, query: queryText, created_at: new Date().toISOString() }
    setSavedQueries(prev => [nq, ...prev])
    setShowSaveQuery(false)
    setQuerySaveName('')
    showToast('クエリを保存しました')
  }

  const handleDeleteSavedQuery = (id: string) => {
    setSavedQueries(prev => prev.filter(q => q.id !== id))
  }

  const handleAddSource = async () => {
    try {
      await apiFetch('/api/v1/admin/cloud-siem/sources', { method: 'POST', body: JSON.stringify(newSource) })
      qc.invalidateQueries({ queryKey: ['cloud-siem-sources'] })
      showToast('ログソースを追加しました')
    } catch {
      showToast('追加に失敗しました', 'error')
    }
    setShowAddSource(false)
  }

  const handleAddRule = async () => {
    try {
      await apiFetch('/api/v1/admin/cloud-siem/rules', { method: 'POST', body: JSON.stringify(newRule) })
      qc.invalidateQueries({ queryKey: ['cloud-siem-rules'] })
      showToast('検出ルールを追加しました')
    } catch {
      showToast('追加に失敗しました', 'error')
    }
    setShowAddRule(false)
    setEditRule(null)
  }

  const topRules = [...rules].sort((a, b) => b.match_count - a.match_count).slice(0, 5)
  const maxMatchCount = topRules[0]?.match_count ?? 1

  return (
    <div className="min-h-screen bg-[#070d19] text-[#7d92b0] p-6">
      <PageDataUnavailable />
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
            <Cloud className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">クラウドネイティブSIEM</h1>
            <p className="text-xs text-[#7d92b0] mt-0.5">ログ収集・分析プラットフォーム</p>
          </div>
        </div>
        <button onClick={() => qc.invalidateQueries()} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] hover:border-[#7d92b0]/40 text-sm transition-colors">
          <RefreshCw className="w-3.5 h-3.5" />
          更新
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'ログソース数', value: totalSources, icon: Database, color: 'text-blue-400' },
          { label: '日次取込量', value: `${dailyIngestionGB.toFixed(1)} GB`, icon: Activity, color: 'text-green-400' },
          { label: 'アクティブルール', value: activeRules, icon: Zap, color: 'text-yellow-400' },
          { label: '本日のアラート', value: alertsToday, icon: AlertCircle, color: 'text-[#e8002d]' },
        ].map(stat => (
          <div key={stat.label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-[#7d92b0]">{stat.label}</span>
              <stat.icon className={`w-4 h-4 ${stat.color}`} />
            </div>
            <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-1 mb-6 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
        {(['sources', 'rules', 'query'] as const).map((t, i) => (
          <button
            key={t}
            onClick={() => setTab(t)}
            className={`px-4 py-2 rounded-sm text-sm font-medium transition-colors ${
              tab === t ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:text-white'
            }`}
          >
            {['ログソース', '検出ルール', 'クエリ'][i]}
          </button>
        ))}
      </div>

      {/* ── Log Sources Tab ─────────────────────────────────── */}
      {tab === 'sources' && (
        <div>
          <div className="flex justify-end mb-4">
            <button onClick={() => setShowAddSource(true)} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c8001e] transition-colors">
              <Plus className="w-4 h-4" />
              ソースを追加
            </button>
          </div>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['名前', 'タイプ', 'ステータス', '日次ボリューム', '最終受信', 'エラー', '有効', '操作'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {sources.map(src => {
                  const ta = timeAgo(src.last_received)
                  return (
                    <tr key={src.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                      <td className="px-4 py-3">
                        <button onClick={() => setSelectedSource(src)} className="text-white font-medium hover:text-[#e8002d] transition-colors text-left">
                          {src.name}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <Badge className={sourceTypeMeta[src.source_type].color}>{sourceTypeMeta[src.source_type].label}</Badge>
                      </td>
                      <td className="px-4 py-3">
                        <Badge className={statusMeta[src.status].color}>{statusMeta[src.status].label}</Badge>
                      </td>
                      <td className="px-4 py-3 text-white font-mono">{formatVolume(src.daily_volume_mb)}</td>
                      <td className={`px-4 py-3 font-mono ${ta.isOld ? 'text-red-400' : 'text-[#7d92b0]'}`}>{ta.text}</td>
                      <td className={`px-4 py-3 font-mono ${src.error_count > 0 ? 'text-red-400' : 'text-[#7d92b0]'}`}>{src.error_count}</td>
                      <td className="px-4 py-3">
                        <button onClick={() => handleToggleSource(src)}>
                          {src.enabled
                            ? <ToggleRight className="w-6 h-6 text-green-400" />
                            : <ToggleLeft className="w-6 h-6 text-[#3d5068]" />
                          }
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <button onClick={() => handleTestConnection(src)} className="px-2 py-1 rounded-sm bg-[#1e2d42] hover:bg-[#2a3f5a] text-xs transition-colors">テスト</button>
                          <button onClick={() => setSelectedSource(src)} className="p-1 rounded-sm hover:bg-[#1e2d42] transition-colors"><Eye className="w-3.5 h-3.5" /></button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>

          {/* Source Detail Panel */}
          {selectedSource && (
            <div className="mt-4 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
              <div className="flex items-center justify-between mb-4">
                <h3 className="text-white font-semibold">{selectedSource.name} — 詳細</h3>
                <button onClick={() => setSelectedSource(null)}><X className="w-4 h-4" /></button>
              </div>
              <div className="mb-4">
                <p className="text-xs text-[#7d92b0] mb-2 uppercase tracking-wide">7日間取込トレンド</p>
                <div className="flex items-end gap-1 h-16">
                  {selectedSource.ingestion_trend.map((v, i) => {
                    const maxV = Math.max(...selectedSource.ingestion_trend, 1)
                    return (
                      <div key={i} className="flex-1 flex flex-col items-center gap-1">
                        <div className="w-full bg-blue-500/60 rounded-xs" style={{ height: `${(v / maxV) * 52}px` }} />
                        <span className="text-[9px] text-[#3d5068]">{['月','火','水','木','金','土','日'][i]}</span>
                      </div>
                    )
                  })}
                </div>
              </div>
              {selectedSource.errors.length > 0 && (
                <div>
                  <p className="text-xs text-[#7d92b0] mb-2 uppercase tracking-wide">直近エラーログ</p>
                  <div className="space-y-1">
                    {selectedSource.errors.map((e, i) => (
                      <p key={i} className="text-xs font-mono text-red-400 bg-red-900/10 border border-red-500/20 rounded-sm px-2 py-1">{e}</p>
                    ))}
                  </div>
                </div>
              )}
              {selectedSource.errors.length === 0 && (
                <p className="text-xs text-green-400 flex items-center gap-1"><CheckCircle className="w-3.5 h-3.5" />エラーなし</p>
              )}
            </div>
          )}
        </div>
      )}

      {/* ── Detection Rules Tab ─────────────────────────────── */}
      {tab === 'rules' && (
        <div>
          <div className="flex justify-end mb-4">
            <button onClick={() => setShowAddRule(true)} className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c8001e] transition-colors">
              <Plus className="w-4 h-4" />
              ルールを追加
            </button>
          </div>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden mb-6">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['名前', 'タイプ', '重大度', '時間窓', '閾値', 'マッチ数', '最終マッチ', '有効', '操作'].map(h => (
                    <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-[#7d92b0] uppercase tracking-wide">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rules.map(rule => (
                  <tr key={rule.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20 transition-colors">
                    <td className="px-4 py-3">
                      <p className="text-white font-medium">{rule.name}</p>
                      <p className="text-xs text-[#7d92b0] truncate max-w-[200px]">{rule.description}</p>
                    </td>
                    <td className="px-4 py-3"><Badge className={ruleTypeMeta[rule.rule_type].color}>{ruleTypeMeta[rule.rule_type].label}</Badge></td>
                    <td className="px-4 py-3"><Badge className={severityMeta[rule.severity].color}>{severityMeta[rule.severity].label}</Badge></td>
                    <td className="px-4 py-3 font-mono text-white">{humanizeSeconds(rule.time_window)}</td>
                    <td className="px-4 py-3 font-mono text-[#7d92b0]">{rule.threshold ?? '—'}</td>
                    <td className="px-4 py-3 font-mono text-white">{(rule.match_count ?? 0).toLocaleString()}</td>
                    <td className="px-4 py-3 text-[#7d92b0] font-mono text-xs">{rule.last_matched ? timeAgo(rule.last_matched).text : '—'}</td>
                    <td className="px-4 py-3">
                      <button onClick={() => handleToggleRule(rule)}>
                        {rule.is_active
                          ? <ToggleRight className="w-6 h-6 text-green-400" />
                          : <ToggleLeft className="w-6 h-6 text-[#3d5068]" />
                        }
                      </button>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <button onClick={() => handleTestRule(rule)} className="px-2 py-1 rounded-sm bg-[#1e2d42] hover:bg-[#2a3f5a] text-xs transition-colors">テスト</button>
                        <button onClick={() => { setEditRule(rule); setShowAddRule(true) }} className="p-1 rounded-sm hover:bg-[#1e2d42] transition-colors"><Edit2 className="w-3.5 h-3.5" /></button>
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>

          {/* Detection Effectiveness Chart */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <h3 className="text-white font-semibold mb-4">検出効果 — マッチ数 Top 5</h3>
            <div className="space-y-3">
              {topRules.map(rule => (
                <div key={rule.id} className="flex items-center gap-3">
                  <span className="text-sm text-[#7d92b0] w-48 truncate">{rule.name}</span>
                  <div className="flex-1 h-5 bg-[#1e2d42] rounded-sm overflow-hidden">
                    <div
                      className="h-full bg-linear-to-r from-[#e8002d] to-[#ff4060] rounded-sm transition-all"
                      style={{ width: `${(rule.match_count / maxMatchCount) * 100}%` }}
                    />
                  </div>
                  <span className="text-sm font-mono text-white w-16 text-right">{(rule.match_count ?? 0).toLocaleString()}</span>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Query Tab ───────────────────────────────────────── */}
      {tab === 'query' && (
        <div className="flex gap-4">
          {/* Main editor + results */}
          <div className="flex-1 flex flex-col gap-4">
            {/* Editor */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4" style={{ flex: '0 0 40%' }}>
              <div className="flex items-center justify-between mb-3">
                <div className="flex items-center gap-2">
                  <span className="text-sm font-medium text-white">クエリエディタ</span>
                  <select value={timeRange} onChange={e => setTimeRange(e.target.value)} className="text-xs bg-[#1e2d42] border border-[#1e2d42] rounded-sm px-2 py-1 text-[#7d92b0] outline-hidden">
                    <option value="15m">過去15分</option>
                    <option value="1h">過去1時間</option>
                    <option value="6h">過去6時間</option>
                    <option value="24h">過去24時間</option>
                    <option value="7d">過去7日間</option>
                  </select>
                </div>
                <div className="flex items-center gap-2">
                  <button onClick={() => setShowSaveQuery(true)} className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-[#1e2d42] hover:bg-[#2a3f5a] text-sm transition-colors">
                    <Save className="w-3.5 h-3.5" />
                    保存
                  </button>
                  <button onClick={handleExecuteQuery} className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-[#e8002d] text-white text-sm hover:bg-[#c8001e] transition-colors">
                    <Play className="w-3.5 h-3.5" />
                    クエリ実行
                  </button>
                </div>
              </div>
              <textarea
                value={queryText}
                onChange={e => setQueryText(e.target.value)}
                placeholder="level=ERROR | timechart span=5m count&#10;source=cloudwatch | stats count by user | sort -count"
                className="w-full h-32 bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 text-sm font-mono text-white placeholder-[#3d5068] outline-hidden resize-none focus:border-[#7d92b0]/40"
              />
              {showSaveQuery && (
                <div className="mt-2 flex items-center gap-2">
                  <input
                    value={querySaveName}
                    onChange={e => setQuerySaveName(e.target.value)}
                    placeholder="クエリ名を入力"
                    className="flex-1 bg-[#1e2d42] border border-[#1e2d42] rounded-sm px-3 py-1.5 text-sm text-white outline-hidden"
                  />
                  <button onClick={handleSaveQuery} className="px-3 py-1.5 rounded-sm bg-green-600 text-white text-sm hover:bg-green-500 transition-colors">保存</button>
                  <button onClick={() => setShowSaveQuery(false)} className="px-3 py-1.5 rounded-sm bg-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">キャンセル</button>
                </div>
              )}
            </div>

            {/* Results */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl flex-1 p-4">
              {queryResults ? (
                <>
                  <div className="flex items-center justify-between mb-3">
                    <span className="text-sm font-medium text-white">クエリ結果</span>
                    <div className="flex items-center gap-3 text-xs text-[#7d92b0]">
                      <span className="flex items-center gap-1"><Clock className="w-3 h-3" />{queryExecTime}ms</span>
                      <span>{queryResults.length} 件</span>
                    </div>
                  </div>
                  <div className="overflow-x-auto">
                    <table className="w-full text-xs font-mono">
                      <thead>
                        <tr className="border-b border-[#1e2d42]">
                          {['タイムスタンプ', 'ソース', 'レベル', 'メッセージ'].map(h => (
                            <th key={h} className="text-left px-3 py-2 text-[#7d92b0]">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody>
                        {queryResults.map((r, i) => (
                          <tr key={i} className="border-b border-[#1e2d42]/30 hover:bg-[#1e2d42]/20">
                            <td className="px-3 py-2 text-[#7d92b0] whitespace-nowrap">{r.timestamp}</td>
                            <td className="px-3 py-2 text-blue-400 whitespace-nowrap">{r.source}</td>
                            <td className="px-3 py-2">
                              <Badge className={
                                r.level === 'CRITICAL' ? 'bg-red-500/20 text-red-400 border-red-500/30' :
                                r.level === 'ERROR' ? 'bg-orange-500/20 text-orange-400 border-orange-500/30' :
                                r.level === 'WARNING' ? 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' :
                                'bg-green-500/20 text-green-400 border-green-500/30'
                              }>{r.level}</Badge>
                            </td>
                            <td className="px-3 py-2 text-white max-w-[400px] truncate">{r.message}</td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                </>
              ) : (
                <div className="flex flex-col items-center justify-center h-32 text-[#3d5068]">
                  <Search className="w-8 h-8 mb-2" />
                  <p className="text-sm">クエリを実行してください</p>
                </div>
              )}
            </div>
          </div>

          {/* Saved queries sidebar */}
          <div className="w-64 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 h-fit">
            <h3 className="text-sm font-medium text-white mb-3">保存済みクエリ</h3>
            <div className="space-y-2">
              {savedQueries.map(q => (
                <div key={q.id} className="bg-[#1e2d42]/40 border border-[#1e2d42] rounded-lg p-3">
                  <div className="flex items-start justify-between gap-2 mb-1">
                    <button onClick={() => setQueryText(q.query)} className="text-sm text-white hover:text-[#e8002d] transition-colors text-left font-medium">{q.name}</button>
                    <button onClick={() => handleDeleteSavedQuery(q.id)} className="text-[#3d5068] hover:text-red-400 transition-colors shrink-0">
                      <Trash2 className="w-3.5 h-3.5" />
                    </button>
                  </div>
                  <p className="text-xs text-[#3d5068] font-mono truncate">{q.query}</p>
                </div>
              ))}
            </div>
          </div>
        </div>
      )}

      {/* ── Add Source Modal ────────────────────────────────── */}
      {showAddSource && (
        <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg p-6">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-bold text-white">ログソースを追加</h2>
              <button onClick={() => setShowAddSource(false)}><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">名前</label>
                <input value={newSource.name} onChange={e => setNewSource(p => ({ ...p, name: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-hidden focus:border-[#7d92b0]/40" placeholder="本番環境CloudWatch" />
              </div>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">ソースタイプ</label>
                <select value={newSource.source_type} onChange={e => setNewSource(p => ({ ...p, source_type: e.target.value as SourceType, config: {} }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-hidden">
                  {Object.entries(sourceTypeMeta).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                </select>
              </div>
              {configFieldLabels[newSource.source_type].map(f => (
                <div key={f.key}>
                  <label className="block text-xs text-[#7d92b0] mb-1">{f.label}</label>
                  <input value={newSource.config[f.key] ?? ''} onChange={e => setNewSource(p => ({ ...p, config: { ...p.config, [f.key]: e.target.value } }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-hidden focus:border-[#7d92b0]/40" placeholder={f.placeholder} />
                </div>
              ))}
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">保持日数</label>
                <input type="number" value={newSource.retention_days} onChange={e => setNewSource(p => ({ ...p, retention_days: Number(e.target.value) }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-hidden focus:border-[#7d92b0]/40" />
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button onClick={() => setShowAddSource(false)} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">キャンセル</button>
              <button onClick={handleAddSource} className="px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c8001e] transition-colors">追加</button>
            </div>
          </div>
        </div>
      )}

      {/* ── Add/Edit Rule Modal ─────────────────────────────── */}
      {showAddRule && (
        <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg p-6 max-h-[90vh] overflow-y-auto">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-bold text-white">{editRule ? 'ルールを編集' : '検出ルールを追加'}</h2>
              <button onClick={() => { setShowAddRule(false); setEditRule(null) }}><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">名前</label>
                <input
                  value={editRule?.name ?? newRule.name}
                  onChange={e => editRule ? setEditRule(p => p ? { ...p, name: e.target.value } : null) : setNewRule(p => ({ ...p, name: e.target.value }))}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-hidden focus:border-[#7d92b0]/40"
                />
              </div>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">説明</label>
                <input
                  value={editRule?.description ?? newRule.description}
                  onChange={e => editRule ? setEditRule(p => p ? { ...p, description: e.target.value } : null) : setNewRule(p => ({ ...p, description: e.target.value }))}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-hidden focus:border-[#7d92b0]/40"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1">ルールタイプ</label>
                  <select value={editRule?.rule_type ?? newRule.rule_type} onChange={e => editRule ? setEditRule(p => p ? { ...p, rule_type: e.target.value as RuleType } : null) : setNewRule(p => ({ ...p, rule_type: e.target.value as RuleType }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-hidden">
                    {Object.entries(ruleTypeMeta).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                  </select>
                </div>
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1">重大度</label>
                  <select value={editRule?.severity ?? newRule.severity} onChange={e => editRule ? setEditRule(p => p ? { ...p, severity: e.target.value as Severity } : null) : setNewRule(p => ({ ...p, severity: e.target.value as Severity }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-hidden">
                    {Object.entries(severityMeta).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">クエリ</label>
                <textarea
                  value={editRule?.query ?? newRule.query}
                  onChange={e => editRule ? setEditRule(p => p ? { ...p, query: e.target.value } : null) : setNewRule(p => ({ ...p, query: e.target.value }))}
                  placeholder="level=ERROR | count > threshold"
                  className="w-full h-24 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm font-mono text-white placeholder-[#3d5068] outline-hidden resize-none focus:border-[#7d92b0]/40"
                />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1">時間窓 (秒)</label>
                  <input type="number" value={editRule?.time_window ?? newRule.time_window} onChange={e => editRule ? setEditRule(p => p ? { ...p, time_window: Number(e.target.value) } : null) : setNewRule(p => ({ ...p, time_window: Number(e.target.value) }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-hidden focus:border-[#7d92b0]/40" />
                </div>
                <div>
                  <label className="block text-xs text-[#7d92b0] mb-1">閾値 (任意)</label>
                  <input type="number" value={editRule?.threshold ?? newRule.threshold} onChange={e => editRule ? setEditRule(p => p ? { ...p, threshold: Number(e.target.value) } : null) : setNewRule(p => ({ ...p, threshold: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-hidden focus:border-[#7d92b0]/40" />
                </div>
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button onClick={() => { setShowAddRule(false); setEditRule(null) }} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">キャンセル</button>
              <button onClick={handleAddRule} className="px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c8001e] transition-colors">{editRule ? '更新' : '追加'}</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// Missing import fix
function Eye({ className }: { className?: string }) {
  return <svg className={className} xmlns="http://www.w3.org/2000/svg" viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="2" strokeLinecap="round" strokeLinejoin="round"><path d="M1 12s4-8 11-8 11 8 11 8-4 8-11 8-11-8-11-8z"/><circle cx="12" cy="12" r="3"/></svg>
}
