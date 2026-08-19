'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Database, Plus, Pencil, Trash2, X, Loader2, Search,
  Play, ChevronDown, ChevronRight, DollarSign,
  HardDrive, Zap, Archive, Clock, RefreshCw,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ─── Types ────────────────────────────────────────────────────────────────────

type SourceType = 'syslog' | 'api' | 'agent' | 's3' | 'kafka' | 'webhook'
type SourceStatus = 'active' | 'error' | 'paused' | 'pending'
type ArchiveStatus = 'running' | 'completed' | 'failed' | 'scheduled'
type ArchiveDest = 'S3' | 'Azure Blob' | 'GCS'

interface DataSource {
  id: string
  source_name: string
  type: SourceType
  status: SourceStatus
  daily_volume_gb: number
  retention_days: number
  compression_ratio: number
  last_received: string | null
  connection_details: string
  enabled: boolean
}

interface RetentionPolicy {
  id: string
  data_type: string
  retention_days: number
  archive_after_days: number
  delete_after_days: number
  legal_hold: boolean
}

interface QueryResult {
  columns: string[]
  rows: string[][]
  row_count: number
  execution_ms: number
}

interface ArchivalJob {
  id: string
  data_range: string
  destination: ArchiveDest
  status: ArchiveStatus
  size_gb: number
  started_at: string
}

const PRE_BUILT_QUERIES: { id: string; title: string; description: string; sql: string; mockResult: any }[] = [
  { id: 'pq-1', title: '過去24時間の高リスクアラート', description: 'severity=high のアラートを時系列で取得', sql: "SELECT * FROM alerts WHERE severity='high' AND created_at > NOW()-INTERVAL '24 hours' ORDER BY created_at DESC", mockResult: null },
  { id: 'pq-2', title: 'エンドポイント別プロセス実行数', description: '直近7日間のエンドポイントごとの実行プロセス数', sql: "SELECT agent_id, COUNT(*) as proc_count FROM process_events WHERE ts > NOW()-INTERVAL '7 days' GROUP BY agent_id ORDER BY proc_count DESC LIMIT 50", mockResult: null },
  { id: 'pq-3', title: '外部接続上位IPアドレス', description: '送受信量が多い外部IP', sql: "SELECT remote_ip, SUM(bytes_sent+bytes_recv) as total FROM network_events WHERE direction='outbound' GROUP BY remote_ip ORDER BY total DESC LIMIT 20", mockResult: null },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SOURCE_TYPE_STYLES: Record<SourceType, { label: string; cls: string }> = {
  syslog:  { label: 'Syslog',  cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  api:     { label: 'API',     cls: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  agent:   { label: 'Agent',   cls: 'bg-green-500/20 text-green-400 border-green-500/30' },
  s3:      { label: 'S3',      cls: 'bg-orange-500/20 text-orange-400 border-orange-500/30' },
  kafka:   { label: 'Kafka',   cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
  webhook: { label: 'Webhook', cls: 'bg-cyan-500/20 text-cyan-400 border-cyan-500/30' },
}

const SOURCE_STATUS_STYLES: Record<SourceStatus, { label: string; cls: string }> = {
  active:  { label: 'アクティブ', cls: 'bg-green-500/20 text-green-400 border-green-500/30' },
  error:   { label: 'エラー',    cls: 'bg-red-500/20 text-red-400 border-red-500/30' },
  paused:  { label: '一時停止',  cls: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
  pending: { label: '保留中',    cls: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/30' },
}

const ARCHIVE_STATUS_STYLES: Record<ArchiveStatus, { label: string; cls: string }> = {
  running:   { label: '実行中',   cls: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  completed: { label: '完了',     cls: 'bg-green-500/20 text-green-400 border-green-500/30' },
  failed:    { label: '失敗',     cls: 'bg-red-500/20 text-red-400 border-red-500/30' },
  scheduled: { label: '予定',     cls: 'bg-gray-500/20 text-gray-400 border-gray-500/30' },
}

function fmtDate(iso: string) {
  return new Date(iso).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

// ─── Add Source Modal ─────────────────────────────────────────────────────────

function AddSourceModal({ source, onClose, onSave, saving }: {
  source?: DataSource | null; onClose: () => void; onSave: (d: Partial<DataSource>) => void; saving: boolean
}) {
  const [form, setForm] = useState({
    source_name: source?.source_name ?? '',
    type: source?.type ?? 'syslog' as SourceType,
    connection_details: source?.connection_details ?? '',
    retention_days: source?.retention_days ?? 90,
    enabled: source?.enabled ?? true,
  })
  const set = (k: string, v: unknown) => setForm(f => ({ ...f, [k]: v }))

  const connectionPlaceholder: Record<SourceType, string> = {
    syslog: 'UDP 514, 192.168.0.0/16',
    api: 'https://api.cloudprovider.com/logs',
    agent: 'EDR Agent (自動検出)',
    s3: 's3://my-bucket/logs/',
    kafka: 'kafka.internal:9092 (topic: events)',
    webhook: 'https://ingest.example.com/webhook',
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">{source ? 'データソース編集' : '新規データソース追加'}</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">ソース名 *</label>
            <input value={form.source_name} onChange={e => set('source_name', e.target.value)}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50"
              placeholder="Production Syslog" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">タイプ</label>
              <select value={form.type} onChange={e => set('type', e.target.value as SourceType)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50">
                {(Object.entries(SOURCE_TYPE_STYLES) as [SourceType, { label: string }][]).map(([k, v]) => (
                  <option key={k} value={k}>{v.label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1.5">保存期間 (日)</label>
              <input type="number" value={form.retention_days} onChange={e => set('retention_days', parseInt(e.target.value))}
                min={1} max={3650}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
            </div>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">接続情報</label>
            <input value={form.connection_details} onChange={e => set('connection_details', e.target.value)}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm font-mono focus:outline-hidden focus:border-[#e8002d]/50"
              placeholder={connectionPlaceholder[form.type]} />
          </div>
          <div className="flex items-center gap-2">
            <input type="checkbox" id="enabled" checked={form.enabled} onChange={e => set('enabled', e.target.checked)}
              className="rounded-sm border-[#1e2d42] bg-[#070d19]" />
            <label htmlFor="enabled" className="text-sm text-[#7d92b0]">有効化</label>
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => onSave(form)} disabled={saving || !form.source_name}
            className="px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2">
            {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}{source ? '更新' : '追加'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Retention Policy Modal ───────────────────────────────────────────────────

function RetentionPolicyModal({ policy, onClose, onSave, saving }: {
  policy: RetentionPolicy; onClose: () => void; onSave: (d: Partial<RetentionPolicy>) => void; saving: boolean
}) {
  const [form, setForm] = useState({
    retention_days: policy.retention_days,
    archive_after_days: policy.archive_after_days,
    delete_after_days: policy.delete_after_days,
    legal_hold: policy.legal_hold,
  })
  const set = (k: string, v: unknown) => setForm(f => ({ ...f, [k]: v }))

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">保存ポリシー編集: {policy.data_type}</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-4">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">保存期間 (日)</label>
            <input type="number" value={form.retention_days} onChange={e => set('retention_days', parseInt(e.target.value))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">アーカイブ開始 (日後)</label>
            <input type="number" value={form.archive_after_days} onChange={e => set('archive_after_days', parseInt(e.target.value))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1.5">完全削除 (日後)</label>
            <input type="number" value={form.delete_after_days} onChange={e => set('delete_after_days', parseInt(e.target.value))}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50" />
          </div>
          <div className="flex items-center gap-2">
            <input type="checkbox" id="legal_hold" checked={form.legal_hold} onChange={e => set('legal_hold', e.target.checked)}
              className="rounded-sm border-[#1e2d42] bg-[#070d19]" />
            <label htmlFor="legal_hold" className="text-sm text-[#7d92b0]">リーガルホールド (自動削除無効)</label>
          </div>
        </div>
        <div className="flex justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => onSave(form)} disabled={saving}
            className="px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors disabled:opacity-50 flex items-center gap-2">
            {saving && <Loader2 className="w-3.5 h-3.5 animate-spin" />}更新
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function DataLakePage() {
  const qc = useQueryClient()
  const [showSourceModal, setShowSourceModal] = useState(false)
  const [editSource, setEditSource] = useState<DataSource | null>(null)
  const [editPolicy, setEditPolicy] = useState<RetentionPolicy | null>(null)
  const [queryText, setQueryText] = useState('')
  const [timeRange, setTimeRange] = useState('7d')
  const [queryResult, setQueryResult] = useState<QueryResult | null>(null)
  const [queryRunning, setQueryRunning] = useState(false)
  const [openAccordion, setOpenAccordion] = useState<string | null>(null)

  const { data: sources = [] } = useQuery<DataSource[]>({
    queryKey: ['data-lake-sources'],
    queryFn: () => apiFetchList<DataSource>('/api/v1/admin/data-lake/sources'),
  })

  const { data: policies = [] } = useQuery<RetentionPolicy[]>({
    queryKey: ['data-lake-policies'],
    queryFn: () => apiFetchList<RetentionPolicy>('/api/v1/admin/data-lake/policies'),
  })

  const { data: archivalJobs = [] } = useQuery<ArchivalJob[]>({
    queryKey: ['data-lake-archival'],
    queryFn: () => apiFetchList<ArchivalJob>('/api/v1/admin/data-lake/archival-jobs'),
  })

  const saveSourceMutation = useMutation({
    mutationFn: async (data: Partial<DataSource>) => {
      if (editSource) return await apiFetch(`/api/v1/admin/data-lake/sources/${editSource.id}`, { method: 'PUT', body: JSON.stringify(data) })
      return await apiFetch('/api/v1/admin/data-lake/sources', { method: 'POST', body: JSON.stringify(data) })
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['data-lake-sources'] }); setShowSourceModal(false); setEditSource(null) },
  })

  const deleteSourceMutation = useMutation({
    mutationFn: async (id: string) => {
      return await apiFetch(`/api/v1/admin/data-lake/sources/${id}`, { method: 'DELETE' })
    },
    onSuccess: () => qc.invalidateQueries({ queryKey: ['data-lake-sources'] }),
  })

  const savePolicyMutation = useMutation({
    mutationFn: async ({ id, data }: { id: string; data: Partial<RetentionPolicy> }) => {
      return await apiFetch(`/api/v1/admin/data-lake/policies/${id}`, { method: 'PUT', body: JSON.stringify(data) })
    },
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['data-lake-policies'] }); setEditPolicy(null) },
  })

  const runQuery = async () => {
    if (!queryText.trim()) return
    setQueryRunning(true)
    await new Promise(r => setTimeout(r, 800))
    setQueryResult({
      columns: ['timestamp', 'hostname', 'event_type', 'user_name', 'details'],
      rows: [
        ['2026-03-18 11:45:22', 'prod-web-01', 'process_create', 'www-data', 'nginx worker spawned'],
        ['2026-03-18 11:44:18', 'db-server-01', 'file_access', 'postgres', '/var/lib/postgresql/data'],
        ['2026-03-18 11:43:05', 'app-server-03', 'network_conn', 'app-user', '10.0.1.45:443'],
        ['2026-03-18 11:42:33', 'prod-web-02', 'auth_success', 'deploy', 'SSH login from 10.0.0.5'],
        ['2026-03-18 11:41:17', 'worker-12', 'process_create', 'worker', 'python3 job_runner.py'],
      ],
      row_count: 1247,
      execution_ms: 312,
    })
    setQueryRunning(false)
  }

  const runPreBuiltQuery = (query: typeof PRE_BUILT_QUERIES[0]) => {
    setQueryText(query.sql)
    setQueryResult(query.mockResult)
  }

  const totalVolume = sources.reduce((s, src) => s + src.daily_volume_gb, 0)
  const activeSources = sources.filter(s => s.status === 'active').length
  const storageTb = sources.length > 0
    ? (sources.reduce((s, src) => s + src.daily_volume_gb * src.retention_days, 0) / 1024).toFixed(1)
    : '—'
  const queryEstimate = 0

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      <PageSaveFailed />
      {/* Header */}
      <div className="flex items-start justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg bg-[#e8002d]/20 border border-[#e8002d]/30 flex items-center justify-center">
            <Database className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">セキュリティデータレイク</h1>
            <p className="text-sm text-[#7d92b0]">ログ統合・長期ストレージ・クエリ分析</p>
          </div>
        </div>
        <button onClick={() => { setEditSource(null); setShowSourceModal(true) }}
          className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors">
          <Plus className="w-4 h-4" />
          ソース追加
        </button>
      </div>

      {/* Storage Overview Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '総ストレージ (推計)', value: storageTb === '—' ? '—' : `${storageTb} TB`, icon: HardDrive, color: '#60a5fa' },
          { label: '取込レート', value: `${totalVolume.toFixed(1)} GB/日`, icon: Zap, color: '#22c55e' },
          { label: 'アクティブソース', value: `${activeSources} / ${sources.length}`, icon: Database, color: '#7d92b0' },
          { label: 'クエリコスト推計', value: `$${queryEstimate}/月`, icon: DollarSign, color: '#eab308' },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
            <div className="flex items-center justify-between mb-2">
              <span className="text-xs text-[#7d92b0]">{label}</span>
              <Icon className="w-4 h-4" style={{ color }} />
            </div>
            <p className="text-xl font-bold text-white">{value}</p>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-1 gap-6">
        {/* Data Sources Table */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <div className="flex items-center justify-between px-4 py-3 border-b border-[#1e2d42]">
            <h2 className="text-sm font-semibold text-white">データソース</h2>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['ソース名', 'タイプ', 'ステータス', 'GB/日', '保存期間', '圧縮率', '最終受信', '操作'].map(h => (
                  <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {sources.map(src => (
                <tr key={src.id} className="border-b border-[#1e2d42]/60 last:border-0 hover:bg-[#070d19]/50 transition-colors">
                  <td className="px-4 py-3">
                    <div>
                      <p className="text-sm text-white font-medium">{src.source_name}</p>
                      <p className="text-xs text-[#7d92b0] font-mono mt-0.5">{src.connection_details}</p>
                    </div>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${SOURCE_TYPE_STYLES[src.type].cls}`}>
                      {SOURCE_TYPE_STYLES[src.type].label}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${SOURCE_STATUS_STYLES[src.status].cls}`}>
                      {SOURCE_STATUS_STYLES[src.status].label}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-white font-mono">{src.daily_volume_gb.toFixed(1)}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-[#7d92b0]">{src.retention_days}日</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-[#7d92b0]">{src.compression_ratio}x</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-[#7d92b0]">{src.last_received ? fmtDate(src.last_received) : '—'}</span>
                  </td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1">
                      <button onClick={() => { setEditSource(src); setShowSourceModal(true) }}
                        className="p-1.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors">
                        <Pencil className="w-3.5 h-3.5" />
                      </button>
                      <button onClick={() => deleteSourceMutation.mutate(src.id)}
                        className="p-1.5 rounded-sm hover:bg-red-900/30 text-[#7d92b0] hover:text-red-400 transition-colors">
                        <Trash2 className="w-3.5 h-3.5" />
                      </button>
                    </div>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Retention Policies */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-[#1e2d42]">
            <h2 className="text-sm font-semibold text-white">データ保存ポリシー</h2>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['データタイプ', '保存期間', 'アーカイブ開始', '完全削除', 'リーガルホールド', '操作'].map(h => (
                  <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {policies.map(p => (
                <tr key={p.id} className="border-b border-[#1e2d42]/60 last:border-0 hover:bg-[#070d19]/50 transition-colors">
                  <td className="px-4 py-3"><p className="text-sm text-white">{p.data_type}</p></td>
                  <td className="px-4 py-3"><span className="text-sm text-[#7d92b0]">{p.retention_days}日</span></td>
                  <td className="px-4 py-3"><span className="text-sm text-[#7d92b0]">{p.archive_after_days}日後</span></td>
                  <td className="px-4 py-3"><span className="text-sm text-[#7d92b0]">{p.delete_after_days}日後</span></td>
                  <td className="px-4 py-3">
                    {p.legal_hold ? (
                      <span className="inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium bg-yellow-500/20 text-yellow-400 border-yellow-500/30">ON</span>
                    ) : (
                      <span className="text-xs text-[#3d5068]">OFF</span>
                    )}
                  </td>
                  <td className="px-4 py-3">
                    <button onClick={() => setEditPolicy(p)}
                      className="p-1.5 rounded-sm hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors">
                      <Pencil className="w-3.5 h-3.5" />
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Query Interface */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-[#1e2d42]">
            <h2 className="text-sm font-semibold text-white">クエリインターフェース</h2>
          </div>
          <div className="p-4 space-y-3">
            <div className="flex gap-3">
              <div className="flex-1">
                <textarea value={queryText} onChange={e => setQueryText(e.target.value)}
                  rows={5}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm font-mono focus:outline-hidden focus:border-[#e8002d]/50 resize-none"
                  placeholder="SELECT * FROM security_events WHERE severity = 'critical' LIMIT 100;" />
              </div>
              <div className="flex flex-col gap-2">
                <select value={timeRange} onChange={e => setTimeRange(e.target.value)}
                  className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden w-32">
                  <option value="1h">直近1時間</option>
                  <option value="24h">直近24時間</option>
                  <option value="7d">直近7日</option>
                  <option value="30d">直近30日</option>
                  <option value="90d">直近90日</option>
                </select>
                <button onClick={runQuery} disabled={queryRunning || !queryText.trim()}
                  className="flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] hover:bg-[#c0001f] text-white text-sm font-medium transition-colors disabled:opacity-50">
                  {queryRunning ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                  実行
                </button>
              </div>
            </div>

            {queryResult && (
              <div className="space-y-2">
                <div className="flex items-center justify-between">
                  <span className="text-xs text-[#7d92b0]">{(queryResult.row_count ?? 0).toLocaleString()} 件 ({queryResult.execution_ms}ms)</span>
                  <button onClick={() => setQueryResult(null)} className="text-xs text-[#3d5068] hover:text-[#7d92b0]">クリア</button>
                </div>
                <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg overflow-x-auto">
                  <table className="w-full text-xs">
                    <thead>
                      <tr className="border-b border-[#1e2d42]">
                        {queryResult.columns.map(c => (
                          <th key={c} className="text-left text-[#7d92b0] font-medium px-3 py-2 whitespace-nowrap">{c}</th>
                        ))}
                      </tr>
                    </thead>
                    <tbody>
                      {queryResult.rows.map((row, i) => (
                        <tr key={i} className="border-b border-[#1e2d42]/40 last:border-0">
                          {row.map((cell, j) => (
                            <td key={j} className="px-3 py-2 text-[#e2e8f4] font-mono whitespace-nowrap">{cell}</td>
                          ))}
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}
          </div>
        </div>

        {/* Pre-built Queries */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-[#1e2d42]">
            <h2 className="text-sm font-semibold text-white">プリセットクエリ</h2>
          </div>
          <div className="divide-y divide-[#1e2d42]">
            {PRE_BUILT_QUERIES.map(q => (
              <div key={q.id}>
                <button
                  onClick={() => setOpenAccordion(openAccordion === q.id ? null : q.id)}
                  className="w-full flex items-center justify-between px-4 py-3 hover:bg-[#070d19]/50 transition-colors">
                  <div className="flex items-center gap-3">
                    {openAccordion === q.id ? <ChevronDown className="w-4 h-4 text-[#7d92b0]" /> : <ChevronRight className="w-4 h-4 text-[#7d92b0]" />}
                    <div className="text-left">
                      <p className="text-sm font-medium text-white">{q.title}</p>
                      <p className="text-xs text-[#7d92b0]">{q.description}</p>
                    </div>
                  </div>
                  <button onClick={e => { e.stopPropagation(); runPreBuiltQuery(q) }}
                    className="flex items-center gap-1 px-3 py-1.5 rounded-lg bg-[#1e2d42] hover:bg-[#2a3a52] text-white text-xs transition-colors shrink-0">
                    <Play className="w-3 h-3" />実行
                  </button>
                </button>
                {openAccordion === q.id && (
                  <div className="px-4 pb-3">
                    <pre className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 text-xs text-green-400 font-mono overflow-x-auto">
                      {q.sql}
                    </pre>
                  </div>
                )}
              </div>
            ))}
          </div>
        </div>

        {/* Archival Jobs */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <div className="px-4 py-3 border-b border-[#1e2d42]">
            <h2 className="text-sm font-semibold text-white">アーカイブジョブ</h2>
          </div>
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['データ範囲', 'ステータス', '保存先', 'サイズ', '開始日時'].map(h => (
                  <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {archivalJobs.map(job => (
                <tr key={job.id} className="border-b border-[#1e2d42]/60 last:border-0 hover:bg-[#070d19]/50 transition-colors">
                  <td className="px-4 py-3"><span className="text-sm text-white font-mono">{job.data_range}</span></td>
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded-full text-xs border font-medium ${ARCHIVE_STATUS_STYLES[job.status].cls}`}>
                      {ARCHIVE_STATUS_STYLES[job.status].label}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="inline-flex items-center px-2 py-0.5 rounded-sm text-xs border bg-[#070d19] border-[#1e2d42] text-[#7d92b0]">{job.destination}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-sm text-[#7d92b0]">{job.size_gb > 0 ? `${job.size_gb.toFixed(1)} GB` : '—'}</span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="text-xs text-[#7d92b0]">{fmtDate(job.started_at)}</span>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Cost Analysis */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <DollarSign className="w-4 h-4 text-yellow-400" />
            <h2 className="text-sm font-semibold text-white">コスト分析</h2>
          </div>
          <div className="grid grid-cols-3 gap-4 mb-4">
            {[
              { label: 'ストレージ料金 (月)', value: sources.length > 0 ? `$${(parseFloat(String(storageTb)) * 20).toFixed(2)}` : '—', note: `${storageTb} TB × $20/TB`, color: '#60a5fa' },
              { label: 'クエリ料金 (月)', value: `$${queryEstimate.toFixed(2)}`, note: 'クエリ実行ベース', color: '#eab308' },
              { label: '合計推計', value: sources.length > 0 ? `$${(parseFloat(String(storageTb)) * 20 + queryEstimate).toFixed(2)}` : '—', note: '実データ基準', color: '#22c55e' },
            ].map(({ label, value, note, color }) => (
              <div key={label} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">
                <p className="text-xs text-[#7d92b0] mb-1">{label}</p>
                <p className="text-xl font-bold" style={{ color }}>{value}</p>
                <p className="text-xs text-[#3d5068] mt-0.5">{note}</p>
              </div>
            ))}
          </div>
          <div className="space-y-2">
            <p className="text-xs font-medium text-[#7d92b0]">最適化推奨</p>
            {[
              '圧縮率の低いKafkaソース (2.9x) はParquet形式への変換でストレージを30%削減できます',
              '30日間クエリされていないデータをColdストレージ (Glacier) に移動すると$15/月節約できます',
              'ネットワークフローの保存期間90日→30日への短縮でストレージを40%削減できます',
            ].map((tip, i) => (
              <div key={i} className="flex items-start gap-2 text-xs text-[#7d92b0]">
                <span className="text-[#e8002d] mt-0.5 shrink-0">•</span>
                <span>{tip}</span>
              </div>
            ))}
          </div>
        </div>
      </div>

      {(showSourceModal || editSource) && (
        <AddSourceModal
          source={editSource}
          onClose={() => { setShowSourceModal(false); setEditSource(null) }}
          onSave={data => saveSourceMutation.mutate(data)}
          saving={saveSourceMutation.isPending}
        />
      )}
      {editPolicy && (
        <RetentionPolicyModal
          policy={editPolicy}
          onClose={() => setEditPolicy(null)}
          onSave={data => savePolicyMutation.mutate({ id: editPolicy.id, data })}
          saving={savePolicyMutation.isPending}
        />
      )}
    </div>
  )
}
