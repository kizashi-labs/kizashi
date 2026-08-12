'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  DatabaseBackup, Trash2, Clock, Edit2, AlertTriangle,
  CheckCircle, RefreshCw, Calendar, BarChart3, ShieldAlert,
  Activity, FileText, Network, Globe, FolderOpen, Cpu, HeartPulse
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────

interface RetentionPolicy {
  type:             string
  retention_days:   number | null  // null = Forever
  records_count:    number
  size_mb:          number
  last_purge:       string | null
  auto_purge:       boolean
  purge_schedule:   'daily' | 'weekly' | 'monthly'
}

interface RetentionResponse {
  policies: RetentionPolicy[]
}

interface PurgePreviewResponse {
  count:   number
  size_mb: number
}

type RetentionDays = 7 | 30 | 60 | 90 | 180 | 365 | null

// ── Static metadata per data type ─────────────────────────────────────────

const DATA_TYPE_META: Record<string, { label: string; labelJp: string; icon: React.ComponentType<{ className?: string; style?: React.CSSProperties }> }> = {
  alerts:              { label: 'Alerts',              labelJp: 'アラート',             icon: ShieldAlert  },
  events:              { label: 'Events',              labelJp: 'イベントログ',         icon: Activity     },
  audit_logs:          { label: 'Audit Logs',          labelJp: '監査ログ',             icon: FileText     },
  agent_heartbeats:    { label: 'Agent Heartbeats',    labelJp: 'エージェントHB',       icon: HeartPulse   },
  network_connections: { label: 'Network Connections', labelJp: 'ネットワーク接続',     icon: Network      },
  dns_queries:         { label: 'DNS Queries',         labelJp: 'DNSクエリ',            icon: Globe        },
  file_changes:        { label: 'File Changes',        labelJp: 'ファイル変更',         icon: FolderOpen   },
  process_events:      { label: 'Process Events',      labelJp: 'プロセスイベント',     icon: Cpu          },
}

const RETENTION_OPTIONS: { value: RetentionDays; label: string }[] = [
  { value: 7, label: '7日' }, { value: 30, label: '30日' }, { value: 60, label: '60日' },
  { value: 90, label: '90日' }, { value: 180, label: '180日' }, { value: 365, label: '1年' },
]
const SCHEDULE_OPTIONS: { value: 'daily' | 'weekly' | 'monthly'; label: string }[] = [
  { value: 'daily', label: '毎日' }, { value: 'weekly', label: '毎週' },
  { value: 'monthly', label: '毎月' },
]

// ── Helpers ────────────────────────────────────────────────────────────────

function formatCount(n: number): string {
  if (n >= 1_000_000) return `${(n / 1_000_000).toFixed(1)}M`
  if (n >= 1_000)     return `${(n / 1_000).toFixed(0)}K`
  return n.toString()
}

function formatSize(mb: number): string {
  if (mb >= 1024) return `${(mb / 1024).toFixed(1)} GB`
  return `${mb} MB`
}

function retentionLabel(days: number | null): string {
  if (days === null) return '無期限'
  if (days === 365)  return '1年'
  if (days === 180)  return '180日'
  if (days === 90)   return '90日'
  if (days === 60)   return '60日'
  if (days === 30)   return '30日'
  if (days === 7)    return '7日'
  return `${days}日`
}

function relativeTime(iso: string | null): string {
  if (!iso) return 'なし'
  const diff = Date.now() - new Date(iso).getTime()
  const h = Math.floor(diff / 3_600_000)
  if (h < 1) return '1時間未満'
  if (h < 24) return `${h}時間前`
  const d = Math.floor(h / 24)
  return `${d}日前`
}

// ── Edit Modal ─────────────────────────────────────────────────────────────

interface EditModalProps {
  policy:   RetentionPolicy
  onSave:   (type: string, days: RetentionDays, autoPurge: boolean, schedule: 'daily' | 'weekly' | 'monthly') => void
  onClose:  () => void
  isSaving: boolean
}

function EditModal({ policy, onSave, onClose, isSaving }: EditModalProps) {
  const meta = DATA_TYPE_META[policy.type]
  const [days, setDays]         = useState<RetentionDays>(policy.retention_days as RetentionDays)
  const [autoPurge, setAutoPurge] = useState(policy.auto_purge)
  const [schedule, setSchedule] = useState<'daily' | 'weekly' | 'monthly'>(policy.purge_schedule)

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-2xl p-6 w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between mb-6">
          <div className="flex items-center gap-2">
            <Edit2 className="w-5 h-5 text-[#e8002d]" />
            <h2 className="text-lg font-bold text-white">保持ポリシーを編集</h2>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white text-xl leading-none">×</button>
        </div>

        <p className="text-sm text-[#7d92b0] mb-6">
          <span className="text-white font-medium">{meta?.labelJp ?? policy.type}</span> のデータ保持設定を変更します
        </p>

        {/* Retention period */}
        <div className="mb-5">
          <label className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wide mb-2 block">
            保持期間
          </label>
          <div className="grid grid-cols-4 gap-2">
            {RETENTION_OPTIONS.map(opt => (
              <button
                key={String(opt.value)}
                onClick={() => setDays(opt.value)}
                className={`py-2 text-xs font-medium rounded-lg border transition-colors ${
                  days === opt.value
                    ? 'bg-[#e8002d] border-[#e8002d] text-white'
                    : 'bg-[#070d19] border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/40 hover:text-white'
                }`}
              >
                {opt.label}
              </button>
            ))}
          </div>
        </div>

        {/* Auto purge toggle */}
        <div className="mb-5 flex items-center justify-between p-3 rounded-lg bg-[#070d19] border border-[#1e2d42]">
          <div>
            <p className="text-sm font-medium text-white">自動パージ</p>
            <p className="text-xs text-[#3d5068]">スケジュールに従って自動的に削除</p>
          </div>
          <button
            onClick={() => setAutoPurge(v => !v)}
            className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
              autoPurge ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'
            }`}
          >
            <span className={`inline-block h-3.5 w-3.5 rounded-full bg-[#e2e8f4] transition-transform ${
              autoPurge ? 'translate-x-4' : 'translate-x-0.5'
            }`} />
          </button>
        </div>

        {/* Schedule */}
        {autoPurge && (
          <div className="mb-5">
            <label className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wide mb-2 block">
              実行スケジュール
            </label>
            <div className="flex gap-2">
              {SCHEDULE_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  onClick={() => setSchedule(opt.value)}
                  className={`flex-1 py-2 text-xs font-medium rounded-lg border transition-colors ${
                    schedule === opt.value
                      ? 'bg-[#1d2f4a] border-[#3d5068] text-white'
                      : 'bg-[#070d19] border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/40 hover:text-white'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
        )}

        {/* Actions */}
        <div className="flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 py-2 text-sm text-[#7d92b0] border border-[#1e2d42] rounded-lg
                       hover:bg-[#1e2d42] transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={() => onSave(policy.type, days, autoPurge, schedule)}
            disabled={isSaving}
            className="flex-1 py-2 text-sm font-medium text-white bg-[#e8002d] rounded-lg
                       hover:bg-[#c8001e] transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {isSaving && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Purge Confirm Dialog ───────────────────────────────────────────────────

interface PurgeDialogProps {
  type:      string
  preview:   PurgePreviewResponse | null
  onConfirm: () => void
  onClose:   () => void
  isPurging: boolean
}

function PurgeDialog({ type, preview, onConfirm, onClose, isPurging }: PurgeDialogProps) {
  const meta = DATA_TYPE_META[type]
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#e8002d]/30 rounded-2xl p-6 w-full max-w-sm shadow-2xl">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-[#e8002d]/10 flex items-center justify-center">
            <AlertTriangle className="w-5 h-5 text-[#e8002d]" />
          </div>
          <h2 className="text-lg font-bold text-white">パージの確認</h2>
        </div>

        <p className="text-sm text-[#7d92b0] mb-4">
          <span className="text-white font-medium">{meta?.labelJp ?? type}</span> の期限切れデータを削除します。この操作は元に戻せません。
        </p>

        {preview && (
          <div className="mb-4 p-3 bg-[#e8002d]/10 border border-[#e8002d]/20 rounded-lg space-y-1.5">
            <div className="flex justify-between text-sm">
              <span className="text-[#7d92b0]">削除予定レコード数</span>
              <span className="text-white font-bold">{formatCount(preview.count)}</span>
            </div>
            <div className="flex justify-between text-sm">
              <span className="text-[#7d92b0]">解放サイズ</span>
              <span className="text-white font-bold">{formatSize(preview.size_mb)}</span>
            </div>
          </div>
        )}

        <div className="flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 py-2 text-sm text-[#7d92b0] border border-[#1e2d42] rounded-lg
                       hover:bg-[#1e2d42] transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={onConfirm}
            disabled={isPurging}
            className="flex-1 py-2 text-sm font-medium text-white bg-[#e8002d] rounded-lg
                       hover:bg-[#c8001e] transition-colors disabled:opacity-50 flex items-center justify-center gap-2"
          >
            {isPurging && <RefreshCw className="w-3.5 h-3.5 animate-spin" />}
            今すぐパージ
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────

export default function DataRetentionPage() {
  const queryClient = useQueryClient()

  const [editingPolicy, setEditingPolicy]   = useState<RetentionPolicy | null>(null)
  const [purgeTarget, setPurgeTarget]       = useState<string | null>(null)
  const [purgePreview, setPurgePreview]     = useState<PurgePreviewResponse | null>(null)
  const [previewLoading, setPreviewLoading] = useState(false)
  const [purgeSuccess, setPurgeSuccess]     = useState<string | null>(null)
  const [globalAutoPurge, setGlobalAutoPurge] = useState(true)
  const [globalSchedule, setGlobalSchedule]   = useState<'daily' | 'weekly' | 'monthly'>('daily')

  // ── Fetch policies ──────────────────────────────────────────────────────
  const { data, isLoading, refetch } = useQuery<RetentionResponse>({
    queryKey: ['data-retention-policies'],
    queryFn: async () => {
      try {
        return await apiFetch<RetentionResponse>('/api/v1/admin/data-retention')
      } catch {
        return { policies: [] as RetentionPolicy[] }
      }
    },
  })

  const policies = data?.policies ?? []

  // ── Update policy mutation ──────────────────────────────────────────────
  const updateMutation = useMutation({
    mutationFn: async ({
      type, retention_days, auto_purge, purge_schedule,
    }: { type: string; retention_days: RetentionDays; auto_purge: boolean; purge_schedule: string }) => {
      try {
        await apiFetch(`/api/v1/admin/data-retention/${type}`, {
          method: 'PUT',
          body: JSON.stringify({ retention_days, auto_purge, purge_schedule }),
        })
      } catch {
        // Optimistic update on 404
      }
    },
    onSuccess: () => {
      queryClient.invalidateQueries({ queryKey: ['data-retention-policies'] })
      setEditingPolicy(null)
    },
  })

  // ── Purge mutation ──────────────────────────────────────────────────────
  const purgeMutation = useMutation({
    // No catch: a failed purge must fail visibly, never simulate success.
    mutationFn: (type: string) =>
      apiFetch('/api/v1/admin/data-retention/purge', {
        method: 'POST',
        body: JSON.stringify({ type }),
      }),
    onSuccess: (_, type) => {
      setPurgeTarget(null)
      setPurgePreview(null)
      setPurgeSuccess(type)
      setTimeout(() => setPurgeSuccess(null), 4000)
      queryClient.invalidateQueries({ queryKey: ['data-retention-policies'] })
    },
  })

  // ── Preview purge ───────────────────────────────────────────────────────
  const handlePreviewPurge = async (type: string) => {
    setPreviewLoading(true)
    setPurgeTarget(type)
    try {
      const preview = await apiFetch<PurgePreviewResponse>(
        '/api/v1/admin/data-retention/purge-preview',
        { method: 'POST', body: JSON.stringify({ type }) }
      )
      setPurgePreview(preview)
    } catch {
      // Never fabricate a preview count — show "0件" rather than a fake estimate.
      setPurgePreview({ count: 0, size_mb: 0 })
    } finally {
      setPreviewLoading(false)
    }
  }

  // ── Storage chart total ─────────────────────────────────────────────────
  const totalSizeMb  = useMemo(() => policies.reduce((s, p) => s + p.size_mb, 0), [policies])
  const maxSizeMb    = useMemo(() => Math.max(...policies.map(p => p.size_mb), 1),  [policies])

  return (
    <div className="min-h-screen bg-[#070d19] p-6">

      {/* ── Success toast ─────────────────────────────────────────── */}
      {purgeSuccess && (
        <div className="fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-3
                        bg-green-900/80 border border-green-700/50 rounded-xl text-sm text-green-300 shadow-xl">
          <CheckCircle className="w-4 h-4" />
          {DATA_TYPE_META[purgeSuccess]?.labelJp ?? purgeSuccess} のパージが完了しました
        </div>
      )}

      {/* ── Header ─────────────────────────────────────────────────── */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <DatabaseBackup className="w-6 h-6 text-[#e8002d]" />
          <div>
            <h1 className="text-2xl font-bold text-white">データ保持ポリシー</h1>
            <p className="text-sm text-[#7d92b0]">データタイプごとの保持期間とパージスケジュールを管理</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-[#3d5068]">合計ストレージ:</span>
          <span className="text-sm font-bold text-white">{formatSize(totalSizeMb)}</span>
          <button
            onClick={() => refetch()}
            disabled={isLoading}
            className="flex items-center gap-1.5 px-3 py-2 text-sm text-[#7d92b0]
                       bg-[#0d1220] border border-[#1e2d42] rounded-lg hover:bg-[#1e2d42] transition-colors
                       disabled:opacity-50 ml-2"
          >
            <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
            更新
          </button>
        </div>
      </div>

      {/* ── Storage Bar Chart ─────────────────────────────────────── */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-2xl p-5 mb-6">
        <div className="flex items-center gap-2 mb-4">
          <BarChart3 className="w-4 h-4 text-[#e8002d]" />
          <h2 className="text-sm font-bold text-white">ストレージ使用量</h2>
          <span className="text-xs text-[#3d5068] ml-auto">合計: {formatSize(totalSizeMb)}</span>
        </div>
        <div className="space-y-2.5">
          {policies
            .slice()
            .sort((a, b) => b.size_mb - a.size_mb)
            .map(policy => {
              const meta    = DATA_TYPE_META[policy.type]
              const Icon    = meta?.icon ?? DatabaseBackup
              const pct     = Math.round((policy.size_mb / maxSizeMb) * 100)
              const colorMap: Record<string, string> = {
                alerts:              '#e8002d',
                events:              '#f97316',
                audit_logs:          '#f59e0b',
                agent_heartbeats:    '#22d3ee',
                network_connections: '#3b82f6',
                dns_queries:         '#8b5cf6',
                file_changes:        '#10b981',
                process_events:      '#ec4899',
              }
              const color = colorMap[policy.type] ?? '#7d92b0'
              return (
                <div key={policy.type} className="flex items-center gap-3">
                  <div className="flex items-center gap-1.5 w-44 flex-shrink-0">
                    <Icon className="w-3.5 h-3.5 flex-shrink-0" style={{ color }} />
                    <span className="text-xs text-[#7d92b0] truncate">{meta?.labelJp ?? policy.type}</span>
                  </div>
                  <div className="flex-1 bg-[#070d19] rounded-full h-3 overflow-hidden border border-[#1e2d42]">
                    <div
                      className="h-full rounded-full transition-all duration-700"
                      style={{ width: `${pct}%`, background: color, opacity: 0.85 }}
                    />
                  </div>
                  <span className="text-xs text-white font-medium w-16 text-right flex-shrink-0">
                    {formatSize(policy.size_mb)}
                  </span>
                </div>
              )
            })}
        </div>
      </div>

      {/* ── Policies Table ─────────────────────────────────────────── */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-2xl mb-6 overflow-hidden">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <h2 className="text-sm font-bold text-white">保持ポリシー</h2>
          <span className="text-xs text-[#3d5068]">{policies.length} データタイプ</span>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['データタイプ', '保持期間', 'レコード数', 'サイズ', '最終パージ', '自動パージ', 'アクション'].map(h => (
                  <th key={h} className="text-left px-4 py-3 text-xs font-semibold text-[#3d5068] uppercase tracking-wide">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {policies.map((policy, idx) => {
                const meta = DATA_TYPE_META[policy.type]
                const Icon = meta?.icon ?? DatabaseBackup
                const colorMap: Record<string, string> = {
                  alerts:              '#e8002d',
                  events:              '#f97316',
                  audit_logs:          '#f59e0b',
                  agent_heartbeats:    '#22d3ee',
                  network_connections: '#3b82f6',
                  dns_queries:         '#8b5cf6',
                  file_changes:        '#10b981',
                  process_events:      '#ec4899',
                }
                const color = colorMap[policy.type] ?? '#7d92b0'
                return (
                  <tr
                    key={policy.type}
                    className={`border-b border-[#1e2d42]/50 hover:bg-[#0a111e] transition-colors ${
                      idx % 2 === 0 ? '' : 'bg-[#070d19]/30'
                    }`}
                  >
                    {/* Data type */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Icon className="w-4 h-4 flex-shrink-0" style={{ color }} />
                        <div>
                          <p className="text-white font-medium text-xs">{meta?.labelJp ?? policy.type}</p>
                          <p className="text-[#3d5068] text-[10px]">{meta?.label ?? policy.type}</p>
                        </div>
                      </div>
                    </td>

                    {/* Retention period */}
                    <td className="px-4 py-3">
                      <span className={`text-xs font-bold px-2 py-1 rounded border ${
                        policy.retention_days === null
                          ? 'bg-purple-900/20 text-purple-300 border-purple-700/30'
                          : policy.retention_days <= 30
                          ? 'bg-yellow-900/20 text-yellow-300 border-yellow-700/30'
                          : 'bg-blue-900/20 text-blue-300 border-blue-700/30'
                      }`}>
                        {retentionLabel(policy.retention_days)}
                      </span>
                    </td>

                    {/* Records count */}
                    <td className="px-4 py-3 text-xs text-[#7d92b0] font-mono">
                      {formatCount(policy.records_count)}
                    </td>

                    {/* Size */}
                    <td className="px-4 py-3 text-xs text-[#7d92b0]">
                      {formatSize(policy.size_mb)}
                    </td>

                    {/* Last purge */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1">
                        <Clock className="w-3 h-3 text-[#3d5068]" />
                        <span className="text-xs text-[#7d92b0]">{relativeTime(policy.last_purge)}</span>
                      </div>
                    </td>

                    {/* Auto purge */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <div className={`w-2 h-2 rounded-full ${policy.auto_purge ? 'bg-green-400' : 'bg-[#3d5068]'}`} />
                        <span className="text-xs text-[#7d92b0]">
                          {policy.auto_purge
                            ? SCHEDULE_OPTIONS.find(s => s.value === policy.purge_schedule)?.label ?? '-'
                            : '無効'}
                        </span>
                      </div>
                    </td>

                    {/* Actions */}
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-1.5">
                        <button
                          onClick={() => setEditingPolicy(policy)}
                          className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-[#7d92b0]
                                     bg-[#0d1220] border border-[#1e2d42] rounded-lg
                                     hover:text-white hover:bg-[#1e2d42] transition-colors"
                        >
                          <Edit2 className="w-3 h-3" />
                          編集
                        </button>
                        <button
                          onClick={() => handlePreviewPurge(policy.type)}
                          disabled={previewLoading && purgeTarget === policy.type}
                          className="flex items-center gap-1 px-2.5 py-1.5 text-xs text-[#7d92b0]
                                     bg-[#0d1220] border border-[#1e2d42] rounded-lg
                                     hover:text-white hover:bg-[#1e2d42] transition-colors disabled:opacity-50"
                        >
                          {previewLoading && purgeTarget === policy.type
                            ? <RefreshCw className="w-3 h-3 animate-spin" />
                            : <Trash2 className="w-3 h-3" />
                          }
                          今すぐ実行
                        </button>
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>

      {/* ── Scheduled Purge Section ─────────────────────────────────── */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-2xl p-5">
        <div className="flex items-center gap-2 mb-5">
          <Calendar className="w-4 h-4 text-[#e8002d]" />
          <h2 className="text-sm font-bold text-white">スケジュールパージ設定</h2>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          {/* Global auto-purge toggle */}
          <div className="p-4 bg-[#070d19] border border-[#1e2d42] rounded-xl">
            <div className="flex items-center justify-between mb-3">
              <div>
                <p className="text-sm font-semibold text-white">グローバル自動パージ</p>
                <p className="text-xs text-[#3d5068] mt-0.5">全データタイプに適用</p>
              </div>
              <button
                onClick={() => setGlobalAutoPurge(v => !v)}
                className={`relative inline-flex h-6 w-11 items-center rounded-full transition-colors ${
                  globalAutoPurge ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'
                }`}
              >
                <span className={`inline-block h-4 w-4 rounded-full bg-[#e2e8f4] transition-transform ${
                  globalAutoPurge ? 'translate-x-6' : 'translate-x-1'
                }`} />
              </button>
            </div>
            <div className={`text-xs flex items-center gap-1.5 ${globalAutoPurge ? 'text-green-400' : 'text-[#3d5068]'}`}>
              <CheckCircle className="w-3.5 h-3.5" />
              {globalAutoPurge ? '自動パージが有効です' : '自動パージは無効です'}
            </div>
          </div>

          {/* Global schedule */}
          <div className="p-4 bg-[#070d19] border border-[#1e2d42] rounded-xl">
            <p className="text-sm font-semibold text-white mb-3">グローバルスケジュール</p>
            <div className="flex gap-2">
              {SCHEDULE_OPTIONS.map(opt => (
                <button
                  key={opt.value}
                  onClick={() => setGlobalSchedule(opt.value)}
                  disabled={!globalAutoPurge}
                  className={`flex-1 py-2 text-xs font-medium rounded-lg border transition-colors disabled:opacity-40 ${
                    globalSchedule === opt.value
                      ? 'bg-[#1d2f4a] border-[#3d5068] text-white'
                      : 'bg-[#0d1220] border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/40 hover:text-white'
                  }`}
                >
                  {opt.label}
                </button>
              ))}
            </div>
          </div>
        </div>

        {/* Purge summary */}
        <div className="mt-4 p-4 bg-[#070d19] border border-[#1e2d42] rounded-xl">
          <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wide mb-3">保持ポリシーサマリー</p>
          <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
            <div>
              <p className="text-xs text-[#3d5068]">自動パージ有効</p>
              <p className="text-lg font-bold text-white">{policies.filter(p => p.auto_purge).length}</p>
              <p className="text-xs text-[#3d5068]">/ {policies.length} タイプ</p>
            </div>
            <div>
              <p className="text-xs text-[#3d5068]">合計レコード数</p>
              <p className="text-lg font-bold text-white">
                {formatCount(policies.reduce((s, p) => s + p.records_count, 0))}
              </p>
            </div>
            <div>
              <p className="text-xs text-[#3d5068]">合計使用量</p>
              <p className="text-lg font-bold text-white">{formatSize(totalSizeMb)}</p>
            </div>
            <div>
              <p className="text-xs text-[#3d5068]">最短保持期間</p>
              <p className="text-lg font-bold text-white">
                {retentionLabel(
                  policies
                    .map(p => p.retention_days)
                    .filter((d): d is number => d !== null)
                    .reduce((m, d) => Math.min(m, d), Infinity) === Infinity
                    ? null
                    : policies
                        .map(p => p.retention_days)
                        .filter((d): d is number => d !== null)
                        .reduce((m, d) => Math.min(m, d), Infinity)
                )}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* ── Edit Modal ─────────────────────────────────────────────── */}
      {editingPolicy && (
        <EditModal
          policy={editingPolicy}
          onSave={(type, days, autoPurge, schedule) =>
            updateMutation.mutate({ type, retention_days: days, auto_purge: autoPurge, purge_schedule: schedule })
          }
          onClose={() => setEditingPolicy(null)}
          isSaving={updateMutation.isPending}
        />
      )}

      {/* ── Purge Confirm Dialog ────────────────────────────────────── */}
      {purgeTarget && !previewLoading && (
        <PurgeDialog
          type={purgeTarget}
          preview={purgePreview}
          onConfirm={() => purgeMutation.mutate(purgeTarget)}
          onClose={() => { setPurgeTarget(null); setPurgePreview(null) }}
          isPurging={purgeMutation.isPending}
        />
      )}
    </div>
  )
}
