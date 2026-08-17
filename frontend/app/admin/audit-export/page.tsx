'use client'

import { useState } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  FileInput, Download, Calendar, Settings2, Clock,
  Database, BarChart2, ArrowUp, Archive, HardDrive,
} from 'lucide-react'

// ─── Types ───────────────────────────────────────────────────────────────────

interface ExportHistoryEntry {
  id: string
  file_name: string
  start_date: string
  end_date: string
  record_count: number
  file_size_bytes: number
  format: string
  created_at: string
  download_url?: string
}

interface ExportHistoryResponse {
  exports: ExportHistoryEntry[]
}

interface ArchiveConfig {
  enabled: boolean
  frequency: 'daily' | 'weekly' | 'monthly'
  retention_days: number
  storage: 'local' | 's3'
  s3_bucket?: string
  s3_prefix?: string
}

// ─── Constants ────────────────────────────────────────────────────────────────

const EVENT_TYPES = [
  { value: 'login',            label: 'ログイン' },
  { value: 'logout',           label: 'ログアウト' },
  { value: 'alert_update',     label: 'アラート更新' },
  { value: 'rule_change',      label: 'ルール変更' },
  { value: 'user_management',  label: 'ユーザー管理' },
  { value: 'system',           label: 'システム' },
]

const RETENTION_OPTIONS = [
  { value: 30,  label: '30日' },
  { value: 90,  label: '90日' },
  { value: 180, label: '180日' },
  { value: 365, label: '365日' },
]

// ─── Helpers ─────────────────────────────────────────────────────────────────

function formatBytes(bytes: number): string {
  if (bytes < 1024) return `${bytes} B`
  if (bytes < 1024 * 1024) return `${(bytes / 1024).toFixed(1)} KB`
  if (bytes < 1024 * 1024 * 1024) return `${(bytes / 1024 / 1024).toFixed(1)} MB`
  return `${(bytes / 1024 / 1024 / 1024).toFixed(2)} GB`
}

function formatDate(iso: string): string {
  return new Date(iso).toLocaleString('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

function todayStr(): string {
  return new Date().toISOString().slice(0, 10)
}

function thirtyDaysAgoStr(): string {
  const d = new Date()
  d.setDate(d.getDate() - 30)
  return d.toISOString().slice(0, 10)
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function AuditExportPage() {
  // Export Now state
  const [startDate, setStartDate] = useState(thirtyDaysAgoStr())
  const [endDate, setEndDate] = useState(todayStr())
  const [exportFormat, setExportFormat] = useState<'json' | 'csv' | 'cef'>('csv')
  const [selectedEvents, setSelectedEvents] = useState<string[]>([])
  const [actorFilter, setActorFilter] = useState('')
  const [exportError, setExportError] = useState('')

  // Archive config state
  const [archiveEnabled, setArchiveEnabled] = useState(false)
  const [frequency, setFrequency] = useState<'daily' | 'weekly' | 'monthly'>('weekly')
  const [retentionDays, setRetentionDays] = useState(90)
  const [storage, setStorage] = useState<'local' | 's3'>('local')
  const [s3Bucket, setS3Bucket] = useState('')
  const [s3Prefix, setS3Prefix] = useState('audit-logs/')
  const [configSaved, setConfigSaved] = useState(false)
  const [configError, setConfigError] = useState('')

  // ── Queries ──────────────────────────────────────────────────────────────

  const { data: historyData, isLoading: historyLoading } = useQuery<ExportHistoryResponse>({
    queryKey: ['audit-export-history'],
    queryFn: () => apiFetch('/api/v1/audit/export-history'),
  })

  const exports = historyData?.exports ?? []

  // ── Mutations ────────────────────────────────────────────────────────────

  const saveConfigMutation = useMutation({
    mutationFn: (body: ArchiveConfig) =>
      apiFetch('/api/v1/admin/audit/archive-config', {
        method: 'PUT',
        body: JSON.stringify(body),
      }),
    onSuccess: () => {
      setConfigSaved(true)
      setConfigError('')
      setTimeout(() => setConfigSaved(false), 3000)
    },
    onError: () => setConfigError('設定の保存に失敗しました'),
  })

  // ── Handlers ─────────────────────────────────────────────────────────────

  const handleExport = () => {
    setExportError('')
    if (!startDate || !endDate) {
      setExportError('開始日と終了日を入力してください')
      return
    }
    if (new Date(startDate) > new Date(endDate)) {
      setExportError('開始日は終了日より前である必要があります')
      return
    }

    const params = new URLSearchParams({
      start: startDate,
      end: endDate,
      format: exportFormat,
    })
    if (actorFilter.trim()) params.set('actor', actorFilter.trim())
    if (selectedEvents.length > 0) params.set('event_types', selectedEvents.join(','))

    const ext = exportFormat === 'json' ? 'json' : exportFormat === 'cef' ? 'txt' : 'csv'
    const a = document.createElement('a')
    a.href = `/api/v1/audit/export?${params.toString()}`
    a.download = `audit-export-${startDate}_${endDate}.${ext}`
    a.click()
  }

  const toggleEvent = (value: string) => {
    setSelectedEvents(prev =>
      prev.includes(value) ? prev.filter(v => v !== value) : [...prev, value]
    )
  }

  const handleSaveConfig = () => {
    setConfigError('')
    if (storage === 's3' && !s3Bucket.trim()) {
      setConfigError('S3バケット名を入力してください')
      return
    }
    saveConfigMutation.mutate({
      enabled: archiveEnabled,
      frequency,
      retention_days: retentionDays,
      storage,
      s3_bucket: storage === 's3' ? s3Bucket.trim() : undefined,
      s3_prefix: storage === 's3' ? s3Prefix.trim() : undefined,
    })
  }

  // ── Stats (computed from mock history) ───────────────────────────────────

  const now = new Date()
  const thisMonthExports = exports.filter(e => {
    const d = new Date(e.created_at)
    return d.getFullYear() === now.getFullYear() && d.getMonth() === now.getMonth()
  })
  const lastMonthExports = exports.filter(e => {
    const d = new Date(e.created_at)
    const lm = new Date(now.getFullYear(), now.getMonth() - 1, 1)
    return d.getFullYear() === lm.getFullYear() && d.getMonth() === lm.getMonth()
  })
  const thisMonthRecords = thisMonthExports.reduce((s, e) => s + e.record_count, 0)
  const lastMonthRecords = lastMonthExports.reduce((s, e) => s + e.record_count, 0)
  const totalArchives = exports.length
  const totalBytes = exports.reduce((s, e) => s + e.file_size_bytes, 0)
  const monthDelta = lastMonthRecords > 0
    ? Math.round(((thisMonthRecords - lastMonthRecords) / lastMonthRecords) * 100)
    : 0

  // ── Render ───────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">

      {/* Header */}
      <div className="flex items-center gap-3">
        <div className="w-8 h-8 rounded-sm bg-falcon-red/10 border border-falcon-red/30 flex items-center justify-center">
          <FileInput className="w-4 h-4 text-falcon-red" />
        </div>
        <div>
          <h1 className="text-xl font-bold text-white">監査ログエクスポート</h1>
          <p className="text-falcon-muted text-sm">監査ログの手動エクスポートと自動アーカイブスケジュールを管理します</p>
        </div>
      </div>

      {/* Stats cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <BarChart2 className="w-4 h-4 text-falcon-red" />
            <span className="text-xs text-falcon-muted">今月のログ件数</span>
          </div>
          <p className="text-2xl font-bold text-white">{thisMonthRecords.toLocaleString()}</p>
        </div>
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <ArrowUp className={`w-4 h-4 ${monthDelta >= 0 ? 'text-green-400' : 'text-red-400'}`} />
            <span className="text-xs text-falcon-muted">先月比</span>
          </div>
          <p className={`text-2xl font-bold ${monthDelta >= 0 ? 'text-green-400' : 'text-red-400'}`}>
            {monthDelta >= 0 ? '+' : ''}{monthDelta}%
          </p>
        </div>
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <Archive className="w-4 h-4 text-blue-400" />
            <span className="text-xs text-falcon-muted">保存済みアーカイブ数</span>
          </div>
          <p className="text-2xl font-bold text-white">{totalArchives}</p>
        </div>
        <div className="bg-falcon-surface border border-falcon-border rounded-lg p-4">
          <div className="flex items-center gap-2 mb-2">
            <HardDrive className="w-4 h-4 text-purple-400" />
            <span className="text-xs text-falcon-muted">総容量</span>
          </div>
          <p className="text-2xl font-bold text-white">{formatBytes(totalBytes)}</p>
        </div>
      </div>

      {/* Export Now panel */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-falcon-border flex items-center gap-2">
          <Download className="w-4 h-4 text-falcon-red" />
          <h2 className="text-sm font-semibold text-white">今すぐエクスポート</h2>
        </div>
        <div className="p-5 space-y-5">

          {/* Date range */}
          <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
            <div>
              <label className="block text-xs font-medium text-falcon-muted mb-1.5">
                <Calendar className="inline w-3 h-3 mr-1" />
                開始日
              </label>
              <input
                type="date"
                value={startDate}
                onChange={e => setStartDate(e.target.value)}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50 scheme-dark"
              />
            </div>
            <div>
              <label className="block text-xs font-medium text-falcon-muted mb-1.5">
                <Calendar className="inline w-3 h-3 mr-1" />
                終了日
              </label>
              <input
                type="date"
                value={endDate}
                onChange={e => setEndDate(e.target.value)}
                className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50 scheme-dark"
              />
            </div>
          </div>

          {/* Format */}
          <div>
            <label className="block text-xs font-medium text-falcon-muted mb-2">フォーマット</label>
            <div className="flex gap-2">
              {([
                { value: 'json', label: 'JSON', desc: '汎用JSON' },
                { value: 'csv',  label: 'CSV',  desc: 'Excel対応CSV' },
                { value: 'cef',  label: 'SIEM (CEF)', desc: 'Splunk/ArcSight' },
              ] as const).map(f => (
                <button
                  key={f.value}
                  type="button"
                  onClick={() => setExportFormat(f.value)}
                  className={`px-4 py-2 rounded border text-xs font-medium transition-colors ${
                    exportFormat === f.value
                      ? 'bg-falcon-red border-falcon-red text-white'
                      : 'bg-[#070d19] border-falcon-border text-falcon-muted hover:border-falcon-muted/40 hover:text-white'
                  }`}
                >
                  <span className="font-semibold">{f.label}</span>
                  <span className="block text-[10px] opacity-70">{f.desc}</span>
                </button>
              ))}
            </div>
          </div>

          {/* Event types */}
          <div>
            <label className="block text-xs font-medium text-falcon-muted mb-2">
              イベントタイプ
              <span className="ml-2 text-falcon-subtle font-normal">(未選択 = すべて)</span>
            </label>
            <div className="flex flex-wrap gap-2">
              {EVENT_TYPES.map(et => {
                const checked = selectedEvents.includes(et.value)
                return (
                  <label
                    key={et.value}
                    className={`flex items-center gap-2 px-3 py-1.5 rounded border cursor-pointer text-xs transition-colors ${
                      checked
                        ? 'bg-falcon-red/10 border-falcon-red/40 text-falcon-red'
                        : 'bg-[#070d19] border-falcon-border text-falcon-muted hover:border-falcon-muted/40 hover:text-white'
                    }`}
                  >
                    <input
                      type="checkbox"
                      checked={checked}
                      onChange={() => toggleEvent(et.value)}
                      className="sr-only"
                    />
                    <span className={`w-3 h-3 rounded-xs border flex items-center justify-center shrink-0 ${
                      checked ? 'bg-falcon-red border-falcon-red' : 'border-falcon-border'
                    }`}>
                      {checked && (
                        <svg viewBox="0 0 12 12" className="w-2.5 h-2.5 text-white fill-current">
                          <path d="M10 3L5 8.5 2 5.5" stroke="currentColor" strokeWidth="1.5" fill="none" strokeLinecap="round" strokeLinejoin="round" />
                        </svg>
                      )}
                    </span>
                    {et.label}
                  </label>
                )
              })}
            </div>
          </div>

          {/* Actor filter */}
          <div>
            <label className="block text-xs font-medium text-falcon-muted mb-1.5">
              アクターフィルター
              <span className="ml-2 text-falcon-subtle font-normal">(メール / ユーザーID)</span>
            </label>
            <input
              type="text"
              value={actorFilter}
              onChange={e => setActorFilter(e.target.value)}
              placeholder="admin@example.com"
              className="w-full max-w-sm bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
            />
          </div>

          {exportError && (
            <p className="text-xs text-falcon-red">{exportError}</p>
          )}

          <div className="flex justify-end pt-1">
            <button
              onClick={handleExport}
              className="flex items-center gap-2 px-5 py-2.5 bg-falcon-red hover:bg-[#c8001f] text-white text-sm font-medium rounded-sm transition-colors"
            >
              <Download className="w-4 h-4" />
              エクスポート
            </button>
          </div>
        </div>
      </div>

      {/* Auto-Archive Schedule panel */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-falcon-border flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Clock className="w-4 h-4 text-blue-400" />
            <h2 className="text-sm font-semibold text-white">自動アーカイブスケジュール</h2>
          </div>
          {/* Enable toggle */}
          <div className="flex items-center gap-2">
            <span className="text-xs text-falcon-muted">{archiveEnabled ? '有効' : '無効'}</span>
            <button
              type="button"
              onClick={() => setArchiveEnabled(v => !v)}
              className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
                archiveEnabled ? 'bg-falcon-red' : 'bg-falcon-border'
              }`}
            >
              <span className={`inline-block h-3.5 w-3.5 transform rounded-full bg-falcon-text transition-transform ${
                archiveEnabled ? 'translate-x-4' : 'translate-x-1'
              }`} />
            </button>
          </div>
        </div>

        <div className={`p-5 space-y-5 transition-opacity ${archiveEnabled ? 'opacity-100' : 'opacity-40 pointer-events-none'}`}>

          {/* Frequency */}
          <div>
            <label className="block text-xs font-medium text-falcon-muted mb-2">頻度</label>
            <div className="flex gap-2">
              {([
                { value: 'daily',   label: '毎日' },
                { value: 'weekly',  label: '毎週' },
                { value: 'monthly', label: '毎月' },
              ] as const).map(f => (
                <button
                  key={f.value}
                  type="button"
                  onClick={() => setFrequency(f.value)}
                  className={`px-4 py-2 rounded border text-sm font-medium transition-colors ${
                    frequency === f.value
                      ? 'bg-falcon-red border-falcon-red text-white'
                      : 'bg-[#070d19] border-falcon-border text-falcon-muted hover:border-falcon-muted/40 hover:text-white'
                  }`}
                >
                  {f.label}
                </button>
              ))}
            </div>
          </div>

          {/* Retention */}
          <div>
            <label className="block text-xs font-medium text-falcon-muted mb-2">保持期間</label>
            <div className="flex gap-2 flex-wrap">
              {RETENTION_OPTIONS.map(r => (
                <button
                  key={r.value}
                  type="button"
                  onClick={() => setRetentionDays(r.value)}
                  className={`px-4 py-2 rounded border text-sm font-medium transition-colors ${
                    retentionDays === r.value
                      ? 'bg-falcon-red border-falcon-red text-white'
                      : 'bg-[#070d19] border-falcon-border text-falcon-muted hover:border-falcon-muted/40 hover:text-white'
                  }`}
                >
                  {r.label}
                </button>
              ))}
            </div>
          </div>

          {/* Storage */}
          <div>
            <label className="block text-xs font-medium text-falcon-muted mb-2">
              <Settings2 className="inline w-3 h-3 mr-1" />
              ストレージ
            </label>
            <div className="flex gap-2 mb-3">
              {([
                { value: 'local', label: 'ローカル', icon: '💾' },
                { value: 's3',    label: 'Amazon S3', icon: '☁️' },
              ] as const).map(s => (
                <button
                  key={s.value}
                  type="button"
                  onClick={() => setStorage(s.value)}
                  className={`flex items-center gap-2 px-4 py-2 rounded border text-sm font-medium transition-colors ${
                    storage === s.value
                      ? 'bg-falcon-red border-falcon-red text-white'
                      : 'bg-[#070d19] border-falcon-border text-falcon-muted hover:border-falcon-muted/40 hover:text-white'
                  }`}
                >
                  <span>{s.icon}</span>
                  {s.label}
                </button>
              ))}
            </div>

            {/* S3 config */}
            {storage === 's3' && (
              <div className="space-y-3 pl-1">
                <div>
                  <label className="block text-xs font-medium text-falcon-muted mb-1.5">
                    S3バケット名 <span className="text-falcon-red">*</span>
                  </label>
                  <input
                    type="text"
                    value={s3Bucket}
                    onChange={e => setS3Bucket(e.target.value)}
                    placeholder="my-audit-logs-bucket"
                    className="w-full max-w-sm bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white font-mono placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
                  />
                </div>
                <div>
                  <label className="block text-xs font-medium text-falcon-muted mb-1.5">プレフィックス</label>
                  <input
                    type="text"
                    value={s3Prefix}
                    onChange={e => setS3Prefix(e.target.value)}
                    placeholder="audit-logs/"
                    className="w-full max-w-sm bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white font-mono placeholder-falcon-subtle focus:outline-hidden focus:border-falcon-red/50"
                  />
                </div>
              </div>
            )}
          </div>

          {configError && (
            <p className="text-xs text-falcon-red">{configError}</p>
          )}
          {configSaved && (
            <p className="text-xs text-green-400">設定を保存しました</p>
          )}

          <div className="flex justify-end pt-1">
            <button
              onClick={handleSaveConfig}
              disabled={saveConfigMutation.isPending}
              className="flex items-center gap-2 px-5 py-2.5 bg-falcon-red hover:bg-[#c8001f] text-white text-sm font-medium rounded-sm transition-colors disabled:opacity-50"
            >
              <Database className="w-4 h-4" />
              {saveConfigMutation.isPending ? '保存中...' : '設定を保存'}
            </button>
          </div>
        </div>

        {/* Disabled overlay message */}
        {!archiveEnabled && (
          <div className="px-5 pb-4 text-xs text-falcon-subtle">
            自動アーカイブを使用するには上部のトグルで有効にしてください。
          </div>
        )}
      </div>

      {/* Recent Exports table */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg overflow-hidden">
        <div className="px-5 py-4 border-b border-falcon-border flex items-center gap-2">
          <Archive className="w-4 h-4 text-falcon-muted" />
          <h2 className="text-sm font-semibold text-white">最近のエクスポート</h2>
          <span className="ml-auto text-xs text-falcon-muted">{exports.length} 件</span>
        </div>

        {historyLoading ? (
          <div className="p-8 text-center text-falcon-muted text-sm">読み込み中...</div>
        ) : exports.length === 0 ? (
          <div className="p-12 text-center">
            <Archive className="w-10 h-10 text-falcon-border mx-auto mb-3" />
            <p className="text-falcon-muted text-sm">エクスポート履歴がありません</p>
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">ファイル名</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">期間</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">件数</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">サイズ</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">作成日</th>
                  <th className="px-4 py-3 text-left text-xs font-medium text-falcon-muted uppercase tracking-wider">ダウンロード</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-falcon-border">
                {exports.map(entry => (
                  <tr key={entry.id} className="hover:bg-[#0a1628] transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className="text-xs px-1.5 py-0.5 rounded-sm bg-[#070d19] border border-falcon-border text-falcon-muted font-mono shrink-0">
                          {entry.format}
                        </span>
                        <span className="text-xs font-mono text-falcon-text truncate max-w-[240px]" title={entry.file_name}>
                          {entry.file_name}
                        </span>
                      </div>
                    </td>
                    <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">
                      {entry.start_date} 〜 {entry.end_date}
                    </td>
                    <td className="px-4 py-3 text-sm text-white font-medium">
                      {(entry.record_count ?? 0).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-xs text-falcon-muted">
                      {formatBytes(entry.file_size_bytes)}
                    </td>
                    <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">
                      {formatDate(entry.created_at)}
                    </td>
                    <td className="px-4 py-3">
                      {entry.download_url ? (
                        <a
                          href={entry.download_url}
                          download
                          className="flex items-center gap-1.5 text-xs text-falcon-muted hover:text-falcon-red transition-colors px-2 py-1 rounded-sm hover:bg-falcon-red/10"
                        >
                          <Download className="w-3.5 h-3.5" />
                          DL
                        </a>
                      ) : (
                        <span className="text-xs text-falcon-subtle">—</span>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}
