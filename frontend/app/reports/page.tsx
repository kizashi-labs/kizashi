'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { useCanWrite } from '@/lib/auth'
import {
  Download,
  FileText,
  Calendar,
  Clock,
  Trash2,
  Plus,
  RefreshCw,
  BarChart2,
  Shield,
  Eye,
  X,
  ChevronRight,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface ReportSchedule {
  id: string
  name: string
  report_type: string
  schedule: string        // cron expression
  next_run: string
  last_run: string | null
  enabled: boolean
}

interface ScheduleCreatePayload {
  name: string
  report_type: string
  schedule: string
  enabled: boolean
}

// ─── Constants ────────────────────────────────────────────────────────────────

const SEVERITY_OPTIONS = [
  { value: '',         label: 'すべての深刻度' },
  { value: 'critical', label: 'クリティカル' },
  { value: 'high',     label: '高' },
  { value: 'medium',   label: '中' },
  { value: 'low',      label: '低' },
]

const FRAMEWORK_OPTIONS = [
  { value: 'CIS',   label: 'CIS' },
  { value: 'NIST',  label: 'NIST' },
  { value: 'SOC2',  label: 'SOC2' },
]

const REPORT_TYPE_OPTIONS = [
  { value: 'alerts',     label: 'アラート' },
  { value: 'compliance', label: 'コンプライアンス' },
  { value: 'summary',    label: 'サマリー' },
]

const CRON_PRESETS = [
  { label: '毎日 (深夜0時)',    value: '0 0 * * *' },
  { label: '毎週月曜 (深夜0時)', value: '0 0 * * 1' },
  { label: '毎月1日 (深夜0時)', value: '0 0 1 * *' },
]

const TYPE_BADGES: Record<string, string> = {
  alerts:     'bg-orange-900/40 text-orange-300',
  compliance: 'bg-blue-900/40 text-blue-300',
  summary:    'bg-purple-900/40 text-purple-300',
}

const TYPE_LABELS: Record<string, string> = {
  alerts:     'アラート',
  compliance: 'コンプライアンス',
  summary:    'サマリー',
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function humanCron(cron: string): string {
  if (cron === '0 0 * * *') return '毎日'
  if (cron === '0 0 * * 1') return '毎週'
  if (cron === '0 0 1 * *') return '毎月'
  return cron
}

function formatDateTime(iso: string | null): string {
  if (!iso) return '—'
  return new Date(iso).toLocaleString('ja-JP', {
    year: 'numeric', month: '2-digit', day: '2-digit',
    hour: '2-digit', minute: '2-digit',
  })
}

function defaultSince(): string {
  const d = new Date()
  d.setDate(d.getDate() - 7)
  // datetime-local format: YYYY-MM-DDTHH:mm
  return d.toISOString().slice(0, 16)
}

function defaultUntil(): string {
  return new Date().toISOString().slice(0, 16)
}

async function downloadViaAnchor(url: string, filename: string) {
  const token = typeof window !== 'undefined' ? localStorage.getItem('edr_token') : null
  const res = await fetch(url, {
    headers: token ? { Authorization: `Bearer ${token}` } : {},
  })
  if (!res.ok) {
    alert(`ダウンロードに失敗しました (${res.status})`)
    return
  }
  const blob = await res.blob()
  const blobUrl = URL.createObjectURL(blob)
  const a = document.createElement('a')
  a.href = blobUrl
  a.download = filename
  document.body.appendChild(a)
  a.click()
  document.body.removeChild(a)
  URL.revokeObjectURL(blobUrl)
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function SectionTitle({ children }: { children: React.ReactNode }) {
  return (
    <h2 className="text-white text-lg font-semibold mb-4">{children}</h2>
  )
}

function Label({ children }: { children: React.ReactNode }) {
  return (
    <label className="block text-sm text-gray-400 mb-1">{children}</label>
  )
}

function InputBase({ className = '', ...props }: React.InputHTMLAttributes<HTMLInputElement>) {
  return (
    <input
      {...props}
      className={`w-full bg-gray-900 border border-gray-700 text-white text-sm rounded-lg px-3 py-2
                  focus:outline-none focus:border-blue-500 placeholder-gray-600 ${className}`}
    />
  )
}

function SelectBase({ className = '', children, ...props }: React.SelectHTMLAttributes<HTMLSelectElement>) {
  return (
    <select
      {...props}
      className={`w-full bg-gray-900 border border-gray-700 text-white text-sm rounded-lg px-3 py-2
                  focus:outline-none focus:border-blue-500 ${className}`}
    >
      {children}
    </select>
  )
}

// ─── Alert Export Card ─────────────────────────────────────────────────────────

function AlertExportCard() {
  const [since, setSince] = useState(defaultSince)
  const [until, setUntil] = useState(defaultUntil)
  const [severity, setSeverity] = useState('')

  function handleDownload() {
    const sinceISO = new Date(since).toISOString()
    const untilISO = new Date(until).toISOString()
    const params = new URLSearchParams({
      since: sinceISO,
      until: untilISO,
      format: 'csv',
    })
    if (severity) params.set('severity', severity)
    const url = `/api/v1/reports/export/alerts?${params.toString()}`
    downloadViaAnchor(url, `alerts_${sinceISO.slice(0, 10)}_${untilISO.slice(0, 10)}.csv`)
  }

  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 p-5 flex flex-col gap-4">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-orange-900/30">
          <BarChart2 className="w-5 h-5 text-orange-400" />
        </div>
        <div>
          <h3 className="text-white font-medium">アラートレポート</h3>
          <p className="text-gray-500 text-xs mt-0.5">期間・深刻度でフィルタしてCSVダウンロード</p>
        </div>
      </div>

      <div className="grid grid-cols-2 gap-3">
        <div>
          <Label>開始日時</Label>
          <InputBase
            type="datetime-local"
            value={since}
            onChange={e => setSince(e.target.value)}
          />
        </div>
        <div>
          <Label>終了日時</Label>
          <InputBase
            type="datetime-local"
            value={until}
            onChange={e => setUntil(e.target.value)}
          />
        </div>
      </div>

      <div>
        <Label>深刻度</Label>
        <SelectBase value={severity} onChange={e => setSeverity(e.target.value)}>
          {SEVERITY_OPTIONS.map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </SelectBase>
      </div>

      <div>
        <Label>フォーマット</Label>
        <div className="flex items-center gap-2 px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-400">
          <FileText className="w-4 h-4" />
          CSV
        </div>
      </div>

      <button
        onClick={handleDownload}
        className="mt-auto flex items-center justify-center gap-2 w-full px-4 py-2.5
                   bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium
                   transition-colors"
      >
        <Download className="w-4 h-4" />
        ダウンロード
      </button>
    </div>
  )
}

// ─── Compliance Export Card ────────────────────────────────────────────────────

function ComplianceExportCard() {
  const [framework, setFramework] = useState('CIS')

  function handleDownload() {
    const params = new URLSearchParams({ framework, format: 'csv' })
    const url = `/api/v1/reports/export/compliance?${params.toString()}`
    downloadViaAnchor(url, `compliance_${framework}.csv`)
  }

  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 p-5 flex flex-col gap-4">
      <div className="flex items-center gap-3">
        <div className="p-2 rounded-lg bg-blue-900/30">
          <Shield className="w-5 h-5 text-blue-400" />
        </div>
        <div>
          <h3 className="text-white font-medium">コンプライアンスレポート</h3>
          <p className="text-gray-500 text-xs mt-0.5">フレームワーク別にCSVダウンロード</p>
        </div>
      </div>

      <div>
        <Label>フレームワーク</Label>
        <SelectBase value={framework} onChange={e => setFramework(e.target.value)}>
          {FRAMEWORK_OPTIONS.map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </SelectBase>
      </div>

      <div>
        <Label>フォーマット</Label>
        <div className="flex items-center gap-2 px-3 py-2 bg-gray-900 border border-gray-700 rounded-lg text-sm text-gray-400">
          <FileText className="w-4 h-4" />
          CSV
        </div>
      </div>

      {/* Spacer to align button with alert card */}
      <div className="flex-1" />

      <button
        onClick={handleDownload}
        className="flex items-center justify-center gap-2 w-full px-4 py-2.5
                   bg-blue-600 hover:bg-blue-500 text-white rounded-lg text-sm font-medium
                   transition-colors"
      >
        <Download className="w-4 h-4" />
        ダウンロード
      </button>
    </div>
  )
}

// ─── Generated Reports ────────────────────────────────────────────────────────

interface GeneratedReport {
  id: string
  type: string
  status: 'completed' | 'pending' | 'failed'
  requested_by_name?: string
  requested_at: string
  completed_at?: string
  download_url?: string
}

function ReportPreviewModal({ report, onClose }: { report: GeneratedReport; onClose: () => void }) {
  const typeLabel = TYPE_LABELS[report.type] ?? report.type
  const typeBadge = TYPE_BADGES[report.type] ?? 'bg-gray-700 text-gray-300'
  const generatedAt = report.completed_at ?? report.requested_at

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-2xl w-full max-w-2xl max-h-[90vh] flex flex-col shadow-2xl">
        <div className="flex items-start justify-between gap-4 p-5 border-b border-[#1e2d42]">
          <div className="flex items-start gap-3 min-w-0">
            <div className={`p-2 rounded-lg shrink-0 ${
              report.type === 'alerts' ? 'bg-orange-900/30' :
              report.type === 'compliance' ? 'bg-blue-900/30' : 'bg-purple-900/30'
            }`}>
              <FileText className={`w-4 h-4 ${
                report.type === 'alerts' ? 'text-orange-400' :
                report.type === 'compliance' ? 'text-blue-400' : 'text-purple-400'
              }`} />
            </div>
            <div className="min-w-0">
              <h2 className="text-white font-semibold text-sm">{typeLabel}レポート</h2>
              <div className="flex items-center gap-2 mt-0.5">
                <span className={`text-xs px-1.5 py-0.5 rounded-full font-medium ${typeBadge}`}>{typeLabel}</span>
                <span className="text-xs text-gray-500">{formatDateTime(generatedAt)}</span>
              </div>
            </div>
          </div>
          <button onClick={onClose} className="text-gray-500 hover:text-white transition-colors shrink-0">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="overflow-y-auto flex-1 p-5 space-y-4">
          <div className="bg-[#070d19] border border-[#1e2d42] rounded-xl p-4 space-y-2 text-sm text-gray-300">
            <div className="flex items-center gap-2">
              <Calendar className="w-4 h-4 text-gray-500" />
              <span>生成日時: {formatDateTime(generatedAt)}</span>
            </div>
            {report.requested_by_name && (
              <div className="flex items-center gap-2">
                <ChevronRight className="w-4 h-4 text-gray-500" />
                <span>依頼者: {report.requested_by_name}</span>
              </div>
            )}
            <div className="flex items-center gap-2">
              <ChevronRight className="w-4 h-4 text-gray-500" />
              <span>ステータス: {report.status === 'completed' ? '完了' : report.status === 'pending' ? '生成中' : '失敗'}</span>
            </div>
          </div>
          <div className="text-center text-xs text-gray-600 py-2">完全なレポートはダウンロードしてご確認ください</div>
        </div>

        <div className="flex gap-2 p-4 border-t border-[#1e2d42]">
          {report.download_url && (
            <button
              onClick={() => downloadViaAnchor(report.download_url!, `report_${report.id}.pdf`)}
              className="flex-1 flex items-center justify-center gap-2 py-2.5 bg-blue-700 hover:bg-blue-600 text-white text-sm rounded-xl transition-colors"
            >
              <Download className="w-4 h-4" />ダウンロード
            </button>
          )}
          <button onClick={onClose} className="px-4 py-2.5 bg-gray-800 hover:bg-gray-700 text-gray-400 text-sm rounded-xl transition-colors border border-gray-700">
            閉じる
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Schedule Form (inline) ────────────────────────────────────────────────────

interface ScheduleFormProps {
  onSubmit: (payload: ScheduleCreatePayload) => void
  onCancel: () => void
  isPending: boolean
}

function ScheduleForm({ onSubmit, onCancel, isPending }: ScheduleFormProps) {
  const [name, setName] = useState('')
  const [reportType, setReportType] = useState('alerts')
  const [schedule, setSchedule] = useState('0 0 * * *')
  const [customCron, setCustomCron] = useState(false)
  const [enabled, setEnabled] = useState(true)

  function handlePreset(value: string) {
    setSchedule(value)
    setCustomCron(false)
  }

  function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!name.trim()) return
    onSubmit({ name: name.trim(), report_type: reportType, schedule, enabled })
  }

  return (
    <form
      onSubmit={handleSubmit}
      className="bg-gray-900 border border-gray-700 rounded-xl p-5 space-y-4"
    >
      <h3 className="text-white font-medium flex items-center gap-2">
        <Plus className="w-4 h-4 text-blue-400" />
        新しいスケジュールを追加
      </h3>

      <div>
        <Label>名前</Label>
        <InputBase
          placeholder="例: 週次アラートレポート"
          value={name}
          onChange={e => setName(e.target.value)}
          required
        />
      </div>

      <div>
        <Label>レポートタイプ</Label>
        <SelectBase value={reportType} onChange={e => setReportType(e.target.value)}>
          {REPORT_TYPE_OPTIONS.map(o => (
            <option key={o.value} value={o.value}>{o.label}</option>
          ))}
        </SelectBase>
      </div>

      <div>
        <Label>スケジュール</Label>
        <div className="flex flex-wrap gap-2 mb-2">
          {CRON_PRESETS.map(p => (
            <button
              key={p.value}
              type="button"
              onClick={() => handlePreset(p.value)}
              className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
                schedule === p.value && !customCron
                  ? 'bg-blue-600 text-white'
                  : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
              }`}
            >
              {p.label}
            </button>
          ))}
          <button
            type="button"
            onClick={() => setCustomCron(true)}
            className={`px-3 py-1.5 rounded-lg text-xs font-medium transition-colors ${
              customCron
                ? 'bg-blue-600 text-white'
                : 'bg-gray-700 text-gray-300 hover:bg-gray-600'
            }`}
          >
            カスタム
          </button>
        </div>
        {customCron && (
          <InputBase
            placeholder="cron式 例: 0 9 * * 1-5"
            value={schedule}
            onChange={e => setSchedule(e.target.value)}
            className="font-mono"
          />
        )}
        {!customCron && (
          <p className="text-gray-500 text-xs font-mono mt-1">{schedule}</p>
        )}
      </div>

      <div className="flex items-center gap-3">
        <button
          type="button"
          onClick={() => setEnabled(v => !v)}
          className={`relative inline-flex h-5 w-9 items-center rounded-full transition-colors ${
            enabled ? 'bg-blue-600' : 'bg-gray-600'
          }`}
          aria-label="有効化"
        >
          <span
            className={`inline-block h-4 w-4 transform rounded-full bg-[#e2e8f4] shadow transition-transform ${
              enabled ? 'translate-x-4' : 'translate-x-0.5'
            }`}
          />
        </button>
        <span className="text-gray-400 text-sm">{enabled ? '有効' : '無効'}</span>
      </div>

      <div className="flex gap-3 pt-1">
        <button
          type="submit"
          disabled={isPending || !name.trim()}
          className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500 text-white
                     rounded-lg text-sm font-medium transition-colors disabled:opacity-50"
        >
          {isPending && (
            <RefreshCw className="w-4 h-4 animate-spin" />
          )}
          保存
        </button>
        <button
          type="button"
          onClick={onCancel}
          className="px-4 py-2 bg-gray-700 hover:bg-gray-600 text-gray-300 rounded-lg text-sm transition-colors"
        >
          キャンセル
        </button>
      </div>
    </form>
  )
}

// ─── Schedule Card ─────────────────────────────────────────────────────────────

interface ScheduleCardProps {
  schedule: ReportSchedule
  onDelete: (id: string) => void
  isDeleting: boolean
  canWrite?: boolean
}

function ScheduleCard({ schedule, onDelete, isDeleting, canWrite = true }: ScheduleCardProps) {
  const [confirmDelete, setConfirmDelete] = useState(false)

  return (
    <div className="bg-gray-800 rounded-xl border border-gray-700 p-4 flex flex-col gap-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex items-center gap-3 min-w-0">
          <div className="p-2 rounded-lg bg-gray-700 shrink-0">
            <Calendar className="w-4 h-4 text-gray-400" />
          </div>
          <div className="min-w-0">
            <p className="text-white text-sm font-medium truncate">{schedule.name}</p>
            <div className="flex items-center gap-2 mt-1">
              <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${
                TYPE_BADGES[schedule.report_type] ?? 'bg-gray-700 text-gray-300'
              }`}>
                {TYPE_LABELS[schedule.report_type] ?? schedule.report_type}
              </span>
              <span className={`text-xs px-2 py-0.5 rounded-full ${
                schedule.enabled
                  ? 'bg-green-900/40 text-green-400'
                  : 'bg-gray-700 text-gray-500'
              }`}>
                {schedule.enabled ? '有効' : '無効'}
              </span>
            </div>
          </div>
        </div>

        {/* Delete button */}
        {canWrite && (confirmDelete ? (
          <div className="flex items-center gap-2 shrink-0">
            <button
              onClick={() => onDelete(schedule.id)}
              disabled={isDeleting}
              className="text-xs px-2.5 py-1 bg-red-700 hover:bg-red-600 text-white rounded-lg
                         transition-colors disabled:opacity-50"
            >
              削除する
            </button>
            <button
              onClick={() => setConfirmDelete(false)}
              className="text-xs text-gray-500 hover:text-gray-300 transition-colors"
            >
              取消
            </button>
          </div>
        ) : (
          <button
            onClick={() => setConfirmDelete(true)}
            className="shrink-0 p-1.5 text-gray-600 hover:text-red-400 transition-colors rounded-lg
                       hover:bg-red-900/20"
            title="削除"
          >
            <Trash2 className="w-4 h-4" />
          </button>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-2 text-xs">
        <div className="bg-gray-900 rounded-lg p-2.5">
          <div className="flex items-center gap-1.5 text-gray-500 mb-0.5">
            <Clock className="w-3 h-3" />
            スケジュール
          </div>
          <p className="text-white font-medium">{humanCron(schedule.schedule)}</p>
          <p className="text-gray-600 font-mono mt-0.5">{schedule.schedule}</p>
        </div>
        <div className="bg-gray-900 rounded-lg p-2.5">
          <div className="flex items-center gap-1.5 text-gray-500 mb-0.5">
            <Calendar className="w-3 h-3" />
            次回実行
          </div>
          <p className="text-gray-300">{formatDateTime(schedule.next_run)}</p>
        </div>
        <div className="bg-gray-900 rounded-lg p-2.5 col-span-2">
          <div className="flex items-center gap-1.5 text-gray-500 mb-0.5">
            <RefreshCw className="w-3 h-3" />
            前回実行
          </div>
          <p className="text-gray-300">{formatDateTime(schedule.last_run)}</p>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ReportsPage() {
  const qc = useQueryClient()
  const canWrite = useCanWrite()
  const [showForm, setShowForm] = useState(false)
  const [deleteConfirmId, setDeleteConfirmId] = useState<string | null>(null)
  const [previewReport, setPreviewReport] = useState<GeneratedReport | null>(null)

  // Fetch generated reports
  const { data: generatedData } = useQuery({
    queryKey: ['reports-list'],
    queryFn: () => apiFetch<{ reports: GeneratedReport[] }>('/api/v1/reports').catch(() => ({ reports: [] })),
    staleTime: 30_000,
  })
  const generatedReports = generatedData?.reports ?? []

  // Fetch schedules
  const {
    data: schedulesData,
    isLoading: schedulesLoading,
    isFetching: schedulesFetching,
    refetch: refetchSchedules,
  } = useQuery({
    queryKey: ['report-schedules'],
    queryFn: () => apiFetch<{ schedules: ReportSchedule[] }>('/api/v1/reports/schedules').catch(() => ({ schedules: [] })),
    refetchInterval: 30_000,
  })

  const schedules = schedulesData?.schedules ?? []

  // Create schedule
  const createMutation = useMutation({
    mutationFn: (payload: ScheduleCreatePayload) =>
      apiFetch('/api/v1/reports/schedules', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['report-schedules'] })
      setShowForm(false)
    },
  })

  // Delete schedule
  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/reports/schedules/${id}`, { method: 'DELETE' }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['report-schedules'] })
      setDeleteConfirmId(null)
    },
  })

  return (
    <div className="min-h-screen bg-gray-900 p-6 space-y-8">
      {previewReport && (
        <ReportPreviewModal report={previewReport} onClose={() => setPreviewReport(null)} />
      )}

      {/* Page header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <FileText className="w-6 h-6 text-blue-400" />
            レポート
          </h1>
          <p className="text-gray-500 text-sm mt-1">エクスポートとスケジュール管理</p>
        </div>
      </div>

      {/* ── Section 1: エクスポート ── */}
      <section>
        <SectionTitle>エクスポート</SectionTitle>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-5">
          <AlertExportCard />
          <ComplianceExportCard />
        </div>
      </section>

      {/* ── Section 2: 生成済みレポート ── */}
      <section>
        <SectionTitle>生成済みレポート</SectionTitle>
        <div className="bg-gray-800 rounded-xl border border-gray-700 overflow-hidden">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-gray-700 text-xs text-gray-400">
                <th className="px-4 py-3 text-left">レポート名</th>
                <th className="px-4 py-3 text-left hidden md:table-cell">種別</th>
                <th className="px-4 py-3 text-left hidden md:table-cell">生成日時</th>
                <th className="px-4 py-3 text-right">操作</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-700/50">
              {generatedReports.length === 0 ? (
                <tr>
                  <td colSpan={4} className="px-4 py-8 text-center text-gray-500 text-sm">
                    生成済みレポートはありません
                  </td>
                </tr>
              ) : generatedReports.map(r => {
                const typeLabel = TYPE_LABELS[r.type] ?? r.type
                const typeBadge = TYPE_BADGES[r.type] ?? 'bg-gray-700 text-gray-300'
                const generatedAt = r.completed_at ?? r.requested_at
                return (
                  <tr key={r.id} className="hover:bg-gray-700/30 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <div className={`p-1.5 rounded ${
                          r.type === 'alerts' ? 'bg-orange-900/30' :
                          r.type === 'compliance' ? 'bg-blue-900/30' : 'bg-purple-900/30'
                        }`}>
                          <FileText className={`w-3.5 h-3.5 ${
                            r.type === 'alerts' ? 'text-orange-400' :
                            r.type === 'compliance' ? 'text-blue-400' : 'text-purple-400'
                          }`} />
                        </div>
                        <div>
                          <p className="text-white text-xs font-medium">{typeLabel}レポート</p>
                          <p className="text-gray-500 text-[10px]">{r.id.slice(0, 8)}...</p>
                        </div>
                      </div>
                    </td>
                    <td className="px-4 py-3 hidden md:table-cell">
                      <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${typeBadge}`}>
                        {typeLabel}
                      </span>
                    </td>
                    <td className="px-4 py-3 text-gray-400 text-xs hidden md:table-cell">
                      {formatDateTime(generatedAt)}
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center justify-end gap-1">
                        <button
                          onClick={() => setPreviewReport(r)}
                          className="flex items-center gap-1 px-2.5 py-1.5 bg-gray-700 hover:bg-gray-600
                                     text-gray-300 hover:text-white text-xs rounded-lg transition-colors"
                        >
                          <Eye className="w-3.5 h-3.5" />プレビュー
                        </button>
                        {r.download_url && (
                          <button
                            onClick={() => downloadViaAnchor(r.download_url!, `report_${r.id}.pdf`)}
                            className="p-1.5 text-gray-500 hover:text-white transition-colors rounded-lg hover:bg-gray-700"
                          >
                            <Download className="w-3.5 h-3.5" />
                          </button>
                        )}
                      </div>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </section>

      {/* ── Section 3: スケジュールレポート ── */}
      <section>
        <div className="flex items-center justify-between mb-4">
          <SectionTitle>スケジュールレポート</SectionTitle>
          <div className="flex items-center gap-2">
            <button
              onClick={() => refetchSchedules()}
              disabled={schedulesFetching}
              className="p-2 text-gray-500 hover:text-white transition-colors disabled:opacity-40 rounded-lg hover:bg-gray-800"
              title="更新"
            >
              <RefreshCw className={`w-4 h-4 ${schedulesFetching ? 'animate-spin' : ''}`} />
            </button>
            {canWrite && (
              <button
                onClick={() => setShowForm(v => !v)}
                className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-500
                           text-white rounded-lg text-sm font-medium transition-colors"
              >
                <Plus className="w-4 h-4" />
                新しいスケジュールを追加
              </button>
            )}
          </div>
        </div>

        {/* Inline form */}
        {showForm && (
          <div className="mb-5">
            <ScheduleForm
              onSubmit={payload => createMutation.mutate(payload)}
              onCancel={() => setShowForm(false)}
              isPending={createMutation.isPending}
            />
            {createMutation.isError && (
              <p className="text-red-400 text-sm mt-2">
                エラー: {(createMutation.error as Error).message}
              </p>
            )}
          </div>
        )}

        {/* Schedules list */}
        {schedulesLoading ? (
          <div className="flex items-center justify-center h-32">
            <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          </div>
        ) : schedules.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-32 text-gray-600 bg-gray-800 rounded-xl border border-gray-700">
            <Calendar className="w-8 h-8 mb-2 opacity-40" />
            <p className="text-sm">スケジュールがありません</p>
            <p className="text-xs mt-1 text-gray-700">上のボタンから追加してください</p>
          </div>
        ) : (
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
            {schedules.map(s => (
              <ScheduleCard
                key={s.id}
                schedule={s}
                onDelete={id => deleteMutation.mutate(id)}
                isDeleting={deleteMutation.isPending && deleteConfirmId === s.id}
                canWrite={canWrite}
              />
            ))}
          </div>
        )}
      </section>
    </div>
  )
}
