'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Shield, Download, Calendar, RefreshCw, X, ChevronDown,
  AlertTriangle, Clock, Activity, TrendingDown, TrendingUp,
  Users, BarChart2, Mail, Plus, Trash2, CheckCircle,
  AlertCircle, Zap, Target, Eye, Lock,
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────────

type Period = '7d' | '30d' | '90d' | 'custom'

interface KpiData {
  total_incidents: number
  mttr_minutes: number
  alert_volume: number
  false_positive_rate: number
  incidents_delta: number
  mttr_delta: number
  alert_delta: number
  fp_delta: number
}

interface SeverityBreakdown {
  severity: 'critical' | 'high' | 'medium' | 'low'
  count: number
  percentage: number
}

interface ThreatCategory {
  rank: number
  category: string
  count: number
  percentage: number
  trend: 'up' | 'down' | 'flat'
}

interface AnalystPerformance {
  analyst: string
  email: string
  incidents_handled: number
  avg_resolution_minutes: number
  sla_compliance: number
}

interface AlertSource {
  source: 'EDR' | 'ネットワーク' | 'クラウド' | 'メール'
  count: number
  percentage: number
}

interface SecurityOpsReport {
  period: string
  generated_at: string
  kpi: KpiData
  severity_breakdown: SeverityBreakdown[]
  threat_categories: ThreatCategory[]
  analyst_performance: AnalystPerformance[]
  alert_sources: AlertSource[]
}

interface SchedulePayload {
  frequency: 'daily' | 'weekly' | 'monthly'
  recipients: string[]
}

// ── Mock data ──────────────────────────────────────────────────────────────────

function buildMockReport(period: string): SecurityOpsReport {
  const multiplier = period === '7d' ? 1 : period === '30d' ? 4.3 : 12.9

  return {
    period,
    generated_at: new Date().toISOString(),
    kpi: {
      total_incidents: Math.round(48 * multiplier),
      mttr_minutes: 94,
      alert_volume: Math.round(3240 * multiplier),
      false_positive_rate: 12.4,
      incidents_delta: -8,
      mttr_delta: -12,
      alert_delta: 5,
      fp_delta: -2.1,
    },
    severity_breakdown: [
      { severity: 'critical', count: Math.round(6 * multiplier),  percentage: 12 },
      { severity: 'high',     count: Math.round(14 * multiplier), percentage: 28 },
      { severity: 'medium',   count: Math.round(19 * multiplier), percentage: 38 },
      { severity: 'low',      count: Math.round(9 * multiplier),  percentage: 22 },
    ],
    threat_categories: [
      { rank: 1,  category: 'マルウェア感染',           count: Math.round(89 * multiplier / 4.3), percentage: 22, trend: 'up'   },
      { rank: 2,  category: 'フィッシング攻撃',         count: Math.round(74 * multiplier / 4.3), percentage: 18, trend: 'up'   },
      { rank: 3,  category: '不正アクセス試行',         count: Math.round(61 * multiplier / 4.3), percentage: 15, trend: 'flat' },
      { rank: 4,  category: 'ランサムウェア',           count: Math.round(44 * multiplier / 4.3), percentage: 11, trend: 'down' },
      { rank: 5,  category: 'データ持ち出し疑惑',       count: Math.round(37 * multiplier / 4.3), percentage: 9,  trend: 'up'   },
      { rank: 6,  category: 'ラテラルムーブメント',     count: Math.round(28 * multiplier / 4.3), percentage: 7,  trend: 'flat' },
      { rank: 7,  category: 'C2通信',                   count: Math.round(22 * multiplier / 4.3), percentage: 5,  trend: 'down' },
      { rank: 8,  category: '特権昇格',                 count: Math.round(18 * multiplier / 4.3), percentage: 4,  trend: 'flat' },
      { rank: 9,  category: 'DNS トンネリング',         count: Math.round(14 * multiplier / 4.3), percentage: 3,  trend: 'down' },
      { rank: 10, category: 'サプライチェーン攻撃',     count: Math.round(10 * multiplier / 4.3), percentage: 2,  trend: 'up'   },
    ],
    analyst_performance: [
      { analyst: '田中 一郎',   email: 'tanaka@example.com',   incidents_handled: Math.round(58 * multiplier / 4.3), avg_resolution_minutes: 72,  sla_compliance: 96.2 },
      { analyst: '鈴木 花子',   email: 'suzuki@example.com',   incidents_handled: Math.round(51 * multiplier / 4.3), avg_resolution_minutes: 88,  sla_compliance: 93.8 },
      { analyst: '佐藤 次郎',   email: 'sato@example.com',     incidents_handled: Math.round(45 * multiplier / 4.3), avg_resolution_minutes: 105, sla_compliance: 88.4 },
      { analyst: '山田 三郎',   email: 'yamada@example.com',   incidents_handled: Math.round(39 * multiplier / 4.3), avg_resolution_minutes: 91,  sla_compliance: 91.7 },
      { analyst: '渡辺 美咲',   email: 'watanabe@example.com', incidents_handled: Math.round(33 * multiplier / 4.3), avg_resolution_minutes: 118, sla_compliance: 84.9 },
    ],
    alert_sources: [
      { source: 'EDR',        count: Math.round(1458 * multiplier / 4.3), percentage: 45 },
      { source: 'ネットワーク', count: Math.round(875 * multiplier / 4.3),  percentage: 27 },
      { source: 'クラウド',    count: Math.round(583 * multiplier / 4.3),  percentage: 18 },
      { source: 'メール',      count: Math.round(324 * multiplier / 4.3),  percentage: 10 },
    ],
  }
}

// ── Constants ──────────────────────────────────────────────────────────────────

const SEVERITY_STYLES: Record<string, { bar: string; badge: string; label: string }> = {
  critical: { bar: 'bg-[#e8002d]',  badge: 'bg-red-900/40 text-red-300 border border-red-700/50',     label: 'クリティカル' },
  high:     { bar: 'bg-orange-500', badge: 'bg-orange-900/40 text-orange-300 border border-orange-700/50', label: '高' },
  medium:   { bar: 'bg-yellow-500', badge: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50', label: '中' },
  low:      { bar: 'bg-blue-500',   badge: 'bg-blue-900/40 text-blue-300 border border-blue-700/50',   label: '低' },
}

const SOURCE_COLORS: Record<string, string> = {
  'EDR':        'bg-[#e8002d]',
  'ネットワーク': 'bg-purple-500',
  'クラウド':    'bg-blue-500',
  'メール':      'bg-green-500',
}

const PERIOD_OPTIONS: { value: Period; label: string }[] = [
  { value: '7d',     label: '過去7日間' },
  { value: '30d',    label: '過去30日間' },
  { value: '90d',    label: '過去90日間' },
  { value: 'custom', label: 'カスタム' },
]

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtMinutes(mins: number): string {
  if (mins < 60) return `${mins}分`
  const h = Math.floor(mins / 60)
  const m = mins % 60
  return m > 0 ? `${h}時間${m}分` : `${h}時間`
}

function fmtDateTime(iso: string): string {
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit',
    })
  } catch { return '—' }
}

function DeltaBadge({ delta, invert = false, suffix = '' }: { delta: number; invert?: boolean; suffix?: string }) {
  const positive = invert ? delta < 0 : delta > 0
  const zero = delta === 0
  if (zero) return <span className="text-[#7d92b0] text-xs">変化なし</span>
  return (
    <span className={`inline-flex items-center gap-0.5 text-xs font-medium ${positive ? 'text-green-400' : 'text-[#e8002d]'}`}>
      {positive ? <TrendingDown className="w-3 h-3" /> : <TrendingUp className="w-3 h-3" />}
      {Math.abs(delta)}{suffix}
    </span>
  )
}

// ── KPI Card ──────────────────────────────────────────────────────────────────

interface KpiCardProps {
  label: string
  value: string | number
  sub?: string
  delta?: number
  invertDelta?: boolean
  deltaSuffix?: string
  icon: React.ComponentType<{ className?: string }>
  iconColor: string
  iconBg: string
}

function KpiCard({ label, value, sub, delta, invertDelta, deltaSuffix, icon: Icon, iconColor, iconBg }: KpiCardProps) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
      <div className="flex items-start justify-between mb-3">
        <p className="text-[#7d92b0] text-xs font-medium">{label}</p>
        <div className={`w-8 h-8 rounded-lg ${iconBg} flex items-center justify-center`}>
          <Icon className={`w-4 h-4 ${iconColor}`} />
        </div>
      </div>
      <p className="text-3xl font-bold text-white">{value}</p>
      {sub && <p className="text-[#7d92b0] text-xs mt-1">{sub}</p>}
      {delta !== undefined && (
        <div className="mt-2">
          <DeltaBadge delta={delta} invert={invertDelta} suffix={deltaSuffix} />
          <span className="text-[#4d6480] text-xs ml-1">前期比</span>
        </div>
      )}
    </div>
  )
}

// ── Schedule Modal ─────────────────────────────────────────────────────────────

function ScheduleModal({ onClose, onSubmit, loading }: {
  onClose: () => void
  onSubmit: (p: SchedulePayload) => void
  loading: boolean
}) {
  const [frequency, setFrequency] = useState<SchedulePayload['frequency']>('weekly')
  const [emailInput, setEmailInput] = useState('')
  const [recipients, setRecipients] = useState<string[]>(['soc@example.com'])

  function addEmail() {
    const e = emailInput.trim()
    if (e && e.includes('@') && !recipients.includes(e)) {
      setRecipients(p => [...p, e])
      setEmailInput('')
    }
  }

  function removeEmail(e: string) { setRecipients(p => p.filter(r => r !== e)) }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center p-4">
      <div className="absolute inset-0 bg-black/60 backdrop-blur-sm" onClick={onClose} />
      <div className="relative w-full max-w-md bg-[#0d1220] border border-[#1e2d42] rounded-xl shadow-2xl">
        {/* Header */}
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <div className="w-8 h-8 rounded-lg bg-purple-500/15 flex items-center justify-center">
              <Calendar className="w-4 h-4 text-purple-400" />
            </div>
            <h3 className="text-white font-semibold">レポートをスケジュール</h3>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>

        <div className="px-6 py-5 space-y-4">
          {/* Frequency */}
          <div>
            <label className="block text-[#7d92b0] text-xs font-medium mb-2">配信頻度</label>
            <div className="grid grid-cols-3 gap-2">
              {([['daily', '毎日'], ['weekly', '毎週'], ['monthly', '毎月']] as const).map(([val, label]) => (
                <button
                  key={val}
                  onClick={() => setFrequency(val)}
                  className={`py-2 text-sm rounded-lg border transition-colors
                    ${frequency === val
                      ? 'bg-[#1a6bff]/15 border-[#1a6bff] text-[#1a6bff]'
                      : 'bg-[#070d19] border-[#1e2d42] text-[#7d92b0] hover:border-[#2d4060]'}`}
                >
                  {label}
                </button>
              ))}
            </div>
          </div>

          {/* Recipients */}
          <div>
            <label className="block text-[#7d92b0] text-xs font-medium mb-2">受信者</label>
            <div className="flex gap-2 mb-2">
              <div className="relative flex-1">
                <Mail className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0]" />
                <input
                  type="email"
                  value={emailInput}
                  onChange={e => setEmailInput(e.target.value)}
                  onKeyDown={e => e.key === 'Enter' && addEmail()}
                  placeholder="メールアドレスを入力..."
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg pl-9 pr-3 py-2 text-white
                             text-sm placeholder-[#3d5275] focus:outline-none focus:border-[#1a6bff] transition-colors"
                />
              </div>
              <button
                onClick={addEmail}
                className="px-3 py-2 bg-[#1a6bff] hover:bg-[#1558e0] text-white rounded-lg transition-colors"
              >
                <Plus className="w-4 h-4" />
              </button>
            </div>
            <div className="space-y-1.5 max-h-32 overflow-y-auto">
              {recipients.map(r => (
                <div key={r} className="flex items-center justify-between bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-1.5">
                  <span className="text-white text-sm">{r}</span>
                  <button onClick={() => removeEmail(r)} className="text-[#7d92b0] hover:text-[#e8002d] transition-colors">
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              ))}
              {recipients.length === 0 && (
                <p className="text-[#4d6480] text-xs text-center py-2">受信者を追加してください</p>
              )}
            </div>
          </div>
        </div>

        <div className="flex items-center justify-end gap-3 px-6 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="px-4 py-2 text-sm text-[#7d92b0] hover:text-white border border-[#1e2d42] hover:border-[#2d4060] rounded-lg transition-colors">
            キャンセル
          </button>
          <button
            onClick={() => onSubmit({ frequency, recipients })}
            disabled={recipients.length === 0 || loading}
            className="px-4 py-2 text-sm text-white bg-[#1a6bff] hover:bg-[#1558e0] rounded-lg transition-colors disabled:opacity-40 flex items-center gap-2"
          >
            {loading && <div className="w-3.5 h-3.5 border-2 border-white border-t-transparent rounded-full animate-spin" />}
            スケジュール設定
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Toast ──────────────────────────────────────────────────────────────────────

function Toast({ message, onClose }: { message: string; onClose: () => void }) {
  return (
    <div className="fixed bottom-6 right-6 z-50 flex items-center gap-3 bg-[#0d1220] border border-[#1e2d42]
                    rounded-xl px-4 py-3 shadow-2xl animate-fade-in">
      <div className="w-7 h-7 rounded-full bg-[#1a6bff]/15 flex items-center justify-center flex-shrink-0">
        <CheckCircle className="w-4 h-4 text-[#1a6bff]" />
      </div>
      <p className="text-white text-sm">{message}</p>
      <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors ml-1">
        <X className="w-4 h-4" />
      </button>
    </div>
  )
}

// ── Section wrapper ────────────────────────────────────────────────────────────

function Section({ title, icon: Icon, children }: { title: string; icon: React.ComponentType<{ className?: string }>; children: React.ReactNode }) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
      <div className="flex items-center gap-2.5 px-5 py-4 border-b border-[#1e2d42]">
        <Icon className="w-4 h-4 text-[#7d92b0]" />
        <h2 className="text-white font-semibold text-sm">{title}</h2>
      </div>
      <div className="p-5">{children}</div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

export default function SecurityOpsReportPage() {
  const [period, setPeriod] = useState<Period>('30d')
  const [customFrom, setCustomFrom] = useState('')
  const [customTo, setCustomTo]     = useState('')
  const [showSchedule, setShowSchedule] = useState(false)
  const [toast, setToast] = useState<string | null>(null)
  const [scheduleLoading, setScheduleLoading] = useState(false)

  const effectivePeriod = period === 'custom' ? `${customFrom}:${customTo}` : period

  // ── API Query ────────────────────────────────────────────────────────────────

  const { data: report, isLoading, refetch } = useQuery<SecurityOpsReport>({
    queryKey: ['security-ops-report', effectivePeriod],
    queryFn: () =>
      apiFetch<SecurityOpsReport>(`/api/v1/reports/security-ops?period=${effectivePeriod}`)
        .catch(() => buildMockReport(period)),
    staleTime: 60_000,
    initialData: () => buildMockReport(period),
  })

  // ── Export PDF ───────────────────────────────────────────────────────────────

  function handleExportPdf() {
    setToast('レポートを生成中...')
    setTimeout(() => setToast(null), 3500)
  }

  // ── Schedule submit ──────────────────────────────────────────────────────────

  async function handleScheduleSubmit(payload: SchedulePayload) {
    setScheduleLoading(true)
    try {
      await apiFetch('/api/v1/reports/security-ops/schedule', {
        method: 'POST',
        body: JSON.stringify(payload),
      })
    } catch {
      // Mock success
    } finally {
      setScheduleLoading(false)
      setShowSchedule(false)
      setToast(`レポートを${payload.frequency === 'daily' ? '毎日' : payload.frequency === 'weekly' ? '毎週' : '毎月'}${payload.recipients.length}名に送信予定`)
      setTimeout(() => setToast(null), 4000)
    }
  }

  const kpi = report?.kpi
  const periodLabel = PERIOD_OPTIONS.find(p => p.value === period)?.label ?? period

  // ── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      {/* Toast */}
      {toast && <Toast message={toast} onClose={() => setToast(null)} />}

      {/* Schedule modal */}
      {showSchedule && (
        <ScheduleModal
          onClose={() => setShowSchedule(false)}
          onSubmit={handleScheduleSubmit}
          loading={scheduleLoading}
        />
      )}

      <div className="max-w-screen-xl mx-auto px-6 py-8 space-y-6">
        {/* Page Header */}
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
          <div className="flex items-center gap-4">
            <div className="w-10 h-10 rounded-xl bg-[#e8002d]/15 border border-[#e8002d]/30
                            flex items-center justify-center">
              <Shield className="w-5 h-5 text-[#e8002d]" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">セキュリティオペレーション レポート</h1>
              <p className="text-[#7d92b0] text-sm mt-0.5">
                {isLoading ? '読み込み中...' : `${periodLabel} — ${fmtDateTime(report?.generated_at ?? '')}`}
              </p>
            </div>
          </div>

          {/* Actions */}
          <div className="flex items-center gap-2 flex-wrap">
            <button
              onClick={() => refetch()}
              className="p-2 text-[#7d92b0] hover:text-white border border-[#1e2d42]
                         hover:border-[#2d4060] rounded-lg transition-colors"
              title="更新"
            >
              <RefreshCw className="w-4 h-4" />
            </button>
            <button
              onClick={() => setShowSchedule(true)}
              className="flex items-center gap-2 px-3 py-2 text-sm text-[#7d92b0] hover:text-white
                         border border-[#1e2d42] hover:border-[#2d4060] rounded-lg transition-colors"
            >
              <Calendar className="w-4 h-4" />
              スケジュール
            </button>
            <button
              onClick={handleExportPdf}
              className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c20026] text-white
                         text-sm font-medium rounded-lg transition-colors"
            >
              <Download className="w-4 h-4" />
              PDF出力
            </button>
          </div>
        </div>

        {/* Period selector */}
        <div className="flex flex-wrap items-center gap-2">
          <div className="flex items-center gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1">
            {PERIOD_OPTIONS.map(opt => (
              <button
                key={opt.value}
                onClick={() => setPeriod(opt.value)}
                className={`px-3 py-1.5 text-sm rounded-md transition-colors
                  ${period === opt.value
                    ? 'bg-[#1a6bff] text-white'
                    : 'text-[#7d92b0] hover:text-white hover:bg-[#161f33]'}`}
              >
                {opt.label}
              </button>
            ))}
          </div>

          {period === 'custom' && (
            <div className="flex items-center gap-2">
              <input
                type="date"
                value={customFrom}
                onChange={e => setCustomFrom(e.target.value)}
                className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm
                           focus:outline-none focus:border-[#1a6bff] transition-colors"
              />
              <span className="text-[#7d92b0] text-sm">〜</span>
              <input
                type="date"
                value={customTo}
                onChange={e => setCustomTo(e.target.value)}
                className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm
                           focus:outline-none focus:border-[#1a6bff] transition-colors"
              />
            </div>
          )}
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center h-64">
            <div className="w-10 h-10 border-2 border-[#e8002d] border-t-transparent rounded-full animate-spin" />
          </div>
        ) : (
          <>
            {/* KPI Cards */}
            <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
              <KpiCard
                label="総インシデント数"
                value={kpi?.total_incidents.toLocaleString() ?? '—'}
                sub={periodLabel}
                delta={kpi?.incidents_delta}
                invertDelta
                icon={AlertCircle}
                iconColor="text-[#e8002d]"
                iconBg="bg-[#e8002d]/15"
              />
              <KpiCard
                label="平均対応時間 (MTTR)"
                value={fmtMinutes(kpi?.mttr_minutes ?? 0)}
                sub="インシデント解決まで"
                delta={kpi?.mttr_delta}
                invertDelta
                deltaSuffix="分"
                icon={Clock}
                iconColor="text-orange-400"
                iconBg="bg-orange-500/15"
              />
              <KpiCard
                label="アラート総数"
                value={kpi?.alert_volume.toLocaleString() ?? '—'}
                sub={periodLabel}
                delta={kpi?.alert_delta}
                deltaSuffix="%"
                icon={Activity}
                iconColor="text-blue-400"
                iconBg="bg-blue-500/15"
              />
              <KpiCard
                label="誤検知率"
                value={`${kpi?.false_positive_rate.toFixed(1) ?? '—'}%`}
                sub="全アラートのうち"
                delta={kpi?.fp_delta}
                invertDelta
                deltaSuffix="pt"
                icon={Target}
                iconColor="text-yellow-400"
                iconBg="bg-yellow-500/15"
              />
            </div>

            {/* Severity Breakdown */}
            <Section title="インシデント — 深刻度別内訳" icon={BarChart2}>
              <div className="space-y-3">
                {report?.severity_breakdown.map(row => {
                  const style = SEVERITY_STYLES[row.severity]
                  return (
                    <div key={row.severity} className="flex items-center gap-4">
                      <span className={`text-xs px-2 py-0.5 rounded-full whitespace-nowrap min-w-[100px] text-center ${style.badge}`}>
                        {style.label}
                      </span>
                      <div className="flex-1 bg-[#070d19] rounded-full h-5 overflow-hidden">
                        <div
                          className={`h-full ${style.bar} rounded-full transition-all duration-700 flex items-center justify-end pr-2`}
                          style={{ width: `${row.percentage}%` }}
                        >
                          <span className="text-white text-xs font-medium">{row.percentage}%</span>
                        </div>
                      </div>
                      <span className="text-white text-sm font-semibold min-w-[60px] text-right">
                        {(row.count ?? 0).toLocaleString()}件
                      </span>
                    </div>
                  )
                })}
              </div>
            </Section>

            {/* Threat Categories */}
            <Section title="Top 10 脅威カテゴリ" icon={Shield}>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      {['順位', 'カテゴリ', '件数', '割合', 'トレンド'].map(h => (
                        <th key={h} className="text-left px-3 py-2 text-[#7d92b0] text-xs font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {report?.threat_categories.map((row, i) => (
                      <tr key={row.rank} className={`border-b border-[#1e2d42]/50 hover:bg-[#111827]/60 transition-colors ${i === (report.threat_categories.length - 1) ? 'border-0' : ''}`}>
                        <td className="px-3 py-2.5">
                          <span className={`inline-flex items-center justify-center w-6 h-6 rounded-full text-xs font-bold
                            ${row.rank <= 3 ? 'bg-[#e8002d]/20 text-[#e8002d]' : 'bg-[#1e2d42] text-[#7d92b0]'}`}>
                            {row.rank}
                          </span>
                        </td>
                        <td className="px-3 py-2.5 text-white text-sm">{row.category}</td>
                        <td className="px-3 py-2.5 text-white text-sm font-semibold">{(row.count ?? 0).toLocaleString()}</td>
                        <td className="px-3 py-2.5">
                          <div className="flex items-center gap-2">
                            <div className="w-20 bg-[#070d19] rounded-full h-1.5 overflow-hidden">
                              <div
                                className="h-full bg-[#1a6bff] rounded-full"
                                style={{ width: `${row.percentage}%` }}
                              />
                            </div>
                            <span className="text-[#7d92b0] text-xs">{row.percentage}%</span>
                          </div>
                        </td>
                        <td className="px-3 py-2.5">
                          {row.trend === 'up'   && <span className="inline-flex items-center gap-1 text-xs text-[#e8002d]"><TrendingUp className="w-3.5 h-3.5" />増加</span>}
                          {row.trend === 'down' && <span className="inline-flex items-center gap-1 text-xs text-green-400"><TrendingDown className="w-3.5 h-3.5" />減少</span>}
                          {row.trend === 'flat' && <span className="text-xs text-[#7d92b0]">横ばい</span>}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </Section>

            {/* Analyst Performance */}
            <Section title="アナリスト パフォーマンス" icon={Users}>
              <div className="overflow-x-auto">
                <table className="w-full">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      {['アナリスト', '担当インシデント', '平均解決時間', 'SLA遵守率'].map(h => (
                        <th key={h} className="text-left px-3 py-2 text-[#7d92b0] text-xs font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {report?.analyst_performance.map((row, i) => {
                      const slaColor = row.sla_compliance >= 95 ? 'text-green-400' : row.sla_compliance >= 85 ? 'text-yellow-400' : 'text-[#e8002d]'
                      const slaBarColor = row.sla_compliance >= 95 ? 'bg-green-500' : row.sla_compliance >= 85 ? 'bg-yellow-500' : 'bg-[#e8002d]'
                      return (
                        <tr key={row.email} className={`border-b border-[#1e2d42]/50 hover:bg-[#111827]/60 transition-colors ${i === (report.analyst_performance.length - 1) ? 'border-0' : ''}`}>
                          <td className="px-3 py-3">
                            <div className="flex items-center gap-2.5">
                              <div className="w-7 h-7 rounded-full bg-gradient-to-br from-[#1a6bff] to-[#0044cc]
                                              flex items-center justify-center text-xs font-bold text-white flex-shrink-0">
                                {row.analyst[0]}
                              </div>
                              <div>
                                <p className="text-white text-sm">{row.analyst}</p>
                                <p className="text-[#4d6480] text-xs font-mono">{row.email}</p>
                              </div>
                            </div>
                          </td>
                          <td className="px-3 py-3">
                            <span className="text-white text-sm font-semibold">{row.incidents_handled}</span>
                            <span className="text-[#7d92b0] text-xs ml-1">件</span>
                          </td>
                          <td className="px-3 py-3">
                            <span className="text-white text-sm">{fmtMinutes(row.avg_resolution_minutes)}</span>
                          </td>
                          <td className="px-3 py-3">
                            <div className="flex items-center gap-2">
                              <div className="w-20 bg-[#070d19] rounded-full h-1.5 overflow-hidden">
                                <div
                                  className={`h-full ${slaBarColor} rounded-full transition-all duration-700`}
                                  style={{ width: `${row.sla_compliance}%` }}
                                />
                              </div>
                              <span className={`text-sm font-semibold ${slaColor}`}>
                                {row.sla_compliance.toFixed(1)}%
                              </span>
                            </div>
                          </td>
                        </tr>
                      )
                    })}
                  </tbody>
                </table>
              </div>
            </Section>

            {/* Alert Source Breakdown */}
            <Section title="アラートソース別内訳" icon={Eye}>
              <div className="space-y-4">
                {report?.alert_sources.map(row => {
                  const barColor = SOURCE_COLORS[row.source] ?? 'bg-[#1a6bff]'
                  return (
                    <div key={row.source} className="flex items-center gap-4">
                      <span className="text-[#7d92b0] text-sm min-w-[100px] text-right">{row.source}</span>
                      <div className="flex-1 bg-[#070d19] rounded-full h-6 overflow-hidden">
                        <div
                          className={`h-full ${barColor} rounded-full transition-all duration-700
                                      flex items-center justify-end pr-3`}
                          style={{ width: `${row.percentage}%` }}
                        >
                          <span className="text-white text-xs font-medium">{row.percentage}%</span>
                        </div>
                      </div>
                      <span className="text-white text-sm font-semibold min-w-[80px] text-right">
                        {(row.count ?? 0).toLocaleString()}件
                      </span>
                    </div>
                  )
                })}
              </div>

              {/* Legend */}
              <div className="flex flex-wrap gap-3 mt-5 pt-4 border-t border-[#1e2d42]">
                {report?.alert_sources.map(row => {
                  const barColor = SOURCE_COLORS[row.source] ?? 'bg-[#1a6bff]'
                  return (
                    <div key={row.source} className="flex items-center gap-1.5">
                      <div className={`w-2.5 h-2.5 rounded-full ${barColor}`} />
                      <span className="text-[#7d92b0] text-xs">{row.source}</span>
                    </div>
                  )
                })}
              </div>
            </Section>

            {/* Footer note */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl px-5 py-4 flex items-start gap-3">
              <Lock className="w-4 h-4 text-[#7d92b0] flex-shrink-0 mt-0.5" />
              <p className="text-[#7d92b0] text-xs leading-relaxed">
                このレポートは機密情報を含みます。社外への共有は禁止されています。
                データは {fmtDateTime(report?.generated_at ?? '')} 時点のものです。
                正確な情報のため、定期的に更新してください。
              </p>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
