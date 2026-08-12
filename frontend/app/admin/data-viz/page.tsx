'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { displayUser } from '@/lib/display-user'
import {
  PieChart, Plus, X, Pencil, Trash2, Save, BarChart2,
  TrendingUp, TrendingDown, Minus, AlertTriangle, CheckCircle,
  LayoutTemplate, Clock, Eye, ChevronDown, GripVertical, Maximize2,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type WidgetType = 'kpi' | 'bar' | 'line' | 'pie' | 'table' | 'heatmap' | 'gauge' | 'alertlist'
type DataSource = 'alerts' | 'incidents' | 'endpoints' | 'vulnerabilities' | 'compliance' | 'metrics'
type Aggregation = 'count' | 'sum' | 'avg' | 'max' | 'min' | 'rate'
type TimeRange = '1h' | '6h' | '24h' | '7d' | '30d'
type ColorScheme = 'red' | 'blue' | 'green' | 'amber' | 'purple' | 'teal'

interface Widget {
  id: string
  type: WidgetType
  title: string
  data_source: DataSource
  metric: string
  aggregation: Aggregation
  time_range: TimeRange
  color_scheme: ColorScheme
  col: number
  row: number
  w: number
  h: number
}

interface Dashboard {
  id: string
  name: string
  created_by: string
  last_updated: string
  widget_count: number
  widgets: Widget[]
}

const DASHBOARD_TEMPLATES: { id: string; icon: string; name: string; description: string }[] = [
  { id: 'tpl-soc', icon: '🛡️', name: 'SOCオペレーション', description: 'アラート・インシデント・エンドポイント状態の概要' },
  { id: 'tpl-exec', icon: '📊', name: 'エグゼクティブ', description: 'KPI・リスクスコア・コンプライアンス状況' },
  { id: 'tpl-threat', icon: '🔍', name: '脅威ハンティング', description: '高度な脅威検知とハンティング用ビュー' },
  { id: 'tpl-cloud', icon: '☁️', name: 'クラウドセキュリティ', description: 'クラウドワークロードとCSPM状態' },
  { id: 'tpl-vuln', icon: '⚡', name: '脆弱性管理', description: '脆弱性トレンドとパッチ適用状況' },
]

// ─── Helpers & Config ─────────────────────────────────────────────────────────

const WIDGET_TYPES: { value: WidgetType; label: string }[] = [
  { value: 'kpi', label: 'KPIカード' },
  { value: 'bar', label: '棒グラフ' },
  { value: 'line', label: '折れ線グラフ' },
  { value: 'pie', label: '円グラフ' },
  { value: 'table', label: 'テーブル' },
  { value: 'heatmap', label: 'ヒートマップ' },
  { value: 'gauge', label: 'ゲージ' },
  { value: 'alertlist', label: 'アラートリスト' },
]

const METRIC_OPTIONS: Record<DataSource, { value: string; label: string }[]> = {
  alerts: [
    { value: 'open_count', label: 'オープン件数' },
    { value: 'daily_count', label: '日別件数' },
    { value: 'by_category', label: 'カテゴリ別' },
    { value: 'latest', label: '最新アラート' },
    { value: 'resolution_rate', label: '解決率' },
  ],
  incidents: [
    { value: 'active_count', label: 'アクティブ件数' },
    { value: 'mttr_hours', label: 'MTTR（時間）' },
    { value: 'by_severity', label: '深刻度別' },
    { value: 'weekly_trend', label: '週次トレンド' },
  ],
  endpoints: [
    { value: 'online_count', label: 'オンライン台数' },
    { value: 'online_rate', label: 'オンライン率' },
    { value: 'patch_rate', label: 'パッチ適用率' },
    { value: 'by_os', label: 'OS別分布' },
    { value: 'activity', label: '活動量' },
  ],
  vulnerabilities: [
    { value: 'open_count', label: 'オープン件数' },
    { value: 'vulnerable_endpoints', label: '脆弱エンドポイント数' },
    { value: 'by_severity', label: '深刻度別' },
    { value: 'remediation_rate', label: '修正率' },
  ],
  compliance: [
    { value: 'compliance_rate', label: 'コンプライアンス率' },
    { value: 'iso27001_rate', label: 'ISO27001適合率' },
    { value: 'nist_score', label: 'NIST CSFスコア' },
    { value: 'controls_by_status', label: 'コントロール状況' },
    { value: 'failed_controls', label: '未対応コントロール' },
    { value: 'score_trend', label: 'スコアトレンド' },
  ],
  metrics: [
    { value: 'security_score', label: 'セキュリティスコア' },
    { value: 'risk_score', label: 'リスクスコア' },
    { value: 'mttd_hours', label: 'MTTD（時間）' },
  ],
}

const COLOR_SCHEMES: Record<ColorScheme, { primary: string; text: string; bg: string }> = {
  red:    { primary: '#e8002d', text: 'text-red-400',    bg: 'bg-red-500/10' },
  blue:   { primary: '#3b82f6', text: 'text-blue-400',   bg: 'bg-blue-500/10' },
  green:  { primary: '#22c55e', text: 'text-green-400',  bg: 'bg-green-500/10' },
  amber:  { primary: '#f59e0b', text: 'text-amber-400',  bg: 'bg-amber-500/10' },
  purple: { primary: '#a855f7', text: 'text-purple-400', bg: 'bg-purple-500/10' },
  teal:   { primary: '#14b8a6', text: 'text-teal-400',   bg: 'bg-teal-500/10' },
}

function getMockValue(_metric: string): number {
  return Math.floor(Math.random() * 100 + 10)
}

// ─── Widget Renderers ─────────────────────────────────────────────────────────

function KPIWidget({ widget }: { widget: Widget }) {
  const cs = COLOR_SCHEMES[widget.color_scheme]
  const value = getMockValue(widget.metric)
  const trend = Math.random() > 0.5 ? 'up' : 'down'
  const trendPct = (Math.random() * 20 + 1).toFixed(1)
  return (
    <div className="flex flex-col justify-between h-full p-1">
      <p className="text-xs text-[#7d92b0] truncate">{widget.title}</p>
      <div>
        <p className={`text-3xl font-bold ${cs.text}`}>{value.toLocaleString()}</p>
        <div className={`flex items-center gap-1 mt-1 text-xs ${trend === 'up' ? 'text-green-400' : 'text-red-400'}`}>
          {trend === 'up' ? <TrendingUp className="w-3 h-3" /> : <TrendingDown className="w-3 h-3" />}
          {trendPct}% vs 前期
        </div>
      </div>
    </div>
  )
}

function BarWidget({ widget }: { widget: Widget }) {
  const cs = COLOR_SCHEMES[widget.color_scheme]
  const bars = ['月', '火', '水', '木', '金', '土', '日'].map(d => ({ label: d, value: Math.floor(Math.random() * 80 + 10) }))
  const max = Math.max(...bars.map(b => b.value))
  return (
    <div className="flex flex-col h-full p-1">
      <p className="text-xs text-[#7d92b0] mb-2 truncate">{widget.title}</p>
      <div className="flex items-end gap-1.5 flex-1">
        {bars.map(b => (
          <div key={b.label} className="flex-1 flex flex-col items-center gap-0.5">
            <div className="w-full rounded-t" style={{ height: `${(b.value / max) * 100}%`, backgroundColor: cs.primary, opacity: 0.8, minHeight: 4 }} />
            <span className="text-[9px] text-[#3d5068]">{b.label}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function LineWidget({ widget }: { widget: Widget }) {
  const cs = COLOR_SCHEMES[widget.color_scheme]
  const points = Array.from({ length: 12 }, (_, i) => ({ x: i, y: Math.random() * 60 + 20 }))
  const minY = Math.min(...points.map(p => p.y))
  const maxY = Math.max(...points.map(p => p.y))
  const rangeY = maxY - minY || 1
  const w = 200, h = 80
  const svgPoints = points.map(p => `${(p.x / (points.length - 1)) * w},${h - ((p.y - minY) / rangeY) * h}`).join(' ')
  return (
    <div className="flex flex-col h-full p-1">
      <p className="text-xs text-[#7d92b0] mb-2 truncate">{widget.title}</p>
      <div className="flex-1 flex items-center">
        <svg width="100%" height="100%" viewBox={`0 0 ${w} ${h}`} preserveAspectRatio="none">
          <defs>
            <linearGradient id={`grad-${widget.id}`} x1="0" y1="0" x2="0" y2="1">
              <stop offset="0%" stopColor={cs.primary} stopOpacity="0.3" />
              <stop offset="100%" stopColor={cs.primary} stopOpacity="0" />
            </linearGradient>
          </defs>
          <polygon points={`0,${h} ${svgPoints} ${w},${h}`} fill={`url(#grad-${widget.id})`} />
          <polyline points={svgPoints} fill="none" stroke={cs.primary} strokeWidth={2} strokeLinecap="round" strokeLinejoin="round" />
        </svg>
      </div>
    </div>
  )
}

function PieWidget({ widget }: { widget: Widget }) {
  const segments = [
    { label: 'カテゴリA', pct: 35, color: '#e8002d' },
    { label: 'カテゴリB', pct: 25, color: '#3b82f6' },
    { label: 'カテゴリC', pct: 20, color: '#f59e0b' },
    { label: 'その他', pct: 20, color: '#3d5068' },
  ]
  const gradient = segments.reduce<{ stops: string[]; cumulative: number }>(
    (acc, s) => {
      const start = acc.cumulative
      const end = start + s.pct
      acc.stops.push(`${s.color} ${start * 3.6}deg ${end * 3.6}deg`)
      acc.cumulative = end
      return acc
    },
    { stops: [], cumulative: 0 }
  ).stops.join(', ')
  return (
    <div className="flex items-center gap-4 h-full p-1">
      <div>
        <p className="text-xs text-[#7d92b0] mb-2 truncate">{widget.title}</p>
        <div className="w-16 h-16 rounded-full flex-shrink-0" style={{ background: `conic-gradient(${gradient})` }} />
      </div>
      <div className="space-y-1 flex-1 min-w-0">
        {segments.map(s => (
          <div key={s.label} className="flex items-center gap-1.5">
            <div className="w-2 h-2 rounded-sm flex-shrink-0" style={{ backgroundColor: s.color }} />
            <span className="text-xs text-[#7d92b0] truncate flex-1">{s.label}</span>
            <span className="text-xs text-white font-mono">{s.pct}%</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function TableWidget({ widget }: { widget: Widget }) {
  const rows = [
    { name: 'CVE-2024-1234', sev: 'Critical', host: 'srv-01', age: '3d' },
    { name: 'CVE-2024-5678', sev: 'High', host: 'wks-02', age: '5d' },
    { name: 'CVE-2023-9999', sev: 'High', host: 'srv-03', age: '12d' },
    { name: 'CVE-2024-2345', sev: 'Medium', host: 'wks-01', age: '1d' },
  ]
  const sevColor: Record<string, string> = { Critical: 'text-red-400', High: 'text-orange-400', Medium: 'text-amber-400' }
  return (
    <div className="flex flex-col h-full p-1">
      <p className="text-xs text-[#7d92b0] mb-2 truncate">{widget.title}</p>
      <div className="overflow-hidden flex-1">
        <table className="w-full text-xs">
          <thead><tr className="border-b border-[#1e2d42]">
            <th className="text-left text-[#3d5068] pb-1 font-medium">ID</th>
            <th className="text-left text-[#3d5068] pb-1 font-medium">深刻度</th>
            <th className="text-left text-[#3d5068] pb-1 font-medium">ホスト</th>
            <th className="text-left text-[#3d5068] pb-1 font-medium">経過</th>
          </tr></thead>
          <tbody>
            {rows.map(r => (
              <tr key={r.name} className="border-b border-[#1e2d42]/30">
                <td className="py-1 font-mono text-[#e2e8f4] text-[10px]">{r.name}</td>
                <td className={`py-1 ${sevColor[r.sev]}`}>{r.sev}</td>
                <td className="py-1 text-[#7d92b0]">{r.host}</td>
                <td className="py-1 text-[#7d92b0]">{r.age}</td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

function HeatmapWidget({ widget }: { widget: Widget }) {
  const hours = Array.from({ length: 24 }, (_, h) => h)
  const days = ['月', '火', '水', '木', '金', '土', '日']
  return (
    <div className="flex flex-col h-full p-1">
      <p className="text-xs text-[#7d92b0] mb-2 truncate">{widget.title}</p>
      <div className="flex gap-0.5 flex-1 overflow-hidden">
        <div className="flex flex-col justify-around pr-1">
          {days.map(d => <span key={d} className="text-[8px] text-[#3d5068]">{d}</span>)}
        </div>
        <div className="flex gap-0.5 flex-1 overflow-x-auto">
          {hours.map(h => (
            <div key={h} className="flex flex-col gap-0.5 flex-shrink-0" style={{ width: 10 }}>
              {days.map((d, di) => {
                const intensity = Math.random()
                const alpha = intensity * 0.9 + 0.1
                return <div key={`${h}-${di}`} style={{ width: 10, height: 10, backgroundColor: COLOR_SCHEMES[widget.color_scheme].primary, opacity: alpha, borderRadius: 1 }} />
              })}
            </div>
          ))}
        </div>
      </div>
    </div>
  )
}

function GaugeWidget({ widget }: { widget: Widget }) {
  const cs = COLOR_SCHEMES[widget.color_scheme]
  const value = getMockValue(widget.metric)
  const pct = Math.min(value, 100)
  const r = 45
  const cx = 60, cy = 60
  const startAngle = -220
  const sweepAngle = 260
  const toRad = (deg: number) => (deg * Math.PI) / 180
  const arcPath = (start: number, sweep: number) => {
    const s = toRad(start), e = toRad(start + sweep)
    const x1 = cx + r * Math.cos(s), y1 = cy + r * Math.sin(s)
    const x2 = cx + r * Math.cos(e), y2 = cy + r * Math.sin(e)
    return `M ${x1} ${y1} A ${r} ${r} 0 ${Math.abs(sweep) > 180 ? 1 : 0} 1 ${x2} ${y2}`
  }
  return (
    <div className="flex flex-col items-center justify-center h-full p-1">
      <p className="text-xs text-[#7d92b0] mb-1 truncate">{widget.title}</p>
      <svg width={120} height={90} viewBox="0 0 120 90">
        <path d={arcPath(startAngle, sweepAngle)} fill="none" stroke="#1e2d42" strokeWidth={8} strokeLinecap="round" />
        <path d={arcPath(startAngle, (pct / 100) * sweepAngle)} fill="none" stroke={cs.primary} strokeWidth={8} strokeLinecap="round" />
        <text x={cx} y={cy + 8} textAnchor="middle" fill="white" fontSize={18} fontWeight="bold">{pct}</text>
        <text x={cx} y={cy + 20} textAnchor="middle" fill="#7d92b0" fontSize={8}>/ 100</text>
      </svg>
    </div>
  )
}

function AlertListWidget({ widget }: { widget: Widget }) {
  const alerts = [
    { id: 'a1', title: 'Suspicious PowerShell Execution', severity: 'critical', time: '2分前', host: 'wks-001' },
    { id: 'a2', title: 'Lateral Movement Detected', severity: 'high', time: '8分前', host: 'srv-003' },
    { id: 'a3', title: 'Brute Force Attempt', severity: 'medium', time: '15分前', host: 'srv-012' },
    { id: 'a4', title: 'Unusual DNS Query', severity: 'low', time: '23分前', host: 'wks-007' },
  ]
  const sevColor: Record<string, string> = { critical: 'bg-red-500', high: 'bg-orange-500', medium: 'bg-amber-500', low: 'bg-blue-500' }
  return (
    <div className="flex flex-col h-full p-1">
      <p className="text-xs text-[#7d92b0] mb-2 truncate">{widget.title}</p>
      <div className="space-y-1.5 flex-1 overflow-hidden">
        {alerts.map(a => (
          <div key={a.id} className="flex items-center gap-2 p-1.5 rounded bg-[#070d19] border border-[#1e2d42]">
            <div className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${sevColor[a.severity]}`} />
            <span className="text-xs text-[#e2e8f4] flex-1 truncate">{a.title}</span>
            <span className="text-[10px] text-[#3d5068] flex-shrink-0">{a.host}</span>
            <span className="text-[10px] text-[#3d5068] flex-shrink-0">{a.time}</span>
          </div>
        ))}
      </div>
    </div>
  )
}

function WidgetRenderer({ widget }: { widget: Widget }) {
  switch (widget.type) {
    case 'kpi': return <KPIWidget widget={widget} />
    case 'bar': return <BarWidget widget={widget} />
    case 'line': return <LineWidget widget={widget} />
    case 'pie': return <PieWidget widget={widget} />
    case 'table': return <TableWidget widget={widget} />
    case 'heatmap': return <HeatmapWidget widget={widget} />
    case 'gauge': return <GaugeWidget widget={widget} />
    case 'alertlist': return <AlertListWidget widget={widget} />
  }
}

// ─── Widget Picker Modal ──────────────────────────────────────────────────────

function WidgetPickerModal({
  initial,
  onClose,
  onSave,
}: {
  initial?: Partial<Widget>
  onClose: () => void
  onSave: (w: Omit<Widget, 'id' | 'col' | 'row'>) => void
}) {
  const [form, setForm] = useState<{
    type: WidgetType
    title: string
    data_source: DataSource
    metric: string
    aggregation: Aggregation
    time_range: TimeRange
    color_scheme: ColorScheme
    w: number
    h: number
  }>({
    type: initial?.type ?? 'kpi',
    title: initial?.title ?? '',
    data_source: initial?.data_source ?? 'alerts',
    metric: initial?.metric ?? 'open_count',
    aggregation: initial?.aggregation ?? 'count',
    time_range: initial?.time_range ?? '24h',
    color_scheme: initial?.color_scheme ?? 'red',
    w: initial?.w ?? 1,
    h: initial?.h ?? 1,
  })
  const set = <K extends keyof typeof form>(k: K, v: typeof form[K]) => setForm(p => ({ ...p, [k]: v }))

  const metrics = METRIC_OPTIONS[form.data_source]

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl max-h-[90vh] flex flex-col">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42] flex-shrink-0">
          <h2 className="text-white font-semibold">{initial?.id ? 'ウィジェットを編集' : 'ウィジェットを追加'}</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="overflow-y-auto px-6 py-5 space-y-4 flex-1">
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">ウィジェットタイプ</label>
            <div className="grid grid-cols-4 gap-2">
              {WIDGET_TYPES.map(wt => (
                <button key={wt.value} onClick={() => set('type', wt.value)}
                  className={`py-2 px-2 rounded-lg border text-xs font-medium transition-all ${form.type === wt.value ? 'bg-[#e8002d]/20 border-[#e8002d]/50 text-[#e8002d]' : 'border-[#1e2d42] text-[#7d92b0] hover:text-white'}`}>
                  {wt.label}
                </button>
              ))}
            </div>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">タイトル</label>
            <input value={form.title} onChange={e => set('title', e.target.value)}
              placeholder="ウィジェットのタイトル"
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">データソース</label>
              <select value={form.data_source} onChange={e => { set('data_source', e.target.value as DataSource); set('metric', METRIC_OPTIONS[e.target.value as DataSource][0].value) }}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
                {(['alerts', 'incidents', 'endpoints', 'vulnerabilities', 'compliance', 'metrics'] as const).map(s => (
                  <option key={s} value={s}>{s}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">メトリクス</label>
              <select value={form.metric} onChange={e => set('metric', e.target.value)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
                {metrics.map(m => <option key={m.value} value={m.value}>{m.label}</option>)}
              </select>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">集計方法</label>
              <select value={form.aggregation} onChange={e => set('aggregation', e.target.value as Aggregation)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
                {(['count', 'sum', 'avg', 'max', 'min', 'rate'] as const).map(a => <option key={a} value={a}>{a}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">期間</label>
              <select value={form.time_range} onChange={e => set('time_range', e.target.value as TimeRange)}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
                {(['1h', '6h', '24h', '7d', '30d'] as const).map(t => <option key={t} value={t}>{t}</option>)}
              </select>
            </div>
          </div>
          <div>
            <label className="block text-xs text-[#7d92b0] mb-1">カラースキーム</label>
            <div className="flex gap-2">
              {(Object.keys(COLOR_SCHEMES) as ColorScheme[]).map(c => (
                <button key={c} onClick={() => set('color_scheme', c)}
                  className={`w-8 h-8 rounded-full border-2 transition-all ${form.color_scheme === c ? 'border-white scale-110' : 'border-transparent'}`}
                  style={{ backgroundColor: COLOR_SCHEMES[c].primary }} />
              ))}
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">幅 (列数)</label>
              <select value={form.w} onChange={e => set('w', Number(e.target.value))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
                {[1, 2, 3].map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
            <div>
              <label className="block text-xs text-[#7d92b0] mb-1">高さ (行数)</label>
              <select value={form.h} onChange={e => set('h', Number(e.target.value))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50">
                {[1, 2, 3, 4].map(n => <option key={n} value={n}>{n}</option>)}
              </select>
            </div>
          </div>
        </div>
        <div className="px-6 py-4 border-t border-[#1e2d42] flex justify-end gap-3 flex-shrink-0">
          <button onClick={onClose} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => onSave(form)} disabled={!form.title.trim()}
            className="px-4 py-2 rounded-lg bg-[#e8002d] text-white hover:bg-[#c8001f] text-sm transition-colors disabled:opacity-50">
            {initial?.id ? '更新' : '追加'}
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Template Picker Modal ────────────────────────────────────────────────────

function TemplatePicker({ onClose, onSelect }: { onClose: () => void; onSelect: (tplId: string) => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg mx-4 shadow-2xl">
        <div className="flex items-center justify-between px-6 py-4 border-b border-[#1e2d42]">
          <h2 className="text-white font-semibold">テンプレートから開始</h2>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="px-6 py-5 space-y-3">
          {DASHBOARD_TEMPLATES.map(tpl => (
            <button key={tpl.id} onClick={() => onSelect(tpl.id)}
              className="w-full flex items-center gap-4 p-4 bg-[#070d19] border border-[#1e2d42] rounded-lg hover:border-[#2a3f5e] transition-colors text-left">
              <span className="text-2xl">{tpl.icon}</span>
              <div>
                <p className="text-white font-medium text-sm">{tpl.name}</p>
                <p className="text-xs text-[#7d92b0] mt-0.5">{tpl.description}</p>
              </div>
            </button>
          ))}
        </div>
      </div>
    </div>
  )
}

// ─── Dashboard Editor ─────────────────────────────────────────────────────────

function DashboardEditor({
  dashboard,
  onClose,
  onSave,
}: {
  dashboard: Dashboard
  onClose: () => void
  onSave: (d: Dashboard) => void
}) {
  const [name, setName] = useState(dashboard.name)
  const [widgets, setWidgets] = useState<Widget[]>(dashboard.widgets)
  const [pickerOpen, setPickerOpen] = useState(false)
  const [editWidget, setEditWidget] = useState<Widget | null>(null)
  const [toast, setToast] = useState<string | null>(null)

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3000) }

  const addWidget = (w: Omit<Widget, 'id' | 'col' | 'row'>) => {
    const newW: Widget = { ...w, id: `w${Date.now()}`, col: 0, row: widgets.length }
    setWidgets(prev => [...prev, newW])
    setPickerOpen(false)
    showToast('ウィジェットを追加しました')
  }

  const updateWidget = (updated: Omit<Widget, 'id' | 'col' | 'row'>) => {
    if (!editWidget) return
    setWidgets(prev => prev.map(w => w.id === editWidget.id ? { ...editWidget, ...updated } : w))
    setEditWidget(null)
    showToast('ウィジェットを更新しました')
  }

  const deleteWidget = (id: string) => {
    setWidgets(prev => prev.filter(w => w.id !== id))
    showToast('ウィジェットを削除しました')
  }

  const CELL_H = 120

  return (
    <div className="min-h-screen bg-[#070d19] flex flex-col">
      {toast && (
        <div className="fixed top-6 right-6 z-50 bg-[#0d1220] border border-green-500/40 text-green-400 px-4 py-3 rounded-lg shadow-2xl text-sm flex items-center gap-2">
          <CheckCircle className="w-4 h-4" /> {toast}
        </div>
      )}
      {/* Editor Header */}
      <div className="flex items-center gap-4 px-6 py-4 border-b border-[#1e2d42] bg-[#0d1220] flex-shrink-0">
        <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
          <X className="w-5 h-5" />
        </button>
        <input value={name} onChange={e => setName(e.target.value)}
          className="flex-1 bg-transparent text-white font-semibold text-lg focus:outline-none border-b border-transparent focus:border-[#e8002d]/40 pb-0.5" />
        <button onClick={() => setPickerOpen(true)}
          className="flex items-center gap-2 px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">
          <Plus className="w-4 h-4" /> ウィジェット追加
        </button>
        <button onClick={() => onSave({ ...dashboard, name, widgets, widget_count: widgets.length, last_updated: new Date().toISOString() })}
          className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] text-white hover:bg-[#c8001f] text-sm transition-colors">
          <Save className="w-4 h-4" /> 保存
        </button>
      </div>

      {/* Canvas */}
      <div className="flex-1 overflow-auto p-6">
        {widgets.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-64 text-[#3d5068]">
            <LayoutTemplate className="w-12 h-12 mb-4" />
            <p className="text-sm">ウィジェットを追加してダッシュボードを構築してください</p>
            <button onClick={() => setPickerOpen(true)}
              className="mt-4 flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d]/20 border border-[#e8002d]/30 text-[#e8002d] text-sm hover:bg-[#e8002d]/30 transition-colors">
              <Plus className="w-4 h-4" /> ウィジェットを追加
            </button>
          </div>
        ) : (
          <div className="grid grid-cols-3 gap-4 auto-rows-min">
            {widgets.map(w => (
              <div key={w.id}
                className="bg-[#0d1220] border border-[#1e2d42] rounded-xl hover:border-[#2a3f5e] transition-colors relative group overflow-hidden"
                style={{ gridColumn: `span ${Math.min(w.w, 3)}`, minHeight: CELL_H * w.h + (w.h - 1) * 16 }}>
                {/* Widget toolbar */}
                <div className="absolute top-2 right-2 flex gap-1 opacity-0 group-hover:opacity-100 transition-opacity z-10">
                  <button onClick={() => setEditWidget(w)}
                    className="p-1.5 rounded bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors">
                    <Pencil className="w-3 h-3" />
                  </button>
                  <button onClick={() => deleteWidget(w.id)}
                    className="p-1.5 rounded bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-red-400 transition-colors">
                    <Trash2 className="w-3 h-3" />
                  </button>
                </div>
                {/* Drag handle */}
                <div className="absolute top-2 left-2 opacity-0 group-hover:opacity-100 transition-opacity cursor-grab">
                  <GripVertical className="w-3.5 h-3.5 text-[#3d5068]" />
                </div>
                {/* Resize handle */}
                <div className="absolute bottom-1 right-1 opacity-0 group-hover:opacity-100 transition-opacity cursor-se-resize">
                  <Maximize2 className="w-3 h-3 text-[#3d5068]" />
                </div>
                <div className="h-full p-4">
                  <WidgetRenderer widget={w} />
                </div>
              </div>
            ))}
          </div>
        )}
      </div>

      {pickerOpen && <WidgetPickerModal onClose={() => setPickerOpen(false)} onSave={addWidget} />}
      {editWidget && <WidgetPickerModal initial={editWidget} onClose={() => setEditWidget(null)} onSave={updateWidget} />}
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function DataVizPage() {
  const qc = useQueryClient()
  const [editingDash, setEditingDash] = useState<Dashboard | null>(null)
  const [newDashName, setNewDashName] = useState('')
  const [showNewForm, setShowNewForm] = useState(false)
  const [showTemplate, setShowTemplate] = useState(false)
  const [toast, setToast] = useState<string | null>(null)

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 3000) }

  const { data: dashboards = [] } = useQuery<Dashboard[]>({
    queryKey: ['dashboards'],
    queryFn: () => apiFetch('/api/v1/admin/dashboards'),
  })

  const saveMutation = useMutation({
    mutationFn: (d: Dashboard) =>
      d.id.startsWith('new')
        ? apiFetch('/api/v1/admin/dashboards', { method: 'POST', body: JSON.stringify(d) }).catch(() => d)
        : apiFetch(`/api/v1/admin/dashboards/${d.id}`, { method: 'PUT', body: JSON.stringify(d) }).catch(() => d),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['dashboards'] }); showToast('ダッシュボードを保存しました') },
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/dashboards/${id}`, { method: 'DELETE' }).catch(() => null),
    onSuccess: () => { qc.invalidateQueries({ queryKey: ['dashboards'] }); showToast('削除しました') },
  })

  const handleNewDashboard = () => {
    const d: Dashboard = {
      id: `new_${Date.now()}`,
      name: newDashName || '新しいダッシュボード',
      created_by: 'current_user',
      last_updated: new Date().toISOString(),
      widget_count: 0,
      widgets: [],
    }
    setEditingDash(d)
    setShowNewForm(false)
    setNewDashName('')
  }

  const handleTemplateSelect = (tplId: string) => {
    const tpl = DASHBOARD_TEMPLATES.find(t => t.id === tplId)!
    const d: Dashboard = {
      id: `new_${Date.now()}`,
      name: tpl.name,
      created_by: 'current_user',
      last_updated: new Date().toISOString(),
      widget_count: 0,
      widgets: [],
    }
    setShowTemplate(false)
    setEditingDash(d)
  }

  if (editingDash) {
    return (
      <DashboardEditor
        dashboard={editingDash}
        onClose={() => setEditingDash(null)}
        onSave={(d) => {
          saveMutation.mutate(d)
          setEditingDash(null)
        }}
      />
    )
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {toast && (
        <div className="fixed top-6 right-6 z-50 bg-[#0d1220] border border-green-500/40 text-green-400 px-4 py-3 rounded-lg shadow-2xl text-sm flex items-center gap-2">
          <CheckCircle className="w-4 h-4" /> {toast}
        </div>
      )}

      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-gradient-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
            <PieChart className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">データビジュアライゼーション</h1>
            <p className="text-xs text-[#7d92b0] mt-0.5">カスタムダッシュボードビルダー</p>
          </div>
        </div>
        <div className="flex gap-3">
          <button onClick={() => setShowTemplate(true)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-sm transition-colors">
            <LayoutTemplate className="w-4 h-4" /> テンプレート
          </button>
          <button onClick={() => setShowNewForm(v => !v)}
            className="flex items-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d] text-white hover:bg-[#c8001f] text-sm transition-colors">
            <Plus className="w-4 h-4" /> 新規ダッシュボード
          </button>
        </div>
      </div>

      {/* New dashboard inline form */}
      {showNewForm && (
        <div className="flex items-center gap-3 p-4 bg-[#0d1220] border border-[#1e2d42] rounded-xl">
          <input value={newDashName} onChange={e => setNewDashName(e.target.value)}
            placeholder="ダッシュボード名を入力..."
            className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]/50" />
          <button onClick={handleNewDashboard}
            className="px-4 py-2 rounded-lg bg-[#e8002d] text-white hover:bg-[#c8001f] text-sm transition-colors">
            作成して編集
          </button>
          <button onClick={() => setShowNewForm(false)} className="text-[#7d92b0] hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>
      )}

      {/* Dashboard Gallery */}
      <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
        {dashboards.map(dash => (
          <div key={dash.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden hover:border-[#2a3f5e] transition-colors group">
            {/* Thumbnail */}
            <div className="relative h-32 bg-[#070d19] border-b border-[#1e2d42] overflow-hidden">
              <div className="absolute inset-0 grid grid-cols-3 grid-rows-3 gap-1 p-2 opacity-60">
                {dash.widgets.slice(0, 6).map((w, i) => {
                  const cs = COLOR_SCHEMES[w.color_scheme]
                  return (
                    <div key={i} className={`${cs.bg} rounded border border-[#1e2d42] flex items-center justify-center`}
                      style={{ gridColumn: `span ${Math.min(w.w, 3)}` }}>
                      <div className="w-4 h-4 rounded-sm" style={{ backgroundColor: cs.primary, opacity: 0.5 }} />
                    </div>
                  )
                })}
              </div>
              <div className="absolute inset-0 bg-gradient-to-t from-[#0d1220] to-transparent opacity-0 group-hover:opacity-60 transition-opacity" />
              <div className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity gap-3">
                <button onClick={() => setEditingDash(dash)}
                  className="p-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors">
                  <Eye className="w-4 h-4" />
                </button>
                <button onClick={() => setEditingDash(dash)}
                  className="p-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors">
                  <Pencil className="w-4 h-4" />
                </button>
              </div>
            </div>
            {/* Info */}
            <div className="p-4">
              <h3 className="text-white font-semibold text-sm truncate">{dash.name}</h3>
              <div className="flex items-center gap-2 mt-1.5">
                <span className="text-xs text-[#7d92b0]">{displayUser(dash.created_by)}</span>
                <span className="w-1 h-1 rounded-full bg-[#3d5068]" />
                <span className="text-xs text-[#7d92b0] flex items-center gap-1">
                  <Clock className="w-3 h-3" />
                  {new Date(dash.last_updated).toLocaleDateString('ja-JP')}
                </span>
                <span className="w-1 h-1 rounded-full bg-[#3d5068]" />
                <span className="text-xs text-[#7d92b0]">{dash.widget_count}個</span>
              </div>
              <div className="flex gap-2 mt-3">
                <button onClick={() => setEditingDash(dash)}
                  className="flex-1 py-1.5 rounded-lg bg-[#e8002d]/20 border border-[#e8002d]/30 text-[#e8002d] hover:bg-[#e8002d]/30 text-xs font-medium transition-colors">
                  開く
                </button>
                <button onClick={() => setEditingDash(dash)}
                  className="flex-1 py-1.5 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white text-xs font-medium transition-colors flex items-center justify-center gap-1">
                  <Pencil className="w-3 h-3" /> 編集
                </button>
                <button onClick={() => deleteMutation.mutate(dash.id)}
                  className="py-1.5 px-3 rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-red-400 text-xs transition-colors">
                  <Trash2 className="w-3 h-3" />
                </button>
              </div>
            </div>
          </div>
        ))}
      </div>

      {/* Template picker */}
      {showTemplate && (
        <TemplatePicker
          onClose={() => setShowTemplate(false)}
          onSelect={handleTemplateSelect}
        />
      )}
    </div>
  )
}
