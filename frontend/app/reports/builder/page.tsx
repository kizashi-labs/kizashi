'use client'

import { useState } from 'react'
import { useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Plus, Trash2, ChevronUp, ChevronDown,
  Settings, Eye, Printer, Save, X,
  BarChart2, PieChart, TrendingUp, Table,
  FileText, Minus, Shield, Monitor, Bell,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

type WidgetSize = 'half' | 'full'

interface WidgetDef {
  id: string
  type: string
  category: string
  label: string
  icon: React.ReactNode
}

interface PlacedWidget {
  uid: string
  type: string
  title: string
  size: WidgetSize
}

interface WidgetConfig {
  title: string
  size: WidgetSize
}

// ─── Widget Definitions ────────────────────────────────────────────────────

const WIDGET_PALETTE: { category: string; widgets: WidgetDef[] }[] = [
  {
    category: 'サマリー',
    widgets: [
      { id: 'alert_count', type: 'alert_count', category: 'summary', label: 'アラート数', icon: <Bell className="w-4 h-4" /> },
      { id: 'agent_status', type: 'agent_status', category: 'summary', label: 'エージェント状態', icon: <Monitor className="w-4 h-4" /> },
      { id: 'risk_score', type: 'risk_score', category: 'summary', label: 'リスクスコア', icon: <Shield className="w-4 h-4" /> },
    ],
  },
  {
    category: 'グラフ',
    widgets: [
      { id: 'alert_trend', type: 'alert_trend', category: 'chart', label: 'アラートトレンド (折れ線)', icon: <TrendingUp className="w-4 h-4" /> },
      { id: 'top_threats', type: 'top_threats', category: 'chart', label: 'トップ脅威 (棒)', icon: <BarChart2 className="w-4 h-4" /> },
      { id: 'severity_dist', type: 'severity_dist', category: 'chart', label: '深刻度分布 (円)', icon: <PieChart className="w-4 h-4" /> },
    ],
  },
  {
    category: 'テーブル',
    widgets: [
      { id: 'recent_alerts', type: 'recent_alerts', category: 'table', label: '最近のアラート', icon: <Table className="w-4 h-4" /> },
      { id: 'active_incidents', type: 'active_incidents', category: 'table', label: 'アクティブインシデント', icon: <Table className="w-4 h-4" /> },
      { id: 'top_agents', type: 'top_agents', category: 'table', label: 'トップエージェント', icon: <Table className="w-4 h-4" /> },
    ],
  },
  {
    category: 'テキスト',
    widgets: [
      { id: 'free_text', type: 'free_text', category: 'text', label: 'フリーテキスト', icon: <FileText className="w-4 h-4" /> },
      { id: 'section_header', type: 'section_header', category: 'text', label: 'セクションヘッダー', icon: <FileText className="w-4 h-4" /> },
      { id: 'divider', type: 'divider', category: 'text', label: '区切り線', icon: <Minus className="w-4 h-4" /> },
    ],
  },
]

// ─── Widget Preview Components ─────────────────────────────────────────────

function AlertCountPreview() {
  return (
    <div className="flex flex-col items-center justify-center py-4">
      <div className="text-5xl font-black text-[#e8002d]">47</div>
      <div className="text-xs text-[#7d92b0] mt-1">過去24時間のアラート</div>
    </div>
  )
}

function AgentStatusPreview() {
  return (
    <div className="flex items-center justify-center gap-6 py-4">
      <div className="flex items-center gap-2 text-sm">
        <span className="w-3 h-3 rounded-full bg-[#00c853]" />
        <span className="text-white font-bold">298</span>
        <span className="text-[#7d92b0] text-xs">オンライン</span>
      </div>
      <div className="flex items-center gap-2 text-sm">
        <span className="w-3 h-3 rounded-full bg-[#ffd740]" />
        <span className="text-white font-bold">21</span>
        <span className="text-[#7d92b0] text-xs">警告</span>
      </div>
      <div className="flex items-center gap-2 text-sm">
        <span className="w-3 h-3 rounded-full bg-[#e8002d]" />
        <span className="text-white font-bold">12</span>
        <span className="text-[#7d92b0] text-xs">オフライン</span>
      </div>
    </div>
  )
}

function RiskScorePreview() {
  return (
    <div className="flex flex-col items-center justify-center py-4">
      <div className="text-5xl font-black text-[#ffd740]">63</div>
      <div className="text-xs text-[#7d92b0] mt-1">組織リスクスコア</div>
      <div className="mt-2 text-xs px-2 py-0.5 rounded bg-[#ffd740]/20 text-[#ffd740]">中リスク</div>
    </div>
  )
}

function AlertTrendPreview() {
  const pts = [18, 24, 19, 31, 27, 22, 35, 29, 42, 38, 31, 47]
  const max = Math.max(...pts)
  const min = Math.min(...pts) - 2
  const w = 200, h = 50
  const toX = (i: number) => (i / (pts.length - 1)) * w
  const toY = (v: number) => h - ((v - min) / (max - min)) * h
  const points = pts.map((v, i) => `${toX(i)},${toY(v)}`).join(' ')
  const area = `0,${h} ${points} ${w},${h}`
  return (
    <div className="px-2 py-2">
      <svg viewBox={`0 0 ${w} ${h}`} className="w-full" style={{ height: 50 }}>
        <defs>
          <linearGradient id="trendGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#e8002d" stopOpacity="0.4" />
            <stop offset="100%" stopColor="#e8002d" stopOpacity="0" />
          </linearGradient>
        </defs>
        <polygon points={area} fill="url(#trendGrad)" />
        <polyline points={points} fill="none" stroke="#e8002d" strokeWidth="2" strokeLinejoin="round" />
      </svg>
      <div className="text-xs text-[#7d92b0] text-center">過去12時間</div>
    </div>
  )
}

function TopThreatsPreview() {
  const threats = [
    { name: 'Mimikatz', count: 12, color: '#e8002d' },
    { name: 'PowerShell', count: 9, color: '#ff9100' },
    { name: 'CobaltStrike', count: 7, color: '#ffd740' },
  ]
  const max = threats[0].count
  return (
    <div className="px-2 py-2 space-y-1.5">
      {threats.map(t => (
        <div key={t.name} className="flex items-center gap-2 text-xs">
          <span className="text-[#7d92b0] w-24 truncate">{t.name}</span>
          <div className="flex-1 h-3 bg-[#1e2d42] rounded overflow-hidden">
            <div className="h-full rounded" style={{ width: `${(t.count / max) * 100}%`, background: t.color }} />
          </div>
          <span className="text-white w-5 text-right">{t.count}</span>
        </div>
      ))}
    </div>
  )
}

function SeverityDistPreview() {
  const items = [
    { label: 'Critical', pct: 15, color: '#e8002d' },
    { label: 'High', pct: 28, color: '#ff9100' },
    { label: 'Medium', pct: 42, color: '#ffd740' },
    { label: 'Low', pct: 15, color: '#69f0ae' },
  ]
  return (
    <div className="px-2 py-2 space-y-1.5">
      {items.map(item => (
        <div key={item.label} className="flex items-center gap-2 text-xs">
          <span className="w-2.5 h-2.5 rounded-sm" style={{ background: item.color }} />
          <span className="text-[#7d92b0] w-14">{item.label}</span>
          <div className="flex-1 h-2.5 bg-[#1e2d42] rounded overflow-hidden">
            <div className="h-full rounded" style={{ width: `${item.pct}%`, background: item.color }} />
          </div>
          <span className="text-[#c8d6ea] w-8 text-right">{item.pct}%</span>
        </div>
      ))}
    </div>
  )
}

function RecentAlertsPreview() {
  const rows = [
    { id: 'AL-5512', title: 'PowerShell異常実行', sev: 'High', time: '5分前' },
    { id: 'AL-5511', title: 'RDP不審接続', sev: 'Critical', time: '12分前' },
    { id: 'AL-5510', title: 'ファイル変更検知', sev: 'Medium', time: '28分前' },
  ]
  const sevColor: Record<string, string> = { Critical: '#e8002d', High: '#ff9100', Medium: '#ffd740' }
  return (
    <div className="px-1 py-1">
      <table className="w-full text-xs">
        <thead><tr className="text-[#7d92b0] border-b border-[#1e2d42]">
          <th className="pb-1 text-left">ID</th>
          <th className="pb-1 text-left">タイトル</th>
          <th className="pb-1 text-right">深刻度</th>
        </tr></thead>
        <tbody className="divide-y divide-[#1e2d42]">
          {rows.map(r => (
            <tr key={r.id}>
              <td className="py-1 text-[#e8002d] font-mono">{r.id}</td>
              <td className="py-1 text-white truncate max-w-[100px]">{r.title}</td>
              <td className="py-1 text-right" style={{ color: sevColor[r.sev] || '#7d92b0' }}>{r.sev}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function ActiveIncidentsPreview() {
  const rows = [
    { id: 'INC-234', title: 'ランサムウェア感染', status: '調査中' },
    { id: 'INC-233', title: '不審なラテラルムーブ', status: '対応中' },
    { id: 'INC-232', title: 'データ漏洩の可能性', status: '調査中' },
  ]
  return (
    <div className="px-1 py-1">
      <table className="w-full text-xs">
        <thead><tr className="text-[#7d92b0] border-b border-[#1e2d42]">
          <th className="pb-1 text-left">ID</th>
          <th className="pb-1 text-left">タイトル</th>
          <th className="pb-1 text-right">状態</th>
        </tr></thead>
        <tbody className="divide-y divide-[#1e2d42]">
          {rows.map(r => (
            <tr key={r.id}>
              <td className="py-1 text-[#e8002d] font-mono">{r.id}</td>
              <td className="py-1 text-white truncate max-w-[100px]">{r.title}</td>
              <td className="py-1 text-right text-[#ffd740]">{r.status}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function TopAgentsPreview() {
  const rows = [
    { host: 'WIN-SRV01', alerts: 12, risk: 'High' },
    { host: 'LINUX-DB02', alerts: 8, risk: 'Medium' },
    { host: 'WIN-WS08', alerts: 5, risk: 'Low' },
  ]
  return (
    <div className="px-1 py-1">
      <table className="w-full text-xs">
        <thead><tr className="text-[#7d92b0] border-b border-[#1e2d42]">
          <th className="pb-1 text-left">ホスト</th>
          <th className="pb-1 text-center">アラート</th>
          <th className="pb-1 text-right">リスク</th>
        </tr></thead>
        <tbody className="divide-y divide-[#1e2d42]">
          {rows.map(r => (
            <tr key={r.host}>
              <td className="py-1 text-white font-mono text-[10px]">{r.host}</td>
              <td className="py-1 text-center text-[#c8d6ea]">{r.alerts}</td>
              <td className="py-1 text-right text-[#ffd740]">{r.risk}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  )
}

function FreeTextPreview({ widgetUid, texts, onTextChange }: { widgetUid: string; texts: Record<string, string>; onTextChange: (uid: string, v: string) => void }) {
  return (
    <textarea
      value={texts[widgetUid] ?? ''}
      onChange={e => onTextChange(widgetUid, e.target.value)}
      placeholder="テキストを入力..."
      rows={3}
      className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-2 text-sm text-[#c8d6ea] resize-none focus:outline-none focus:border-[#e8002d]"
    />
  )
}

function SectionHeaderPreview() {
  return <div className="text-base font-bold text-white py-2 border-b border-[#1e2d42]">セクション名</div>
}

function DividerPreview() {
  return <hr className="border-[#1e2d42] my-2" />
}

const WIDGET_PREVIEWS: Record<string, React.ComponentType<any>> = {
  alert_count: AlertCountPreview,
  agent_status: AgentStatusPreview,
  risk_score: RiskScorePreview,
  alert_trend: AlertTrendPreview,
  top_threats: TopThreatsPreview,
  severity_dist: SeverityDistPreview,
  recent_alerts: RecentAlertsPreview,
  active_incidents: ActiveIncidentsPreview,
  top_agents: TopAgentsPreview,
  section_header: SectionHeaderPreview,
  divider: DividerPreview,
}

// ─── Main Page ─────────────────────────────────────────────────────────────

export default function ReportBuilderPage() {
  const [widgets, setWidgets] = useState<PlacedWidget[]>([])
  const [reportTitle, setReportTitle] = useState('新しいレポート')
  const [reportDesc, setReportDesc] = useState('')
  const [dateFrom, setDateFrom] = useState('')
  const [dateTo, setDateTo] = useState('')
  const [configModal, setConfigModal] = useState<string | null>(null)
  const [configDraft, setConfigDraft] = useState<WidgetConfig>({ title: '', size: 'half' })
  const [previewOpen, setPreviewOpen] = useState(false)
  const [freeTexts, setFreeTexts] = useState<Record<string, string>>({})
  const [saveMsg, setSaveMsg] = useState('')

  const saveMutation = useMutation({
    mutationFn: () =>
      apiFetch('/api/v1/admin/report-templates', {
        method: 'POST',
        body: JSON.stringify({ title: reportTitle, description: reportDesc, widgets }),
      }).catch(() => ({ ok: true })),
    onSuccess: () => {
      setSaveMsg('テンプレートを保存しました')
      setTimeout(() => setSaveMsg(''), 3000)
    },
  })

  function addWidget(def: WidgetDef) {
    const uid = `${def.type}_${Date.now()}`
    setWidgets(prev => [...prev, { uid, type: def.type, title: def.label, size: 'half' }])
  }

  function removeWidget(uid: string) {
    setWidgets(prev => prev.filter(w => w.uid !== uid))
  }

  function moveWidget(uid: string, dir: 'up' | 'down') {
    setWidgets(prev => {
      const idx = prev.findIndex(w => w.uid === uid)
      if (idx === -1) return prev
      const next = [...prev]
      if (dir === 'up' && idx > 0) {
        [next[idx - 1], next[idx]] = [next[idx], next[idx - 1]]
      } else if (dir === 'down' && idx < next.length - 1) {
        [next[idx], next[idx + 1]] = [next[idx + 1], next[idx]]
      }
      return next
    })
  }

  function openConfig(w: PlacedWidget) {
    setConfigDraft({ title: w.title, size: w.size })
    setConfigModal(w.uid)
  }

  function applyConfig() {
    if (!configModal) return
    setWidgets(prev => prev.map(w => w.uid === configModal ? { ...w, ...configDraft } : w))
    setConfigModal(null)
  }

  function handleFreeTextChange(uid: string, v: string) {
    setFreeTexts(prev => ({ ...prev, [uid]: v }))
  }

  function renderWidgetPreview(w: PlacedWidget) {
    if (w.type === 'free_text') {
      return <FreeTextPreview widgetUid={w.uid} texts={freeTexts} onTextChange={handleFreeTextChange} />
    }
    const Comp = WIDGET_PREVIEWS[w.type]
    return Comp ? <Comp /> : <div className="text-[#7d92b0] text-xs py-3 text-center">プレビューなし</div>
  }

  // Group widgets into rows of 2 for half-size, full-size takes full row
  function buildGrid(): PlacedWidget[][] {
    const rows: PlacedWidget[][] = []
    let i = 0
    while (i < widgets.length) {
      const w = widgets[i]
      if (w.size === 'full') {
        rows.push([w])
        i++
      } else {
        const next = widgets[i + 1]
        if (next && next.size === 'half') {
          rows.push([w, next])
          i += 2
        } else {
          rows.push([w])
          i++
        }
      }
    }
    return rows
  }

  const grid = buildGrid()

  return (
    <div className="min-h-screen bg-[#070d19]">
      {/* Config Modal */}
      {configModal && (
        <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-80 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-semibold text-white">ウィジェット設定</h3>
              <button onClick={() => setConfigModal(null)}><X className="w-4 h-4 text-[#7d92b0]" /></button>
            </div>
            <div className="space-y-3">
              <div>
                <label className="text-xs text-[#7d92b0] mb-1 block">タイトル</label>
                <input
                  value={configDraft.title}
                  onChange={e => setConfigDraft(p => ({ ...p, title: e.target.value }))}
                  className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#e8002d]"
                />
              </div>
              <div>
                <label className="text-xs text-[#7d92b0] mb-1 block">サイズ</label>
                <div className="flex gap-2">
                  {(['half', 'full'] as const).map(s => (
                    <button
                      key={s}
                      onClick={() => setConfigDraft(p => ({ ...p, size: s }))}
                      className={`flex-1 py-1.5 rounded text-xs font-medium border transition-colors ${configDraft.size === s ? 'bg-[#e8002d]/20 border-[#e8002d] text-[#e8002d]' : 'border-[#1e2d42] text-[#7d92b0]'}`}
                    >
                      {s === 'half' ? '1/2幅' : '全幅'}
                    </button>
                  ))}
                </div>
              </div>
            </div>
            <button
              onClick={applyConfig}
              className="w-full py-2 bg-[#e8002d] hover:bg-[#c0001e] rounded text-white text-sm font-medium transition-colors"
            >
              適用
            </button>
          </div>
        </div>
      )}

      {/* Preview Modal */}
      {previewOpen && (
        <div className="fixed inset-0 bg-[#070d19] z-50 overflow-auto p-8">
          <div className="max-w-5xl mx-auto">
            <div className="flex items-center justify-between mb-6">
              <div>
                <h1 className="text-2xl font-bold text-white">{reportTitle}</h1>
                {reportDesc && <p className="text-[#7d92b0] text-sm mt-1">{reportDesc}</p>}
                {(dateFrom || dateTo) && (
                  <p className="text-xs text-[#7d92b0] mt-1">{dateFrom} 〜 {dateTo}</p>
                )}
              </div>
              <button
                onClick={() => setPreviewOpen(false)}
                className="flex items-center gap-2 px-4 py-2 bg-[#1e2d42] hover:bg-[#2d3f58] rounded text-white text-sm transition-colors"
              >
                <X className="w-4 h-4" /> 閉じる
              </button>
            </div>
            {grid.length === 0 ? (
              <div className="text-center text-[#7d92b0] py-16">ウィジェットが追加されていません</div>
            ) : (
              <div className="space-y-4">
                {grid.map((row, ri) => (
                  <div key={ri} className={`grid gap-4 ${row.length === 2 ? 'grid-cols-2' : 'grid-cols-1'}`}>
                    {row.map(w => (
                      <div key={w.uid} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
                        <h3 className="text-sm font-semibold text-white mb-3 border-b border-[#1e2d42] pb-2">{w.title}</h3>
                        {renderWidgetPreview(w)}
                      </div>
                    ))}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}

      <div className="flex h-screen">
        {/* Left Panel — Palette */}
        <div className="w-64 flex-shrink-0 bg-[#0d1220] border-r border-[#1e2d42] flex flex-col">
          <div className="px-4 py-4 border-b border-[#1e2d42]">
            <h2 className="text-sm font-semibold text-white">ウィジェットパレット</h2>
            <p className="text-xs text-[#7d92b0] mt-0.5">クリックして追加</p>
          </div>
          <div className="flex-1 overflow-y-auto p-3 space-y-4">
            {WIDGET_PALETTE.map(group => (
              <div key={group.category}>
                <div className="text-[10px] text-[#3d5068] uppercase tracking-wider mb-2 px-1">{group.category}</div>
                <div className="space-y-1">
                  {group.widgets.map(def => (
                    <button
                      key={def.id}
                      onClick={() => addWidget(def)}
                      className="w-full flex items-center gap-2.5 px-3 py-2 rounded-lg text-left text-sm text-[#c8d6ea] hover:bg-[#1e2d42] hover:text-white transition-colors group"
                    >
                      <span className="text-[#7d92b0] group-hover:text-[#e8002d] transition-colors">{def.icon}</span>
                      <span className="flex-1 truncate">{def.label}</span>
                      <Plus className="w-3.5 h-3.5 text-[#3d5068] group-hover:text-[#e8002d] flex-shrink-0" />
                    </button>
                  ))}
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Right Panel — Canvas */}
        <div className="flex-1 flex flex-col overflow-hidden">
          {/* Metadata Bar */}
          <div className="bg-[#0d1220] border-b border-[#1e2d42] px-5 py-3 space-y-2">
            <div className="flex items-center gap-3">
              <h1 className="text-sm font-semibold text-[#7d92b0] flex-shrink-0">カスタムレポートビルダー</h1>
              <div className="flex items-center gap-2 flex-1">
                <input
                  value={reportTitle}
                  onChange={e => setReportTitle(e.target.value)}
                  placeholder="レポートタイトル"
                  className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded px-3 py-1.5 text-sm text-white focus:outline-none focus:border-[#e8002d] min-w-0"
                />
                <input
                  type="date"
                  value={dateFrom}
                  onChange={e => setDateFrom(e.target.value)}
                  className="bg-[#070d19] border border-[#1e2d42] rounded px-3 py-1.5 text-xs text-[#c8d6ea] focus:outline-none focus:border-[#e8002d] w-36"
                />
                <span className="text-[#7d92b0] text-xs">〜</span>
                <input
                  type="date"
                  value={dateTo}
                  onChange={e => setDateTo(e.target.value)}
                  className="bg-[#070d19] border border-[#1e2d42] rounded px-3 py-1.5 text-xs text-[#c8d6ea] focus:outline-none focus:border-[#e8002d] w-36"
                />
              </div>
              {/* Action buttons */}
              <div className="flex items-center gap-2 flex-shrink-0">
                <button
                  onClick={() => setPreviewOpen(true)}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1e2d42] hover:bg-[#2d3f58] rounded text-xs text-white transition-colors"
                >
                  <Eye className="w-3.5 h-3.5" /> プレビュー
                </button>
                <button
                  onClick={() => window.print()}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-[#1e2d42] hover:bg-[#2d3f58] rounded text-xs text-white transition-colors"
                >
                  <Printer className="w-3.5 h-3.5" /> PDFエクスポート
                </button>
                <button
                  onClick={() => saveMutation.mutate()}
                  disabled={saveMutation.isPending}
                  className="flex items-center gap-1.5 px-3 py-1.5 bg-[#e8002d] hover:bg-[#c0001e] rounded text-xs text-white transition-colors disabled:opacity-50"
                >
                  <Save className="w-3.5 h-3.5" /> テンプレート保存
                </button>
                <button
                  onClick={() => { setWidgets([]); setFreeTexts({}) }}
                  className="flex items-center gap-1.5 px-3 py-1.5 border border-[#1e2d42] hover:border-[#e8002d] rounded text-xs text-[#7d92b0] hover:text-[#e8002d] transition-colors"
                >
                  <X className="w-3.5 h-3.5" /> クリア
                </button>
              </div>
            </div>
            <textarea
              value={reportDesc}
              onChange={e => setReportDesc(e.target.value)}
              placeholder="レポートの説明 (オプション)"
              rows={1}
              className="w-full bg-[#070d19] border border-[#1e2d42] rounded px-3 py-1.5 text-xs text-[#c8d6ea] resize-none focus:outline-none focus:border-[#e8002d]"
            />
            {saveMsg && <p className="text-xs text-[#00c853]">{saveMsg}</p>}
          </div>

          {/* Canvas */}
          <div className="flex-1 overflow-y-auto p-5">
            {widgets.length === 0 ? (
              <div className="h-full flex flex-col items-center justify-center text-center gap-3">
                <div className="w-16 h-16 rounded-full bg-[#1e2d42] flex items-center justify-center">
                  <Plus className="w-8 h-8 text-[#3d5068]" />
                </div>
                <p className="text-[#7d92b0] text-sm">左のパレットからウィジェットを追加してください</p>
                <p className="text-[#3d5068] text-xs">クリックするとキャンバスに配置されます</p>
              </div>
            ) : (
              <div className="space-y-4">
                {grid.map((row, ri) => (
                  <div key={ri} className={`grid gap-4 ${row.length === 2 ? 'grid-cols-2' : 'grid-cols-1'}`}>
                    {row.map(w => {
                      const globalIdx = widgets.findIndex(x => x.uid === w.uid)
                      return (
                        <div
                          key={w.uid}
                          className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden hover:border-[#2d3f58] transition-colors group"
                        >
                          {/* Widget header */}
                          <div className="flex items-center justify-between px-4 py-2 bg-[#0a1020] border-b border-[#1e2d42]">
                            <span className="text-sm font-medium text-white truncate">{w.title}</span>
                            <div className="flex items-center gap-0.5 opacity-0 group-hover:opacity-100 transition-opacity">
                              <button
                                onClick={() => moveWidget(w.uid, 'up')}
                                disabled={globalIdx === 0}
                                className="p-1 rounded hover:bg-[#1e2d42] text-[#7d92b0] disabled:opacity-30"
                              >
                                <ChevronUp className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => moveWidget(w.uid, 'down')}
                                disabled={globalIdx === widgets.length - 1}
                                className="p-1 rounded hover:bg-[#1e2d42] text-[#7d92b0] disabled:opacity-30"
                              >
                                <ChevronDown className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => openConfig(w)}
                                className="p-1 rounded hover:bg-[#1e2d42] text-[#7d92b0] hover:text-white"
                              >
                                <Settings className="w-3.5 h-3.5" />
                              </button>
                              <button
                                onClick={() => removeWidget(w.uid)}
                                className="p-1 rounded hover:bg-[#e8002d]/20 text-[#7d92b0] hover:text-[#e8002d]"
                              >
                                <Trash2 className="w-3.5 h-3.5" />
                              </button>
                            </div>
                          </div>
                          {/* Widget content */}
                          <div className="px-4 py-3">
                            {renderWidgetPreview(w)}
                          </div>
                        </div>
                      )
                    })}
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      </div>
    </div>
  )

}
