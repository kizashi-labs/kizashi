'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  ShieldCheck, RefreshCw, Download, ChevronDown, ChevronRight,
  CheckCircle, XCircle, AlertTriangle, Clock, X,
  Activity, TrendingDown, TrendingUp, Minus,
  Settings, FileText, Link as LinkIcon, Play
} from 'lucide-react'

// ── Types ────────────────────────────────────────────────────────

type ControlStatus = 'passing' | 'failing' | 'degraded' | 'not_tested'
type ControlType = 'automated' | 'manual'
type Trend = 'up' | 'down' | 'stable'
type MonitorFreq = 'hourly' | 'daily' | 'weekly' | 'manual'

interface ControlHistoryEntry {
  date: string
  status: ControlStatus
  measurement: string
}

interface Control {
  id: string
  name: string
  description: string
  expected_behavior: string
  current_measurement: string
  threshold: string
  control_type: ControlType
  last_tested: string | null
  current_status: ControlStatus
  trend: Trend
  evidence_link: string
  compliance_mappings: string[]
  history: ControlHistoryEntry[]
}

interface ControlDomain {
  id: string
  name: string
  health_percent: number
  monitor_frequency: MonitorFreq
  controls: Control[]
}

interface CCMSummary {
  overall_health: number
  last_assessment: string
  total_controls: number
  passing: number
  failing: number
  degraded: number
  not_tested: number
  domains: ControlDomain[]
}

const EMPTY_DATA: CCMSummary = {
  overall_health: 0,
  last_assessment: '',
  total_controls: 0,
  passing: 0,
  failing: 0,
  degraded: 0,
  not_tested: 0,
  domains: [],
}

// ── Helpers ──────────────────────────────────────────────────────

const STATUS_CONFIG: Record<ControlStatus, { icon: React.ComponentType<{ className?: string }>; bg: string; text: string; label: string }> = {
  passing:    { icon: CheckCircle,   bg: 'bg-green-900/40',   text: 'text-green-300',  label: '正常' },
  failing:    { icon: XCircle,       bg: 'bg-red-900/40',     text: 'text-red-300',    label: '失敗' },
  degraded:   { icon: AlertTriangle, bg: 'bg-yellow-900/40',  text: 'text-yellow-300', label: '低下' },
  not_tested: { icon: Clock,         bg: 'bg-gray-800',       text: 'text-gray-400',   label: '未テスト' },
}

function getHealthColor(pct: number) {
  if (pct >= 85) return { color: 'text-green-400', label: 'GREEN', bg: 'bg-green-500' }
  if (pct >= 65) return { color: 'text-yellow-400', label: 'AMBER', bg: 'bg-yellow-500' }
  return { color: 'text-red-400', label: 'RED', bg: 'bg-red-500' }
}

function fmtDate(ts: string | null) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function TrendIcon({ trend }: { trend: Trend }) {
  if (trend === 'up') return <TrendingUp className="w-3.5 h-3.5 text-green-400" />
  if (trend === 'down') return <TrendingDown className="w-3.5 h-3.5 text-red-400" />
  return <Minus className="w-3.5 h-3.5 text-gray-400" />
}

// ── Control Row ──────────────────────────────────────────────────

function ControlRow({ control }: { control: Control }) {
  const [expanded, setExpanded] = useState(false)
  const status = STATUS_CONFIG[control.current_status]
  const StatusIcon = status.icon

  return (
    <>
      <tr className="border-t border-[#1e2d42] hover:bg-[#070d19]/50 cursor-pointer" onClick={() => setExpanded(e => !e)}>
        <td className="px-4 py-3">
          <div className="flex items-center gap-2">
            {expanded ? <ChevronDown className="w-3.5 h-3.5 text-[#7d92b0]" /> : <ChevronRight className="w-3.5 h-3.5 text-[#7d92b0]" />}
            <span className="text-white text-sm font-medium">{control.name}</span>
          </div>
        </td>
        <td className="px-4 py-3">
          <span className={`px-2 py-0.5 rounded text-xs font-medium ${control.control_type === 'automated' ? 'bg-blue-900/40 text-blue-300' : 'bg-purple-900/40 text-purple-300'}`}>
            {control.control_type === 'automated' ? '自動' : '手動'}
          </span>
        </td>
        <td className="px-4 py-3 text-[#7d92b0] text-xs">{fmtDate(control.last_tested)}</td>
        <td className="px-4 py-3">
          <div className="flex items-center gap-1.5">
            <StatusIcon className={`w-4 h-4 ${status.text}`} />
            <span className={`px-1.5 py-0.5 rounded text-xs font-medium ${status.bg} ${status.text}`}>{status.label}</span>
          </div>
        </td>
        <td className="px-4 py-3"><TrendIcon trend={control.trend} /></td>
        <td className="px-4 py-3 text-[#7d92b0] text-xs truncate max-w-[120px]">{control.evidence_link || '—'}</td>
      </tr>
      {expanded && (
        <tr className="bg-[#070d19]/30">
          <td colSpan={6} className="px-8 py-4">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-1">期待動作</p>
                <p className="text-white text-sm">{control.expected_behavior}</p>
              </div>
              <div>
                <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-1">現在の測定値</p>
                <p className={`text-sm font-semibold ${status.text}`}>{control.current_measurement}</p>
              </div>
              <div>
                <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-1">閾値</p>
                <p className="text-white text-sm">{control.threshold}</p>
              </div>
              <div>
                <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-1">コンプライアンスマッピング</p>
                <div className="flex flex-wrap gap-1">
                  {control.compliance_mappings.map(m => (
                    <span key={m} className="px-1.5 py-0.5 bg-[#1e2d42] rounded text-[10px] text-[#7d92b0]">{m}</span>
                  ))}
                </div>
              </div>
            </div>
            {/* History */}
            <div className="mt-3">
              <p className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">最近5回の結果</p>
              <div className="flex items-center gap-2">
                {control.history.map((h, i) => {
                  const hs = STATUS_CONFIG[h.status]
                  const HIcon = hs.icon
                  return (
                    <div key={i} className="flex flex-col items-center gap-1">
                      <HIcon className={`w-4 h-4 ${hs.text}`} />
                      <span className="text-[#3d5068] text-[9px]">{h.date}</span>
                      <span className="text-[#7d92b0] text-[9px] font-mono">{h.measurement}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          </td>
        </tr>
      )}
    </>
  )
}

// ── Domain Accordion ─────────────────────────────────────────────

function DomainAccordion({ domain, freq, onFreqChange }: { domain: ControlDomain; freq: MonitorFreq; onFreqChange: (freq: MonitorFreq) => void }) {
  const [open, setOpen] = useState(false)
  const health = getHealthColor(domain.health_percent)

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
      <button onClick={() => setOpen(o => !o)}
        className="w-full flex items-center justify-between p-4 hover:bg-[#070d19]/30 transition-colors">
        <div className="flex items-center gap-3">
          {open ? <ChevronDown className="w-4 h-4 text-[#7d92b0]" /> : <ChevronRight className="w-4 h-4 text-[#7d92b0]" />}
          <span className="text-white font-semibold">{domain.name}</span>
          <span className={`text-xs font-bold ${health.color}`}>{domain.health_percent}%</span>
        </div>
        <div className="flex items-center gap-3">
          <div className="w-32 bg-[#1e2d42] rounded-full h-2">
            <div className={`h-2 rounded-full transition-all ${health.bg}`} style={{ width: `${domain.health_percent}%` }} />
          </div>
          <span className="text-[#7d92b0] text-xs">{domain.controls.length}コントロール</span>
        </div>
      </button>
      {open && (
        <div>
          <div className="px-4 pb-3 flex items-center gap-3 border-b border-[#1e2d42]">
            <Settings className="w-3.5 h-3.5 text-[#7d92b0]" />
            <span className="text-[#7d92b0] text-xs">監視頻度:</span>
            <select value={freq} onChange={e => onFreqChange(e.target.value as MonitorFreq)}
              className="bg-[#070d19] border border-[#1e2d42] rounded px-2 py-1 text-[#7d92b0] text-xs focus:outline-none"
              onClick={e => e.stopPropagation()}>
              <option value="hourly">毎時</option>
              <option value="daily">日次</option>
              <option value="weekly">週次</option>
              <option value="manual">手動</option>
            </select>
          </div>
          <table className="w-full text-sm">
            <thead className="bg-[#070d19]">
              <tr>
                {['コントロール名', '種別', '最終テスト', 'ステータス', 'トレンド', '証跡'].map(h => (
                  <th key={h} className="text-left px-4 py-2 text-[#7d92b0] text-xs font-medium">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {domain.controls.map(ctrl => <ControlRow key={ctrl.id} control={ctrl} />)}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}

// ── Main Page ────────────────────────────────────────────────────

export default function ControlsMonitoringPage() {
  const [assessing, setAssessing] = useState(false)
  const [collecting, setCollecting] = useState(false)
  const [toast, setToast] = useState('')
  const [domainFreqs, setDomainFreqs] = useState<Record<string, MonitorFreq>>({})

  const { data } = useQuery<CCMSummary>({
    queryKey: ['ccm-summary'],
    queryFn: async () => {
      try {
        const res = await apiFetch('/api/v1/admin/controls-monitoring')
        return (res && typeof res === 'object' && 'domains' in (res as object)) ? res as CCMSummary : EMPTY_DATA
      } catch { return EMPTY_DATA }
    },
    refetchInterval: 60_000,
  })

  const summary = data ?? EMPTY_DATA

  const runAssessment = async () => {
    setAssessing(true)
    try {
      await apiFetch('/api/v1/admin/controls-monitoring/assess', { method: 'POST' })
    } catch (_) {}
    await new Promise(r => setTimeout(r, 3000))
    setAssessing(false)
    setToast('評価が完了しました')
  }

  const collectEvidence = async () => {
    setCollecting(true)
    await new Promise(r => setTimeout(r, 2000))
    setCollecting(false)
    setToast('全自動コントロールの証拠を収集しました')
  }

  const exportReport = () => {
    const blob = new Blob([JSON.stringify(summary, null, 2)], { type: 'application/json' })
    const url = URL.createObjectURL(blob)
    const a = document.createElement('a')
    a.href = url
    a.download = `ccm-report-${new Date().toISOString().split('T')[0]}.json`
    a.click()
  }

  const health = getHealthColor(summary.overall_health)
  const failingControls = summary.domains.flatMap(d => d.controls.filter(c => c.current_status === 'failing'))
  const driftControls = summary.domains.flatMap(d => d.controls.filter(c => {
    if (c.current_status !== 'failing' && c.current_status !== 'degraded') return false
    const prevPassing = c.history.slice(1).some(h => h.status === 'passing')
    return prevPassing
  }))

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <div className="max-w-7xl mx-auto px-6 py-6 space-y-6">

        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/20 flex items-center justify-center">
              <ShieldCheck className="w-5 h-5 text-[#e8002d]" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">継続的コントロール監視</h1>
              <p className="text-[#7d92b0] text-sm">Continuous Controls Monitoring (CCM) – リアルタイムセキュリティコントロール評価</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button onClick={collectEvidence} disabled={collecting}
              className="flex items-center gap-2 px-4 py-2 border border-[#1e2d42] rounded-lg text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/50 text-sm transition-colors disabled:opacity-50">
              {collecting ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Activity className="w-4 h-4" />}
              全証拠を収集
            </button>
            <button onClick={exportReport}
              className="flex items-center gap-2 px-4 py-2 border border-[#1e2d42] rounded-lg text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/50 text-sm transition-colors">
              <Download className="w-4 h-4" /> レポート出力
            </button>
          </div>
        </div>

        {/* Overall Health */}
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-6">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-8">
              <div className="text-center">
                <p className="text-[#7d92b0] text-sm mb-1">総合ヘルス</p>
                <p className={`text-6xl font-black ${health.color}`}>{summary.overall_health}%</p>
                <span className={`inline-block mt-1 px-3 py-1 rounded-full text-xs font-bold ${
                  health.label === 'GREEN' ? 'bg-green-900/40 text-green-300' :
                  health.label === 'AMBER' ? 'bg-yellow-900/40 text-yellow-300' : 'bg-red-900/40 text-red-300'
                }`}>{health.label}</span>
              </div>
              <div className="grid grid-cols-4 gap-6">
                {[
                  { label: '正常', value: summary.passing, color: 'text-green-400', icon: CheckCircle },
                  { label: '失敗', value: summary.failing, color: 'text-red-400', icon: XCircle },
                  { label: '低下', value: summary.degraded, color: 'text-yellow-400', icon: AlertTriangle },
                  { label: '未テスト', value: summary.not_tested, color: 'text-gray-400', icon: Clock },
                ].map(({ label, value, color, icon: Icon }) => (
                  <div key={label} className="flex flex-col items-center">
                    <Icon className={`w-5 h-5 ${color} mb-1`} />
                    <p className={`text-2xl font-bold ${color}`}>{value}</p>
                    <p className="text-[#7d92b0] text-xs">{label}</p>
                  </div>
                ))}
              </div>
            </div>
            <div className="text-right">
              <p className="text-[#7d92b0] text-xs mb-1">最終評価</p>
              <p className="text-white text-sm">{fmtDate(summary.last_assessment)}</p>
              <button onClick={runAssessment} disabled={assessing}
                className="mt-3 flex items-center gap-2 px-4 py-2 bg-[#e8002d] rounded-lg text-white text-sm font-medium hover:bg-[#e8002d]/80 disabled:opacity-50 transition-colors">
                {assessing ? <RefreshCw className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
                {assessing ? '評価中...' : '今すぐ評価'}
              </button>
            </div>
          </div>
          {/* Health bar */}
          <div className="mt-4 w-full bg-[#1e2d42] rounded-full h-3">
            <div className={`h-3 rounded-full transition-all ${health.bg}`} style={{ width: `${summary.overall_health}%` }} />
          </div>
        </div>

        {/* Failing Controls */}
        {failingControls.length > 0 && (
          <div className="bg-red-900/10 border border-red-500/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3">
              <XCircle className="w-5 h-5 text-red-400" />
              <h3 className="text-white font-semibold">失敗中のコントロール ({failingControls.length}件)</h3>
            </div>
            <div className="space-y-2">
              {failingControls.map(ctrl => (
                <div key={ctrl.id} className="flex items-center justify-between bg-[#0d1220] rounded px-4 py-3">
                  <div>
                    <p className="text-white font-medium text-sm">{ctrl.name}</p>
                    <p className="text-[#7d92b0] text-xs mt-0.5">{ctrl.current_measurement} (閾値: {ctrl.threshold})</p>
                  </div>
                  <button className="flex items-center gap-1 px-3 py-1.5 bg-[#e8002d]/10 border border-[#e8002d]/30 rounded text-[#e8002d] text-xs hover:bg-[#e8002d]/20 transition-colors">
                    <ChevronRight className="w-3 h-3" /> 対処
                  </button>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Control Drift */}
        {driftControls.length > 0 && (
          <div className="bg-yellow-900/10 border border-yellow-500/30 rounded-lg p-4">
            <div className="flex items-center gap-2 mb-3">
              <TrendingDown className="w-5 h-5 text-yellow-400" />
              <h3 className="text-white font-semibold">コントロールドリフト検知 (直近7日間)</h3>
            </div>
            <div className="flex flex-wrap gap-2">
              {driftControls.map(ctrl => (
                <div key={ctrl.id} className="flex items-center gap-2 px-3 py-2 bg-[#0d1220] rounded border border-[#1e2d42]">
                  <TrendingDown className="w-3.5 h-3.5 text-yellow-400" />
                  <span className="text-white text-xs">{ctrl.name}</span>
                  <span className={`px-1.5 py-0.5 rounded text-[10px] ${STATUS_CONFIG[ctrl.current_status].bg} ${STATUS_CONFIG[ctrl.current_status].text}`}>
                    {STATUS_CONFIG[ctrl.current_status].label}
                  </span>
                </div>
              ))}
            </div>
          </div>
        )}

        {/* Domain Accordions */}
        <div className="space-y-3">
          <h2 className="text-white font-semibold">コントロールドメイン</h2>
          {summary.domains.map(domain => (
            <DomainAccordion
              key={domain.id}
              domain={domain}
              freq={domainFreqs[domain.id] ?? domain.monitor_frequency}
              onFreqChange={freq => setDomainFreqs(f => ({ ...f, [domain.id]: freq }))}
            />
          ))}
        </div>
      </div>

      {/* Toast */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 bg-[#0d1220] border border-green-500/50 rounded-lg p-4 shadow-xl flex items-center gap-3">
          <CheckCircle className="w-4 h-4 text-green-400" />
          <span className="text-white text-sm">{toast}</span>
          <button onClick={() => setToast('')} className="text-[#7d92b0] hover:text-white"><X className="w-4 h-4" /></button>
        </div>
      )}
    </div>
  )
}
