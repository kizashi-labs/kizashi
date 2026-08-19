'use client'

import { useState, useEffect } from 'react'
import { apiFetch } from '@/lib/api'
import {
  FileText, Printer, RefreshCw, Shield, AlertTriangle, Monitor,
  BarChart2, CheckCircle, Clock, TrendingUp, AlertCircle, Target,
  ChevronDown,
} from 'lucide-react'

// ─── Types ───────────────────────────────────────────────────────────────────

type Period = 'daily' | 'weekly' | 'monthly'

interface ReportConfig {
  period: Period
  dateFrom: string
  dateTo: string
  sections: Record<string, boolean>
}

interface MetricsSummary {
  total_incidents: number
  critical_alerts: number
  agent_coverage_pct: number
  open_incidents: number
  resolved_incidents: number
  mttr_minutes: number
  posture_grade: string
}

interface AlertStat {
  severity: string
  count: number
  resolved: number
  pending: number
}

interface IncidentRow {
  id: string
  title: string
  severity: string
  status: string
  created_at: string
  mttr_minutes: number | null
}

interface AgentStatus {
  status: string
  count: number
}

interface ComplianceScore {
  framework: string
  score: number
  controls_passed: number
  controls_total: number
  status: string
}

interface ReportData {
  metrics: MetricsSummary
  alert_stats: AlertStat[]
  incidents: IncidentRow[]
  agent_statuses: AgentStatus[]
  offline_agents: { hostname: string; last_seen: string }[]
  threat_intel: { ioc_count: number; new_threats: number; blocked: number }
  compliance: ComplianceScore[]
  recommendations: string[]
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_DATA: ReportData = {
  metrics: {
    total_incidents: 23,
    critical_alerts: 47,
    agent_coverage_pct: 96.4,
    open_incidents: 5,
    resolved_incidents: 18,
    mttr_minutes: 142,
    posture_grade: 'B+',
  },
  alert_stats: [
    { severity: 'Critical (9-10)', count: 12, resolved: 10, pending: 2 },
    { severity: 'High (7-8)', count: 35, resolved: 29, pending: 6 },
    { severity: 'Medium (4-6)', count: 87, resolved: 80, pending: 7 },
    { severity: 'Low (1-3)', count: 124, resolved: 119, pending: 5 },
  ],
  incidents: [
    { id: 'INC-001', title: 'Ransomware Activity - WIN-DESKTOP-042', severity: 'critical', status: 'closed', created_at: '2026-03-15', mttr_minutes: 250 },
    { id: 'INC-002', title: 'Lateral Movement Detected', severity: 'high', status: 'investigating', created_at: '2026-03-16', mttr_minutes: null },
    { id: 'INC-003', title: 'Data Exfiltration Attempt', severity: 'high', status: 'investigating', created_at: '2026-03-16', mttr_minutes: null },
    { id: 'INC-004', title: 'Brute Force on Admin Account', severity: 'medium', status: 'closed', created_at: '2026-03-17', mttr_minutes: 48 },
    { id: 'INC-005', title: 'Suspicious PowerShell Execution', severity: 'high', status: 'open', created_at: '2026-03-18', mttr_minutes: null },
  ],
  agent_statuses: [
    { status: 'オンライン', count: 482 },
    { status: 'オフライン', count: 18 },
    { status: '未応答', count: 7 },
    { status: '隔離', count: 3 },
  ],
  offline_agents: [
    { hostname: 'WIN-LAPTOP-015', last_seen: '2026-03-17T10:00:00Z' },
    { hostname: 'MAC-DEV-007', last_seen: '2026-03-16T14:00:00Z' },
    { hostname: 'WIN-DESKTOP-099', last_seen: '2026-03-15T09:00:00Z' },
    { hostname: 'LINUX-SERVER-04', last_seen: '2026-03-14T18:00:00Z' },
    { hostname: 'WIN-LAPTOP-021', last_seen: '2026-03-13T11:00:00Z' },
  ],
  threat_intel: {
    ioc_count: 1247,
    new_threats: 34,
    blocked: 892,
  },
  compliance: [
    { framework: 'CIS Benchmark', score: 87, controls_passed: 174, controls_total: 200, status: '良好' },
    { framework: 'NIST CSF', score: 79, controls_passed: 158, controls_total: 200, status: '要改善' },
    { framework: 'MITRE ATT&CK', score: 72, controls_passed: 108, controls_total: 150, status: '要改善' },
    { framework: 'ISO 27001', score: 91, controls_passed: 91, controls_total: 100, status: '良好' },
  ],
  recommendations: [
    '18台のオフラインエージェントを調査し、再接続または再インストールを実施してください',
    '未パッチのWindowsエンドポイント (24台) に対して緊急パッチ適用を推奨します',
    'NIST CSFスコア向上のため、ネットワーク監視ルールの見直しを実施してください',
    '管理者アカウントへのMFA強制を全エンドポイントで有効化してください',
    'MITRE ATT&CK T1486 (暗号化ランサムウェア) に対するプレイブックを更新してください',
    '外部通信のアウトバウンドフィルタリングポリシーを強化し、不審なドメインを追加ブロックしてください',
    '月次コンプライアンス評価サイクルを確立し、CIS Benchmarkスコア90以上を目標としてください',
  ],
}

const EMPTY_REPORT_DATA: ReportData = {
  metrics: {
    total_incidents: 0,
    critical_alerts: 0,
    agent_coverage_pct: 0,
    open_incidents: 0,
    resolved_incidents: 0,
    mttr_minutes: 0,
    posture_grade: '-',
  },
  alert_stats: [],
  incidents: [],
  agent_statuses: [],
  offline_agents: [],
  threat_intel: { ioc_count: 0, new_threats: 0, blocked: 0 },
  compliance: [],
  recommendations: [],
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function todayStr(): string {
  return new Date().toISOString().split('T')[0]
}

function nDaysAgoStr(n: number): string {
  const d = new Date()
  d.setDate(d.getDate() - n)
  return d.toISOString().split('T')[0]
}

const SECTIONS = [
  { key: 'executive', label: 'エグゼクティブサマリー' },
  { key: 'alerts', label: 'アラート統計' },
  { key: 'incidents', label: 'インシデントサマリー' },
  { key: 'endpoints', label: 'エンドポイント状態' },
  { key: 'threat_intel', label: '脅威インテリジェンス' },
  { key: 'compliance', label: 'コンプライアンス' },
  { key: 'recommendations', label: '推奨事項' },
  { key: 'appendix', label: '付録' },
]

const SEVERITY_COLORS: Record<string, string> = {
  critical: '#e8002d',
  high: '#f97316',
  medium: '#eab308',
  low: '#22c55e',
}

const SEVERITY_LABELS: Record<string, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

function formatRelDate(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const days = Math.floor(diff / 86400000)
  if (days === 0) return '今日'
  if (days === 1) return '昨日'
  return `${days}日前`
}

// ─── SVG Bar Chart ─────────────────────────────────────────────────────────────

function AlertBarChart({ stats }: { stats: AlertStat[] }) {
  const max = Math.max(...stats.map(s => s.count), 1)
  const W = 400
  const H = 120
  const BAR_W = 60
  const GAP = (W - stats.length * BAR_W) / (stats.length + 1)
  const COLORS = ['#e8002d', '#f97316', '#eab308', '#22c55e']

  return (
    <svg viewBox={`0 0 ${W} ${H + 30}`} className="w-full max-w-md">
      {stats.map((s, i) => {
        const barH = (s.count / max) * H
        const x = GAP + i * (BAR_W + GAP)
        const y = H - barH
        return (
          <g key={i}>
            <rect x={x} y={y} width={BAR_W} height={barH} fill={COLORS[i]} opacity={0.8} rx={2} />
            <text x={x + BAR_W / 2} y={H + 14} textAnchor="middle" fontSize="10" fill="#7d92b0">
              {s.severity.split(' ')[0]}
            </text>
            <text x={x + BAR_W / 2} y={y - 4} textAnchor="middle" fontSize="11" fill="#e2e8f4" fontWeight="bold">
              {s.count}
            </text>
          </g>
        )
      })}
    </svg>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function OpsReportPage() {
  const [config, setConfig] = useState<ReportConfig>({
    period: 'weekly',
    dateFrom: nDaysAgoStr(7),
    dateTo: todayStr(),
    sections: Object.fromEntries(SECTIONS.map(s => [s.key, true])),
  })
  const [reportData, setReportData] = useState<ReportData | null>(null)
  const [generating, setGenerating] = useState(false)

  const handleGenerate = async () => {
    setGenerating(true)
    try {
      const days = config.period === 'daily' ? 1 : config.period === 'weekly' ? 7 : 30
      const result = await apiFetch<ReportData>(`/api/v1/reports/ops-report?days=${days}`)
      setReportData(result)
    } catch {
      setReportData(EMPTY_REPORT_DATA)
    } finally {
      setGenerating(false)
    }
  }

  // Generate on mount
  useEffect(() => {
    handleGenerate()
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [])

  const data: ReportData = reportData ?? EMPTY_REPORT_DATA

  const toggleSection = (key: string) => {
    setConfig(prev => ({
      ...prev,
      sections: { ...prev.sections, [key]: !prev.sections[key] },
    }))
  }

  const setPeriod = (period: Period) => {
    const days = period === 'daily' ? 1 : period === 'weekly' ? 7 : 30
    setConfig(prev => ({
      ...prev,
      period,
      dateFrom: nDaysAgoStr(days),
      dateTo: todayStr(),
    }))
  }

  return (
    <>
      {/* Print CSS */}
      <style>{`
        @media print {
          .no-print { display: none !important; }
          .print-area { background: white !important; color: black !important; }
          body { background: white !important; }
          .print-area * { color: black !important; border-color: #ddd !important; background: white !important; }
          .print-area table { border-collapse: collapse; width: 100%; }
          .print-area td, .print-area th { border: 1px solid #ddd; padding: 6px 10px; }
          .print-area .severity-critical { color: #c0001f !important; font-weight: bold; }
          .print-area .severity-high { color: #c2410c !important; }
          .print-area .severity-medium { color: #a16207 !important; }
          .print-kpi-box { border: 2px solid #ddd !important; padding: 16px !important; border-radius: 4px !important; }
        }
      `}</style>

      <div className="min-h-screen bg-[#070d19]">
        {/* ── Config Bar (no-print) ──────────────────────────────── */}
        <div className="no-print sticky top-0 z-10 bg-[#0d1220] border-b border-[#1e2d42] px-6 py-3">
          <div className="flex items-center gap-4 flex-wrap">
            <div className="flex items-center gap-2">
              <FileText className="w-4 h-4 text-[#e8002d]" />
              <span className="text-white font-semibold text-sm">セキュリティオペレーションレポート</span>
            </div>

            {/* Period */}
            <div className="flex gap-1">
              {(['daily', 'weekly', 'monthly'] as Period[]).map(p => (
                <button
                  key={p}
                  onClick={() => setPeriod(p)}
                  className={`px-3 py-1 rounded-sm text-xs font-medium transition-colors ${
                    config.period === p ? 'bg-[#e8002d] text-white' : 'bg-[#1e2d42] text-[#7d92b0] hover:text-white'
                  }`}
                >
                  {p === 'daily' ? '日次' : p === 'weekly' ? '週次' : '月次'}
                </button>
              ))}
            </div>

            {/* Date range */}
            <div className="flex items-center gap-2">
              <input
                type="date"
                value={config.dateFrom}
                onChange={e => setConfig(prev => ({ ...prev, dateFrom: e.target.value }))}
                className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1 text-xs text-[#e2e8f4] focus:outline-hidden"
              />
              <span className="text-[#3d5068] text-xs">〜</span>
              <input
                type="date"
                value={config.dateTo}
                onChange={e => setConfig(prev => ({ ...prev, dateTo: e.target.value }))}
                className="bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1 text-xs text-[#e2e8f4] focus:outline-hidden"
              />
            </div>

            {/* Section toggles */}
            <div className="flex items-center gap-1.5 flex-wrap">
              {SECTIONS.map(s => (
                <label key={s.key} className="flex items-center gap-1 cursor-pointer">
                  <input
                    type="checkbox"
                    checked={config.sections[s.key]}
                    onChange={() => toggleSection(s.key)}
                    className="accent-[#e8002d] w-3 h-3"
                  />
                  <span className="text-[#7d92b0] text-xs">{s.label}</span>
                </label>
              ))}
            </div>

            <div className="ml-auto flex items-center gap-2">
              <button
                onClick={handleGenerate}
                disabled={generating}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-[#1e2d42] hover:bg-[#2a3d5a] text-[#e2e8f4] text-xs font-medium transition-colors disabled:opacity-50"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${generating ? 'animate-spin' : ''}`} />
                レポート生成
              </button>
              <button
                onClick={() => window.print()}
                className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-[#e8002d] hover:bg-[#c0001f] text-white text-xs font-medium transition-colors"
              >
                <Printer className="w-3.5 h-3.5" />
                印刷/PDF
              </button>
            </div>
          </div>
        </div>

        {/* ── Printable Report Area ─────────────────────────────── */}
        <div className="print-area max-w-5xl mx-auto p-8">

          {/* 表紙 */}
          <div className="mb-12 border-b border-[#1e2d42] pb-10">
            <div className="flex items-center gap-4 mb-6">
              <div className="w-12 h-12 rounded-sm bg-[#e8002d]/20 flex items-center justify-center">
                <Shield className="w-7 h-7 text-[#e8002d]" />
              </div>
              <div>
                <p className="text-[#7d92b0] text-sm">Kizashi</p>
                <h1 className="text-white text-2xl font-bold">EDRプラットフォーム セキュリティレポート</h1>
              </div>
            </div>
            <div className="grid grid-cols-3 gap-4 mt-6">
              {[
                { label: 'レポート期間', value: `${config.dateFrom} 〜 ${config.dateTo}` },
                { label: '生成日時', value: new Date().toLocaleString('ja-JP') },
                { label: '作成者', value: 'セキュリティオペレーションチーム' },
                { label: 'レポート種別', value: config.period === 'daily' ? '日次レポート' : config.period === 'weekly' ? '週次レポート' : '月次レポート' },
                { label: 'テナント', value: 'Kizashi Demo Org' },
                { label: '機密分類', value: '社外秘' },
              ].map(({ label, value }) => (
                <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-sm p-3">
                  <p className="text-[#7d92b0] text-xs">{label}</p>
                  <p className="text-[#e2e8f4] text-sm font-medium mt-1">{value}</p>
                </div>
              ))}
            </div>
          </div>

          {/* エグゼクティブサマリー */}
          {config.sections.executive && (
            <section className="mb-10">
              <h2 className="text-white text-lg font-bold mb-4 flex items-center gap-2">
                <TrendingUp className="w-5 h-5 text-[#e8002d]" />
                エグゼクティブサマリー
              </h2>

              {/* KPI Boxes */}
              <div className="grid grid-cols-4 gap-4 mb-6">
                {[
                  { label: '総インシデント', value: data.metrics.total_incidents, icon: AlertCircle, color: 'text-orange-400', sub: `解決済み: ${data.metrics.resolved_incidents}` },
                  { label: '重大アラート', value: data.metrics.critical_alerts, icon: AlertTriangle, color: 'text-[#e8002d]', sub: '深刻度9-10' },
                  { label: 'エージェントカバレッジ', value: `${data.metrics.agent_coverage_pct}%`, icon: Monitor, color: 'text-emerald-400', sub: '全エンドポイント比' },
                  { label: '平均修復時間', value: `${data.metrics.mttr_minutes}分`, icon: Clock, color: 'text-blue-400', sub: 'MTTR' },
                ].map(({ label, value, icon: Icon, color, sub }) => (
                  <div key={label} className="print-kpi-box bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
                    <div className="flex items-center gap-2 mb-2">
                      <Icon className={`w-4 h-4 ${color}`} />
                      <span className="text-[#7d92b0] text-xs">{label}</span>
                    </div>
                    <p className="text-white text-2xl font-bold">{value}</p>
                    <p className="text-[#7d92b0] text-xs mt-1">{sub}</p>
                  </div>
                ))}
              </div>

              {/* Security Posture Grade */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5 flex items-center gap-6">
                <div className="shrink-0 text-center">
                  <div className="w-20 h-20 rounded-full border-4 border-[#e8002d] flex items-center justify-center">
                    <span className="text-white text-3xl font-black">{data.metrics.posture_grade}</span>
                  </div>
                  <p className="text-[#7d92b0] text-xs mt-2">セキュリティポスチャー</p>
                </div>
                <div className="flex-1">
                  <p className="text-[#e2e8f4] text-sm font-medium mb-2">総合評価</p>
                  <p className="text-[#7d92b0] text-sm">
                    今期のセキュリティポスチャーは <strong className="text-white">B+</strong> と評価されました。
                    重大インシデントへの対応速度は改善傾向にありますが、エンドポイントカバレッジとコンプライアンス維持に引き続き注力が必要です。
                  </p>
                  <div className="flex gap-4 mt-3">
                    <span className="text-xs text-emerald-400">+ 前期比 MTTR 12%改善</span>
                    <span className="text-xs text-amber-400">△ NIST CSF スコア要注意</span>
                    <span className="text-xs text-[#e8002d]">! オフラインエージェント増加</span>
                  </div>
                </div>
              </div>
            </section>
          )}

          {/* アラート統計 */}
          {config.sections.alerts && (
            <section className="mb-10">
              <h2 className="text-white text-lg font-bold mb-4 flex items-center gap-2">
                <AlertTriangle className="w-5 h-5 text-[#e8002d]" />
                アラート統計
              </h2>
              <div className="flex gap-6">
                <div className="flex-1">
                  <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
                    <table className="w-full text-sm">
                      <thead>
                        <tr className="border-b border-[#1e2d42] bg-[#070d19]">
                          {['深刻度', '総数', '解決済み', '未解決', '解決率'].map(h => (
                            <th key={h} className="px-4 py-2.5 text-left text-[#7d92b0] text-xs font-medium">{h}</th>
                          ))}
                        </tr>
                      </thead>
                      <tbody className="divide-y divide-[#1e2d42]">
                        {data.alert_stats.map((s, i) => (
                          <tr key={i} className="hover:bg-[#0a1525]">
                            <td className="px-4 py-2.5 text-xs font-medium text-[#e2e8f4]">{s.severity}</td>
                            <td className="px-4 py-2.5 text-xs text-[#e2e8f4] font-bold">{s.count}</td>
                            <td className="px-4 py-2.5 text-xs text-emerald-400">{s.resolved}</td>
                            <td className="px-4 py-2.5 text-xs text-[#e8002d]">{s.pending}</td>
                            <td className="px-4 py-2.5 text-xs">
                              <span className={`font-medium ${s.count > 0 && (s.resolved / s.count) > 0.9 ? 'text-emerald-400' : 'text-amber-400'}`}>
                                {s.count > 0 ? Math.round((s.resolved / s.count) * 100) : 0}%
                              </span>
                            </td>
                          </tr>
                        ))}
                        <tr className="border-t-2 border-[#3d5068] bg-[#070d19]">
                          <td className="px-4 py-2.5 text-xs font-bold text-[#e2e8f4]">合計</td>
                          <td className="px-4 py-2.5 text-xs font-bold text-[#e2e8f4]">
                            {data.alert_stats.reduce((a, s) => a + s.count, 0)}
                          </td>
                          <td className="px-4 py-2.5 text-xs text-emerald-400 font-bold">
                            {data.alert_stats.reduce((a, s) => a + s.resolved, 0)}
                          </td>
                          <td className="px-4 py-2.5 text-xs text-[#e8002d] font-bold">
                            {data.alert_stats.reduce((a, s) => a + s.pending, 0)}
                          </td>
                          <td className="px-4 py-2.5 text-xs text-[#7d92b0]">—</td>
                        </tr>
                      </tbody>
                    </table>
                  </div>
                </div>
                <div className="w-56 shrink-0 flex items-center justify-center">
                  <AlertBarChart stats={data.alert_stats} />
                </div>
              </div>
            </section>
          )}

          {/* インシデントサマリー */}
          {config.sections.incidents && (
            <section className="mb-10">
              <h2 className="text-white text-lg font-bold mb-4 flex items-center gap-2">
                <AlertCircle className="w-5 h-5 text-[#e8002d]" />
                インシデントサマリー
              </h2>
              <div className="flex gap-4 mb-4">
                {[
                  { label: '未解決', value: data.metrics.open_incidents, color: 'text-[#e8002d]' },
                  { label: '解決済み', value: data.metrics.resolved_incidents, color: 'text-emerald-400' },
                  { label: 'MTTR', value: `${data.metrics.mttr_minutes}分`, color: 'text-blue-400' },
                ].map(({ label, value, color }) => (
                  <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-5 py-3 flex items-center gap-3">
                    <span className={`text-xl font-bold ${color}`}>{value}</span>
                    <span className="text-[#7d92b0] text-xs">{label}</span>
                  </div>
                ))}
              </div>
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42] bg-[#070d19]">
                      {['ID', 'タイトル', '深刻度', 'ステータス', '発生日', '修復時間'].map(h => (
                        <th key={h} className="px-4 py-2.5 text-left text-[#7d92b0] text-xs font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]">
                    {data.incidents.map(inc => (
                      <tr key={inc.id} className="hover:bg-[#0a1525]">
                        <td className="px-4 py-2.5 text-xs font-mono text-[#7d92b0]">{inc.id}</td>
                        <td className="px-4 py-2.5 text-xs text-[#e2e8f4] max-w-[200px]">
                          <span className="truncate block">{inc.title}</span>
                        </td>
                        <td className="px-4 py-2.5 text-xs">
                          <span className="font-medium" style={{ color: SEVERITY_COLORS[inc.severity] }}>
                            {SEVERITY_LABELS[inc.severity]}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-xs">
                          <span className={`px-1.5 py-0.5 rounded-sm text-[10px] font-medium ${
                            inc.status === 'closed' ? 'bg-emerald-500/20 text-emerald-400' :
                            inc.status === 'investigating' ? 'bg-amber-500/20 text-amber-400' :
                            'bg-[#e8002d]/20 text-[#e8002d]'
                          }`}>
                            {inc.status === 'closed' ? '解決済み' : inc.status === 'investigating' ? '調査中' : '未対応'}
                          </span>
                        </td>
                        <td className="px-4 py-2.5 text-xs text-[#7d92b0]">{inc.created_at}</td>
                        <td className="px-4 py-2.5 text-xs text-[#7d92b0]">
                          {inc.mttr_minutes ? `${inc.mttr_minutes}分` : '—'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* エンドポイント状態 */}
          {config.sections.endpoints && (
            <section className="mb-10">
              <h2 className="text-white text-lg font-bold mb-4 flex items-center gap-2">
                <Monitor className="w-5 h-5 text-[#e8002d]" />
                エンドポイント状態
              </h2>
              <div className="flex gap-4 mb-4">
                {data.agent_statuses.map(s => (
                  <div key={s.status} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-5 py-3 flex items-center gap-3">
                    <span className="text-xl font-bold text-white">{s.count}</span>
                    <span className="text-[#7d92b0] text-xs">{s.status}</span>
                  </div>
                ))}
              </div>
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
                <div className="px-4 py-3 border-b border-[#1e2d42]">
                  <span className="text-[#e2e8f4] text-xs font-semibold">オフラインエージェント一覧 (上位5件)</span>
                </div>
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42] bg-[#070d19]">
                      {['ホスト名', '最終確認', '経過時間'].map(h => (
                        <th key={h} className="px-4 py-2.5 text-left text-[#7d92b0] text-xs font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]">
                    {data.offline_agents.map(a => (
                      <tr key={a.hostname} className="hover:bg-[#0a1525]">
                        <td className="px-4 py-2.5 text-xs font-mono text-[#e2e8f4]">{a.hostname}</td>
                        <td className="px-4 py-2.5 text-xs text-[#7d92b0]">
                          {new Date(a.last_seen).toLocaleString('ja-JP')}
                        </td>
                        <td className="px-4 py-2.5 text-xs text-amber-400">
                          {formatRelDate(a.last_seen)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* 脅威インテリジェンス */}
          {config.sections.threat_intel && (
            <section className="mb-10">
              <h2 className="text-white text-lg font-bold mb-4 flex items-center gap-2">
                <Target className="w-5 h-5 text-[#e8002d]" />
                脅威インテリジェンス
              </h2>
              <div className="grid grid-cols-3 gap-4">
                {[
                  { label: '総IOC数', value: (data.threat_intel?.ioc_count ?? 0).toLocaleString(), icon: AlertTriangle, color: 'text-orange-400' },
                  { label: '新規脅威 (本期間)', value: data.threat_intel.new_threats, icon: TrendingUp, color: 'text-[#e8002d]' },
                  { label: 'ブロック済みIOC', value: (data.threat_intel?.blocked ?? 0).toLocaleString(), icon: CheckCircle, color: 'text-emerald-400' },
                ].map(({ label, value, icon: Icon, color }) => (
                  <div key={label} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5 flex items-center gap-4">
                    <div className="w-10 h-10 rounded-full bg-[#1e2d42] flex items-center justify-center shrink-0">
                      <Icon className={`w-5 h-5 ${color}`} />
                    </div>
                    <div>
                      <p className="text-white text-xl font-bold">{value}</p>
                      <p className="text-[#7d92b0] text-xs mt-0.5">{label}</p>
                    </div>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* コンプライアンス */}
          {config.sections.compliance && (
            <section className="mb-10">
              <h2 className="text-white text-lg font-bold mb-4 flex items-center gap-2">
                <CheckCircle className="w-5 h-5 text-[#e8002d]" />
                コンプライアンス
              </h2>
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42] bg-[#070d19]">
                      {['フレームワーク', 'スコア', '合格コントロール', '全コントロール', '評価'].map(h => (
                        <th key={h} className="px-4 py-2.5 text-left text-[#7d92b0] text-xs font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]">
                    {data.compliance.map(c => (
                      <tr key={c.framework} className="hover:bg-[#0a1525]">
                        <td className="px-4 py-2.5 text-xs font-semibold text-[#e2e8f4]">{c.framework}</td>
                        <td className="px-4 py-2.5 text-xs">
                          <div className="flex items-center gap-2">
                            <div className="w-24 h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                              <div
                                className="h-full rounded-full"
                                style={{
                                  width: `${c.score}%`,
                                  background: c.score >= 90 ? '#22c55e' : c.score >= 75 ? '#eab308' : '#e8002d',
                                }}
                              />
                            </div>
                            <span className="font-bold text-[#e2e8f4]">{c.score}%</span>
                          </div>
                        </td>
                        <td className="px-4 py-2.5 text-xs text-emerald-400 font-medium">{c.controls_passed}</td>
                        <td className="px-4 py-2.5 text-xs text-[#7d92b0]">{c.controls_total}</td>
                        <td className="px-4 py-2.5 text-xs">
                          <span className={`px-1.5 py-0.5 rounded-sm text-[10px] font-medium ${
                            c.status === '良好' ? 'bg-emerald-500/20 text-emerald-400' : 'bg-amber-500/20 text-amber-400'
                          }`}>
                            {c.status}
                          </span>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          )}

          {/* 推奨事項 */}
          {config.sections.recommendations && (
            <section className="mb-10">
              <h2 className="text-white text-lg font-bold mb-4 flex items-center gap-2">
                <BarChart2 className="w-5 h-5 text-[#e8002d]" />
                推奨事項
              </h2>
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-5 space-y-3">
                {data.recommendations.map((rec, i) => (
                  <div key={i} className="flex items-start gap-3">
                    <span className="shrink-0 w-6 h-6 rounded-full bg-[#e8002d]/20 text-[#e8002d] text-xs font-bold flex items-center justify-center">
                      {i + 1}
                    </span>
                    <p className="text-[#7d92b0] text-sm">{rec}</p>
                  </div>
                ))}
              </div>
            </section>
          )}

          {/* 付録 */}
          {config.sections.appendix && (
            <section className="mb-10">
              <h2 className="text-white text-lg font-bold mb-4 flex items-center gap-2">
                <FileText className="w-5 h-5 text-[#e8002d]" />
                付録: 技術詳細
              </h2>
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42] bg-[#070d19]">
                      {['項目', '値', '備考'].map(h => (
                        <th key={h} className="px-4 py-2.5 text-left text-[#7d92b0] text-xs font-medium">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]">
                    {[
                      ['エージェントバージョン', '3.2.1', '最新バージョン適用率 94.2%'],
                      ['収集ログ総量', '2.4 TB', '本期間累計'],
                      ['検知ルール数', '1,247件', '有効: 1,198 / 無効: 49'],
                      ['IOCフィード更新', '毎時自動更新', '最終更新: ' + new Date().toLocaleString('ja-JP')],
                      ['バックアップ状態', '正常', '最終バックアップ: 前日 02:00'],
                      ['APIコール数 (本期間)', '4,821,304', 'エラー率: 0.02%'],
                      ['Webhook配信数', '18,441', '配信成功率: 99.7%'],
                    ].map(([item, value, note]) => (
                      <tr key={item} className="hover:bg-[#0a1525]">
                        <td className="px-4 py-2.5 text-xs text-[#e2e8f4] font-medium">{item}</td>
                        <td className="px-4 py-2.5 text-xs text-[#7d92b0]">{value}</td>
                        <td className="px-4 py-2.5 text-xs text-[#3d5068]">{note}</td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>

              {/* Report footer */}
              <div className="mt-8 pt-4 border-t border-[#1e2d42] flex items-center justify-between text-[#3d5068] text-xs">
                <span>Kizashi — セキュリティオペレーションレポート</span>
                <span>生成日時: {new Date().toLocaleString('ja-JP')}</span>
              </div>
            </section>
          )}
        </div>
      </div>
    </>
  )
}
