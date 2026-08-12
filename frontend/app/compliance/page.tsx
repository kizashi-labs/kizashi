'use client'

import { useState, useCallback } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import {
  RadarChart, Radar, PolarGrid, PolarAngleAxis, PolarRadiusAxis,
  ResponsiveContainer, Tooltip,
} from 'recharts'
import { format, parseISO } from 'date-fns'
import { ja } from 'date-fns/locale'
import {
  Shield, CheckCircle, XCircle, RefreshCw, ChevronDown, ChevronRight,
  AlertTriangle, Activity, Users, LayoutGrid, List, TrendingUp, AlertCircle,
} from 'lucide-react'
import { apiFetch, apiFetchList } from '@/lib/api'
import { StatCard } from '@/components/ui/StatCard'

// ── Types ─────────────────────────────────────────────────────────────────────

type Framework = 'CIS' | 'NIST' | 'SOC2'
type MainTab = 'overview' | 'mitre' | 'cis' | 'nist' | 'gaps' | 'agent-scores'

interface ComplianceCheck {
  id: string
  title: string
  passed: boolean
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info'
}

interface ComplianceDetails {
  checks: ComplianceCheck[]
}

interface ComplianceScore {
  agent_id: string
  framework: Framework
  score: number
  total_checks: number
  passed_checks: number
  details: ComplianceDetails
  computed_at: string
}

// Framework mapping types
interface FrameworkSummary {
  frameworks: {
    mitre: number
    cis: number
    nist: number
    iso27001: number
  }
}

interface MitreTechnique {
  id: string
  name: string
  alert_count: number
}

interface MitreTactic {
  name: string
  techniques: MitreTechnique[]
}

interface MitreData {
  tactics: MitreTactic[]
}

interface CisControl {
  id: number
  name: string
  status: 'Implemented' | 'Partial' | 'Not Implemented'
  alert_count: number
}

interface CisData {
  controls: CisControl[]
}

interface NistSubcategory {
  id: string
  name: string
  coverage: number
}

interface NistFunction {
  id: string
  name: string
  coverage: number
  subcategories: NistSubcategory[]
}

interface NistData {
  functions: NistFunction[]
}

interface GapItem {
  id: string
  framework: string
  control: string
  risk: 'Critical' | 'High' | 'Medium' | 'Low'
  description: string
}

// ── Mock / Fallback Data ───────────────────────────────────────────────────────

const MITRE_TACTICS_LIST = [
  'Initial Access',
  'Execution',
  'Persistence',
  'Privilege Escalation',
  'Defense Evasion',
  'Credential Access',
  'Discovery',
  'Lateral Movement',
  'Collection',
  'Exfiltration',
  'Command and Control',
  'Impact',
]


// ── Helpers ───────────────────────────────────────────────────────────────────

function scoreColor(score: number): string {
  if (score >= 80) return '#22c55e'
  if (score >= 60) return '#f59e0b'
  return '#ef4444'
}

function scoreTextClass(score: number): string {
  if (score >= 80) return 'text-green-400'
  if (score >= 60) return 'text-yellow-400'
  return 'text-red-400'
}

function formatDate(iso: string): string {
  try {
    return format(parseISO(iso), 'MM/dd HH:mm', { locale: ja })
  } catch {
    return iso
  }
}

function mitreAlertBg(count: number): string {
  if (count === 0) return 'bg-[#0d1220]'
  if (count <= 5) return 'bg-yellow-500/15 border-yellow-500/30'
  return 'bg-[#e8002d]/20 border-[#e8002d]/30'
}

function mitreAlertText(count: number): string {
  if (count === 0) return 'text-[#7d92b0]'
  if (count <= 5) return 'text-yellow-300'
  return 'text-red-300'
}

// ── Score Gauge (SVG circular progress) ───────────────────────────────────────

function ScoreGauge({ score, size = 72 }: { score: number; size?: number }) {
  const r = size * 0.75
  const cx = size
  const cy = size
  const circumference = 2 * Math.PI * r
  const offset = circumference - (score / 100) * circumference
  const color = scoreColor(score)

  return (
    <div className="flex items-center justify-center">
      <div className="relative" style={{ width: size * 2, height: size * 2 }}>
        <svg className="w-full h-full -rotate-90" viewBox={`0 0 ${size * 2} ${size * 2}`}>
          <circle cx={cx} cy={cy} r={r} fill="none" stroke="#374151" strokeWidth={size * 0.16} />
          <circle
            cx={cx} cy={cy} r={r}
            fill="none"
            stroke={color}
            strokeWidth={size * 0.16}
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.5s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex flex-col items-center justify-center">
          <span className={`font-bold ${scoreTextClass(score)}`} style={{ fontSize: size * 0.38 }}>
            {Math.round(score)}
          </span>
          <span className="text-gray-400" style={{ fontSize: size * 0.16 }}>/ 100</span>
        </div>
      </div>
    </div>
  )
}

// ── Inline mini gauge for table rows ──────────────────────────────────────────

function MiniGauge({ score }: { score: number }) {
  const color = scoreColor(score)
  const r = 18
  const circumference = 2 * Math.PI * r
  const offset = circumference - (score / 100) * circumference
  return (
    <div className="flex items-center gap-2">
      <div className="relative w-10 h-10 flex-shrink-0">
        <svg className="w-full h-full -rotate-90" viewBox="0 0 40 40">
          <circle cx="20" cy="20" r={r} fill="none" stroke="#374151" strokeWidth="4" />
          <circle
            cx="20" cy="20" r={r}
            fill="none"
            stroke={color}
            strokeWidth="4"
            strokeDasharray={circumference}
            strokeDashoffset={offset}
            strokeLinecap="round"
            style={{ transition: 'stroke-dashoffset 0.4s ease' }}
          />
        </svg>
        <div className="absolute inset-0 flex items-center justify-center">
          <span className="text-[9px] font-bold" style={{ color }}>{Math.round(score)}</span>
        </div>
      </div>
      <span className={`text-sm font-semibold tabular-nums ${scoreTextClass(score)}`}>
        {Math.round(score)}
      </span>
    </div>
  )
}

// ── Severity Badge ────────────────────────────────────────────────────────────

type CheckSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info'

const SEVERITY_STYLES: Record<CheckSeverity, { bg: string; text: string; label: string }> = {
  critical: { bg: 'bg-red-500/20',    text: 'text-red-300',    label: 'クリティカル' },
  high:     { bg: 'bg-orange-500/20', text: 'text-orange-300', label: '高' },
  medium:   { bg: 'bg-yellow-500/20', text: 'text-yellow-300', label: '中' },
  low:      { bg: 'bg-blue-500/20',   text: 'text-blue-300',   label: '低' },
  info:     { bg: 'bg-gray-500/20',   text: 'text-gray-400',   label: '情報' },
}

function CheckSeverityBadge({ severity }: { severity: CheckSeverity }) {
  const s = SEVERITY_STYLES[severity] ?? SEVERITY_STYLES.info
  return (
    <span className={`inline-flex items-center px-1.5 py-0.5 rounded text-[10px] font-bold
                      tracking-wider uppercase ${s.bg} ${s.text}`}>
      {s.label}
    </span>
  )
}

function PassedBadge({ passed }: { passed: boolean }) {
  return passed ? (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold
                     bg-green-500/15 text-green-300">
      <CheckCircle size={10} />
      合格
    </span>
  ) : (
    <span className="inline-flex items-center gap-1 px-1.5 py-0.5 rounded text-[10px] font-bold
                     bg-red-500/15 text-red-300">
      <XCircle size={10} />
      不合格
    </span>
  )
}

// ── Radar data builder ────────────────────────────────────────────────────────

interface RadarPoint {
  category: string
  score: number
  fullMark: number
}

function buildRadarData(checks: ComplianceCheck[]): RadarPoint[] {
  const SEVERITY_ORDER: CheckSeverity[] = ['critical', 'high', 'medium', 'low', 'info']
  const map = new Map<string, { passed: number; total: number }>()

  for (const sev of SEVERITY_ORDER) {
    map.set(sev, { passed: 0, total: 0 })
  }

  for (const c of checks) {
    const sev = (SEVERITY_ORDER.includes(c.severity) ? c.severity : 'info') as CheckSeverity
    const bucket = map.get(sev)!
    bucket.total += 1
    if (c.passed) bucket.passed += 1
  }

  const LABELS: Record<CheckSeverity, string> = {
    critical: 'クリティカル',
    high:     '高',
    medium:   '中',
    low:      '低',
    info:     '情報',
  }

  return SEVERITY_ORDER
    .filter(sev => (map.get(sev)?.total ?? 0) > 0)
    .map(sev => {
      const { passed, total } = map.get(sev)!
      return {
        category: LABELS[sev],
        score: total > 0 ? Math.round((passed / total) * 100) : 0,
        fullMark: 100,
      }
    })
}

// ── Custom Radar tooltip ──────────────────────────────────────────────────────

interface RadarTooltipProps {
  active?: boolean
  payload?: Array<{ value: number; payload: RadarPoint }>
}

function RadarTooltipContent({ active, payload }: RadarTooltipProps) {
  if (!active || !payload || payload.length === 0) return null
  const { category, score } = payload[0].payload
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded px-2 py-1 text-xs text-[#7d92b0]">
      <span className="font-semibold text-white">{category}</span>: {score}%
    </div>
  )
}

// ── Detail Panel ──────────────────────────────────────────────────────────────

interface DetailPanelProps {
  score: ComplianceScore
  onClose: () => void
}

function DetailPanel({ score, onClose }: DetailPanelProps) {
  const checks = score.details.checks
  const radarData = buildRadarData(checks)

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 mt-2">
      <div className="flex items-center justify-between mb-4">
        <div className="flex items-center gap-2">
          <ScoreGauge score={score.score} size={32} />
          <div>
            <p className="text-sm font-semibold text-white">
              エージェント: <span className="font-mono text-blue-300">{score.agent_id}</span>
            </p>
            <p className="text-xs text-[#7d92b0]">
              {score.passed_checks} / {score.total_checks} チェック合格 —
              最終計算: {formatDate(score.computed_at)}
            </p>
          </div>
        </div>
        <button
          onClick={onClose}
          className="text-[#7d92b0] hover:text-white transition-colors text-xs px-2 py-1"
        >
          閉じる ✕
        </button>
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-5">
        <div className="bg-[#070d19] rounded-lg p-4">
          <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-widest mb-3">
            重要度別スコア
          </p>
          {radarData.length > 0 ? (
            <ResponsiveContainer width="100%" height={220}>
              <RadarChart data={radarData} margin={{ top: 10, right: 30, bottom: 10, left: 30 }}>
                <PolarGrid stroke="#1e2d42" />
                <PolarAngleAxis
                  dataKey="category"
                  tick={{ fill: '#7d92b0', fontSize: 11 }}
                />
                <PolarRadiusAxis
                  angle={90}
                  domain={[0, 100]}
                  tick={{ fill: '#7d92b0', fontSize: 9 }}
                  tickCount={4}
                />
                <Radar
                  name="Score"
                  dataKey="score"
                  stroke="#e8002d"
                  fill="#e8002d"
                  fillOpacity={0.2}
                  strokeWidth={2}
                />
                <Tooltip content={<RadarTooltipContent />} />
              </RadarChart>
            </ResponsiveContainer>
          ) : (
            <div className="flex items-center justify-center h-[220px] text-[#7d92b0] text-sm">
              チェックデータなし
            </div>
          )}
        </div>

        <div className="bg-[#070d19] rounded-lg overflow-hidden">
          <p className="text-xs font-semibold text-[#7d92b0] uppercase tracking-widest px-4 pt-4 pb-2">
            チェック ({checks.length})
          </p>
          <div className="overflow-y-auto max-h-[240px]">
            <table className="w-full text-xs">
              <thead className="sticky top-0 bg-[#070d19]">
                <tr className="text-[#7d92b0] border-b border-[#1e2d42]">
                  <th className="px-3 py-2 text-left font-medium">ID</th>
                  <th className="px-3 py-2 text-left font-medium">タイトル</th>
                  <th className="px-3 py-2 text-left font-medium">重要度</th>
                  <th className="px-3 py-2 text-left font-medium">結果</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {checks.map(check => (
                  <tr key={check.id} className="hover:bg-[#1e2d42]/40">
                    <td className="px-3 py-2 font-mono text-[#7d92b0] whitespace-nowrap">
                      {check.id}
                    </td>
                    <td className="px-3 py-2 text-white max-w-[180px]">
                      <span className="line-clamp-2">{check.title}</span>
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <CheckSeverityBadge severity={check.severity} />
                    </td>
                    <td className="px-3 py-2 whitespace-nowrap">
                      <PassedBadge passed={check.passed} />
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      </div>
    </div>
  )
}

// ── Framework Score Card ───────────────────────────────────────────────────────

interface FrameworkScoreCardProps {
  name: string
  score: number
  description: string
  icon: React.ReactNode
}

function FrameworkScoreCard({ name, score, description, icon }: FrameworkScoreCardProps) {
  const color = scoreColor(score)
  const barColor = score >= 80 ? 'bg-green-500' : score >= 60 ? 'bg-yellow-500' : 'bg-[#e8002d]'

  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5 flex flex-col gap-4">
      <div className="flex items-start justify-between">
        <div>
          <div className="flex items-center gap-2 mb-1">
            <span className="text-[#7d92b0]">{icon}</span>
            <span className="text-sm font-semibold text-white">{name}</span>
          </div>
          <p className="text-xs text-[#7d92b0]">{description}</p>
        </div>
        <span className="text-2xl font-bold tabular-nums" style={{ color }}>
          {score}%
        </span>
      </div>
      <div className="w-full h-2 bg-[#1e2d42] rounded-full overflow-hidden">
        <div
          className={`h-full ${barColor} rounded-full transition-all duration-700`}
          style={{ width: `${score}%` }}
        />
      </div>
    </div>
  )
}

// ── Overview Tab ──────────────────────────────────────────────────────────────

function OverviewTab() {
  const { data, isLoading } = useQuery<FrameworkSummary | null>({
    queryKey: ['compliance', 'summary'],
    queryFn: async () => {
      try {
        return await apiFetch<FrameworkSummary>('/api/v1/compliance/summary')
      } catch {
        return null
      }
    },
    staleTime: 60_000,
  })

  const frameworks = data?.frameworks ?? { mitre: 0, cis: 0, nist: 0, iso27001: 0 }
  const overallScore = Math.round(
    (frameworks.mitre + frameworks.cis + frameworks.nist + frameworks.iso27001) / 4
  )

  const frameworkCards = [
    {
      name: 'MITRE ATT&CK',
      score: frameworks.mitre,
      description: '12タクティクスカテゴリにわたるテクニックカバレッジ',
      icon: <LayoutGrid size={16} />,
    },
    {
      name: 'CIS Controls',
      score: frameworks.cis,
      description: 'CIS Controls v8（18コントロール）の実装状況',
      icon: <List size={16} />,
    },
    {
      name: 'NIST CSF',
      score: frameworks.nist,
      description: 'サイバーセキュリティフレームワーク5機能のカバレッジ',
      icon: <TrendingUp size={16} />,
    },
    {
      name: 'ISO 27001',
      score: frameworks.iso27001,
      description: '情報セキュリティ管理システムの適合性',
      icon: <Shield size={16} />,
    },
  ]

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20 text-[#7d92b0]">
        <RefreshCw size={18} className="animate-spin mr-2" /> フレームワークデータを読み込み中...
      </div>
    )
  }

  return (
    <div className="space-y-6">
      {/* Overall score banner */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
        <div className="flex flex-col sm:flex-row sm:items-center gap-6">
          <div className="flex-shrink-0">
            <ScoreGauge score={overallScore} size={52} />
          </div>
          <div className="flex-1">
            <h2 className="text-lg font-bold text-white mb-1">総合コンプライアンススコア</h2>
            <p className="text-sm text-[#7d92b0] mb-3">
              4つのコンプライアンスフレームワークの平均スコア。検知カバレッジ・コントロール実装・マッピングされたアラートルールを反映します。
            </p>
            <div className="flex flex-wrap gap-3">
              {overallScore >= 80 ? (
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs
                                 font-semibold bg-green-500/15 text-green-400">
                  <CheckCircle size={12} /> 準拠
                </span>
              ) : overallScore >= 60 ? (
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs
                                 font-semibold bg-yellow-500/15 text-yellow-400">
                  <AlertTriangle size={12} /> 一部準拠
                </span>
              ) : (
                <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs
                                 font-semibold bg-red-500/15 text-red-400">
                  <XCircle size={12} /> 非準拠
                </span>
              )}
              <span className="inline-flex items-center gap-1.5 px-3 py-1 rounded-full text-xs
                               font-semibold bg-[#1e2d42] text-[#7d92b0]">
                {([] as GapItem[]).filter(g => g.risk === 'Critical' || g.risk === 'High').length} クリティカル/高リスクギャップ
              </span>
            </div>
          </div>
        </div>
      </div>

      {/* Framework score cards grid */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">
        {frameworkCards.map(card => (
          <FrameworkScoreCard key={card.name} {...card} />
        ))}
      </div>

      {/* Summary table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-[#1e2d42]">
          <p className="text-sm font-semibold text-white">フレームワーク比較</p>
        </div>
        <table className="w-full text-sm">
          <thead>
            <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42]">
              <th className="px-5 py-3 text-left font-medium">フレームワーク</th>
              <th className="px-5 py-3 text-left font-medium">カバレッジ</th>
              <th className="px-5 py-3 text-left font-medium hidden sm:table-cell">ステータス</th>
              <th className="px-5 py-3 text-right font-medium">スコア</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-[#1e2d42]">
            {frameworkCards.map(card => (
              <tr key={card.name} className="hover:bg-[#1e2d42]/30">
                <td className="px-5 py-3 text-white font-medium">{card.name}</td>
                <td className="px-5 py-3">
                  <div className="flex items-center gap-3">
                    <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full max-w-[120px]">
                      <div
                        className={`h-full rounded-full ${
                          card.score >= 80 ? 'bg-green-500' :
                          card.score >= 60 ? 'bg-yellow-500' : 'bg-[#e8002d]'
                        }`}
                        style={{ width: `${card.score}%` }}
                      />
                    </div>
                    <span className="text-xs text-[#7d92b0] tabular-nums">{card.score}%</span>
                  </div>
                </td>
                <td className="px-5 py-3 hidden sm:table-cell">
                  {card.score >= 80 ? (
                    <span className="text-xs text-green-400">準拠</span>
                  ) : card.score >= 60 ? (
                    <span className="text-xs text-yellow-400">一部準拠</span>
                  ) : (
                    <span className="text-xs text-red-400">ギャップあり</span>
                  )}
                </td>
                <td className="px-5 py-3 text-right">
                  <span
                    className="text-sm font-bold tabular-nums"
                    style={{ color: scoreColor(card.score) }}
                  >
                    {card.score}%
                  </span>
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  )
}

// ── MITRE ATT&CK Tab ──────────────────────────────────────────────────────────

function MitreTab() {
  const [expandedTactic, setExpandedTactic] = useState<string | null>(null)

  const { data, isLoading } = useQuery<MitreData | null>({
    queryKey: ['compliance', 'mitre'],
    queryFn: async () => {
      try {
        return await apiFetch<MitreData>('/api/v1/compliance/mitre')
      } catch {
        return null
      }
    },
    staleTime: 60_000,
  })

  const tactics: MitreTactic[] = data?.tactics ?? []

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20 text-[#7d92b0]">
        <RefreshCw size={18} className="animate-spin mr-2" /> MITRE ATT&CKデータを読み込み中...
      </div>
    )
  }

  // Build a map of tactic name -> techniques for ordered display
  const tacticMap = new Map<string, MitreTechnique[]>()
  for (const t of tactics) {
    tacticMap.set(t.name, t.techniques)
  }

  const totalAlerts = tactics.reduce(
    (sum, t) => sum + t.techniques.reduce((s, tech) => s + tech.alert_count, 0),
    0
  )
  const coveredTechniques = tactics.reduce(
    (sum, t) => sum + t.techniques.filter(tech => tech.alert_count > 0).length,
    0
  )
  const totalTechniques = tactics.reduce((sum, t) => sum + t.techniques.length, 0)

  return (
    <div className="space-y-5">
      {/* Stats row */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-4 py-3">
          <p className="text-xs text-[#7d92b0] mb-1">対応タクティクス</p>
          <p className="text-xl font-bold text-white">{MITRE_TACTICS_LIST.length}</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-4 py-3">
          <p className="text-xs text-[#7d92b0] mb-1">マッピング済みテクニック</p>
          <p className="text-xl font-bold text-white">
            {coveredTechniques}
            <span className="text-sm text-[#7d92b0] font-normal"> / {totalTechniques}</span>
          </p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-4 py-3">
          <p className="text-xs text-[#7d92b0] mb-1">総アラート数</p>
          <p className="text-xl font-bold text-[#e8002d]">{totalAlerts}</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-4 py-3">
          <p className="text-xs text-[#7d92b0] mb-1">カバレッジ</p>
          <p className="text-xl font-bold" style={{ color: scoreColor(Math.round((coveredTechniques / totalTechniques) * 100)) }}>
            {Math.round((coveredTechniques / totalTechniques) * 100)}%
          </p>
        </div>
      </div>

      {/* Legend */}
      <div className="flex flex-wrap items-center gap-4 text-xs text-[#7d92b0]">
        <span className="font-medium text-white">アラート密度:</span>
        <span className="flex items-center gap-1.5">
          <span className="w-4 h-4 rounded bg-[#0d1220] border border-[#1e2d42] inline-block" />
          0件
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-4 h-4 rounded bg-yellow-500/15 border border-yellow-500/30 inline-block" />
          1〜5件
        </span>
        <span className="flex items-center gap-1.5">
          <span className="w-4 h-4 rounded bg-[#e8002d]/20 border border-[#e8002d]/30 inline-block" />
          6件以上
        </span>
      </div>

      {/* Tactic matrix grid */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-[#1e2d42]">
          <p className="text-sm font-semibold text-white">タクティクス / テクニックマトリクス</p>
          <p className="text-xs text-[#7d92b0] mt-0.5">
            タクティクスをクリックするとテクニック詳細が展開されます
          </p>
        </div>

        {/* Horizontal tactic cards */}
        <div className="p-4 grid grid-cols-2 sm:grid-cols-3 md:grid-cols-4 xl:grid-cols-6 gap-3">
          {MITRE_TACTICS_LIST.map(tacticName => {
            const techniques = tacticMap.get(tacticName) ?? []
            const tacticAlerts = techniques.reduce((s, t) => s + t.alert_count, 0)
            const isExpanded = expandedTactic === tacticName
            const coveredCount = techniques.filter(t => t.alert_count > 0).length

            return (
              <div key={tacticName} className="flex flex-col">
                {/* Tactic header cell */}
                <button
                  onClick={() => setExpandedTactic(isExpanded ? null : tacticName)}
                  className={`w-full text-left rounded-lg border p-2.5 transition-all ${
                    isExpanded
                      ? 'bg-[#e8002d]/10 border-[#e8002d]/40'
                      : 'bg-[#070d19] border-[#1e2d42] hover:border-[#e8002d]/30 hover:bg-[#1e2d42]/40'
                  }`}
                >
                  <p className="text-[10px] font-semibold text-white leading-tight mb-1.5 line-clamp-2">
                    {tacticName}
                  </p>
                  <div className="flex items-center justify-between">
                    <span className={`text-xs font-bold tabular-nums ${mitreAlertText(tacticAlerts)}`}>
                      {tacticAlerts}
                    </span>
                    <span className="text-[9px] text-[#7d92b0]">
                      {coveredCount}/{techniques.length}
                    </span>
                  </div>
                </button>

                {/* Technique cells when expanded */}
                {isExpanded && (
                  <div className="mt-1.5 flex flex-col gap-1">
                    {techniques.map(tech => (
                      <div
                        key={tech.id}
                        className={`rounded border p-1.5 ${mitreAlertBg(tech.alert_count)}`}
                      >
                        <p className="text-[9px] font-mono text-[#7d92b0] mb-0.5">{tech.id}</p>
                        <p className="text-[10px] text-white leading-tight line-clamp-2">{tech.name}</p>
                        <p className={`text-xs font-bold mt-1 ${mitreAlertText(tech.alert_count)}`}>
                          {tech.alert_count}件
                        </p>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            )
          })}
        </div>
      </div>

      {/* Full technique table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-[#1e2d42]">
          <p className="text-sm font-semibold text-white">全テクニック一覧</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42]">
                <th className="px-4 py-3 text-left font-medium">テクニックID</th>
                <th className="px-4 py-3 text-left font-medium">テクニック名</th>
                <th className="px-4 py-3 text-left font-medium">タクティクス</th>
                <th className="px-4 py-3 text-right font-medium">アラート数</th>
                <th className="px-4 py-3 text-left font-medium hidden md:table-cell">カバレッジ</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {tactics.flatMap(tactic =>
                tactic.techniques.map(tech => (
                  <tr key={`${tactic.name}-${tech.id}`} className="hover:bg-[#1e2d42]/30">
                    <td className="px-4 py-2.5 font-mono text-blue-300 text-xs whitespace-nowrap">
                      {tech.id}
                    </td>
                    <td className="px-4 py-2.5 text-white text-xs">{tech.name}</td>
                    <td className="px-4 py-2.5 text-[#7d92b0] text-xs whitespace-nowrap">
                      {tactic.name}
                    </td>
                    <td className="px-4 py-2.5 text-right">
                      <span className={`text-xs font-bold tabular-nums ${mitreAlertText(tech.alert_count)}`}>
                        {tech.alert_count}
                      </span>
                    </td>
                    <td className="px-4 py-2.5 hidden md:table-cell">
                      {tech.alert_count > 0 ? (
                        <span className="inline-flex items-center gap-1 text-xs text-green-400">
                          <CheckCircle size={11} /> カバー済み
                        </span>
                      ) : (
                        <span className="inline-flex items-center gap-1 text-xs text-[#7d92b0]">
                          <XCircle size={11} /> 未カバー
                        </span>
                      )}
                    </td>
                  </tr>
                ))
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── CIS Controls Tab ──────────────────────────────────────────────────────────

const STATUS_STYLE: Record<CisControl['status'], { bg: string; text: string; dot: string; label: string }> = {
  'Implemented':     { bg: 'bg-green-500/15',  text: 'text-green-400',  dot: 'bg-green-500',  label: '実装済み' },
  'Partial':         { bg: 'bg-yellow-500/15', text: 'text-yellow-400', dot: 'bg-yellow-500', label: '一部実装' },
  'Not Implemented': { bg: 'bg-red-500/15',    text: 'text-red-400',    dot: 'bg-red-500',    label: '未実装' },
}

function CisTab() {
  const { data, isLoading } = useQuery<CisData | null>({
    queryKey: ['compliance', 'cis'],
    queryFn: async () => {
      try {
        return await apiFetch<CisData>('/api/v1/compliance/cis')
      } catch {
        return null
      }
    },
    staleTime: 60_000,
  })

  const controls: CisControl[] = data?.controls ?? []

  const implemented = controls.filter(c => c.status === 'Implemented').length
  const partial = controls.filter(c => c.status === 'Partial').length
  const notImplemented = controls.filter(c => c.status === 'Not Implemented').length

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20 text-[#7d92b0]">
        <RefreshCw size={18} className="animate-spin mr-2" /> CIS Controlsデータを読み込み中...
      </div>
    )
  }

  return (
    <div className="space-y-5">
      {/* Stats */}
      <div className="grid grid-cols-3 gap-3">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-4 py-3 text-center">
          <p className="text-xs text-[#7d92b0] mb-1">実装済み</p>
          <p className="text-2xl font-bold text-green-400">{implemented}</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-4 py-3 text-center">
          <p className="text-xs text-[#7d92b0] mb-1">一部実装</p>
          <p className="text-2xl font-bold text-yellow-400">{partial}</p>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-4 py-3 text-center">
          <p className="text-xs text-[#7d92b0] mb-1">未実装</p>
          <p className="text-2xl font-bold text-red-400">{notImplemented}</p>
        </div>
      </div>

      {/* Progress bar summary */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
        <div className="flex items-center justify-between mb-2">
          <p className="text-sm font-semibold text-white">CIS Controls v8 実装状況</p>
          <p className="text-xs text-[#7d92b0]">
            {implemented} / {controls.length} 完全実装
          </p>
        </div>
        <div className="w-full h-3 bg-[#1e2d42] rounded-full overflow-hidden flex">
          <div
            className="h-full bg-green-500 transition-all duration-700"
            style={{ width: `${(implemented / controls.length) * 100}%` }}
          />
          <div
            className="h-full bg-yellow-500 transition-all duration-700"
            style={{ width: `${(partial / controls.length) * 100}%` }}
          />
          <div
            className="h-full bg-red-500/70 transition-all duration-700"
            style={{ width: `${(notImplemented / controls.length) * 100}%` }}
          />
        </div>
        <div className="flex gap-4 mt-2 text-xs text-[#7d92b0]">
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-green-500 inline-block" />
            実装済み {Math.round((implemented / controls.length) * 100)}%
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-yellow-500 inline-block" />
            一部実装 {Math.round((partial / controls.length) * 100)}%
          </span>
          <span className="flex items-center gap-1.5">
            <span className="w-2.5 h-2.5 rounded-sm bg-red-500/70 inline-block" />
            未実装 {Math.round((notImplemented / controls.length) * 100)}%
          </span>
        </div>
      </div>

      {/* Controls table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-[#1e2d42]">
          <p className="text-sm font-semibold text-white">CIS Controls 一覧</p>
        </div>
        <div className="divide-y divide-[#1e2d42]">
          {controls.map(control => {
            const style = STATUS_STYLE[control.status]
            return (
              <div key={control.id} className="flex items-center gap-4 px-5 py-3 hover:bg-[#1e2d42]/30">
                {/* Control number */}
                <div className="flex-shrink-0 w-8 h-8 rounded-lg bg-[#070d19] border border-[#1e2d42]
                               flex items-center justify-center text-xs font-bold text-[#7d92b0]">
                  {control.id}
                </div>

                {/* Name */}
                <div className="flex-1 min-w-0">
                  <p className="text-sm text-white font-medium truncate">{control.name}</p>
                </div>

                {/* Alert count */}
                <div className="flex-shrink-0 text-right hidden sm:block">
                  <p className="text-xs text-[#7d92b0]">関連アラート</p>
                  <p className="text-sm font-semibold text-white tabular-nums">{control.alert_count}</p>
                </div>

                {/* Status badge */}
                <div className="flex-shrink-0">
                  <span className={`inline-flex items-center gap-1.5 px-2.5 py-1 rounded-full text-xs
                                   font-semibold ${style.bg} ${style.text}`}>
                    <span className={`w-1.5 h-1.5 rounded-full ${style.dot}`} />
                    {style.label}
                  </span>
                </div>
              </div>
            )
          })}
        </div>
      </div>
    </div>
  )
}

// ── NIST CSF Tab ──────────────────────────────────────────────────────────────

const NIST_FUNCTION_COLORS: Record<string, string> = {
  ID: '#3b82f6',
  PR: '#8b5cf6',
  DE: '#22c55e',
  RS: '#f59e0b',
  RC: '#ec4899',
}

function NistCoverageBar({ coverage, color }: { coverage: number; color: string }) {
  return (
    <div className="flex items-center gap-2 flex-1">
      <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
        <div
          className="h-full rounded-full transition-all duration-700"
          style={{ width: `${coverage}%`, backgroundColor: color }}
        />
      </div>
      <span className="text-xs font-semibold tabular-nums w-8 text-right" style={{ color }}>
        {coverage}%
      </span>
    </div>
  )
}

function NistTab() {
  const [expandedFn, setExpandedFn] = useState<string | null>('DE')

  const { data, isLoading } = useQuery<NistData | null>({
    queryKey: ['compliance', 'nist'],
    queryFn: async () => {
      try {
        return await apiFetch<NistData>('/api/v1/compliance/nist')
      } catch {
        return null
      }
    },
    staleTime: 60_000,
  })

  const functions: NistFunction[] = data?.functions ?? []

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-20 text-[#7d92b0]">
        <RefreshCw size={18} className="animate-spin mr-2" /> NIST CSFデータを読み込み中...
      </div>
    )
  }

  return (
    <div className="space-y-5">
      {/* 5-function overview */}
      <div className="grid grid-cols-1 sm:grid-cols-5 gap-3">
        {functions.map(fn => {
          const color = NIST_FUNCTION_COLORS[fn.id] ?? '#7d92b0'
          return (
            <div
              key={fn.id}
              className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 text-center
                         cursor-pointer hover:border-opacity-60 transition-all"
              style={{ borderColor: expandedFn === fn.id ? color : undefined }}
              onClick={() => setExpandedFn(expandedFn === fn.id ? null : fn.id)}
            >
              <div
                className="w-10 h-10 rounded-full mx-auto mb-3 flex items-center justify-center
                           text-xs font-bold text-white"
                style={{ backgroundColor: `${color}25`, color }}
              >
                {fn.id}
              </div>
              <p className="text-xs font-semibold text-white mb-2">{fn.name}</p>
              <p className="text-2xl font-bold tabular-nums" style={{ color }}>
                {fn.coverage}%
              </p>
              <div className="mt-2 w-full h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                <div
                  className="h-full rounded-full"
                  style={{ width: `${fn.coverage}%`, backgroundColor: color }}
                />
              </div>
              <p className="text-[10px] text-[#7d92b0] mt-1">
                {fn.subcategories.length} サブカテゴリ
              </p>
            </div>
          )
        })}
      </div>

      {/* Subcategory detail for selected function */}
      {functions.map(fn => {
        if (expandedFn !== fn.id) return null
        const color = NIST_FUNCTION_COLORS[fn.id] ?? '#7d92b0'
        return (
          <div key={fn.id} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <div
              className="px-5 py-3 border-b border-[#1e2d42] flex items-center gap-3"
              style={{ borderLeftColor: color, borderLeftWidth: 3 }}
            >
              <span
                className="text-xs font-bold px-2 py-0.5 rounded"
                style={{ backgroundColor: `${color}20`, color }}
              >
                {fn.id}
              </span>
              <p className="text-sm font-semibold text-white">{fn.name}</p>
              <span className="ml-auto text-sm font-bold" style={{ color }}>全体 {fn.coverage}%</span>
            </div>
            <div className="divide-y divide-[#1e2d42]">
              {fn.subcategories.map(sub => (
                <div key={sub.id} className="flex items-center gap-4 px-5 py-3 hover:bg-[#1e2d42]/30">
                  <div className="flex-shrink-0 w-16">
                    <span className="text-xs font-mono text-blue-300">{sub.id}</span>
                  </div>
                  <p className="text-sm text-white flex-1">{sub.name}</p>
                  <div className="flex-shrink-0 w-44 hidden sm:block">
                    <NistCoverageBar coverage={sub.coverage} color={color} />
                  </div>
                  <div className="flex-shrink-0">
                    {sub.coverage >= 70 ? (
                      <span className="text-xs text-green-400 flex items-center gap-1">
                        <CheckCircle size={11} /> 十分
                      </span>
                    ) : sub.coverage >= 40 ? (
                      <span className="text-xs text-yellow-400 flex items-center gap-1">
                        <AlertTriangle size={11} /> 一部
                      </span>
                    ) : (
                      <span className="text-xs text-red-400 flex items-center gap-1">
                        <XCircle size={11} /> 不十分
                      </span>
                    )}
                  </div>
                </div>
              ))}
            </div>
          </div>
        )
      })}

      {/* All subcategories table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-[#1e2d42]">
          <p className="text-sm font-semibold text-white">NIST CSF サブカテゴリ一覧</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42]">
                <th className="px-4 py-3 text-left font-medium">機能</th>
                <th className="px-4 py-3 text-left font-medium">サブカテゴリ</th>
                <th className="px-4 py-3 text-left font-medium">名称</th>
                <th className="px-4 py-3 text-left font-medium">カバレッジ</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {functions.flatMap(fn =>
                fn.subcategories.map(sub => {
                  const color = NIST_FUNCTION_COLORS[fn.id] ?? '#7d92b0'
                  return (
                    <tr key={sub.id} className="hover:bg-[#1e2d42]/30">
                      <td className="px-4 py-2.5">
                        <span
                          className="text-xs font-bold px-1.5 py-0.5 rounded"
                          style={{ backgroundColor: `${color}20`, color }}
                        >
                          {fn.id}
                        </span>
                      </td>
                      <td className="px-4 py-2.5 font-mono text-xs text-blue-300 whitespace-nowrap">
                        {sub.id}
                      </td>
                      <td className="px-4 py-2.5 text-white text-xs">{sub.name}</td>
                      <td className="px-4 py-2.5 w-40">
                        <NistCoverageBar coverage={sub.coverage} color={color} />
                      </td>
                    </tr>
                  )
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── Gaps Tab ──────────────────────────────────────────────────────────────────

const RISK_STYLE: Record<GapItem['risk'], { bg: string; text: string; order: number }> = {
  Critical: { bg: 'bg-red-500/20',    text: 'text-red-300',    order: 0 },
  High:     { bg: 'bg-orange-500/20', text: 'text-orange-300', order: 1 },
  Medium:   { bg: 'bg-yellow-500/20', text: 'text-yellow-300', order: 2 },
  Low:      { bg: 'bg-blue-500/20',   text: 'text-blue-300',   order: 3 },
}

function GapsTab() {
  const sortedGaps = [...([] as GapItem[])].sort(
    (a, b) => RISK_STYLE[a.risk].order - RISK_STYLE[b.risk].order
  )

  const criticalCount = sortedGaps.filter(g => g.risk === 'Critical').length
  const highCount = sortedGaps.filter(g => g.risk === 'High').length
  const mediumCount = sortedGaps.filter(g => g.risk === 'Medium').length
  const lowCount = sortedGaps.filter(g => g.risk === 'Low').length

  return (
    <div className="space-y-5">
      {/* Risk summary */}
      <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
        {[
          { label: 'クリティカルギャップ', count: criticalCount, color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/20' },
          { label: '高リスクギャップ',     count: highCount,     color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/20' },
          { label: '中リスクギャップ',     count: mediumCount,   color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/20' },
          { label: '低リスクギャップ',     count: lowCount,      color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/20' },
        ].map(item => (
          <div key={item.label} className={`${item.bg} border rounded-xl px-4 py-3`}>
            <p className="text-xs text-[#7d92b0] mb-1">{item.label}</p>
            <p className={`text-2xl font-bold ${item.color}`}>{item.count}</p>
          </div>
        ))}
      </div>

      {/* Alert banner for critical gaps */}
      {criticalCount > 0 && (
        <div className="flex items-start gap-3 p-4 bg-[#e8002d]/10 border border-[#e8002d]/30 rounded-xl">
          <AlertCircle size={18} className="text-[#e8002d] flex-shrink-0 mt-0.5" />
          <div>
            <p className="text-sm font-semibold text-white">
              {criticalCount}件のクリティカルギャップに即時対応が必要です
            </p>
            <p className="text-xs text-[#7d92b0] mt-0.5">
              これらのコントロールはカバレッジがなく、セキュリティ態勢における最大のリスクです。早急に検知ルールまたはコントロールを実装してください。
            </p>
          </div>
        </div>
      )}

      {/* Gaps table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-[#1e2d42] flex items-center justify-between">
          <p className="text-sm font-semibold text-white">カバレッジギャップ</p>
          <p className="text-xs text-[#7d92b0]">{sortedGaps.length}件（リスク順）</p>
        </div>
        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42]">
                <th className="px-4 py-3 text-left font-medium">リスク</th>
                <th className="px-4 py-3 text-left font-medium">フレームワーク</th>
                <th className="px-4 py-3 text-left font-medium">コントロール / テクニック</th>
                <th className="px-4 py-3 text-left font-medium hidden md:table-cell">説明</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {sortedGaps.map(gap => {
                const riskStyle = RISK_STYLE[gap.risk]
                return (
                  <tr key={gap.id} className="hover:bg-[#1e2d42]/30">
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px]
                                       font-bold uppercase tracking-wider ${riskStyle.bg} ${riskStyle.text}`}>
                        {gap.risk}
                      </span>
                    </td>
                    <td className="px-4 py-3 whitespace-nowrap">
                      <span className="text-xs text-[#7d92b0] bg-[#1e2d42] px-2 py-0.5 rounded">
                        {gap.framework}
                      </span>
                    </td>
                    <td className="px-4 py-3">
                      <span className="text-sm text-white font-medium">{gap.control}</span>
                    </td>
                    <td className="px-4 py-3 hidden md:table-cell">
                      <span className="text-xs text-[#7d92b0]">{gap.description}</span>
                    </td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      </div>
    </div>
  )
}

// ── Agent Scores Tab (original functionality, preserved) ───────────────────────

const AGENT_FRAMEWORKS: Framework[] = ['CIS', 'NIST', 'SOC2']

function AgentScoresTab() {
  const queryClient = useQueryClient()
  const [selectedFramework, setSelectedFramework] = useState<Framework>('CIS')
  const [expandedAgent, setExpandedAgent] = useState<string | null>(null)
  const [computingAgents, setComputingAgents] = useState<Set<string>>(new Set())

  const { data: scores = [], isLoading, error } = useQuery<ComplianceScore[]>({
    queryKey: ['compliance', 'scores', selectedFramework],
    queryFn: () => apiFetchList<ComplianceScore>(
      `/api/v1/compliance/scores?framework=${selectedFramework}`
    ),
    refetchInterval: 60_000,
  })

  const recomputeMutation = useMutation({
    mutationFn: (agentId: string) =>
      apiFetch<ComplianceScore>(
        `/api/v1/compliance/scores/${agentId}/compute`,
        { method: 'POST', body: JSON.stringify({ framework: selectedFramework }) }
      ),
    onMutate: (agentId: string) => {
      setComputingAgents(prev => new Set(prev).add(agentId))
    },
    onSettled: (_data, _err, agentId: string) => {
      setComputingAgents(prev => {
        const next = new Set(prev)
        next.delete(agentId)
        return next
      })
      void queryClient.invalidateQueries({ queryKey: ['compliance', 'scores', selectedFramework] })
    },
  })

  const handleBulkRecompute = useCallback(async () => {
    for (const s of scores) {
      recomputeMutation.mutate(s.agent_id)
    }
  }, [scores, recomputeMutation])

  const avgScore =
    scores.length > 0
      ? scores.reduce((sum, s) => sum + s.score, 0) / scores.length
      : 0

  const compliantCount = scores.filter(s => s.score >= 80).length

  const criticalFailures = scores.reduce((sum, s) => {
    const critFailed = s.details.checks.filter(
      c => c.severity === 'critical' && !c.passed
    ).length
    return sum + critFailed
  }, 0)

  const handleRowClick = (agentId: string) => {
    setExpandedAgent(prev => (prev === agentId ? null : agentId))
  }

  return (
    <div className="space-y-5">
      {/* Framework selector + bulk recompute */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1">
          {AGENT_FRAMEWORKS.map(fw => (
            <button
              key={fw}
              onClick={() => {
                setSelectedFramework(fw)
                setExpandedAgent(null)
              }}
              className={`px-3 py-1.5 rounded-md text-sm font-medium transition-all duration-150 ${
                selectedFramework === fw
                  ? 'bg-[#e8002d] text-white shadow'
                  : 'text-[#7d92b0] hover:text-white hover:bg-[#1e2d42]'
              }`}
            >
              {fw}
            </button>
          ))}
        </div>

        <button
          onClick={() => void handleBulkRecompute()}
          disabled={scores.length === 0 || recomputeMutation.isPending}
          className="flex items-center gap-2 px-3 py-2 bg-[#0d1220] border border-[#1e2d42]
                     hover:bg-[#1e2d42] disabled:opacity-50 disabled:cursor-not-allowed
                     rounded-lg text-sm text-white transition-colors"
        >
          <RefreshCw size={14} className={recomputeMutation.isPending ? 'animate-spin' : ''} />
          全て再計算
        </button>
      </div>

      {/* Summary cards */}
      <div className="grid grid-cols-1 sm:grid-cols-3 gap-4">
        <StatCard
          title="平均スコア"
          value={`${Math.round(avgScore)}`}
          icon={<Activity size={18} />}
          color={avgScore >= 80 ? 'green' : avgScore >= 60 ? 'yellow' : 'red'}
          subtext={`${scores.length} エージェント`}
        />
        <StatCard
          title="準拠エージェント (≥80)"
          value={compliantCount}
          icon={<Users size={18} />}
          color="green"
          subtext={scores.length > 0 ? `全体の${Math.round((compliantCount / scores.length) * 100)}%` : '—'}
        />
        <StatCard
          title="クリティカル違反"
          value={criticalFailures}
          icon={<AlertTriangle size={18} />}
          color={criticalFailures > 0 ? 'red' : 'green'}
          subtext="クリティカルチェック違反合計"
          subtextColor={criticalFailures > 0 ? 'red' : 'green'}
        />
      </div>

      {/* Agent table */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        <div className="px-5 py-3 border-b border-[#1e2d42] flex items-center justify-between">
          <p className="text-sm font-semibold text-white">
            エージェントスコア
            <span className="ml-2 text-xs text-[#7d92b0] font-normal">({selectedFramework})</span>
          </p>
          {isLoading && (
            <span className="text-xs text-[#7d92b0] flex items-center gap-1">
              <RefreshCw size={12} className="animate-spin" /> 読み込み中...
            </span>
          )}
        </div>

        {error ? (
          <div className="text-center py-16 text-red-400 text-sm">データの読み込みに失敗しました</div>
        ) : isLoading && scores.length === 0 ? (
          <div className="text-center py-16 text-[#7d92b0] text-sm">読み込み中...</div>
        ) : scores.length === 0 ? (
          <div className="text-center py-16 text-[#7d92b0] text-sm">スコアデータがありません</div>
        ) : (
          <div className="divide-y divide-[#1e2d42]">
            {scores.map(score => {
              const isExpanded = expandedAgent === score.agent_id
              const isComputing = computingAgents.has(score.agent_id)
              const failedChecks = score.total_checks - score.passed_checks

              return (
                <div key={score.agent_id}>
                  <div
                    className="flex items-center gap-4 px-5 py-3 hover:bg-[#1e2d42]/40
                               cursor-pointer transition-colors"
                    onClick={() => handleRowClick(score.agent_id)}
                  >
                    <div className="text-[#7d92b0] flex-shrink-0 w-4">
                      {isExpanded
                        ? <ChevronDown size={14} />
                        : <ChevronRight size={14} />
                      }
                    </div>

                    <div className="flex-1 min-w-0">
                      <p className="text-sm font-mono text-white truncate">{score.agent_id}</p>
                    </div>

                    <div className="flex-shrink-0">
                      <MiniGauge score={score.score} />
                    </div>

                    <div className="text-xs text-[#7d92b0] flex-shrink-0 w-28 text-center">
                      <span className="text-green-400 font-semibold">{score.passed_checks}</span>
                      <span className="text-[#1e2d42]"> / </span>
                      <span className="text-white">{score.total_checks}</span>
                      {failedChecks > 0 && (
                        <span className="ml-1 text-red-400">({failedChecks}件失敗)</span>
                      )}
                    </div>

                    <div className="text-xs text-[#7d92b0] flex-shrink-0 w-28 hidden sm:block">
                      {formatDate(score.computed_at)}
                    </div>

                    <button
                      onClick={e => {
                        e.stopPropagation()
                        recomputeMutation.mutate(score.agent_id)
                      }}
                      disabled={isComputing}
                      className="flex items-center gap-1 px-2.5 py-1.5 text-xs rounded
                                 bg-[#1e2d42] hover:bg-[#2d3f58] text-white
                                 disabled:opacity-50 disabled:cursor-not-allowed
                                 transition-colors flex-shrink-0"
                    >
                      <RefreshCw size={11} className={isComputing ? 'animate-spin' : ''} />
                      再計算
                    </button>
                  </div>

                  {isExpanded && (
                    <div className="px-5 pb-4">
                      <DetailPanel
                        score={score}
                        onClose={() => setExpandedAgent(null)}
                      />
                    </div>
                  )}
                </div>
              )
            })}
          </div>
        )}
      </div>

      <p className="text-xs text-[#7d92b0]/60 text-right">
        スコア = 合格チェック / 総チェック × 100 | 準拠閾値: ≥80 | フレームワーク: {selectedFramework}
      </p>
    </div>
  )
}

// ── Tab Config ────────────────────────────────────────────────────────────────

interface TabConfig {
  id: MainTab
  label: string
  icon: React.ReactNode
}

const MAIN_TABS: TabConfig[] = [
  { id: 'overview', label: '概要',          icon: <Activity size={14} /> },
  { id: 'mitre',    label: 'MITRE ATT&CK',  icon: <LayoutGrid size={14} /> },
  { id: 'cis',      label: 'CIS Controls',  icon: <List size={14} /> },
  { id: 'nist',     label: 'NIST CSF',      icon: <TrendingUp size={14} /> },
  { id: 'gaps',     label: 'ギャップ',      icon: <AlertCircle size={14} /> },
]

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function CompliancePage() {
  const [activeTab, setActiveTab] = useState<MainTab>('overview')

  return (
    <div className="min-h-screen bg-[#070d19] text-white">
      <div className="max-w-screen-xl mx-auto px-4 sm:px-6 py-8">

        {/* Page Header */}
        <div className="flex items-center gap-3 mb-6">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/15 flex items-center justify-center">
            <Shield size={22} className="text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-white">コンプライアンス</h1>
            <p className="text-sm text-[#7d92b0]">フレームワークマッピング・カバレッジ分析・ギャップ評価</p>
          </div>
        </div>

        {/* Tab bar */}
        <div className="flex items-center gap-1 border-b border-[#1e2d42] mb-6 overflow-x-auto pb-px">
          {MAIN_TABS.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium whitespace-nowrap
                         border-b-2 transition-all duration-150 -mb-px ${
                activeTab === tab.id
                  ? 'border-[#e8002d] text-white'
                  : 'border-transparent text-[#7d92b0] hover:text-white hover:border-[#1e2d42]'
              }`}
            >
              {tab.icon}
              {tab.label}
              {tab.id === 'gaps' && (
                <span className="ml-0.5 px-1.5 py-0.5 rounded-full text-[10px] font-bold
                                 bg-[#e8002d]/20 text-[#e8002d]">
                  {([] as GapItem[]).filter(g => g.risk === 'Critical' || g.risk === 'High').length}
                </span>
              )}
            </button>
          ))}

          {/* Agent scores tab — slightly separated */}
          <div className="flex-1" />
          <button
            onClick={() => setActiveTab('agent-scores')}
            className={`flex items-center gap-1.5 px-3 py-2 text-xs font-medium whitespace-nowrap
                       rounded-lg transition-all ${activeTab === 'agent-scores' ? 'text-white bg-[#1e2d42]' : 'text-[#7d92b0] hover:text-white hover:bg-[#1e2d42]'}`}
            title="エージェント別コンプライアンススコア"
          >
            <Users size={13} />
            エージェントスコア
          </button>
        </div>

        {/* Tab content */}
        <div>
          {activeTab === 'overview'      && <OverviewTab />}
          {activeTab === 'mitre'         && <MitreTab />}
          {activeTab === 'cis'           && <CisTab />}
          {activeTab === 'nist'          && <NistTab />}
          {activeTab === 'gaps'          && <GapsTab />}
          {activeTab === 'agent-scores'  && <AgentScoresTab />}
        </div>

      </div>
    </div>
  )
}
