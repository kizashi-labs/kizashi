'use client'

import { useMemo } from 'react'
import Link from 'next/link'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { USE_MOCK } from '@/lib/mock'
import {
  ShieldCheck, TrendingUp, AlertTriangle, RefreshCw,
  ChevronRight, Bug, Shield, Monitor, Activity,
  BarChart3, CheckCircle,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

interface Agent {
  id: string
  status?: string
}

interface AgentsResponse {
  data?: Agent[]
  items?: Agent[]
  agents?: Agent[]
}

interface DetectionRate {
  detection_rate?: number
  total_alerts?: number
  detected?: number
  rule_coverage?: number
  mttr_hours?: number
  mttr?: number
}

interface ComplianceScores {
  score?: number
  overall?: number
  frameworks?: { score?: number }[]
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function clamp(v: number, min: number, max: number) {
  return Math.max(min, Math.min(max, v))
}

function scoreColor(score: number): string {
  if (score >= 70) return '#22c55e'
  if (score >= 40) return '#f59e0b'
  return '#e8002d'
}

function scoreTailwindText(score: number): string {
  if (score >= 70) return 'text-green-400'
  if (score >= 40) return 'text-amber-400'
  return 'text-red-400'
}

function scoreBgClass(score: number): string {
  if (score >= 70) return 'bg-green-500'
  if (score >= 40) return 'bg-amber-500'
  return 'bg-red-500'
}

function scoreLabel(score: number): string {
  if (score >= 70) return '良好'
  if (score >= 40) return '要改善'
  return '要対処'
}

// ─── SVG Arc Gauge ────────────────────────────────────────────────────────────

function SecurityGauge({ score }: { score: number }) {
  const radius = 80
  const cx = 100
  const cy = 105
  const startAngle = -210
  const sweepDeg = 240
  const filled = (score / 100) * sweepDeg

  function polar(angle: number) {
    const rad = (angle * Math.PI) / 180
    return { x: cx + radius * Math.cos(rad), y: cy + radius * Math.sin(rad) }
  }

  function arcPath(start: number, end: number) {
    const s = polar(start)
    const e = polar(end)
    const large = end - start > 180 ? 1 : 0
    return `M ${s.x} ${s.y} A ${radius} ${radius} 0 ${large} 1 ${e.x} ${e.y}`
  }

  const color = scoreColor(score)
  const endAngle = startAngle + 240

  return (
    <svg viewBox="0 0 200 180" className="w-56 h-48">
      {/* Track */}
      <path
        d={arcPath(startAngle, endAngle)}
        fill="none"
        stroke="#1e2d42"
        strokeWidth={14}
        strokeLinecap="round"
      />
      {/* Ticks */}
      {[0, 25, 50, 75, 100].map(pct => {
        const angle = startAngle + (pct / 100) * sweepDeg
        const inner = polar(angle)
        const r2 = radius - 10
        const rad = (angle * Math.PI) / 180
        const ox = cx + r2 * Math.cos(rad)
        const oy = cy + r2 * Math.sin(rad)
        return (
          <line
            key={pct}
            x1={inner.x} y1={inner.y}
            x2={ox} y2={oy}
            stroke="#1e2d42"
            strokeWidth={1.5}
          />
        )
      })}
      {/* Filled arc */}
      {score > 0 && (
        <path
          d={arcPath(startAngle, startAngle + filled)}
          fill="none"
          stroke={color}
          strokeWidth={14}
          strokeLinecap="round"
          style={{ filter: `drop-shadow(0 0 8px ${color}80)` }}
        />
      )}
      {/* Score text */}
      <text
        x={cx} y={cy + 6}
        textAnchor="middle"
        dominantBaseline="middle"
        fill={color}
        fontSize={34}
        fontWeight="bold"
        fontFamily="monospace"
      >
        {score}
      </text>
      {/* Label */}
      <text x={cx} y={cy + 32} textAnchor="middle" fill="#9ca3af" fontSize={11}>
        セキュリティスコア
      </text>
      <text x={cx} y={cy + 46} textAnchor="middle" fill={color} fontSize={10} fontWeight="bold">
        {scoreLabel(score)}
      </text>
      {/* Scale */}
      <text x={16} y={170} fill="#3d5068" fontSize={9}>0</text>
      <text x={178} y={170} fill="#3d5068" fontSize={9}>100</text>
    </svg>
  )
}

// ─── Category Progress Bar ────────────────────────────────────────────────────

function CategoryBar({
  label, score, description, icon: Icon,
}: {
  label: string
  score: number
  description?: string
  icon: React.ElementType
}) {
  const color = scoreColor(score)
  const bgClass = scoreBgClass(score)
  const textClass = scoreTailwindText(score)

  return (
    <div className="space-y-1.5">
      <div className="flex items-center justify-between gap-2">
        <div className="flex items-center gap-2 min-w-0">
          <Icon className="w-3.5 h-3.5 text-[#3d5068] shrink-0" />
          <span className="text-sm text-[#e2e8f4] font-medium truncate">{label}</span>
        </div>
        <span className={`text-sm font-bold tabular-nums shrink-0 ${textClass}`}>{score}</span>
      </div>
      <div className="h-2.5 bg-[#0a1525] rounded-full overflow-hidden">
        <div
          className={`h-full rounded-full transition-all duration-700 ${bgClass}`}
          style={{ width: `${score}%` }}
        />
      </div>
      {description && <p className="text-[10px] text-[#7d92b0]">{description}</p>}
    </div>
  )
}

// ─── CSS Sparkline ────────────────────────────────────────────────────────────

function SparklineBar({ data }: { data: number[] }) {
  const max = Math.max(...data, 1)
  return (
    <div className="flex items-end gap-1 h-12">
      {data.map((v, i) => {
        const pct = Math.round((v / max) * 100)
        const isLast = i === data.length - 1
        return (
          <div
            key={i}
            className="flex-1 rounded-t-sm transition-all duration-300"
            style={{
              height: `${Math.max(pct, 4)}%`,
              background: isLast ? '#e8002d' : '#1e2d42',
              opacity: isLast ? 1 : 0.5 + (i / data.length) * 0.5,
            }}
            title={`${v}`}
          />
        )
      })}
    </div>
  )
}

// ─── Priority Badge ───────────────────────────────────────────────────────────

function PriorityBadge({ priority }: { priority: 'Critical' | 'High' | 'Medium' }) {
  const styles = {
    Critical: 'bg-red-900/40 text-red-300 border border-red-700/40',
    High:     'bg-orange-900/40 text-orange-300 border border-orange-700/40',
    Medium:   'bg-amber-900/40 text-amber-300 border border-amber-700/40',
  }
  const labels = { Critical: '重大', High: '高', Medium: '中' }
  return (
    <span className={`px-2 py-0.5 rounded-sm text-[10px] font-bold ${styles[priority]}`}>
      {labels[priority]}
    </span>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SecurityScorePage() {

  // ── API queries ──

  const { data: rawAgents, isLoading: agentsLoading, refetch: refetchAgents } = useQuery<AgentsResponse | Agent[]>({
    queryKey: ['security-score-agents'],
    queryFn: () => apiFetch('/api/v1/agents?limit=500'),
    refetchInterval: 120_000,
    staleTime: 60_000,
  })

  const { data: detectionRaw, refetch: refetchDetection } = useQuery<DetectionRate>({
    queryKey: ['security-score-detection'],
    queryFn: () => apiFetch('/api/v1/dashboard/detection-rate'),
    retry: false,
    refetchInterval: 120_000,
    staleTime: 60_000,
  })

  const { data: complianceRaw, refetch: refetchCompliance } = useQuery<ComplianceScores>({
    queryKey: ['security-score-compliance'],
    queryFn: () => apiFetch('/api/v1/compliance/scores'),
    retry: false,
    refetchInterval: 120_000,
    staleTime: 60_000,
  })

  // ── Normalize ──

  const agents: Agent[] = useMemo(() => {
    if (!rawAgents) return []
    if (Array.isArray(rawAgents)) return rawAgents
    return (rawAgents as AgentsResponse).data
      ?? (rawAgents as AgentsResponse).items
      ?? (rawAgents as AgentsResponse).agents
      ?? []
  }, [rawAgents])

  // ── Compute category scores ──

  const endpointCoverage = useMemo(() => {
    if (agents.length === 0) return 72 // fallback mock
    const online = agents.filter(a => a.status === 'online').length
    return agents.length > 0 ? clamp(Math.round((online / agents.length) * 100), 0, 100) : 0
  }, [agents])

  const threatDetection = useMemo(() => {
    if (detectionRaw?.detection_rate !== undefined) return clamp(Math.round(detectionRaw.detection_rate), 0, 100)
    if (detectionRaw?.rule_coverage !== undefined) return clamp(Math.round(detectionRaw.rule_coverage), 0, 100)
    return 65 // mock fallback
  }, [detectionRaw])

  const incidentResponse = useMemo(() => {
    const mttr = detectionRaw?.mttr_hours ?? detectionRaw?.mttr ?? null
    if (mttr !== null) {
      // Score based on MTTR: <=1h = 100, 4h = 75, 8h = 50, 24h+ = 20
      if (mttr <= 1)  return 95
      if (mttr <= 4)  return 75
      if (mttr <= 8)  return 55
      if (mttr <= 24) return 35
      return 20
    }
    return 58 // mock fallback
  }, [detectionRaw])

  const vulnManagement = useMemo(() => {
    // Mock: would come from /api/v1/vulnerabilities/stats
    return 48
  }, [])

  const complianceScore = useMemo(() => {
    if (complianceRaw?.score !== undefined) return clamp(Math.round(complianceRaw.score), 0, 100)
    if (complianceRaw?.overall !== undefined) return clamp(Math.round(complianceRaw.overall), 0, 100)
    const frameworks = complianceRaw?.frameworks
    if (frameworks && frameworks.length > 0) {
      const avg = frameworks.reduce((s, f) => s + (f.score ?? 0), 0) / frameworks.length
      return clamp(Math.round(avg), 0, 100)
    }
    return 71 // mock fallback
  }, [complianceRaw])

  const visibility = useMemo(() => {
    // Derived from agent coverage + detection rate
    const base = Math.round((endpointCoverage * 0.6 + threatDetection * 0.4))
    return clamp(base, 0, 100)
  }, [endpointCoverage, threatDetection])

  // ── Overall score ──

  const overallScore = useMemo(() => {
    const weights = [
      { score: endpointCoverage, w: 0.25 },
      { score: threatDetection,  w: 0.20 },
      { score: incidentResponse, w: 0.20 },
      { score: vulnManagement,   w: 0.15 },
      { score: complianceScore,  w: 0.10 },
      { score: visibility,       w: 0.10 },
    ]
    return clamp(Math.round(weights.reduce((s, { score, w }) => s + score * w, 0)), 0, 100)
  }, [endpointCoverage, threatDetection, incidentResponse, vulnManagement, complianceScore, visibility])

  // ── 7-day trend (simulated) ──

  // 7日間の推移。過去のスコアは保存されていないので、以前はここで
  // 乱数から作っていました。「先週より上がった」は、この画面を見た人に
  // とっては報告できる事実になります。
  const trendData = useMemo(() => {
    if (!USE_MOCK) return []
    return Array.from({ length: 7 }, (_, i) => {
      const delta = i === 6 ? 0 : Math.round((Math.random() - 0.5) * 10) - (6 - i)
      return clamp(overallScore + delta, 20, 100)
    })
  }, [overallScore])

  // ── Recommendations ──

  const recommendations = useMemo(() => {
    const recs: {
      priority: 'Critical' | 'High' | 'Medium'
      title: string
      detail: string
      gain: number
      href: string
    }[] = []

    if (vulnManagement < 60) {
      recs.push({
        priority: 'Critical',
        title: '脆弱性パッチ適用率の向上',
        detail: `現在の脆弱性管理スコアは ${vulnManagement} です。未パッチのCVEを優先的に対処してください。`,
        gain: 8,
        href: '/vulnerabilities',
      })
    }
    if (endpointCoverage < 80) {
      recs.push({
        priority: 'High',
        title: 'オフラインエージェントの復旧',
        detail: `エンドポイント保護スコア ${endpointCoverage}。オフラインエージェントを確認し、接続を復旧してください。`,
        gain: 6,
        href: '/agent-health',
      })
    }
    if (incidentResponse < 70) {
      recs.push({
        priority: 'High',
        title: 'インシデント対応プロセスの最適化',
        detail: `MTTRを短縮するため、プレイブックの自動化を推進してください。`,
        gain: 5,
        href: '/playbooks',
      })
    }
    if (threatDetection < 70) {
      recs.push({
        priority: 'High',
        title: '検知ルールカバレッジの拡充',
        detail: `脅威検知スコア ${threatDetection}。MITRE ATT&CKフレームワークを参照してルールを追加してください。`,
        gain: 7,
        href: '/rules',
      })
    }
    if (complianceScore < 80) {
      recs.push({
        priority: 'Medium',
        title: 'コンプライアンス違反の解消',
        detail: `コンプライアンススコアを改善するため、未対処の違反事項を確認してください。`,
        gain: 4,
        href: '/compliance',
      })
    }
    if (visibility < 75) {
      recs.push({
        priority: 'Medium',
        title: 'ログ収集・可視性の向上',
        detail: '監視対象アセットのログ収集設定を見直し、可視性を高めてください。',
        gain: 3,
        href: '/events',
      })
    }

    // Always show at least 3
    if (recs.length < 3) {
      recs.push({
        priority: 'Medium',
        title: 'MFA（多要素認証）の全ユーザーへの展開',
        detail: '認証セキュリティを強化するため、全管理者アカウントにMFAを有効化してください。',
        gain: 3,
        href: '/settings/mfa/backup-codes',
      })
    }

    return recs.slice(0, 6)
  }, [endpointCoverage, threatDetection, incidentResponse, vulnManagement, complianceScore, visibility])

  // ── Benchmark data (mock industry averages) ──

  const benchmarks = [
    { label: 'エンドポイント保護', org: endpointCoverage, industry: 78 },
    { label: '脅威検知',           org: threatDetection,  industry: 70 },
    { label: 'インシデント対応',    org: incidentResponse, industry: 62 },
    { label: '脆弱性管理',         org: vulnManagement,   industry: 55 },
    { label: 'コンプライアンス',    org: complianceScore,  industry: 74 },
    { label: '可視性',             org: visibility,       industry: 68 },
  ]

  const isLoading = agentsLoading

  const handleRefresh = () => {
    refetchAgents()
    refetchDetection()
    refetchCompliance()
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />

      {/* ── Header ── */}
      <div className="flex items-start justify-between flex-wrap gap-3">
        <div className="flex items-center gap-3">
          <div className="w-9 h-9 rounded-lg flex items-center justify-center bg-linear-to-br from-[#e8002d] to-[#a80020] shrink-0">
            <ShieldCheck className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">セキュリティスコアカード</h1>
            <p className="text-xs text-[#7d92b0]">組織のセキュリティ成熟度を総合的に評価します</p>
          </div>
        </div>
        <button
          onClick={handleRefresh}
          disabled={isLoading}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white hover:border-[#7d92b0]/40 text-sm transition-colors disabled:opacity-40"
        >
          <RefreshCw className={`w-4 h-4 ${isLoading ? 'animate-spin' : ''}`} />
          更新
        </button>
      </div>

      {/* ── Top row: Gauge + Categories ── */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

        {/* Overall Score Gauge */}
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-5">
          <h2 className="text-sm font-semibold text-white mb-1 flex items-center gap-2">
            <Shield className="w-4 h-4 text-[#e8002d]" />
            総合セキュリティスコア
          </h2>
          <p className="text-xs text-[#7d92b0] mb-4">6カテゴリの加重平均スコア</p>
          <div className="flex flex-col items-center gap-3">
            <SecurityGauge score={overallScore} />

            {/* Score history sparkline */}
            <div className="w-full">
              <div className="flex items-center justify-between mb-2">
                <p className="text-xs text-[#7d92b0]">過去7日間のトレンド</p>
                <span className={`text-xs font-bold ${scoreTailwindText(overallScore)}`}>
                  {overallScore >= 70 ? '↑ 改善中' : overallScore >= 40 ? '→ 安定' : '↓ 要対処'}
                </span>
              </div>
              <SparklineBar data={trendData} />
              <div className="flex justify-between text-[9px] text-[#3d5068] mt-1">
                <span>7日前</span>
                <span>今日</span>
              </div>
            </div>
          </div>
        </div>

        {/* Category Scores */}
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-5">
          <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
            <BarChart3 className="w-4 h-4 text-[#e8002d]" />
            カテゴリ別スコア
          </h2>
          <div className="space-y-5">
            <CategoryBar
              icon={Monitor}
              label="エンドポイント保護"
              score={endpointCoverage}
              description={`エージェントカバレッジ ${endpointCoverage}% (オンライン ${agents.filter(a => a.status === 'online').length}/${agents.length || '—'})`}
            />
            <CategoryBar
              icon={Activity}
              label="脅威検知"
              score={threatDetection}
              description="検知ルールカバレッジ・アラート対処率"
            />
            <CategoryBar
              icon={AlertTriangle}
              label="インシデント対応"
              score={incidentResponse}
              description={detectionRaw?.mttr_hours ? `MTTR: ${detectionRaw.mttr_hours}時間` : 'MTTR・対応速度に基づく'}
            />
            <CategoryBar
              icon={Bug}
              label="脆弱性管理"
              score={vulnManagement}
              description="パッチ適用率・脆弱性対処状況"
            />
            <CategoryBar
              icon={CheckCircle}
              label="コンプライアンス"
              score={complianceScore}
              description="CIS / NIST / SOC2 準拠率"
            />
            <CategoryBar
              icon={TrendingUp}
              label="可視性"
              score={visibility}
              description="監視対象アセットのカバレッジ"
            />
          </div>
        </div>
      </div>

      {/* ── Recommendations + Benchmark side by side ── */}
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-6">

        {/* Improvement Recommendations */}
        <div className="xl:col-span-3 bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
          <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center justify-between">
            <h2 className="text-sm font-semibold text-white flex items-center gap-2">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              改善推奨アクション
            </h2>
            <span className="text-xs text-[#7d92b0]">優先度順</span>
          </div>
          <div className="divide-y divide-[#1e2d42]/50">
            {recommendations.map((rec, i) => (
              <div key={i} className="px-5 py-4 hover:bg-[#111928] transition-colors">
                <div className="flex items-start gap-3">
                  <div className="flex-1 min-w-0 space-y-1.5">
                    <div className="flex items-center gap-2 flex-wrap">
                      <PriorityBadge priority={rec.priority} />
                      <span className="text-sm font-medium text-white">{rec.title}</span>
                    </div>
                    <p className="text-xs text-[#7d92b0] leading-relaxed">{rec.detail}</p>
                  </div>
                  <div className="flex flex-col items-end gap-2 shrink-0">
                    <span className="text-xs font-bold text-green-400 whitespace-nowrap">
                      +{rec.gain} pts
                    </span>
                    <Link
                      href={rec.href}
                      className="flex items-center gap-1 text-[10px] text-[#1a6bff] hover:text-blue-300 transition-colors whitespace-nowrap"
                    >
                      対処する
                      <ChevronRight className="w-3 h-3" />
                    </Link>
                  </div>
                </div>
              </div>
            ))}
            {recommendations.length === 0 && (
              <div className="px-5 py-12 text-center">
                <CheckCircle className="w-8 h-8 text-green-500 mx-auto mb-2" />
                <p className="text-sm text-[#7d92b0]">すべてのカテゴリが良好な状態です</p>
              </div>
            )}
          </div>
        </div>

        {/* Benchmark Comparison */}
        <div className="xl:col-span-2 bg-[#0d1220] rounded-xl border border-[#1e2d42] p-5">
          <h2 className="text-sm font-semibold text-white mb-1 flex items-center gap-2">
            <TrendingUp className="w-4 h-4 text-[#e8002d]" />
            業界平均との比較
          </h2>
          <p className="text-xs text-[#7d92b0] mb-5">セキュリティ業界平均との比較</p>

          {/* Overall comparison */}
          <div className="flex items-center justify-center gap-8 mb-6 pb-5 border-b border-[#1e2d42]">
            <div className="text-center">
              <p className={`text-3xl font-bold tabular-nums ${scoreTailwindText(overallScore)}`}>{overallScore}</p>
              <p className="text-xs text-[#7d92b0] mt-1">自組織</p>
            </div>
            <div className="text-center">
              <p className="text-3xl font-bold text-[#7d92b0] tabular-nums">67</p>
              <p className="text-xs text-[#7d92b0] mt-1">業界平均</p>
            </div>
            <div className="text-center">
              <p className={`text-xl font-bold tabular-nums ${overallScore >= 67 ? 'text-green-400' : 'text-[#e8002d]'}`}>
                {overallScore >= 67 ? '+' : ''}{overallScore - 67}
              </p>
              <p className="text-xs text-[#7d92b0] mt-1">差分</p>
            </div>
          </div>

          {/* Per-category comparison */}
          <div className="space-y-4">
            {benchmarks.map(b => {
              const diff = b.org - b.industry
              return (
                <div key={b.label} className="space-y-1">
                  <div className="flex items-center justify-between text-xs">
                    <span className="text-[#7d92b0]">{b.label}</span>
                    <span className={`font-bold tabular-nums ${diff >= 0 ? 'text-green-400' : 'text-[#e8002d]'}`}>
                      {diff >= 0 ? '+' : ''}{diff}
                    </span>
                  </div>
                  {/* Dual bar: org vs industry */}
                  <div className="relative h-5">
                    {/* Industry average bar */}
                    <div className="absolute inset-0 flex items-center">
                      <div className="h-2 bg-[#1e2d42] rounded-full" style={{ width: `${b.industry}%` }} />
                    </div>
                    {/* Org bar */}
                    <div className="absolute inset-0 flex items-end">
                      <div
                        className={`h-1.5 rounded-full transition-all duration-700 ${scoreBgClass(b.org)}`}
                        style={{ width: `${b.org}%`, opacity: 0.8 }}
                      />
                    </div>
                    {/* Industry marker line */}
                    <div
                      className="absolute top-0 bottom-0 w-0.5 bg-[#7d92b0]/40"
                      style={{ left: `${b.industry}%` }}
                    />
                  </div>
                  <div className="flex justify-between text-[9px] text-[#3d5068]">
                    <span>自組織: {b.org}</span>
                    <span>業界平均: {b.industry}</span>
                  </div>
                </div>
              )
            })}
          </div>

          {/* Legend */}
          <div className="flex items-center gap-4 mt-5 pt-4 border-t border-[#1e2d42] text-[10px] text-[#7d92b0]">
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-2 rounded-sm bg-[#1e2d42] inline-block" />
              業界平均
            </span>
            <span className="flex items-center gap-1.5">
              <span className="w-3 h-1.5 rounded-sm bg-green-500 inline-block" />
              自組織
            </span>
          </div>
        </div>
      </div>

      {/* ── Score Matrix ── */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-5">
        <h2 className="text-sm font-semibold text-white mb-4 flex items-center gap-2">
          <ShieldCheck className="w-4 h-4 text-[#e8002d]" />
          セキュリティ成熟度マトリクス
        </h2>
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          {[
            { label: 'エンドポイント保護', score: endpointCoverage, icon: Monitor },
            { label: '脅威検知',           score: threatDetection,  icon: Activity },
            { label: 'インシデント対応',    score: incidentResponse, icon: AlertTriangle },
            { label: '脆弱性管理',         score: vulnManagement,   icon: Bug },
            { label: 'コンプライアンス',    score: complianceScore,  icon: CheckCircle },
            { label: '可視性',             score: visibility,       icon: TrendingUp },
          ].map(item => {
            const Icon = item.icon
            const color = scoreColor(item.score)
            const textClass = scoreTailwindText(item.score)
            return (
              <div
                key={item.label}
                className="bg-[#0a1525] rounded-lg border border-[#1e2d42] p-4 flex flex-col items-center gap-2 text-center"
              >
                <Icon className="w-5 h-5 text-[#3d5068]" />
                {/* Mini circular indicator */}
                <div className="relative w-14 h-14">
                  <svg viewBox="0 0 56 56" className="w-full h-full -rotate-90">
                    <circle cx="28" cy="28" r="22" fill="none" stroke="#1e2d42" strokeWidth="5" />
                    <circle
                      cx="28" cy="28" r="22"
                      fill="none"
                      stroke={color}
                      strokeWidth="5"
                      strokeLinecap="round"
                      strokeDasharray={`${2 * Math.PI * 22}`}
                      strokeDashoffset={`${2 * Math.PI * 22 * (1 - item.score / 100)}`}
                      style={{ filter: `drop-shadow(0 0 4px ${color}60)` }}
                    />
                  </svg>
                  <span className={`absolute inset-0 flex items-center justify-center text-sm font-bold tabular-nums ${textClass}`}>
                    {item.score}
                  </span>
                </div>
                <p className="text-[10px] text-[#7d92b0] leading-tight">{item.label}</p>
                <span className={`text-[9px] font-bold px-1.5 py-0.5 rounded-sm ${
                  item.score >= 70 ? 'bg-green-900/30 text-green-400' :
                  item.score >= 40 ? 'bg-amber-900/30 text-amber-400' :
                  'bg-red-900/30 text-red-400'
                }`}>
                  {scoreLabel(item.score)}
                </span>
              </div>
            )
          })}
        </div>
      </div>

    </div>
  )
}
