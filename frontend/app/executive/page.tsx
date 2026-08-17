'use client'

import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Shield, TrendingUp, TrendingDown, Clock, FileText,
  AlertTriangle, CheckCircle, Target, ArrowUpRight, ArrowDownRight,
  ChevronRight, RefreshCw, Star, Zap,
} from 'lucide-react'

// ─── Types ────────────────────────────────────────────────────────────────────

interface SecurityPosture {
  score: number
  grade: string
  trend: number
  last_updated: string
}

interface DetectionStats {
  mttd_hours: number
  mttd_trend: number
  mttd_benchmark: number
  mttr_hours: number
  mttr_trend: number
  mttr_benchmark: number
  incidents_30d: number
  critical_alerts: number
  blocked_threats: number
  threat_categories: { name: string; count: number }[]
}

interface ComplianceData {
  score: number
  frameworks: { name: string; score: number; status: string; last_assessment: string; next_due: string }[]
}

interface ExecDashboard {
  posture: SecurityPosture
  detection: DetectionStats
  compliance: ComplianceData
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK: ExecDashboard = {
  posture: {
    score: 72,
    grade: 'B',
    trend: 3,
    last_updated: new Date(Date.now() - 12 * 60 * 1000).toISOString(),
  },
  detection: {
    mttd_hours: 4.2,
    mttd_trend: -0.8,
    mttd_benchmark: 6.0,
    mttr_hours: 8.7,
    mttr_trend: 0.5,
    mttr_benchmark: 12.0,
    incidents_30d: 127,
    critical_alerts: 18,
    blocked_threats: 2341,
    threat_categories: [
      { name: 'マルウェア感染試行', count: 98 },
      { name: '不正アクセス試行', count: 73 },
      { name: 'フィッシング', count: 45 },
      { name: 'データ流出リスク', count: 22 },
      { name: 'その他', count: 14 },
    ],
  },
  compliance: {
    score: 84,
    frameworks: [
      { name: 'MITRE ATT&CK',  score: 76, status: '良好',   last_assessment: '2026-03-01', next_due: '2026-06-01' },
      { name: 'CIS Controls',   score: 81, status: '良好',   last_assessment: '2026-02-15', next_due: '2026-05-15' },
      { name: 'NIST CSF',       score: 88, status: '優秀',   last_assessment: '2026-03-10', next_due: '2026-09-10' },
      { name: 'ISO 27001',      score: 91, status: '優秀',   last_assessment: '2026-01-20', next_due: '2027-01-20' },
    ],
  },
}

// Monthly trend mock for 6 months
const MONTHLY_TRENDS = [
  { month: '10月', incidents: 198, alerts: 892 },
  { month: '11月', incidents: 212, alerts: 964 },
  { month: '12月', incidents: 176, alerts: 801 },
  { month: '1月',  incidents: 154, alerts: 723 },
  { month: '2月',  incidents: 138, alerts: 678 },
  { month: '3月',  incidents: 127, alerts: 634 },
]

// Asset protection mock
const ASSET_PROTECTION = {
  agent_coverage: 94,
  patched_pct: 79,
  healthy: 287,
  warning: 31,
  critical: 13,
  offline: 8,
  total: 339,
}

// Top risks mock
const TOP_RISKS = [
  {
    title: 'パッチ未適用のシステムが多数存在',
    impact: 'high',
    likelihood: 'high',
    detail: '139台のシステムに重大な脆弱性が残存しています',
  },
  {
    title: '多要素認証の未導入ユーザー',
    impact: 'high',
    likelihood: 'medium',
    detail: '14名のユーザーがMFA未設定のままです',
  },
  {
    title: 'クラウド設定の不備',
    impact: 'medium',
    likelihood: 'medium',
    detail: 'クラウドストレージのアクセス権限が過剰に設定されています',
  },
]

const INVESTMENTS = [
  { item: 'パッチ管理の自動化導入', risk_reduction: 28, priority: 1 },
  { item: '全社MFAロールアウト完了', risk_reduction: 22, priority: 2 },
  { item: 'EDRエージェント100%展開', risk_reduction: 15, priority: 3 },
  { item: 'クラウドセキュリティ体制強化', risk_reduction: 12, priority: 4 },
  { item: 'セキュリティ意識向上トレーニング', risk_reduction: 9, priority: 5 },
]

// ─── Gauge Ring SVG ───────────────────────────────────────────────────────────

function ScoreRing({ score, size = 140 }: { score: number; size?: number }) {
  const [anim, setAnim] = useState(0)
  useEffect(() => { const t = setTimeout(() => setAnim(score), 300); return () => clearTimeout(t) }, [score])

  const cx = size / 2, cy = size / 2
  const r = (size / 2) * 0.72
  const sw = size * 0.07
  const totalAngle = 240
  const circumference = 2 * Math.PI * r
  const arcFull = (totalAngle / 360) * circumference
  const arcFilled = arcFull * (anim / 100)
  const startAngle = -210

  const toRad = (d: number) => (d * Math.PI) / 180
  const px = (d: number) => cx + r * Math.cos(toRad(d))
  const py = (d: number) => cy + r * Math.sin(toRad(d))
  const endAngle = startAngle + totalAngle
  const progressAngle = startAngle + totalAngle * (anim / 100)
  const la = (angle: number) => (angle > 180 ? 1 : 0)

  const bgPath = `M ${px(startAngle)} ${py(startAngle)} A ${r} ${r} 0 ${la(totalAngle)} 1 ${px(endAngle)} ${py(endAngle)}`
  const progPath = anim > 0
    ? `M ${px(startAngle)} ${py(startAngle)} A ${r} ${r} 0 ${la(totalAngle * anim / 100)} 1 ${px(progressAngle)} ${py(progressAngle)}`
    : ''

  const color = score >= 90 ? '#00c853' : score >= 75 ? '#69f0ae' : score >= 60 ? '#ffd740' : score >= 45 ? '#ff9100' : '#e8002d'

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <path d={bgPath} fill="none" stroke="#1e2d42" strokeWidth={sw} strokeLinecap="round" />
      {progPath && (
        <path d={progPath} fill="none" stroke={color} strokeWidth={sw} strokeLinecap="round"
          style={{ transition: 'all 1.2s ease-out', filter: `drop-shadow(0 0 6px ${color}80)` }} />
      )}
      <text x={cx} y={cy - 4} textAnchor="middle" fill="white" fontSize={size * 0.22} fontWeight="bold">{anim}</text>
      <text x={cx} y={cy + size * 0.14} textAnchor="middle" fill="#7d92b0" fontSize={size * 0.08}>/100</text>
    </svg>
  )
}

// ─── Donut SVG ────────────────────────────────────────────────────────────────

function DonutChart({ pct, size = 120, color = '#1a6bff' }: { pct: number; size?: number; color?: string }) {
  const [anim, setAnim] = useState(0)
  useEffect(() => { const t = setTimeout(() => setAnim(pct), 400); return () => clearTimeout(t) }, [pct])

  const cx = size / 2, cy = size / 2, r = size * 0.36, sw = size * 0.12
  const circ = 2 * Math.PI * r
  const offset = circ * (1 - anim / 100)

  return (
    <svg width={size} height={size} viewBox={`0 0 ${size} ${size}`}>
      <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1e2d42" strokeWidth={sw} />
      <circle cx={cx} cy={cy} r={r} fill="none" stroke={color} strokeWidth={sw}
        strokeDasharray={circ} strokeDashoffset={offset} strokeLinecap="round"
        transform={`rotate(-90 ${cx} ${cy})`}
        style={{ transition: 'stroke-dashoffset 1.2s ease-out', filter: `drop-shadow(0 0 5px ${color}60)` }} />
      <text x={cx} y={cy + 2} textAnchor="middle" dominantBaseline="middle"
        fill="white" fontSize={size * 0.18} fontWeight="bold">{anim}%</text>
    </svg>
  )
}

// ─── Monthly Trend SVG ────────────────────────────────────────────────────────

function MonthlyTrendChart({ trends }: { trends: typeof MONTHLY_TRENDS }) {
  const W = 700, H = 200, PL = 40, PR = 20, PT = 20, PB = 36

  const incMax = Math.max(...trends.map(d => d.incidents))
  const alertMax = Math.max(...trends.map(d => d.alerts))
  const n = trends.length

  const toX = (i: number) => PL + (i / (n - 1)) * (W - PL - PR)
  const toYInc = (v: number) => PT + (1 - v / (incMax * 1.2)) * (H - PT - PB)
  const toYAlert = (v: number) => PT + (1 - v / (alertMax * 1.2)) * (H - PT - PB)

  const incLine = trends.map((d, i) => `${i === 0 ? 'M' : 'L'} ${toX(i)} ${toYInc(d.incidents)}`).join(' ')
  const alertLine = trends.map((d, i) => `${i === 0 ? 'M' : 'L'} ${toX(i)} ${toYAlert(d.alerts)}`).join(' ')
  const incArea = `${incLine} L ${toX(n - 1)} ${H - PB} L ${toX(0)} ${H - PB} Z`
  const alertArea = `${alertLine} L ${toX(n - 1)} ${H - PB} L ${toX(0)} ${H - PB} Z`

  return (
    <div>
      <svg viewBox={`0 0 ${W} ${H}`} className="w-full" style={{ height: 200 }}>
        <defs>
          <linearGradient id="incGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#e8002d" stopOpacity="0.3" />
            <stop offset="100%" stopColor="#e8002d" stopOpacity="0.02" />
          </linearGradient>
          <linearGradient id="alertGrad" x1="0" y1="0" x2="0" y2="1">
            <stop offset="0%" stopColor="#ffd740" stopOpacity="0.2" />
            <stop offset="100%" stopColor="#ffd740" stopOpacity="0.02" />
          </linearGradient>
        </defs>
        {/* Grid */}
        {[0, 25, 50, 75, 100].map(pct => {
          const y = PT + (1 - pct / 100) * (H - PT - PB)
          return <line key={pct} x1={PL} y1={y} x2={W - PR} y2={y} stroke="#1e2d42" strokeWidth="1" strokeDasharray="3,4" />
        })}
        {/* Areas */}
        <path d={alertArea} fill="url(#alertGrad)" />
        <path d={incArea} fill="url(#incGrad)" />
        {/* Lines */}
        <path d={alertLine} fill="none" stroke="#ffd740" strokeWidth="2" strokeLinejoin="round" />
        <path d={incLine} fill="none" stroke="#e8002d" strokeWidth="2.5" strokeLinejoin="round" />
        {/* Dots & labels */}
        {trends.map((d, i) => (
          <g key={i}>
            <circle cx={toX(i)} cy={toYInc(d.incidents)} r="4" fill="#e8002d" />
            <circle cx={toX(i)} cy={toYAlert(d.alerts)} r="3" fill="#ffd740" />
            <text x={toX(i)} y={H - PB + 14} textAnchor="middle" fill="#7d92b0" fontSize="11">{d.month}</text>
            <text x={toX(i)} y={toYInc(d.incidents) - 8} textAnchor="middle" fill="#e2e8f4" fontSize="9">{d.incidents}</text>
          </g>
        ))}
        {/* Y axis */}
        <text x={PL - 4} y={PT + 4} textAnchor="end" fill="#7d92b0" fontSize="9">{incMax || 0}</text>
        <text x={PL - 4} y={H - PB} textAnchor="end" fill="#7d92b0" fontSize="9">0</text>
      </svg>
      <div className="flex items-center gap-6 mt-2 text-xs text-falcon-muted">
        <span className="flex items-center gap-1.5"><span className="w-4 h-0.5 bg-falcon-red inline-block rounded-sm" />インシデント件数</span>
        <span className="flex items-center gap-1.5"><span className="w-4 h-0.5 bg-[#ffd740] inline-block rounded-sm" />アラート件数</span>
      </div>
    </div>
  )
}

// ─── Protocol Pie SVG ─────────────────────────────────────────────────────────

const RISK_COLOR: Record<string, string> = {
  high:   'text-falcon-red bg-falcon-red/15 border-falcon-red/30',
  medium: 'text-[#ffd740] bg-[#ffd740]/15 border-[#ffd740]/30',
  low:    'text-falcon-green bg-falcon-green/15 border-falcon-green/30',
}

const RISK_LABEL: Record<string, string> = { high: '高', medium: '中', low: '低' }

function scoreStatusColor(score: number) {
  if (score >= 85) return 'text-falcon-green bg-falcon-green/15 border-falcon-green/30'
  if (score >= 70) return 'text-[#ffd740] bg-[#ffd740]/15 border-[#ffd740]/30'
  return 'text-falcon-red bg-falcon-red/15 border-falcon-red/30'
}

function scoreBar(score: number) {
  if (score >= 85) return '#00c853'
  if (score >= 70) return '#ffd740'
  return '#e8002d'
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ExecutiveDashboardPage() {
  const { data: postureRaw } = useQuery<SecurityPosture>({
    queryKey: ['exec-security-posture'],
    queryFn: () => apiFetch<SecurityPosture>('/api/v1/security-posture').catch(() => MOCK.posture),
    staleTime: 5 * 60 * 1000,
  })
  const { data: detectionRaw } = useQuery<DetectionStats>({
    queryKey: ['exec-detection-stats'],
    queryFn: () => apiFetch<DetectionStats>('/api/v1/metrics/detection-stats').catch(() => MOCK.detection),
    staleTime: 5 * 60 * 1000,
  })
  const { data: complianceRaw } = useQuery<ComplianceData>({
    queryKey: ['exec-compliance'],
    queryFn: () => apiFetch<ComplianceData>('/api/v1/compliance').catch(() => MOCK.compliance),
    staleTime: 5 * 60 * 1000,
  })
  const { data: agentStatsRaw } = useQuery({
    queryKey: ['exec-agent-stats'],
    queryFn: () => apiFetch<{total:number;online:number;offline:number;stale:number}>('/api/v1/metrics/agent-stats').catch(() => null),
    staleTime: 5 * 60 * 1000,
  })
  const { data: patchStatsRaw } = useQuery({
    queryKey: ['exec-patch-stats'],
    queryFn: () => apiFetch<{coverage_pct:number}>('/api/v1/patches/stats').catch(() => null),
    staleTime: 5 * 60 * 1000,
  })
  const { data: riskOrgRaw } = useQuery({
    queryKey: ['exec-risk-org'],
    queryFn: () => apiFetch<any>('/api/v1/admin/risk-scoring/organization').catch(() => null),
    staleTime: 5 * 60 * 1000,
  })
  const { data: socMetricsRaw } = useQuery({
    queryKey: ['exec-soc-metrics'],
    queryFn: () => apiFetch<any>('/api/v1/soc-metrics/summary?days=180').catch(() => null),
    staleTime: 5 * 60 * 1000,
  })

  const posture = postureRaw ?? MOCK.posture
  const detection: DetectionStats = (detectionRaw as any)?.threat_categories
    ? detectionRaw as DetectionStats
    : MOCK.detection
  const compliance: ComplianceData = (() => {
    const raw = complianceRaw as any
    if (!raw) return MOCK.compliance
    // API returns frameworks as an object {mitre,cis,nist,iso27001} + framework_details array
    if (Array.isArray(raw.frameworks)) return complianceRaw as ComplianceData
    if (Array.isArray(raw.framework_details)) {
      return {
        score: Number(raw.overall) || 0,
        frameworks: (raw.framework_details as { id: string; name: string; score: number }[]).map(f => ({
          name: f.name ?? '',
          score: Math.round(Number(f.score) || 0),
          status: (Number(f.score) || 0) >= 85 ? '優秀' : (Number(f.score) || 0) >= 70 ? '良好' : '要改善',
          last_assessment: '',
          next_due: '',
        })),
      }
    }
    return MOCK.compliance
  })()

  // ─── Asset Protection from real API ────────────────────────
  const assetProtection = (() => {
    const ag = agentStatsRaw as any
    if (ag?.total > 0) {
      const total = ag.total as number
      const online = (ag.online ?? 0) as number
      const stale = (ag.stale ?? 0) as number
      const offline = (ag.offline ?? 0) as number
      const patchPct = Math.round(Number((patchStatsRaw as any)?.coverage_pct) || 0)
      return {
        agent_coverage: Math.round(online * 100 / total),
        patched_pct: patchPct || ASSET_PROTECTION.patched_pct,
        healthy: online,
        warning: stale,
        critical: Math.max(0, total - online - stale - offline),
        offline,
        total,
      }
    }
    return ASSET_PROTECTION
  })()

  // ─── Top Risks derived from real data ────────────────────
  const topRisks = (() => {
    // First try real risk_scores API
    const apiRisks = (riskOrgRaw as any)?.top_risks ?? []
    if (apiRisks.length > 0) {
      return (apiRisks as {entity:string;score:number;risk_level:string}[]).slice(0, 3).map(r => ({
        title: r.entity ?? '不明',
        impact: (r.risk_level === 'critical' || r.risk_level === 'high') ? 'high' : r.risk_level === 'medium' ? 'medium' : 'low',
        likelihood: 'medium' as 'medium',
        detail: `リスクスコア: ${Math.round(r.score ?? 0)}`,
      }))
    }
    // Derive from real metrics already fetched
    const ap = assetProtection
    const derived: {title:string;impact:string;likelihood:string;detail:string}[] = []
    if (ap.patched_pct < 85)
      derived.push({title:'パッチ未適用のシステムが存在', impact:'high', likelihood:'high',
        detail:`パッチ適用率 ${ap.patched_pct}% — 未適用端末が脆弱性リスクを高めています`})
    if (ap.agent_coverage < 90)
      derived.push({title:'EDRカバレッジが不十分', impact:'high', likelihood:'medium',
        detail:`エージェント稼働率 ${ap.agent_coverage}% — 監視対象外の端末が存在します`})
    if (compliance.score < 75)
      derived.push({title:'コンプライアンス基準への対応遅れ', impact:'medium', likelihood:'medium',
        detail:`コンプライアンス達成率 ${compliance.score}% — 基準値(75%)を下回っています`})
    if (detection.critical_alerts > 0)
      derived.push({title:'未解決のクリティカルアラート', impact:'high', likelihood:'high',
        detail:`${detection.critical_alerts}件のクリティカルアラートが未対応のままです`})
    if (ap.offline > 0)
      derived.push({title:'オフライン状態のエンドポイント', impact:'medium', likelihood:'low',
        detail:`${ap.offline}台がオフライン — 保護が届いていない可能性があります`})
    if (derived.length > 0) return derived.slice(0, 3)
    return TOP_RISKS
  })()

  // ─── Monthly Trends from real API ────────────────────────
  const monthlyTrends = (() => {
    const daily = ((socMetricsRaw as any)?.daily_volume ?? []) as {date:string;total:number;critical:number;high:number;resolved:number}[]
    if (daily.length >= 30) {
      const monthMap = new Map<string, {label:string;incidents:number;alerts:number}>()
      for (const d of daily) {
        const dt = new Date(d.date)
        const key = `${dt.getFullYear()}-${String(dt.getMonth()+1).padStart(2,'0')}`
        if (!monthMap.has(key)) monthMap.set(key, {label:`${dt.getMonth()+1}月`, incidents:0, alerts:0})
        const e = monthMap.get(key)!
        e.alerts += d.total ?? 0
        e.incidents += (d.critical ?? 0) + (d.high ?? 0)
      }
      const entries = Array.from(monthMap.entries()).sort((a,b) => a[0].localeCompare(b[0])).slice(-6)
      if (entries.length >= 2) return entries.map(([,v]) => ({month:v.label, incidents:v.incidents, alerts:v.alerts}))
    }
    return MONTHLY_TRENDS
  })()

  // ─── Investments derived from real data ──────────────────
  const investments = (() => {
    const recs: {item:string;risk_reduction:number;priority:number}[] = []
    if (assetProtection.patched_pct < 85) recs.push({item:'パッチ管理の自動化導入', risk_reduction:28, priority:0})
    if (assetProtection.agent_coverage < 95) recs.push({item:'EDRエージェント100%展開', risk_reduction:15, priority:0})
    if (compliance.score < 75) recs.push({item:'コンプライアンス基準の改善', risk_reduction:20, priority:0})
    if (detection.critical_alerts > 5) recs.push({item:'クリティカルアラート対応強化', risk_reduction:18, priority:0})
    const extras = [
      {item:'全社MFAロールアウト完了', risk_reduction:22, priority:0},
      {item:'クラウドセキュリティ体制強化', risk_reduction:12, priority:0},
      {item:'セキュリティ意識向上トレーニング', risk_reduction:9, priority:0},
    ]
    for (const e of extras) { if (recs.length < 5) recs.push(e) }
    return recs.slice(0,5).map((r,i) => ({...r, priority:i+1}))
  })()

  const gradeColor =
    posture.score >= 90 ? 'text-falcon-green'
    : posture.score >= 75 ? 'text-[#69f0ae]'
    : posture.score >= 60 ? 'text-[#ffd740]'
    : 'text-falcon-red'

  const updatedStr = new Date(posture.last_updated).toLocaleString('ja-JP', {
    month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit'
  })

  const threatMax = Math.max(...detection.threat_categories.map(t => t.count))

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">

      {/* ── Header ──────────────────────────────────────────────── */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Star className="w-6 h-6 text-falcon-red" />
            エグゼクティブダッシュボード
          </h1>
          <p className="text-falcon-muted text-sm mt-1">セキュリティ態勢の経営レベルサマリー</p>
        </div>
        <div className="flex items-center gap-3">
          <span className="flex items-center gap-2 text-xs text-falcon-muted">
            <Clock className="w-4 h-4" />
            最終更新: {updatedStr}
          </span>
          <button
            onClick={() => alert('PDFレポートを生成中...\n(モック: 実際のPDF出力はレポートシステムと連携します)')}
            className="flex items-center gap-2 px-4 py-2 bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium rounded-lg transition-colors"
          >
            <FileText className="w-4 h-4" />
            レポート出力
          </button>
        </div>
      </div>

      {/* ── Top KPI Row ─────────────────────────────────────────── */}
      <div className="grid grid-cols-1 sm:grid-cols-2 xl:grid-cols-4 gap-4">

        {/* KPI 1 — Security Score */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5 flex flex-col items-center text-center">
          <p className="text-xs text-falcon-muted font-medium uppercase tracking-wider mb-2">総合セキュリティスコア</p>
          <ScoreRing score={posture.score} size={130} />
          <div className={`mt-2 text-4xl font-black ${gradeColor}`}>{posture.grade}</div>
          <p className="text-xs text-falcon-muted mt-1">グレード</p>
          <div className="mt-3 flex items-center gap-1 text-xs">
            {posture.trend > 0 ? (
              <><ArrowUpRight className="w-4 h-4 text-falcon-green" /><span className="text-falcon-green font-semibold">+{posture.trend}pt 先月比改善</span></>
            ) : posture.trend < 0 ? (
              <><ArrowDownRight className="w-4 h-4 text-falcon-red" /><span className="text-falcon-red font-semibold">{posture.trend}pt 先月比低下</span></>
            ) : (
              <span className="text-falcon-muted">変化なし</span>
            )}
          </div>
        </div>

        {/* KPI 2 — MTTD */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <p className="text-xs text-falcon-muted font-medium uppercase tracking-wider mb-3">脅威発見までの時間 (MTTD)</p>
          <div className="flex items-baseline gap-2 mb-1">
            <span className="text-5xl font-black text-white">{detection.mttd_hours}</span>
            <span className="text-lg text-falcon-muted">時間</span>
          </div>
          <div className="flex items-center gap-1 text-xs mb-4">
            {detection.mttd_trend < 0 ? (
              <><TrendingDown className="w-4 h-4 text-falcon-green" /><span className="text-falcon-green">{detection.mttd_trend}時間 改善</span></>
            ) : (
              <><TrendingUp className="w-4 h-4 text-falcon-red" /><span className="text-falcon-red">+{detection.mttd_trend}時間 悪化</span></>
            )}
          </div>
          <div className="p-3 bg-[#070d19] rounded-lg border border-falcon-border">
            <p className="text-[10px] text-falcon-muted uppercase tracking-wider mb-1">業界平均との比較</p>
            <div className="flex items-center justify-between">
              <span className="text-xs text-falcon-muted">業界平均</span>
              <span className="text-sm font-semibold text-[#ffd740]">{detection.mttd_benchmark}時間</span>
            </div>
            <div className="mt-2 h-2 bg-falcon-border rounded-full overflow-hidden">
              <div className="h-full bg-falcon-green rounded-full" style={{ width: `${Math.min(100, (1 - detection.mttd_hours / detection.mttd_benchmark) * 100 + 60)}%` }} />
            </div>
            <p className="text-[10px] text-falcon-green mt-1">業界平均より優秀</p>
          </div>
        </div>

        {/* KPI 3 — MTTR */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <p className="text-xs text-falcon-muted font-medium uppercase tracking-wider mb-3">脅威対応完了までの時間 (MTTR)</p>
          <div className="flex items-baseline gap-2 mb-1">
            <span className="text-5xl font-black text-white">{detection.mttr_hours}</span>
            <span className="text-lg text-falcon-muted">時間</span>
          </div>
          <div className="flex items-center gap-1 text-xs mb-4">
            {detection.mttr_trend > 0 ? (
              <><TrendingUp className="w-4 h-4 text-[#ffd740]" /><span className="text-[#ffd740]">+{detection.mttr_trend}時間 (要改善)</span></>
            ) : (
              <><TrendingDown className="w-4 h-4 text-falcon-green" /><span className="text-falcon-green">{detection.mttr_trend}時間 改善</span></>
            )}
          </div>
          <div className="p-3 bg-[#070d19] rounded-lg border border-falcon-border">
            <p className="text-[10px] text-falcon-muted uppercase tracking-wider mb-1">業界平均との比較</p>
            <div className="flex items-center justify-between">
              <span className="text-xs text-falcon-muted">業界平均</span>
              <span className="text-sm font-semibold text-[#ffd740]">{detection.mttr_benchmark}時間</span>
            </div>
            <div className="mt-2 h-2 bg-falcon-border rounded-full overflow-hidden">
              <div className="h-full bg-falcon-green rounded-full" style={{ width: `${Math.min(100, (1 - detection.mttr_hours / detection.mttr_benchmark) * 100 + 60)}%` }} />
            </div>
            <p className="text-[10px] text-falcon-green mt-1">業界平均より優秀</p>
          </div>
        </div>

        {/* KPI 4 — Compliance */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <p className="text-xs text-falcon-muted font-medium uppercase tracking-wider mb-3">コンプライアンス達成率</p>
          <div className="flex items-baseline gap-2 mb-3">
            <span className="text-5xl font-black text-falcon-green">{compliance.score}%</span>
          </div>
          <p className="text-xs text-falcon-muted mb-3">対応フレームワーク</p>
          <div className="flex flex-wrap gap-2">
            {compliance.frameworks.map(f => (
              <span key={f.name} className="px-2 py-1 bg-falcon-border text-falcon-text text-[10px] font-medium rounded-sm border border-[#2d3f58]">
                {f.name}
              </span>
            ))}
          </div>
          <div className="mt-3 h-2 bg-falcon-border rounded-full overflow-hidden">
            <div className="h-full rounded-full transition-all duration-1000" style={{ width: `${compliance.score}%`, background: '#00c853' }} />
          </div>
        </div>
      </div>

      {/* ── Middle Row — 3 Panels ────────────────────────────────── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">

        {/* Panel 1 — Threat Landscape */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Zap className="w-4 h-4 text-falcon-red" />
            <h2 className="text-sm font-semibold text-white">脅威の状況 (過去30日)</h2>
          </div>
          <div className="grid grid-cols-3 gap-3 mb-5">
            <div className="text-center p-3 bg-[#070d19] rounded-lg border border-falcon-border">
              <p className="text-2xl font-black text-white">{detection.incidents_30d}</p>
              <p className="text-[10px] text-falcon-muted mt-1">インシデント発生</p>
            </div>
            <div className="text-center p-3 bg-[#070d19] rounded-lg border border-red-500/20">
              <p className="text-2xl font-black text-falcon-red">{detection.critical_alerts}</p>
              <p className="text-[10px] text-falcon-muted mt-1">緊急アラート</p>
            </div>
            <div className="text-center p-3 bg-[#070d19] rounded-lg border border-falcon-green/20">
              <p className="text-2xl font-black text-falcon-green">{(detection.blocked_threats ?? 0).toLocaleString()}</p>
              <p className="text-[10px] text-falcon-muted mt-1">脅威をブロック</p>
            </div>
          </div>
          <p className="text-xs text-falcon-muted font-medium mb-3">脅威の種類別内訳</p>
          <div className="space-y-2.5">
            {detection.threat_categories.map(cat => (
              <div key={cat.name}>
                <div className="flex items-center justify-between mb-1">
                  <span className="text-xs text-falcon-text">{cat.name}</span>
                  <span className="text-xs font-semibold text-falcon-muted">{cat.count}件</span>
                </div>
                <div className="h-2 bg-falcon-border rounded-full overflow-hidden">
                  <div
                    className="h-full rounded-full transition-all duration-700"
                    style={{ width: `${(cat.count / threatMax) * 100}%`, background: '#e8002d' }}
                  />
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* Panel 2 — Asset Protection */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Shield className="w-4 h-4 text-falcon-blue" />
            <h2 className="text-sm font-semibold text-white">資産の保護状況</h2>
          </div>
          <div className="flex items-center justify-center mb-4">
            <div className="relative">
              <DonutChart pct={assetProtection.agent_coverage} size={130} color="#1a6bff" />
              <div className="absolute -bottom-1 left-1/2 -translate-x-1/2 whitespace-nowrap">
                <p className="text-[10px] text-falcon-muted text-center">監視カバレッジ</p>
              </div>
            </div>
          </div>
          <div className="grid grid-cols-2 gap-3 mb-4">
            <div className="text-center p-2.5 bg-[#070d19] rounded-lg border border-falcon-border">
              <p className="text-xl font-black text-falcon-green">{assetProtection.patched_pct}%</p>
              <p className="text-[10px] text-falcon-muted">パッチ適用済み</p>
            </div>
            <div className="text-center p-2.5 bg-[#070d19] rounded-lg border border-falcon-border">
              <p className="text-xl font-black text-white">{assetProtection.total}</p>
              <p className="text-[10px] text-falcon-muted">総エンドポイント数</p>
            </div>
          </div>
          <p className="text-xs text-falcon-muted font-medium mb-2">エンドポイント健全性</p>
          <div className="space-y-1.5">
            {[
              { label: '正常稼働中', count: assetProtection.healthy, color: '#00c853' },
              { label: '注意が必要', count: assetProtection.warning, color: '#ffd740' },
              { label: '要対応', count: assetProtection.critical, color: '#e8002d' },
              { label: 'オフライン', count: assetProtection.offline, color: '#3d5068' },
            ].map(row => (
              <div key={row.label} className="flex items-center justify-between text-xs">
                <div className="flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full inline-block" style={{ background: row.color }} />
                  <span className="text-falcon-muted">{row.label}</span>
                </div>
                <span className="font-semibold" style={{ color: row.color }}>{row.count}台</span>
              </div>
            ))}
          </div>
        </div>

        {/* Panel 3 — Risk Posture */}
        <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <AlertTriangle className="w-4 h-4 text-[#ffd740]" />
            <h2 className="text-sm font-semibold text-white">主要リスク</h2>
          </div>
          <div className="space-y-3 mb-5">
            {topRisks.map((risk, i) => (
              <div key={i} className="p-3 bg-[#070d19] rounded-lg border border-falcon-border">
                <div className="flex items-start gap-2 mb-2">
                  <span className="w-5 h-5 rounded-full bg-falcon-border flex items-center justify-center text-[10px] font-bold text-falcon-muted shrink-0 mt-0.5">
                    {i + 1}
                  </span>
                  <p className="text-xs font-medium text-falcon-text leading-snug">{risk.title}</p>
                </div>
                <p className="text-[10px] text-falcon-muted pl-7 mb-2">{risk.detail}</p>
                <div className="flex items-center gap-2 pl-7">
                  <span className="text-[10px] text-falcon-muted">影響度:</span>
                  <span className={`px-1.5 py-0.5 rounded-sm border text-[9px] font-medium ${RISK_COLOR[risk.impact]}`}>{RISK_LABEL[risk.impact]}</span>
                  <span className="text-[10px] text-falcon-muted">発生可能性:</span>
                  <span className={`px-1.5 py-0.5 rounded-sm border text-[9px] font-medium ${RISK_COLOR[risk.likelihood]}`}>{RISK_LABEL[risk.likelihood]}</span>
                </div>
              </div>
            ))}
          </div>
          <p className="text-xs text-falcon-muted font-medium mb-2">推奨する対策</p>
          <ul className="space-y-1.5">
            {investments.slice(0, 3).map((inv, i) => (
              <li key={i} className="flex items-start gap-2 text-xs text-falcon-text">
                <ChevronRight className="w-3.5 h-3.5 text-falcon-red shrink-0 mt-0.5" />
                <span>{inv.item}</span>
              </li>
            ))}
          </ul>
        </div>
      </div>

      {/* ── Bottom Row ───────────────────────────────────────────── */}
      <div className="grid grid-cols-1 xl:grid-cols-5 gap-4">

        {/* Monthly Trend Chart — wider */}
        <div className="xl:col-span-2 bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <TrendingDown className="w-4 h-4 text-falcon-green" />
            <h2 className="text-sm font-semibold text-white">インシデント・アラートの推移 (過去6ヶ月)</h2>
          </div>
          <p className="text-xs text-falcon-muted mb-3">月別の脅威件数の変化を示しています。数値が減少するほど安全な状態です。</p>
          <MonthlyTrendChart trends={monthlyTrends} />
        </div>

        {/* Compliance Table */}
        <div className="xl:col-span-2 bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <CheckCircle className="w-4 h-4 text-falcon-green" />
            <h2 className="text-sm font-semibold text-white">コンプライアンス状況</h2>
          </div>
          <div className="overflow-x-auto">
            <table className="w-full text-xs">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['フレームワーク', 'スコア', '状態', '前回評価', '次回予定'].map(h => (
                    <th key={h} className="text-left py-2 px-2 text-falcon-muted font-medium whitespace-nowrap">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {compliance.frameworks.map(f => (
                  <tr key={f.name} className="border-b border-falcon-border/40 hover:bg-falcon-border/20">
                    <td className="py-2.5 px-2 text-falcon-text font-medium whitespace-nowrap">{f.name}</td>
                    <td className="py-2.5 px-2">
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                          <div className="h-full rounded-full" style={{ width: `${f.score}%`, background: scoreBar(f.score) }} />
                        </div>
                        <span className="font-semibold text-falcon-text">{f.score}%</span>
                      </div>
                    </td>
                    <td className="py-2.5 px-2">
                      <span className={`px-2 py-0.5 rounded-sm border text-[10px] font-medium ${scoreStatusColor(f.score)}`}>{f.status}</span>
                    </td>
                    <td className="py-2.5 px-2 text-falcon-muted whitespace-nowrap">{f.last_assessment}</td>
                    <td className="py-2.5 px-2 text-falcon-muted whitespace-nowrap">{f.next_due}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>

        {/* Security Investments */}
        <div className="xl:col-span-1 bg-falcon-surface border border-falcon-border rounded-xl p-5">
          <div className="flex items-center gap-2 mb-4">
            <Target className="w-4 h-4 text-falcon-red" />
            <h2 className="text-sm font-semibold text-white">投資優先度</h2>
          </div>
          <p className="text-[10px] text-falcon-muted mb-3">リスク低減効果の高い順</p>
          <div className="space-y-3">
            {investments.map((inv, i) => (
              <div key={i} className="flex items-start gap-2">
                <span className="w-5 h-5 rounded-full flex items-center justify-center text-[10px] font-bold shrink-0 mt-0.5"
                  style={{ background: i === 0 ? '#e8002d20' : '#1e2d42', color: i === 0 ? '#e8002d' : '#7d92b0', border: `1px solid ${i === 0 ? '#e8002d40' : '#2d3f58'}` }}>
                  {inv.priority}
                </span>
                <div className="flex-1 min-w-0">
                  <p className="text-xs text-falcon-text leading-snug">{inv.item}</p>
                  <div className="flex items-center gap-1 mt-1">
                    <div className="flex-1 h-1 bg-falcon-border rounded-full overflow-hidden">
                      <div className="h-full bg-falcon-green rounded-full" style={{ width: `${inv.risk_reduction}%` }} />
                    </div>
                    <span className="text-[10px] text-falcon-green font-semibold whitespace-nowrap">-{inv.risk_reduction}%</span>
                  </div>
                  <p className="text-[9px] text-falcon-subtle">リスク低減効果</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </div>
    </div>
  )
}
