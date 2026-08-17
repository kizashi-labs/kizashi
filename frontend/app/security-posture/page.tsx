'use client'

import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import {
  Shield, TrendingUp, TrendingDown, AlertTriangle, CheckCircle,
  RefreshCw, Target, Loader2, ArrowUp, ArrowDown, Minus,
} from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { USE_MOCK } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

interface PostureSummary {
  overall_score: number
  grade: string
  trend: number
  domain_scores: {
    endpoint: number
    network: number
    identity: number
    data: number
    cloud: number
  }
  critical_findings: CriticalFinding[]
  coverage_metrics: CoverageMetrics
  recent_improvements: Improvement[]
  open_risks: Risk[]
  compliance_heatmap: ComplianceCell[]
  trend_30d: TrendPoint[]
}

interface CriticalFinding {
  id: string
  title: string
  category: string
  severity: 'critical' | 'high' | 'medium'
  affected_assets: number
  days_open: number
  impact_score: number
}

interface CoverageMetrics {
  agent_coverage: number
  vuln_scan_coverage: number
  patched_sla: number
  mfa_coverage: number
  encrypted_data: number
  log_retention: number
}

interface Improvement {
  id: string
  description: string
  change: number
  category: string
  date: string
}

interface Risk {
  id: string
  title: string
  risk_score: number
  category: string
  trend: 'up' | 'down' | 'stable'
}

interface ComplianceCell {
  framework: string
  domain: string
  status: 'compliant' | 'partial' | 'non_compliant' | 'not_assessed'
  score: number
}

interface TrendPoint {
  date: string
  score: number
}

// ─── Empty / Mock Data ────────────────────────────────────────────────────────

const EMPTY_SUMMARY: PostureSummary = {
  overall_score: 0, grade: '-', trend: 0,
  domain_scores: { endpoint: 0, network: 0, identity: 0, data: 0, cloud: 0 },
  critical_findings: [], coverage_metrics: { agent_coverage: 0, vuln_scan_coverage: 0, patched_sla: 0, mfa_coverage: 0, encrypted_data: 0, log_retention: 0 },
  recent_improvements: [], open_risks: [], compliance_heatmap: [], trend_30d: [],
}

const MOCK_SUMMARY: PostureSummary = {
  overall_score: 73,
  grade: 'B',
  trend: 4,
  domain_scores: {
    endpoint: 82,
    network: 68,
    identity: 77,
    data: 61,
    cloud: 74,
  },
  critical_findings: [
    { id: '1', title: 'エンドポイントエージェント未インストール', category: 'Endpoint', severity: 'critical', affected_assets: 47, days_open: 12, impact_score: 9.2 },
    { id: '2', title: 'MFA未設定の特権アカウント', category: 'Identity', severity: 'critical', affected_assets: 8, days_open: 5, impact_score: 9.0 },
    { id: '3', title: '暗号化されていないデータストレージ', category: 'Data', severity: 'high', affected_assets: 23, days_open: 21, impact_score: 8.1 },
    { id: '4', title: 'パッチ未適用のCritical CVE (CVE-2024-1234)', category: 'Endpoint', severity: 'critical', affected_assets: 15, days_open: 8, impact_score: 8.8 },
    { id: '5', title: 'ネットワークセグメンテーション不備', category: 'Network', severity: 'high', affected_assets: 3, days_open: 31, impact_score: 7.9 },
  ],
  coverage_metrics: {
    agent_coverage: 91,
    vuln_scan_coverage: 84,
    patched_sla: 78,
    mfa_coverage: 86,
    encrypted_data: 69,
    log_retention: 95,
  },
  recent_improvements: [
    { id: '1', description: 'MFAカバレッジ +3%', change: 3, category: 'Identity', date: '2026-03-15' },
    { id: '2', description: 'エージェントカバレッジ +5%', change: 5, category: 'Endpoint', date: '2026-03-14' },
    { id: '3', description: 'ログ保持カバレッジ +2%', change: 2, category: 'Monitoring', date: '2026-03-12' },
    { id: '4', description: '脆弱性スキャン適用率 +4%', change: 4, category: 'Vulnerability', date: '2026-03-10' },
    { id: '5', description: 'SLA内パッチ適用率 +6%', change: 6, category: 'Patching', date: '2026-03-08' },
  ],
  open_risks: [
    { id: '1', title: 'クラウドストレージ公開設定', risk_score: 92, category: 'Cloud', trend: 'stable' },
    { id: '2', title: 'レガシーシステム残存', risk_score: 88, category: 'Endpoint', trend: 'down' },
    { id: '3', title: 'サービスアカウント過剰権限', risk_score: 85, category: 'Identity', trend: 'up' },
    { id: '4', title: 'VPN接続の暗号化設定', risk_score: 81, category: 'Network', trend: 'stable' },
    { id: '5', title: 'バックアップ暗号化未設定', risk_score: 79, category: 'Data', trend: 'stable' },
    { id: '6', title: '外部公開ポート管理', risk_score: 76, category: 'Network', trend: 'down' },
    { id: '7', title: 'パスワードポリシー未準拠', risk_score: 72, category: 'Identity', trend: 'up' },
    { id: '8', title: 'EDRエージェント非応答', risk_score: 68, category: 'Endpoint', trend: 'stable' },
    { id: '9', title: 'コンテナイメージ脆弱性', risk_score: 64, category: 'Cloud', trend: 'up' },
    { id: '10', title: 'DNS over HTTPS未設定', risk_score: 61, category: 'Network', trend: 'stable' },
  ],
  compliance_heatmap: [
    { framework: 'ISO 27001', domain: 'Endpoint', status: 'compliant', score: 91 },
    { framework: 'ISO 27001', domain: 'Network', status: 'partial', score: 68 },
    { framework: 'ISO 27001', domain: 'Identity', status: 'compliant', score: 88 },
    { framework: 'ISO 27001', domain: 'Data', status: 'partial', score: 65 },
    { framework: 'ISO 27001', domain: 'Cloud', status: 'compliant', score: 79 },
    { framework: 'NIST CSF', domain: 'Endpoint', status: 'partial', score: 74 },
    { framework: 'NIST CSF', domain: 'Network', status: 'partial', score: 71 },
    { framework: 'NIST CSF', domain: 'Identity', status: 'compliant', score: 83 },
    { framework: 'NIST CSF', domain: 'Data', status: 'non_compliant', score: 45 },
    { framework: 'NIST CSF', domain: 'Cloud', status: 'partial', score: 67 },
    { framework: 'PCI DSS', domain: 'Endpoint', status: 'compliant', score: 90 },
    { framework: 'PCI DSS', domain: 'Network', status: 'partial', score: 72 },
    { framework: 'PCI DSS', domain: 'Identity', status: 'compliant', score: 86 },
    { framework: 'PCI DSS', domain: 'Data', status: 'partial', score: 63 },
    { framework: 'PCI DSS', domain: 'Cloud', status: 'not_assessed', score: 0 },
    { framework: 'SOC 2', domain: 'Endpoint', status: 'compliant', score: 88 },
    { framework: 'SOC 2', domain: 'Network', status: 'compliant', score: 82 },
    { framework: 'SOC 2', domain: 'Identity', status: 'partial', score: 74 },
    { framework: 'SOC 2', domain: 'Data', status: 'partial', score: 69 },
    { framework: 'SOC 2', domain: 'Cloud', status: 'compliant', score: 85 },
    { framework: 'GDPR', domain: 'Endpoint', status: 'compliant', score: 87 },
    { framework: 'GDPR', domain: 'Network', status: 'partial', score: 64 },
    { framework: 'GDPR', domain: 'Identity', status: 'compliant', score: 91 },
    { framework: 'GDPR', domain: 'Data', status: 'non_compliant', score: 38 },
    { framework: 'GDPR', domain: 'Cloud', status: 'partial', score: 61 },
  ],
  trend_30d: Array.from({ length: 30 }, (_, i) => ({
    date: new Date(Date.now() - (29 - i) * 86400000).toISOString().split('T')[0],
    score: Math.max(50, Math.min(95, 65 + Math.round(Math.sin(i * 0.3) * 8) + Math.round(i * 0.28))),
  })),
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function CircularGauge({ score, grade }: { score: number; grade: string }) {
  const [animatedScore, setAnimatedScore] = useState(0)
  const radius = 80
  const stroke = 10
  const normalizedRadius = radius - stroke
  const circumference = normalizedRadius * 2 * Math.PI
  const strokeDashoffset = circumference - (animatedScore / 100) * circumference

  useEffect(() => {
    const timer = setTimeout(() => {
      let start = 0
      const step = () => {
        start += 2
        if (start <= score) {
          setAnimatedScore(start)
          requestAnimationFrame(step)
        } else {
          setAnimatedScore(score)
        }
      }
      requestAnimationFrame(step)
    }, 300)
    return () => clearTimeout(timer)
  }, [score])

  const gradeColor =
    grade === 'A' ? '#00c853' :
    grade === 'B' ? '#1a6bff' :
    grade === 'C' ? '#ff9800' :
    grade === 'D' ? '#ff5722' : '#e8002d'

  return (
    <div className="relative flex items-center justify-center" style={{ width: radius * 2, height: radius * 2 }}>
      <svg height={radius * 2} width={radius * 2} className="-rotate-90">
        <circle stroke="#1e2d42" fill="transparent" strokeWidth={stroke} r={normalizedRadius} cx={radius} cy={radius} />
        <circle
          stroke={gradeColor}
          fill="transparent"
          strokeWidth={stroke}
          strokeDasharray={`${circumference} ${circumference}`}
          style={{ strokeDashoffset, transition: 'stroke-dashoffset 0.05s linear' }}
          strokeLinecap="round"
          r={normalizedRadius}
          cx={radius}
          cy={radius}
        />
      </svg>
      <div className="absolute inset-0 flex flex-col items-center justify-center">
        <span className="text-4xl font-bold text-white">{animatedScore}</span>
        <span className="text-xs text-falcon-muted mt-0.5">/ 100</span>
        <span className="text-2xl font-bold mt-1" style={{ color: gradeColor }}>{grade}</span>
      </div>
    </div>
  )
}

function PentagonChart({ scores }: { scores: PostureSummary['domain_scores'] }) {
  const labels = ['Endpoint', 'Network', 'Identity', 'Data', 'Cloud']
  const values = [scores.endpoint, scores.network, scores.identity, scores.data, scores.cloud]
  const cx = 120
  const cy = 120
  const maxR = 85

  const angleOf = (i: number) => (i * 2 * Math.PI) / 5 - Math.PI / 2

  const outerPoints = labels.map((_, i) => ({
    x: cx + maxR * Math.cos(angleOf(i)),
    y: cy + maxR * Math.sin(angleOf(i)),
  }))

  const dataPoints = values.map((v, i) => ({
    x: cx + (v / 100) * maxR * Math.cos(angleOf(i)),
    y: cy + (v / 100) * maxR * Math.sin(angleOf(i)),
  }))

  const toPolyline = (pts: { x: number; y: number }[]) =>
    pts.map(p => `${p.x.toFixed(1)},${p.y.toFixed(1)}`).join(' ')

  const rings = [20, 40, 60, 80, 100].map(pct =>
    labels.map((_, i) => ({
      x: cx + (pct / 100) * maxR * Math.cos(angleOf(i)),
      y: cy + (pct / 100) * maxR * Math.sin(angleOf(i)),
    }))
  )

  const colorForScore = (s: number) =>
    s >= 80 ? '#00c853' : s >= 60 ? '#1a6bff' : s >= 40 ? '#ff9800' : '#e8002d'

  return (
    <svg width={240} height={240} className="overflow-visible">
      {rings.map((ring, ri) => (
        <polygon key={ri} points={toPolyline(ring)} fill="none" stroke="#1e2d42" strokeWidth={1} />
      ))}
      {outerPoints.map((op, i) => (
        <line key={i} x1={cx} y1={cy} x2={op.x.toFixed(1)} y2={op.y.toFixed(1)} stroke="#1e2d42" strokeWidth={1} />
      ))}
      <polygon points={toPolyline(dataPoints)} fill="rgba(26,107,255,0.15)" stroke="#1a6bff" strokeWidth={2} />
      {dataPoints.map((dp, i) => (
        <circle key={i} cx={dp.x.toFixed(1)} cy={dp.y.toFixed(1)} r={4} fill={colorForScore(values[i])} />
      ))}
      {outerPoints.map((op, i) => {
        const lx = cx + (maxR + 20) * Math.cos(angleOf(i))
        const ly = cy + (maxR + 20) * Math.sin(angleOf(i))
        return (
          <g key={i}>
            <text x={lx.toFixed(1)} y={(ly - 6).toFixed(1)} textAnchor="middle" fontSize={10} fill="#7d92b0" fontFamily="sans-serif">{labels[i]}</text>
            <text x={lx.toFixed(1)} y={(ly + 8).toFixed(1)} textAnchor="middle" fontSize={11} fill={colorForScore(values[i])} fontWeight="bold" fontFamily="sans-serif">{values[i]}</text>
          </g>
        )
      })}
    </svg>
  )
}

function TrendChart({ points }: { points: TrendPoint[] }) {
  if (!points.length) return null
  const scores = points.map(p => p.score)
  const minS = Math.min(...scores) - 5
  const maxS = Math.max(...scores) + 5
  const w = 560
  const h = 120
  const pad = { top: 10, right: 10, bottom: 25, left: 35 }

  const sx = (i: number) => pad.left + (i / (points.length - 1)) * (w - pad.left - pad.right)
  const sy = (s: number) => pad.top + ((maxS - s) / (maxS - minS)) * (h - pad.top - pad.bottom)

  const polyline = points.map((p, i) => `${sx(i).toFixed(1)},${sy(p.score).toFixed(1)}`).join(' ')
  const area = `${sx(0).toFixed(1)},${sy(minS).toFixed(1)} ` +
    points.map((p, i) => `${sx(i).toFixed(1)},${sy(p.score).toFixed(1)}`).join(' ') +
    ` ${sx(points.length - 1).toFixed(1)},${sy(minS).toFixed(1)} Z`

  const yLabels = [Math.round(minS), Math.round((minS + maxS) / 2), Math.round(maxS)]
  const xIndices = [0, Math.floor(points.length / 2), points.length - 1]

  return (
    <svg width="100%" viewBox={`0 0 ${w} ${h}`} className="overflow-visible">
      {yLabels.map((v, i) => (
        <g key={i}>
          <line x1={pad.left} y1={sy(v).toFixed(1)} x2={w - pad.right} y2={sy(v).toFixed(1)} stroke="#1e2d42" strokeWidth={1} strokeDasharray="4,4" />
          <text x={pad.left - 5} y={(sy(v) + 4).toFixed(1)} textAnchor="end" fontSize={9} fill="#3d5068" fontFamily="sans-serif">{v}</text>
        </g>
      ))}
      <path d={area} fill="rgba(26,107,255,0.08)" />
      <polyline points={polyline} fill="none" stroke="#1a6bff" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />
      <circle cx={sx(0).toFixed(1)} cy={sy(points[0].score).toFixed(1)} r={3} fill="#1a6bff" />
      <circle cx={sx(points.length - 1).toFixed(1)} cy={sy(points[points.length - 1].score).toFixed(1)} r={4} fill="#00c853" />
      {xIndices.map(idx => (
        <text key={idx} x={sx(idx).toFixed(1)} y={h - 5} textAnchor="middle" fontSize={9} fill="#3d5068" fontFamily="sans-serif">
          {points[idx].date.slice(5)}
        </text>
      ))}
    </svg>
  )
}

function SeverityBadge({ severity }: { severity: CriticalFinding['severity'] }) {
  const cfg: Record<string, string> = {
    critical: 'bg-falcon-red/20 text-falcon-red border-falcon-red/40',
    high: 'bg-orange-500/20 text-orange-400 border-orange-500/40',
    medium: 'bg-yellow-500/20 text-yellow-400 border-yellow-500/40',
  }
  const label: Record<string, string> = { critical: 'Critical', high: 'High', medium: 'Medium' }
  return (
    <span className={`text-[10px] font-bold px-2 py-0.5 rounded-sm border ${cfg[severity]}`}>
      {label[severity]}
    </span>
  )
}

function CoverageBar({ label, value }: { label: string; value: number }) {
  const color = value >= 90 ? '#00c853' : value >= 70 ? '#1a6bff' : value >= 50 ? '#ff9800' : '#e8002d'
  return (
    <div className="bg-falcon-surface rounded-lg border border-falcon-border p-4">
      <div className="flex items-center justify-between mb-2">
        <span className="text-falcon-muted text-xs">{label}</span>
        <span className="text-white font-bold text-sm">{value}%</span>
      </div>
      <div className="h-2 rounded-full bg-falcon-border overflow-hidden">
        <div className="h-full rounded-full transition-all duration-700" style={{ width: `${value}%`, backgroundColor: color }} />
      </div>
    </div>
  )
}

function ComplianceStatusCell({ status, score }: { status: ComplianceCell['status']; score: number }) {
  const cfg: Record<string, string> = {
    compliant: 'bg-falcon-green/20 text-falcon-green',
    partial: 'bg-yellow-500/20 text-yellow-400',
    non_compliant: 'bg-falcon-red/20 text-falcon-red',
    not_assessed: 'bg-falcon-border text-falcon-subtle',
  }
  return (
    <div className={`rounded-sm p-2 text-center ${cfg[status]}`}>
      <div className="text-xs font-bold">{status === 'not_assessed' ? 'N/A' : `${score}%`}</div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function SecurityPosturePage() {
  const [scanProgress, setScanProgress] = useState<number | null>(null)

  const { data, isLoading, error, refetch } = useQuery<PostureSummary>({
    queryKey: ['security-posture-summary'],
    queryFn: () => apiFetch('/api/v1/security-posture/summary'),
    staleTime: 60_000,
  })

  const summary = error || !data ? (USE_MOCK ? MOCK_SUMMARY : EMPTY_SUMMARY) : data

  const runScan = () => {
    setScanProgress(0)
    const interval = setInterval(() => {
      setScanProgress(prev => {
        if (prev === null) return null
        if (prev >= 100) {
          clearInterval(interval)
          setTimeout(() => {
            setScanProgress(null)
            refetch()
          }, 1000)
          return 100
        }
        return prev + 5
      })
    }, 150)
  }

  const frameworks = ['ISO 27001', 'NIST CSF', 'PCI DSS', 'SOC 2', 'GDPR']
  const domains = ['Endpoint', 'Network', 'Identity', 'Data', 'Cloud']

  return (
    <div className="min-h-screen bg-[#070d19] text-falcon-muted">
      {/* Header */}
      <div className="border-b border-falcon-border bg-falcon-surface px-6 py-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center">
              <Shield className="w-5 h-5 text-white" />
            </div>
            <div>
              <h1 className="text-xl font-bold text-white">セキュリティ態勢 総合ダッシュボード</h1>
              <p className="text-xs text-falcon-subtle mt-0.5">Security Posture Dashboard v2 — 最終更新: {new Date().toLocaleString('ja-JP')}</p>
            </div>
          </div>
          <div className="flex items-center gap-3">
            <button
              onClick={() => refetch()}
              className="flex items-center gap-2 px-3 py-2 rounded-lg border border-falcon-border text-falcon-muted hover:text-white hover:border-falcon-muted/40 transition-all text-sm"
            >
              <RefreshCw className="w-4 h-4" />
              更新
            </button>
            <button
              onClick={runScan}
              disabled={scanProgress !== null}
              className="flex items-center gap-2 px-4 py-2 rounded-lg bg-falcon-red text-white hover:bg-[#c0001f] disabled:opacity-60 disabled:cursor-not-allowed transition-all text-sm font-medium"
            >
              {scanProgress !== null ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  {scanProgress < 100 ? `スキャン中... ${scanProgress}%` : 'スキャン完了'}
                </>
              ) : (
                <>
                  <Target className="w-4 h-4" />
                  スキャン今すぐ実行
                </>
              )}
            </button>
          </div>
        </div>
        {scanProgress !== null && (
          <div className="mt-3 h-1.5 rounded-full bg-falcon-border overflow-hidden">
            <div className="h-full rounded-full bg-falcon-red transition-all duration-150" style={{ width: `${scanProgress}%` }} />
          </div>
        )}
      </div>

      {isLoading && (
        <div className="flex items-center justify-center h-64">
          <Loader2 className="w-8 h-8 animate-spin text-falcon-blue" />
        </div>
      )}

      {!isLoading && (
        <div className="p-6 space-y-6">

          {/* Row 1: Overall Score + Radar + Trend */}
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">

            {/* Overall Score */}
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6 flex flex-col items-center gap-4">
              <h2 className="text-white font-semibold text-base self-start">総合スコア</h2>
              <CircularGauge score={summary.overall_score} grade={summary.grade} />
              <div className="flex items-center gap-2">
                {summary.trend > 0 ? (
                  <span className="flex items-center gap-1 text-falcon-green text-sm font-medium">
                    <ArrowUp className="w-4 h-4" /> +{summary.trend}% (前月比)
                  </span>
                ) : summary.trend < 0 ? (
                  <span className="flex items-center gap-1 text-falcon-red text-sm font-medium">
                    <ArrowDown className="w-4 h-4" /> {summary.trend}% (前月比)
                  </span>
                ) : (
                  <span className="flex items-center gap-1 text-falcon-muted text-sm">
                    <Minus className="w-4 h-4" /> 変化なし
                  </span>
                )}
              </div>
              <div className="w-full grid grid-cols-3 gap-2 text-center">
                {(['A', 'B', 'C', 'D', 'F'] as const).map(g => {
                  const range = { A: '90-100', B: '75-89', C: '60-74', D: '45-59', F: '0-44' }
                  const color: Record<string, string> = { A: '#00c853', B: '#1a6bff', C: '#ff9800', D: '#ff5722', F: '#e8002d' }
                  return (
                    <div
                      key={g}
                      className={`rounded-sm px-2 py-1 text-xs border ${summary.grade === g ? 'border-current font-bold' : 'border-falcon-border'}`}
                      style={{ color: summary.grade === g ? color[g] : '#3d5068' }}
                    >
                      {g}: {range[g]}
                    </div>
                  )
                })}
              </div>
            </div>

            {/* Pentagon Radar */}
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6 flex flex-col items-center gap-2">
              <h2 className="text-white font-semibold text-base self-start">ドメイン別スコア</h2>
              <PentagonChart scores={summary.domain_scores} />
              <div className="grid grid-cols-5 gap-1 w-full mt-1">
                {(Object.entries(summary.domain_scores) as [string, number][]).map(([k, v]) => {
                  const color = v >= 80 ? '#00c853' : v >= 60 ? '#1a6bff' : '#ff9800'
                  const label: Record<string, string> = { endpoint: 'EP', network: 'NW', identity: 'ID', data: 'DA', cloud: 'CL' }
                  return (
                    <div key={k} className="text-center">
                      <div className="text-[9px] text-falcon-subtle">{label[k]}</div>
                      <div className="text-xs font-bold" style={{ color }}>{v}</div>
                    </div>
                  )
                })}
              </div>
            </div>

            {/* 30-day Trend */}
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-6">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-white font-semibold text-base">30日間トレンド</h2>
                <span className="text-xs text-falcon-subtle">スコア推移</span>
              </div>
              <TrendChart points={summary.trend_30d} />
              <div className="flex items-center justify-between mt-3 text-xs text-falcon-subtle">
                <span>開始: {summary.trend_30d[0]?.score ?? 0}</span>
                <span className="text-falcon-green font-medium">
                  現在: {summary.trend_30d[summary.trend_30d.length - 1]?.score ?? 0}
                </span>
              </div>
            </div>
          </div>

          {/* Coverage Metrics */}
          <div>
            <h2 className="text-white font-semibold text-base mb-3">カバレッジメトリクス</h2>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
              <CoverageBar label="エージェントカバレッジ" value={summary.coverage_metrics.agent_coverage} />
              <CoverageBar label="脆弱性スキャン" value={summary.coverage_metrics.vuln_scan_coverage} />
              <CoverageBar label="SLA内パッチ適用" value={summary.coverage_metrics.patched_sla} />
              <CoverageBar label="MFAカバレッジ" value={summary.coverage_metrics.mfa_coverage} />
              <CoverageBar label="データ暗号化" value={summary.coverage_metrics.encrypted_data} />
              <CoverageBar label="ログ保持期間" value={summary.coverage_metrics.log_retention} />
            </div>
          </div>

          {/* Critical Findings */}
          <div>
            <div className="flex items-center justify-between mb-3">
              <h2 className="text-white font-semibold text-base">Critical検知項目 (TOP 5)</h2>
              <span className="text-xs text-falcon-subtle">インパクト順</span>
            </div>
            <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-falcon-border text-falcon-subtle text-xs">
                    <th className="text-left px-4 py-3">検知内容</th>
                    <th className="text-left px-4 py-3">カテゴリ</th>
                    <th className="text-left px-4 py-3">深刻度</th>
                    <th className="text-right px-4 py-3">影響資産</th>
                    <th className="text-right px-4 py-3">経過日数</th>
                    <th className="text-right px-4 py-3">インパクト</th>
                    <th className="px-4 py-3"></th>
                  </tr>
                </thead>
                <tbody>
                  {summary.critical_findings.map((f, i) => (
                    <tr key={f.id} className={`border-b border-falcon-border last:border-0 hover:bg-falcon-hover transition-colors ${i === 0 ? 'bg-falcon-red/5' : ''}`}>
                      <td className="px-4 py-3">
                        <span className="text-white font-medium text-sm">{f.title}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-[10px] bg-falcon-border text-falcon-muted px-2 py-0.5 rounded-sm">{f.category}</span>
                      </td>
                      <td className="px-4 py-3">
                        <SeverityBadge severity={f.severity} />
                      </td>
                      <td className="px-4 py-3 text-right text-white">{f.affected_assets}</td>
                      <td className="px-4 py-3 text-right">
                        <span className={f.days_open > 14 ? 'text-falcon-red' : 'text-falcon-amber'}>{f.days_open}日</span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <span className="text-falcon-red font-bold">{f.impact_score.toFixed(1)}</span>
                      </td>
                      <td className="px-4 py-3 text-right">
                        <button className="text-xs px-3 py-1 rounded-sm bg-falcon-red/20 text-falcon-red border border-falcon-red/40 hover:bg-falcon-red/30 transition-colors">
                          対処
                        </button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {/* Improvements + Open Risks */}
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">

            {/* Recent Improvements */}
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
              <div className="flex items-center gap-2 mb-4">
                <TrendingUp className="w-4 h-4 text-falcon-green" />
                <h2 className="text-white font-semibold text-base">最近の改善 (直近5件)</h2>
              </div>
              <div className="space-y-3">
                {summary.recent_improvements.map(imp => (
                  <div key={imp.id} className="flex items-center gap-3 py-2 border-b border-falcon-border last:border-0">
                    <div className="w-8 h-8 rounded-lg bg-falcon-green/10 flex items-center justify-center shrink-0">
                      <ArrowUp className="w-4 h-4 text-falcon-green" />
                    </div>
                    <div className="flex-1 min-w-0">
                      <p className="text-white text-sm font-medium">{imp.description}</p>
                      <p className="text-falcon-subtle text-xs mt-0.5">{imp.category} · {imp.date}</p>
                    </div>
                    <span className="text-xs font-bold px-2 py-0.5 rounded-sm bg-falcon-green/20 text-falcon-green border border-falcon-green/30">
                      +{imp.change}%
                    </span>
                  </div>
                ))}
              </div>
            </div>

            {/* Open Risks */}
            <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
              <div className="flex items-center gap-2 mb-4">
                <AlertTriangle className="w-4 h-4 text-falcon-amber" />
                <h2 className="text-white font-semibold text-base">オープンリスク (TOP 10)</h2>
              </div>
              <div className="space-y-2">
                {summary.open_risks.map((risk, i) => (
                  <div key={risk.id} className="flex items-center gap-3">
                    <span className="text-xs text-falcon-subtle w-4 shrink-0">{i + 1}</span>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center justify-between mb-0.5">
                        <span className="text-falcon-muted text-xs truncate">{risk.title}</span>
                        <div className="flex items-center gap-1.5 shrink-0 ml-2">
                          {risk.trend === 'up' && <TrendingUp className="w-3 h-3 text-falcon-red" />}
                          {risk.trend === 'down' && <TrendingDown className="w-3 h-3 text-falcon-green" />}
                          {risk.trend === 'stable' && <Minus className="w-3 h-3 text-falcon-muted" />}
                          <span className="text-[10px] text-white font-bold">{risk.risk_score}</span>
                        </div>
                      </div>
                      <div className="h-1.5 rounded-full bg-falcon-border overflow-hidden">
                        <div
                          className="h-full rounded-full"
                          style={{
                            width: `${risk.risk_score}%`,
                            backgroundColor: risk.risk_score >= 85 ? '#e8002d' : risk.risk_score >= 70 ? '#ff9800' : '#1a6bff',
                          }}
                        />
                      </div>
                    </div>
                    <span className="text-[9px] bg-falcon-border text-falcon-muted px-1.5 py-0.5 rounded-sm shrink-0">{risk.category}</span>
                  </div>
                ))}
              </div>
            </div>
          </div>

          {/* Compliance Heatmap */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <div className="flex items-center gap-2">
                <CheckCircle className="w-4 h-4 text-falcon-blue" />
                <h2 className="text-white font-semibold text-base">コンプライアンスヒートマップ</h2>
              </div>
              <div className="flex items-center gap-3 text-xs text-falcon-muted">
                <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-sm bg-falcon-green/30 inline-block" />準拠</span>
                <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-sm bg-yellow-500/30 inline-block" />一部準拠</span>
                <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-sm bg-falcon-red/30 inline-block" />非準拠</span>
                <span className="flex items-center gap-1"><span className="w-3 h-3 rounded-sm bg-falcon-border inline-block" />未評価</span>
              </div>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-xs">
                <thead>
                  <tr>
                    <th className="text-left text-falcon-subtle font-medium pb-2 pr-4">フレームワーク</th>
                    {domains.map(d => (
                      <th key={d} className="text-center text-falcon-subtle font-medium pb-2 px-2 min-w-[80px]">{d}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {frameworks.map(fw => (
                    <tr key={fw} className="border-t border-falcon-border">
                      <td className="py-2 pr-4 text-falcon-muted font-medium whitespace-nowrap">{fw}</td>
                      {domains.map(d => {
                        const cell = summary.compliance_heatmap.find(c => c.framework === fw && c.domain === d)
                        return (
                          <td key={d} className="py-2 px-2">
                            {cell ? (
                              <ComplianceStatusCell status={cell.status} score={cell.score} />
                            ) : (
                              <div className="rounded-sm p-2 text-center bg-falcon-border text-falcon-subtle text-xs">N/A</div>
                            )}
                          </td>
                        )
                      })}
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

        </div>
      )}
    </div>
  )
}
