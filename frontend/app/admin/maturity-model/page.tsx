'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  TrendingUp, ChevronDown, ChevronRight, CheckCircle, Circle,
  Download, BarChart3, X, AlertTriangle, Info, Shield,
  RefreshCw, Calendar, Target, Award
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ─────────────────────────────────────────────────────────

type MaturityLevel = 1 | 2 | 3 | 4 | 5

interface DomainPractice {
  id: string
  text: string
  completed: boolean
}

interface AssessmentDomain {
  id: string
  name: string
  description: string
  current_level: MaturityLevel
  target_level: MaturityLevel
  justification: string
  gap_description: string
  current_practices: DomainPractice[]
  next_level_practices: DomainPractice[]
  evidence_required: string[]
  level_criteria: Record<MaturityLevel, string>
}

interface HistoricalAssessment {
  id: string
  date: string
  overall_level: number
  domain_scores: Record<string, number>
  key_improvements: string[]
  assessor: string
}

interface RoadmapItem {
  priority: number
  domain: string
  action: string
  effort: 'low' | 'medium' | 'high'
  impact: 'low' | 'medium' | 'high'
  timeline: string
}

const MATURITY_LEVEL_DESCRIPTIONS: Record<number, { label: string; color: string; bg: string; description: string }> = {
  1: { label: 'Initial', color: 'text-red-400', bg: 'bg-red-500/10 border-red-500/30', description: 'プロセスが場当たり的で再現性がない' },
  2: { label: 'Developing', color: 'text-orange-400', bg: 'bg-orange-500/10 border-orange-500/30', description: '基本的なプロセスが存在するが一貫性に欠ける' },
  3: { label: 'Defined', color: 'text-yellow-400', bg: 'bg-yellow-500/10 border-yellow-500/30', description: 'プロセスが文書化されており組織全体で標準化されている' },
  4: { label: 'Managed', color: 'text-blue-400', bg: 'bg-blue-500/10 border-blue-500/30', description: 'プロセスが測定・管理されており予測可能' },
  5: { label: 'Optimizing', color: 'text-green-400', bg: 'bg-green-500/10 border-green-500/30', description: '継続的な改善にフォーカスし最適化されている' },
}

const INDUSTRY_BENCHMARK: Record<string, { ours: number; industry: number }> = {
  'Endpoint Detection': { ours: 3.6, industry: 3.4 },
  'Incident Response': { ours: 3.1, industry: 3.0 },
  'Threat Intelligence': { ours: 2.9, industry: 2.7 },
  'Vulnerability Mgmt': { ours: 3.3, industry: 3.2 },
  'Access Control': { ours: 3.6, industry: 3.5 },
}

// ── Helpers ───────────────────────────────────────────────────────

const EFFORT_CONFIG = { low: { label: '低', color: 'text-green-400' }, medium: { label: '中', color: 'text-yellow-400' }, high: { label: '高', color: 'text-orange-400' } }
const IMPACT_CONFIG = { low: { label: '低', color: 'text-gray-400' }, medium: { label: '中', color: 'text-blue-400' }, high: { label: '高', color: 'text-purple-400' } }

function levelColor(l: number) {
  if (l >= 4) return 'text-green-400'
  if (l >= 3) return 'text-blue-400'
  if (l >= 2) return 'text-yellow-400'
  return 'text-red-400'
}
function levelBg(l: number) {
  if (l >= 4) return 'bg-green-900/30 border-green-700/30'
  if (l >= 3) return 'bg-blue-900/30 border-blue-700/30'
  if (l >= 2) return 'bg-yellow-900/30 border-yellow-700/30'
  return 'bg-red-900/30 border-red-700/30'
}

// ── Radar Chart ───────────────────────────────────────────────────

function RadarChart({ domains }: { domains: AssessmentDomain[] }) {
  const cx = 180, cy = 180, r = 140
  const n = domains.length
  const angles = domains.map((_, i) => (2 * Math.PI * i) / n - Math.PI / 2)

  const point = (level: number, i: number) => {
    const a = angles[i]
    const rad = (level / 5) * r
    return { x: cx + rad * Math.cos(a), y: cy + rad * Math.sin(a) }
  }

  const currentPts = domains.map((d, i) => point(d.current_level, i))
  const targetPts = domains.map((d, i) => point(d.target_level, i))
  const gridPts = (level: number) => domains.map((_, i) => point(level, i))

  const polyline = (pts: { x: number; y: number }[]) =>
    pts.map(p => `${p.x},${p.y}`).join(' ')

  return (
    <svg width={360} height={360} className="mx-auto">
      {/* Grid */}
      {[1, 2, 3, 4, 5].map(level => (
        <polygon key={level} points={polyline(gridPts(level))} fill="none"
          stroke="#1e2d42" strokeWidth={1} />
      ))}
      {/* Axes */}
      {domains.map((_, i) => {
        const pt = point(5, i)
        return <line key={i} x1={cx} y1={cy} x2={pt.x} y2={pt.y} stroke="#1e2d42" strokeWidth={1} />
      })}
      {/* Target area */}
      <polygon points={polyline(targetPts)} fill="rgba(99,102,241,0.1)" stroke="rgba(99,102,241,0.4)" strokeWidth={1.5} strokeDasharray="4,4" />
      {/* Current area */}
      <polygon points={polyline(currentPts)} fill="rgba(232,0,45,0.15)" stroke="#e8002d" strokeWidth={2} />
      {/* Current dots */}
      {currentPts.map((p, i) => (
        <circle key={i} cx={p.x} cy={p.y} r={4} fill="#e8002d" />
      ))}
      {/* Labels */}
      {domains.map((d, i) => {
        const pt = point(5.6, i)
        const short = d.name.length > 8 ? d.name.slice(0, 7) + '…' : d.name
        return (
          <text key={i} x={pt.x} y={pt.y} textAnchor="middle" dominantBaseline="middle"
            className="text-[10px]" fill="#7d92b0" fontSize={10}>{short}</text>
        )
      })}
      {/* Level labels */}
      {[1, 2, 3, 4, 5].map(l => (
        <text key={l} x={cx + 8} y={cy - (l / 5) * r + 4} fill="#3d5068" fontSize={9}>{l}</text>
      ))}
    </svg>
  )
}

// ── Domain Accordion ──────────────────────────────────────────────

function DomainAccordion({ domain, onUpdatePractice, onUpdateTarget }: {
  domain: AssessmentDomain
  onUpdatePractice: (domainId: string, practiceId: string, isNext: boolean, checked: boolean) => void
  onUpdateTarget: (domainId: string, level: MaturityLevel) => void
}) {
  const [open, setOpen] = useState(false)
  const [showCriteria, setShowCriteria] = useState(false)
  const lCfg = MATURITY_LEVEL_DESCRIPTIONS[domain.current_level]

  return (
    <div className={`bg-[#0d1220] border rounded-xl overflow-hidden transition-colors ${levelBg(domain.current_level)}`}>
      <button
        onClick={() => setOpen(!open)}
        className="w-full flex items-center justify-between px-5 py-4 hover:bg-[#070d19]/30 transition-colors"
      >
        <div className="flex items-center gap-3">
          <span className={`text-lg font-bold ${levelColor(domain.current_level)}`}>{domain.current_level}</span>
          <div className="text-left">
            <p className="text-white font-medium text-sm">{domain.name}</p>
            <p className="text-[#7d92b0] text-xs">{domain.description}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${lCfg.bg} ${lCfg.color}`}>
            Lv {domain.current_level}
          </span>
          <span className="text-xs text-[#3d5068]">→ 目標: Lv {domain.target_level}</span>
          {open ? <ChevronDown className="w-4 h-4 text-[#7d92b0]" /> : <ChevronRight className="w-4 h-4 text-[#7d92b0]" />}
        </div>
      </button>

      {open && (
        <div className="px-5 pb-5 border-t border-[#1e2d42]/50">
          <p className="text-sm text-[#e2e8f4] mt-4 mb-4">{domain.justification}</p>

          <div className="grid grid-cols-2 gap-4 mb-4">
            {/* Current level practices */}
            <div>
              <p className="text-xs text-[#7d92b0] mb-2 font-medium uppercase tracking-wider">現レベルのプラクティス</p>
              <div className="space-y-2">
                {domain.current_practices.map(p => (
                  <label key={p.id} className="flex items-start gap-2 cursor-pointer">
                    <input type="checkbox" checked={p.completed} onChange={e => onUpdatePractice(domain.id, p.id, false, e.target.checked)}
                      className="mt-0.5 accent-[#e8002d]" />
                    <span className={`text-xs ${p.completed ? 'text-[#e2e8f4]' : 'text-[#7d92b0]'}`}>{p.text}</span>
                  </label>
                ))}
              </div>
            </div>

            {/* Next level practices */}
            <div>
              <p className="text-xs text-[#7d92b0] mb-2 font-medium uppercase tracking-wider">次レベルへのプラクティス</p>
              <div className="space-y-2">
                {domain.next_level_practices.map(p => (
                  <label key={p.id} className="flex items-start gap-2 cursor-pointer">
                    <input type="checkbox" checked={p.completed} onChange={e => onUpdatePractice(domain.id, p.id, true, e.target.checked)}
                      className="mt-0.5 accent-blue-500" />
                    <span className={`text-xs ${p.completed ? 'text-blue-300' : 'text-[#7d92b0]'}`}>{p.text}</span>
                  </label>
                ))}
              </div>
            </div>
          </div>

          {/* Gap */}
          <div className="p-3 bg-[#070d19] rounded-lg border border-[#1e2d42] mb-3">
            <p className="text-xs text-[#7d92b0] mb-1 font-medium">次レベルへのギャップ</p>
            <p className="text-sm text-[#e2e8f4]">{domain.gap_description}</p>
          </div>

          {/* Evidence */}
          <div className="mb-3">
            <p className="text-xs text-[#7d92b0] mb-2 font-medium">レベル昇格に必要なエビデンス</p>
            <div className="flex flex-wrap gap-1.5">
              {domain.evidence_required.map(e => (
                <span key={e} className="text-xs px-2 py-0.5 rounded-sm bg-[#1e2d42] text-[#7d92b0] border border-[#2a3f5a]">{e}</span>
              ))}
            </div>
          </div>

          {/* Level criteria toggle */}
          <button onClick={() => setShowCriteria(!showCriteria)}
            className="flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 mb-3">
            <Info className="w-3.5 h-3.5" />
            {showCriteria ? 'レベル基準を非表示' : 'レベル基準を表示'}
          </button>

          {showCriteria && (
            <div className="grid grid-cols-5 gap-2 mb-3">
              {([1, 2, 3, 4, 5] as MaturityLevel[]).map(l => (
                <div key={l} className={`p-2 rounded-sm border text-xs ${domain.current_level === l ? levelBg(l) : 'border-[#1e2d42] bg-[#070d19]'}`}>
                  <p className={`font-bold mb-1 ${levelColor(l)}`}>Lv {l}</p>
                  <p className="text-[#7d92b0] leading-relaxed">{domain.level_criteria[l]}</p>
                </div>
              ))}
            </div>
          )}

          {/* Target level selector */}
          <div className="flex items-center gap-3">
            <p className="text-xs text-[#7d92b0]">次回目標レベル:</p>
            <div className="flex gap-1">
              {([1, 2, 3, 4, 5] as MaturityLevel[]).map(l => (
                <button key={l} onClick={() => onUpdateTarget(domain.id, l)}
                  className={`w-7 h-7 rounded-sm text-xs font-bold transition-colors ${domain.target_level === l ? `${levelBg(l)} ${levelColor(l)}` : 'bg-[#070d19] border border-[#1e2d42] text-[#3d5068] hover:text-white'}`}>
                  {l}
                </button>
              ))}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────

export default function MaturityModelPage() {
  const [domains, setDomains] = useState<AssessmentDomain[]>([])
  const [activeSection, setActiveSection] = useState<'assessment' | 'history' | 'roadmap' | 'benchmark'>('assessment')
  const [toast, setToast] = useState<string | null>(null)

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 4000) }

  useQuery({
    queryKey: ['maturity-assessment'],
    queryFn: () => apiFetch('/api/v1/admin/maturity-assessment'),
    onError: () => {},
  } as any)

  const overallLevel = domains.length ? domains.reduce((sum, d) => sum + d.current_level, 0) / domains.length : 0
  const overallLevelRounded = Math.round(overallLevel) as MaturityLevel
  const overallCfg = MATURITY_LEVEL_DESCRIPTIONS[overallLevelRounded] ?? MATURITY_LEVEL_DESCRIPTIONS[1]

  const handleUpdatePractice = (domainId: string, practiceId: string, isNext: boolean, checked: boolean) => {
    setDomains(prev => prev.map(d => {
      if (d.id !== domainId) return d
      if (!isNext) {
        return { ...d, current_practices: d.current_practices.map(p => p.id === practiceId ? { ...p, completed: checked } : p) }
      }
      return { ...d, next_level_practices: d.next_level_practices.map(p => p.id === practiceId ? { ...p, completed: checked } : p) }
    }))
  }

  const handleUpdateTarget = (domainId: string, level: MaturityLevel) => {
    setDomains(prev => prev.map(d => d.id === domainId ? { ...d, target_level: level } : d))
  }

  const handleExportReport = () => {
    showToast('評価レポートを生成中... (PDFダウンロード開始)')
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-linear-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
            <TrendingUp className="w-5 h-5 text-white" />
          </div>
          <div>
            <h1 className="text-white text-2xl font-bold">セキュリティ成熟度評価</h1>
            <p className="text-[#7d92b0] text-sm">CMMI ベースのセキュリティ成熟度モデル (SMM)</p>
          </div>
        </div>
        <button onClick={handleExportReport}
          className="flex items-center gap-2 px-4 py-2 bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] rounded-lg text-sm hover:text-white transition-colors">
          <Download className="w-4 h-4" /> 評価レポートを出力
        </button>
      </div>

      {/* Maturity info banner */}
      <div className="p-3 bg-[#0d1220] border border-[#1e2d42] rounded-lg mb-6 flex items-start gap-2">
        <Info className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
        <p className="text-xs text-[#7d92b0]">成熟度モデル: <span className="text-[#e2e8f4]">Level 1 (初期)</span> → <span className="text-[#e2e8f4]">Level 2 (管理)</span> → <span className="text-[#e2e8f4]">Level 3 (定義)</span> → <span className="text-[#e2e8f4]">Level 4 (定量管理)</span> → <span className="text-[#e2e8f4]">Level 5 (最適化)</span></p>
      </div>

      {/* Overall level + radar */}
      <div className="grid grid-cols-3 gap-4 mb-6">
        <div className={`col-span-1 bg-[#0d1220] border rounded-xl p-5 flex flex-col items-center justify-center ${levelBg(overallLevelRounded)}`}>
          <p className="text-xs text-[#7d92b0] mb-2 uppercase tracking-wider">総合成熟度レベル</p>
          <div className={`text-6xl font-black mb-2 ${overallCfg.color}`}>{overallLevelRounded}</div>
          <p className={`text-sm font-semibold mb-2 ${overallCfg.color}`}>{overallCfg.label}</p>
          <p className="text-xs text-[#7d92b0] text-center leading-relaxed">{overallCfg.description}</p>
          <p className="mt-3 text-xs text-[#3d5068]">平均スコア: {overallLevel.toFixed(2)}</p>
        </div>
        <div className="col-span-2 bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
          <p className="text-xs text-[#7d92b0] mb-2 font-medium uppercase tracking-wider text-center">ドメイン別スコア (レーダー)</p>
          <RadarChart domains={domains} />
          <div className="flex items-center justify-center gap-4 mt-1">
            <div className="flex items-center gap-1.5"><div className="w-3 h-0.5 bg-[#e8002d]" /><span className="text-xs text-[#7d92b0]">現在</span></div>
            <div className="flex items-center gap-1.5"><div className="w-3 h-0.5 border-t border-indigo-400 border-dashed" /><span className="text-xs text-[#7d92b0]">目標</span></div>
          </div>
        </div>
      </div>

      {/* Domain scores summary */}
      <div className="grid grid-cols-4 gap-3 mb-6">
        {domains.map(d => (
          <div key={d.id} className={`bg-[#0d1220] border rounded-xl p-3 ${levelBg(d.current_level)}`}>
            <p className="text-xs text-[#7d92b0] mb-1 truncate">{d.name}</p>
            <div className="flex items-center justify-between">
              <span className={`text-xl font-bold ${levelColor(d.current_level)}`}>{d.current_level}</span>
              <span className="text-xs text-[#3d5068]">→{d.target_level}</span>
            </div>
          </div>
        ))}
      </div>

      {/* Section Tabs */}
      <div className="flex gap-2 mb-6">
        {[
          { key: 'assessment', label: 'ドメイン評価' },
          { key: 'history', label: '評価履歴' },
          { key: 'roadmap', label: '改善ロードマップ' },
          { key: 'benchmark', label: '業界比較' },
        ].map(t => (
          <button key={t.key} onClick={() => setActiveSection(t.key as any)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${activeSection === t.key ? 'bg-[#e8002d] text-white' : 'bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-white'}`}>
            {t.label}
          </button>
        ))}
      </div>

      {/* Assessment Section */}
      {activeSection === 'assessment' && (
        <div className="space-y-3">
          {domains.map(d => (
            <DomainAccordion key={d.id} domain={d} onUpdatePractice={handleUpdatePractice} onUpdateTarget={handleUpdateTarget} />
          ))}
        </div>
      )}

      {/* History Section */}
      {activeSection === 'history' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
          <table className="w-full">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                {['評価日', '総合レベル', '主な改善点', '評価者'].map(h => (
                  <th key={h} className="text-left text-xs text-[#7d92b0] font-medium px-4 py-3">{h}</th>
                ))}
              </tr>
            </thead>
            <tbody>
              {([] as HistoricalAssessment[]).map((h, idx) => {
                const prev = ([] as HistoricalAssessment[])[idx + 1]
                const delta = prev ? h.overall_level - prev.overall_level : null
                return (
                  <tr key={h.id} className="border-b border-[#1e2d42]/50 hover:bg-[#070d19]/50 transition-colors">
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <Calendar className="w-3.5 h-3.5 text-[#7d92b0]" />
                        <span className="text-sm text-[#e2e8f4]">{h.date}</span>
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex items-center gap-2">
                        <span className={`text-xl font-bold ${levelColor(Math.round(h.overall_level) as MaturityLevel)}`}>{h.overall_level.toFixed(1)}</span>
                        {delta !== null && (
                          <span className={`text-xs font-medium ${delta > 0 ? 'text-green-400' : 'text-red-400'}`}>
                            {delta > 0 ? '+' : ''}{delta.toFixed(1)}
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-3">
                      <ul className="space-y-1">
                        {h.key_improvements.map((k, i) => (
                          <li key={i} className="flex items-start gap-1.5 text-xs text-[#7d92b0]">
                            <CheckCircle className="w-3 h-3 text-green-400 shrink-0 mt-0.5" />{k}
                          </li>
                        ))}
                      </ul>
                    </td>
                    <td className="px-4 py-3 text-sm text-[#7d92b0]">{h.assessor}</td>
                  </tr>
                )
              })}
            </tbody>
          </table>
        </div>
      )}

      {/* Roadmap Section */}
      {activeSection === 'roadmap' && (
        <div className="space-y-3">
          {([] as RoadmapItem[]).map(item => (
            <div key={item.priority} className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-start gap-4">
              <div className="w-8 h-8 rounded-full bg-[#e8002d]/20 border border-[#e8002d]/30 flex items-center justify-center shrink-0">
                <span className="text-sm font-bold text-[#e8002d]">{item.priority}</span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-white font-medium text-sm mb-1">{item.action}</p>
                <p className="text-xs text-[#7d92b0]">{item.domain}</p>
              </div>
              <div className="flex items-center gap-2 shrink-0">
                <div>
                  <p className="text-[9px] text-[#3d5068] mb-0.5">工数</p>
                  <span className={`text-xs font-medium ${EFFORT_CONFIG[item.effort].color}`}>{EFFORT_CONFIG[item.effort].label}</span>
                </div>
                <div>
                  <p className="text-[9px] text-[#3d5068] mb-0.5">効果</p>
                  <span className={`text-xs font-medium ${IMPACT_CONFIG[item.impact].color}`}>{IMPACT_CONFIG[item.impact].label}</span>
                </div>
                <span className="text-xs text-[#7d92b0] bg-[#1e2d42] px-2 py-0.5 rounded-sm">{item.timeline}</span>
              </div>
            </div>
          ))}
        </div>
      )}

      {/* Benchmark Section */}
      {activeSection === 'benchmark' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
          <p className="text-xs text-[#7d92b0] mb-4 font-medium uppercase tracking-wider flex items-center gap-2">
            <Award className="w-3.5 h-3.5" /> 業界平均との比較 (スコア / 5)
          </p>
          <div className="space-y-4">
            {Object.entries(INDUSTRY_BENCHMARK).map(([domain, scores]) => (
              <div key={domain}>
                <div className="flex items-center justify-between mb-1.5">
                  <p className="text-sm text-[#e2e8f4]">{domain}</p>
                  <div className="flex items-center gap-3 text-xs">
                    <span className="text-[#e8002d] font-bold">自社: {scores.ours}</span>
                    <span className="text-[#7d92b0]">業界: {scores.industry}</span>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <div className="flex-1 h-3 bg-[#1e2d42] rounded-full overflow-hidden relative">
                    {/* Industry average */}
                    <div className="absolute h-full rounded-full bg-[#2a3f5a]" style={{ width: `${(scores.industry / 5) * 100}%` }} />
                    {/* Ours */}
                    <div className={`absolute h-full rounded-full ${scores.ours >= scores.industry ? 'bg-green-500' : 'bg-[#e8002d]'}`} style={{ width: `${(scores.ours / 5) * 100}%` }} />
                  </div>
                  <span className={`text-xs font-medium w-10 text-right ${scores.ours >= scores.industry ? 'text-green-400' : 'text-red-400'}`}>
                    {scores.ours >= scores.industry ? '+' : ''}{(scores.ours - scores.industry).toFixed(1)}
                  </span>
                </div>
              </div>
            ))}
          </div>
          <div className="flex items-center gap-4 mt-4 text-xs text-[#7d92b0]">
            <div className="flex items-center gap-1.5"><div className="w-3 h-2 bg-[#e8002d] rounded-sm" /><span>自社</span></div>
            <div className="flex items-center gap-1.5"><div className="w-3 h-2 bg-[#2a3f5a] rounded-sm" /><span>業界平均</span></div>
          </div>
        </div>
      )}

      {toast && (
        <div className="fixed bottom-6 right-6 z-50 max-w-sm bg-[#0d1220] border border-green-500/50 rounded-lg p-4 shadow-xl flex items-center gap-3">
          <CheckCircle className="w-4 h-4 text-green-400 shrink-0" />
          <p className="text-sm text-[#e2e8f4] flex-1">{toast}</p>
          <button onClick={() => setToast(null)} className="text-[#7d92b0] hover:text-white"><X className="w-4 h-4" /></button>
        </div>
      )}
    </div>
  )
}
