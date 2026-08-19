'use client'

import { useState, useEffect } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Calculator, TrendingUp, DollarSign, AlertTriangle,
  Shield, Database, Wifi, Mail, Package, Users,
  ChevronRight, BarChart2, CheckCircle, Clock,
  Info, Save, Download, RefreshCw, X, Star,
  Building2, FileText, Lock, Globe,
} from 'lucide-react'

import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ─── Types ────────────────────────────────────────────────────────────────────

type IncidentType = 'ransomware' | 'data_breach' | 'ddos' | 'insider_threat' | 'supply_chain' | 'phishing'
type RegulationFine = 'none' | 'gdpr' | 'pci' | 'hipaa' | 'appi'
type ReputationLevel = 0 | 1 | 2  // minor / moderate / severe

interface DirectCosts {
  analyst_count: number
  analyst_hours: number
  analyst_rate: number
  ir_services: number
  forensics: number
  legal_response: number
  hardware_replacement: number
  software_replacement: number
  legal_notification: number
}

interface IndirectCosts {
  downtime_hours: number
  affected_users: number
  hourly_productivity: number
  lost_business: number
  reputation_level: ReputationLevel
  regulation: RegulationFine
  affected_records: number
}

interface SavedCalculation {
  id: string
  name: string
  incident_type: IncidentType
  date: string
  total_jpy: number
  total_usd: number
}

// ─── Constants ────────────────────────────────────────────────────────────────

const JPY_TO_USD = 150

const INCIDENT_TYPES: { type: IncidentType; label: string; icon: React.ComponentType<{ className?: string }>; color: string; description: string }[] = [
  { type: 'ransomware', label: 'ランサムウェア', icon: Lock, color: 'text-red-400 border-red-500/40 bg-red-500/10', description: '暗号化・身代金・復旧費用' },
  { type: 'data_breach', label: 'データ侵害', icon: Database, color: 'text-orange-400 border-orange-500/40 bg-orange-500/10', description: '個人情報漏洩・通知費用' },
  { type: 'ddos', label: 'DDoS攻撃', icon: Wifi, color: 'text-yellow-400 border-yellow-500/40 bg-yellow-500/10', description: 'サービス停止・機会損失' },
  { type: 'insider_threat', label: '内部脅威', icon: Users, color: 'text-purple-400 border-purple-500/40 bg-purple-500/10', description: '情報漏洩・調査費用' },
  { type: 'supply_chain', label: 'サプライチェーン', icon: Package, color: 'text-blue-400 border-blue-500/40 bg-blue-500/10', description: '広範囲の影響・復旧' },
  { type: 'phishing', label: 'フィッシング', icon: Mail, color: 'text-teal-400 border-teal-500/40 bg-teal-500/10', description: 'アカウント侵害・対応' },
]

const REPUTATION_LEVELS: { level: ReputationLevel; label: string; multiplier: number }[] = [
  { level: 0, label: '軽微', multiplier: 1 },
  { level: 1, label: '中程度', multiplier: 3 },
  { level: 2, label: '深刻', multiplier: 8 },
]

const REPUTATION_BASE: Record<IncidentType, number> = {
  ransomware: 50_000_000,
  data_breach: 80_000_000,
  ddos: 20_000_000,
  insider_threat: 60_000_000,
  supply_chain: 100_000_000,
  phishing: 15_000_000,
}

const REGULATION_FINES: Record<RegulationFine, { label: string; estimate: number }> = {
  none: { label: '該当なし', estimate: 0 },
  gdpr: { label: 'GDPR', estimate: 150_000_000 },
  pci: { label: 'PCI DSS', estimate: 30_000_000 },
  hipaa: { label: 'HIPAA', estimate: 80_000_000 },
  appi: { label: '個人情報保護法 (APPI)', estimate: 10_000_000 },
}

const INDUSTRY_BENCHMARKS: Record<IncidentType, { avg_jpy: number; description: string }> = {
  ransomware: { avg_jpy: 420_000_000, description: '身代金・復旧・法的費用含む (IBM 2024)' },
  data_breach: { avg_jpy: 640_000_000, description: '平均侵害コスト (Ponemon 2024)' },
  ddos: { avg_jpy: 85_000_000, description: '平均ダウンタイム損失 (Corero 2024)' },
  insider_threat: { avg_jpy: 380_000_000, description: '内部犯罪・過失含む (CERT 2024)' },
  supply_chain: { avg_jpy: 840_000_000, description: 'サプライチェーン攻撃 (BSI 2024)' },
  phishing: { avg_jpy: 170_000_000, description: 'フィッシング起因侵害 (APWG 2024)' },
}

const PREVENTION_ROI: { investment: string; cost_jpy: number; saves_pct: Record<IncidentType, number> }[] = [
  { investment: 'EDRソリューション強化', cost_jpy: 5_000_000, saves_pct: { ransomware: 60, data_breach: 40, ddos: 15, insider_threat: 35, supply_chain: 30, phishing: 45 } },
  { investment: 'ゼロトラストアーキテクチャ', cost_jpy: 15_000_000, saves_pct: { ransomware: 70, data_breach: 65, ddos: 10, insider_threat: 75, supply_chain: 50, phishing: 60 } },
  { investment: 'セキュリティ意識向上トレーニング', cost_jpy: 2_000_000, saves_pct: { ransomware: 35, data_breach: 30, ddos: 5, insider_threat: 40, supply_chain: 20, phishing: 70 } },
  { investment: 'インシデント対応計画', cost_jpy: 3_000_000, saves_pct: { ransomware: 45, data_breach: 40, ddos: 35, insider_threat: 30, supply_chain: 35, phishing: 30 } },
]

const DEFAULT_DIRECT: DirectCosts = { analyst_count: 2, analyst_hours: 40, analyst_rate: 8000, ir_services: 0, forensics: 0, legal_response: 0, hardware_replacement: 0, software_replacement: 0, legal_notification: 0 }
const DEFAULT_INDIRECT: IndirectCosts = { downtime_hours: 8, affected_users: 100, hourly_productivity: 5000, lost_business: 0, reputation_level: 0, regulation: 'none', affected_records: 0 }

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtJPY(n: number): string {
  if (n >= 1_000_000_000) return `¥${(n / 1_000_000_000).toFixed(1)}B`
  if (n >= 1_000_000) return `¥${(n / 1_000_000).toFixed(1)}M`
  if (n >= 10_000) return `¥${(n / 10_000).toFixed(0)}万`
  return `¥${n.toLocaleString()}`
}

function fmtJPYFull(n: number): string {
  return `¥${n.toLocaleString()}`
}

function fmtUSD(n: number): string {
  return `$${Math.round(n / JPY_TO_USD).toLocaleString()}`
}

function NumInput({ label, value, onChange, unit, min, placeholder }: {
  label: string; value: number; onChange: (v: number) => void; unit?: string; min?: number; placeholder?: string
}) {
  return (
    <div>
      <label className="block text-xs text-[#7d92b0] mb-1">{label}</label>
      <div className="flex items-center gap-1">
        {unit && <span className="text-[#7d92b0] text-sm">{unit}</span>}
        <input
          type="number"
          min={min ?? 0}
          value={value || ''}
          placeholder={placeholder ?? '0'}
          onChange={e => onChange(Number(e.target.value))}
          className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d] w-full"
        />
      </div>
    </div>
  )
}

function CostRow({ label, value, indent }: { label: string; value: number; indent?: boolean }) {
  if (value === 0) return null
  return (
    <div className={`flex items-center justify-between py-1.5 ${indent ? 'pl-4' : ''}`}>
      <span className={`text-xs ${indent ? 'text-[#7d92b0]' : 'text-[#a8c0d8]'}`}>{label}</span>
      <span className="text-white text-xs font-mono">{fmtJPY(value)}</span>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function IncidentCostCalculatorPage() {
  const [mode, setMode] = useState<'new' | 'history'>('new')
  const [selectedType, setSelectedType] = useState<IncidentType | null>(null)
  const [direct, setDirect] = useState<DirectCosts>(DEFAULT_DIRECT)
  const [indirect, setIndirect] = useState<IndirectCosts>(DEFAULT_INDIRECT)
  const [savedCalcs, setSavedCalcs] = useState<SavedCalculation[]>([])
  const [selectedSaved, setSelectedSaved] = useState<SavedCalculation | null>(null)
  const [savedNotice, setSavedNotice] = useState(false)
  const [calcName, setCalcName] = useState('')

  // Compute costs
  const laborCost = direct.analyst_count * direct.analyst_hours * direct.analyst_rate
  const toolsCost = direct.ir_services + direct.forensics + direct.legal_response
  const recoveryCost = direct.hardware_replacement + direct.software_replacement
  const legalCost = direct.legal_notification
  const directTotal = laborCost + toolsCost + recoveryCost + legalCost

  const productivityLoss = indirect.downtime_hours * indirect.affected_users * indirect.hourly_productivity
  const repBase = selectedType ? REPUTATION_BASE[selectedType] : 20_000_000
  const repCost = repBase * REPUTATION_LEVELS[indirect.reputation_level].multiplier
  const regulationCost = REGULATION_FINES[indirect.regulation].estimate
  const indirectTotal = productivityLoss + indirect.lost_business + repCost + regulationCost

  const grandTotal = directTotal + indirectTotal
  const grandTotalUSD = grandTotal / JPY_TO_USD
  const costPerRecord = indirect.affected_records > 0 ? grandTotal / indirect.affected_records : 0

  const benchmark = selectedType ? INDUSTRY_BENCHMARKS[selectedType] : null

  const updateDirect = (key: keyof DirectCosts, val: number) => setDirect(d => ({ ...d, [key]: val }))
  const updateIndirect = (key: keyof IndirectCosts, val: number | RegulationFine | ReputationLevel) =>
    setIndirect(d => ({ ...d, [key]: val }))

  const handleSave = () => {
    if (!selectedType) return
    const newCalc: SavedCalculation = {
      id: `sc-${Date.now()}`,
      name: calcName || `${new Date().toLocaleDateString('ja-JP')} ${INCIDENT_TYPES.find(t => t.type === selectedType)?.label ?? ''}`,
      incident_type: selectedType,
      date: new Date().toISOString().slice(0, 10),
      total_jpy: grandTotal,
      total_usd: grandTotalUSD,
    }
    setSavedCalcs(prev => [newCalc, ...prev])
    setSavedNotice(true)
    setTimeout(() => setSavedNotice(false), 3000)
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      <PageDataUnavailable />
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Calculator className="w-7 h-7 text-[#e8002d]" />
            インシデントコスト計算機
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">セキュリティインシデントの直接・間接コストをインタラクティブに試算</p>
        </div>
      </div>

      {/* Mode tabs */}
      <div className="flex border-b border-[#1e2d42]">
        {[
          { id: 'new', label: '新規試算' },
          { id: 'history', label: '過去インシデント分析' },
        ].map(t => (
          <button
            key={t.id}
            onClick={() => setMode(t.id as 'new' | 'history')}
            className={`px-5 py-3 text-sm font-medium transition-colors ${mode === t.id ? 'text-white border-b-2 border-[#e8002d]' : 'text-[#7d92b0] hover:text-white'}`}
          >
            {t.label}
          </button>
        ))}
      </div>

      {/* ── New Estimate Mode ─────────────────────────────────────── */}
      {mode === 'new' && (
        <div className="space-y-6">
          {/* Incident type selector */}
          <div>
            <h2 className="text-white font-semibold mb-4">インシデント種別を選択</h2>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
              {INCIDENT_TYPES.map(({ type, label, icon: Icon, color, description }) => (
                <button
                  key={type}
                  onClick={() => setSelectedType(type)}
                  className={`border rounded-xl p-3 text-left transition-all ${
                    selectedType === type ? color : 'border-[#1e2d42] bg-[#0d1220] hover:border-[#7d92b0]/40'
                  }`}
                >
                  <Icon className={`w-5 h-5 mb-2 ${selectedType === type ? '' : 'text-[#7d92b0]'}`} />
                  <p className={`text-xs font-semibold ${selectedType === type ? '' : 'text-white'}`}>{label}</p>
                  <p className="text-[10px] text-[#7d92b0] mt-0.5 leading-tight">{description}</p>
                </button>
              ))}
            </div>
          </div>

          {selectedType && (
            <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
              {/* Left: Input form */}
              <div className="lg:col-span-2 space-y-4">
                {/* Direct Costs */}
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
                  <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center gap-2">
                    <DollarSign className="w-4 h-4 text-red-400" />
                    <h3 className="text-white font-semibold">直接コスト</h3>
                  </div>
                  <div className="p-5 space-y-5">
                    {/* Labor */}
                    <div>
                      <p className="text-[#7d92b0] text-xs font-medium uppercase mb-3">対応工数</p>
                      <div className="grid grid-cols-3 gap-3">
                        <NumInput label="アナリスト数" value={direct.analyst_count} onChange={v => updateDirect('analyst_count', v)} min={1} />
                        <NumInput label="対応時間 (h)" value={direct.analyst_hours} onChange={v => updateDirect('analyst_hours', v)} />
                        <NumInput label="時間単価 (¥)" value={direct.analyst_rate} onChange={v => updateDirect('analyst_rate', v)} unit="¥" />
                      </div>
                      <div className="mt-2 text-right text-xs text-[#7d92b0]">
                        小計: <span className="text-white font-mono">{fmtJPYFull(laborCost)}</span>
                      </div>
                    </div>

                    {/* Tools */}
                    <div>
                      <p className="text-[#7d92b0] text-xs font-medium uppercase mb-3">ツール・サービス</p>
                      <div className="grid grid-cols-3 gap-3">
                        <NumInput label="外部IR支援 (¥)" value={direct.ir_services} onChange={v => updateDirect('ir_services', v)} unit="¥" />
                        <NumInput label="フォレンジック (¥)" value={direct.forensics} onChange={v => updateDirect('forensics', v)} unit="¥" />
                        <NumInput label="法的対応 (¥)" value={direct.legal_response} onChange={v => updateDirect('legal_response', v)} unit="¥" />
                      </div>
                    </div>

                    {/* Recovery */}
                    <div>
                      <p className="text-[#7d92b0] text-xs font-medium uppercase mb-3">システム復旧</p>
                      <div className="grid grid-cols-2 gap-3">
                        <NumInput label="ハードウェア交換 (¥)" value={direct.hardware_replacement} onChange={v => updateDirect('hardware_replacement', v)} unit="¥" />
                        <NumInput label="ソフトウェア交換 (¥)" value={direct.software_replacement} onChange={v => updateDirect('software_replacement', v)} unit="¥" />
                      </div>
                    </div>

                    {/* Legal */}
                    <div>
                      <p className="text-[#7d92b0] text-xs font-medium uppercase mb-3">法的費用</p>
                      <div className="grid grid-cols-1 gap-3">
                        <NumInput label="通知・法的費用 (¥)" value={direct.legal_notification} onChange={v => updateDirect('legal_notification', v)} unit="¥" />
                      </div>
                    </div>
                  </div>
                </div>

                {/* Indirect Costs */}
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
                  <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center gap-2">
                    <TrendingUp className="w-4 h-4 text-orange-400" />
                    <h3 className="text-white font-semibold">間接コスト</h3>
                  </div>
                  <div className="p-5 space-y-5">
                    {/* Productivity */}
                    <div>
                      <p className="text-[#7d92b0] text-xs font-medium uppercase mb-3">生産性損失</p>
                      <div className="grid grid-cols-3 gap-3">
                        <NumInput label="ダウンタイム (h)" value={indirect.downtime_hours} onChange={v => updateIndirect('downtime_hours', v)} />
                        <NumInput label="影響ユーザー数" value={indirect.affected_users} onChange={v => updateIndirect('affected_users', v)} />
                        <NumInput label="時間生産性 (¥)" value={indirect.hourly_productivity} onChange={v => updateIndirect('hourly_productivity', v)} unit="¥" />
                      </div>
                      <div className="mt-2 text-right text-xs text-[#7d92b0]">
                        小計: <span className="text-white font-mono">{fmtJPYFull(productivityLoss)}</span>
                      </div>
                    </div>

                    {/* Business loss */}
                    <div>
                      <p className="text-[#7d92b0] text-xs font-medium uppercase mb-3">機会損失</p>
                      <NumInput label="事業機会損失 (¥)" value={indirect.lost_business} onChange={v => updateIndirect('lost_business', v)} unit="¥" />
                    </div>

                    {/* Reputation */}
                    <div>
                      <p className="text-[#7d92b0] text-xs font-medium uppercase mb-3">レピュテーション損失</p>
                      <div className="flex gap-2">
                        {REPUTATION_LEVELS.map(({ level, label, multiplier }) => (
                          <button
                            key={level}
                            onClick={() => updateIndirect('reputation_level', level)}
                            className={`flex-1 py-2 rounded-lg text-xs font-medium border transition-all ${
                              indirect.reputation_level === level
                                ? level === 0 ? 'border-green-500/50 bg-green-500/10 text-green-400'
                                : level === 1 ? 'border-yellow-500/50 bg-yellow-500/10 text-yellow-400'
                                : 'border-red-500/50 bg-red-500/10 text-red-400'
                                : 'border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/40'
                            }`}
                          >
                            {label}
                          </button>
                        ))}
                      </div>
                      <div className="mt-2 text-right text-xs text-[#7d92b0]">
                        推定: <span className="text-white font-mono">{fmtJPYFull(repCost)}</span>
                      </div>
                    </div>

                    {/* Regulation */}
                    <div>
                      <p className="text-[#7d92b0] text-xs font-medium uppercase mb-3">規制制裁 (推定値)</p>
                      <select
                        value={indirect.regulation}
                        onChange={e => updateIndirect('regulation', e.target.value as RegulationFine)}
                        className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]"
                      >
                        {Object.entries(REGULATION_FINES).map(([key, { label, estimate }]) => (
                          <option key={key} value={key}>
                            {label}{estimate > 0 ? ` — 推定 ${fmtJPY(estimate)}` : ''}
                          </option>
                        ))}
                      </select>
                    </div>

                    {/* Data breach specific */}
                    <div>
                      <p className="text-[#7d92b0] text-xs font-medium uppercase mb-3">漏洩レコード数 (データ侵害の場合)</p>
                      <NumInput
                        label="影響レコード数"
                        value={indirect.affected_records}
                        onChange={v => updateIndirect('affected_records', v)}
                        placeholder="例: 10000"
                      />
                    </div>
                  </div>
                </div>

                {/* Prevention ROI */}
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
                  <div className="px-5 py-4 border-b border-[#1e2d42] flex items-center gap-2">
                    <Shield className="w-4 h-4 text-green-400" />
                    <h3 className="text-white font-semibold">予防コスト比較</h3>
                    <span className="text-[#7d92b0] text-xs ml-auto">このインシデントをどれだけ防げたか</span>
                  </div>
                  <div className="p-5">
                    <div className="space-y-3">
                      {PREVENTION_ROI.map(({ investment, cost_jpy, saves_pct }) => {
                        const saves = Math.round(grandTotal * (saves_pct[selectedType] / 100))
                        const roi = cost_jpy > 0 ? Math.round((saves - cost_jpy) / cost_jpy * 100) : 0
                        return (
                          <div key={investment} className="border border-[#1e2d42] rounded-lg p-3 bg-[#070d19]">
                            <div className="flex items-start justify-between gap-3">
                              <div className="flex-1">
                                <p className="text-white text-xs font-medium">{investment}</p>
                                <p className="text-[#7d92b0] text-xs mt-0.5">投資: {fmtJPY(cost_jpy)}</p>
                              </div>
                              <div className="text-right">
                                <p className="text-green-400 text-sm font-bold">{fmtJPY(saves)} 節約</p>
                                <p className={`text-xs ${roi > 0 ? 'text-green-400' : 'text-red-400'}`}>
                                  ROI: {roi > 0 ? '+' : ''}{roi}%
                                </p>
                              </div>
                            </div>
                            <div className="mt-2 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                              <div
                                className="h-full rounded-full bg-green-500"
                                style={{ width: `${saves_pct[selectedType]}%` }}
                              />
                            </div>
                            <p className="text-[#7d92b0] text-[10px] mt-1">{saves_pct[selectedType]}% 軽減可能</p>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                </div>
              </div>

              {/* Right: Running total */}
              <div className="space-y-4">
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden sticky top-4">
                  <div className="px-5 py-4 border-b border-[#1e2d42]">
                    <h3 className="text-white font-semibold flex items-center gap-2">
                      <Calculator className="w-4 h-4 text-[#e8002d]" />
                      試算結果
                    </h3>
                  </div>
                  <div className="p-5 space-y-4">
                    {/* Direct subtotal */}
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-white text-sm font-medium">直接コスト</span>
                        <span className="text-white text-sm font-bold font-mono">{fmtJPY(directTotal)}</span>
                      </div>
                      <div className="pl-2 border-l-2 border-red-500/30 space-y-0.5">
                        <CostRow label="対応工数" value={laborCost} indent />
                        <CostRow label="ツール・サービス" value={toolsCost} indent />
                        <CostRow label="システム復旧" value={recoveryCost} indent />
                        <CostRow label="法的費用" value={legalCost} indent />
                      </div>
                    </div>

                    <div className="border-t border-[#1e2d42]" />

                    {/* Indirect subtotal */}
                    <div>
                      <div className="flex items-center justify-between mb-2">
                        <span className="text-white text-sm font-medium">間接コスト</span>
                        <span className="text-white text-sm font-bold font-mono">{fmtJPY(indirectTotal)}</span>
                      </div>
                      <div className="pl-2 border-l-2 border-orange-500/30 space-y-0.5">
                        <CostRow label="生産性損失" value={productivityLoss} indent />
                        <CostRow label="機会損失" value={indirect.lost_business} indent />
                        <CostRow label="レピュテーション" value={repCost} indent />
                        <CostRow label="規制制裁" value={regulationCost} indent />
                      </div>
                    </div>

                    <div className="border-t-2 border-[#1e2d42]" />

                    {/* Grand total */}
                    <div className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-4 space-y-2">
                      <div className="flex items-center justify-between">
                        <span className="text-[#7d92b0] text-sm">合計 (¥)</span>
                        <span className="text-2xl font-bold text-white font-mono">{fmtJPY(grandTotal)}</span>
                      </div>
                      <div className="flex items-center justify-between">
                        <span className="text-[#7d92b0] text-xs">米ドル換算 ($1=¥{JPY_TO_USD})</span>
                        <span className="text-lg font-bold text-blue-400 font-mono">{fmtUSD(grandTotal)}</span>
                      </div>
                      {costPerRecord > 0 && (
                        <div className="flex items-center justify-between border-t border-[#1e2d42] pt-2 mt-2">
                          <span className="text-[#7d92b0] text-xs">1レコードあたり</span>
                          <span className="text-yellow-400 font-mono text-sm">{fmtJPY(costPerRecord)}</span>
                        </div>
                      )}
                    </div>

                    {/* Benchmark comparison */}
                    {benchmark && (
                      <div className="border border-[#1e2d42] rounded-lg p-3 bg-[#070d19]">
                        <p className="text-[#7d92b0] text-xs mb-2 flex items-center gap-1">
                          <BarChart2 className="w-3 h-3" />業界平均比較
                        </p>
                        <div className="flex items-center justify-between mb-1">
                          <span className="text-[#7d92b0] text-xs">業界平均</span>
                          <span className="text-[#7d92b0] text-xs font-mono">{fmtJPY(benchmark.avg_jpy)}</span>
                        </div>
                        <div className="flex items-center justify-between mb-2">
                          <span className="text-white text-xs">今回の試算</span>
                          <span className={`text-xs font-mono font-bold ${grandTotal > benchmark.avg_jpy ? 'text-red-400' : 'text-green-400'}`}>
                            {fmtJPY(grandTotal)}
                          </span>
                        </div>
                        <div className="h-1 bg-[#1e2d42] rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${grandTotal > benchmark.avg_jpy ? 'bg-red-500' : 'bg-green-500'}`}
                            style={{ width: `${Math.min((grandTotal / benchmark.avg_jpy) * 100, 200) / 2}%` }}
                          />
                        </div>
                        <p className="text-[#7d92b0] text-[10px] mt-1.5 italic">{benchmark.description}</p>
                      </div>
                    )}

                    {/* Save */}
                    <div className="space-y-2">
                      <input
                        type="text"
                        placeholder="計算名 (任意)"
                        value={calcName}
                        onChange={e => setCalcName(e.target.value)}
                        className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]"
                      />
                      <button
                        onClick={handleSave}
                        className="w-full flex items-center justify-center gap-2 px-4 py-2.5 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c0001f] transition-colors font-medium"
                      >
                        <Save className="w-4 h-4" />試算結果を保存
                      </button>
                    </div>

                    {savedNotice && (
                      <div className="flex items-center gap-2 px-3 py-2 bg-green-500/10 border border-green-500/30 rounded-lg text-green-400 text-xs">
                        <CheckCircle className="w-3.5 h-3.5" />保存しました
                      </div>
                    )}
                  </div>
                </div>

                {/* Industry benchmarks */}
                <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
                  <div className="px-5 py-4 border-b border-[#1e2d42]">
                    <h3 className="text-white text-sm font-semibold flex items-center gap-2">
                      <Info className="w-4 h-4 text-blue-400" />業界平均コスト
                    </h3>
                  </div>
                  <div className="p-4 space-y-2">
                    {Object.entries(INDUSTRY_BENCHMARKS).map(([type, { avg_jpy }]) => {
                      const info = INCIDENT_TYPES.find(t => t.type === type)
                      return (
                        <div key={type} className="flex items-center justify-between py-1.5 border-b border-[#1e2d42]/50 last:border-0">
                          <span className="text-[#7d92b0] text-xs">{info?.label ?? type}</span>
                          <span className="text-white text-xs font-mono">{fmtJPY(avg_jpy)}</span>
                        </div>
                      )
                    })}
                    <p className="text-[#3d5068] text-[10px] mt-2">※ IBM/Ponemon/BSI 2024レポートより</p>
                  </div>
                </div>
              </div>
            </div>
          )}

          {!selectedType && (
            <div className="text-center py-16 text-[#7d92b0]">
              <Calculator className="w-12 h-12 mx-auto mb-3 opacity-30" />
              <p className="text-sm">インシデント種別を選択してコスト試算を開始してください</p>
            </div>
          )}
        </div>
      )}

      {/* ── History Mode ─────────────────────────────────────────── */}
      {mode === 'history' && (
        <div className="space-y-6">
          {!selectedSaved ? (
            <>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                {savedCalcs.map(calc => {
                  const typeInfo = INCIDENT_TYPES.find(t => t.type === calc.incident_type)
                  const Icon = typeInfo?.icon ?? Calculator
                  const benchmark = INDUSTRY_BENCHMARKS[calc.incident_type]
                  const vsAvg = Math.round((calc.total_jpy / benchmark.avg_jpy - 1) * 100)
                  return (
                    <button
                      key={calc.id}
                      onClick={() => setSelectedSaved(calc)}
                      className="border border-[#1e2d42] rounded-xl p-4 bg-[#0d1220] hover:border-[#7d92b0]/40 text-left transition-all group"
                    >
                      <div className="flex items-start justify-between mb-3">
                        <div className="flex items-center gap-2">
                          <Icon className="w-4 h-4 text-[#7d92b0]" />
                          <span className="text-xs text-[#7d92b0]">{typeInfo?.label}</span>
                        </div>
                        <span className="text-[#7d92b0] text-xs">{calc.date}</span>
                      </div>
                      <p className="text-white font-medium text-sm mb-2">{calc.name}</p>
                      <p className="text-2xl font-bold text-white font-mono">{fmtJPY(calc.total_jpy)}</p>
                      <p className="text-[#7d92b0] text-xs mt-1">{fmtUSD(calc.total_jpy)} USD</p>
                      <div className={`mt-3 flex items-center gap-1 text-xs ${vsAvg > 0 ? 'text-red-400' : 'text-green-400'}`}>
                        {vsAvg > 0 ? <TrendingUp className="w-3 h-3" /> : <TrendingUp className="w-3 h-3 rotate-180" />}
                        業界平均比 {vsAvg > 0 ? '+' : ''}{vsAvg}%
                      </div>
                      <ChevronRight className="w-4 h-4 text-[#3d5068] group-hover:text-[#7d92b0] mt-2" />
                    </button>
                  )
                })}
              </div>

              {/* Industry benchmarks */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
                <div className="px-5 py-4 border-b border-[#1e2d42]">
                  <h3 className="text-white font-semibold">業界平均コスト ベンチマーク</h3>
                </div>
                <div className="p-5">
                  <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
                    {Object.entries(INDUSTRY_BENCHMARKS).map(([type, { avg_jpy, description }]) => {
                      const typeInfo = INCIDENT_TYPES.find(t => t.type === type)
                      const Icon = typeInfo?.icon ?? Calculator
                      return (
                        <div key={type} className="border border-[#1e2d42] rounded-lg p-4 bg-[#070d19]">
                          <div className="flex items-center gap-2 mb-2">
                            <Icon className="w-4 h-4 text-[#7d92b0]" />
                            <span className="text-white text-sm font-medium">{typeInfo?.label}</span>
                          </div>
                          <p className="text-xl font-bold text-white font-mono">{fmtJPY(avg_jpy)}</p>
                          <p className="text-[#7d92b0] text-xs mt-0.5">{fmtUSD(avg_jpy)} USD</p>
                          <p className="text-[#3d5068] text-[10px] mt-2">{description}</p>
                        </div>
                      )
                    })}
                  </div>
                </div>
              </div>
            </>
          ) : (
            /* Selected saved calc detail */
            <div className="space-y-6">
              <button
                onClick={() => setSelectedSaved(null)}
                className="flex items-center gap-2 text-[#7d92b0] hover:text-white text-sm transition-colors"
              >
                <ChevronRight className="w-4 h-4 rotate-180" />一覧に戻る
              </button>

              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* Detail */}
                <div className="space-y-4">
                  <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                    <h3 className="text-white font-semibold mb-4">{selectedSaved.name}</h3>
                    <div className="space-y-3">
                      {[
                        ['種別', INCIDENT_TYPES.find(t => t.type === selectedSaved.incident_type)?.label ?? ''],
                        ['発生日', selectedSaved.date],
                        ['合計コスト', fmtJPYFull(selectedSaved.total_jpy)],
                        ['USD換算', fmtUSD(selectedSaved.total_jpy)],
                      ].map(([k, v]) => (
                        <div key={k} className="flex items-center justify-between py-2 border-b border-[#1e2d42]/50 last:border-0">
                          <span className="text-[#7d92b0] text-sm">{k}</span>
                          <span className="text-white text-sm font-medium">{v}</span>
                        </div>
                      ))}
                    </div>
                  </div>
                </div>

                {/* Comparison + ROI */}
                <div className="space-y-4">
                  <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                    <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                      <BarChart2 className="w-4 h-4 text-blue-400" />業界平均比較
                    </h3>
                    {(() => {
                      const bm = INDUSTRY_BENCHMARKS[selectedSaved.incident_type]
                      const diff = selectedSaved.total_jpy - bm.avg_jpy
                      const pct = Math.round((selectedSaved.total_jpy / bm.avg_jpy - 1) * 100)
                      return (
                        <div className="space-y-3">
                          {[
                            ['業界平均', bm.avg_jpy, 'text-[#7d92b0]'],
                            ['このインシデント', selectedSaved.total_jpy, 'text-white'],
                          ].map(([label, val, color]) => (
                            <div key={label as string} className="flex items-center justify-between">
                              <span className="text-[#7d92b0] text-xs">{label as string}</span>
                              <span className={`text-sm font-mono font-bold ${color as string}`}>{fmtJPY(val as number)}</span>
                            </div>
                          ))}
                          <div className={`flex items-center gap-2 p-3 rounded-lg border text-sm font-medium ${
                            diff > 0 ? 'bg-red-500/10 border-red-500/30 text-red-400' : 'bg-green-500/10 border-green-500/30 text-green-400'
                          }`}>
                            {diff > 0 ? <TrendingUp className="w-4 h-4" /> : <TrendingUp className="w-4 h-4 rotate-180" />}
                            業界平均より {Math.abs(pct)}% {diff > 0 ? '高い' : '低い'} ({diff > 0 ? '+' : ''}{fmtJPY(Math.abs(diff))})
                          </div>
                        </div>
                      )
                    })()}
                  </div>

                  <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                    <h3 className="text-white font-semibold mb-4 flex items-center gap-2">
                      <Shield className="w-4 h-4 text-green-400" />ROI分析 — 投資対効果
                    </h3>
                    <div className="space-y-2.5">
                      {PREVENTION_ROI.map(({ investment, cost_jpy, saves_pct }) => {
                        const saves = Math.round(selectedSaved.total_jpy * (saves_pct[selectedSaved.incident_type] / 100))
                        const roi = cost_jpy > 0 ? Math.round((saves - cost_jpy) / cost_jpy * 100) : 0
                        return (
                          <div key={investment} className="border border-[#1e2d42] rounded-lg p-3">
                            <div className="flex items-start justify-between gap-2">
                              <div>
                                <p className="text-white text-xs font-medium">{investment}</p>
                                <p className="text-[#7d92b0] text-xs">投資額: {fmtJPY(cost_jpy)}</p>
                              </div>
                              <div className="text-right shrink-0">
                                <p className="text-green-400 text-xs font-bold">{fmtJPY(saves)} 節約</p>
                                <p className={`text-[10px] ${roi > 0 ? 'text-green-400' : 'text-red-400'}`}>ROI: {roi > 0 ? '+' : ''}{roi}%</p>
                              </div>
                            </div>
                          </div>
                        )
                      })}
                    </div>
                  </div>
                </div>
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}
