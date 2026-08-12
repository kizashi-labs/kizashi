'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  GitMerge, Shield, Globe, Search, Plus, X, AlertTriangle,
  CheckCircle, TrendingUp, TrendingDown, Zap, Database,
  RefreshCw, ChevronRight, Activity, Eye, AlertCircle,
  BarChart2, Filter, Clock, Info, Star, Layers,
  ArrowRight, Package
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ─── Types ────────────────────────────────────────────────────────────────────

type SourceType = 'commercial' | 'open_source' | 'internal' | 'isac'
type IOCType = 'ip' | 'domain' | 'hash' | 'url' | 'email'
type Verdict = 'malicious' | 'suspicious' | 'clean' | 'unknown'

interface TISource {
  id: string
  name: string
  type: SourceType
  reliability_score: number
  ioc_count: number
  last_updated: string
  enabled: boolean
  false_positive_rate: number
  hit_rate: number
  freshness_score: number
  top_indicator_types: { type: IOCType; count: number }[]
}

interface IOCSourceResult {
  source_id: string
  source_name: string
  verdict: Verdict
  confidence: number
  last_seen: string
  tags: string[]
  details?: string
}

interface FusedIOC {
  ioc: string
  ioc_type: IOCType
  fusion_score: number
  fusion_verdict: Verdict
  confidence: number
  source_results: IOCSourceResult[]
  first_seen: string
  last_seen: string
  tags: string[]
}

interface PipelineStep {
  step: number
  name: string
  items_in: number
  items_out: number
  description: string
}

interface CorrelationRule {
  id: string
  name: string
  description: string
  condition: string
  action: string
  matches_today: number
  enabled: boolean
}

interface FusionStats {
  total_iocs: number
  sources_active: number
  duplicates_removed: number
  correlation_hits: number
  last_sync: string
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_SOURCES: TISource[] = [
  {
    id: 'vt', name: 'VirusTotal', type: 'commercial',
    reliability_score: 95, ioc_count: 142_000, last_updated: new Date(Date.now() - 5 * 60_000).toISOString(),
    enabled: true, false_positive_rate: 2.1, hit_rate: 34.5, freshness_score: 98,
    top_indicator_types: [{ type: 'hash', count: 88000 }, { type: 'ip', count: 32000 }, { type: 'domain', count: 22000 }],
  },
  {
    id: 'otx', name: 'AlienVault OTX', type: 'open_source',
    reliability_score: 78, ioc_count: 280_000, last_updated: new Date(Date.now() - 30 * 60_000).toISOString(),
    enabled: true, false_positive_rate: 8.4, hit_rate: 18.2, freshness_score: 82,
    top_indicator_types: [{ type: 'ip', count: 180000 }, { type: 'domain', count: 70000 }, { type: 'hash', count: 30000 }],
  },
  {
    id: 'shodan', name: 'Shodan', type: 'commercial',
    reliability_score: 88, ioc_count: 52_000, last_updated: new Date(Date.now() - 2 * 3600_000).toISOString(),
    enabled: true, false_positive_rate: 4.2, hit_rate: 22.7, freshness_score: 75,
    top_indicator_types: [{ type: 'ip', count: 52000 }],
  },
  {
    id: 'misp', name: 'MISP', type: 'internal',
    reliability_score: 92, ioc_count: 18_500, last_updated: new Date(Date.now() - 15 * 60_000).toISOString(),
    enabled: true, false_positive_rate: 1.8, hit_rate: 41.0, freshness_score: 94,
    top_indicator_types: [{ type: 'hash', count: 9000 }, { type: 'ip', count: 5500 }, { type: 'domain', count: 4000 }],
  },
  {
    id: 'isac', name: 'FS-ISAC', type: 'isac',
    reliability_score: 90, ioc_count: 7_200, last_updated: new Date(Date.now() - 4 * 3600_000).toISOString(),
    enabled: true, false_positive_rate: 2.5, hit_rate: 28.4, freshness_score: 80,
    top_indicator_types: [{ type: 'ip', count: 4000 }, { type: 'domain', count: 2000 }, { type: 'email', count: 1200 }],
  },
  {
    id: 'custom', name: 'カスタムフィード', type: 'internal',
    reliability_score: 72, ioc_count: 3_400, last_updated: new Date(Date.now() - 8 * 3600_000).toISOString(),
    enabled: false, false_positive_rate: 12.1, hit_rate: 9.8, freshness_score: 55,
    top_indicator_types: [{ type: 'ip', count: 2200 }, { type: 'url', count: 1200 }],
  },
]

const MOCK_PIPELINE: PipelineStep[] = [
  { step: 1, name: 'インジェスト', items_in: 503_100, items_out: 503_100, description: '全ソースからの生IOCを取り込み' },
  { step: 2, name: '正規化', items_in: 503_100, items_out: 412_800, description: '重複削除・フォーマット統一' },
  { step: 3, name: 'エンリッチメント', items_in: 412_800, items_out: 412_800, description: 'クロスソース相関・コンテキスト付与' },
  { step: 4, name: 'スコアリング', items_in: 412_800, items_out: 412_800, description: '信頼度重み付けスコア算出' },
  { step: 5, name: '出力', items_in: 412_800, items_out: 412_800, description: 'アラート強化・IOCブロック・TTA帰属' },
]

const MOCK_FUSED_IOCS: FusedIOC[] = [
  {
    ioc: '185.220.101.42',
    ioc_type: 'ip',
    fusion_score: 94,
    fusion_verdict: 'malicious',
    confidence: 96,
    first_seen: new Date(Date.now() - 30 * 24 * 3600_000).toISOString(),
    last_seen: new Date(Date.now() - 2 * 3600_000).toISOString(),
    tags: ['C2', 'Tor Exit Node', 'APT29'],
    source_results: [
      { source_id: 'vt', source_name: 'VirusTotal', verdict: 'malicious', confidence: 98, last_seen: new Date(Date.now() - 1 * 3600_000).toISOString(), tags: ['C2', 'Ransomware'], details: '52/72 engines detected' },
      { source_id: 'otx', source_name: 'AlienVault OTX', verdict: 'malicious', confidence: 91, last_seen: new Date(Date.now() - 3 * 3600_000).toISOString(), tags: ['Tor', 'C2'], details: '14 pulse references' },
      { source_id: 'shodan', source_name: 'Shodan', verdict: 'suspicious', confidence: 72, last_seen: new Date(Date.now() - 6 * 3600_000).toISOString(), tags: ['Open Ports: 4444,1337'], details: 'Unusual service exposure' },
      { source_id: 'misp', source_name: 'MISP', verdict: 'malicious', confidence: 99, last_seen: new Date(Date.now() - 30 * 60_000).toISOString(), tags: ['APT29', 'Cozy Bear'], details: 'Internal incident correlation' },
    ],
  },
  {
    ioc: 'malware-c2.evil-domain.com',
    ioc_type: 'domain',
    fusion_score: 87,
    fusion_verdict: 'malicious',
    confidence: 89,
    first_seen: new Date(Date.now() - 7 * 24 * 3600_000).toISOString(),
    last_seen: new Date(Date.now() - 4 * 3600_000).toISOString(),
    tags: ['C2', 'DGA', 'Emotet'],
    source_results: [
      { source_id: 'vt', source_name: 'VirusTotal', verdict: 'malicious', confidence: 95, last_seen: new Date(Date.now() - 2 * 3600_000).toISOString(), tags: ['C2', 'Emotet'], details: '45/72 engines' },
      { source_id: 'otx', source_name: 'AlienVault OTX', verdict: 'suspicious', confidence: 82, last_seen: new Date(Date.now() - 5 * 3600_000).toISOString(), tags: ['DGA'], details: '8 pulse references' },
      { source_id: 'misp', source_name: 'MISP', verdict: 'malicious', confidence: 96, last_seen: new Date(Date.now() - 1 * 3600_000).toISOString(), tags: ['Emotet', 'Malspam'], details: 'Campaign tracking' },
    ],
  },
  {
    ioc: 'd41d8cd98f00b204e9800998ecf8427e',
    ioc_type: 'hash',
    fusion_score: 45,
    fusion_verdict: 'suspicious',
    confidence: 52,
    first_seen: new Date(Date.now() - 2 * 24 * 3600_000).toISOString(),
    last_seen: new Date(Date.now() - 12 * 3600_000).toISOString(),
    tags: ['Suspicious', 'Packed'],
    source_results: [
      { source_id: 'vt', source_name: 'VirusTotal', verdict: 'suspicious', confidence: 65, last_seen: new Date(Date.now() - 10 * 3600_000).toISOString(), tags: ['Packed', 'Obfuscated'], details: '12/72 engines flagged' },
      { source_id: 'otx', source_name: 'AlienVault OTX', verdict: 'unknown', confidence: 30, last_seen: new Date(Date.now() - 12 * 3600_000).toISOString(), tags: [], details: 'Low confidence' },
    ],
  },
]

const MOCK_CORRELATION_RULES: CorrelationRule[] = [
  {
    id: 'cr-001',
    name: '同一/24 C2関連付け',
    description: '既知C2と同じ/24 IPサブネットのIPは関連IOCとしてマーク',
    condition: 'ip.subnet(/24) IN known_c2_subnets',
    action: 'tag:related_c2, score_boost:+20',
    matches_today: 14,
    enabled: true,
  },
  {
    id: 'cr-002',
    name: 'マルウェアハッシュ→C2IP',
    description: 'マルウェアサンプルとC2 IPが同一インシデントに関連',
    condition: 'hash.incident_id == ip.incident_id AND ip.verdict == malicious',
    action: 'correlate, tag:same_campaign',
    matches_today: 6,
    enabled: true,
  },
  {
    id: 'cr-003',
    name: '低スコアソース単独検出除外',
    description: '信頼度60未満の単一ソース検出はアラートから除外',
    condition: 'source_count == 1 AND source.reliability < 60',
    action: 'suppress_alert, tag:low_confidence',
    matches_today: 83,
    enabled: true,
  },
  {
    id: 'cr-004',
    name: 'AGE > 30日のIOC降格',
    description: '30日以上更新されていないIOCのスコアを低下',
    condition: 'last_seen > 30d',
    action: 'score_decay:-15, tag:stale',
    matches_today: 211,
    enabled: true,
  },
  {
    id: 'cr-005',
    name: 'ISAC + 内部一致',
    description: 'ISAC及び内部フィードの両方に存在するIOCは優先度昇格',
    condition: 'source:isac AND source:internal',
    action: 'priority:high, score_boost:+25',
    matches_today: 3,
    enabled: false,
  },
]

const MOCK_STATS: FusionStats = {
  total_iocs: 412_800,
  sources_active: 5,
  duplicates_removed: 90_300,
  correlation_hits: 317,
  last_sync: new Date(Date.now() - 5 * 60_000).toISOString(),
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function fmtTime(iso: string): string {
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60_000)
  const hours = Math.floor(mins / 60)
  const days = Math.floor(hours / 24)
  if (days > 0) return `${days}日前`
  if (hours > 0) return `${hours}時間前`
  return `${mins}分前`
}

const SOURCE_TYPE_LABELS: Record<SourceType, string> = {
  commercial: '商用', open_source: 'OSS', internal: '内部', isac: 'ISAC',
}
const SOURCE_TYPE_COLORS: Record<SourceType, string> = {
  commercial: 'bg-blue-500/20 text-blue-400 border-blue-500/30',
  open_source: 'bg-green-500/20 text-green-400 border-green-500/30',
  internal: 'bg-purple-500/20 text-purple-400 border-purple-500/30',
  isac: 'bg-orange-500/20 text-orange-400 border-orange-500/30',
}
const VERDICT_COLORS: Record<Verdict, string> = {
  malicious: 'text-red-400 bg-red-500/10 border-red-500/30',
  suspicious: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30',
  clean: 'text-green-400 bg-green-500/10 border-green-500/30',
  unknown: 'text-gray-400 bg-gray-500/10 border-gray-500/30',
}
const VERDICT_LABELS: Record<Verdict, string> = {
  malicious: '悪意あり', suspicious: '不審', clean: 'クリーン', unknown: '不明',
}

// ─── Sub-components ───────────────────────────────────────────────────────────

function StatCard({ label, value, sub, color }: { label: string; value: string | number; sub?: string; color?: string }) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
      <p className="text-[#7d92b0] text-xs mb-1">{label}</p>
      <p className={`text-2xl font-bold ${color ?? 'text-white'}`}>{value}</p>
      {sub && <p className="text-[#7d92b0] text-xs mt-1">{sub}</p>}
    </div>
  )
}

function ReliabilityBar({ score }: { score: number }) {
  const color = score >= 85 ? 'bg-green-500' : score >= 70 ? 'bg-yellow-500' : 'bg-red-500'
  return (
    <div className="flex items-center gap-2">
      <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color}`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs font-mono text-white w-6 text-right">{score}</span>
    </div>
  )
}

function SourceTypeBadge({ type }: { type: SourceType }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[10px] font-medium border ${SOURCE_TYPE_COLORS[type]}`}>
      {SOURCE_TYPE_LABELS[type]}
    </span>
  )
}

function VerdictBadge({ verdict }: { verdict: Verdict }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${VERDICT_COLORS[verdict]}`}>
      {VERDICT_LABELS[verdict]}
    </span>
  )
}

// ─── Source Detail Modal ──────────────────────────────────────────────────────

function SourceDetailModal({ source, onClose }: { source: TISource; onClose: () => void }) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <div className="flex items-center gap-3">
            <Database className="w-5 h-5 text-[#e8002d]" />
            <div>
              <h3 className="text-white font-semibold">{source.name}</h3>
              <SourceTypeBadge type={source.type} />
            </div>
          </div>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-5">
          {/* Quality Scores */}
          <div>
            <h4 className="text-white text-sm font-medium mb-3">品質スコア</h4>
            <div className="space-y-3">
              {[
                { label: '信頼性スコア', value: source.reliability_score },
                { label: 'フレッシュネス', value: source.freshness_score },
              ].map(({ label, value }) => (
                <div key={label}>
                  <div className="flex justify-between mb-1">
                    <span className="text-[#7d92b0] text-xs">{label}</span>
                    <span className="text-white text-xs font-mono">{value}/100</span>
                  </div>
                  <ReliabilityBar score={value} />
                </div>
              ))}
            </div>
          </div>
          {/* Stats grid */}
          <div className="grid grid-cols-2 gap-3">
            {[
              ['IOC総数', (source.ioc_count ?? 0).toLocaleString()],
              ['最終更新', fmtTime(source.last_updated)],
              ['誤検知率', `${source.false_positive_rate}%`],
              ['ヒット率', `${source.hit_rate}%`],
            ].map(([k, v]) => (
              <div key={k} className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3">
                <p className="text-[#7d92b0] text-xs">{k}</p>
                <p className="text-white text-sm font-medium mt-0.5">{v}</p>
              </div>
            ))}
          </div>
          {/* Top types */}
          <div>
            <h4 className="text-white text-sm font-medium mb-3">主要インジケータータイプ</h4>
            <div className="space-y-2">
              {source.top_indicator_types.map(({ type, count }) => {
                const total = source.ioc_count
                const pct = Math.round((count / total) * 100)
                return (
                  <div key={type} className="flex items-center gap-3">
                    <span className="text-[#7d92b0] text-xs w-20 uppercase">{type}</span>
                    <div className="flex-1 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                      <div className="h-full rounded-full bg-[#e8002d]" style={{ width: `${pct}%` }} />
                    </div>
                    <span className="text-white text-xs font-mono w-16 text-right">{count.toLocaleString()}</span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Add Correlation Rule Modal ───────────────────────────────────────────────

function AddRuleModal({ onClose, onAdd }: { onClose: () => void; onAdd: (rule: Partial<CorrelationRule>) => void }) {
  const [form, setForm] = useState({ name: '', description: '', condition: '', action: '' })
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-lg">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold flex items-center gap-2"><Plus className="w-4 h-4 text-[#e8002d]" />コリレーションルール追加</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-4 h-4" /></button>
        </div>
        <div className="p-5 space-y-4">
          {[
            { key: 'name', label: 'ルール名', placeholder: '例: 同一C2サブネット関連付け' },
            { key: 'description', label: '説明', placeholder: 'ルールの説明を入力' },
            { key: 'condition', label: '条件式', placeholder: '例: ip.subnet(/24) IN known_c2_subnets' },
            { key: 'action', label: 'アクション', placeholder: '例: tag:related_c2, score_boost:+20' },
          ].map(({ key, label, placeholder }) => (
            <div key={key}>
              <label className="block text-xs text-[#7d92b0] mb-1">{label}</label>
              <input
                type="text"
                placeholder={placeholder}
                value={(form as Record<string, string>)[key]}
                onChange={e => setForm(f => ({ ...f, [key]: e.target.value }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-none focus:border-[#e8002d]"
              />
            </div>
          ))}
          <div className="flex gap-3 justify-end pt-2">
            <button onClick={onClose} className="px-4 py-2 text-sm rounded-lg border border-[#1e2d42] text-[#7d92b0] hover:text-white transition-colors">キャンセル</button>
            <button
              onClick={() => form.name && form.condition && onAdd(form)}
              disabled={!form.name || !form.condition}
              className="px-4 py-2 text-sm rounded-lg bg-[#e8002d] text-white hover:bg-[#c0001f] disabled:opacity-40 transition-colors flex items-center gap-2"
            >
              <Plus className="w-4 h-4" />追加
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function ThreatIntelFusionPage() {
  const qc = useQueryClient()
  const [tab, setTab] = useState<'sources' | 'pipeline' | 'ioc' | 'rules' | 'quality'>('sources')
  const [selectedSource, setSelectedSource] = useState<TISource | null>(null)
  const [iocQuery, setIocQuery] = useState('')
  const [iocResult, setIocResult] = useState<FusedIOC | null>(null)
  const [iocSearched, setIocSearched] = useState(false)
  const [showAddRule, setShowAddRule] = useState(false)
  const [localRules, setLocalRules] = useState<CorrelationRule[]>(m(MOCK_CORRELATION_RULES))
  const [localSources, setLocalSources] = useState<TISource[]>(m(MOCK_SOURCES))
  const [pipelineAnimate, setPipelineAnimate] = useState(false)

  const { data: statsData } = useQuery<FusionStats>({
    queryKey: ['ti-fusion-stats'],
    queryFn: () => apiFetch('/api/v1/threat-intel/fusion/stats'),
    retry: false, staleTime: 60_000,
  })
  const stats = statsData ?? m(MOCK_STATS)

  const { data: sourcesData } = useQuery<TISource[]>({
    queryKey: ['ti-fusion-sources'],
    queryFn: () => apiFetch('/api/v1/threat-intel/fusion/sources'),
    retry: false, staleTime: 60_000,
    ...(USE_MOCK ? { initialData: MOCK_SOURCES } : {}),
  })
  const sources = sourcesData ?? localSources

  const handleIOCSearch = () => {
    setIocSearched(true)
    const found = m(MOCK_FUSED_IOCS).find(i => i.ioc.toLowerCase().includes(iocQuery.toLowerCase()))
    setIocResult(found ?? null)
  }

  const toggleSource = (id: string) => {
    setLocalSources(prev => prev.map(s => s.id === id ? { ...s, enabled: !s.enabled } : s))
  }

  const handleAddRule = (rule: Partial<CorrelationRule>) => {
    const newRule: CorrelationRule = {
      id: `cr-${Date.now()}`,
      name: rule.name ?? '',
      description: rule.description ?? '',
      condition: rule.condition ?? '',
      action: rule.action ?? '',
      matches_today: 0,
      enabled: true,
    }
    setLocalRules(prev => [newRule, ...prev])
    setShowAddRule(false)
  }

  useEffect(() => {
    if (tab === 'pipeline') {
      setPipelineAnimate(false)
      setTimeout(() => setPipelineAnimate(true), 100)
    }
  }, [tab])

  const TABS = [
    { id: 'sources', label: 'フィードソース' },
    { id: 'pipeline', label: 'フュージョンパイプライン' },
    { id: 'ioc', label: 'IOC照合' },
    { id: 'rules', label: 'コリレーションルール' },
    { id: 'quality', label: '品質ダッシュボード' },
  ] as const

  return (
    <div className="min-h-screen bg-[#070d19] p-6 space-y-6">
      {/* Header */}
      <div className="flex items-start justify-between gap-4 flex-wrap">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <GitMerge className="w-7 h-7 text-[#e8002d]" />
            脅威インテリジェンスフュージョン
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">複数TIフィードの重複排除・スコアリング・コリレーション</p>
        </div>
        <div className="flex items-center gap-2 text-xs text-[#7d92b0]">
          <Clock className="w-3.5 h-3.5" />
          最終同期: {fmtTime(stats.last_sync)}
        </div>
      </div>

      {/* What is Fusion */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 flex items-start gap-3">
        <Info className="w-5 h-5 text-blue-400 flex-shrink-0 mt-0.5" />
        <div>
          <p className="text-white text-sm font-medium mb-1">フュージョンエンジンとは</p>
          <p className="text-[#7d92b0] text-xs leading-relaxed">
            複数の脅威インテリジェンスフィード（商用・OSS・内部・ISAC）から収集したIOCを自動で正規化・重複排除し、
            ソースの信頼性スコアで重み付けしたフュージョンスコアを算出します。
            クロスソースコリレーションにより誤検知を抑制し、高精度なアラート強化・IOCブロック・脅威アクター帰属を実現します。
          </p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-5 gap-4">
        <StatCard label="フュージョンIOC" value={(stats.total_iocs ?? 0).toLocaleString()} sub="正規化済み" color="text-white" />
        <StatCard label="アクティブソース" value={stats.sources_active} sub="フィード" color="text-green-400" />
        <StatCard label="重複削除" value={(stats.duplicates_removed ?? 0).toLocaleString()} sub="件" color="text-blue-400" />
        <StatCard label="コリレーションヒット" value={stats.correlation_hits} sub="本日" color="text-yellow-400" />
        <StatCard label="ソース数" value={sources.length} sub="登録済み" color="text-white" />
      </div>

      {/* Main card */}
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
        {/* Tabs */}
        <div className="flex border-b border-[#1e2d42] overflow-x-auto">
          {TABS.map(t => (
            <button
              key={t.id}
              onClick={() => setTab(t.id)}
              className={`px-5 py-3 text-sm font-medium transition-colors whitespace-nowrap flex-shrink-0 ${
                tab === t.id ? 'text-white border-b-2 border-[#e8002d]' : 'text-[#7d92b0] hover:text-white'
              }`}
            >
              {t.label}
            </button>
          ))}
        </div>

        <div className="p-5">
          {/* ── Sources Tab ─────────────────────────────────────── */}
          {tab === 'sources' && (
            <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-3 gap-4">
              {(sourcesData ?? localSources).map(source => (
                <div
                  key={source.id}
                  className={`border rounded-xl p-4 transition-all ${source.enabled ? 'border-[#1e2d42] bg-[#070d19]' : 'border-[#1e2d42]/40 bg-[#070d19]/40 opacity-60'}`}
                >
                  <div className="flex items-start justify-between mb-3">
                    <div>
                      <div className="flex items-center gap-2 flex-wrap">
                        <p className="text-white font-semibold text-sm">{source.name}</p>
                        <SourceTypeBadge type={source.type} />
                        {!source.enabled && <span className="text-[10px] text-gray-500">無効</span>}
                      </div>
                      <p className="text-[#7d92b0] text-xs mt-0.5">
                        {(source.ioc_count ?? 0).toLocaleString()} IOC • 更新: {fmtTime(source.last_updated)}
                      </p>
                    </div>
                    <div className="flex items-center gap-2">
                      <button
                        onClick={() => setSelectedSource(source)}
                        className="text-[#7d92b0] hover:text-white transition-colors"
                      >
                        <Eye className="w-4 h-4" />
                      </button>
                      <div
                        onClick={() => toggleSource(source.id)}
                        className={`w-9 h-4.5 rounded-full cursor-pointer relative transition-colors ${source.enabled ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'}`}
                        style={{ width: 36, height: 18 }}
                      >
                        <span className={`absolute top-0.5 w-3.5 h-3.5 rounded-full bg-[#e2e8f4] transition-all ${source.enabled ? 'left-[18px]' : 'left-0.5'}`} />
                      </div>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <div>
                      <div className="flex justify-between mb-1">
                        <span className="text-[#7d92b0] text-xs">信頼性</span>
                        <span className="text-xs font-mono text-white">{source.reliability_score}</span>
                      </div>
                      <ReliabilityBar score={source.reliability_score} />
                    </div>
                  </div>
                  <div className="grid grid-cols-3 gap-2 mt-3">
                    {[
                      ['誤検知', `${source.false_positive_rate}%`, source.false_positive_rate > 5 ? 'text-red-400' : 'text-green-400'],
                      ['ヒット率', `${source.hit_rate}%`, 'text-blue-400'],
                      ['鮮度', `${source.freshness_score}`, 'text-white'],
                    ].map(([k, v, c]) => (
                      <div key={k} className="bg-[#0d1220] rounded-lg p-2 text-center">
                        <p className="text-[#7d92b0] text-[10px]">{k}</p>
                        <p className={`text-sm font-bold ${c}`}>{v}</p>
                      </div>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          )}

          {/* ── Pipeline Tab ─────────────────────────────────────── */}
          {tab === 'pipeline' && (
            <div className="space-y-4">
              <p className="text-[#7d92b0] text-sm">フュージョンパイプラインの各ステップと処理統計</p>
              <div className="flex flex-col gap-3">
                {m(MOCK_PIPELINE).map((step, idx) => (
                  <div key={step.step} className="flex items-stretch gap-3">
                    <div className="flex flex-col items-center">
                      <div className={`w-8 h-8 rounded-full flex items-center justify-center font-bold text-sm flex-shrink-0 transition-all duration-700 ${pipelineAnimate ? 'bg-[#e8002d] text-white' : 'bg-[#1e2d42] text-[#7d92b0]'}`}
                        style={{ transitionDelay: `${idx * 150}ms` }}>
                        {step.step}
                      </div>
                      {idx < m(MOCK_PIPELINE).length - 1 && (
                        <div className={`w-0.5 flex-1 min-h-4 mt-1 transition-all duration-700 ${pipelineAnimate ? 'bg-[#e8002d]/40' : 'bg-[#1e2d42]'}`}
                          style={{ transitionDelay: `${idx * 150 + 100}ms` }} />
                      )}
                    </div>
                    <div className={`flex-1 border rounded-lg p-4 mb-3 transition-all duration-700 ${pipelineAnimate ? 'border-[#1e2d42] bg-[#070d19] opacity-100 translate-x-0' : 'border-[#1e2d42]/30 bg-[#070d19]/50 opacity-0 translate-x-4'}`}
                      style={{ transitionDelay: `${idx * 150}ms` }}>
                      <div className="flex items-start justify-between flex-wrap gap-2">
                        <div>
                          <p className="text-white font-semibold text-sm">{step.name}</p>
                          <p className="text-[#7d92b0] text-xs mt-0.5">{step.description}</p>
                        </div>
                        <div className="flex items-center gap-3 text-xs">
                          <div className="text-right">
                            <p className="text-[#7d92b0]">入力</p>
                            <p className="text-white font-mono">{(step.items_in ?? 0).toLocaleString()}</p>
                          </div>
                          <ArrowRight className="w-3 h-3 text-[#7d92b0]" />
                          <div className="text-right">
                            <p className="text-[#7d92b0]">出力</p>
                            <p className="text-white font-mono">{(step.items_out ?? 0).toLocaleString()}</p>
                          </div>
                          {step.items_in !== step.items_out && (
                            <div className="text-right">
                              <p className="text-[#7d92b0]">削減</p>
                              <p className="text-red-400 font-mono">-{(step.items_in - step.items_out).toLocaleString()}</p>
                            </div>
                          )}
                        </div>
                      </div>
                    </div>
                  </div>
                ))}
              </div>

              <div className="border border-[#1e2d42] rounded-lg p-4 bg-[#070d19]">
                <p className="text-white text-sm font-medium mb-3">出力先</p>
                <div className="flex flex-wrap gap-3">
                  {[
                    { label: 'アラート強化', icon: Shield, color: 'text-blue-400' },
                    { label: 'IOCブロッキング', icon: AlertCircle, color: 'text-red-400' },
                    { label: '脅威アクター帰属', icon: Eye, color: 'text-purple-400' },
                    { label: 'レポート生成', icon: BarChart2, color: 'text-green-400' },
                    { label: 'SIEM転送', icon: Database, color: 'text-yellow-400' },
                  ].map(({ label, icon: Icon, color }) => (
                    <div key={label} className="flex items-center gap-2 px-3 py-2 bg-[#0d1220] border border-[#1e2d42] rounded-lg">
                      <Icon className={`w-4 h-4 ${color}`} />
                      <span className="text-[#7d92b0] text-xs">{label}</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}

          {/* ── IOC Lookup Tab ───────────────────────────────────── */}
          {tab === 'ioc' && (
            <div className="space-y-6">
              <div>
                <p className="text-[#7d92b0] text-sm mb-3">IOC（IP/ドメイン/ハッシュ）を全フィードで照合してフュージョン結果を表示します</p>
                <div className="flex gap-2">
                  <input
                    type="text"
                    placeholder="例: 185.220.101.42, malware-c2.evil-domain.com, d41d8cd9..."
                    value={iocQuery}
                    onChange={e => setIocQuery(e.target.value)}
                    onKeyDown={e => e.key === 'Enter' && handleIOCSearch()}
                    className="flex-1 bg-[#070d19] border border-[#1e2d42] rounded-lg px-4 py-2.5 text-white text-sm focus:outline-none focus:border-[#e8002d]"
                  />
                  <button
                    onClick={handleIOCSearch}
                    className="flex items-center gap-2 px-4 py-2.5 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c0001f] transition-colors"
                  >
                    <Search className="w-4 h-4" />照合
                  </button>
                </div>
              </div>

              {/* Sample IOCs */}
              <div>
                <p className="text-[#7d92b0] text-xs mb-2">サンプルIOC:</p>
                <div className="flex flex-wrap gap-2">
                  {m(MOCK_FUSED_IOCS).map(ioc => (
                    <button
                      key={ioc.ioc}
                      onClick={() => { setIocQuery(ioc.ioc); setIocResult(ioc); setIocSearched(true) }}
                      className="px-3 py-1.5 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-xs font-mono hover:text-white hover:border-[#7d92b0] transition-colors"
                    >
                      {ioc.ioc}
                    </button>
                  ))}
                </div>
              </div>

              {iocSearched && !iocResult && (
                <div className="text-center py-10 text-[#7d92b0]">
                  <Search className="w-8 h-8 mx-auto mb-2 opacity-30" />
                  <p className="text-sm">「{iocQuery}」に一致するIOCが見つかりません</p>
                </div>
              )}

              {iocResult && (
                <div className="space-y-4">
                  {/* Fusion summary */}
                  <div className="border border-[#1e2d42] rounded-xl p-5 bg-[#070d19]">
                    <div className="flex items-start justify-between flex-wrap gap-4">
                      <div>
                        <div className="flex items-center gap-3 flex-wrap">
                          <span className="font-mono text-white text-lg">{iocResult.ioc}</span>
                          <span className="px-2 py-0.5 rounded bg-[#1e2d42] text-[#7d92b0] text-xs uppercase">{iocResult.ioc_type}</span>
                          <VerdictBadge verdict={iocResult.fusion_verdict} />
                        </div>
                        <div className="flex flex-wrap gap-1.5 mt-2">
                          {iocResult.tags.map(t => (
                            <span key={t} className="px-2 py-0.5 rounded bg-[#1e2d42] text-[#7d92b0] text-[10px]">{t}</span>
                          ))}
                        </div>
                      </div>
                      <div className="text-right">
                        <p className="text-[#7d92b0] text-xs">フュージョンスコア</p>
                        <p className={`text-3xl font-bold ${iocResult.fusion_score >= 70 ? 'text-red-400' : iocResult.fusion_score >= 40 ? 'text-yellow-400' : 'text-green-400'}`}>
                          {iocResult.fusion_score}
                        </p>
                        <p className="text-[#7d92b0] text-xs">信頼度: {iocResult.confidence}%</p>
                      </div>
                    </div>
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
                      {[
                        ['初検出', new Date(iocResult.first_seen).toLocaleDateString('ja-JP')],
                        ['最終検出', fmtTime(iocResult.last_seen)],
                        ['ソース数', iocResult.source_results.length],
                        ['悪意判定数', iocResult.source_results.filter(r => r.verdict === 'malicious').length],
                      ].map(([k, v]) => (
                        <div key={k} className="bg-[#0d1220] rounded-lg p-2.5">
                          <p className="text-[#7d92b0] text-xs">{k}</p>
                          <p className="text-white text-sm font-medium mt-0.5">{v}</p>
                        </div>
                      ))}
                    </div>
                  </div>

                  {/* Per-source results */}
                  <div>
                    <h4 className="text-white text-sm font-medium mb-3">ソース別判定結果</h4>
                    <div className="space-y-2">
                      {iocResult.source_results.map(r => (
                        <div key={r.source_id} className="flex items-center gap-4 p-3 border border-[#1e2d42] rounded-lg bg-[#070d19] flex-wrap">
                          <div className="w-28">
                            <p className="text-white text-xs font-medium">{r.source_name}</p>
                            <p className="text-[#7d92b0] text-[10px] mt-0.5">{fmtTime(r.last_seen)}</p>
                          </div>
                          <VerdictBadge verdict={r.verdict} />
                          <div className="flex items-center gap-2 flex-1 min-w-[100px]">
                            <div className="h-1.5 flex-1 bg-[#1e2d42] rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${r.verdict === 'malicious' ? 'bg-red-500' : r.verdict === 'suspicious' ? 'bg-yellow-500' : 'bg-green-500'}`}
                                style={{ width: `${r.confidence}%` }}
                              />
                            </div>
                            <span className="text-xs font-mono text-white w-8">{r.confidence}%</span>
                          </div>
                          <div className="flex flex-wrap gap-1">
                            {r.tags.slice(0, 3).map(t => <span key={t} className="px-1.5 py-0.5 rounded bg-[#1e2d42] text-[#7d92b0] text-[10px]">{t}</span>)}
                          </div>
                          {r.details && <p className="text-[#7d92b0] text-xs italic">{r.details}</p>}
                        </div>
                      ))}
                    </div>
                  </div>
                </div>
              )}
            </div>
          )}

          {/* ── Correlation Rules Tab ────────────────────────────── */}
          {tab === 'rules' && (
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <p className="text-[#7d92b0] text-sm">{localRules.length} ルール登録済み</p>
                <button
                  onClick={() => setShowAddRule(true)}
                  className="flex items-center gap-2 px-3 py-1.5 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c0001f] transition-colors"
                >
                  <Plus className="w-4 h-4" />ルール追加
                </button>
              </div>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-[#1e2d42]">
                      {['ルール名', '条件', 'アクション', '本日マッチ', '状態', ''].map(h => (
                        <th key={h} className="text-left text-[#7d92b0] text-xs font-medium px-3 py-2">{h}</th>
                      ))}
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-[#1e2d42]/50">
                    {localRules.map(rule => (
                      <tr key={rule.id} className="hover:bg-[#0a1428]/40 transition-colors">
                        <td className="px-3 py-3">
                          <p className="text-white text-xs font-medium">{rule.name}</p>
                          <p className="text-[#7d92b0] text-[10px] mt-0.5">{rule.description}</p>
                        </td>
                        <td className="px-3 py-3 font-mono text-xs text-[#a8c0d8] max-w-[160px] truncate" title={rule.condition}>{rule.condition}</td>
                        <td className="px-3 py-3 font-mono text-xs text-purple-300 max-w-[140px] truncate" title={rule.action}>{rule.action}</td>
                        <td className="px-3 py-3">
                          <span className={`text-sm font-bold ${rule.matches_today > 50 ? 'text-yellow-400' : 'text-white'}`}>
                            {rule.matches_today}
                          </span>
                        </td>
                        <td className="px-3 py-3">
                          <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-xs font-medium border ${rule.enabled ? 'bg-green-500/20 text-green-400 border-green-500/30' : 'bg-gray-500/20 text-gray-400 border-gray-500/30'}`}>
                            {rule.enabled ? '有効' : '無効'}
                          </span>
                        </td>
                        <td className="px-3 py-3">
                          <button
                            onClick={() => setLocalRules(prev => prev.map(r => r.id === rule.id ? { ...r, enabled: !r.enabled } : r))}
                            className="text-xs text-[#7d92b0] hover:text-white border border-[#1e2d42] px-2 py-1 rounded transition-colors"
                          >
                            {rule.enabled ? '無効化' : '有効化'}
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </div>
          )}

          {/* ── Quality Dashboard Tab ────────────────────────────── */}
          {tab === 'quality' && (
            <div className="space-y-6">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* False positive rate */}
                <div className="border border-[#1e2d42] rounded-xl p-4 bg-[#070d19]">
                  <h4 className="text-white text-sm font-semibold mb-4 flex items-center gap-2">
                    <AlertTriangle className="w-4 h-4 text-yellow-400" />誤検知率
                  </h4>
                  <div className="space-y-3">
                    {(sourcesData ?? localSources).filter(s => s.enabled).map(s => (
                      <div key={s.id} className="flex items-center gap-3">
                        <span className="text-[#7d92b0] text-xs w-28 truncate">{s.name}</span>
                        <div className="flex-1 h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${s.false_positive_rate > 8 ? 'bg-red-500' : s.false_positive_rate > 4 ? 'bg-yellow-500' : 'bg-green-500'}`}
                            style={{ width: `${Math.min(s.false_positive_rate * 5, 100)}%` }}
                          />
                        </div>
                        <span className={`text-xs font-mono w-10 text-right ${s.false_positive_rate > 8 ? 'text-red-400' : s.false_positive_rate > 4 ? 'text-yellow-400' : 'text-green-400'}`}>
                          {s.false_positive_rate}%
                        </span>
                      </div>
                    ))}
                  </div>
                </div>

                {/* Hit rate */}
                <div className="border border-[#1e2d42] rounded-xl p-4 bg-[#070d19]">
                  <h4 className="text-white text-sm font-semibold mb-4 flex items-center gap-2">
                    <TrendingUp className="w-4 h-4 text-green-400" />ヒット率（アラートトリガー）
                  </h4>
                  <div className="space-y-3">
                    {(sourcesData ?? localSources).filter(s => s.enabled).map(s => (
                      <div key={s.id} className="flex items-center gap-3">
                        <span className="text-[#7d92b0] text-xs w-28 truncate">{s.name}</span>
                        <div className="flex-1 h-2 bg-[#1e2d42] rounded-full overflow-hidden">
                          <div className="h-full rounded-full bg-blue-500" style={{ width: `${s.hit_rate}%` }} />
                        </div>
                        <span className="text-blue-400 text-xs font-mono w-10 text-right">{s.hit_rate}%</span>
                      </div>
                    ))}
                  </div>
                </div>
              </div>

              {/* Recommendations */}
              <div className="border border-[#1e2d42] rounded-xl p-4 bg-[#070d19]">
                <h4 className="text-white text-sm font-semibold mb-4 flex items-center gap-2">
                  <Star className="w-4 h-4 text-yellow-400" />推奨アクション
                </h4>
                <div className="space-y-3">
                  {[
                    { type: 'warn', msg: 'カスタムフィード: 誤検知率12.1%は高すぎます。フィルタリング強化またはソース見直しを推奨します。' },
                    { type: 'warn', msg: 'AlienVault OTX: ヒット率18.2%は他ソースより低めです。低信頼度IOCの自動フィルタリングを検討してください。' },
                    { type: 'info', msg: 'VirusTotal + MISP の組み合わせは最も高いヒット率（34.5% / 41.0%）を示しています。優先ソースとして設定することを推奨します。' },
                    { type: 'success', msg: '内部MISP: 誤検知率1.8%、ヒット率41.0% — 最高品質ソースです。スコアリング重みを増加することを推奨します。' },
                  ].map((item, i) => (
                    <div key={i} className={`flex items-start gap-2 p-3 rounded-lg border text-xs ${
                      item.type === 'warn' ? 'bg-yellow-500/5 border-yellow-500/20 text-yellow-300' :
                      item.type === 'success' ? 'bg-green-500/5 border-green-500/20 text-green-300' :
                      'bg-blue-500/5 border-blue-500/20 text-blue-300'
                    }`}>
                      {item.type === 'warn' ? <AlertTriangle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" /> :
                       item.type === 'success' ? <CheckCircle className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" /> :
                       <Info className="w-3.5 h-3.5 flex-shrink-0 mt-0.5" />}
                      {item.msg}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </div>
      </div>

      {selectedSource && <SourceDetailModal source={selectedSource} onClose={() => setSelectedSource(null)} />}
      {showAddRule && <AddRuleModal onClose={() => setShowAddRule(false)} onAdd={handleAddRule} />}
    </div>
  )
}
