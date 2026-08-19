'use client'

import { useState, useMemo } from 'react'
import { useQuery, useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Cloud, Server, Database, HardDrive, Zap, Shield,
  AlertTriangle, CheckCircle, RefreshCw, X, ChevronDown,
  Settings, Eye, Activity, TrendingUp, Globe, Lock,
  ChevronRight, Filter, Search, ExternalLink
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'
import { PageSaveFailed } from '@/components/PageSaveFailed'

// ── Types ──────────────────────────────────────────────────────────────────────

type Provider = 'AWS' | 'Azure' | 'GCP'
type AssetType = 'EC2' | 'S3' | 'RDS' | 'VM' | 'Storage' | 'Function' | 'CloudSQL' | 'Blob' | 'Database'
type RiskLevel = 'critical' | 'high' | 'medium' | 'low'

interface CloudAsset {
  id: string
  name: string
  provider: Provider
  asset_type: AssetType
  region: string
  account_id: string
  risk_score: number
  status: 'running' | 'stopped' | 'unknown'
  last_seen: string
  tags: Record<string, string>
  config: Record<string, unknown>
  risk_factors: string[]
}

interface ProviderConfig {
  provider: Provider
  connected: boolean
  last_sync?: string
  asset_count: number
  fields: { key: string; label: string; masked: boolean; value: string }[]
}

// ── Helpers ────────────────────────────────────────────────────────────────────

function fmtDateTime(iso?: string): string {
  if (!iso) return '—'
  try {
    return new Date(iso).toLocaleString('ja-JP', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit'
    })
  } catch { return '—' }
}

function getRiskLevel(score: number): RiskLevel {
  if (score >= 80) return 'critical'
  if (score >= 60) return 'high'
  if (score >= 40) return 'medium'
  return 'low'
}

const PROVIDER_STYLES: Record<Provider, { bg: string; text: string; border: string; color: string }> = {
  AWS:   { bg: 'bg-orange-900/40', text: 'text-orange-300', border: 'border-orange-700/50', color: '#f97316' },
  Azure: { bg: 'bg-blue-900/40',   text: 'text-blue-300',   border: 'border-blue-700/50',   color: '#3b82f6' },
  GCP:   { bg: 'bg-green-900/40',  text: 'text-green-300',  border: 'border-green-700/50',  color: '#22c55e' },
}

const RISK_STYLES: Record<RiskLevel, { bg: string; text: string; border: string }> = {
  critical: { bg: 'bg-red-900/40',    text: 'text-red-300',    border: 'border-red-700/50' },
  high:     { bg: 'bg-orange-900/40', text: 'text-orange-300', border: 'border-orange-700/50' },
  medium:   { bg: 'bg-yellow-900/40', text: 'text-yellow-300', border: 'border-yellow-700/50' },
  low:      { bg: 'bg-green-900/40',  text: 'text-green-300',  border: 'border-green-700/50' },
}

const RISK_LABELS: Record<RiskLevel, string> = {
  critical: 'クリティカル', high: '高', medium: '中', low: '低'
}

const STATUS_STYLES: Record<string, string> = {
  running: 'bg-green-900/40 text-green-300 border border-green-700/50',
  stopped: 'bg-[#161f33] text-[#8899aa] border border-[#1e2d42]',
  unknown: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/50',
}

const STATUS_LABELS: Record<string, string> = {
  running: '稼働中', stopped: '停止', unknown: '不明'
}

const ALL_TYPES: AssetType[] = ['EC2', 'S3', 'RDS', 'VM', 'Storage', 'Function', 'CloudSQL', 'Blob', 'Database']

// ── Stat Card ─────────────────────────────────────────────────────────────────

function StatCard({ label, value, icon: Icon, color = '#7d92b0' }: {
  label: string; value: string | number; icon: React.ElementType; color?: string
}) {
  return (
    <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4 flex items-center gap-4">
      <div className="w-10 h-10 rounded-lg flex items-center justify-center shrink-0"
           style={{ backgroundColor: `${color}20` }}>
        <Icon className="w-5 h-5" style={{ color }} />
      </div>
      <div>
        <p className="text-[#7d92b0] text-xs">{label}</p>
        <p className="text-white text-xl font-bold">{value}</p>
      </div>
    </div>
  )
}

// ── Asset Detail Panel ─────────────────────────────────────────────────────────

function AssetDetailPanel({ asset, onClose }: { asset: CloudAsset; onClose: () => void }) {
  const [configExpanded, setConfigExpanded] = useState(false)
  const ps = PROVIDER_STYLES[asset.provider]
  const rl = getRiskLevel(asset.risk_score)
  const rs = RISK_STYLES[rl]

  return (
    <div className="fixed inset-y-0 right-0 z-40 w-[420px] bg-[#0d1220] border-l border-[#1e2d42] flex flex-col shadow-2xl">
      {/* Header */}
      <div className="flex items-center justify-between p-5 border-b border-[#1e2d42]">
        <div>
          <h3 className="text-white font-bold">{asset.name}</h3>
          <div className="flex items-center gap-2 mt-1">
            <span className={`text-xs px-2 py-0.5 rounded-full border ${ps.bg} ${ps.text} ${ps.border}`}>
              {asset.provider}
            </span>
            <span className="text-[#7d92b0] text-xs">{asset.asset_type}</span>
          </div>
        </div>
        <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
          <X className="w-5 h-5" />
        </button>
      </div>

      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Basic info */}
        <div className="space-y-3">
          <h4 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wide">基本情報</h4>
          {[
            ['リージョン', asset.region],
            ['アカウント / サブスクリプション', asset.account_id],
            ['ステータス', null],
            ['最終確認', fmtDateTime(asset.last_seen)],
          ].map(([label, value]) => (
            <div key={label as string} className="flex justify-between items-center">
              <span className="text-[#7d92b0] text-sm">{label}</span>
              {label === 'ステータス' ? (
                <span className={`text-xs px-2 py-0.5 rounded-full ${STATUS_STYLES[asset.status]}`}>
                  {STATUS_LABELS[asset.status]}
                </span>
              ) : (
                <span className="text-white text-sm font-mono text-right max-w-[220px] truncate">{value as string}</span>
              )}
            </div>
          ))}
        </div>

        {/* Risk */}
        <div className="space-y-3">
          <h4 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wide">リスク評価</h4>
          <div className="flex items-center justify-between">
            <span className="text-[#7d92b0] text-sm">リスクスコア</span>
            <div className="flex items-center gap-2">
              <span className={`text-xs px-2 py-0.5 rounded-full border ${rs.bg} ${rs.text} ${rs.border}`}>
                {RISK_LABELS[rl]}
              </span>
              <span className={`text-lg font-bold ${rs.text}`}>{asset.risk_score}</span>
            </div>
          </div>
          <div className="w-full h-2 bg-[#1e2d42] rounded-full overflow-hidden">
            <div className="h-full rounded-full transition-all"
              style={{
                width: `${asset.risk_score}%`,
                backgroundColor: asset.risk_score >= 80 ? '#ef4444'
                  : asset.risk_score >= 60 ? '#f97316'
                  : asset.risk_score >= 40 ? '#eab308' : '#22c55e'
              }} />
          </div>
          {asset.risk_factors.length > 0 && (
            <div className="space-y-1.5">
              <p className="text-[#7d92b0] text-xs">リスク要因:</p>
              {asset.risk_factors.map((f, i) => (
                <div key={i} className="flex items-center gap-2 text-xs text-orange-300">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  {f}
                </div>
              ))}
            </div>
          )}
        </div>

        {/* Tags */}
        {Object.keys(asset.tags).length > 0 && (
          <div className="space-y-2">
            <h4 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wide">タグ</h4>
            <div className="flex flex-wrap gap-2">
              {Object.entries(asset.tags).map(([k, v]) => (
                <span key={k} className="text-xs bg-[#161f33] border border-[#1e2d42] rounded-sm px-2 py-0.5 text-[#7d92b0]">
                  {k}: <span className="text-white">{v}</span>
                </span>
              ))}
            </div>
          </div>
        )}

        {/* Config */}
        <div className="space-y-2">
          <button
            onClick={() => setConfigExpanded(!configExpanded)}
            className="flex items-center justify-between w-full">
            <h4 className="text-[#7d92b0] text-xs font-semibold uppercase tracking-wide">設定情報</h4>
            <ChevronDown className={`w-4 h-4 text-[#7d92b0] transition-transform ${configExpanded ? 'rotate-180' : ''}`} />
          </button>
          {configExpanded && (
            <pre className="bg-[#070d19] border border-[#1e2d42] rounded-lg p-3 text-xs text-[#7d92b0] overflow-auto max-h-48 font-mono">
              {JSON.stringify(asset.config, null, 2)}
            </pre>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Provider Config Modal ──────────────────────────────────────────────────────

function ProviderConfigModal({ config, onClose }: { config: ProviderConfig; onClose: () => void }) {
  const ps = PROVIDER_STYLES[config.provider]
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-sm">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6 w-full max-w-md">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-white font-bold text-lg flex items-center gap-2">
            <Settings className="w-5 h-5 text-[#7d92b0]" />
            {config.provider} 設定
          </h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white transition-colors">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="space-y-4">
          {config.fields.map(field => (
            <div key={field.key}>
              <label className="block text-[#7d92b0] text-xs mb-1.5">{field.label}</label>
              <input
                type={field.masked ? 'password' : 'text'}
                defaultValue={field.value}
                className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-white text-sm focus:outline-hidden focus:border-[#e8002d]/50 font-mono"
              />
            </div>
          ))}
        </div>
        <div className="flex gap-3 mt-6">
          <button onClick={onClose}
            className="flex-1 px-4 py-2 border border-[#1e2d42] text-[#7d92b0] rounded-lg text-sm hover:bg-[#19253d] transition-colors">
            キャンセル
          </button>
          <button onClick={onClose}
            className="flex-1 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] text-white rounded-lg text-sm font-medium transition-colors">
            保存
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Risk Donut Chart (SVG) ─────────────────────────────────────────────────────

function RiskDonutChart({ assets }: { assets: CloudAsset[] }) {
  const counts = {
    critical: assets.filter(a => getRiskLevel(a.risk_score) === 'critical').length,
    high:     assets.filter(a => getRiskLevel(a.risk_score) === 'high').length,
    medium:   assets.filter(a => getRiskLevel(a.risk_score) === 'medium').length,
    low:      assets.filter(a => getRiskLevel(a.risk_score) === 'low').length,
  }
  const total = assets.length
  const colors = { critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }
  const labels = { critical: 'クリティカル', high: '高', medium: '中', low: '低' }

  // Build donut segments
  const r = 60, cx = 80, cy = 80, stroke = 20
  const circumference = 2 * Math.PI * r
  let offset = 0
  const segments = (['critical', 'high', 'medium', 'low'] as RiskLevel[]).map(level => {
    const pct = total > 0 ? counts[level] / total : 0
    const dashArr = pct * circumference
    const seg = { level, count: counts[level], pct, dashArr, offset }
    offset += dashArr
    return seg
  })

  return (
    <div className="flex items-center gap-8">
      <svg width="160" height="160" viewBox="0 0 160 160">
        {total === 0 ? (
          <circle cx={cx} cy={cy} r={r} fill="none" stroke="#1e2d42" strokeWidth={stroke} />
        ) : segments.map(seg => (
          <circle key={seg.level}
            cx={cx} cy={cy} r={r}
            fill="none"
            stroke={colors[seg.level]}
            strokeWidth={stroke}
            strokeDasharray={`${seg.dashArr} ${circumference - seg.dashArr}`}
            strokeDashoffset={-seg.offset}
            transform={`rotate(-90 ${cx} ${cy})`}
          />
        ))}
        <text x={cx} y={cy - 8} textAnchor="middle" fill="white" fontSize="24" fontWeight="bold">{total}</text>
        <text x={cx} y={cy + 14} textAnchor="middle" fill="#7d92b0" fontSize="10">アセット</text>
      </svg>
      <div className="space-y-2">
        {(['critical', 'high', 'medium', 'low'] as RiskLevel[]).map(level => (
          <div key={level} className="flex items-center gap-3">
            <div className="w-3 h-3 rounded-full shrink-0" style={{ backgroundColor: colors[level] }} />
            <span className="text-[#7d92b0] text-sm w-20">{labels[level]}</span>
            <span className="text-white font-bold text-sm">{counts[level]}</span>
            <span className="text-[#7d92b0] text-xs">
              ({total > 0 ? Math.round((counts[level] / total) * 100) : 0}%)
            </span>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Risk By Provider Chart (SVG horizontal bars) ───────────────────────────────

function RiskByProviderChart({ assets }: { assets: CloudAsset[] }) {
  const providers: Provider[] = ['AWS', 'Azure', 'GCP']
  const maxAvg = 100

  return (
    <svg width="100%" height={providers.length * 52 + 20} style={{ display: 'block' }}>
      {providers.map((p, i) => {
        const pAssets = assets.filter(a => a.provider === p)
        const avg = pAssets.length > 0
          ? Math.round(pAssets.reduce((s, a) => s + a.risk_score, 0) / pAssets.length)
          : 0
        const barW = (avg / maxAvg) * 200
        const color = PROVIDER_STYLES[p].color
        const y = i * 52 + 10

        return (
          <g key={p}>
            <text x={0} y={y + 14} fill="#7d92b0" fontSize="12">{p}</text>
            <rect x={60} y={y} width={200} height={20} rx={4} fill="#1e2d42" />
            <rect x={60} y={y} width={barW} height={20} rx={4} fill={color} opacity={0.8} />
            <text x={270} y={y + 14} fill="white" fontSize="12" fontWeight="bold">{avg}</text>
            <text x={295} y={y + 14} fill="#7d92b0" fontSize="11">(avg)</text>
          </g>
        )
      })}
    </svg>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function CloudAssetsPage() {
  const [activeTab, setActiveTab] = useState<'assets' | 'risk' | 'providers'>('assets')
  const [selectedProvider, setSelectedProvider] = useState<Provider | 'ALL'>('ALL')
  const [selectedTypes, setSelectedTypes] = useState<AssetType[]>([])
  const [selectedRegion, setSelectedRegion] = useState<string>('all')
  const [selectedRisk, setSelectedRisk] = useState<string>('all')
  const [detailAsset, setDetailAsset] = useState<CloudAsset | null>(null)
  const [configModal, setConfigModal] = useState<ProviderConfig | null>(null)
  const [syncingProvider, setSyncingProvider] = useState<Provider | null>(null)

  const { data: assets = [] } = useQuery<CloudAsset[], Error, CloudAsset[]>({
    queryKey: ['cloud-assets'],
    queryFn: (): Promise<CloudAsset[]> => apiFetch('/api/v1/cloud-assets').then((r: any) => Array.isArray(r) ? r : (r?.data ?? [])).catch(() => []) as Promise<CloudAsset[]>,
    staleTime: 60_000,
  })

  const { data: providerConfigs = [] } = useQuery<ProviderConfig[], Error, ProviderConfig[]>({
    queryKey: ['cloud-provider-configs'],
    queryFn: (): Promise<ProviderConfig[]> => apiFetch('/api/v1/cloud-assets/providers') as Promise<ProviderConfig[]>,
    staleTime: 60_000,
  })

  const syncMutation = useMutation({
    mutationFn: (provider: Provider) => {
      setSyncingProvider(provider)
      return apiFetch('/api/v1/cloud-assets/sync', {
        method: 'POST', body: JSON.stringify({ provider })
      })
    },
    onSettled: () => setSyncingProvider(null),
  })

  const riskCalcMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/cloud-assets/${id}/risk`, { method: 'POST' }),
  })

  const allRegions = useMemo(() => {
    const regions = [...new Set(assets.map(a => a.region))].sort()
    return regions
  }, [assets])

  const filteredAssets = useMemo(() => {
    return assets.filter(a => {
      if (selectedProvider !== 'ALL' && a.provider !== selectedProvider) return false
      if (selectedTypes.length > 0 && !selectedTypes.includes(a.asset_type)) return false
      if (selectedRegion !== 'all' && a.region !== selectedRegion) return false
      if (selectedRisk !== 'all' && getRiskLevel(a.risk_score) !== selectedRisk) return false
      return true
    })
  }, [assets, selectedProvider, selectedTypes, selectedRegion, selectedRisk])

  const highRiskAssets = useMemo(() =>
    assets.filter(a => a.risk_score >= 60).sort((a, b) => b.risk_score - a.risk_score).slice(0, 10),
    [assets])

  const awsCount = assets.filter(a => a.provider === 'AWS').length
  const azureCount = assets.filter(a => a.provider === 'Azure').length
  const gcpCount = assets.filter(a => a.provider === 'GCP').length
  const highRiskCount = assets.filter(a => getRiskLevel(a.risk_score) === 'critical' || getRiskLevel(a.risk_score) === 'high').length

  const toggleType = (t: AssetType) => {
    setSelectedTypes(prev =>
      prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t]
    )
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      <PageSaveFailed />
      {/* Overlay for side panel */}
      {detailAsset && (
        <div className="fixed inset-0 z-30 bg-black/20" onClick={() => setDetailAsset(null)} />
      )}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-2xl font-bold text-white flex items-center gap-3">
            <Cloud className="w-7 h-7 text-[#e8002d]" />
            クラウドアセット
          </h1>
          <p className="text-[#7d92b0] text-sm mt-1">AWS・Azure・GCP リソースの統合管理</p>
        </div>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-5 gap-4 mb-6">
        <StatCard label="総アセット" value={assets.length} icon={Cloud} color="#7d92b0" />
        <StatCard label="AWS" value={awsCount} icon={Server} color="#f97316" />
        <StatCard label="Azure" value={azureCount} icon={HardDrive} color="#3b82f6" />
        <StatCard label="GCP" value={gcpCount} icon={Database} color="#22c55e" />
        <StatCard label="高リスクアセット" value={highRiskCount} icon={AlertTriangle} color="#e8002d" />
      </div>

      {/* Tabs */}
      <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit mb-6">
        {([['assets', 'アセット一覧'], ['risk', 'リスク分析'], ['providers', 'プロバイダー設定']] as const).map(([key, label]) => (
          <button key={key}
            onClick={() => setActiveTab(key)}
            className={`px-4 py-2 rounded-sm text-sm font-medium transition-colors ${
              activeTab === key ? 'bg-[#1d2f4a] text-white' : 'text-[#7d92b0] hover:text-white'
            }`}>
            {label}
          </button>
        ))}
      </div>

      {/* ── アセット一覧 Tab ─────────────────────────────────────────────────── */}
      {activeTab === 'assets' && (
        <div>
          {/* Filter bar */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4 mb-4 space-y-3">
            {/* Provider pills */}
            <div className="flex items-center gap-2 flex-wrap">
              <span className="text-[#7d92b0] text-xs">プロバイダー:</span>
              {(['ALL', 'AWS', 'Azure', 'GCP'] as const).map(p => (
                <button key={p}
                  onClick={() => setSelectedProvider(p)}
                  className={`px-3 py-1 rounded-full text-xs font-medium transition-colors border ${
                    selectedProvider === p
                      ? p === 'ALL' ? 'bg-[#1d2f4a] text-white border-[#e8002d]/50'
                        : p === 'AWS' ? 'bg-orange-900/60 text-orange-200 border-orange-600'
                        : p === 'Azure' ? 'bg-blue-900/60 text-blue-200 border-blue-600'
                        : 'bg-green-900/60 text-green-200 border-green-600'
                      : 'bg-[#070d19] text-[#7d92b0] border-[#1e2d42] hover:border-[#2a3f5c]'
                  }`}>
                  {p}
                </button>
              ))}
            </div>

            <div className="flex items-center gap-3 flex-wrap">
              {/* Asset type multi-select */}
              <div className="flex items-center gap-2 flex-wrap">
                <span className="text-[#7d92b0] text-xs">タイプ:</span>
                {ALL_TYPES.map(t => (
                  <button key={t}
                    onClick={() => toggleType(t)}
                    className={`px-2 py-0.5 rounded-sm text-xs transition-colors border ${
                      selectedTypes.includes(t)
                        ? 'bg-[#1d2f4a] text-white border-[#e8002d]/50'
                        : 'bg-[#070d19] text-[#7d92b0] border-[#1e2d42] hover:border-[#2a3f5c]'
                    }`}>
                    {t}
                  </button>
                ))}
              </div>

              {/* Region */}
              <select value={selectedRegion} onChange={e => setSelectedRegion(e.target.value)}
                className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-white text-xs focus:outline-hidden focus:border-[#e8002d]/50">
                <option value="all">全リージョン</option>
                {allRegions.map(r => <option key={r} value={r}>{r}</option>)}
              </select>

              {/* Risk level */}
              <select value={selectedRisk} onChange={e => setSelectedRisk(e.target.value)}
                className="bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-1.5 text-white text-xs focus:outline-hidden focus:border-[#e8002d]/50">
                <option value="all">全リスクレベル</option>
                <option value="critical">クリティカル</option>
                <option value="high">高</option>
                <option value="medium">中</option>
                <option value="low">低</option>
              </select>
            </div>
          </div>

          {/* Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['名前', 'プロバイダー', 'タイプ', 'リージョン', 'アカウント', 'リスク', 'ステータス', '最終確認', ''].map(h => (
                    <th key={h} className="px-4 py-3 text-left text-xs text-[#7d92b0] font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredAssets.length === 0 ? (
                  <tr>
                    <td colSpan={9} className="px-4 py-8 text-center text-[#7d92b0] text-sm">
                      アセットがありません
                    </td>
                  </tr>
                ) : filteredAssets.map(asset => {
                  const ps = PROVIDER_STYLES[asset.provider]
                  const rl = getRiskLevel(asset.risk_score)
                  const rs = RISK_STYLES[rl]
                  return (
                    <tr key={asset.id}
                      onClick={() => setDetailAsset(asset)}
                      className="border-b border-[#1e2d42]/50 hover:bg-[#19253d]/30 transition-colors cursor-pointer">
                      <td className="px-4 py-3 text-white text-sm font-medium">{asset.name}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full border ${ps.bg} ${ps.text} ${ps.border}`}>
                          {asset.provider}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] text-sm">{asset.asset_type}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-sm">{asset.region}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs font-mono truncate max-w-[120px]">{asset.account_id}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full border font-bold ${rs.bg} ${rs.text} ${rs.border}`}>
                          {asset.risk_score}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full ${STATUS_STYLES[asset.status]}`}>
                          {STATUS_LABELS[asset.status]}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{fmtDateTime(asset.last_seen)}</td>
                      <td className="px-4 py-3">
                        <ChevronRight className="w-4 h-4 text-[#3d5068]" />
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── リスク分析 Tab ───────────────────────────────────────────────────── */}
      {activeTab === 'risk' && (
        <div className="space-y-6">
          <div className="grid grid-cols-2 gap-6">
            {/* Donut */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
              <h3 className="text-white font-semibold mb-4">リスク分布</h3>
              <RiskDonutChart assets={assets} />
            </div>

            {/* Provider bars */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
              <h3 className="text-white font-semibold mb-4">プロバイダー別平均リスク</h3>
              <RiskByProviderChart assets={assets} />
            </div>
          </div>

          {/* Top 10 high risk */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-white font-semibold">高リスクアセット Top 10</h3>
              <button
                onClick={() => highRiskAssets.forEach(a => riskCalcMutation.mutate(a.id))}
                disabled={riskCalcMutation.isPending}
                className="flex items-center gap-2 px-3 py-1.5 bg-[#e8002d]/10 hover:bg-[#e8002d]/20 border border-[#e8002d]/30 text-[#e8002d] rounded-lg text-xs font-medium transition-colors disabled:opacity-50">
                {riskCalcMutation.isPending
                  ? <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  : <RefreshCw className="w-3.5 h-3.5" />}
                リスク再計算
              </button>
            </div>
            <table className="w-full">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  {['#', '名前', 'プロバイダー', 'タイプ', 'リスクスコア', 'リスク要因'].map(h => (
                    <th key={h} className="px-3 py-2 text-left text-xs text-[#7d92b0] font-medium">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {highRiskAssets.map((asset, i) => {
                  const ps = PROVIDER_STYLES[asset.provider]
                  const rl = getRiskLevel(asset.risk_score)
                  const rs = RISK_STYLES[rl]
                  return (
                    <tr key={asset.id} className="border-b border-[#1e2d42]/50 hover:bg-[#19253d]/20 transition-colors">
                      <td className="px-3 py-3 text-[#7d92b0] text-sm">{i + 1}</td>
                      <td className="px-3 py-3 text-white text-sm font-medium">{asset.name}</td>
                      <td className="px-3 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full border ${ps.bg} ${ps.text} ${ps.border}`}>
                          {asset.provider}
                        </span>
                      </td>
                      <td className="px-3 py-3 text-[#7d92b0] text-sm">{asset.asset_type}</td>
                      <td className="px-3 py-3">
                        <span className={`text-sm font-bold ${rs.text}`}>{asset.risk_score}</span>
                      </td>
                      <td className="px-3 py-3">
                        <div className="flex flex-wrap gap-1">
                          {asset.risk_factors.slice(0, 2).map((f, j) => (
                            <span key={j} className="text-xs bg-orange-900/20 text-orange-300 border border-orange-700/30 px-1.5 py-0.5 rounded-sm">
                              {f}
                            </span>
                          ))}
                          {asset.risk_factors.length > 2 && (
                            <span className="text-xs text-[#7d92b0]">+{asset.risk_factors.length - 2}</span>
                          )}
                          {asset.risk_factors.length === 0 && (
                            <span className="text-xs text-[#3d5068]">なし</span>
                          )}
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* ── プロバイダー設定 Tab ──────────────────────────────────────────────── */}
      {activeTab === 'providers' && (
        <div className="grid grid-cols-3 gap-6">
          {(providerConfigs as ProviderConfig[]).map(cfg => {
            const ps = PROVIDER_STYLES[cfg.provider]
            return (
              <div key={cfg.provider}
                className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-6">
                {/* Provider header */}
                <div className="flex items-center justify-between mb-4">
                  <div className="flex items-center gap-3">
                    <div className="w-10 h-10 rounded-lg flex items-center justify-center"
                         style={{ backgroundColor: `${ps.color}20` }}>
                      <Cloud className="w-5 h-5" style={{ color: ps.color }} />
                    </div>
                    <div>
                      <h3 className="text-white font-bold">{cfg.provider}</h3>
                      <div className="flex items-center gap-1.5 mt-0.5">
                        <div className={`w-2 h-2 rounded-full ${cfg.connected ? 'bg-green-400' : 'bg-red-500'}`} />
                        <span className="text-xs text-[#7d92b0]">{cfg.connected ? '接続済み' : '未接続'}</span>
                      </div>
                    </div>
                  </div>
                </div>

                {/* Config fields */}
                <div className="space-y-3 mb-4">
                  {cfg.fields.map(field => (
                    <div key={field.key}>
                      <p className="text-[#7d92b0] text-xs mb-1">{field.label}</p>
                      <p className="text-white text-sm font-mono bg-[#070d19] border border-[#1e2d42] rounded-sm px-2 py-1.5 truncate">
                        {field.value}
                      </p>
                    </div>
                  ))}
                </div>

                {/* Stats */}
                <div className="flex items-center justify-between py-3 border-t border-b border-[#1e2d42] mb-4">
                  <div>
                    <p className="text-[#7d92b0] text-xs">アセット数</p>
                    <p className="text-white font-bold">{cfg.asset_count}</p>
                  </div>
                  <div className="text-right">
                    <p className="text-[#7d92b0] text-xs">最終同期</p>
                    <p className="text-[#7d92b0] text-xs">{fmtDateTime(cfg.last_sync)}</p>
                  </div>
                </div>

                {/* Buttons */}
                <div className="flex gap-2">
                  <button
                    onClick={() => syncMutation.mutate(cfg.provider)}
                    disabled={syncingProvider === cfg.provider}
                    className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 bg-[#1d2f4a] hover:bg-[#243a5c] border border-[#1e2d42] text-white rounded-lg text-xs font-medium transition-colors disabled:opacity-50">
                    {syncingProvider === cfg.provider
                      ? <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                      : <RefreshCw className="w-3.5 h-3.5" />}
                    同期
                  </button>
                  <button
                    onClick={() => setConfigModal(cfg)}
                    className="flex-1 flex items-center justify-center gap-1.5 px-3 py-2 bg-[#070d19] border border-[#1e2d42] text-[#7d92b0] hover:text-white rounded-lg text-xs font-medium transition-colors">
                    <Settings className="w-3.5 h-3.5" />
                    設定
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      )}

      {/* Asset detail panel */}
      {detailAsset && (
        <AssetDetailPanel asset={detailAsset} onClose={() => setDetailAsset(null)} />
      )}

      {/* Provider config modal */}
      {configModal && (
        <ProviderConfigModal config={configModal} onClose={() => setConfigModal(null)} />
      )}
    </div>
  )
}
