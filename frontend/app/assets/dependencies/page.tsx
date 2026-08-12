'use client'

import { useState, useCallback } from 'react'
import { useQuery, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  GitFork, Plus, X, RefreshCw, Download, Search,
  AlertCircle, CheckCircle, AlertTriangle, Activity,
  ChevronRight, Zap, Database, Server, Globe, Box,
  Trash2, Filter
} from 'lucide-react'
import { USE_MOCK, m } from '@/lib/mock'

// ── Types ──────────────────────────────────────────────────────

type AssetType = 'application' | 'service' | 'database' | 'infrastructure' | 'external'
type HealthStatus = 'healthy' | 'degraded' | 'critical' | 'unknown'
type RelationshipType = 'depends_on' | 'communicates_with' | 'shares_data' | 'replicates_to'
type Criticality = 'critical' | 'high' | 'medium' | 'low'
type ZoomLevel = 'service' | 'application' | 'datacenter'

interface Asset {
  id: string
  name: string
  type: AssetType
  health: HealthStatus
  owner: string
  criticality: Criticality
  description: string
}

interface Dependency {
  id: string
  from_asset_id: string
  to_asset_id: string
  relationship_type: RelationshipType
  criticality: Criticality
}

// ── Mock Data ──────────────────────────────────────────────────

const MOCK_ASSETS: Asset[] = [
  { id: 'a1',  name: 'Web Frontend',       type: 'application',    health: 'healthy',  owner: 'frontend-team',  criticality: 'high',     description: 'ユーザー向けWebアプリケーション' },
  { id: 'a2',  name: 'API Gateway',         type: 'service',        health: 'healthy',  owner: 'platform-team',  criticality: 'critical', description: '全APIリクエストのゲートウェイ' },
  { id: 'a3',  name: 'Auth Service',         type: 'service',        health: 'healthy',  owner: 'security-team',  criticality: 'critical', description: '認証・認可サービス' },
  { id: 'a4',  name: 'User DB (Primary)',    type: 'database',       health: 'healthy',  owner: 'dba-team',       criticality: 'critical', description: 'ユーザーデータプライマリDB' },
  { id: 'a5',  name: 'User DB (Replica)',    type: 'database',       health: 'healthy',  owner: 'dba-team',       criticality: 'high',     description: 'ユーザーデータレプリカDB' },
  { id: 'a6',  name: 'Payment Service',     type: 'service',        health: 'degraded', owner: 'payments-team',  criticality: 'critical', description: '決済処理サービス' },
  { id: 'a7',  name: 'Payment Gateway',     type: 'external',       health: 'healthy',  owner: 'vendor',         criticality: 'critical', description: '外部決済ゲートウェイ' },
  { id: 'a8',  name: 'Notification Service', type: 'service',       health: 'healthy',  owner: 'backend-team',   criticality: 'medium',   description: '通知送信サービス' },
  { id: 'a9',  name: 'Email Provider',      type: 'external',       health: 'healthy',  owner: 'vendor',         criticality: 'medium',   description: '外部メールプロバイダー (SES)' },
  { id: 'a10', name: 'Cache (Redis)',        type: 'infrastructure', health: 'healthy',  owner: 'platform-team',  criticality: 'high',     description: 'Redisキャッシュクラスター' },
  { id: 'a11', name: 'Message Queue',       type: 'infrastructure', health: 'healthy',  owner: 'platform-team',  criticality: 'high',     description: 'RabbitMQメッセージキュー' },
  { id: 'a12', name: 'Search Service',      type: 'service',        health: 'healthy',  owner: 'backend-team',   criticality: 'medium',   description: 'Elasticsearch検索エンジン' },
  { id: 'a13', name: 'Analytics DB',        type: 'database',       health: 'healthy',  owner: 'data-team',      criticality: 'medium',   description: '分析データウェアハウス' },
  { id: 'a14', name: 'CDN',                 type: 'infrastructure', health: 'healthy',  owner: 'platform-team',  criticality: 'medium',   description: 'CloudFront CDN' },
  { id: 'a15', name: 'Load Balancer',       type: 'infrastructure', health: 'healthy',  owner: 'platform-team',  criticality: 'critical', description: 'ALBロードバランサー' },
  { id: 'a16', name: 'Report Service',      type: 'service',        health: 'critical', owner: 'backend-team',   criticality: 'medium',   description: 'レポート生成サービス' },
  { id: 'a17', name: 'File Storage (S3)',   type: 'infrastructure', health: 'healthy',  owner: 'platform-team',  criticality: 'high',     description: 'S3ファイルストレージ' },
  { id: 'a18', name: 'Admin Panel',         type: 'application',    health: 'healthy',  owner: 'platform-team',  criticality: 'high',     description: '管理者パネル' },
  { id: 'a19', name: 'Monitoring Agent',    type: 'service',        health: 'healthy',  owner: 'ops-team',       criticality: 'medium',   description: '監視エージェント' },
  { id: 'a20', name: 'Config Service',      type: 'service',        health: 'unknown',  owner: 'platform-team',  criticality: 'high',     description: '設定管理サービス' },
]

const MOCK_DEPS: Dependency[] = [
  { id: 'd1',  from_asset_id: 'a1',  to_asset_id: 'a2',  relationship_type: 'depends_on',        criticality: 'critical' },
  { id: 'd2',  from_asset_id: 'a1',  to_asset_id: 'a14', relationship_type: 'depends_on',        criticality: 'medium' },
  { id: 'd3',  from_asset_id: 'a2',  to_asset_id: 'a3',  relationship_type: 'depends_on',        criticality: 'critical' },
  { id: 'd4',  from_asset_id: 'a2',  to_asset_id: 'a6',  relationship_type: 'communicates_with', criticality: 'high' },
  { id: 'd5',  from_asset_id: 'a2',  to_asset_id: 'a8',  relationship_type: 'communicates_with', criticality: 'medium' },
  { id: 'd6',  from_asset_id: 'a2',  to_asset_id: 'a10', relationship_type: 'depends_on',        criticality: 'high' },
  { id: 'd7',  from_asset_id: 'a2',  to_asset_id: 'a12', relationship_type: 'communicates_with', criticality: 'medium' },
  { id: 'd8',  from_asset_id: 'a3',  to_asset_id: 'a4',  relationship_type: 'depends_on',        criticality: 'critical' },
  { id: 'd9',  from_asset_id: 'a4',  to_asset_id: 'a5',  relationship_type: 'replicates_to',     criticality: 'high' },
  { id: 'd10', from_asset_id: 'a6',  to_asset_id: 'a7',  relationship_type: 'depends_on',        criticality: 'critical' },
  { id: 'd11', from_asset_id: 'a6',  to_asset_id: 'a4',  relationship_type: 'depends_on',        criticality: 'high' },
  { id: 'd12', from_asset_id: 'a8',  to_asset_id: 'a9',  relationship_type: 'depends_on',        criticality: 'medium' },
  { id: 'd13', from_asset_id: 'a8',  to_asset_id: 'a11', relationship_type: 'depends_on',        criticality: 'medium' },
  { id: 'd14', from_asset_id: 'a12', to_asset_id: 'a13', relationship_type: 'shares_data',       criticality: 'medium' },
  { id: 'd15', from_asset_id: 'a15', to_asset_id: 'a2',  relationship_type: 'depends_on',        criticality: 'critical' },
  { id: 'd16', from_asset_id: 'a1',  to_asset_id: 'a15', relationship_type: 'depends_on',        criticality: 'critical' },
  { id: 'd17', from_asset_id: 'a16', to_asset_id: 'a13', relationship_type: 'depends_on',        criticality: 'high' },
  { id: 'd18', from_asset_id: 'a16', to_asset_id: 'a17', relationship_type: 'depends_on',        criticality: 'medium' },
  { id: 'd19', from_asset_id: 'a18', to_asset_id: 'a2',  relationship_type: 'depends_on',        criticality: 'high' },
  { id: 'd20', from_asset_id: 'a2',  to_asset_id: 'a20', relationship_type: 'depends_on',        criticality: 'high' },
  { id: 'd21', from_asset_id: 'a19', to_asset_id: 'a4',  relationship_type: 'communicates_with', criticality: 'low' },
  { id: 'd22', from_asset_id: 'a6',  to_asset_id: 'a11', relationship_type: 'communicates_with', criticality: 'medium' },
  { id: 'd23', from_asset_id: 'a3',  to_asset_id: 'a10', relationship_type: 'depends_on',        criticality: 'high' },
  { id: 'd24', from_asset_id: 'a2',  to_asset_id: 'a17', relationship_type: 'communicates_with', criticality: 'medium' },
  { id: 'd25', from_asset_id: 'a18', to_asset_id: 'a3',  relationship_type: 'depends_on',        criticality: 'critical' },
  { id: 'd26', from_asset_id: 'a13', to_asset_id: 'a17', relationship_type: 'shares_data',       criticality: 'medium' },
  { id: 'd27', from_asset_id: 'a10', to_asset_id: 'a4',  relationship_type: 'communicates_with', criticality: 'medium' },
  { id: 'd28', from_asset_id: 'a11', to_asset_id: 'a6',  relationship_type: 'communicates_with', criticality: 'high' },
  { id: 'd29', from_asset_id: 'a20', to_asset_id: 'a3',  relationship_type: 'communicates_with', criticality: 'high' },
  { id: 'd30', from_asset_id: 'a9',  to_asset_id: 'a8',  relationship_type: 'communicates_with', criticality: 'low' },
]

// ── Helpers ────────────────────────────────────────────────────

const healthMeta: Record<HealthStatus, { color: string; bgColor: string; label: string; icon: React.ComponentType<{ className?: string }> }> = {
  healthy:  { color: 'text-green-400',  bgColor: 'bg-green-500/20 border-green-500/40',   label: 'Healthy',  icon: CheckCircle },
  degraded: { color: 'text-yellow-400', bgColor: 'bg-yellow-500/20 border-yellow-500/40', label: 'Degraded', icon: AlertTriangle },
  critical: { color: 'text-red-400',    bgColor: 'bg-red-500/20 border-red-500/40',       label: 'Critical', icon: AlertCircle },
  unknown:  { color: 'text-gray-400',   bgColor: 'bg-gray-500/20 border-gray-500/40',     label: 'Unknown',  icon: Activity },
}

const assetTypeIcon: Record<AssetType, React.ComponentType<{ className?: string }>> = {
  application:    Globe,
  service:        Zap,
  database:       Database,
  infrastructure: Server,
  external:       Globe,
}

const criticalityColor: Record<Criticality, string> = {
  critical: 'bg-red-500/20 text-red-400 border-red-500/30',
  high:     'bg-orange-500/20 text-orange-400 border-orange-500/30',
  medium:   'bg-yellow-500/20 text-yellow-400 border-yellow-500/30',
  low:      'bg-blue-500/20 text-blue-400 border-blue-500/30',
}

const relTypeMeta: Record<RelationshipType, { label: string; color: string }> = {
  depends_on:       { label: '依存',      color: 'bg-red-500/20 text-red-400 border-red-500/30' },
  communicates_with:{ label: '通信',      color: 'bg-blue-500/20 text-blue-400 border-blue-500/30' },
  shares_data:      { label: 'データ共有', color: 'bg-purple-500/20 text-purple-400 border-purple-500/30' },
  replicates_to:    { label: 'レプリカ',   color: 'bg-green-500/20 text-green-400 border-green-500/30' },
}

const assetTypeGroups: { label: string; type: AssetType }[] = [
  { label: 'Applications', type: 'application' },
  { label: 'Services', type: 'service' },
  { label: 'Databases', type: 'database' },
  { label: 'Infrastructure', type: 'infrastructure' },
  { label: 'External', type: 'external' },
]

function Badge({ className, children }: { className: string; children: React.ReactNode }) {
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded text-xs font-medium border ${className}`}>
      {children}
    </span>
  )
}

function Toast({ message, type, onClose }: { message: string; type: 'success' | 'error'; onClose: () => void }) {
  return (
    <div className={`fixed top-4 right-4 z-50 flex items-center gap-3 px-4 py-3 rounded-lg border shadow-xl ${
      type === 'success' ? 'bg-green-900/90 border-green-500/40 text-green-100' : 'bg-red-900/90 border-red-500/40 text-red-100'
    }`}>
      {type === 'success' ? <CheckCircle className="w-4 h-4 text-green-400" /> : <AlertCircle className="w-4 h-4 text-red-400" />}
      <span className="text-sm">{message}</span>
      <button onClick={onClose}><X className="w-3.5 h-3.5" /></button>
    </div>
  )
}

// ── Dependency Graph (CSS-based) ───────────────────────────────

function DependencyGraph({
  centerAsset,
  assets,
  deps,
  onSelectAsset,
}: {
  centerAsset: Asset | null
  assets: Asset[]
  deps: Dependency[]
  onSelectAsset: (a: Asset) => void
}) {
  if (!centerAsset) {
    return (
      <div className="flex items-center justify-center h-full text-[#3d5068]">
        <div className="text-center">
          <GitFork className="w-12 h-12 mx-auto mb-3 opacity-30" />
          <p className="text-sm">左のリストからアセットを選択してください</p>
        </div>
      </div>
    )
  }

  const upstreamDeps = deps.filter(d => d.to_asset_id === centerAsset.id)
  const downstreamDeps = deps.filter(d => d.from_asset_id === centerAsset.id)
  const upstreamAssets = upstreamDeps.map(d => assets.find(a => a.id === d.from_asset_id)).filter(Boolean) as Asset[]
  const downstreamAssets = downstreamDeps.map(d => assets.find(a => a.id === d.to_asset_id)).filter(Boolean) as Asset[]

  const AssetNode = ({ asset, isCenter = false }: { asset: Asset; isCenter?: boolean }) => {
    const meta = healthMeta[asset.health]
    const TypeIcon = assetTypeIcon[asset.type]
    return (
      <button
        onClick={() => !isCenter && onSelectAsset(asset)}
        className={`flex flex-col items-center gap-1.5 px-3 py-2 rounded-lg border transition-all ${
          isCenter
            ? 'bg-[#e8002d]/10 border-[#e8002d]/50 cursor-default min-w-[120px]'
            : `${meta.bgColor} hover:opacity-80 cursor-pointer min-w-[100px]`
        }`}
      >
        <TypeIcon className={`w-5 h-5 ${isCenter ? 'text-[#e8002d]' : meta.color}`} />
        <span className={`text-xs font-medium text-center leading-tight ${isCenter ? 'text-white' : 'text-[#e2e8f4]'}`}>{asset.name}</span>
        {!isCenter && <span className={`text-[10px] ${meta.color}`}>{meta.label}</span>}
      </button>
    )
  }

  return (
    <div className="relative flex items-center justify-center gap-8 h-full min-h-[300px] p-4">
      {/* Upstream column */}
      {upstreamAssets.length > 0 && (
        <div className="flex flex-col gap-3 items-end">
          <p className="text-[10px] text-[#3d5068] uppercase tracking-wide mb-1">上流 (依存元)</p>
          {upstreamAssets.map(a => <AssetNode key={a.id} asset={a} />)}
        </div>
      )}

      {/* Arrows from upstream to center */}
      {upstreamAssets.length > 0 && (
        <div className="flex flex-col items-center justify-center">
          <div className="flex items-center gap-1 text-[#3d5068]">
            <div className="w-8 h-px bg-[#1e2d42]" />
            <ChevronRight className="w-3 h-3" />
          </div>
        </div>
      )}

      {/* Center asset */}
      <div className="flex flex-col items-center gap-2">
        <AssetNode asset={centerAsset} isCenter />
        <Badge className={healthMeta[centerAsset.health].bgColor.replace('border-', 'border-') + ' ' + healthMeta[centerAsset.health].color}>
          {healthMeta[centerAsset.health].label}
        </Badge>
      </div>

      {/* Arrows from center to downstream */}
      {downstreamAssets.length > 0 && (
        <div className="flex flex-col items-center justify-center">
          <div className="flex items-center gap-1 text-[#3d5068]">
            <div className="w-8 h-px bg-[#1e2d42]" />
            <ChevronRight className="w-3 h-3" />
          </div>
        </div>
      )}

      {/* Downstream column */}
      {downstreamAssets.length > 0 && (
        <div className="flex flex-col gap-3 items-start">
          <p className="text-[10px] text-[#3d5068] uppercase tracking-wide mb-1">下流 (依存先)</p>
          {downstreamAssets.map(a => <AssetNode key={a.id} asset={a} />)}
        </div>
      )}
    </div>
  )
}

// ── Main Component ─────────────────────────────────────────────

export default function DependenciesPage() {
  const qc = useQueryClient()
  const [toast, setToast] = useState<{ message: string; type: 'success' | 'error' } | null>(null)
  const showToast = useCallback((message: string, type: 'success' | 'error' = 'success') => {
    setToast({ message, type })
    setTimeout(() => setToast(null), 4000)
  }, [])

  const [selectedAsset, setSelectedAsset] = useState<Asset | null>(null)
  const [searchQuery, setSearchQuery] = useState('')
  const [zoomLevel, setZoomLevel] = useState<ZoomLevel>('service')
  const [showAddDep, setShowAddDep] = useState(false)
  const [newDep, setNewDep] = useState({ from_asset_id: '', to_asset_id: '', relationship_type: 'depends_on' as RelationshipType, criticality: 'medium' as Criticality })
  const [impactResult, setImpactResult] = useState<Asset[] | null>(null)
  const [localDeps, setLocalDeps] = useState<Dependency[]>(m(MOCK_DEPS))

  // API queries
  const { data: assetsData } = useQuery<{ assets: Asset[]; dependencies: Dependency[] }>({
    queryKey: ['asset-dependencies'],
    queryFn: () => apiFetch('/api/v1/assets/dependencies'),
    staleTime: 30_000,
  })
  const assets = assetsData?.assets ?? m(MOCK_ASSETS)
  const deps = assetsData?.dependencies ?? localDeps

  const filteredAssets = assets.filter(a =>
    searchQuery === '' || a.name.toLowerCase().includes(searchQuery.toLowerCase())
  )

  const upstreamDeps = selectedAsset ? deps.filter(d => d.to_asset_id === selectedAsset.id) : []
  const downstreamDeps = selectedAsset ? deps.filter(d => d.from_asset_id === selectedAsset.id) : []

  const handleImpactAnalysis = async () => {
    if (!selectedAsset) return
    try {
      const res = await apiFetch<{ affected: Asset[] }>(`/api/v1/assets/dependencies/impact?asset_id=${selectedAsset.id}`)
      setImpactResult(res.affected)
    } catch {
      // Mock: BFS over downstream
      const affected: Asset[] = []
      const visited = new Set<string>()
      const queue = [selectedAsset.id]
      while (queue.length > 0) {
        const curr = queue.shift()!
        if (visited.has(curr)) continue
        visited.add(curr)
        deps.filter(d => d.from_asset_id === curr).forEach(d => {
          const a = assets.find(a => a.id === d.to_asset_id)
          if (a && !visited.has(a.id)) {
            affected.push(a)
            queue.push(a.id)
          }
        })
      }
      setImpactResult(affected)
    }
  }

  const handleAddDep = async () => {
    try {
      await apiFetch('/api/v1/assets/dependencies', { method: 'POST', body: JSON.stringify(newDep) })
      qc.invalidateQueries({ queryKey: ['asset-dependencies'] })
    } catch {
      const d: Dependency = { id: `d${Date.now()}`, ...newDep }
      setLocalDeps(prev => [...prev, d])
    }
    showToast('依存関係を追加しました')
    setShowAddDep(false)
  }

  const handleDeleteDep = async (id: string) => {
    try {
      await apiFetch(`/api/v1/assets/dependencies/${id}`, { method: 'DELETE' })
      qc.invalidateQueries({ queryKey: ['asset-dependencies'] })
    } catch {
      setLocalDeps(prev => prev.filter(d => d.id !== id))
    }
    showToast('依存関係を削除しました')
  }

  // Critical path for selected asset
  const criticalPath: string[] = selectedAsset ? (() => {
    const path: string[] = [selectedAsset.name]
    let curr = selectedAsset.id
    for (let i = 0; i < 4; i++) {
      const critDep = deps.find(d => d.from_asset_id === curr && d.criticality === 'critical')
      if (!critDep) break
      const next = assets.find(a => a.id === critDep.to_asset_id)
      if (!next) break
      path.push(next.name)
      curr = next.id
    }
    return path
  })() : []

  return (
    <div className="min-h-screen bg-[#070d19] text-[#7d92b0] p-6">
      {toast && <Toast message={toast.message} type={toast.type} onClose={() => setToast(null)} />}

      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="w-10 h-10 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
            <GitFork className="w-5 h-5 text-[#e8002d]" />
          </div>
          <div>
            <h1 className="text-xl font-bold text-white">資産依存関係マッピング</h1>
            <p className="text-xs text-[#7d92b0] mt-0.5">{assets.length} アセット · {deps.length} 依存関係</p>
          </div>
        </div>
        <div className="flex items-center gap-2">
          <select value={zoomLevel} onChange={e => setZoomLevel(e.target.value as ZoomLevel)} className="bg-[#0d1220] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-[#7d92b0] outline-none">
            <option value="service">サービス単位</option>
            <option value="application">アプリケーション単位</option>
            <option value="datacenter">データセンター単位</option>
          </select>
          <button onClick={() => showToast('画像エクスポートを開始しました')} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] hover:border-[#7d92b0]/40 text-sm transition-colors">
            <Download className="w-3.5 h-3.5" />
            エクスポート
          </button>
        </div>
      </div>

      <div className="flex gap-4">
        {/* Left sidebar: asset list */}
        <div className="w-56 flex-shrink-0 space-y-3">
          <div className="relative">
            <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#3d5068]" />
            <input
              value={searchQuery}
              onChange={e => setSearchQuery(e.target.value)}
              placeholder="アセットを検索..."
              className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-lg pl-8 pr-3 py-2 text-sm text-white outline-none"
            />
          </div>
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-3 max-h-[500px] overflow-y-auto space-y-3">
            {assetTypeGroups.map(group => {
              const groupAssets = filteredAssets.filter(a => a.type === group.type)
              if (groupAssets.length === 0) return null
              const TypeIcon = assetTypeIcon[group.type]
              return (
                <div key={group.type}>
                  <p className="text-[10px] text-[#3d5068] uppercase tracking-wide mb-1 flex items-center gap-1">
                    <TypeIcon className="w-3 h-3" />
                    {group.label}
                  </p>
                  {groupAssets.map(asset => {
                    const meta = healthMeta[asset.health]
                    return (
                      <button
                        key={asset.id}
                        onClick={() => { setSelectedAsset(asset); setImpactResult(null) }}
                        className={`w-full flex items-center gap-2 px-2 py-1.5 rounded text-left transition-colors ${
                          selectedAsset?.id === asset.id ? 'bg-[#1e2d42] text-white' : 'text-[#7d92b0] hover:bg-[#1e2d42]/50'
                        }`}
                      >
                        <span className={`w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                          asset.health === 'healthy' ? 'bg-green-400' :
                          asset.health === 'degraded' ? 'bg-yellow-400' :
                          asset.health === 'critical' ? 'bg-red-400' : 'bg-gray-400'
                        }`} />
                        <span className="text-xs truncate">{asset.name}</span>
                      </button>
                    )
                  })}
                </div>
              )
            })}
          </div>
        </div>

        {/* Main: graph + details */}
        <div className="flex-1 flex flex-col gap-4">
          {/* Graph */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl" style={{ minHeight: 320 }}>
            <DependencyGraph
              centerAsset={selectedAsset}
              assets={assets}
              deps={deps}
              onSelectAsset={a => { setSelectedAsset(a); setImpactResult(null) }}
            />
          </div>

          {/* Details + Impact */}
          {selectedAsset && (
            <div className="grid grid-cols-2 gap-4">
              {/* Asset details */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <h3 className="text-white font-semibold mb-3">{selectedAsset.name}</h3>
                <div className="space-y-2 mb-4">
                  <div className="flex justify-between text-sm">
                    <span className="text-[#7d92b0]">タイプ</span>
                    <span className="text-white capitalize">{selectedAsset.type}</span>
                  </div>
                  <div className="flex justify-between text-sm items-center">
                    <span className="text-[#7d92b0]">ヘルス</span>
                    <Badge className={healthMeta[selectedAsset.health].bgColor + ' ' + healthMeta[selectedAsset.health].color}>
                      {healthMeta[selectedAsset.health].label}
                    </Badge>
                  </div>
                  <div className="flex justify-between text-sm items-center">
                    <span className="text-[#7d92b0]">重要度</span>
                    <Badge className={criticalityColor[selectedAsset.criticality]}>{selectedAsset.criticality}</Badge>
                  </div>
                  <div className="flex justify-between text-sm">
                    <span className="text-[#7d92b0]">オーナー</span>
                    <span className="text-white">{selectedAsset.owner}</span>
                  </div>
                </div>
                <div className="mb-4">
                  <p className="text-xs text-[#7d92b0] mb-1">上流依存 ({upstreamDeps.length})</p>
                  <div className="flex flex-wrap gap-1">
                    {upstreamDeps.map(d => {
                      const a = assets.find(a => a.id === d.from_asset_id)
                      return a ? <Badge key={d.id} className="bg-blue-500/20 text-blue-400 border-blue-500/30">{a.name}</Badge> : null
                    })}
                    {upstreamDeps.length === 0 && <span className="text-xs text-[#3d5068]">なし</span>}
                  </div>
                </div>
                <div className="mb-4">
                  <p className="text-xs text-[#7d92b0] mb-1">下流依存 ({downstreamDeps.length})</p>
                  <div className="flex flex-wrap gap-1">
                    {downstreamDeps.map(d => {
                      const a = assets.find(a => a.id === d.to_asset_id)
                      return a ? <Badge key={d.id} className="bg-orange-500/20 text-orange-400 border-orange-500/30">{a.name}</Badge> : null
                    })}
                    {downstreamDeps.length === 0 && <span className="text-xs text-[#3d5068]">なし</span>}
                  </div>
                </div>
                {criticalPath.length > 1 && (
                  <div>
                    <p className="text-xs text-[#7d92b0] mb-2">クリティカルパス</p>
                    <div className="flex items-center flex-wrap gap-1">
                      {criticalPath.map((name, i) => (
                        <span key={i} className="flex items-center gap-1">
                          <span className="text-xs text-white bg-[#1e2d42] px-2 py-0.5 rounded">{name}</span>
                          {i < criticalPath.length - 1 && <ChevronRight className="w-3 h-3 text-[#3d5068]" />}
                        </span>
                      ))}
                    </div>
                  </div>
                )}
                <button onClick={handleImpactAnalysis} className="mt-4 w-full flex items-center justify-center gap-2 px-4 py-2 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/30 text-[#e8002d] text-sm hover:bg-[#e8002d]/20 transition-colors">
                  <AlertCircle className="w-4 h-4" />
                  影響分析
                </button>
              </div>

              {/* Impact analysis */}
              <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
                <h3 className="text-white font-semibold mb-3">影響分析結果</h3>
                {impactResult === null ? (
                  <p className="text-sm text-[#3d5068]">「影響分析」ボタンをクリックして分析を実行してください</p>
                ) : impactResult.length === 0 ? (
                  <p className="text-sm text-green-400 flex items-center gap-2"><CheckCircle className="w-4 h-4" />影響を受けるアセットなし</p>
                ) : (
                  <div className="space-y-2">
                    <p className="text-sm text-[#7d92b0] mb-3">{selectedAsset.name} が障害になった場合、{impactResult.length}件のアセットが影響を受けます</p>
                    {impactResult.map(a => (
                      <div key={a.id} className="flex items-center justify-between px-3 py-2 bg-[#1e2d42]/30 border border-[#1e2d42] rounded-lg">
                        <div className="flex items-center gap-2">
                          <span className={`w-2 h-2 rounded-full ${
                            a.health === 'healthy' ? 'bg-green-400' :
                            a.health === 'degraded' ? 'bg-yellow-400' :
                            a.health === 'critical' ? 'bg-red-400' : 'bg-gray-400'
                          }`} />
                          <span className="text-sm text-white">{a.name}</span>
                        </div>
                        <Badge className={criticalityColor[a.criticality]}>{a.criticality}</Badge>
                      </div>
                    ))}
                  </div>
                )}
              </div>
            </div>
          )}

          {/* Dependency rules table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-5">
            <div className="flex items-center justify-between mb-4">
              <h3 className="text-white font-semibold">依存関係ルール</h3>
              <button onClick={() => setShowAddDep(true)} className="flex items-center gap-2 px-3 py-2 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c8001e] transition-colors">
                <Plus className="w-3.5 h-3.5" />
                追加
              </button>
            </div>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    {['元アセット', '関係タイプ', '先アセット', '重要度', '操作'].map(h => (
                      <th key={h} className="text-left px-3 py-2 text-xs font-semibold text-[#7d92b0] uppercase">{h}</th>
                    ))}
                  </tr>
                </thead>
                <tbody>
                  {(selectedAsset
                    ? deps.filter(d => d.from_asset_id === selectedAsset.id || d.to_asset_id === selectedAsset.id)
                    : deps.slice(0, 10)
                  ).map(dep => {
                    const fromA = assets.find(a => a.id === dep.from_asset_id)
                    const toA = assets.find(a => a.id === dep.to_asset_id)
                    if (!fromA || !toA) return null
                    return (
                      <tr key={dep.id} className="border-b border-[#1e2d42]/50 hover:bg-[#1e2d42]/20">
                        <td className="px-3 py-2 text-white">{fromA.name}</td>
                        <td className="px-3 py-2"><Badge className={relTypeMeta[dep.relationship_type].color}>{relTypeMeta[dep.relationship_type].label}</Badge></td>
                        <td className="px-3 py-2 text-white">{toA.name}</td>
                        <td className="px-3 py-2"><Badge className={criticalityColor[dep.criticality]}>{dep.criticality}</Badge></td>
                        <td className="px-3 py-2">
                          <button onClick={() => handleDeleteDep(dep.id)} className="p-1 rounded hover:bg-red-900/30 text-[#3d5068] hover:text-red-400 transition-colors">
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
              {!selectedAsset && deps.length > 10 && (
                <p className="text-xs text-[#3d5068] text-center mt-2">アセットを選択すると関連する依存関係のみ表示されます</p>
              )}
            </div>
          </div>
        </div>
      </div>

      {/* Add Dependency Modal */}
      {showAddDep && (
        <div className="fixed inset-0 bg-black/60 z-40 flex items-center justify-center p-4">
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md p-6">
            <div className="flex items-center justify-between mb-5">
              <h2 className="text-lg font-bold text-white">依存関係を追加</h2>
              <button onClick={() => setShowAddDep(false)}><X className="w-5 h-5" /></button>
            </div>
            <div className="space-y-4">
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">元アセット (From)</label>
                <select value={newDep.from_asset_id} onChange={e => setNewDep(p => ({ ...p, from_asset_id: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-none">
                  <option value="">選択してください</option>
                  {assets.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">関係タイプ</label>
                <select value={newDep.relationship_type} onChange={e => setNewDep(p => ({ ...p, relationship_type: e.target.value as RelationshipType }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-none">
                  {Object.entries(relTypeMeta).map(([k, v]) => <option key={k} value={k}>{v.label}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">先アセット (To)</label>
                <select value={newDep.to_asset_id} onChange={e => setNewDep(p => ({ ...p, to_asset_id: e.target.value }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-none">
                  <option value="">選択してください</option>
                  {assets.map(a => <option key={a.id} value={a.id}>{a.name}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs text-[#7d92b0] mb-1">重要度</label>
                <select value={newDep.criticality} onChange={e => setNewDep(p => ({ ...p, criticality: e.target.value as Criticality }))} className="w-full bg-[#070d19] border border-[#1e2d42] rounded-lg px-3 py-2 text-sm text-white outline-none">
                  {Object.entries(criticalityColor).map(([k]) => <option key={k} value={k}>{k}</option>)}
                </select>
              </div>
            </div>
            <div className="flex justify-end gap-3 mt-6">
              <button onClick={() => setShowAddDep(false)} className="px-4 py-2 rounded-lg border border-[#1e2d42] text-[#7d92b0] text-sm hover:text-white transition-colors">キャンセル</button>
              <button onClick={handleAddDep} className="px-4 py-2 rounded-lg bg-[#e8002d] text-white text-sm hover:bg-[#c8001e] transition-colors">追加</button>
            </div>
          </div>
        </div>
      )}
    </div>
  )
}
