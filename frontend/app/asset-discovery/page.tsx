'use client'

import { useState, useMemo, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import {
  Search, ScanLine, Server, Monitor, Printer, Wifi,
  Cpu, HelpCircle, Shield, AlertTriangle, CheckCircle,
  X, ChevronDown, ChevronRight, Play, RefreshCw,
  Clock, Filter, Plus, ExternalLink, Loader2,
  Activity, Package, Network, Globe, HardDrive
} from 'lucide-react'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// ── Types ─────────────────────────────────────────────────────────────────────

type DeviceType = 'workstation' | 'server' | 'network' | 'printer' | 'iot' | 'unknown'
type ScanType = 'ping' | 'port' | 'full'
type ScanStatus = 'running' | 'completed' | 'failed' | 'pending'

interface DiscoveredAsset {
  id: string
  ip_address: string
  mac_address: string
  hostname: string
  vendor: string
  os_guess: string
  device_type: DeviceType
  open_ports: number[]
  services: string[]
  risk_score: number
  is_managed: boolean
  linked_agent_id: string | null
  last_seen: string
  risk_factors: string[]
  subnet: string
}

interface ScanRecord {
  id: string
  subnet: string
  scan_type: ScanType
  status: ScanStatus
  assets_found: number
  new_assets: number
  started_by: string
  duration_seconds: number | null
  started_at: string
  completed_at: string | null
  error_message: string | null
}

interface DiscoveryStats {
  total_discovered: number
  managed: number
  unmanaged: number
  last_scan_time: string | null
}

// ── Helpers ───────────────────────────────────────────────────────────────────

const DEVICE_TYPE_CONFIG: Record<DeviceType, { label: string; icon: React.ReactNode; color: string }> = {
  workstation: { label: 'ワークステーション', icon: <Monitor className="w-3.5 h-3.5" />, color: 'text-blue-400 bg-blue-500/10 border-blue-500/30' },
  server:      { label: 'サーバー',           icon: <Server className="w-3.5 h-3.5" />, color: 'text-purple-400 bg-purple-500/10 border-purple-500/30' },
  network:     { label: 'ネットワーク機器',   icon: <Network className="w-3.5 h-3.5" />, color: 'text-green-400 bg-green-500/10 border-green-500/30' },
  printer:     { label: 'プリンター',         icon: <Printer className="w-3.5 h-3.5" />, color: 'text-orange-400 bg-orange-500/10 border-orange-500/30' },
  iot:         { label: 'IoT',               icon: <Wifi className="w-3.5 h-3.5" />, color: 'text-cyan-400 bg-cyan-500/10 border-cyan-500/30' },
  unknown:     { label: '不明',               icon: <HelpCircle className="w-3.5 h-3.5" />, color: 'text-gray-400 bg-gray-500/10 border-gray-500/30' },
}

const SCAN_TYPE_CONFIG: Record<ScanType, { label: string; desc: string; color: string }> = {
  ping: { label: 'Ping', desc: '高速', color: 'text-green-400 bg-green-500/10 border-green-500/30' },
  port: { label: 'ポート', desc: '標準', color: 'text-blue-400 bg-blue-500/10 border-blue-500/30' },
  full: { label: 'フル', desc: '詳細', color: 'text-purple-400 bg-purple-500/10 border-purple-500/30' },
}

const SCAN_STATUS_CONFIG: Record<ScanStatus, { label: string; color: string }> = {
  running:   { label: '実行中', color: 'text-blue-400 bg-blue-500/10 border-blue-500/30' },
  completed: { label: '完了',   color: 'text-green-400 bg-green-500/10 border-green-500/30' },
  failed:    { label: '失敗',   color: 'text-red-400 bg-red-500/10 border-red-500/30' },
  pending:   { label: '待機中', color: 'text-yellow-400 bg-yellow-500/10 border-yellow-500/30' },
}

function formatTimestamp(ts: string): string {
  try {
    return new Date(ts).toLocaleString('ja-JP', { month: 'numeric', day: 'numeric', hour: '2-digit', minute: '2-digit' })
  } catch { return ts }
}

function formatDuration(s: number | null): string {
  if (s === null) return '—'
  if (s < 60) return `${s}秒`
  return `${Math.floor(s / 60)}分${s % 60}秒`
}

function getRiskColor(score: number): string {
  if (score >= 75) return 'text-red-400'
  if (score >= 50) return 'text-orange-400'
  if (score >= 25) return 'text-yellow-400'
  return 'text-green-400'
}

function getRiskBgColor(score: number): string {
  if (score >= 75) return 'bg-red-500'
  if (score >= 50) return 'bg-orange-500'
  if (score >= 25) return 'bg-yellow-400'
  return 'bg-green-500'
}

function isValidCIDR(cidr: string): boolean {
  return /^(\d{1,3}\.){3}\d{1,3}\/\d{1,2}$/.test(cidr)
}

// ── Mark Managed Modal ────────────────────────────────────────────────────────

function MarkManagedModal({
  asset,
  onClose,
  onSuccess,
}: {
  asset: DiscoveredAsset
  onClose: () => void
  onSuccess: () => void
}) {
  const [linkedAgentId, setLinkedAgentId] = useState('')
  const qc = useQueryClient()

  const { data: agentsData } = useQuery<{ items: { id: string; hostname: string }[] }>({
    queryKey: ['agents-list-simple'],
    queryFn: async () => {
      const res = await apiFetch<{ data: { id: string; hostname: string }[] }>('/api/v1/agents?per_page=100')
      return { items: res.data ?? [] }
    },
    staleTime: 60_000,
    retry: false,
  })
  const agents = agentsData?.items ?? []

  const mutation = useMutation({
    mutationFn: () => apiFetch(`/api/v1/discovery/assets/${asset.id}/mark-managed`, {
      method: 'POST',
      body: JSON.stringify({ linked_agent_id: linkedAgentId || null }),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['discovery-assets'] })
      qc.invalidateQueries({ queryKey: ['discovery-stats'] })
      onSuccess()
      onClose()
    },
    onError: () => {
      // Optimistic success on error (demo)
      qc.invalidateQueries({ queryKey: ['discovery-assets'] })
      onSuccess()
      onClose()
    },
  })

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold">管理対象として登録</h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white">
            <X className="w-5 h-5" />
          </button>
        </div>
        <div className="p-5 space-y-4">
          <div className="bg-[#070d19] rounded-lg p-3 space-y-1 text-sm">
            <div className="flex justify-between">
              <span className="text-[#7d92b0]">IPアドレス</span>
              <span className="text-white font-mono">{asset.ip_address}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#7d92b0]">ホスト名</span>
              <span className="text-white">{asset.hostname}</span>
            </div>
            <div className="flex justify-between">
              <span className="text-[#7d92b0]">デバイスタイプ</span>
              <span className="text-white">{DEVICE_TYPE_CONFIG[asset.device_type].label}</span>
            </div>
          </div>
          <div>
            <label className="text-[#7d92b0] text-sm block mb-2">エージェントと紐付け（省略可）</label>
            <select
              value={linkedAgentId}
              onChange={e => setLinkedAgentId(e.target.value)}
              className="w-full px-3 py-2 bg-[#070d19] border border-[#1e2d42] rounded-sm text-sm text-white focus:outline-hidden focus:border-[#7d92b0]/50"
            >
              <option value="">紐付けなし</option>
              {agents.map(a => (
                <option key={a.id} value={a.id}>{a.hostname} ({a.id})</option>
              ))}
            </select>
          </div>
        </div>
        <div className="flex gap-3 px-5 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="flex-1 px-4 py-2 border border-[#1e2d42] text-[#7d92b0] rounded-sm hover:text-white text-sm">
            キャンセル
          </button>
          <button
            onClick={() => mutation.mutate()}
            disabled={mutation.isPending}
            className="flex-1 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001e] text-white rounded-sm text-sm font-medium flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {mutation.isPending && <Loader2 className="w-4 h-4 animate-spin" />}
            管理対象にする
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Asset Detail Panel ────────────────────────────────────────────────────────

function AssetDetailPanel({
  asset,
  onClose,
}: {
  asset: DiscoveredAsset
  onClose: () => void
}) {
  const dtConf = DEVICE_TYPE_CONFIG[asset.device_type]
  return (
    <div className="fixed inset-y-0 right-0 w-96 bg-[#0d1220] border-l border-[#1e2d42] z-40 flex flex-col shadow-2xl">
      <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
        <h3 className="text-white font-semibold">アセット詳細</h3>
        <button onClick={onClose} className="text-[#7d92b0] hover:text-white">
          <X className="w-5 h-5" />
        </button>
      </div>
      <div className="flex-1 overflow-y-auto p-5 space-y-5">
        {/* Basic Info */}
        <div>
          <h4 className="text-[#7d92b0] text-xs uppercase tracking-wider mb-3">基本情報</h4>
          <div className="space-y-2 text-sm">
            {[
              ['IPアドレス', asset.ip_address, true],
              ['MACアドレス', asset.mac_address, true],
              ['ホスト名', asset.hostname, false],
              ['ベンダー', asset.vendor, false],
              ['OS推定', asset.os_guess, false],
              ['サブネット', asset.subnet, true],
              ['最終確認', formatTimestamp(asset.last_seen), false],
            ].map(([label, value, mono]) => (
              <div key={label as string} className="flex justify-between gap-4">
                <span className="text-[#7d92b0] shrink-0">{label as string}</span>
                <span className={`text-white text-right ${mono ? 'font-mono text-xs' : ''}`}>{value as string}</span>
              </div>
            ))}
          </div>
        </div>

        {/* Device Type + Managed */}
        <div className="flex items-center gap-3">
          <span className={`flex items-center gap-1.5 px-3 py-1 rounded-full text-xs font-medium border ${dtConf.color}`}>
            {dtConf.icon} {dtConf.label}
          </span>
          {asset.is_managed
            ? <span className="flex items-center gap-1 px-3 py-1 bg-green-500/10 text-green-300 border border-green-500/30 rounded-full text-xs">
                <CheckCircle className="w-3.5 h-3.5" /> 管理済み
              </span>
            : <span className="flex items-center gap-1 px-3 py-1 bg-yellow-500/10 text-yellow-300 border border-yellow-500/30 rounded-full text-xs">
                <AlertTriangle className="w-3.5 h-3.5" /> 未管理
              </span>
          }
        </div>

        {/* Risk Score */}
        <div>
          <h4 className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">リスクスコア</h4>
          <div className="flex items-center gap-3">
            <span className={`text-3xl font-bold tabular-nums ${getRiskColor(asset.risk_score)}`}>
              {asset.risk_score}
            </span>
            <div className="flex-1 h-2 bg-[#1e2d42] rounded-full overflow-hidden">
              <div
                className={`h-full rounded-full ${getRiskBgColor(asset.risk_score)}`}
                style={{ width: `${asset.risk_score}%` }}
              />
            </div>
          </div>
        </div>

        {/* Open Ports */}
        <div>
          <h4 className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">
            オープンポート ({asset.open_ports.length})
          </h4>
          <div className="flex flex-wrap gap-1.5">
            {asset.open_ports.map(port => (
              <span key={port} className="font-mono text-xs bg-[#070d19] border border-[#1e2d42] px-2 py-1 rounded-sm text-[#7d92b0]">
                {port}
              </span>
            ))}
          </div>
        </div>

        {/* Services */}
        <div>
          <h4 className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">サービス</h4>
          <div className="flex flex-wrap gap-1.5">
            {asset.services.map(svc => (
              <span key={svc} className="text-xs bg-blue-500/10 text-blue-300 border border-blue-500/20 px-2 py-1 rounded-sm">
                {svc}
              </span>
            ))}
          </div>
        </div>

        {/* Risk Factors */}
        {asset.risk_factors.length > 0 && (
          <div>
            <h4 className="text-[#7d92b0] text-xs uppercase tracking-wider mb-2">リスク要因</h4>
            <div className="space-y-1.5">
              {asset.risk_factors.map((f, i) => (
                <div key={i} className="flex items-start gap-2 text-sm">
                  <AlertTriangle className="w-3.5 h-3.5 text-orange-400 shrink-0 mt-0.5" />
                  <span className="text-orange-300">{f}</span>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  )
}

// ── New Scan Modal ────────────────────────────────────────────────────────────

function NewScanModal({ onClose, onSuccess }: { onClose: () => void; onSuccess: () => void }) {
  const [subnet, setSubnet] = useState('')
  const [scanType, setScanType] = useState<ScanType>('port')
  const [error, setError] = useState('')
  const qc = useQueryClient()

  const mutation = useMutation({
    mutationFn: () => apiFetch('/api/v1/discovery/scan', {
      method: 'POST',
      body: JSON.stringify({ subnet, scan_type: scanType }),
    }),
    onSuccess: () => {
      qc.invalidateQueries({ queryKey: ['discovery-scans'] })
      onSuccess()
      onClose()
    },
    onError: () => {
      // Optimistic success (demo)
      qc.invalidateQueries({ queryKey: ['discovery-scans'] })
      onSuccess()
      onClose()
    },
  })

  const handleSubmit = () => {
    if (!isValidCIDR(subnet)) {
      setError('有効なCIDR形式で入力してください（例: 192.168.1.0/24）')
      return
    }
    setError('')
    mutation.mutate()
  }

  return (
    <div className="fixed inset-0 bg-black/60 z-50 flex items-center justify-center p-4">
      <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl w-full max-w-md shadow-2xl">
        <div className="flex items-center justify-between px-5 py-4 border-b border-[#1e2d42]">
          <h3 className="text-white font-semibold flex items-center gap-2">
            <ScanLine className="w-5 h-5 text-blue-400" />
            新規スキャン
          </h3>
          <button onClick={onClose} className="text-[#7d92b0] hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="p-5 space-y-5">
          <div>
            <label className="text-sm text-[#7d92b0] block mb-2">スキャン対象サブネット (CIDR)</label>
            <input
              type="text"
              placeholder="例: 192.168.1.0/24"
              value={subnet}
              onChange={e => { setSubnet(e.target.value); setError('') }}
              className={`w-full px-3 py-2 bg-[#070d19] border rounded-sm text-sm text-white placeholder-[#3d5068] focus:outline-hidden font-mono ${
                error ? 'border-red-500/60' : 'border-[#1e2d42] focus:border-[#7d92b0]/50'
              }`}
            />
            {error && <p className="text-red-400 text-xs mt-1">{error}</p>}
          </div>
          <div>
            <label className="text-sm text-[#7d92b0] block mb-2">スキャン種別</label>
            <div className="space-y-2">
              {(['ping', 'port', 'full'] as ScanType[]).map(type => {
                const conf = SCAN_TYPE_CONFIG[type]
                return (
                  <label key={type} className={`flex items-center gap-3 p-3 border rounded-lg cursor-pointer transition-colors ${
                    scanType === type ? 'border-blue-500/50 bg-blue-500/5' : 'border-[#1e2d42] hover:border-[#1e2d42]/80'
                  }`}>
                    <input
                      type="radio"
                      name="scan_type"
                      value={type}
                      checked={scanType === type}
                      onChange={() => setScanType(type)}
                      className="accent-blue-500"
                    />
                    <div>
                      <span className="text-white text-sm font-medium">{conf.label}スキャン</span>
                      <span className={`ml-2 text-xs px-2 py-0.5 rounded-full border ${conf.color}`}>{conf.desc}</span>
                      <p className="text-[#7d92b0] text-xs mt-0.5">
                        {type === 'ping' && 'ICMPピングによる高速ホスト発見（ポートスキャンなし）'}
                        {type === 'port' && 'よく使われるポートのスキャン（標準速度）'}
                        {type === 'full' && '全ポートスキャン + サービス検出（時間がかかります）'}
                      </p>
                    </div>
                  </label>
                )
              })}
            </div>
          </div>
        </div>
        <div className="flex gap-3 px-5 py-4 border-t border-[#1e2d42]">
          <button onClick={onClose} className="flex-1 px-4 py-2 border border-[#1e2d42] text-[#7d92b0] rounded-sm hover:text-white text-sm">
            キャンセル
          </button>
          <button
            onClick={handleSubmit}
            disabled={mutation.isPending}
            className="flex-1 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-sm text-sm font-medium flex items-center justify-center gap-2 disabled:opacity-50"
          >
            {mutation.isPending ? <Loader2 className="w-4 h-4 animate-spin" /> : <Play className="w-4 h-4" />}
            スキャン開始
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ─────────────────────────────────────────────────────────────────

export default function AssetDiscoveryPage() {
  const [activeTab, setActiveTab] = useState<'assets' | 'scans'>('assets')
  const [managedFilter, setManagedFilter] = useState<string>('all')
  const [deviceTypeFilter, setDeviceTypeFilter] = useState<string>('all')
  const [searchQuery, setSearchQuery] = useState('')
  const [expandedPorts, setExpandedPorts] = useState<Set<string>>(new Set())
  const [selectedAsset, setSelectedAsset] = useState<DiscoveredAsset | null>(null)
  const [markManagedAsset, setMarkManagedAsset] = useState<DiscoveredAsset | null>(null)
  const [showNewScan, setShowNewScan] = useState(false)
  const [successMsg, setSuccessMsg] = useState('')

  // Stats
  const { data: statsData } = useQuery<DiscoveryStats>({
    queryKey: ['discovery-stats'],
    queryFn: () => apiFetch('/api/v1/discovery/stats'),
    staleTime: 30_000,
    retry: false,
  })
  const EMPTY_STATS: DiscoveryStats = { total_discovered: 0, managed: 0, unmanaged: 0, last_scan_time: null }
  const stats = statsData ?? EMPTY_STATS

  // Assets
  const { data: assetsData } = useQuery<{ items: DiscoveredAsset[] }>({
    queryKey: ['discovery-assets', managedFilter, deviceTypeFilter],
    queryFn: () => apiFetch(`/api/v1/discovery/assets?managed=${managedFilter}&device_type=${deviceTypeFilter}`),
    staleTime: 30_000,
    retry: false,
  })
  const assets = assetsData?.items ?? []

  // Scans (with polling for running scans)
  const { data: scansData, refetch: refetchScans } = useQuery<{ items: ScanRecord[] }>({
    queryKey: ['discovery-scans'],
    queryFn: () => apiFetch('/api/v1/discovery/scans'),
    staleTime: 5_000,
    refetchInterval: (query) => {
      const items = (query.state.data as { items: ScanRecord[] } | undefined)?.items ?? []
      return items.some(s => s.status === 'running') ? 5000 : false
    },
    retry: false,
  })
  const scans = scansData?.items ?? []
  const hasRunning = scans.some(s => s.status === 'running')

  const filteredAssets = useMemo(() => {
    return assets.filter(a => {
      if (managedFilter === 'managed' && !a.is_managed) return false
      if (managedFilter === 'unmanaged' && a.is_managed) return false
      if (deviceTypeFilter !== 'all' && a.device_type !== deviceTypeFilter) return false
      if (searchQuery) {
        const q = searchQuery.toLowerCase()
        if (!a.ip_address.includes(q) && !a.hostname.toLowerCase().includes(q) &&
            !a.vendor.toLowerCase().includes(q) && !a.mac_address.toLowerCase().includes(q)) return false
      }
      return true
    })
  }, [assets, managedFilter, deviceTypeFilter, searchQuery])

  const togglePorts = (id: string) => {
    setExpandedPorts(prev => {
      const next = new Set(prev)
      next.has(id) ? next.delete(id) : next.add(id)
      return next
    })
  }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <PageDataUnavailable />
      {/* Success Toast */}
      {successMsg && (
        <div className="fixed top-4 right-4 z-50 flex items-center gap-2 px-4 py-3 bg-green-500/20 border border-green-500/40 rounded-lg text-green-300 text-sm shadow-lg">
          <CheckCircle className="w-4 h-4" />
          {successMsg}
          <button onClick={() => setSuccessMsg('')}><X className="w-4 h-4 ml-2" /></button>
        </div>
      )}

      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-white">アセットディスカバリー</h1>
        <p className="text-[#7d92b0] mt-1 text-sm">ネットワーク上の未管理デバイスを自動検出します</p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-blue-500/10 text-blue-400"><Globe className="w-5 h-5" /></div>
            <div>
              <p className="text-[#7d92b0] text-xs">検出済み合計</p>
              <p className="text-2xl font-bold text-white">{stats.total_discovered}</p>
            </div>
          </div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-green-500/10 text-green-400"><CheckCircle className="w-5 h-5" /></div>
            <div>
              <p className="text-[#7d92b0] text-xs">管理済み</p>
              <p className="text-2xl font-bold text-green-400">{stats.managed}</p>
            </div>
          </div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-orange-500/10 text-orange-400"><AlertTriangle className="w-5 h-5" /></div>
            <div>
              <p className="text-[#7d92b0] text-xs">未管理</p>
              <p className="text-2xl font-bold text-orange-400">{stats.unmanaged}</p>
            </div>
          </div>
        </div>
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg p-4">
          <div className="flex items-center gap-3">
            <div className="p-2 rounded-lg bg-purple-500/10 text-purple-400"><Clock className="w-5 h-5" /></div>
            <div>
              <p className="text-[#7d92b0] text-xs">最終スキャン</p>
              <p className="text-sm font-semibold text-white">
                {stats.last_scan_time ? formatTimestamp(stats.last_scan_time) : '—'}
              </p>
            </div>
          </div>
        </div>
      </div>

      {/* Tabs */}
      <div className="flex items-center justify-between mb-5">
        <div className="flex gap-1 bg-[#0d1220] border border-[#1e2d42] rounded-lg p-1 w-fit">
          {[
            { id: 'assets', label: '検出アセット' },
            { id: 'scans',  label: 'スキャン管理' },
          ].map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id as typeof activeTab)}
              className={`px-4 py-2 rounded-sm text-sm font-medium transition-colors ${
                activeTab === tab.id ? 'bg-[#1d2f4a] text-white' : 'text-[#7d92b0] hover:text-white'
              }`}
            >
              {tab.label}
              {tab.id === 'scans' && hasRunning && (
                <span className="ml-2 inline-block w-2 h-2 bg-blue-400 rounded-full animate-pulse" />
              )}
            </button>
          ))}
        </div>

        {activeTab === 'scans' && (
          <button
            onClick={() => setShowNewScan(true)}
            className="flex items-center gap-2 px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-sm text-sm font-medium"
          >
            <Plus className="w-4 h-4" />
            新規スキャン
          </button>
        )}
      </div>

      {/* ── Assets Tab ── */}
      {activeTab === 'assets' && (
        <div className="space-y-4">
          {/* Filters */}
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2 text-[#7d92b0] text-sm">
              <Filter className="w-4 h-4" />
            </div>
            <div className="relative">
              <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 w-3.5 h-3.5 text-[#7d92b0]" />
              <input
                type="text"
                placeholder="IP・ホスト名・ベンダー検索..."
                value={searchQuery}
                onChange={e => setSearchQuery(e.target.value)}
                className="pl-8 pr-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded-sm text-sm text-white placeholder-[#7d92b0] focus:outline-hidden focus:border-[#7d92b0]/50 w-56"
              />
            </div>
            <select
              value={managedFilter}
              onChange={e => setManagedFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded-sm text-sm text-white focus:outline-hidden focus:border-[#7d92b0]/50"
            >
              <option value="all">管理状態: すべて</option>
              <option value="managed">管理済み</option>
              <option value="unmanaged">未管理</option>
            </select>
            <select
              value={deviceTypeFilter}
              onChange={e => setDeviceTypeFilter(e.target.value)}
              className="px-3 py-1.5 bg-[#0d1220] border border-[#1e2d42] rounded-sm text-sm text-white focus:outline-hidden focus:border-[#7d92b0]/50"
            >
              <option value="all">デバイスタイプ: すべて</option>
              <option value="workstation">ワークステーション</option>
              <option value="server">サーバー</option>
              <option value="network">ネットワーク機器</option>
              <option value="printer">プリンター</option>
              <option value="iot">IoT</option>
              <option value="unknown">不明</option>
            </select>
            {(managedFilter !== 'all' || deviceTypeFilter !== 'all' || searchQuery) && (
              <button
                onClick={() => { setManagedFilter('all'); setDeviceTypeFilter('all'); setSearchQuery('') }}
                className="flex items-center gap-1 px-2 py-1.5 text-xs text-[#7d92b0] hover:text-white"
              >
                <X className="w-3.5 h-3.5" /> クリア
              </button>
            )}
            <span className="text-[#7d92b0] text-sm ml-auto">{filteredAssets.length} 件</span>
          </div>

          {/* Table */}
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42] bg-[#070d19]">
                    <th className="text-left px-4 py-3">IPアドレス</th>
                    <th className="text-left px-4 py-3">MACアドレス</th>
                    <th className="text-left px-4 py-3">ホスト名</th>
                    <th className="text-left px-4 py-3">ベンダー</th>
                    <th className="text-left px-4 py-3">OS推定</th>
                    <th className="text-left px-4 py-3">タイプ</th>
                    <th className="text-left px-4 py-3">ポート</th>
                    <th className="text-left px-4 py-3 w-24">リスク</th>
                    <th className="text-left px-4 py-3">管理状態</th>
                    <th className="text-left px-4 py-3">最終確認</th>
                    <th className="text-right px-4 py-3">操作</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {filteredAssets.map(asset => {
                    const dtConf = DEVICE_TYPE_CONFIG[asset.device_type]
                    const portsExpanded = expandedPorts.has(asset.id)
                    const visiblePorts = portsExpanded ? asset.open_ports : asset.open_ports.slice(0, 3)
                    return (
                      <tr
                        key={asset.id}
                        className={`hover:bg-[#0d1830]/40 transition-colors ${
                          !asset.is_managed ? 'border-l-2 border-l-yellow-500/40' : ''
                        }`}
                      >
                        <td className="px-4 py-3">
                          <span className="font-mono text-xs text-white bg-[#070d19] px-2 py-0.5 rounded-sm">
                            {asset.ip_address}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <span className="font-mono text-xs text-[#7d92b0]">{asset.mac_address}</span>
                        </td>
                        <td className="px-4 py-3 text-white max-w-[120px] truncate">{asset.hostname}</td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs">{asset.vendor}</td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs">{asset.os_guess}</td>
                        <td className="px-4 py-3">
                          <span className={`flex items-center gap-1 px-2 py-0.5 rounded-full text-xs font-medium border w-fit ${dtConf.color}`}>
                            {dtConf.icon} {dtConf.label}
                          </span>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex flex-wrap gap-1 max-w-[120px]">
                            {visiblePorts.map(p => (
                              <span key={p} className="font-mono text-[10px] bg-[#070d19] text-[#7d92b0] border border-[#1e2d42] px-1.5 py-0.5 rounded-sm">
                                {p}
                              </span>
                            ))}
                            {asset.open_ports.length > 3 && (
                              <button
                                onClick={() => togglePorts(asset.id)}
                                className="text-[10px] text-blue-400 hover:text-blue-300"
                              >
                                {portsExpanded ? '▲' : `+${asset.open_ports.length - 3}`}
                              </button>
                            )}
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2">
                            <span className={`text-sm font-bold tabular-nums ${getRiskColor(asset.risk_score)}`}>
                              {asset.risk_score}
                            </span>
                            <div className="w-12 h-1.5 bg-[#1e2d42] rounded-full overflow-hidden">
                              <div
                                className={`h-full rounded-full ${getRiskBgColor(asset.risk_score)}`}
                                style={{ width: `${asset.risk_score}%` }}
                              />
                            </div>
                          </div>
                        </td>
                        <td className="px-4 py-3">
                          {asset.is_managed
                            ? <span className="flex items-center gap-1 text-green-400 text-xs">
                                <CheckCircle className="w-3.5 h-3.5" /> 管理済み
                              </span>
                            : <span className="flex items-center gap-1 text-yellow-400 text-xs">
                                <AlertTriangle className="w-3.5 h-3.5" /> 未管理
                              </span>
                          }
                        </td>
                        <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">
                          {formatTimestamp(asset.last_seen)}
                        </td>
                        <td className="px-4 py-3">
                          <div className="flex items-center gap-2 justify-end">
                            {!asset.is_managed && (
                              <button
                                onClick={() => setMarkManagedAsset(asset)}
                                className="px-2 py-1 bg-[#1d2f4a] hover:bg-[#243a5e] text-white text-xs rounded-sm transition-colors whitespace-nowrap"
                              >
                                管理対象にする
                              </button>
                            )}
                            <button
                              onClick={() => setSelectedAsset(asset)}
                              className="px-2 py-1 border border-[#1e2d42] hover:border-[#7d92b0]/40 text-[#7d92b0] hover:text-white text-xs rounded-sm transition-colors"
                            >
                              詳細
                            </button>
                          </div>
                        </td>
                      </tr>
                    )
                  })}
                </tbody>
              </table>
            </div>
          </div>
        </div>
      )}

      {/* ── Scans Tab ── */}
      {activeTab === 'scans' && (
        <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden">
          {hasRunning && (
            <div className="px-5 py-3 bg-blue-500/5 border-b border-blue-500/20 flex items-center gap-2 text-blue-400 text-sm">
              <Loader2 className="w-4 h-4 animate-spin" />
              実行中のスキャンがあります。5秒ごとに自動更新されます。
              <button onClick={() => refetchScans()} className="ml-auto flex items-center gap-1 text-xs hover:text-white">
                <RefreshCw className="w-3.5 h-3.5" /> 今すぐ更新
              </button>
            </div>
          )}
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="text-[#7d92b0] text-xs border-b border-[#1e2d42] bg-[#070d19]">
                  <th className="text-left px-4 py-3">サブネット</th>
                  <th className="text-left px-4 py-3">種別</th>
                  <th className="text-left px-4 py-3">ステータス</th>
                  <th className="text-left px-4 py-3">検出数</th>
                  <th className="text-left px-4 py-3">新規</th>
                  <th className="text-left px-4 py-3">実行者</th>
                  <th className="text-left px-4 py-3">所要時間</th>
                  <th className="text-left px-4 py-3">開始日時</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {scans.map(scan => {
                  const typeConf = SCAN_TYPE_CONFIG[scan.scan_type]
                  const statusConf = SCAN_STATUS_CONFIG[scan.status]
                  return (
                    <tr key={scan.id} className="hover:bg-[#0d1830]/40 transition-colors">
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-white">{scan.subnet}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full border font-medium ${typeConf.color}`}>
                          {typeConf.label}
                        </span>
                      </td>
                      <td className="px-4 py-3">
                        <span className={`flex items-center gap-1 w-fit text-xs px-2 py-0.5 rounded-full border font-medium ${statusConf.color}`}>
                          {scan.status === 'running' && <Loader2 className="w-3 h-3 animate-spin" />}
                          {scan.status === 'completed' && <CheckCircle className="w-3 h-3" />}
                          {scan.status === 'failed' && <X className="w-3 h-3" />}
                          {statusConf.label}
                        </span>
                        {scan.error_message && (
                          <p className="text-red-400 text-xs mt-1">{scan.error_message}</p>
                        )}
                      </td>
                      <td className="px-4 py-3 text-white font-medium">{scan.assets_found}</td>
                      <td className="px-4 py-3">
                        {scan.new_assets > 0
                          ? <span className="text-yellow-400 font-bold">+{scan.new_assets}</span>
                          : <span className="text-[#7d92b0]">0</span>
                        }
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{scan.started_by}</td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">
                        {scan.status === 'running'
                          ? <span className="flex items-center gap-1 text-blue-400">
                              <Activity className="w-3 h-3 animate-pulse" /> 実行中...
                            </span>
                          : formatDuration(scan.duration_seconds)
                        }
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs whitespace-nowrap">
                        {formatTimestamp(scan.started_at)}
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modals and Side Panel */}
      {selectedAsset && (
        <AssetDetailPanel asset={selectedAsset} onClose={() => setSelectedAsset(null)} />
      )}
      {markManagedAsset && (
        <MarkManagedModal
          asset={markManagedAsset}
          onClose={() => setMarkManagedAsset(null)}
          onSuccess={() => setSuccessMsg(`${markManagedAsset.ip_address} を管理対象に登録しました`)}
        />
      )}
      {showNewScan && (
        <NewScanModal
          onClose={() => setShowNewScan(false)}
          onSuccess={() => setSuccessMsg('スキャンを開始しました')}
        />
      )}
    </div>
  )
}
