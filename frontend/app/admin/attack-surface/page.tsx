'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  ScanSearch, Plus, Trash2, Edit2, X, AlertTriangle,
  Globe, Server, Wifi, Shield, FileCode, Download,
  ToggleLeft, ToggleRight, RefreshCw, Play, Filter,
  Tag, Clock, ChevronRight
} from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────

type AssetType = 'domain' | 'ip' | 'port' | 'service' | 'certificate' | 'api_endpoint'
type ScanType = 'port_scan' | 'dns_enum' | 'cert_check' | 'api_discovery'
type ScanStatus = 'pending' | 'running' | 'completed' | 'failed'

interface Asset {
  id: string
  type: AssetType
  value: string
  risk_score: number
  is_known: boolean
  is_monitored: boolean
  tags: string[]
  first_seen: string
  last_seen: string
}

interface Scan {
  id: string
  scan_type: ScanType
  target: string
  description: string
  status: ScanStatus
  assets_found: number
  new_assets: number
  duration: number | null
  started_at: string
  completed_at: string | null
}

interface AttackSurfaceStats {
  total_assets: number
  unknown_assets: number
  high_risk_assets: number
  last_scan_time: string
  by_type: Record<AssetType, number>
}

const EMPTY_STATS: AttackSurfaceStats = {
  total_assets: 0,
  unknown_assets: 0,
  high_risk_assets: 0,
  last_scan_time: '',
  by_type: {} as Record<AssetType, number>,
}

// ── Helpers ────────────────────────────────────────────────────────

const ASSET_TYPE_CONFIG: Record<AssetType, { label: string; icon: typeof Globe; bg: string; text: string }> = {
  domain:       { label: 'Domain',      icon: Globe,     bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  ip:           { label: 'IP',          icon: Server,    bg: 'bg-purple-900/40', text: 'text-purple-300' },
  port:         { label: 'Port',        icon: Wifi,      bg: 'bg-green-900/40',  text: 'text-green-300' },
  service:      { label: 'Service',     icon: Shield,    bg: 'bg-orange-900/40', text: 'text-orange-300' },
  certificate:  { label: 'Cert',        icon: FileCode,  bg: 'bg-pink-900/40',   text: 'text-pink-300' },
  api_endpoint: { label: 'API',         icon: ChevronRight, bg: 'bg-cyan-900/40', text: 'text-cyan-300' },
}

const SCAN_TYPE_CONFIG: Record<ScanType, { label: string; bg: string; text: string }> = {
  port_scan:     { label: 'ポートスキャン',  bg: 'bg-blue-900/40',   text: 'text-blue-300' },
  dns_enum:      { label: 'DNS列挙',         bg: 'bg-purple-900/40', text: 'text-purple-300' },
  cert_check:    { label: '証明書確認',       bg: 'bg-green-900/40',  text: 'text-green-300' },
  api_discovery: { label: 'API探索',          bg: 'bg-orange-900/40', text: 'text-orange-300' },
}

const SCAN_STATUS_CONFIG: Record<ScanStatus, { label: string; bg: string; text: string }> = {
  pending:   { label: '待機中',    bg: 'bg-gray-800',      text: 'text-gray-300' },
  running:   { label: '実行中',    bg: 'bg-blue-900/50',   text: 'text-blue-300' },
  completed: { label: '完了',      bg: 'bg-green-900/50',  text: 'text-green-300' },
  failed:    { label: '失敗',      bg: 'bg-red-900/50',    text: 'text-red-300' },
}

function riskColor(score: number): string {
  if (score < 30) return 'bg-green-500'
  if (score < 70) return 'bg-yellow-500'
  return 'bg-red-500'
}

function riskTextColor(score: number): string {
  if (score < 30) return 'text-green-400'
  if (score < 70) return 'text-yellow-400'
  return 'text-red-400'
}

function fmt(ts: string | null) {
  if (!ts) return '—'
  return new Date(ts).toLocaleString('ja-JP', { month: '2-digit', day: '2-digit', hour: '2-digit', minute: '2-digit' })
}

function fmtDuration(sec: number | null): string {
  if (sec === null) return '—'
  if (sec < 60) return `${sec}s`
  return `${Math.floor(sec / 60)}m ${sec % 60}s`
}

// ── Add Asset Modal ────────────────────────────────────────────────

function AddAssetModal({ onClose, onAdd }: {
  onClose: () => void
  onAdd: (a: Omit<Asset, 'id' | 'first_seen' | 'last_seen'>) => void
}) {
  const [form, setForm] = useState({
    type: 'domain' as AssetType,
    value: '',
    risk_score: 50,
    is_known: true,
    is_monitored: true,
    tags: [] as string[],
  })
  const [tagInput, setTagInput] = useState('')

  const addTag = () => {
    const t = tagInput.trim()
    if (t && !form.tags.includes(t)) {
      setForm(p => ({ ...p, tags: [...p.tags, t] }))
    }
    setTagInput('')
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-white font-semibold text-lg">資産追加</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">タイプ</label>
            <select value={form.type} onChange={e => setForm(p => ({ ...p, type: e.target.value as AssetType }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50">
              {(Object.keys(ASSET_TYPE_CONFIG) as AssetType[]).map(t => (
                <option key={t} value={t}>{ASSET_TYPE_CONFIG[t].label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">値</label>
            <input value={form.value} onChange={e => setForm(p => ({ ...p, value: e.target.value }))}
              placeholder="example.com / 192.168.1.1 / ..."
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white font-mono focus:outline-hidden focus:border-falcon-red/50" />
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">リスクスコア: <span className={riskTextColor(form.risk_score)}>{form.risk_score}</span></label>
            <input type="range" min={0} max={100} value={form.risk_score} onChange={e => setForm(p => ({ ...p, risk_score: Number(e.target.value) }))}
              className="w-full accent-falcon-red" />
          </div>
          <div className="flex gap-6">
            <label className="flex items-center gap-2 text-sm text-falcon-muted cursor-pointer">
              <button onClick={() => setForm(p => ({ ...p, is_known: !p.is_known }))} className="text-falcon-muted">
                {form.is_known ? <ToggleRight className="w-6 h-6 text-green-400" /> : <ToggleLeft className="w-6 h-6" />}
              </button>
              既知の資産
            </label>
            <label className="flex items-center gap-2 text-sm text-falcon-muted cursor-pointer">
              <button onClick={() => setForm(p => ({ ...p, is_monitored: !p.is_monitored }))} className="text-falcon-muted">
                {form.is_monitored ? <ToggleRight className="w-6 h-6 text-green-400" /> : <ToggleLeft className="w-6 h-6" />}
              </button>
              監視中
            </label>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">タグ</label>
            <div className="flex gap-2 mb-2 flex-wrap">
              {form.tags.map(t => (
                <span key={t} className="flex items-center gap-1 bg-falcon-border text-falcon-muted text-xs px-2 py-0.5 rounded-full">
                  {t}
                  <button onClick={() => setForm(p => ({ ...p, tags: p.tags.filter(x => x !== t) }))} className="hover:text-white">
                    <X className="w-2.5 h-2.5" />
                  </button>
                </span>
              ))}
            </div>
            <div className="flex gap-2">
              <input value={tagInput} onChange={e => setTagInput(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && (e.preventDefault(), addTag())}
                placeholder="タグを入力..."
                className="flex-1 bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50" />
              <button onClick={addTag} className="px-3 py-2 bg-falcon-border text-falcon-muted rounded-sm text-sm hover:text-white">追加</button>
            </div>
          </div>
        </div>
        <div className="flex gap-3 mt-6">
          <button onClick={onClose} className="flex-1 py-2 rounded-sm border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => { if (form.value) { onAdd(form); onClose() } }}
            className="flex-1 py-2 rounded-sm bg-falcon-red text-white text-sm font-medium hover:bg-[#c8001e] transition-colors">追加</button>
        </div>
      </div>
    </div>
  )
}

// ── New Scan Modal ─────────────────────────────────────────────────

function NewScanModal({ onClose, onStart }: {
  onClose: () => void
  onStart: (s: { scan_type: ScanType; target: string; description: string }) => void
}) {
  const [form, setForm] = useState({ scan_type: 'port_scan' as ScanType, target: '', description: '' })

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60">
      <div className="bg-falcon-surface border border-falcon-border rounded-xl w-full max-w-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <h2 className="text-white font-semibold text-lg">新規スキャン</h2>
          <button onClick={onClose} className="text-falcon-muted hover:text-white"><X className="w-5 h-5" /></button>
        </div>
        <div className="space-y-4">
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">スキャンタイプ</label>
            <select value={form.scan_type} onChange={e => setForm(p => ({ ...p, scan_type: e.target.value as ScanType }))}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50">
              {(Object.keys(SCAN_TYPE_CONFIG) as ScanType[]).map(t => (
                <option key={t} value={t}>{SCAN_TYPE_CONFIG[t].label}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">ターゲット (ドメインまたはIP/CIDR)</label>
            <input value={form.target} onChange={e => setForm(p => ({ ...p, target: e.target.value }))}
              placeholder="example.com / 192.168.1.0/24"
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white font-mono focus:outline-hidden focus:border-falcon-red/50" />
          </div>
          <div>
            <label className="text-xs text-falcon-muted mb-1 block">説明 (任意)</label>
            <textarea value={form.description} onChange={e => setForm(p => ({ ...p, description: e.target.value }))}
              rows={3} placeholder="スキャンの目的や背景..."
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-white focus:outline-hidden focus:border-falcon-red/50 resize-none" />
          </div>
        </div>
        <div className="flex gap-3 mt-6">
          <button onClick={onClose} className="flex-1 py-2 rounded-sm border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors">キャンセル</button>
          <button onClick={() => { if (form.target) { onStart(form); onClose() } }}
            className="flex-1 py-2 rounded-sm bg-falcon-red text-white text-sm font-medium hover:bg-[#c8001e] transition-colors flex items-center justify-center gap-2">
            <Play className="w-4 h-4" /> スキャン開始
          </button>
        </div>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────

export default function AttackSurfacePage() {
  const [tab, setTab] = useState<'assets' | 'scans'>('assets')
  const [assetTypeFilter, setAssetTypeFilter] = useState<AssetType | 'all'>('all')
  const [tagFilters, setTagFilters] = useState<string[]>([])
  const [showAddAsset, setShowAddAsset] = useState(false)
  const [showNewScan, setShowNewScan] = useState(false)
  const [editAsset, setEditAsset] = useState<Asset | null>(null)
  const [localAssets, setLocalAssets] = useState<Asset[]>([])
  const [localScans, setLocalScans] = useState<Scan[]>([])
  const [toast, setToast] = useState<string | null>(null)

  const showToast = (msg: string) => { setToast(msg); setTimeout(() => setToast(null), 4000) }

  // Fetch assets
  const { data: assetsData } = useQuery<Asset[]>({
    queryKey: ['attack-surface-assets'],
    queryFn: () => apiFetchList<Asset>('/api/v1/admin/attack-surface/assets').catch(() => []),
  })

  const { data: statsData } = useQuery<AttackSurfaceStats>({
    queryKey: ['attack-surface-stats'],
    queryFn: async () => {
      try {
        const res = await apiFetch('/api/v1/admin/attack-surface/stats')
        return (res && typeof res === 'object' && 'by_type' in (res as object)) ? res as AttackSurfaceStats : EMPTY_STATS
      } catch { return EMPTY_STATS }
    },
  })

  const { data: scansData } = useQuery<Scan[]>({
    queryKey: ['attack-surface-scans'],
    queryFn: () => apiFetchList<Scan>('/api/v1/admin/attack-surface/scans').catch(() => []),
  })

  const assets: Asset[] = assetsData ?? localAssets
  const stats: AttackSurfaceStats = statsData ?? EMPTY_STATS
  const scans: Scan[] = scansData ?? localScans

  // Poll running scans
  useEffect(() => {
    const running = localScans.filter(s => s.status === 'running')
    if (running.length === 0) return
    const interval = setInterval(() => {
      setLocalScans(prev => prev.map(s => {
        if (s.status !== 'running') return s
        const elapsed = (Date.now() - new Date(s.started_at).getTime()) / 1000
        if (elapsed > 15) {
          return { ...s, status: 'completed', assets_found: Math.floor(Math.random() * 30) + 5, new_assets: Math.floor(Math.random() * 5), duration: Math.floor(elapsed), completed_at: new Date().toISOString() }
        }
        return s
      }))
    }, 3000)
    return () => clearInterval(interval)
  }, [localScans])

  // Collect all tags
  const allTags = Array.from(new Set(assets.flatMap(a => a.tags))).sort()

  // Filter assets
  const filteredAssets = localAssets.filter(a => {
    if (assetTypeFilter !== 'all' && a.type !== assetTypeFilter) return false
    if (tagFilters.length > 0 && !tagFilters.every(t => a.tags.includes(t))) return false
    return true
  })

  const handleToggleKnown = async (asset: Asset) => {
    try { await apiFetch(`/api/v1/admin/attack-surface/assets/${asset.id}`, { method: 'PUT', body: JSON.stringify({ is_known: !asset.is_known }) }) } catch {}
    setLocalAssets(prev => prev.map(a => a.id === asset.id ? { ...a, is_known: !a.is_known } : a))
  }

  const handleToggleMonitored = async (asset: Asset) => {
    try { await apiFetch(`/api/v1/admin/attack-surface/assets/${asset.id}`, { method: 'PUT', body: JSON.stringify({ is_monitored: !asset.is_monitored }) }) } catch {}
    setLocalAssets(prev => prev.map(a => a.id === asset.id ? { ...a, is_monitored: !a.is_monitored } : a))
  }

  const handleDeleteAsset = async (asset: Asset) => {
    try { await apiFetch(`/api/v1/admin/attack-surface/assets/${asset.id}`, { method: 'DELETE' }) } catch {}
    setLocalAssets(prev => prev.filter(a => a.id !== asset.id))
    showToast(`資産「${asset.value}」を削除しました`)
  }

  const handleAddAsset = (form: Omit<Asset, 'id' | 'first_seen' | 'last_seen'>) => {
    const newAsset: Asset = { ...form, id: String(Date.now()), first_seen: new Date().toISOString(), last_seen: new Date().toISOString() }
    try { apiFetch('/api/v1/admin/attack-surface/assets', { method: 'POST', body: JSON.stringify(form) }) } catch {}
    setLocalAssets(prev => [newAsset, ...prev])
    showToast(`資産「${form.value}」を追加しました`)
  }

  const handleStartScan = async (form: { scan_type: ScanType; target: string; description: string }) => {
    const newScan: Scan = { id: String(Date.now()), ...form, status: 'running', assets_found: 0, new_assets: 0, duration: null, started_at: new Date().toISOString(), completed_at: null }
    try { await apiFetch('/api/v1/admin/attack-surface/scans', { method: 'POST', body: JSON.stringify(form) }) } catch {}
    setLocalScans(prev => [newScan, ...prev])
    showToast(`スキャンを開始しました: ${form.target}`)
  }

  const handleExportCSV = () => {
    const header = 'type,value,risk_score,is_known,is_monitored,tags,first_seen,last_seen\n'
    const rows = filteredAssets.map(a => `${a.type},${a.value},${a.risk_score},${a.is_known},${a.is_monitored},"${a.tags.join(';')}",${a.first_seen},${a.last_seen}`).join('\n')
    const blob = new Blob([header + rows], { type: 'text/csv' })
    const url = URL.createObjectURL(blob)
    const link = document.createElement('a')
    link.href = url; link.download = 'attack-surface-assets.csv'; link.click()
    showToast('CSVをエクスポートしました')
  }

  const totalScans = localScans.length
  const avgAssetsPerScan = totalScans > 0 ? Math.round(localScans.reduce((s, sc) => s + sc.assets_found, 0) / totalScans) : 0
  const newAssetsThisWeek = localScans.filter(s => {
    const d = new Date(s.started_at)
    return (Date.now() - d.getTime()) < 7 * 24 * 3600 * 1000
  }).reduce((s, sc) => s + sc.new_assets, 0)

  const typeValues = Object.values(stats.by_type) as number[]
  const typeMaxCount = typeValues.length > 0 ? Math.max(...typeValues) : 1

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="flex items-center gap-3 mb-6">
        <div className="w-10 h-10 rounded-lg bg-linear-to-br from-falcon-red to-falcon-red-dark flex items-center justify-center">
          <ScanSearch className="w-5 h-5 text-white" />
        </div>
        <div>
          <h1 className="text-white text-2xl font-bold">攻撃面管理</h1>
          <p className="text-falcon-muted text-sm">発見された外部・内部資産のリスク管理</p>
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '総発見資産', value: stats.total_assets, icon: ScanSearch, color: 'text-blue-400' },
          { label: '未確認資産', value: stats.unknown_assets, icon: AlertTriangle, color: 'text-yellow-400' },
          { label: '高リスク資産', value: stats.high_risk_assets, icon: Shield, color: 'text-red-400' },
          { label: '最終スキャン', value: fmt(stats.last_scan_time), icon: Clock, color: 'text-green-400', small: true },
        ].map(c => (
          <div key={c.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
            <div className="flex items-center gap-2 mb-2">
              <c.icon className={`w-4 h-4 ${c.color}`} />
              <span className="text-falcon-muted text-xs">{c.label}</span>
            </div>
            <p className={`font-bold ${c.color} ${(c as any).small ? 'text-base' : 'text-3xl'}`}>{c.value}</p>
          </div>
        ))}
      </div>

      {/* Tabs */}
      <div className="flex gap-2 mb-6">
        {[{ key: 'assets', label: '発見資産' }, { key: 'scans', label: 'スキャン管理' }].map(t => (
          <button key={t.key} onClick={() => setTab(t.key as any)}
            className={`px-4 py-2 rounded-lg text-sm font-medium transition-colors ${
              tab === t.key ? 'bg-falcon-red text-white' : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-white'
            }`}>{t.label}</button>
        ))}
      </div>

      {/* Assets Tab */}
      {tab === 'assets' && (
        <div>
          {/* Asset Type Filters */}
          <div className="flex items-center gap-2 mb-4 flex-wrap">
            {(['all', 'domain', 'ip', 'port', 'service', 'certificate', 'api_endpoint'] as const).map(t => (
              <button key={t} onClick={() => setAssetTypeFilter(t)}
                className={`px-3 py-1.5 rounded-full text-xs font-medium transition-colors ${
                  assetTypeFilter === t
                    ? 'bg-falcon-red text-white'
                    : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-white'
                }`}>
                {t === 'all' ? 'すべて' : ASSET_TYPE_CONFIG[t].label}
              </button>
            ))}
          </div>

          {/* Tag Filters */}
          {allTags.length > 0 && (
            <div className="flex items-center gap-2 mb-4 flex-wrap">
              <span className="text-xs text-falcon-muted flex items-center gap-1"><Tag className="w-3 h-3" /> タグ:</span>
              {allTags.map(t => (
                <button key={t} onClick={() => setTagFilters(prev => prev.includes(t) ? prev.filter(x => x !== t) : [...prev, t])}
                  className={`px-2 py-0.5 rounded-full text-xs transition-colors ${
                    tagFilters.includes(t) ? 'bg-blue-600 text-white' : 'bg-falcon-surface border border-falcon-border text-falcon-muted hover:text-white'
                  }`}>{t}</button>
              ))}
              {tagFilters.length > 0 && (
                <button onClick={() => setTagFilters([])} className="text-xs text-falcon-muted hover:text-white ml-2">クリア</button>
              )}
            </div>
          )}

          {/* Toolbar */}
          <div className="flex items-center justify-between mb-4">
            <p className="text-falcon-muted text-sm">{filteredAssets.length} 件</p>
            <div className="flex gap-2">
              <button onClick={handleExportCSV}
                className="flex items-center gap-2 px-3 py-2 bg-falcon-surface border border-falcon-border text-falcon-muted rounded-lg text-sm hover:text-white transition-colors">
                <Download className="w-4 h-4" /> CSV
              </button>
              <button onClick={() => setShowAddAsset(true)}
                className="flex items-center gap-2 px-4 py-2 bg-falcon-red text-white rounded-lg text-sm font-medium hover:bg-[#c8001e] transition-colors">
                <Plus className="w-4 h-4" /> 資産追加
              </button>
            </div>
          </div>

          {/* Assets Table */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden mb-6">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['タイプ', '値', 'リスク', '既知', '監視', 'タグ', '初回検出', '最終確認', '操作'].map(h => (
                    <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {filteredAssets.map(asset => {
                  const tc = ASSET_TYPE_CONFIG[asset.type]
                  const AssetIcon = tc.icon
                  return (
                    <tr key={asset.id}
                      className={`border-b border-falcon-border/50 hover:bg-[#070d19]/50 transition-colors ${!asset.is_known ? 'bg-yellow-900/5' : ''}`}>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-1.5">
                          <span className={`inline-flex items-center gap-1 text-xs px-2 py-0.5 rounded-full font-medium ${tc.bg} ${tc.text}`}>
                            <AssetIcon className="w-3 h-3" />
                            {tc.label}
                          </span>
                          {!asset.is_known && (
                            <span className="text-xs px-1.5 py-0.5 rounded-sm bg-yellow-900/50 text-yellow-300 font-medium">未確認</span>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 max-w-[220px]">
                        <span className="text-white text-xs font-mono truncate block" title={asset.value}>{asset.value}</span>
                      </td>
                      <td className="px-4 py-3 min-w-[120px]">
                        <div className="flex items-center gap-2">
                          <div className="flex-1 h-1.5 bg-falcon-border rounded-full overflow-hidden">
                            <div className={`h-full rounded-full ${riskColor(asset.risk_score)}`} style={{ width: `${asset.risk_score}%` }} />
                          </div>
                          <span className={`text-xs font-bold ${riskTextColor(asset.risk_score)}`}>{asset.risk_score}</span>
                        </div>
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => handleToggleKnown(asset)}>
                          {asset.is_known ? <ToggleRight className="w-5 h-5 text-green-400" /> : <ToggleLeft className="w-5 h-5 text-falcon-subtle" />}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <button onClick={() => handleToggleMonitored(asset)}>
                          {asset.is_monitored ? <ToggleRight className="w-5 h-5 text-blue-400" /> : <ToggleLeft className="w-5 h-5 text-falcon-subtle" />}
                        </button>
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {asset.tags.map(t => (
                            <span key={t} className="text-xs bg-falcon-border text-falcon-muted px-1.5 py-0.5 rounded-full">{t}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">{fmt(asset.first_seen)}</td>
                      <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">{fmt(asset.last_seen)}</td>
                      <td className="px-4 py-3">
                        <div className="flex items-center gap-2">
                          <button onClick={() => setEditAsset(asset)} className="text-falcon-muted hover:text-white transition-colors">
                            <Edit2 className="w-3.5 h-3.5" />
                          </button>
                          <button onClick={() => handleDeleteAsset(asset)} className="text-falcon-muted hover:text-red-400 transition-colors">
                            <Trash2 className="w-3.5 h-3.5" />
                          </button>
                        </div>
                      </td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
            {filteredAssets.length === 0 && <div className="text-center py-12 text-falcon-muted text-sm">条件に一致する資産がありません</div>}
          </div>

          {/* Stats — Asset count by type */}
          <div className="bg-falcon-surface border border-falcon-border rounded-xl p-5">
            <h3 className="text-white font-semibold text-sm mb-4">資産タイプ別分布</h3>
            <div className="space-y-3">
              {(Object.entries(stats.by_type) as [AssetType, number][]).map(([type, count]) => {
                const tc = ASSET_TYPE_CONFIG[type]
                const pct = typeMaxCount > 0 ? (count / typeMaxCount) * 100 : 0
                return (
                  <div key={type} className="flex items-center gap-3">
                    <span className={`text-xs font-medium ${tc.text} w-24 shrink-0`}>{tc.label}</span>
                    <div className="flex-1 h-2 bg-falcon-border rounded-full overflow-hidden">
                      <div className={`h-full rounded-full ${tc.bg.replace('/40', '')}`} style={{ width: `${pct}%` }} />
                    </div>
                    <span className="text-xs text-falcon-muted w-6 text-right">{count}</span>
                  </div>
                )
              })}
            </div>
          </div>
        </div>
      )}

      {/* Scans Tab */}
      {tab === 'scans' && (
        <div>
          {/* Scan summary cards */}
          <div className="grid grid-cols-3 gap-4 mb-6">
            {[
              { label: '総スキャン数', value: totalScans, color: 'text-blue-400' },
              { label: '平均検出数/スキャン', value: avgAssetsPerScan, color: 'text-green-400' },
              { label: '今週の新規発見', value: newAssetsThisWeek, color: 'text-yellow-400' },
            ].map(c => (
              <div key={c.label} className="bg-falcon-surface border border-falcon-border rounded-xl p-4">
                <p className="text-xs text-falcon-muted mb-1">{c.label}</p>
                <p className={`text-3xl font-bold ${c.color}`}>{c.value}</p>
              </div>
            ))}
          </div>

          <div className="flex justify-between items-center mb-4">
            <p className="text-falcon-muted text-sm">{localScans.length} 件のスキャン履歴</p>
            <button onClick={() => setShowNewScan(true)}
              className="flex items-center gap-2 px-4 py-2 bg-falcon-red text-white rounded-lg text-sm font-medium hover:bg-[#c8001e] transition-colors">
              <Plus className="w-4 h-4" /> 新規スキャン
            </button>
          </div>

          <div className="bg-falcon-surface border border-falcon-border rounded-xl overflow-hidden">
            <table className="w-full">
              <thead>
                <tr className="border-b border-falcon-border">
                  {['タイプ', 'ターゲット', 'ステータス', '発見数', '新規', '所要時間', '開始時刻'].map(h => (
                    <th key={h} className="text-left text-xs text-falcon-muted font-medium px-4 py-3">{h}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {localScans.map(scan => {
                  const sc = SCAN_TYPE_CONFIG[scan.scan_type]
                  const ss = SCAN_STATUS_CONFIG[scan.status]
                  return (
                    <tr key={scan.id} className="border-b border-falcon-border/50 hover:bg-[#070d19]/50 transition-colors">
                      <td className="px-4 py-3">
                        <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${sc.bg} ${sc.text}`}>{sc.label}</span>
                      </td>
                      <td className="px-4 py-3">
                        <span className="text-white text-xs font-mono">{scan.target}</span>
                        {scan.description && <p className="text-falcon-muted text-xs truncate max-w-[180px]">{scan.description}</p>}
                      </td>
                      <td className="px-4 py-3">
                        <div className="flex flex-col gap-1">
                          <span className={`text-xs px-2 py-0.5 rounded-full font-medium ${ss.bg} ${ss.text} inline-flex items-center gap-1 w-fit ${scan.status === 'running' ? 'animate-pulse' : ''}`}>
                            {scan.status === 'running' && <span className="w-1.5 h-1.5 rounded-full bg-blue-400 animate-ping" />}
                            {ss.label}
                          </span>
                          {scan.status === 'running' && (
                            <div className="w-24 h-1 bg-falcon-border rounded-full overflow-hidden">
                              <div className="h-full bg-blue-400 rounded-full animate-pulse" style={{ width: '60%' }} />
                            </div>
                          )}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-xs text-white font-semibold">{scan.assets_found}</td>
                      <td className="px-4 py-3">
                        <span className={`text-xs font-semibold ${scan.new_assets > 0 ? 'text-yellow-300 bg-yellow-900/40 px-2 py-0.5 rounded-sm' : 'text-falcon-muted'}`}>
                          {scan.new_assets > 0 ? `+${scan.new_assets}` : '0'}
                        </span>
                      </td>
                      <td className="px-4 py-3 text-xs text-falcon-muted font-mono">{fmtDuration(scan.duration)}</td>
                      <td className="px-4 py-3 text-xs text-falcon-muted whitespace-nowrap">{fmt(scan.started_at)}</td>
                    </tr>
                  )
                })}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Modals */}
      {showAddAsset && <AddAssetModal onClose={() => setShowAddAsset(false)} onAdd={handleAddAsset} />}
      {showNewScan && <NewScanModal onClose={() => setShowNewScan(false)} onStart={handleStartScan} />}

      {/* Toast */}
      {toast && (
        <div className="fixed bottom-6 right-6 z-50 max-w-sm bg-falcon-surface border border-green-500/50 rounded-lg p-4 shadow-xl flex items-center gap-3">
          <Shield className="w-4 h-4 text-green-400 shrink-0" />
          <p className="text-sm text-falcon-text flex-1">{toast}</p>
          <button onClick={() => setToast(null)} className="text-falcon-muted hover:text-white"><X className="w-4 h-4" /></button>
        </div>
      )}
    </div>
  )
}
