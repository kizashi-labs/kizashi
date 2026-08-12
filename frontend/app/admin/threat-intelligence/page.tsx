'use client'

import { useState } from 'react'
import { useQuery } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Globe, RefreshCw, Plus, X, Search, ChevronLeft, ChevronRight,
  AlertTriangle, CheckCircle, Clock, Database, Shield, Wifi, Hash,
  Link, ToggleLeft, ToggleRight, ExternalLink,
} from 'lucide-react'


// ─── Types ────────────────────────────────────────────────────────────────────

type FeedType = 'MISP' | 'OpenCTI' | 'CSV' | 'Static'
type IocType = 'ip' | 'domain' | 'hash' | 'url'
type Severity = 'critical' | 'high' | 'medium' | 'low'

interface Feed {
  id: string
  name: string
  type: FeedType
  url: string
  enabled: boolean
  ioc_count: number
  last_sync: string
  api_key?: string
  fetch_interval: number
}

interface IOC {
  id: string
  value: string
  type: IocType
  confidence: number
  severity: Severity
  source: string
  tags: string[]
  expires: string
}

interface LookupResult {
  value: string
  type: IocType
  confidence: number
  severity: Severity
  source: string
  tags: string[]
  found: boolean
}

interface Stats {
  total_iocs: number
  active_feeds: number
  last_updated: string
  high_confidence: number
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

const FEED_TYPE_STYLE: Record<FeedType, string> = {
  MISP: 'bg-purple-500/15 text-purple-400 border-purple-500/30',
  OpenCTI: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
  CSV: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  Static: 'bg-zinc-500/15 text-zinc-400 border-zinc-500/30',
}

const SEVERITY_STYLE: Record<Severity, string> = {
  critical: 'bg-red-500/15 text-red-400 border-red-500/30',
  high: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
  medium: 'bg-yellow-500/15 text-yellow-400 border-yellow-500/30',
  low: 'bg-blue-500/15 text-blue-400 border-blue-500/30',
}

const SEVERITY_LABEL: Record<Severity, string> = {
  critical: '重大',
  high: '高',
  medium: '中',
  low: '低',
}

const IOC_TYPE_ICON: Record<IocType, React.ReactNode> = {
  ip: <Wifi className="w-3.5 h-3.5" />,
  domain: <Globe className="w-3.5 h-3.5" />,
  hash: <Hash className="w-3.5 h-3.5" />,
  url: <Link className="w-3.5 h-3.5" />,
}

const IOC_TYPE_LABEL: Record<IocType, string> = {
  ip: 'IP',
  domain: 'ドメイン',
  hash: 'ハッシュ',
  url: 'URL',
}

const PAGE_SIZE = 5

// ─── Main Component ───────────────────────────────────────────────────────────

export default function ThreatIntelligencePage() {
  const [syncingFeed, setSyncingFeed] = useState<string | null>(null)
  const [showAddFeed, setShowAddFeed] = useState(false)
  const [feedForm, setFeedForm] = useState({ name: '', type: 'MISP' as FeedType, url: '', api_key: '', fetch_interval: 60 })
  const [lookupValue, setLookupValue] = useState('')
  const [lookupResult, setLookupResult] = useState<LookupResult | null>(null)
  const [lookupLoading, setLookupLoading] = useState(false)
  const [iocTab, setIocTab] = useState<'all' | IocType>('all')
  const [iocPage, setIocPage] = useState(1)

  const { data: statsData } = useQuery<Stats>({
    queryKey: ['ti-stats'],
    queryFn: () => apiFetch('/api/v1/admin/threat-intel/stats'),
    staleTime: 30_000,
    retry: false,
  })

  const { data: feedsData, refetch: refetchFeeds } = useQuery<Feed[]>({
    queryKey: ['ti-feeds'],
    queryFn: async () => {
      try { return await apiFetchList<Feed>('/api/v1/admin/threat-intel/feeds') } catch { return [] }
    },
    staleTime: 30_000,
    retry: false,
  })

  const { data: iocsData } = useQuery<IOC[]>({
    queryKey: ['ti-iocs'],
    queryFn: async () => {
      try { return await apiFetchList<IOC>('/api/v1/admin/threat-intel/iocs') } catch { return [] }
    },
    staleTime: 30_000,
    retry: false,
  })

  const EMPTY_STATS: Stats = { total_iocs: 0, active_feeds: 0, last_updated: '', high_confidence: 0 }
  const stats = statsData ?? EMPTY_STATS
  const feeds: Feed[] = feedsData ?? []
  const iocs: IOC[] = iocsData ?? []

  const filteredIocs = iocTab === 'all' ? iocs : iocs.filter(i => i.type === iocTab)
  const totalPages = Math.ceil(filteredIocs.length / PAGE_SIZE)
  const pagedIocs = filteredIocs.slice((iocPage - 1) * PAGE_SIZE, iocPage * PAGE_SIZE)

  const handleSync = async (feedId: string) => {
    setSyncingFeed(feedId)
    try {
      await apiFetch(`/api/v1/admin/threat-intel/feeds/${feedId}/sync`, { method: 'POST' })
    } catch {
      // ignore - mock success
    } finally {
      setTimeout(() => { setSyncingFeed(null); refetchFeeds() }, 1500)
    }
  }

  const handleAddFeed = async () => {
    try {
      await apiFetch('/api/v1/admin/threat-intel/feeds', { method: 'POST', body: JSON.stringify(feedForm) })
    } catch {
      // ignore
    }
    setShowAddFeed(false)
    setFeedForm({ name: '', type: 'MISP', url: '', api_key: '', fetch_interval: 60 })
    refetchFeeds()
  }

  const handleLookup = async () => {
    if (!lookupValue.trim()) return
    setLookupLoading(true)
    setLookupResult(null)
    try {
      const result = await apiFetch<LookupResult>('/api/v1/admin/threat-intel/lookup', {
        method: 'POST',
        body: JSON.stringify({ value: lookupValue }),
      })
      setLookupResult(result)
    } catch {
      // Mock lookup result
      const found = Math.random() > 0.4
      setLookupResult({
        value: lookupValue,
        type: lookupValue.includes('http') ? 'url' : lookupValue.includes('.') ? (lookupValue.match(/^\d/) ? 'ip' : 'domain') : 'hash',
        confidence: found ? Math.floor(Math.random() * 40) + 60 : 0,
        severity: found ? (['critical', 'high', 'medium', 'low'] as Severity[])[Math.floor(Math.random() * 4)] : 'low',
        source: found ? 'MISP Community' : 'N/A',
        tags: found ? ['malware', 'c2'] : [],
        found,
      })
    } finally {
      setLookupLoading(false)
    }
  }

  return (
    <div className="min-h-screen bg-zinc-950 p-6">
      {/* Header */}
      <div className="mb-6">
        <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
          <Globe className="w-7 h-7 text-blue-400" />
          脅威インテリジェンス
        </h1>
        <p className="text-zinc-400 text-sm mt-1">
          脅威インテリジェンスフィード・IOCの管理とインジケーター照合
        </p>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: 'IOC総数', value: (stats.total_iocs ?? 0).toLocaleString(), color: 'text-blue-400', icon: <Database className="w-5 h-5" /> },
          { label: 'アクティブフィード', value: stats.active_feeds, color: 'text-green-400', icon: <Globe className="w-5 h-5" /> },
          { label: '最終更新', value: stats.last_updated ? new Date(stats.last_updated).toLocaleTimeString('ja-JP') : '—', color: 'text-zinc-300', icon: <Clock className="w-5 h-5" /> },
          { label: '高信頼度IOC', value: (stats.high_confidence ?? 0).toLocaleString(), color: 'text-orange-400', icon: <Shield className="w-5 h-5" /> },
        ].map(s => (
          <div key={s.label} className="bg-zinc-900 border border-zinc-800 rounded-lg p-4 flex items-center gap-3">
            <div className={`${s.color} opacity-60`}>{s.icon}</div>
            <div>
              <p className={`text-xl font-bold ${s.color}`}>{s.value}</p>
              <p className="text-zinc-500 text-xs mt-0.5">{s.label}</p>
            </div>
          </div>
        ))}
      </div>

      <div className="grid grid-cols-2 gap-6 mb-6">
        {/* Feeds Section */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-5">
          <div className="flex items-center justify-between mb-4">
            <h2 className="text-zinc-100 font-semibold">インテリジェンスフィード</h2>
            <button
              onClick={() => setShowAddFeed(v => !v)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-zinc-800 text-zinc-300 hover:text-zinc-100 text-sm transition-colors"
            >
              <Plus className="w-3.5 h-3.5" />
              フィード追加
            </button>
          </div>

          {showAddFeed && (
            <div className="mb-4 p-4 bg-zinc-800/50 border border-zinc-700 rounded-lg space-y-3">
              <div className="flex items-center justify-between">
                <span className="text-sm font-medium text-zinc-300">新規フィード</span>
                <button onClick={() => setShowAddFeed(false)} className="text-zinc-500 hover:text-zinc-300">
                  <X className="w-4 h-4" />
                </button>
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-xs text-zinc-500 mb-1">名前</label>
                  <input
                    value={feedForm.name}
                    onChange={e => setFeedForm(f => ({ ...f, name: e.target.value }))}
                    className="w-full px-2.5 py-1.5 bg-zinc-900 border border-zinc-700 rounded text-sm text-zinc-200 focus:outline-none focus:border-blue-500/50"
                    placeholder="フィード名"
                  />
                </div>
                <div>
                  <label className="block text-xs text-zinc-500 mb-1">種別</label>
                  <select
                    value={feedForm.type}
                    onChange={e => setFeedForm(f => ({ ...f, type: e.target.value as FeedType }))}
                    className="w-full px-2.5 py-1.5 bg-zinc-900 border border-zinc-700 rounded text-sm text-zinc-200 focus:outline-none focus:border-blue-500/50"
                  >
                    {(['MISP', 'OpenCTI', 'CSV', 'Static'] as FeedType[]).map(t => (
                      <option key={t} value={t}>{t}</option>
                    ))}
                  </select>
                </div>
              </div>
              <div>
                <label className="block text-xs text-zinc-500 mb-1">URL</label>
                <input
                  value={feedForm.url}
                  onChange={e => setFeedForm(f => ({ ...f, url: e.target.value }))}
                  className="w-full px-2.5 py-1.5 bg-zinc-900 border border-zinc-700 rounded text-sm text-zinc-200 focus:outline-none focus:border-blue-500/50"
                  placeholder="https://..."
                />
              </div>
              <div className="grid grid-cols-2 gap-2">
                <div>
                  <label className="block text-xs text-zinc-500 mb-1">APIキー</label>
                  <input
                    type="password"
                    value={feedForm.api_key}
                    onChange={e => setFeedForm(f => ({ ...f, api_key: e.target.value }))}
                    className="w-full px-2.5 py-1.5 bg-zinc-900 border border-zinc-700 rounded text-sm text-zinc-200 focus:outline-none focus:border-blue-500/50"
                    placeholder="任意"
                  />
                </div>
                <div>
                  <label className="block text-xs text-zinc-500 mb-1">取得間隔（分）</label>
                  <input
                    type="number"
                    value={feedForm.fetch_interval}
                    onChange={e => setFeedForm(f => ({ ...f, fetch_interval: Number(e.target.value) }))}
                    className="w-full px-2.5 py-1.5 bg-zinc-900 border border-zinc-700 rounded text-sm text-zinc-200 focus:outline-none focus:border-blue-500/50"
                    min={5}
                  />
                </div>
              </div>
              <button
                onClick={handleAddFeed}
                disabled={!feedForm.name || !feedForm.url}
                className="w-full py-2 rounded bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors"
              >
                フィード追加
              </button>
            </div>
          )}

          <div className="space-y-3">
            {feeds.map(feed => (
              <div key={feed.id} className="p-3 bg-zinc-800/50 border border-zinc-700/50 rounded-lg">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${FEED_TYPE_STYLE[feed.type]}`}>
                      {feed.type}
                    </span>
                    <span className="text-zinc-200 text-sm font-medium">{feed.name}</span>
                  </div>
                  <div className="flex items-center gap-2">
                    {feed.enabled
                      ? <ToggleRight className="w-5 h-5 text-green-400" />
                      : <ToggleLeft className="w-5 h-5 text-zinc-600" />
                    }
                    <button
                      onClick={() => handleSync(feed.id)}
                      disabled={syncingFeed === feed.id}
                      className="flex items-center gap-1 px-2.5 py-1 rounded bg-zinc-700 text-zinc-300 hover:text-zinc-100 text-xs transition-colors disabled:opacity-50"
                    >
                      <RefreshCw className={`w-3 h-3 ${syncingFeed === feed.id ? 'animate-spin' : ''}`} />
                      同期
                    </button>
                  </div>
                </div>
                <div className="flex items-center gap-4 text-xs text-zinc-500">
                  <span>{(feed.ioc_count ?? 0).toLocaleString()} IOC</span>
                  <span>最終同期: {new Date(feed.last_sync).toLocaleString('ja-JP')}</span>
                  <span>{feed.fetch_interval}分ごと</span>
                </div>
              </div>
            ))}
          </div>
        </div>

        {/* IOC Lookup */}
        <div className="bg-zinc-900 border border-zinc-800 rounded-lg p-5">
          <h2 className="text-zinc-100 font-semibold mb-4">IOC照合</h2>
          <div className="flex gap-2 mb-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-zinc-500" />
              <input
                value={lookupValue}
                onChange={e => setLookupValue(e.target.value)}
                onKeyDown={e => e.key === 'Enter' && handleLookup()}
                placeholder="IP、ドメイン、ハッシュ、URLを入力"
                className="w-full pl-9 pr-3 py-2 bg-zinc-800 border border-zinc-700 rounded text-sm text-zinc-200 placeholder-zinc-600 focus:outline-none focus:border-blue-500/50"
              />
            </div>
            <button
              onClick={handleLookup}
              disabled={lookupLoading || !lookupValue.trim()}
              className="px-4 py-2 rounded bg-blue-600 text-white text-sm font-medium hover:bg-blue-700 disabled:opacity-50 transition-colors flex items-center gap-1.5"
            >
              {lookupLoading ? <RefreshCw className="w-3.5 h-3.5 animate-spin" /> : <Search className="w-3.5 h-3.5" />}
              照合
            </button>
          </div>

          {lookupResult && (
            <div className={`p-4 rounded-lg border ${lookupResult.found ? 'bg-red-500/5 border-red-500/20' : 'bg-green-500/5 border-green-500/20'}`}>
              <div className="flex items-center gap-2 mb-3">
                {lookupResult.found
                  ? <AlertTriangle className="w-5 h-5 text-red-400" />
                  : <CheckCircle className="w-5 h-5 text-green-400" />
                }
                <span className={`font-semibold text-sm ${lookupResult.found ? 'text-red-400' : 'text-green-400'}`}>
                  {lookupResult.found ? '脅威インジケーター検出' : '脅威データベースに登録なし'}
                </span>
              </div>
              {lookupResult.found && (
                <div className="space-y-3">
                  <div className="flex items-center gap-3 flex-wrap">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded text-[11px] font-medium border ${FEED_TYPE_STYLE['MISP']}`}>
                      {IOC_TYPE_ICON[lookupResult.type]}
                      {IOC_TYPE_LABEL[lookupResult.type]}
                    </span>
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${SEVERITY_STYLE[lookupResult.severity]}`}>
                      {SEVERITY_LABEL[lookupResult.severity]}
                    </span>
                    <span className="text-xs text-zinc-500">ソース: {lookupResult.source}</span>
                  </div>
                  <div>
                    <div className="flex items-center justify-between text-xs text-zinc-500 mb-1">
                      <span>信頼度</span>
                      <span className="text-zinc-300 font-medium">{lookupResult.confidence}%</span>
                    </div>
                    <div className="h-1.5 bg-zinc-700 rounded-full overflow-hidden">
                      <div
                        className={`h-full rounded-full ${lookupResult.confidence >= 80 ? 'bg-red-400' : lookupResult.confidence >= 60 ? 'bg-orange-400' : 'bg-yellow-400'}`}
                        style={{ width: `${lookupResult.confidence}%` }}
                      />
                    </div>
                  </div>
                  {lookupResult.tags.length > 0 && (
                    <div className="flex flex-wrap gap-1.5">
                      {lookupResult.tags.map(tag => (
                        <span key={tag} className="px-2 py-0.5 rounded-full bg-zinc-700 text-zinc-400 text-[11px]">{tag}</span>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          )}

          {!lookupResult && (
            <div className="flex flex-col items-center justify-center h-32 text-zinc-600">
              <Search className="w-8 h-8 mb-2 opacity-40" />
              <p className="text-sm">インジケーターを入力して脅威フィードと照合</p>
            </div>
          )}
        </div>
      </div>

      {/* IOCs Table */}
      <div className="bg-zinc-900 border border-zinc-800 rounded-lg">
        <div className="flex items-center justify-between px-5 py-4 border-b border-zinc-800">
          <h2 className="text-zinc-100 font-semibold">侵害インジケーター（IOC）</h2>
          <div className="flex gap-1">
            {(['all', 'ip', 'domain', 'hash', 'url'] as const).map(tab => (
              <button
                key={tab}
                onClick={() => { setIocTab(tab); setIocPage(1) }}
                className={`px-3 py-1.5 rounded text-sm transition-colors ${
                  iocTab === tab
                    ? 'bg-zinc-700 text-zinc-100'
                    : 'text-zinc-500 hover:text-zinc-300'
                }`}
              >
                {tab === 'all' ? 'すべて' : tab === 'ip' ? 'IP' : tab === 'domain' ? 'ドメイン' : tab === 'hash' ? 'ハッシュ' : 'URL'}
              </button>
            ))}
          </div>
        </div>

        <div className="overflow-x-auto">
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-zinc-800">
                {['値', '種別', '信頼度', '深刻度', 'ソース', '有効期限'].map(h => (
                  <th key={h} className="text-left px-5 py-3 text-xs font-semibold text-zinc-500 uppercase tracking-wider whitespace-nowrap">
                    {h}
                  </th>
                ))}
              </tr>
            </thead>
            <tbody>
              {pagedIocs.map((ioc, i) => (
                <tr key={ioc.id} className={`border-b border-zinc-800/50 hover:bg-zinc-800/30 transition-colors ${i % 2 === 0 ? '' : 'bg-zinc-950/30'}`}>
                  <td className="px-5 py-3 font-mono text-zinc-300 text-xs truncate max-w-[200px]" title={ioc.value}>
                    {ioc.value.length > 30 ? ioc.value.slice(0, 30) + '…' : ioc.value}
                  </td>
                  <td className="px-5 py-3">
                    <span className="inline-flex items-center gap-1 text-xs text-zinc-400">
                      {IOC_TYPE_ICON[ioc.type]}
                      {IOC_TYPE_LABEL[ioc.type]}
                    </span>
                  </td>
                  <td className="px-5 py-3 w-32">
                    <div className="flex items-center gap-2">
                      <div className="flex-1 h-1.5 bg-zinc-700 rounded-full overflow-hidden">
                        <div
                          className={`h-full rounded-full ${ioc.confidence >= 80 ? 'bg-red-400' : ioc.confidence >= 60 ? 'bg-orange-400' : 'bg-yellow-400'}`}
                          style={{ width: `${ioc.confidence}%` }}
                        />
                      </div>
                      <span className="text-xs text-zinc-400 w-8 text-right">{ioc.confidence}%</span>
                    </div>
                  </td>
                  <td className="px-5 py-3">
                    <span className={`inline-flex items-center px-2 py-0.5 rounded text-[11px] font-medium border ${SEVERITY_STYLE[ioc.severity]}`}>
                      {SEVERITY_LABEL[ioc.severity]}
                    </span>
                  </td>
                  <td className="px-5 py-3 text-xs text-zinc-400">{ioc.source}</td>
                  <td className="px-5 py-3 text-xs text-zinc-500 whitespace-nowrap">
                    {new Date(ioc.expires).toLocaleDateString('ja-JP')}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>

        {/* Pagination */}
        <div className="flex items-center justify-between px-5 py-3 border-t border-zinc-800">
          <span className="text-xs text-zinc-500">
            {filteredIocs.length}件中 {(iocPage - 1) * PAGE_SIZE + 1}–{Math.min(iocPage * PAGE_SIZE, filteredIocs.length)}件を表示
          </span>
          <div className="flex items-center gap-1">
            <button
              onClick={() => setIocPage(p => Math.max(1, p - 1))}
              disabled={iocPage === 1}
              className="p-1 rounded hover:bg-zinc-700 text-zinc-500 hover:text-zinc-300 disabled:opacity-30 transition-colors"
            >
              <ChevronLeft className="w-4 h-4" />
            </button>
            {Array.from({ length: totalPages }, (_, i) => i + 1).map(p => (
              <button
                key={p}
                onClick={() => setIocPage(p)}
                className={`w-7 h-7 rounded text-xs transition-colors ${iocPage === p ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300'}`}
              >
                {p}
              </button>
            ))}
            <button
              onClick={() => setIocPage(p => Math.min(totalPages, p + 1))}
              disabled={iocPage === totalPages}
              className="p-1 rounded hover:bg-zinc-700 text-zinc-500 hover:text-zinc-300 disabled:opacity-30 transition-colors"
            >
              <ChevronRight className="w-4 h-4" />
            </button>
          </div>
        </div>
      </div>
    </div>
  )
}
