'use client'

import { useState, useEffect, useCallback, useRef } from 'react'
import {
  Globe, RefreshCw, Plus, Check, X, Clock, AlertTriangle,
  Activity, Trash2, Pencil, Loader2, Rss, Search, Shield,
  Database, Hash, Link, AtSign, BarChart2, User,
} from 'lucide-react'
import { apiFetch } from '@/lib/api'

// ─── Types ───────────────────────────────────────────────────────────────────

interface ThreatFeed {
  id: string
  name: string
  url: string
  feed_type: 'taxii' | 'csv' | 'json' | 'stix'
  enabled: boolean
  last_sync?: string
  next_sync?: string
  ioc_count?: number
  error?: string
  sync_interval_hours?: number
}

type FeedFormData = {
  name: string
  url: string
  feed_type: 'taxii' | 'csv' | 'json' | 'stix'
  sync_interval_hours: number
  enabled: boolean
}

const DEFAULT_FORM: FeedFormData = {
  name: '',
  url: '',
  feed_type: 'csv',
  sync_interval_hours: 24,
  enabled: true,
}

interface ThreatActor {
  name: string
  aliases: string[]
  origin: string
  motivation: string
  sectors: string[]
  ttps: string[]
  lastSeen: string
}

interface SearchResult {
  value: string
  ioc_type: string
  threat_level: number
  tags: string[]
  description: string
  source_feed: string
  first_seen?: string
  last_seen?: string
}

// ─── Static reference data ────────────────────────────────────────────────────

const THREAT_ACTORS: ThreatActor[] = [
  {
    name: 'APT28',
    aliases: ['Fancy Bear', 'Sofacy', 'Pawn Storm'],
    origin: 'Russia (GRU)',
    motivation: 'スパイ活動・影響工作',
    sectors: ['政府機関', '防衛', '政治機関', 'メディア'],
    ttps: ['T1566', 'T1078', 'T1055', 'T1071', 'T1190'],
    lastSeen: '2026-03-10',
  },
  {
    name: 'Lazarus Group',
    aliases: ['Hidden Cobra', 'Zinc', 'APT38'],
    origin: 'North Korea (RGB)',
    motivation: '金銭目的・破壊活動',
    sectors: ['金融', '暗号資産', '防衛', 'メディア'],
    ttps: ['T1059', 'T1027', 'T1486', 'T1041', 'T1204'],
    lastSeen: '2026-03-14',
  },
  {
    name: 'Sandworm',
    aliases: ['Voodoo Bear', 'TeleBots', 'IRIDIUM'],
    origin: 'Russia (GRU Unit 74455)',
    motivation: '破壊・妨害工作',
    sectors: ['重要インフラ', 'エネルギー', '政府機関', '公共サービス'],
    ttps: ['T1486', 'T1485', 'T1561', 'T1529', 'T1195'],
    lastSeen: '2026-03-05',
  },
]

// ─── Sub-components ───────────────────────────────────────────────────────────

type Tab = 'feeds' | 'recent-iocs' | 'threat-actors' | 'ioc-search'

function FeedTypeBadge({ type }: { type: string }) {
  const colors: Record<string, string> = {
    taxii: 'bg-purple-500/20 text-purple-300 ring-1 ring-purple-500/30',
    csv:   'bg-blue-500/20 text-blue-300 ring-1 ring-blue-500/30',
    json:  'bg-yellow-500/20 text-yellow-300 ring-1 ring-yellow-500/30',
    stix:  'bg-orange-500/20 text-orange-300 ring-1 ring-orange-500/30',
  }
  return (
    <span className={`px-2 py-0.5 rounded-sm text-xs font-mono uppercase ${colors[type] ?? 'bg-gray-500/20 text-gray-300'}`}>
      {type}
    </span>
  )
}

function IOCTypeBadge({ type }: { type: string }) {
  const map: Record<string, { icon: React.ReactNode; color: string }> = {
    ip:     { icon: <Globe size={10} />,    color: 'bg-blue-500/20 text-blue-300 ring-1 ring-blue-500/30' },
    domain: { icon: <Globe size={10} />,    color: 'bg-cyan-500/20 text-cyan-300 ring-1 ring-cyan-500/30' },
    hash:   { icon: <Hash size={10} />,     color: 'bg-yellow-500/20 text-yellow-300 ring-1 ring-yellow-500/30' },
    url:    { icon: <Link size={10} />,     color: 'bg-purple-500/20 text-purple-300 ring-1 ring-purple-500/30' },
    email:  { icon: <AtSign size={10} />,   color: 'bg-pink-500/20 text-pink-300 ring-1 ring-pink-500/30' },
  }
  const { icon, color } = map[type] ?? { icon: <Shield size={10} />, color: 'bg-gray-500/20 text-gray-300' }
  return (
    <span className={`flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs font-mono uppercase ${color}`}>
      {icon}{type}
    </span>
  )
}

function ThreatLevelBadge({ level }: { level: number }) {
  const color =
    level >= 9 ? 'bg-red-500/20 text-red-400 ring-1 ring-red-500/30' :
    level >= 7 ? 'bg-orange-500/20 text-orange-400 ring-1 ring-orange-500/30' :
    level >= 4 ? 'bg-yellow-500/20 text-yellow-400 ring-1 ring-yellow-500/30' :
                 'bg-gray-500/20 text-gray-400'
  const label =
    level >= 9 ? 'クリティカル' :
    level >= 7 ? '高' :
    level >= 4 ? '中' : '低'
  return (
    <span className={`px-2 py-0.5 rounded-sm text-xs ${color}`}>
      {label} ({level})
    </span>
  )
}

function SyncStatusBadge({ error }: { error?: string }) {
  if (error) {
    return (
      <span className="flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs bg-red-500/15 text-red-400 ring-1 ring-red-500/30">
        <AlertTriangle size={10} />エラー
      </span>
    )
  }
  return (
    <span className="flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs bg-green-500/15 text-green-400 ring-1 ring-green-500/30">
      <Check size={10} />同期済み
    </span>
  )
}

function Toggle({ checked, onChange }: { checked: boolean; onChange: () => void }) {
  return (
    <button
      type="button"
      onClick={onChange}
      className={`relative inline-flex h-5 w-9 shrink-0 cursor-pointer rounded-full border-2 border-transparent transition-colors duration-200 focus:outline-hidden ${
        checked ? 'bg-[#e8002d]' : 'bg-[#1e2d42]'
      }`}
    >
      <span
        className={`pointer-events-none inline-block h-4 w-4 transform rounded-full bg-[#e2e8f4] shadow-sm ring-0 transition duration-200 ease-in-out ${
          checked ? 'translate-x-4' : 'translate-x-0'
        }`}
      />
    </button>
  )
}

// ─── Feed Form (add / edit modal) ─────────────────────────────────────────────

function FeedModal({
  initial,
  onSave,
  onClose,
}: {
  initial: FeedFormData & { id?: string }
  onSave: (data: FeedFormData & { id?: string }) => Promise<void>
  onClose: () => void
}) {
  const [form, setForm] = useState<FeedFormData & { id?: string }>(initial)
  const [submitting, setSubmitting] = useState(false)

  const isEdit = Boolean(form.id)
  const isValid = form.name.trim() !== '' && form.url.trim() !== ''

  const handleSubmit = async () => {
    if (!isValid) return
    setSubmitting(true)
    try { await onSave(form) } finally { setSubmitting(false) }
  }

  return (
    <div className="fixed inset-0 bg-black/60 flex items-center justify-center z-50 p-4">
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-6 w-full max-w-lg shadow-2xl">
        <h2 className="text-lg font-semibold text-white mb-5">
          {isEdit ? 'フィード編集' : 'フィード追加'}
        </h2>

        <div className="space-y-4">
          <div>
            <label className="block text-sm text-[#7d92b0] mb-1">フィード名 <span className="text-[#e8002d]">*</span></label>
            <input
              value={form.name}
              onChange={e => setForm(f => ({ ...f, name: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] focus:border-[#e8002d] rounded-lg px-3 py-2 text-gray-200 text-sm outline-hidden transition-colors"
              placeholder="e.g. Abuse.ch URLhaus"
            />
          </div>

          <div>
            <label className="block text-sm text-[#7d92b0] mb-1">URL <span className="text-[#e8002d]">*</span></label>
            <input
              value={form.url}
              onChange={e => setForm(f => ({ ...f, url: e.target.value }))}
              className="w-full bg-[#070d19] border border-[#1e2d42] focus:border-[#e8002d] rounded-lg px-3 py-2 text-gray-200 text-sm outline-hidden transition-colors font-mono"
              placeholder="https://..."
            />
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm text-[#7d92b0] mb-1">フォーマット</label>
              <select
                value={form.feed_type}
                onChange={e => setForm(f => ({ ...f, feed_type: e.target.value as FeedFormData['feed_type'] }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] focus:border-[#e8002d] rounded-lg px-3 py-2 text-gray-200 text-sm outline-hidden transition-colors"
              >
                <option value="csv">CSV</option>
                <option value="json">JSON</option>
                <option value="taxii">TAXII</option>
                <option value="stix">STIX</option>
              </select>
            </div>
            <div>
              <label className="block text-sm text-[#7d92b0] mb-1">同期間隔</label>
              <select
                value={form.sync_interval_hours}
                onChange={e => setForm(f => ({ ...f, sync_interval_hours: Number(e.target.value) }))}
                className="w-full bg-[#070d19] border border-[#1e2d42] focus:border-[#e8002d] rounded-lg px-3 py-2 text-gray-200 text-sm outline-hidden transition-colors"
              >
                <option value={1}>1時間</option>
                <option value={6}>6時間</option>
                <option value={12}>12時間</option>
                <option value={24}>24時間</option>
                <option value={48}>48時間</option>
              </select>
            </div>
          </div>

          <div className="flex items-center justify-between">
            <span className="text-sm text-[#7d92b0]">フィードを有効化</span>
            <Toggle checked={form.enabled} onChange={() => setForm(f => ({ ...f, enabled: !f.enabled }))} />
          </div>
        </div>

        <div className="flex gap-3 mt-6">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 bg-[#0d1220] hover:bg-[#1e2d42] border border-[#1e2d42] rounded-lg text-sm text-[#7d92b0] transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={handleSubmit}
            disabled={!isValid || submitting}
            className="flex-1 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-50 rounded-lg text-sm font-medium text-white transition-colors"
          >
            {submitting
              ? <span className="flex items-center justify-center gap-2"><Loader2 size={14} className="animate-spin" />{isEdit ? '更新中...' : '追加中...'}</span>
              : isEdit ? '更新' : '追加'
            }
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Feed Statistics Tab ───────────────────────────────────────────────────────

function FeedStatsTab({ feeds }: { feeds: ThreatFeed[] }) {
  return (
    <div className="space-y-4">
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
        <div className="px-4 py-3 bg-[#0d1220] border-b border-[#1e2d42] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <BarChart2 size={14} className="text-[#e8002d]" />
            <h3 className="font-medium text-gray-200 text-sm">フィード統計</h3>
          </div>
          <span className="text-xs text-[#7d92b0]">{feeds.length}件</span>
        </div>
        {feeds.length === 0 ? (
          <div className="text-center py-10 text-[#7d92b0] text-sm">
            フィードがまだ登録されていません。
          </div>
        ) : (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-[#1e2d42]">
                  <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">フィード名</th>
                  <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">種別</th>
                  <th className="text-right px-4 py-3 text-xs text-[#7d92b0] font-medium">IOC数</th>
                  <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">最終更新</th>
                  <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">ステータス</th>
                  <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">IOCタイプ</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-[#1e2d42]">
                {feeds.map(feed => (
                  <tr key={feed.id} className="hover:bg-[#1e2d42]/30 transition-colors">
                    <td className="px-4 py-3 text-gray-200 font-medium">{feed.name}</td>
                    <td className="px-4 py-3"><FeedTypeBadge type={feed.feed_type} /></td>
                    <td className="px-4 py-3 text-right text-gray-300 font-mono">
                      {(feed.ioc_count ?? 0).toLocaleString()}
                    </td>
                    <td className="px-4 py-3 text-[#7d92b0] text-xs">
                      {feed.last_sync ? new Date(feed.last_sync).toLocaleString('ja-JP') : '—'}
                    </td>
                    <td className="px-4 py-3">
                      {feed.enabled
                        ? <span className="flex items-center gap-1 text-xs text-green-400"><Check size={10} />有効</span>
                        : <span className="flex items-center gap-1 text-xs text-[#7d92b0]"><X size={10} />無効</span>
                      }
                    </td>
                    <td className="px-4 py-3">
                      <div className="flex flex-wrap gap-1">
                        {(['ip', 'domain', 'hash', 'url'] as const).map(t => (
                          <span key={t} className="px-1.5 py-0.5 rounded-sm text-xs bg-[#1e2d42] text-[#7d92b0]">{t}</span>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Recent IOCs Tab ──────────────────────────────────────────────────────────

interface IOCEntryRaw {
  id: string
  type: string
  value: string
  description?: string
  severity: number
  is_active: boolean
  added_by_name?: string
  created_at: string
}

function RecentIOCsTab() {
  const [iocs, setIocs] = useState<IOCEntryRaw[]>([])
  const [loading, setLoading] = useState(true)
  const mounted = useRef(true)

  useEffect(() => {
    mounted.current = true
    apiFetch<{ data?: IOCEntryRaw[] }>('/api/v1/ioc?per_page=20')
      .then(res => { if (mounted.current) setIocs(res.data ?? []) })
      .catch(() => { if (mounted.current) setIocs([]) })
      .finally(() => { if (mounted.current) setLoading(false) })
    return () => { mounted.current = false }
  }, [])

  return (
    <div className="space-y-4">
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
        <div className="px-4 py-3 bg-[#0d1220] border-b border-[#1e2d42] flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Database size={14} className="text-[#e8002d]" />
            <h3 className="font-medium text-gray-200 text-sm">最新IOC</h3>
          </div>
          <span className="text-xs text-[#7d92b0]">直近20件</span>
        </div>
        <div className="overflow-x-auto">
          {loading ? (
            <div className="flex items-center justify-center py-10 text-[#7d92b0] text-sm gap-2">
              <Loader2 size={14} className="animate-spin" />
              <span>読み込み中...</span>
            </div>
          ) : iocs.length === 0 ? (
            <div className="py-10 text-center text-[#7d92b0] text-sm">IOCデータがありません</div>
          ) : (
          <table className="w-full text-sm">
            <thead>
              <tr className="border-b border-[#1e2d42]">
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">種別</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">値</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">登録者</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">重大度</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">状態</th>
                <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">登録日</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-[#1e2d42]">
              {iocs.map((ioc) => (
                <tr key={ioc.id} className="hover:bg-[#1e2d42]/30 transition-colors">
                  <td className="px-4 py-3"><IOCTypeBadge type={ioc.type} /></td>
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs text-gray-200 max-w-[220px] truncate block" title={ioc.value}>
                      {ioc.value.length > 40 ? ioc.value.slice(0, 40) + '…' : ioc.value}
                    </span>
                    {ioc.description && (
                      <span className="text-xs text-[#7d92b0] block mt-0.5">{ioc.description}</span>
                    )}
                  </td>
                  <td className="px-4 py-3 text-[#7d92b0] text-xs">{ioc.added_by_name ?? '—'}</td>
                  <td className="px-4 py-3"><ThreatLevelBadge level={ioc.severity} /></td>
                  <td className="px-4 py-3">
                    <span className={`px-1.5 py-0.5 rounded-sm text-xs ${ioc.is_active ? 'bg-green-900/40 text-green-400' : 'bg-[#1e2d42] text-[#7d92b0]'}`}>
                      {ioc.is_active ? '有効' : '無効'}
                    </span>
                  </td>
                  <td className="px-4 py-3 text-[#7d92b0] text-xs">{new Date(ioc.created_at).toLocaleDateString('ja-JP')}</td>
                </tr>
              ))}
            </tbody>
          </table>
          )}
        </div>
      </div>
    </div>
  )
}

// ─── Threat Actor Profiles Tab ────────────────────────────────────────────────

function ThreatActorsTab() {
  return (
    <div className="space-y-4">
      {THREAT_ACTORS.map(actor => (
        <div key={actor.name} className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-5">
          <div className="flex items-start gap-4">
            <div className="p-2.5 rounded-lg bg-[#e8002d]/10 border border-[#e8002d]/20 shrink-0">
              <User size={20} className="text-[#e8002d]" />
            </div>
            <div className="flex-1 min-w-0">
              <div className="flex flex-wrap items-center gap-2 mb-1">
                <h3 className="text-base font-semibold text-white">{actor.name}</h3>
                {actor.aliases.map(alias => (
                  <span key={alias} className="px-2 py-0.5 rounded-sm text-xs bg-[#1e2d42] text-[#7d92b0]">
                    {alias}
                  </span>
                ))}
              </div>
              <p className="text-xs text-[#7d92b0] mb-3">
                <span className="text-gray-400 font-medium">{actor.origin}</span>
                {' · '}
                {actor.motivation}
              </p>

              <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                <div>
                  <p className="text-xs text-[#7d92b0] mb-1.5 font-medium uppercase tracking-wide">標的セクター</p>
                  <div className="flex flex-wrap gap-1">
                    {actor.sectors.map(sector => (
                      <span key={sector} className="px-2 py-0.5 rounded-sm text-xs bg-blue-500/10 text-blue-300 ring-1 ring-blue-500/20">
                        {sector}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-xs text-[#7d92b0] mb-1.5 font-medium uppercase tracking-wide">関連TTP</p>
                  <div className="flex flex-wrap gap-1">
                    {actor.ttps.map(ttp => (
                      <span key={ttp} className="px-2 py-0.5 rounded-sm text-xs bg-orange-500/10 text-orange-300 ring-1 ring-orange-500/20 font-mono">
                        {ttp}
                      </span>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-xs text-[#7d92b0] mb-1.5 font-medium uppercase tracking-wide">最終確認</p>
                  <span className="flex items-center gap-1 text-sm text-gray-300">
                    <Clock size={12} className="text-[#7d92b0]" />
                    {actor.lastSeen}
                  </span>
                </div>
              </div>
            </div>
          </div>
        </div>
      ))}
    </div>
  )
}

// ─── IOC Search Tab ───────────────────────────────────────────────────────────

function IOCSearchTab() {
  const [query, setQuery] = useState('')
  const [searching, setSearching] = useState(false)
  const [results, setResults] = useState<SearchResult[] | null>(null)
  const [error, setError] = useState<string | null>(null)

  const handleSearch = async () => {
    if (!query.trim()) return
    setSearching(true)
    setError(null)
    try {
      const data = await apiFetch<{ results: SearchResult[]; count: number }>(
        `/api/v1/threat-intel/search?q=${encodeURIComponent(query.trim())}`
      )
      setResults(data.results ?? [])
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Search failed')
      setResults(null)
    } finally {
      setSearching(false)
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'Enter') handleSearch()
  }

  return (
    <div className="space-y-4">
      {/* Search bar */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4">
        <div className="flex gap-3">
          <div className="relative flex-1">
            <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-[#7d92b0]" />
            <input
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder="IOC検索 — IP, ドメイン, ハッシュ, URL..."
              className="w-full bg-[#070d19] border border-[#1e2d42] focus:border-[#e8002d] rounded-lg pl-9 pr-4 py-2.5 text-gray-200 text-sm outline-hidden transition-colors"
            />
          </div>
          <button
            onClick={handleSearch}
            disabled={searching || !query.trim()}
            className="flex items-center gap-2 px-4 py-2 bg-[#e8002d] hover:bg-[#c0001f] disabled:opacity-50 rounded-lg text-sm font-medium text-white transition-colors"
          >
            {searching
              ? <><Loader2 size={14} className="animate-spin" />検索中...</>
              : <><Search size={14} />検索</>
            }
          </button>
        </div>
      </div>

      {/* Error */}
      {error && (
        <div className="bg-red-500/10 border border-red-500/30 rounded-lg px-4 py-3 text-red-400 text-sm flex items-center gap-2">
          <AlertTriangle size={14} />{error}
        </div>
      )}

      {/* Results */}
      {results !== null && (
        <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
          <div className="px-4 py-3 border-b border-[#1e2d42] flex items-center justify-between">
            <h3 className="text-sm font-medium text-gray-200">
              検索結果
            </h3>
            <span className="text-xs text-[#7d92b0]">{results.length}件一致</span>
          </div>
          {results.length === 0 ? (
            <div className="py-10 text-center text-[#7d92b0] text-sm">
              <span className="font-mono text-gray-300">&quot;{query}&quot;</span> に一致するIOCが見つかりませんでした
            </div>
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="border-b border-[#1e2d42]">
                    <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">種別</th>
                    <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">値</th>
                    <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">脅威レベル</th>
                    <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">ソース</th>
                    <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">タグ</th>
                    <th className="text-left px-4 py-3 text-xs text-[#7d92b0] font-medium">最終確認</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-[#1e2d42]">
                  {results.map((r, i) => (
                    <tr key={i} className="hover:bg-[#1e2d42]/30 transition-colors">
                      <td className="px-4 py-3"><IOCTypeBadge type={r.ioc_type} /></td>
                      <td className="px-4 py-3">
                        <span className="font-mono text-xs text-gray-200 max-w-[240px] truncate block" title={r.value}>
                          {r.value}
                        </span>
                        {r.description && (
                          <span className="text-xs text-[#7d92b0] block mt-0.5">{r.description}</span>
                        )}
                      </td>
                      <td className="px-4 py-3"><ThreatLevelBadge level={r.threat_level} /></td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">{r.source_feed || '—'}</td>
                      <td className="px-4 py-3">
                        <div className="flex flex-wrap gap-1">
                          {(r.tags ?? []).map(tag => (
                            <span key={tag} className="px-1.5 py-0.5 rounded-sm text-xs bg-[#1e2d42] text-[#7d92b0]">{tag}</span>
                          ))}
                        </div>
                      </td>
                      <td className="px-4 py-3 text-[#7d92b0] text-xs">
                        {r.last_seen ? new Date(r.last_seen).toLocaleDateString() : '—'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ─── Feeds Management Tab (original content) ─────────────────────────────────

function FeedsManagementTab({
  feeds, loading, syncing, syncMsg,
  onToggle, onSync, onEdit, onDelete, onAdd,
}: {
  feeds: ThreatFeed[]
  loading: boolean
  syncing: Record<string, boolean>
  syncMsg: Record<string, string>
  onToggle: (f: ThreatFeed) => void
  onSync: (id: string) => void
  onEdit: (f: ThreatFeed) => void
  onDelete: (id: string) => void
  onAdd: () => void
}) {
  return (
    <div className="space-y-5">
      {/* Stats row */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        {[
          { label: '総フィード数',  value: feeds.length,                          color: 'text-white' },
          { label: '有効フィード',   value: feeds.filter(f => f.enabled).length,   color: 'text-green-400' },
          { label: '総IOC数',        value: feeds.reduce((s, f) => s + (f.ioc_count ?? 0), 0).toLocaleString(), color: 'text-purple-400' },
          { label: 'エラー数',       value: feeds.filter(f => f.error).length,     color: feeds.some(f => f.error) ? 'text-red-400' : 'text-[#7d92b0]' },
        ].map(stat => (
          <div key={stat.label} className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4">
            <p className="text-xs text-[#7d92b0] mb-1">{stat.label}</p>
            <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
          </div>
        ))}
      </div>

      {/* Feed list */}
      <div className="bg-[#0d1220] rounded-xl border border-[#1e2d42] overflow-hidden">
        <div className="px-4 py-3 bg-[#0d1220] flex items-center justify-between border-b border-[#1e2d42]">
          <h3 className="font-medium text-gray-200 text-sm">登録済みフィード</h3>
          <div className="flex items-center gap-2">
            <span className="text-xs text-[#7d92b0]">{feeds.length}件</span>
            <button
              onClick={onAdd}
              className="flex items-center gap-1 px-2.5 py-1.5 bg-[#e8002d] hover:bg-[#c0001f] rounded-lg text-xs font-medium text-white transition-colors"
            >
              <Plus size={12} />フィード追加
            </button>
          </div>
        </div>

        {loading ? (
          <div className="flex items-center justify-center gap-2 py-14 text-[#7d92b0] text-sm">
            <Loader2 size={16} className="animate-spin" />読み込み中...
          </div>
        ) : feeds.length === 0 ? (
          <div className="text-center py-14 text-[#7d92b0] text-sm">
            <Rss size={32} className="mx-auto mb-3 text-[#1e2d42]" />
            フィードが登録されていません。「フィード追加」から開始してください。
          </div>
        ) : (
          <div className="divide-y divide-[#1e2d42]">
            {feeds.map(feed => (
              <div key={feed.id} className="px-4 py-4 hover:bg-[#1e2d42]/20 transition-colors">
                <div className="flex items-start gap-4">
                  <div className="flex-1 min-w-0">
                    <div className="flex flex-wrap items-center gap-2 mb-1">
                      <span className="font-medium text-gray-200">{feed.name}</span>
                      <FeedTypeBadge type={feed.feed_type} />
                      {feed.last_sync && <SyncStatusBadge error={feed.error} />}
                      {!feed.enabled && (
                        <span className="flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs bg-[#1e2d42] text-[#7d92b0]">
                          <X size={10} />無効
                        </span>
                      )}
                    </div>

                    <p className="text-xs text-[#7d92b0] font-mono truncate max-w-lg">{feed.url}</p>

                    {feed.error && (
                      <p className="mt-1 text-xs text-red-400 bg-red-500/10 rounded-sm px-2 py-1 max-w-lg truncate">
                        {feed.error}
                      </p>
                    )}

                    <div className="flex flex-wrap items-center gap-4 mt-2 text-xs text-[#7d92b0]">
                      {feed.last_sync && (
                        <span className="flex items-center gap-1">
                          <Clock size={10} />最終同期: {new Date(feed.last_sync).toLocaleString('ja-JP')}
                        </span>
                      )}
                      {feed.next_sync && (
                        <span className="flex items-center gap-1">
                          <Clock size={10} />次回同期: {new Date(feed.next_sync).toLocaleString('ja-JP')}
                        </span>
                      )}
                      {feed.ioc_count != null && feed.ioc_count > 0 && (
                        <span className="flex items-center gap-1">
                          <Activity size={10} />{(feed.ioc_count ?? 0).toLocaleString()}件のIOC
                        </span>
                      )}
                      {feed.sync_interval_hours != null && (
                        <span>同期間隔: {feed.sync_interval_hours}時間</span>
                      )}
                    </div>

                    {syncMsg[feed.id] && (
                      <p className="mt-1 text-xs text-green-400 flex items-center gap-1">
                        <Check size={10} />{syncMsg[feed.id]}
                      </p>
                    )}
                  </div>

                  <div className="flex items-center gap-2 shrink-0">
                    <Toggle checked={feed.enabled} onChange={() => onToggle(feed)} />

                    <button
                      onClick={() => onSync(feed.id)}
                      disabled={syncing[feed.id]}
                      className="flex items-center gap-1 px-2.5 py-1.5 bg-[#1e2d42] hover:bg-[#1e2d42]/80 text-gray-300 rounded-sm text-xs disabled:opacity-50 transition-colors"
                    >
                      {syncing[feed.id]
                        ? <><Loader2 size={12} className="animate-spin" />同期中</>
                        : <><RefreshCw size={12} />同期</>
                      }
                    </button>

                    <button
                      onClick={() => onEdit(feed)}
                      className="p-1.5 bg-[#1e2d42]/40 hover:bg-[#1e2d42] text-gray-300 rounded-sm transition-colors"
                    >
                      <Pencil size={13} />
                    </button>

                    <button
                      onClick={() => onDelete(feed.id)}
                      className="p-1.5 bg-red-700/20 hover:bg-red-700/40 text-red-400 rounded-sm transition-colors"
                    >
                      <Trash2 size={13} />
                    </button>
                  </div>
                </div>
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}

// ─── Main page ────────────────────────────────────────────────────────────────

export default function ThreatIntelPage() {
  const [feeds, setFeeds] = useState<ThreatFeed[]>([])
  const [loading, setLoading] = useState(true)
  const [syncing, setSyncing] = useState<Record<string, boolean>>({})
  const [syncMsg, setSyncMsg] = useState<Record<string, string>>({})
  const [modal, setModal] = useState<(FeedFormData & { id?: string }) | null>(null)
  const [deletingId, setDeletingId] = useState<string | null>(null)
  const [actionError, setActionError] = useState('')
  const [loadError, setLoadError] = useState('')
  const [activeTab, setActiveTab] = useState<Tab>('feeds')

  // ── data fetching ──────────────────────────────────────────────────────────

  // 読めなかったときに黙って空のままにすると、画面は「フィードは
  // まだありません」と同じ見た目になります。取り込み元の一覧なので、
  // 空に見える＝何も取り込んでいない、と読まれます。
  const fetchFeeds = useCallback(async () => {
    try {
      const res = await fetch('/api/v1/threat-feeds', { credentials: 'include' })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      const data = await res.json()
      setFeeds(Array.isArray(data) ? data : (data.feeds ?? []))
      setLoadError('')
    } catch (e) {
      setLoadError(
        `脅威フィードの一覧を取得できませんでした（${e instanceof Error ? e.message : String(e)}）。` +
        '下の一覧は最後に取得できた内容です'
      )
    }
    setLoading(false)
  }, [])

  useEffect(() => { fetchFeeds() }, [fetchFeeds])

  // ── derived stats ──────────────────────────────────────────────────────────

  const totalIocs    = feeds.reduce((sum, f) => sum + (f.ioc_count ?? 0), 0)
  const enabledFeeds = feeds.filter(f => f.enabled).length
  const highSevIocs  = 0

  // ── actions ────────────────────────────────────────────────────────────────

  // 二重に黙っていました。fetch は 4xx/5xx で reject しないので res.ok を
  // 見ないと成功に見え、さらに catch が /* ignore */ なので通信エラーも
  // 消えます。フィードの有効/無効は、何を取り込むかを決める設定です。
  const handleToggle = async (feed: ThreatFeed) => {
    setActionError('')
    try {
      const res = await fetch(`/api/v1/threat-feeds/${feed.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        credentials: 'include',
        body: JSON.stringify({ ...feed, enabled: !feed.enabled }),
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      await fetchFeeds()
    } catch (e) {
      setActionError(
        `フィードの有効/無効を変更できませんでした（${e instanceof Error ? e.message : String(e)}）。` +
        '設定は変わっていません'
      )
    }
  }

  const handleSync = async (feedId: string) => {
    setSyncing(s => ({ ...s, [feedId]: true }))
    setSyncMsg(m => ({ ...m, [feedId]: '' }))
    try {
      const res = await fetch(`/api/v1/threat-feeds/${feedId}/sync`, {
        method: 'POST',
        credentials: 'include',
      })
      if (!res.ok) {
        // 同期を押して何も出ないのは「まだ回っている」に見えます。
        // スピナーが止まって表示が変わらないだけなので、失敗したことに
        // 気づく手がかりがありません。
        setSyncMsg(m => ({ ...m, [feedId]: `同期できませんでした（HTTP ${res.status}）` }))
        return
      }
      const data = await res.json()
      setSyncMsg(m => ({
        ...m,
        [feedId]: data.imported != null ? `${data.imported}件のIOCをインポートしました` : (data.message ?? '完了'),
      }))
      setTimeout(() => setSyncMsg(m => ({ ...m, [feedId]: '' })), 4000)
      await fetchFeeds()
    } catch (e) {
      setSyncMsg(m => ({
        ...m,
        [feedId]: `同期できませんでした（${e instanceof Error ? e.message : String(e)}）`,
      }))
    } finally {
      setSyncing(s => ({ ...s, [feedId]: false }))
    }
  }

  const handleSave = async (data: FeedFormData & { id?: string }) => {
    const { id, ...body } = data
    const url    = id ? `/api/v1/threat-feeds/${id}` : '/api/v1/threat-feeds'
    const method = id ? 'PUT' : 'POST'
    const res = await fetch(url, {
      method,
      headers: { 'Content-Type': 'application/json' },
      credentials: 'include',
      body: JSON.stringify(body),
    })
    if (!res.ok) {
      // 失敗するとモーダルが開いたまま何も出ません。押した人には
      // 「反応していない」ようにしか見えないので、もう一度押します。
      setActionError(`フィードを保存できませんでした（HTTP ${res.status}）`)
      return
    }
    setActionError('')
    setModal(null)
    await fetchFeeds()
  }

  const handleDelete = async (feedId: string) => {
    if (!confirm('このフィードを削除しますか？')) return
    setDeletingId(feedId)
    setActionError('')
    try {
      const res = await fetch(`/api/v1/threat-feeds/${feedId}`, {
        method: 'DELETE',
        credentials: 'include',
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      await fetchFeeds()
    } catch (e) {
      setActionError(
        `フィードを削除できませんでした（${e instanceof Error ? e.message : String(e)}）。` +
        'フィードは残っています'
      )
    } finally {
      setDeletingId(null)
    }
    void deletingId // suppress unused warning
  }

  const openAdd  = () => setModal({ ...DEFAULT_FORM })
  const openEdit = (f: ThreatFeed) => setModal({
    id: f.id,
    name: f.name,
    url: f.url,
    feed_type: f.feed_type,
    sync_interval_hours: f.sync_interval_hours ?? 24,
    enabled: f.enabled,
  })

  // ── tabs config ────────────────────────────────────────────────────────────

  const tabs: { id: Tab; label: string; icon: React.ReactNode }[] = [
    { id: 'feeds',          label: 'フィード管理',   icon: <Rss size={14} /> },
    { id: 'recent-iocs',    label: '最新IOC',        icon: <Database size={14} /> },
    { id: 'threat-actors',  label: '脅威アクター',   icon: <User size={14} /> },
    { id: 'ioc-search',     label: 'IOC検索',        icon: <Search size={14} /> },
  ]

  // ── render ─────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-[#070d19] text-gray-100 p-6">
      <div className="max-w-7xl mx-auto space-y-6">

        {loadError && (
          <div className="rounded-lg border border-amber-800 bg-amber-950/40 px-4 py-3 text-sm text-amber-200">
            {loadError}
          </div>
        )}
        {actionError && (
          <div className="rounded-lg border border-red-800 bg-red-950/40 px-4 py-3 text-sm text-red-200">
            {actionError}
          </div>
        )}

        {/* ── Page header ────────────────────────────────────────────────── */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="p-2 bg-[#e8002d]/10 rounded-lg border border-[#e8002d]/20">
              <Shield size={24} className="text-[#e8002d]" />
            </div>
            <div>
              <h1 className="text-2xl font-bold text-white">脅威インテリジェンス</h1>
              <p className="text-[#7d92b0] text-sm">フィード管理・IOCエンリッチメント・脅威アクタープロファイリング</p>
            </div>
          </div>
          <button
            onClick={fetchFeeds}
            className="flex items-center gap-2 px-3 py-2 bg-[#0d1220] hover:bg-[#1e2d42] border border-[#1e2d42] rounded-lg text-sm text-[#7d92b0] transition-colors"
          >
            <RefreshCw size={14} />更新
          </button>
        </div>

        {/* ── Summary cards ──────────────────────────────────────────────── */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          {[
            { label: '総IOC数',           value: totalIocs.toLocaleString(),          color: 'text-white',       sub: '全フィード合計' },
            { label: '有効フィード',       value: enabledFeeds,                        color: 'text-green-400',   sub: `全${feeds.length}件中` },
            { label: '高危険度IOC',        value: highSevIocs,                         color: 'text-[#e8002d]',   sub: '脅威レベル 9以上' },
            { label: '本日の検知',         value: 3,                                   color: 'text-orange-400',  sub: 'リアルタイム検知' },
          ].map(card => (
            <div key={card.label} className="bg-[#0d1220] rounded-xl border border-[#1e2d42] p-4">
              <p className="text-xs text-[#7d92b0] mb-1">{card.label}</p>
              <p className={`text-2xl font-bold ${card.color}`}>{card.value}</p>
              <p className="text-xs text-[#7d92b0] mt-1">{card.sub}</p>
            </div>
          ))}
        </div>

        {/* ── Tabs ───────────────────────────────────────────────────────── */}
        <div className="border-b border-[#1e2d42]">
          <nav className="flex gap-1">
            {tabs.map(tab => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium rounded-t-lg transition-colors ${
                  activeTab === tab.id
                    ? 'bg-[#0d1220] text-white border border-b-[#0d1220] border-[#1e2d42] -mb-px'
                    : 'text-[#7d92b0] hover:text-gray-300 hover:bg-[#0d1220]/50'
                }`}
              >
                {tab.icon}
                {tab.label}
              </button>
            ))}
          </nav>
        </div>

        {/* ── Tab content ────────────────────────────────────────────────── */}
        {activeTab === 'feeds' && (
          <FeedsManagementTab
            feeds={feeds}
            loading={loading}
            syncing={syncing}
            syncMsg={syncMsg}
            onToggle={handleToggle}
            onSync={handleSync}
            onEdit={openEdit}
            onDelete={handleDelete}
            onAdd={openAdd}
          />
        )}

        {activeTab === 'recent-iocs' && (
          <RecentIOCsTab />
        )}

        {activeTab === 'threat-actors' && (
          <ThreatActorsTab />
        )}

        {activeTab === 'ioc-search' && (
          <IOCSearchTab />
        )}

      </div>

      {/* ── Add / Edit modal ─────────────────────────────────────────────── */}
      {modal && (
        <FeedModal
          initial={modal}
          onSave={handleSave}
          onClose={() => setModal(null)}
        />
      )}
    </div>
  )
}
