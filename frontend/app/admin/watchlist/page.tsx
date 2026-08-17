'use client'

import { useState } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import {
  Eye, Plus, Trash2, RefreshCw, X, Search, Star,
  CheckCircle, XCircle, AlertTriangle, Tag, Calendar,
  Hash, Globe, User, Cpu, Server, Activity, TrendingUp
} from 'lucide-react'


// ── Types ──────────────────────────────────────────────────────────────────────

type EntityType = 'ip' | 'domain' | 'hash' | 'hostname' | 'username' | 'process'

interface WatchlistEntry {
  id: string
  entity_type: EntityType
  value: string
  label: string
  reason?: string
  priority: number  // 1–5
  hit_count: number
  hit_trend: number  // positive = up, negative = down
  last_hit?: string
  tags: string[]
  expires_at?: string
  created_at: string
}

interface WatchlistStats {
  total: number
  hits_today: number
  ips_watched: number
  domains_watched: number
}

interface CheckResult {
  watchlisted: boolean
  entry?: WatchlistEntry
}

const EMPTY_WATCHLIST_STATS: WatchlistStats = { total: 0, hits_today: 0, ips_watched: 0, domains_watched: 0 }

// ── Helpers ────────────────────────────────────────────────────────────────────

const ENTITY_STYLES: Record<EntityType, { color: string; label: string; icon: React.ElementType }> = {
  ip:       { color: 'bg-orange-900/40 text-orange-300 border border-orange-700/40', label: 'IPアドレス', icon: Globe },
  domain:   { color: 'bg-purple-900/40 text-purple-300 border border-purple-700/40', label: 'ドメイン', icon: Globe },
  hash:     { color: 'bg-yellow-900/40 text-yellow-300 border border-yellow-700/40', label: 'ハッシュ', icon: Hash },
  hostname: { color: 'bg-blue-900/40 text-blue-300 border border-blue-700/40', label: 'ホスト名', icon: Server },
  username: { color: 'bg-cyan-900/40 text-cyan-300 border border-cyan-700/40', label: 'ユーザー名', icon: User },
  process:  { color: 'bg-red-900/40 text-red-300 border border-red-700/40', label: 'プロセス', icon: Cpu },
}

const PRIORITY_COLORS: Record<number, string> = {
  5: 'text-red-400',
  4: 'text-orange-400',
  3: 'text-yellow-400',
  2: 'text-blue-400',
  1: 'text-zinc-500',
}

function PriorityStars({ priority }: { priority: number }) {
  return (
    <div className="flex items-center gap-0.5">
      {[1,2,3,4,5].map(n => (
        <Star key={n} className={`h-3 w-3 ${n <= priority ? PRIORITY_COLORS[priority] + ' fill-current' : 'text-zinc-700'}`} />
      ))}
    </div>
  )
}

function fmtRelative(iso?: string): string {
  if (!iso) return '—'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 1) return 'たった今'
  if (mins < 60) return `${mins}分前`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}時間前`
  return `${Math.floor(hrs / 24)}日前`
}

function fmtDate(iso?: string): string {
  if (!iso) return '—'
  try { return new Date(iso).toLocaleDateString() } catch { return '—' }
}

// ── Add Entry Modal ────────────────────────────────────────────────────────────

interface AddEntryModalProps {
  onClose: () => void
  onSuccess: () => void
}

function AddEntryModal({ onClose, onSuccess }: AddEntryModalProps) {
  const [form, setForm] = useState({
    entity_type: 'ip' as EntityType,
    value: '',
    label: '',
    reason: '',
    priority: 3,
    tags: '',
    expires_at: '',
  })
  const [saving, setSaving] = useState(false)
  const [error, setError] = useState('')

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    if (!form.value || !form.label) { setError('エンティティの値とラベルは必須です。'); return }
    setSaving(true)
    setError('')
    try {
      await apiFetch('/api/v1/admin/watchlist', {
        method: 'POST',
        body: JSON.stringify({
          ...form,
          tags: form.tags.split(',').map(t => t.trim()).filter(Boolean),
          expires_at: form.expires_at || undefined,
        }),
      })
    } catch { /* ignore */ }
    setSaving(false)
    onSuccess()
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl shadow-2xl w-full max-w-lg mx-4">
        <div className="flex items-center justify-between px-6 py-4 border-b border-zinc-700">
          <h2 className="text-lg font-semibold text-zinc-100">ウォッチリストエントリ追加</h2>
          <button onClick={onClose} className="text-zinc-400 hover:text-zinc-200 transition-colors"><X className="h-5 w-5" /></button>
        </div>
        <form onSubmit={handleSubmit} className="p-6 space-y-4">
          {error && <div className="text-red-400 text-sm bg-red-900/20 border border-red-700/40 rounded-sm px-3 py-2">{error}</div>}

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-xs text-zinc-400 mb-1">エンティティ種別</label>
              <select value={form.entity_type} onChange={e => setForm(f => ({ ...f, entity_type: e.target.value as EntityType }))}
                className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm focus:outline-hidden focus:border-blue-500">
                {(Object.keys(ENTITY_STYLES) as EntityType[]).map(t => (
                  <option key={t} value={t}>{ENTITY_STYLES[t].label}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">優先度 (1–5)</label>
              <div className="flex items-center gap-2">
                <input type="range" min={1} max={5} value={form.priority} onChange={e => setForm(f => ({ ...f, priority: Number(e.target.value) }))}
                  className="flex-1 accent-blue-500" />
                <span className={`text-sm font-bold w-4 ${PRIORITY_COLORS[form.priority]}`}>{form.priority}</span>
              </div>
            </div>
            <div className="col-span-2">
              <label className="block text-xs text-zinc-400 mb-1">値</label>
              <input value={form.value} onChange={e => setForm(f => ({ ...f, value: e.target.value }))}
                className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm font-mono focus:outline-hidden focus:border-blue-500" placeholder="例: 192.168.1.1, evil.com, sha256..." />
            </div>
            <div className="col-span-2">
              <label className="block text-xs text-zinc-400 mb-1">ラベル</label>
              <input value={form.label} onChange={e => setForm(f => ({ ...f, label: e.target.value }))}
                className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm focus:outline-hidden focus:border-blue-500" placeholder="簡潔な説明" />
            </div>
            <div className="col-span-2">
              <label className="block text-xs text-zinc-400 mb-1">理由</label>
              <textarea value={form.reason} onChange={e => setForm(f => ({ ...f, reason: e.target.value }))} rows={2}
                className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm focus:outline-hidden focus:border-blue-500 resize-none" placeholder="このエンティティを監視する理由" />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">タグ（カンマ区切り）</label>
              <input value={form.tags} onChange={e => setForm(f => ({ ...f, tags: e.target.value }))}
                className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm focus:outline-hidden focus:border-blue-500" placeholder="tor, c2, malware" />
            </div>
            <div>
              <label className="block text-xs text-zinc-400 mb-1">有効期限（任意）</label>
              <input type="date" value={form.expires_at} onChange={e => setForm(f => ({ ...f, expires_at: e.target.value }))}
                className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm focus:outline-hidden focus:border-blue-500" />
            </div>
          </div>

          <div className="flex justify-end gap-3 pt-2">
            <button type="button" onClick={onClose} className="px-4 py-2 text-sm text-zinc-400 hover:text-zinc-200 transition-colors">キャンセル</button>
            <button type="submit" disabled={saving}
              className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg transition-colors flex items-center gap-2">
              {saving ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Plus className="h-4 w-4" />}
              エントリを追加
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

// ── Main Page ──────────────────────────────────────────────────────────────────

const TABS: { key: string; label: string }[] = [
  { key: 'all', label: 'すべて' },
  { key: 'ip', label: 'IP' },
  { key: 'domain', label: 'ドメイン' },
  { key: 'hash', label: 'ハッシュ' },
  { key: 'hostname', label: 'ホスト名' },
  { key: 'username', label: 'ユーザー名' },
  { key: 'process', label: 'プロセス' },
]

export default function WatchlistPage() {
  const qc = useQueryClient()
  const [showAdd, setShowAdd] = useState(false)
  const [activeTab, setActiveTab] = useState('all')
  const [search, setSearch] = useState('')
  const [checkType, setCheckType] = useState<EntityType>('ip')
  const [checkValue, setCheckValue] = useState('')
  const [checkResult, setCheckResult] = useState<CheckResult | null>(null)
  const [checking, setChecking] = useState(false)

  const { data: entries = [] } = useQuery<WatchlistEntry[]>({
    queryKey: ['admin-watchlist'],
    queryFn: async () => {
      try { return await apiFetchList<WatchlistEntry>('/api/v1/admin/watchlist') } catch { return [] }
    },
  })

  const { data: stats = EMPTY_WATCHLIST_STATS } = useQuery<WatchlistStats>({
    queryKey: ['admin-watchlist-stats'],
    queryFn: async () => {
      try { return await apiFetch('/api/v1/admin/watchlist/stats') } catch { return EMPTY_WATCHLIST_STATS }
    },
  })

  const deleteMut = useMutation({
    mutationFn: (id: string) => apiFetch(`/api/v1/admin/watchlist/${id}`, { method: 'DELETE' }).catch(() => {}),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['admin-watchlist'] }),
  })

  const filtered = entries.filter(e => {
    const matchTab = activeTab === 'all' || e.entity_type === activeTab
    const matchSearch = !search || e.value.toLowerCase().includes(search.toLowerCase()) || e.label.toLowerCase().includes(search.toLowerCase())
    return matchTab && matchSearch
  })

  async function handleCheck(e: React.FormEvent) {
    e.preventDefault()
    if (!checkValue) return
    setChecking(true)
    setCheckResult(null)
    try {
      const result = await apiFetch<CheckResult>('/api/v1/admin/watchlist/check', {
        method: 'POST',
        body: JSON.stringify({ entity_type: checkType, value: checkValue }),
      })
      setCheckResult(result)
    } catch {
      // Mock check
      const found = entries.find(e => e.entity_type === checkType && e.value.toLowerCase() === checkValue.toLowerCase())
      setCheckResult({ watchlisted: !!found, entry: found })
    }
    setChecking(false)
  }

  const STATS_CARDS = [
    { label: '総エントリ数', value: stats.total ?? 0, icon: Eye, color: 'text-blue-400' },
    { label: '本日のヒット', value: stats.hits_today ?? 0, icon: Activity, color: 'text-orange-400' },
    { label: '監視中IP', value: stats.ips_watched ?? 0, icon: Globe, color: 'text-purple-400' },
    { label: '監視中ドメイン', value: stats.domains_watched ?? 0, icon: Globe, color: 'text-cyan-400' },
  ]

  return (
    <div className="min-h-screen bg-zinc-950 text-zinc-100 p-6">
      {/* Header */}
      <div className="flex items-center justify-between mb-6">
        <div className="flex items-center gap-3">
          <div className="h-10 w-10 rounded-xl bg-orange-900/40 border border-orange-700/40 flex items-center justify-center">
            <Eye className="h-5 w-5 text-orange-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold text-zinc-100">アラート ウォッチリスト</h1>
            <p className="text-sm text-zinc-400">特定のIP、ドメイン、ハッシュ、IDを監視</p>
          </div>
        </div>
        <button onClick={() => setShowAdd(true)}
          className="flex items-center gap-2 px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 text-white rounded-lg transition-colors font-medium">
          <Plus className="h-4 w-4" />
          エントリ追加
        </button>
      </div>

      {/* Stats */}
      <div className="grid grid-cols-2 lg:grid-cols-4 gap-4 mb-6">
        {STATS_CARDS.map(s => (
          <div key={s.label} className="bg-zinc-900 border border-zinc-700 rounded-xl p-4 flex items-center gap-3">
            <div className="h-10 w-10 rounded-lg bg-zinc-800 flex items-center justify-center">
              <s.icon className={`h-5 w-5 ${s.color}`} />
            </div>
            <div>
              <div className="text-2xl font-bold text-zinc-100">{s.value}</div>
              <div className="text-xs text-zinc-500">{s.label}</div>
            </div>
          </div>
        ))}
      </div>

      {/* Check Entity Panel */}
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl p-4 mb-6">
        <h3 className="text-sm font-medium text-zinc-200 mb-3 flex items-center gap-2">
          <Search className="h-4 w-4 text-zinc-400" />エンティティ検索
        </h3>
        <form onSubmit={handleCheck} className="flex items-end gap-3">
          <div>
            <label className="block text-xs text-zinc-500 mb-1">種別</label>
            <select value={checkType} onChange={e => setCheckType(e.target.value as EntityType)}
              className="bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm focus:outline-hidden focus:border-blue-500">
              {(Object.keys(ENTITY_STYLES) as EntityType[]).map(t => (
                <option key={t} value={t}>{ENTITY_STYLES[t].label}</option>
              ))}
            </select>
          </div>
          <div className="flex-1">
            <label className="block text-xs text-zinc-500 mb-1">値</label>
            <input value={checkValue} onChange={e => setCheckValue(e.target.value)}
              className="w-full bg-zinc-800 border border-zinc-600 rounded-lg px-3 py-2 text-zinc-100 text-sm font-mono focus:outline-hidden focus:border-blue-500" placeholder="IP、ドメイン、ハッシュを入力..." />
          </div>
          <button type="submit" disabled={checking || !checkValue}
            className="px-4 py-2 text-sm bg-blue-600 hover:bg-blue-500 disabled:opacity-50 text-white rounded-lg transition-colors flex items-center gap-2">
            {checking ? <RefreshCw className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
            検索
          </button>
        </form>
        {checkResult && (
          <div className={`mt-3 rounded-lg px-4 py-3 flex items-start gap-3 ${checkResult.watchlisted ? 'bg-red-900/20 border border-red-700/40' : 'bg-green-900/20 border border-green-700/40'}`}>
            {checkResult.watchlisted
              ? <AlertTriangle className="h-5 w-5 text-red-400 shrink-0 mt-0.5" />
              : <CheckCircle className="h-5 w-5 text-green-400 shrink-0 mt-0.5" />
            }
            <div>
              <div className={`font-bold text-sm ${checkResult.watchlisted ? 'text-red-400' : 'text-green-400'}`}>
                {checkResult.watchlisted ? '監視対象に登録済み' : '監視対象に未登録'}
              </div>
              {checkResult.watchlisted && checkResult.entry && (
                <div className="text-xs text-zinc-400 mt-1">
                  <span className="font-medium text-zinc-300">{checkResult.entry.label}</span>
                  {checkResult.entry.reason && <span> — {checkResult.entry.reason}</span>}
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* Tabs + Search */}
      <div className="flex items-center justify-between mb-4 gap-4">
        <div className="flex gap-1 bg-zinc-900 border border-zinc-700 rounded-lg p-1">
          {TABS.map(t => (
            <button key={t.key} onClick={() => setActiveTab(t.key)}
              className={`px-3 py-1.5 text-xs rounded-md transition-colors ${activeTab === t.key ? 'bg-zinc-700 text-zinc-100' : 'text-zinc-500 hover:text-zinc-300'}`}>
              {t.label}
            </button>
          ))}
        </div>
        <div className="relative">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-zinc-500" />
          <input value={search} onChange={e => setSearch(e.target.value)} placeholder="エントリを検索..."
            className="bg-zinc-900 border border-zinc-700 rounded-lg pl-9 pr-4 py-2 text-sm text-zinc-100 focus:outline-hidden focus:border-blue-500 w-64" />
        </div>
      </div>

      {/* Table */}
      <div className="bg-zinc-900 border border-zinc-700 rounded-xl overflow-hidden">
        <table className="w-full text-sm">
          <thead>
            <tr className="border-b border-zinc-700 bg-zinc-800/50">
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">種別</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">値</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">ラベル</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">優先度</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">ヒット数</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">最終ヒット</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">タグ</th>
              <th className="text-left px-4 py-3 text-xs text-zinc-400 font-medium">有効期限</th>
              <th className="text-right px-4 py-3 text-xs text-zinc-400 font-medium">操作</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-800">
            {filtered.length === 0 ? (
              <tr><td colSpan={9} className="px-4 py-8 text-center text-zinc-600 italic">エントリが見つかりません</td></tr>
            ) : filtered.map(entry => {
              const es = ENTITY_STYLES[entry.entity_type]
              return (
                <tr key={entry.id} className="hover:bg-zinc-800/30 transition-colors">
                  <td className="px-4 py-3">
                    <span className={`inline-flex items-center gap-1 px-2 py-0.5 rounded-sm text-xs font-medium ${es.color}`}>
                      <es.icon className="h-3 w-3" />{es.label}
                    </span>
                  </td>
                  <td className="px-4 py-3">
                    <span className="font-mono text-xs text-zinc-300 max-w-[160px] truncate block" title={entry.value}>{entry.value}</span>
                  </td>
                  <td className="px-4 py-3 text-xs text-zinc-400">{entry.label}</td>
                  <td className="px-4 py-3"><PriorityStars priority={entry.priority} /></td>
                  <td className="px-4 py-3">
                    <div className="flex items-center gap-1 text-xs">
                      <span className="text-zinc-300 font-medium">{entry.hit_count}</span>
                      {entry.hit_trend > 0 && <TrendingUp className="h-3 w-3 text-red-400" />}
                      {entry.hit_trend < 0 && <TrendingUp className="h-3 w-3 text-green-400 rotate-180" />}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-zinc-500">{fmtRelative(entry.last_hit)}</td>
                  <td className="px-4 py-3">
                    <div className="flex flex-wrap gap-1">
                      {entry.tags.slice(0, 2).map(t => (
                        <span key={t} className="text-xs px-1.5 py-0.5 bg-zinc-800 text-zinc-400 rounded-sm border border-zinc-700">{t}</span>
                      ))}
                      {entry.tags.length > 2 && <span className="text-xs text-zinc-600">+{entry.tags.length - 2}</span>}
                    </div>
                  </td>
                  <td className="px-4 py-3 text-xs text-zinc-500">{entry.expires_at ? fmtDate(entry.expires_at) : <span className="text-zinc-600">無期限</span>}</td>
                  <td className="px-4 py-3 text-right">
                    <button onClick={() => { if (confirm('このエントリを削除しますか？')) deleteMut.mutate(entry.id) }}
                      className="text-red-400 hover:text-red-300 transition-colors p-1">
                      <Trash2 className="h-4 w-4" />
                    </button>
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      </div>

      {showAdd && (
        <AddEntryModal
          onClose={() => setShowAdd(false)}
          onSuccess={() => { setShowAdd(false); qc.invalidateQueries({ queryKey: ['admin-watchlist'] }) }}
        />
      )}
    </div>
  )
}
