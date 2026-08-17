'use client'

import { useState, useEffect } from 'react'
import { useQuery, useMutation, useQueryClient } from '@tanstack/react-query'
import { apiFetch, apiFetchList } from '@/lib/api'
import { useRouter } from 'next/navigation'
import {
  Search, Star, Share2, Edit2, Trash2, Play, Plus, X, Filter,
  Clock, BarChart2, Globe, AlertTriangle, Monitor, Activity, Tag, ChevronDown,
  BookmarkCheck, Users, User, Bookmark,
} from 'lucide-react'
import { m } from '@/lib/mock'

// ─── Types ───────────────────────────────────────────────────────────────────

type Scope = 'global' | 'alerts' | 'endpoints' | 'events' | 'logs'
type OwnerFilter = 'all' | 'mine' | 'team'
type SortBy = 'newest' | 'most_used' | 'name'

interface SavedSearch {
  id: string
  name: string
  description: string
  scope: Scope
  query: string
  shared: boolean
  owner: string
  owner_initial: string
  last_used: string | null
  use_count: number
  tags: string[]
  created_at: string
}

interface SystemFilter {
  id: string
  name: string
  scope: Scope
  query: string
  description: string
  favorited: boolean
}

// ─── Mock Data ────────────────────────────────────────────────────────────────

const MOCK_SAVED_SEARCHES: SavedSearch[] = [
  {
    id: '1',
    name: '重大アラート監視',
    description: '未解決の重大アラートを一覧表示',
    scope: 'alerts',
    query: 'severity>=9 status=open assigned_to=me',
    shared: true,
    owner: '田中 太郎',
    owner_initial: 'T',
    last_used: new Date(Date.now() - 3600000).toISOString(),
    use_count: 42,
    tags: ['daily', 'critical'],
    created_at: new Date(Date.now() - 86400000 * 30).toISOString(),
  },
  {
    id: '2',
    name: 'Windowsエンドポイント異常',
    description: 'Windowsホストの異常プロセス検索',
    scope: 'endpoints',
    query: 'os=windows status=anomaly last_seen<1d',
    shared: false,
    owner: '田中 太郎',
    owner_initial: 'T',
    last_used: new Date(Date.now() - 7200000).toISOString(),
    use_count: 18,
    tags: ['windows', 'anomaly'],
    created_at: new Date(Date.now() - 86400000 * 14).toISOString(),
  },
  {
    id: '3',
    name: 'ランサムウェア関連イベント',
    description: 'ランサムウェア指標に関連するイベント',
    scope: 'events',
    query: 'mitre_technique=T1486 OR file_extension=.encrypted',
    shared: true,
    owner: '鈴木 花子',
    owner_initial: 'H',
    last_used: new Date(Date.now() - 86400000).toISOString(),
    use_count: 7,
    tags: ['ransomware', 'critical'],
    created_at: new Date(Date.now() - 86400000 * 7).toISOString(),
  },
  {
    id: '4',
    name: '外部接続監視',
    description: '不審な外部通信の検索',
    scope: 'global',
    query: 'type=network direction=outbound country!=JP bytes>1000000',
    shared: true,
    owner: '佐藤 健',
    owner_initial: 'K',
    last_used: new Date(Date.now() - 86400000 * 2).toISOString(),
    use_count: 31,
    tags: ['network', 'exfiltration'],
    created_at: new Date(Date.now() - 86400000 * 60).toISOString(),
  },
  {
    id: '5',
    name: '管理者ログイン失敗',
    description: '管理者アカウントへの認証失敗',
    scope: 'logs',
    query: 'event_type=auth_failure user_role=admin count>5 window=5m',
    shared: false,
    owner: '田中 太郎',
    owner_initial: 'T',
    last_used: null,
    use_count: 3,
    tags: ['auth', 'brute-force'],
    created_at: new Date(Date.now() - 86400000 * 3).toISOString(),
  },
  {
    id: '6',
    name: 'マルウェアプロセス実行',
    description: '既知マルウェアシグネチャに合致するプロセス',
    scope: 'events',
    query: 'event_type=process_create hash_verdict=malicious OR yara_match=true',
    shared: true,
    owner: '山田 次郎',
    owner_initial: 'J',
    last_used: new Date(Date.now() - 3600000 * 5).toISOString(),
    use_count: 55,
    tags: ['malware', 'process'],
    created_at: new Date(Date.now() - 86400000 * 90).toISOString(),
  },
]

const MOCK_SYSTEM_FILTERS: SystemFilter[] = [
  {
    id: 'sys1',
    name: '重大アラート (未解決)',
    scope: 'alerts',
    query: 'severity>=9 status=open',
    description: '深刻度9以上の未解決アラート',
    favorited: true,
  },
  {
    id: 'sys2',
    name: 'オフラインエージェント',
    scope: 'endpoints',
    query: 'status=offline last_seen<30m',
    description: '30分以上オフラインのエージェント',
    favorited: false,
  },
  {
    id: 'sys3',
    name: '今日のセキュリティイベント',
    scope: 'events',
    query: 'created_at>=today severity>=5',
    description: '本日の重要セキュリティイベント',
    favorited: true,
  },
  {
    id: 'sys4',
    name: '未パッチの脆弱性',
    scope: 'endpoints',
    query: 'has_cve=true patch_status=unpatched cvss>=7',
    description: 'CVSSスコア7以上の未対応脆弱性',
    favorited: false,
  },
  {
    id: 'sys5',
    name: '新規IOCマッチ',
    scope: 'global',
    query: 'type=ioc_match created_at>=24h',
    description: '過去24時間のIOCマッチ',
    favorited: false,
  },
  {
    id: 'sys6',
    name: 'コンプライアンス違反',
    scope: 'global',
    query: 'type=compliance_violation status=open framework=CIS',
    description: 'CIS未対応のコンプライアンス違反',
    favorited: true,
  },
]

// ─── Helpers ──────────────────────────────────────────────────────────────────

const SCOPE_COLORS: Record<Scope, string> = {
  global: 'bg-purple-500/20 text-purple-300 border-purple-500/30',
  alerts: 'bg-red-500/20 text-red-300 border-red-500/30',
  endpoints: 'bg-blue-500/20 text-blue-300 border-blue-500/30',
  events: 'bg-emerald-500/20 text-emerald-300 border-emerald-500/30',
  logs: 'bg-amber-500/20 text-amber-300 border-amber-500/30',
}

const SCOPE_LABELS: Record<Scope, string> = {
  global: 'グローバル',
  alerts: 'アラート',
  endpoints: 'エンドポイント',
  events: 'イベント',
  logs: 'ログ',
}

const SCOPE_ICONS: Record<Scope, React.FC<{ className?: string }>> = {
  global: Globe,
  alerts: AlertTriangle,
  endpoints: Monitor,
  events: Activity,
  logs: Tag,
}

function formatRelative(iso: string | null): string {
  if (!iso) return '未使用'
  const diff = Date.now() - new Date(iso).getTime()
  const mins = Math.floor(diff / 60000)
  if (mins < 60) return `${mins}分前`
  const hrs = Math.floor(mins / 60)
  if (hrs < 24) return `${hrs}時間前`
  return `${Math.floor(hrs / 24)}日前`
}

const LS_KEY = 'edr_saved_searches'

function loadFromLS(): SavedSearch[] {
  try {
    const raw = localStorage.getItem(LS_KEY)
    return raw ? JSON.parse(raw) : m(MOCK_SAVED_SEARCHES)
  } catch {
    return m(MOCK_SAVED_SEARCHES)
  }
}

function saveToLS(items: SavedSearch[]) {
  localStorage.setItem(LS_KEY, JSON.stringify(items))
}

// ─── Modals ───────────────────────────────────────────────────────────────────

interface SaveModalProps {
  initial?: SavedSearch
  onClose: () => void
  onSave: (data: Omit<SavedSearch, 'id' | 'owner' | 'owner_initial' | 'last_used' | 'use_count' | 'created_at'>) => void
}

function SaveModal({ initial, onClose, onSave }: SaveModalProps) {
  const [name, setName] = useState(initial?.name ?? '')
  const [description, setDescription] = useState(initial?.description ?? '')
  const [scope, setScope] = useState<Scope>(initial?.scope ?? 'global')
  const [query, setQuery] = useState(initial?.query ?? '')
  const [shared, setShared] = useState(initial?.shared ?? false)
  const [tags, setTags] = useState(initial?.tags.join(', ') ?? '')

  const handleSubmit = (e: React.FormEvent) => {
    e.preventDefault()
    onSave({
      name,
      description,
      scope,
      query,
      shared,
      tags: tags.split(',').map(t => t.trim()).filter(Boolean),
    })
  }

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-lg w-full max-w-lg p-6 shadow-2xl">
        <div className="flex items-center justify-between mb-5">
          <h3 className="text-white font-semibold text-base">
            {initial ? '検索を編集' : '検索を保存'}
          </h3>
          <button onClick={onClose} className="text-falcon-muted hover:text-white transition-colors">
            <X className="w-4 h-4" />
          </button>
        </div>
        <form onSubmit={handleSubmit} className="space-y-4">
          <div>
            <label className="text-falcon-muted text-xs font-medium block mb-1.5">名前 *</label>
            <input
              required
              value={name}
              onChange={e => setName(e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-falcon-text focus:outline-hidden focus:border-falcon-subtle placeholder-falcon-subtle"
              placeholder="検索名を入力"
            />
          </div>
          <div>
            <label className="text-falcon-muted text-xs font-medium block mb-1.5">説明</label>
            <input
              value={description}
              onChange={e => setDescription(e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-falcon-text focus:outline-hidden focus:border-falcon-subtle placeholder-falcon-subtle"
              placeholder="任意の説明"
            />
          </div>
          <div>
            <label className="text-falcon-muted text-xs font-medium block mb-1.5">スコープ</label>
            <select
              value={scope}
              onChange={e => setScope(e.target.value as Scope)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-falcon-text focus:outline-hidden focus:border-falcon-subtle"
            >
              {(Object.keys(SCOPE_LABELS) as Scope[]).map(s => (
                <option key={s} value={s}>{SCOPE_LABELS[s]}</option>
              ))}
            </select>
          </div>
          <div>
            <label className="text-falcon-muted text-xs font-medium block mb-1.5">クエリ文字列</label>
            <textarea
              value={query}
              onChange={e => setQuery(e.target.value)}
              rows={3}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-falcon-text font-mono focus:outline-hidden focus:border-falcon-subtle placeholder-falcon-subtle resize-none"
              placeholder="例: severity>=9 status=open"
            />
          </div>
          <div>
            <label className="text-falcon-muted text-xs font-medium block mb-1.5">タグ (カンマ区切り)</label>
            <input
              value={tags}
              onChange={e => setTags(e.target.value)}
              className="w-full bg-[#070d19] border border-falcon-border rounded-sm px-3 py-2 text-sm text-falcon-text focus:outline-hidden focus:border-falcon-subtle placeholder-falcon-subtle"
              placeholder="例: daily, critical, team"
            />
          </div>
          <div className="flex items-center gap-3">
            <button
              type="button"
              onClick={() => setShared(!shared)}
              className={`relative w-10 h-5 rounded-full transition-colors ${shared ? 'bg-falcon-red' : 'bg-falcon-border'}`}
            >
              <span className={`absolute top-0.5 w-4 h-4 bg-falcon-text rounded-full transition-transform ${shared ? 'translate-x-5' : 'translate-x-0.5'}`} />
            </button>
            <span className="text-falcon-muted text-sm">チームと共有</span>
          </div>
          <div className="flex gap-3 pt-2">
            <button
              type="button"
              onClick={onClose}
              className="flex-1 px-4 py-2 rounded-sm border border-falcon-border text-falcon-muted hover:text-white hover:border-falcon-subtle text-sm transition-colors"
            >
              キャンセル
            </button>
            <button
              type="submit"
              className="flex-1 px-4 py-2 rounded-sm bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium transition-colors"
            >
              {initial ? '更新' : '保存'}
            </button>
          </div>
        </form>
      </div>
    </div>
  )
}

interface DeleteConfirmProps {
  name: string
  onClose: () => void
  onConfirm: () => void
}

function DeleteConfirm({ name, onClose, onConfirm }: DeleteConfirmProps) {
  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/60 backdrop-blur-xs">
      <div className="bg-falcon-surface border border-falcon-border rounded-lg w-full max-w-sm p-6 shadow-2xl">
        <div className="flex items-center gap-3 mb-4">
          <div className="w-10 h-10 rounded-full bg-red-500/20 flex items-center justify-center shrink-0">
            <Trash2 className="w-5 h-5 text-red-400" />
          </div>
          <div>
            <h3 className="text-white font-semibold text-sm">検索を削除</h3>
            <p className="text-falcon-muted text-xs mt-0.5">この操作は元に戻せません</p>
          </div>
        </div>
        <p className="text-falcon-muted text-sm mb-5">
          <span className="text-white font-medium">{name}</span> を削除しますか？
        </p>
        <div className="flex gap-3">
          <button
            onClick={onClose}
            className="flex-1 px-4 py-2 rounded-sm border border-falcon-border text-falcon-muted hover:text-white text-sm transition-colors"
          >
            キャンセル
          </button>
          <button
            onClick={onConfirm}
            className="flex-1 px-4 py-2 rounded-sm bg-falcon-red hover:bg-[#c0001f] text-white text-sm font-medium transition-colors"
          >
            削除
          </button>
        </div>
      </div>
    </div>
  )
}

// ─── Page ─────────────────────────────────────────────────────────────────────

export default function SavedSearchPage() {
  const router = useRouter()
  const qc = useQueryClient()
  const [searches, setSearches] = useState<SavedSearch[]>([])
  const [systemFilters, setSystemFilters] = useState<SystemFilter[]>(m(MOCK_SYSTEM_FILTERS))
  const [scopeFilter, setScopeFilter] = useState<Scope | 'all'>('all')
  const [ownerFilter, setOwnerFilter] = useState<OwnerFilter>('all')
  const [sortBy, setSortBy] = useState<SortBy>('newest')
  const [showSaveModal, setShowSaveModal] = useState(false)
  const [editTarget, setEditTarget] = useState<SavedSearch | null>(null)
  const [deleteTarget, setDeleteTarget] = useState<SavedSearch | null>(null)

  // Load from localStorage on mount
  useEffect(() => {
    setSearches(loadFromLS())
  }, [])

  // Try to fetch from API, fallback to localStorage
  const { data: apiSearches } = useQuery<SavedSearch[]>({
    queryKey: ['saved-searches'],
    queryFn: () => apiFetchList<SavedSearch>('/api/v1/search/saved'),
    retry: false,
  })

  useEffect(() => {
    if (apiSearches) setSearches(apiSearches)
  }, [apiSearches])

  const filtered = searches
    .filter(s => scopeFilter === 'all' || s.scope === scopeFilter)
    .filter(s => {
      if (ownerFilter === 'mine') return s.owner === '田中 太郎'
      if (ownerFilter === 'team') return s.shared
      return true
    })
    .sort((a, b) => {
      if (sortBy === 'most_used') return b.use_count - a.use_count
      if (sortBy === 'name') return a.name.localeCompare(b.name, 'ja')
      return new Date(b.created_at).getTime() - new Date(a.created_at).getTime()
    })

  const createMutation = useMutation({
    mutationFn: (payload: { name: string; query: string; page: string }) =>
      apiFetch<{ id: string }>('/api/v1/search/saved', {
        method: 'POST',
        body: JSON.stringify(payload),
      }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['saved-searches'] }),
  })

  const deleteMutation = useMutation({
    mutationFn: (id: string) =>
      apiFetch(`/api/v1/search/saved/${id}`, { method: 'DELETE' }),
    onSuccess: () => qc.invalidateQueries({ queryKey: ['saved-searches'] }),
  })

  const handleSave = (data: Omit<SavedSearch, 'id' | 'owner' | 'owner_initial' | 'last_used' | 'use_count' | 'created_at'>) => {
    if (editTarget) {
      const updated = searches.map(s => s.id === editTarget.id ? { ...s, ...data } : s)
      setSearches(updated)
      saveToLS(updated)
      setEditTarget(null)
    } else {
      // DB永続化（APIが利用可能な場合）
      createMutation.mutate({ name: data.name, query: data.query, page: data.scope })
      // ローカル表示もすぐ反映
      const newItem: SavedSearch = {
        ...data,
        id: Date.now().toString(),
        owner: '自分',
        owner_initial: 'M',
        last_used: null,
        use_count: 0,
        created_at: new Date().toISOString(),
      }
      const updated = [newItem, ...searches]
      setSearches(updated)
      saveToLS(updated)
    }
    setShowSaveModal(false)
  }

  const handleDelete = (id: string) => {
    // DB削除（APIが利用可能な場合）
    deleteMutation.mutate(id)
    const updated = searches.filter(s => s.id !== id)
    setSearches(updated)
    saveToLS(updated)
    setDeleteTarget(null)
  }

  const handleToggleShare = (id: string) => {
    const updated = searches.map(s => s.id === id ? { ...s, shared: !s.shared } : s)
    setSearches(updated)
    saveToLS(updated)
  }

  const handleRun = (s: SavedSearch) => {
    router.push(`/search?q=${encodeURIComponent(s.query)}&scope=${s.scope}`)
  }

  const handleRunSystem = (f: SystemFilter) => {
    router.push(`/search?q=${encodeURIComponent(f.query)}&scope=${f.scope}`)
  }

  const handleToggleFavorite = (id: string) => {
    setSystemFilters(prev => prev.map(f => f.id === id ? { ...f, favorited: !f.favorited } : f))
  }

  const totalShared = searches.filter(s => s.shared).length
  const totalPersonal = searches.filter(s => !s.shared).length

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="mb-6">
        <div className="flex items-center gap-3 mb-1">
          <div className="w-8 h-8 rounded-sm bg-falcon-red/20 flex items-center justify-center">
            <BookmarkCheck className="w-4 h-4 text-falcon-red" />
          </div>
          <h1 className="text-xl font-bold text-white">保存済み検索</h1>
        </div>
        <p className="text-falcon-muted text-sm ml-11">カスタムフィルターの保存・管理・共有</p>
      </div>

      {/* Stats Row */}
      <div className="grid grid-cols-4 gap-4 mb-6">
        {[
          { label: '合計保存数', value: searches.length, icon: Bookmark, color: 'text-blue-400' },
          { label: 'チーム共有', value: totalShared, icon: Users, color: 'text-emerald-400' },
          { label: '個人', value: totalPersonal, icon: User, color: 'text-purple-400' },
          {
            label: '最終使用',
            value: searches.reduce((latest, s) => {
              if (!s.last_used) return latest
              return !latest || new Date(s.last_used) > new Date(latest) ? s.last_used : latest
            }, null as string | null) ? formatRelative(
              searches.reduce((latest, s) => {
                if (!s.last_used) return latest
                return !latest || new Date(s.last_used) > new Date(latest) ? s.last_used : latest
              }, null as string | null)
            ) : '―',
            icon: Clock,
            color: 'text-amber-400',
          },
        ].map(({ label, value, icon: Icon, color }) => (
          <div key={label} className="bg-falcon-surface border border-falcon-border rounded-lg p-4 flex items-center gap-3">
            <div className={`w-9 h-9 rounded-sm bg-falcon-border flex items-center justify-center shrink-0`}>
              <Icon className={`w-4 h-4 ${color}`} />
            </div>
            <div>
              <p className="text-white font-bold text-lg leading-none">{value}</p>
              <p className="text-falcon-muted text-xs mt-1">{label}</p>
            </div>
          </div>
        ))}
      </div>

      {/* Quick System Filters */}
      <div className="mb-6">
        <div className="flex items-center justify-between mb-3">
          <h2 className="text-falcon-text font-semibold text-sm">クイックフィルター</h2>
          <span className="text-falcon-muted text-xs">システム定義の検索</span>
        </div>
        <div className="grid grid-cols-3 gap-3">
          {systemFilters.map(f => {
            const ScopeIcon = SCOPE_ICONS[f.scope]
            return (
              <div key={f.id} className="bg-falcon-surface border border-falcon-border rounded-lg p-4 flex flex-col gap-2 hover:border-falcon-subtle transition-colors group">
                <div className="flex items-start justify-between">
                  <div className="flex items-center gap-2">
                    <ScopeIcon className="w-4 h-4 text-falcon-muted" />
                    <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border ${SCOPE_COLORS[f.scope]} font-medium`}>
                      {SCOPE_LABELS[f.scope]}
                    </span>
                  </div>
                  <button
                    onClick={() => handleToggleFavorite(f.id)}
                    className={`transition-colors ${f.favorited ? 'text-amber-400' : 'text-falcon-subtle group-hover:text-falcon-muted'}`}
                    title="お気に入り"
                  >
                    <Star className="w-4 h-4" fill={f.favorited ? 'currentColor' : 'none'} />
                  </button>
                </div>
                <p className="text-falcon-text text-sm font-medium">{f.name}</p>
                <p className="text-falcon-muted text-xs">{f.description}</p>
                <code className="text-falcon-muted text-[10px] font-mono bg-[#070d19] px-2 py-1 rounded-sm border border-falcon-border truncate block">
                  {f.query}
                </code>
                <button
                  onClick={() => handleRunSystem(f)}
                  className="mt-auto w-full py-1.5 rounded-sm bg-falcon-border hover:bg-falcon-red text-falcon-muted hover:text-white text-xs font-medium transition-colors flex items-center justify-center gap-1.5"
                >
                  <Play className="w-3 h-3" />
                  実行
                </button>
              </div>
            )
          })}
        </div>
      </div>

      {/* Saved Searches */}
      <div className="bg-falcon-surface border border-falcon-border rounded-lg">
        {/* Toolbar */}
        <div className="flex items-center justify-between gap-3 p-4 border-b border-falcon-border">
          <h2 className="text-falcon-text font-semibold text-sm flex items-center gap-2">
            <BookmarkCheck className="w-4 h-4 text-falcon-red" />
            保存済み検索一覧
          </h2>
          <div className="flex items-center gap-2">
            {/* Scope filter */}
            <div className="relative">
              <select
                value={scopeFilter}
                onChange={e => setScopeFilter(e.target.value as Scope | 'all')}
                className="appearance-none bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5 text-xs text-falcon-muted focus:outline-hidden focus:border-falcon-subtle pr-7"
              >
                <option value="all">全スコープ</option>
                {(Object.keys(SCOPE_LABELS) as Scope[]).map(s => (
                  <option key={s} value={s}>{SCOPE_LABELS[s]}</option>
                ))}
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-falcon-subtle pointer-events-none" />
            </div>
            {/* Owner filter */}
            <div className="relative">
              <select
                value={ownerFilter}
                onChange={e => setOwnerFilter(e.target.value as OwnerFilter)}
                className="appearance-none bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5 text-xs text-falcon-muted focus:outline-hidden focus:border-falcon-subtle pr-7"
              >
                <option value="all">全員</option>
                <option value="mine">自分</option>
                <option value="team">チーム共有</option>
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-falcon-subtle pointer-events-none" />
            </div>
            {/* Sort */}
            <div className="relative">
              <select
                value={sortBy}
                onChange={e => setSortBy(e.target.value as SortBy)}
                className="appearance-none bg-[#070d19] border border-falcon-border rounded-sm px-3 py-1.5 text-xs text-falcon-muted focus:outline-hidden focus:border-falcon-subtle pr-7"
              >
                <option value="newest">新着順</option>
                <option value="most_used">使用回数</option>
                <option value="name">名前順</option>
              </select>
              <ChevronDown className="absolute right-2 top-1/2 -translate-y-1/2 w-3 h-3 text-falcon-subtle pointer-events-none" />
            </div>
            <button
              onClick={() => setShowSaveModal(true)}
              className="flex items-center gap-1.5 px-3 py-1.5 rounded-sm bg-falcon-red hover:bg-[#c0001f] text-white text-xs font-medium transition-colors"
            >
              <Plus className="w-3 h-3" />
              検索を保存
            </button>
          </div>
        </div>

        {/* List */}
        <div className="divide-y divide-falcon-border">
          {filtered.length === 0 && (
            <div className="py-12 text-center">
              <Search className="w-8 h-8 text-falcon-subtle mx-auto mb-2" />
              <p className="text-falcon-muted text-sm">該当する保存済み検索がありません</p>
            </div>
          )}
          {filtered.map(s => {
            const ScopeIcon = SCOPE_ICONS[s.scope]
            return (
              <div key={s.id} className="p-4 flex items-center gap-4 hover:bg-[#0a1525] transition-colors group">
                {/* Scope icon */}
                <div className="w-9 h-9 rounded-sm bg-falcon-border flex items-center justify-center shrink-0">
                  <ScopeIcon className="w-4 h-4 text-falcon-muted" />
                </div>
                {/* Info */}
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <span className="text-falcon-text text-sm font-medium">{s.name}</span>
                    <span className={`text-[10px] px-1.5 py-0.5 rounded-sm border ${SCOPE_COLORS[s.scope]} font-medium`}>
                      {SCOPE_LABELS[s.scope]}
                    </span>
                    {s.shared && (
                      <span className="text-[10px] px-1.5 py-0.5 rounded-sm bg-emerald-500/20 text-emerald-300 border border-emerald-500/30 font-medium flex items-center gap-1">
                        <Users className="w-2.5 h-2.5" />共有
                      </span>
                    )}
                  </div>
                  {s.description && (
                    <p className="text-falcon-muted text-xs mb-1.5">{s.description}</p>
                  )}
                  <code className="text-falcon-muted text-[11px] font-mono bg-[#070d19] px-2 py-0.5 rounded-sm border border-falcon-border truncate inline-block max-w-lg">
                    {s.query}
                  </code>
                  <div className="flex items-center gap-3 mt-1.5">
                    {/* Owner avatar */}
                    <div className="flex items-center gap-1">
                      <div className="w-4 h-4 rounded-full bg-falcon-blue flex items-center justify-center">
                        <span className="text-[8px] font-bold text-white">{s.owner_initial}</span>
                      </div>
                      <span className="text-falcon-subtle text-[10px]">{s.owner}</span>
                    </div>
                    <span className="text-falcon-subtle text-[10px] flex items-center gap-1">
                      <Clock className="w-3 h-3" />{formatRelative(s.last_used)}
                    </span>
                    <span className="text-falcon-subtle text-[10px] flex items-center gap-1">
                      <BarChart2 className="w-3 h-3" />{s.use_count}回使用
                    </span>
                    {s.tags.map(t => (
                      <span key={t} className="text-falcon-subtle text-[10px] px-1.5 py-0.5 rounded-sm bg-falcon-border">{t}</span>
                    ))}
                  </div>
                </div>
                {/* Actions */}
                <div className="flex items-center gap-2 opacity-0 group-hover:opacity-100 transition-opacity">
                  <button
                    onClick={() => handleRun(s)}
                    title="実行"
                    className="flex items-center gap-1 px-2.5 py-1.5 rounded-sm bg-falcon-red/20 hover:bg-falcon-red text-falcon-red hover:text-white text-xs font-medium transition-colors"
                  >
                    <Play className="w-3 h-3" />実行
                  </button>
                  <button
                    onClick={() => handleToggleShare(s.id)}
                    title={s.shared ? '共有を解除' : '共有する'}
                    className={`p-1.5 rounded-sm transition-colors ${s.shared ? 'bg-emerald-500/20 text-emerald-400 hover:bg-emerald-500/40' : 'bg-falcon-border text-falcon-muted hover:text-white'}`}
                  >
                    <Share2 className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => setEditTarget(s)}
                    title="編集"
                    className="p-1.5 rounded-sm bg-falcon-border text-falcon-muted hover:text-white transition-colors"
                  >
                    <Edit2 className="w-3.5 h-3.5" />
                  </button>
                  <button
                    onClick={() => setDeleteTarget(s)}
                    title="削除"
                    className="p-1.5 rounded-sm bg-falcon-border text-falcon-muted hover:text-red-400 transition-colors"
                  >
                    <Trash2 className="w-3.5 h-3.5" />
                  </button>
                </div>
              </div>
            )
          })}
        </div>
      </div>

      {/* Modals */}
      {(showSaveModal || editTarget) && (
        <SaveModal
          initial={editTarget ?? undefined}
          onClose={() => { setShowSaveModal(false); setEditTarget(null) }}
          onSave={handleSave}
        />
      )}
      {deleteTarget && (
        <DeleteConfirm
          name={deleteTarget.name}
          onClose={() => setDeleteTarget(null)}
          onConfirm={() => handleDelete(deleteTarget.id)}
        />
      )}
    </div>
  )
}
