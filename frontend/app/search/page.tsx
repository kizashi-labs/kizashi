'use client'

import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useMutation } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import Link from 'next/link'
import {
  Search, ShieldAlert, Monitor, AlertTriangle,
  FileCode, Play, ArrowRight, Clock, X,
  Lightbulb, Loader2, Compass,
} from 'lucide-react'

// ── Nav items (client-side search) ────────────────────────────

const NAV_ITEMS = [
  { href: '/dashboard',       label: 'ダッシュボード',      group: '概要',           keywords: ['dashboard', 'top', 'トップ'] },
  { href: '/timeline',        label: 'タイムライン',        group: '概要',           keywords: ['timeline'] },
  { href: '/alerts',          label: 'アラート',            group: '検知',           keywords: ['alert', '警告', 'アラート一覧'] },
  { href: '/alerts/triage',   label: 'トリアージ',          group: '検知',           keywords: ['triage', '振り分け', '仕分け'] },
  { href: '/incidents',       label: 'インシデント',        group: '検知',           keywords: ['incident', '事案', '事故'] },
  { href: '/rules',           label: '検知ルール',          group: '検知',           keywords: ['rule', 'sigma', 'ルール'] },
  { href: '/suppressions',    label: 'アラート抑制',        group: '検知',           keywords: ['suppression', '抑制', '除外', 'ホワイトリスト'] },
  { href: '/endpoints',       label: 'エンドポイント',      group: 'エンドポイント', keywords: ['endpoint', 'agent', '端末', 'ホスト'] },
  { href: '/live-response',   label: 'ライブレスポンス',    group: 'エンドポイント', keywords: ['live response', 'remote shell', 'リモート', '端末操作', 'ターミナル'] },
  { href: '/forensics',       label: 'フォレンジクス',      group: 'エンドポイント', keywords: ['forensics', '証拠', '調査', 'メモリ'] },
  { href: '/quarantine',      label: '検疫ファイル',        group: 'エンドポイント', keywords: ['quarantine', '検疫', '隔離ファイル'] },
  { href: '/software',        label: 'ソフトウェア管理',    group: 'エンドポイント', keywords: ['software', 'package', 'インベントリ'] },
  { href: '/agents/deploy',   label: 'エージェント配布',    group: 'エンドポイント', keywords: ['deploy', 'install', 'インストール', '配布'] },
  { href: '/endpoints/bulk',  label: '一括操作',            group: 'エンドポイント', keywords: ['bulk', '一括', 'まとめて'] },
  { href: '/endpoints/tags',  label: 'エンドポイントタグ',  group: 'エンドポイント', keywords: ['tag', 'タグ', 'ラベル'] },
  { href: '/events',          label: 'イベントログ',        group: 'エンドポイント', keywords: ['event', 'log', 'イベント', 'ログ'] },
  { href: '/ioc',             label: 'IOC管理',             group: 'インテリジェンス', keywords: ['ioc', 'indicator', '侵害指標', 'hash', 'ip'] },
  { href: '/mitre',           label: 'MITRE ATT&CK',        group: 'インテリジェンス', keywords: ['mitre', 'att&ck', 'attack', 'ミトレ', 'ttps'] },
  { href: '/threat-intel',    label: '脅威インテリジェンス', group: 'インテリジェンス', keywords: ['threat intel', 'ti', 'feed', 'フィード'] },
  { href: '/threat-hunting',  label: 'スレットハンティング', group: 'インテリジェンス', keywords: ['hunt', 'hunting', 'ハンティング', '脅威探索'] },
  { href: '/network',         label: 'ネットワーク分析',    group: '監視',           keywords: ['network', 'ネットワーク', 'nta'] },
  { href: '/ueba',            label: '行動分析 (UEBA)',     group: '監視',           keywords: ['ueba', '行動分析', '異常', '振る舞い'] },
  { href: '/fim',             label: 'ファイル変更監視',    group: '監視',           keywords: ['fim', 'file integrity', 'ファイル監視', '改ざん'] },
  { href: '/playbooks',       label: 'プレイブック',        group: '対応',           keywords: ['playbook', 'soar', '自動対応', 'プレイ'] },
  { href: '/vulnerabilities', label: '脆弱性管理',          group: '対応',           keywords: ['vulnerability', 'cve', '脆弱性', 'パッチ'] },
  { href: '/compliance',      label: 'コンプライアンス',    group: '対応',           keywords: ['compliance', 'iso', 'pci', 'コンプラ', '準拠'] },
  { href: '/reports',         label: 'レポート',            group: '分析',           keywords: ['report', 'レポート', '帳票'] },
  { href: '/settings',        label: '設定',                group: '管理',           keywords: ['settings', 'config', '設定', 'コンフィグ'] },
  { href: '/admin/sigma-rules', label: 'Sigmaルール管理',   group: '管理',           keywords: ['sigma', 'rule', 'シグマ', '検知ルール管理'] },
  { href: '/admin/yara-rules',  label: 'YARAルール管理',    group: '管理',           keywords: ['yara', 'ヤラ', 'マルウェア検知'] },
  { href: '/admin/live-response', label: 'ライブレスポンス（管理）', group: '管理',   keywords: ['live response', 'ライブレスポンス', 'リモート'] },
]

// ── Types ──────────────────────────────────────────────────────

type ResultType = 'nav' | 'alert' | 'agent' | 'incident' | 'rule' | 'playbook'

interface SearchResult {
  id: string
  type: ResultType
  title: string
  subtitle: string
  link: string
}

interface SearchResponse {
  results: SearchResult[]
  total: number
  took_ms: number
}

type FilterType = 'all' | ResultType

// ── Constants ──────────────────────────────────────────────────

const FILTER_PILLS: { value: FilterType; label: string }[] = [
  { value: 'all',      label: 'すべて' },
  { value: 'nav',      label: 'ページ' },
  { value: 'alert',    label: 'アラート' },
  { value: 'agent',    label: 'エージェント' },
  { value: 'incident', label: 'インシデント' },
  { value: 'rule',     label: 'ルール' },
  { value: 'playbook', label: 'プレイブック' },
]

const TYPE_ICONS: Record<ResultType, React.ComponentType<{ className?: string }>> = {
  nav:      Compass,
  alert:    ShieldAlert,
  agent:    Monitor,
  incident: AlertTriangle,
  rule:     FileCode,
  playbook: Play,
}

const TYPE_LABELS: Record<ResultType, string> = {
  nav:      'ページ',
  alert:    'アラート',
  agent:    'エージェント',
  incident: 'インシデント',
  rule:     'ルール',
  playbook: 'プレイブック',
}

const TYPE_COLORS: Record<ResultType, string> = {
  nav:      'text-teal-400 bg-teal-500/10',
  alert:    'text-[#e8002d] bg-[#e8002d]/10',
  agent:    'text-blue-400 bg-blue-500/10',
  incident: 'text-orange-400 bg-orange-500/10',
  rule:     'text-green-400 bg-green-500/10',
  playbook: 'text-purple-400 bg-purple-500/10',
}

const SEARCH_TIPS = [
  'ページ名（例：アラート、ライブレスポンス）で画面を検索',
  'エージェントのホスト名やIPアドレスで検索',
  'アラートIDや重大度で絞り込み',
  'MITRE技術ID (例: T1059) で検索',
  'インシデントタイトルで検索',
]

const RECENT_KEY = 'edr_recent_searches'
const MAX_RECENT = 10

function loadRecentSearches(): string[] {
  if (typeof window === 'undefined') return []
  try {
    return JSON.parse(localStorage.getItem(RECENT_KEY) ?? '[]')
  } catch {
    return []
  }
}

function saveRecentSearch(query: string) {
  if (!query.trim()) return
  const current = loadRecentSearches()
  const updated = [query, ...current.filter(q => q !== query)].slice(0, MAX_RECENT)
  localStorage.setItem(RECENT_KEY, JSON.stringify(updated))
}

function removeRecentSearch(query: string) {
  const current = loadRecentSearches()
  localStorage.setItem(RECENT_KEY, JSON.stringify(current.filter(q => q !== query)))
}

// ── Result Item ────────────────────────────────────────────────

function ResultItem({
  result,
  isActive,
  onMouseEnter,
}: {
  result: SearchResult
  isActive: boolean
  onMouseEnter: () => void
}) {
  const Icon = TYPE_ICONS[result.type]
  const colorClass = TYPE_COLORS[result.type]

  return (
    <Link
      href={result.link}
      onMouseEnter={onMouseEnter}
      className={`flex items-center gap-3 px-4 py-3 rounded-lg transition-all group ${
        isActive ? 'bg-[#1d2f4a]' : 'hover:bg-[#0d1220]'
      }`}
    >
      <div className={`w-8 h-8 rounded-lg flex items-center justify-center flex-shrink-0 ${colorClass}`}>
        <Icon className="w-4 h-4" />
      </div>
      <div className="flex-1 min-w-0">
        <p className="text-sm font-medium text-[#e2e8f4] truncate group-hover:text-white transition-colors">
          {result.title}
        </p>
        <p className="text-xs text-[#7d92b0] truncate">{result.subtitle}</p>
      </div>
      <div className="flex items-center gap-2 flex-shrink-0">
        <span className={`text-[10px] font-medium px-2 py-0.5 rounded-full ${colorClass}`}>
          {TYPE_LABELS[result.type]}
        </span>
        <ArrowRight className={`w-4 h-4 text-[#3d5068] transition-all ${isActive ? 'text-[#7d92b0] translate-x-0.5' : ''}`} />
      </div>
    </Link>
  )
}

// ── Page ───────────────────────────────────────────────────────

export default function SearchPage() {
  const inputRef = useRef<HTMLInputElement>(null)
  const [query, setQuery] = useState('')
  const [activeFilter, setActiveFilter] = useState<FilterType>('all')
  const [activeIndex, setActiveIndex] = useState(-1)
  const [recentSearches, setRecentSearches] = useState<string[]>([])
  const [searchData, setSearchData] = useState<SearchResponse | null>(null)
  const debounceTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  // Auto-focus on mount
  useEffect(() => {
    inputRef.current?.focus()
    setRecentSearches(loadRecentSearches())
  }, [])

  const searchMutation = useMutation({
    mutationFn: (body: object) =>
      apiFetch('/api/v1/search', { method: 'POST', body: JSON.stringify(body) }) as Promise<SearchResponse>,
    onSuccess: data => {
      setSearchData(data)
      setActiveIndex(-1)
    },
  })

  // ナビゲーション項目のクライアントサイド検索
  const navResults = useMemo<SearchResult[]>(() => {
    const q = query.trim().toLowerCase()
    if (q.length < 2) return []
    if (activeFilter !== 'all' && activeFilter !== 'nav') return []
    return NAV_ITEMS
      .filter(item => {
        const label = item.label.toLowerCase()
        return label.includes(q) || q.includes(label) ||
               item.group.toLowerCase().includes(q) ||
               item.href.toLowerCase().includes(q) ||
               (item.keywords ?? []).some(k => k.toLowerCase().includes(q))
      })
      .slice(0, 6)
      .map(item => ({
        id: item.href,
        type: 'nav' as const,
        title: item.label,
        subtitle: item.group,
        link: item.href,
      }))
  }, [query, activeFilter])

  // Debounced search trigger
  const triggerSearch = useCallback((q: string, filter: FilterType) => {
    if (!q.trim()) {
      setSearchData(null)
      return
    }
    if (filter === 'nav') {
      setSearchData(null)
      return
    }
    const types: Exclude<ResultType, 'nav'>[] = filter === 'all'
      ? ['alert', 'agent', 'incident', 'rule', 'playbook']
      : [filter as Exclude<ResultType, 'nav'>]
    searchMutation.mutate({ query: q, types, limit: 20 })
  }, []) // eslint-disable-line react-hooks/exhaustive-deps

  // Handle input change with debounce
  const handleQueryChange = (value: string) => {
    setQuery(value)
    if (debounceTimer.current) clearTimeout(debounceTimer.current)
    debounceTimer.current = setTimeout(() => {
      triggerSearch(value, activeFilter)
    }, 300)
  }

  // Re-trigger search when filter changes
  const handleFilterChange = (filter: FilterType) => {
    setActiveFilter(filter)
    if (query.trim()) {
      triggerSearch(query, filter)
    }
  }

  // Handle recent search click
  const handleRecentClick = (q: string) => {
    setQuery(q)
    triggerSearch(q, activeFilter)
  }

  // Handle clear
  const handleClear = () => {
    setQuery('')
    setSearchData(null)
    setRecentSearches(loadRecentSearches())
    inputRef.current?.focus()
  }

  // Remove recent search
  const handleRemoveRecent = (q: string, e: React.MouseEvent) => {
    e.stopPropagation()
    removeRecentSearch(q)
    setRecentSearches(loadRecentSearches())
  }

  // nav + API 結果をマージ
  const filteredResults = useMemo<SearchResult[]>(() => {
    if (activeFilter === 'nav') return navResults
    const apiRes = searchData?.results ?? []
    if (activeFilter === 'all') return [...navResults, ...apiRes]
    return apiRes
  }, [activeFilter, navResults, searchData])

  // Keyboard navigation
  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (!filteredResults.length) return
    if (e.key === 'ArrowDown') {
      e.preventDefault()
      setActiveIndex(i => Math.min(i + 1, filteredResults.length - 1))
    } else if (e.key === 'ArrowUp') {
      e.preventDefault()
      setActiveIndex(i => Math.max(i - 1, -1))
    } else if (e.key === 'Enter') {
      if (activeIndex >= 0 && filteredResults[activeIndex]) {
        saveRecentSearch(query)
        window.location.href = filteredResults[activeIndex].link
      } else if (filteredResults[0]) {
        saveRecentSearch(query)
        window.location.href = filteredResults[0].link
      }
    }
  }

  // Group results by type
  const groupedResults = filteredResults.reduce<Record<string, SearchResult[]>>((acc, r) => {
    if (!acc[r.type]) acc[r.type] = []
    acc[r.type].push(r)
    return acc
  }, {})

  const typeOrder: ResultType[] = ['nav', 'alert', 'incident', 'agent', 'rule', 'playbook']

  const isLoading = searchMutation.isPending && activeFilter !== 'nav'
  const showEmpty = query.trim().length >= 2 && !isLoading && filteredResults.length === 0
  const showResults = query.trim().length >= 2 && filteredResults.length > 0
  const showRecent = query.trim() === ''

  // Flatten index for keyboard nav
  let globalIdx = -1
  const getGlobalIdx = () => { globalIdx++; return globalIdx }

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      <div className="max-w-3xl mx-auto">

        {/* Header */}
        <div className="text-center mb-8">
          <div className="flex items-center justify-center gap-3 mb-3">
            <div className="w-10 h-10 rounded-xl bg-[#e8002d]/10 border border-[#e8002d]/30 flex items-center justify-center">
              <Search className="w-5 h-5 text-[#e8002d]" />
            </div>
            <h1 className="text-2xl font-bold text-white">グローバル検索</h1>
          </div>
          <p className="text-[#7d92b0] text-sm">
            ページ・アラート・エージェント・インシデント・ルール・プレイブックを横断検索
          </p>
        </div>

        {/* Search Input */}
        <div className="relative mb-4">
          <Search className="absolute left-4 top-1/2 -translate-y-1/2 w-5 h-5 text-[#3d5068] pointer-events-none" />
          <input
            ref={inputRef}
            id="search-input"
            name="q"
            type="text"
            autoComplete="off"
            value={query}
            onChange={e => handleQueryChange(e.target.value)}
            onCompositionEnd={() => setTimeout(() => { if (inputRef.current) handleQueryChange(inputRef.current.value) }, 0)}
            onKeyDown={handleKeyDown}
            placeholder="ページ名・キーワードを入力して検索..."
            className="w-full bg-[#0d1220] border border-[#1e2d42] rounded-xl
                       pl-12 pr-12 py-4 text-base text-[#e2e8f4] placeholder-[#3d5068]
                       focus:outline-none focus:border-[#e8002d]/50 focus:ring-1 focus:ring-[#e8002d]/20
                       transition-all"
          />
          {query && (
            <button
              onClick={handleClear}
              className="absolute right-4 top-1/2 -translate-y-1/2 p-1 rounded
                         text-[#3d5068] hover:text-[#7d92b0] transition-colors"
            >
              <X className="w-4 h-4" />
            </button>
          )}
          {isLoading && (
            <Loader2 className="absolute right-12 top-1/2 -translate-y-1/2 w-4 h-4 text-[#7d92b0] animate-spin" />
          )}
        </div>

        {/* Type Filter Pills */}
        <div className="flex gap-2 flex-wrap mb-6">
          {FILTER_PILLS.map(pill => (
            <button
              key={pill.value}
              onClick={() => handleFilterChange(pill.value)}
              className={`px-3 py-1.5 rounded-full text-xs font-medium border transition-all ${
                activeFilter === pill.value
                  ? 'bg-[#e8002d]/15 border-[#e8002d]/40 text-[#e8002d]'
                  : 'bg-[#0d1220] border-[#1e2d42] text-[#7d92b0] hover:border-[#7d92b0]/40 hover:text-[#e2e8f4]'
              }`}
            >
              {pill.label}
            </button>
          ))}
        </div>

        {/* Results Area */}
        {showResults && (
          <div className="space-y-1 mb-4">
            {/* Meta line */}
            <div className="flex items-center justify-between mb-3">
              <p className="text-xs text-[#7d92b0]">
                <span className="text-white font-medium">{filteredResults.length}</span> 件の結果
                {searchData?.took_ms !== undefined && activeFilter !== 'nav' && (
                  <span className="ml-2 text-[#3d5068]">• {searchData.took_ms}ms</span>
                )}
              </p>
              <button
                onClick={() => { saveRecentSearch(query) }}
                className="text-xs text-[#3d5068] hover:text-[#7d92b0] transition-colors"
              >
                最近の検索に保存
              </button>
            </div>

            {/* Grouped results */}
            {typeOrder.map(type => {
              const items = groupedResults[type]
              if (!items?.length) return null
              const Icon = TYPE_ICONS[type]
              const colorClass = TYPE_COLORS[type]
              return (
                <div key={type} className="mb-4">
                  {/* Section header */}
                  <div className="flex items-center gap-2 px-1 mb-1.5">
                    <div className={`w-5 h-5 rounded flex items-center justify-center ${colorClass}`}>
                      <Icon className="w-3 h-3" />
                    </div>
                    <span className="text-xs font-semibold text-[#7d92b0] uppercase tracking-wider">
                      {TYPE_LABELS[type]}
                    </span>
                    <span className="text-xs text-[#3d5068]">({items.length})</span>
                  </div>

                  {/* Items */}
                  <div className="bg-[#0d1220] border border-[#1e2d42] rounded-lg overflow-hidden divide-y divide-[#1e2d42]">
                    {items.map(result => {
                      const idx = getGlobalIdx()
                      return (
                        <ResultItem
                          key={result.id}
                          result={result}
                          isActive={activeIndex === idx}
                          onMouseEnter={() => setActiveIndex(idx)}
                        />
                      )
                    })}
                  </div>
                </div>
              )
            })}
          </div>
        )}

        {/* Empty state */}
        {showEmpty && (
          <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-8 text-center">
            <Search className="w-10 h-10 text-[#1e2d42] mx-auto mb-3" />
            <p className="text-sm font-medium text-[#7d92b0] mb-1">
              「{query}」に一致する結果がありません
            </p>
            <p className="text-xs text-[#3d5068]">検索ワードを変更するか、フィルターを調整してください</p>
          </div>
        )}

        {/* Recent searches + Tips (shown when no query) */}
        {showRecent && (
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">

            {/* Recent searches */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
              <div className="flex items-center gap-2 mb-3">
                <Clock className="w-4 h-4 text-[#7d92b0]" />
                <h3 className="text-sm font-semibold text-white">最近の検索</h3>
              </div>
              {recentSearches.length === 0 ? (
                <p className="text-xs text-[#3d5068]">まだ検索履歴がありません</p>
              ) : (
                <div className="space-y-1">
                  {recentSearches.map(q => (
                    <div
                      key={q}
                      className="flex items-center gap-2 group"
                    >
                      <button
                        onClick={() => handleRecentClick(q)}
                        className="flex-1 flex items-center gap-2 px-3 py-2 rounded
                                   text-sm text-[#7d92b0] hover:text-[#e2e8f4] hover:bg-[#0a1628]
                                   transition-colors text-left"
                      >
                        <Clock className="w-3 h-3 text-[#3d5068] flex-shrink-0" />
                        <span className="truncate">{q}</span>
                      </button>
                      <button
                        onClick={e => handleRemoveRecent(q, e)}
                        className="p-1 rounded text-[#3d5068] hover:text-[#7d92b0]
                                   opacity-0 group-hover:opacity-100 transition-all"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Search tips */}
            <div className="bg-[#0d1220] border border-[#1e2d42] rounded-xl p-4">
              <div className="flex items-center gap-2 mb-3">
                <Lightbulb className="w-4 h-4 text-yellow-400" />
                <h3 className="text-sm font-semibold text-white">検索のヒント</h3>
              </div>
              <ul className="space-y-2">
                {SEARCH_TIPS.map((tip, i) => (
                  <li key={i} className="flex items-start gap-2 text-xs text-[#7d92b0]">
                    <span className="w-4 h-4 rounded bg-[#1e2d42] flex items-center justify-center
                                     text-[9px] font-bold text-[#3d5068] flex-shrink-0 mt-0.5">
                      {i + 1}
                    </span>
                    {tip}
                  </li>
                ))}
              </ul>
              <div className="mt-4 pt-3 border-t border-[#1e2d42]">
                <p className="text-xs text-[#3d5068]">
                  <kbd className="px-1.5 py-0.5 bg-[#1e2d42] rounded text-[10px] font-mono">↑</kbd>
                  <kbd className="px-1.5 py-0.5 bg-[#1e2d42] rounded text-[10px] font-mono ml-1">↓</kbd>
                  {' '}で移動、{' '}
                  <kbd className="px-1.5 py-0.5 bg-[#1e2d42] rounded text-[10px] font-mono">Enter</kbd>
                  {' '}で開く
                </p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  )
}
