'use client'

import { useState, useEffect, useRef, useCallback } from 'react'
import { useRouter } from 'next/navigation'
import {
  Search, X, ShieldAlert, Monitor, Siren, BookOpen,
  Loader2, LayoutDashboard, AlertOctagon, FileText,
  CornerDownLeft, Crosshair, Archive, Fingerprint, Trash2,
} from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { getSeverityColor, getSeverityLabel } from '@/components/ui/badges'

// ── Types ───────────────────────────────────────────────────────

interface AlertResult {
  id: string
  title: string
  severity: number
  status: string
}

interface AgentResult {
  id: string
  hostname: string
  ip_address?: string
  status: string
}

interface IncidentResult {
  id: string
  title: string
  status: string
}

interface RuleResult {
  id: string
  name: string
  rule_type?: string
  type?: string
}

interface IOCResult {
  id: string
  value: string
  type: string
  severity?: string
}

interface FlatResult {
  kind: 'alert' | 'agent' | 'incident' | 'rule' | 'ioc' | 'quick-nav' | 'page'
  id: string
  primary: string
  secondary?: string
  severity?: number
  status?: string
  href: string
  icon?: React.ElementType
}

// ── Quick-nav links shown when no query ─────────────────────────

const QUICK_NAV: Array<{ href: string; label: string; icon: React.ElementType; color: string }> = [
  { href: '/dashboard', label: 'ダッシュボード', icon: LayoutDashboard, color: '#1a6bff' },
  { href: '/alerts',    label: 'アラート',       icon: ShieldAlert,     color: '#e8002d' },
  { href: '/endpoints', label: 'エンドポイント', icon: Monitor,         color: '#00c853' },
]

// ── Nav items (Japanese labels + keywords) ───────────────────

interface NavItem { href: string; label: string; group: string; keywords?: string[]; icon: React.ElementType }

const NAV_ITEMS: NavItem[] = [
  { href: '/dashboard',        label: 'ダッシュボード',      group: '概要',           keywords: ['dashboard', 'top', 'トップ'], icon: LayoutDashboard },
  { href: '/alerts',           label: 'アラート',            group: '検知',           keywords: ['alert', '警告', 'アラート一覧'], icon: ShieldAlert },
  { href: '/endpoints',        label: 'エンドポイント',      group: 'エンドポイント', keywords: ['endpoint', 'agent', '端末', 'ホスト', 'agents'], icon: Monitor },
  { href: '/events',           label: 'イベントログ',        group: 'エンドポイント', keywords: ['event', 'log', 'イベント', 'ログ', 'events'], icon: FileText },
  { href: '/settings',         label: '設定',                group: '管理',           keywords: ['settings', 'config', '設定', 'コンフィグ'], icon: LayoutDashboard },
]

const RECENT_SEARCHES_KEY = 'edr_recent_searches'

function getRecentSearches(): string[] {
  if (typeof window === 'undefined') return []
  try {
    return JSON.parse(localStorage.getItem(RECENT_SEARCHES_KEY) || '[]')
  } catch { return [] }
}

function saveRecentSearch(q: string) {
  if (typeof window === 'undefined') return
  try {
    const prev = getRecentSearches().filter(s => s !== q)
    localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify([q, ...prev].slice(0, 5)))
  } catch { /* ignore */ }
}

function deleteRecentSearch(q: string) {
  if (typeof window === 'undefined') return
  try {
    const prev = getRecentSearches().filter(s => s !== q)
    localStorage.setItem(RECENT_SEARCHES_KEY, JSON.stringify(prev))
  } catch { /* ignore */ }
}

function clearRecentSearches() {
  if (typeof window === 'undefined') return
  try { localStorage.removeItem(RECENT_SEARCHES_KEY) } catch { /* ignore */ }
}

// ── Component ───────────────────────────────────────────────────

export interface CommandPaletteProps {
  isOpen: boolean
  onClose: () => void
}

export function CommandPalette({ isOpen, onClose }: CommandPaletteProps) {
  const router = useRouter()
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<FlatResult[]>([])
  const [loading, setLoading] = useState(false)
  const [selectedIdx, setSelectedIdx] = useState(0)
  const [recentAlerts, setRecentAlerts] = useState<AlertResult[]>([])
  const [recentSearches, setRecentSearches] = useState<string[]>([])

  const inputRef = useRef<HTMLInputElement>(null)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const containerRef = useRef<HTMLDivElement>(null)

  // ── Reset & focus on open ────────────────────────────────────
  useEffect(() => {
    if (isOpen) {
      setQuery('')
      setResults([])
      setSelectedIdx(0)
      setRecentSearches(getRecentSearches())
      setTimeout(() => {
        if (inputRef.current) {
          inputRef.current.value = ''
          inputRef.current.focus()
        }
      }, 50)
    }
  }, [isOpen])

  // ── Native IME event listeners (Windows Chrome Japanese IME support) ─
  useEffect(() => {
    if (!isOpen) return
    const input = inputRef.current
    if (!input) return
    let composing = false
    const onCompositionStart = () => { composing = true }
    const onCompositionEnd = () => { composing = false; setQuery(input.value) }
    const onInput = () => { if (!composing) setQuery(input.value) }
    input.addEventListener('compositionstart', onCompositionStart)
    input.addEventListener('compositionend', onCompositionEnd)
    input.addEventListener('input', onInput)
    return () => {
      input.removeEventListener('compositionstart', onCompositionStart)
      input.removeEventListener('compositionend', onCompositionEnd)
      input.removeEventListener('input', onInput)
    }
  }, [isOpen])

  // ── Load recent alerts for initial state ─────────────────────
  useEffect(() => {
    if (!isOpen) return
    apiFetch<{ alerts?: AlertResult[]; items?: AlertResult[] }>(
      '/api/v1/alerts?limit=5&sort=created_at&order=desc'
    )
      .then(data => setRecentAlerts(data.alerts ?? data.items ?? []))
      .catch(() => setRecentAlerts([]))
  }, [isOpen])

  // ── Parallel search across resource types ────────────────────
  const doSearch = useCallback(async (q: string) => {
    if (q.length < 2) {
      setResults([])
      return
    }
    setLoading(true)
    try {
      const qs = encodeURIComponent(q)
      const [alertsData, agentsData, incidentsData, rulesData, iocData] = await Promise.allSettled([
        apiFetch<{ alerts?: AlertResult[]; items?: AlertResult[] }>(
          `/api/v1/alerts?search=${qs}&limit=5`
        ),
        apiFetch<{ agents?: AgentResult[]; items?: AgentResult[] }>(
          `/api/v1/agents?search=${qs}&limit=5`
        ),
        apiFetch<{ incidents?: IncidentResult[]; items?: IncidentResult[] }>(
          `/api/v1/incidents?search=${qs}&limit=5`
        ),
        apiFetch<{ rules?: RuleResult[]; items?: RuleResult[] }>(
          `/api/v1/rules?search=${qs}&limit=5`
        ),
        apiFetch<{ iocs?: IOCResult[]; items?: IOCResult[] }>(
          `/api/v1/ioc?search=${qs}&limit=5`
        ),
      ])

      const flat: FlatResult[] = []

      // Page results — static, always included first
      const qLower = q.toLowerCase()
      NAV_ITEMS
        .filter(item => {
          const label = item.label.toLowerCase()
          return label.includes(qLower) || qLower.includes(label) ||
                 item.group.toLowerCase().includes(qLower) ||
                 item.href.toLowerCase().includes(qLower) ||
                 (item.keywords ?? []).some(k => k.toLowerCase().includes(qLower))
        })
        .slice(0, 5)
        .forEach(item => flat.push({
          kind: 'page',
          id: item.href,
          primary: item.label,
          secondary: item.group,
          href: item.href,
          icon: item.icon,
        }))

      if (alertsData.status === 'fulfilled') {
        const items = alertsData.value.alerts ?? alertsData.value.items ?? []
        items.forEach(a =>
          flat.push({
            kind: 'alert',
            id: a.id,
            primary: a.title,
            secondary: a.status,
            severity: a.severity,
            status: a.status,
            href: `/alerts/${a.id}`,
          })
        )
      }

      if (agentsData.status === 'fulfilled') {
        const items = agentsData.value.agents ?? agentsData.value.items ?? []
        items.forEach(a =>
          flat.push({
            kind: 'agent',
            id: a.id,
            primary: a.hostname,
            secondary: a.ip_address,
            status: a.status,
            href: `/endpoints/${a.id}`,
          })
        )
      }

      if (incidentsData.status === 'fulfilled') {
        const items = incidentsData.value.incidents ?? incidentsData.value.items ?? []
        items.forEach(i =>
          flat.push({
            kind: 'incident',
            id: i.id,
            primary: i.title,
            secondary: i.status,
            status: i.status,
            href: `/incidents/${i.id}`,
          })
        )
      }

      if (rulesData.status === 'fulfilled') {
        const items = rulesData.value.rules ?? rulesData.value.items ?? []
        items.forEach(r =>
          flat.push({
            kind: 'rule',
            id: r.id,
            primary: r.name,
            secondary: r.rule_type ?? r.type,
            href: `/rules/${r.id}`,
          })
        )
      }

      if (iocData.status === 'fulfilled') {
        const items = iocData.value.iocs ?? iocData.value.items ?? []
        items.forEach(i =>
          flat.push({
            kind: 'ioc',
            id: i.id,
            primary: i.value,
            secondary: i.type,
            href: `/ioc`,
          })
        )
      }

      setResults(flat)
      setSelectedIdx(0)
    } catch {
      setResults([])
    } finally {
      setLoading(false)
    }
  }, [])

  // ── Debounce search ──────────────────────────────────────────
  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => doSearch(query), 300)
    return () => {
      if (debounceRef.current) clearTimeout(debounceRef.current)
    }
  }, [query, doSearch])

  // ── Navigate to a result ─────────────────────────────────────
  const navigate = useCallback(
    (href: string) => {
      if (query.length >= 2) saveRecentSearch(query)
      router.push(href)
      onClose()
    },
    [router, onClose, query]
  )

  // ── Keyboard navigation ──────────────────────────────────────
  useEffect(() => {
    if (!isOpen) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') {
        onClose()
        return
      }
      if (e.key === 'ArrowDown') {
        e.preventDefault()
        setSelectedIdx(s => Math.min(s + 1, results.length - 1))
      } else if (e.key === 'ArrowUp') {
        e.preventDefault()
        setSelectedIdx(s => Math.max(s - 1, 0))
      } else if (e.key === 'Enter') {
        if (results[selectedIdx]) {
          navigate(results[selectedIdx].href)
        }
      }
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [isOpen, results, selectedIdx, navigate, onClose])

  if (!isOpen) return null

  // ── Grouped results ──────────────────────────────────────────
  type GroupKey = 'page' | 'alert' | 'agent' | 'incident' | 'rule' | 'ioc'
  const GROUP_META: Record<GroupKey, { label: string; icon: React.ElementType; color: string }> = {
    page:     { label: 'Pages',          icon: LayoutDashboard, color: '#7d92b0' },
    alert:    { label: 'アラート',       icon: ShieldAlert,     color: '#e8002d' },
    agent:    { label: 'エンドポイント', icon: Monitor,         color: '#1a6bff' },
    incident: { label: 'インシデント',   icon: Siren,           color: '#ff6b35' },
    rule:     { label: '検知ルール',     icon: BookOpen,        color: '#7c3aed' },
    ioc:      { label: 'IOC',            icon: Fingerprint,     color: '#f59e0b' },
  }
  const ORDER: GroupKey[] = ['page', 'alert', 'agent', 'incident', 'rule', 'ioc']

  const grouped: Record<GroupKey, FlatResult[]> = {
    page: [], alert: [], agent: [], incident: [], rule: [], ioc: [],
  }
  results.forEach(r => {
    if (r.kind in grouped) grouped[r.kind as GroupKey].push(r)
  })

  let flatIdx = 0

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-[10vh] px-4"
      onClick={onClose}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-[#080c14]/80 backdrop-blur-md" />

      {/* Modal */}
      <div
        ref={containerRef}
        className="relative w-full max-w-2xl bg-[#0d1220] border border-[#1e2d42] rounded-lg shadow-2xl overflow-hidden animate-slide-in"
        onClick={e => e.stopPropagation()}
      >
        {/* ── Search Input ────────────────────────────────────── */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-[#1e2d42]">
          <div className="shrink-0">
            {loading ? (
              <Loader2 className="w-4 h-4 text-[#e8002d] animate-spin" />
            ) : (
              <Search className="w-4 h-4 text-[#3d5068]" />
            )}
          </div>
          <input
            ref={inputRef}
            id="command-palette-input"
            name="command-search"
            autoComplete="off"
            placeholder="アラート、エンドポイント、インシデント、IOC を検索..."
            className="flex-1 bg-transparent text-[#e2e8f4] placeholder-[#3d5068] text-sm outline-hidden font-medium"
          />
          <div className="flex items-center gap-2 shrink-0">
            {query && (
              <button
                onClick={() => { if (inputRef.current) inputRef.current.value = ''; setQuery(''); setResults([]) }}
                className="text-[#3d5068] hover:text-[#7d92b0] transition-colors"
                aria-label="クリア"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
            <kbd className="inline-flex items-center px-1.5 py-0.5 bg-[#161f33] border border-[#1e2d42] rounded-sm text-[10px] text-[#3d5068] font-mono">
              ESC
            </kbd>
          </div>
        </div>

        {/* ── Body ────────────────────────────────────────────── */}
        <div className="max-h-[480px] overflow-y-auto">

          {/* Initial state: recent alerts + quick nav */}
          {query.length < 2 && !loading && (
            <div className="py-2">
              {/* Recent alerts section */}
              {recentAlerts.length > 0 && (
                <div>
                  <div className="flex items-center gap-2 px-4 py-1.5 bg-[#161f33]/40 border-b border-[#1e2d42]/50">
                    <ShieldAlert className="w-3 h-3 text-[#e8002d]" />
                    <span className="text-[10px] font-bold text-[#7d92b0] uppercase tracking-widest">
                      最近のアラート
                    </span>
                  </div>
                  {recentAlerts.map(alert => {
                    const sevColor = getSeverityColor(alert.severity)
                    const sevLabel = getSeverityLabel(alert.severity)
                    return (
                      <button
                        key={alert.id}
                        onClick={() => navigate(`/alerts/${alert.id}`)}
                        className="w-full flex items-center gap-3 px-4 py-2.5 text-left hover:bg-[#19253d] transition-colors border-b border-[#1e2d42]/20 last:border-0 group"
                      >
                        <ShieldAlert
                          className="w-4 h-4 shrink-0"
                          style={{ color: sevColor }}
                        />
                        <div className="flex-1 min-w-0">
                          <p className="text-sm text-[#e2e8f4] truncate font-medium">
                            {alert.title}
                          </p>
                        </div>
                        <span
                          className="text-[10px] font-bold font-mono px-1.5 py-0.5 rounded-sm border shrink-0"
                          style={{
                            color: sevColor,
                            borderColor: `${sevColor}40`,
                            backgroundColor: `${sevColor}15`,
                          }}
                        >
                          {sevLabel}
                        </span>
                        <CornerDownLeft
                          className="w-3 h-3 text-[#3d5068] opacity-0 group-hover:opacity-100 transition-opacity shrink-0"
                        />
                      </button>
                    )
                  })}
                </div>
              )}

              {/* Recent Searches */}
              {recentSearches.length > 0 && (
                <div>
                  <div className="flex items-center gap-2 px-4 py-1.5 bg-[#161f33]/40 border-b border-[#1e2d42]/50 mt-1">
                    <Search className="w-3 h-3 text-[#3d5068]" />
                    <span className="text-[10px] font-bold text-[#7d92b0] uppercase tracking-widest flex-1">
                      最近の検索
                    </span>
                    <button
                      onClick={() => { clearRecentSearches(); setRecentSearches([]) }}
                      className="text-[10px] text-[#3d5068] hover:text-[#7d92b0] transition-colors flex items-center gap-1"
                      title="履歴をすべて削除"
                    >
                      <Trash2 className="w-3 h-3" />
                      <span>すべて削除</span>
                    </button>
                  </div>
                  <div className="flex flex-wrap gap-2 px-4 py-2">
                    {recentSearches.map(s => (
                      <div key={s} className="flex items-center group/pill">
                        <button
                          onClick={() => { setQuery(s); if (inputRef.current) { inputRef.current.value = s; inputRef.current.focus() } }}
                          className="text-[11px] px-2.5 py-1 rounded-l bg-[#161f33] border border-[#1e2d42] border-r-0 text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#3d5068] hover:border-r-0 transition-colors"
                        >
                          {s}
                        </button>
                        <button
                          onClick={() => {
                            deleteRecentSearch(s)
                            setRecentSearches(getRecentSearches())
                          }}
                          className="text-[11px] px-1.5 py-1 rounded-r bg-[#161f33] border border-[#1e2d42] text-[#3d5068] hover:text-[#e8002d] hover:border-[#3d5068] transition-colors"
                          title="削除"
                        >
                          <X className="w-2.5 h-2.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Quick navigation */}
              <div>
                <div className="flex items-center gap-2 px-4 py-1.5 bg-[#161f33]/40 border-b border-[#1e2d42]/50 mt-1">
                  <FileText className="w-3 h-3 text-[#3d5068]" />
                  <span className="text-[10px] font-bold text-[#7d92b0] uppercase tracking-widest">
                    クイックナビゲーション
                  </span>
                </div>
                <div className="grid grid-cols-5 gap-0 divide-x divide-[#1e2d42]/50">
                  {QUICK_NAV.map(item => {
                    const Icon = item.icon
                    return (
                      <button
                        key={item.href}
                        onClick={() => navigate(item.href)}
                        className="flex flex-col items-center gap-1.5 px-3 py-3 hover:bg-[#19253d] transition-colors group"
                      >
                        <Icon
                          className="w-4 h-4 shrink-0 transition-transform group-hover:scale-110"
                          style={{ color: item.color }}
                        />
                        <span className="text-[10px] text-[#7d92b0] group-hover:text-[#e2e8f4] transition-colors text-center leading-tight">
                          {item.label}
                        </span>
                      </button>
                    )
                  })}
                </div>
              </div>
            </div>
          )}

          {/* Loading spinner */}
          {query.length >= 2 && loading && (
            <div className="flex items-center justify-center py-12 gap-3">
              <Loader2 className="w-5 h-5 text-[#e8002d] animate-spin" />
              <span className="text-sm text-[#3d5068]">検索中...</span>
            </div>
          )}

          {/* Empty state */}
          {query.length >= 2 && !loading && results.length === 0 && (
            <div className="px-4 py-14 text-center">
              <Search className="w-8 h-8 text-[#1e2d42] mx-auto mb-3" />
              <p className="text-[#3d5068] text-sm">結果が見つかりません</p>
              <p className="text-[#3d5068] text-xs mt-1 font-mono">「{query}」</p>
            </div>
          )}

          {/* Grouped results */}
          {query.length >= 2 && !loading && results.length > 0 && (
            <>
              {ORDER.map(kind => {
                const items = grouped[kind]
                if (items.length === 0) return null
                const meta = GROUP_META[kind]
                const GroupIcon = meta.icon
                return (
                  <div key={kind}>
                    {/* Group header */}
                    <div className="flex items-center gap-2 px-4 py-1.5 bg-[#161f33]/50 border-b border-[#1e2d42]/50 sticky top-0 z-10">
                      <GroupIcon
                        className="w-3 h-3 shrink-0"
                        style={{ color: meta.color }}
                      />
                      <span className="text-[10px] font-bold text-[#7d92b0] uppercase tracking-widest">
                        {meta.label}
                      </span>
                      <span className="text-[10px] text-[#3d5068] ml-auto font-mono">
                        {items.length}
                      </span>
                    </div>

                    {/* Result rows */}
                    {items.map(r => {
                      const idx = flatIdx++
                      const isSelected = idx === selectedIdx
                      return (
                        <ResultRow
                          key={r.id}
                          result={r}
                          kind={kind}
                          meta={meta}
                          isSelected={isSelected}
                          onHover={() => setSelectedIdx(idx)}
                          onClick={() => navigate(r.href)}
                        />
                      )
                    })}
                  </div>
                )
              })}
            </>
          )}
        </div>

        {/* ── Footer ──────────────────────────────────────────── */}
        {results.length > 0 && (
          <div className="flex items-center gap-4 px-4 py-2 border-t border-[#1e2d42] bg-[#161f33]/50 text-[10px] text-[#3d5068]">
            <span className="flex items-center gap-1">
              <kbd className="font-mono bg-[#1e2d42] px-1 rounded-sm">↑↓</kbd>
              移動
            </span>
            <span className="flex items-center gap-1">
              <kbd className="font-mono bg-[#1e2d42] px-1 rounded-sm">↵</kbd>
              開く
            </span>
            <span className="flex items-center gap-1">
              <kbd className="font-mono bg-[#1e2d42] px-1 rounded-sm">Esc</kbd>
              閉じる
            </span>
            <span className="ml-auto font-mono text-[#3d5068]">
              {results.length} 件
              {results.length > 0 && (
                <span className="ml-2 text-[#1e2d42]">
                  {ORDER.filter(k => grouped[k]?.length > 0).map(k => `${GROUP_META[k].label} ${grouped[k].length}`).join(' · ')}
                </span>
              )}
            </span>
          </div>
        )}
      </div>
    </div>
  )
}

// ── Result Row Sub-component ─────────────────────────────────────

interface ResultRowProps {
  result: FlatResult
  kind: 'page' | 'alert' | 'agent' | 'incident' | 'rule' | 'ioc'
  meta: { label: string; icon: React.ElementType; color: string }
  isSelected: boolean
  onHover: () => void
  onClick: () => void
}

function ResultRow({ result, kind, meta, isSelected, onHover, onClick }: ResultRowProps) {
  // For pages, use the page-specific icon if available
  const GroupIcon = (kind === 'page' && result.icon) ? result.icon : meta.icon

  // Determine icon color per kind
  let iconColor = meta.color
  if (kind === 'alert' && result.severity !== undefined) {
    iconColor = getSeverityColor(result.severity)
  } else if (kind === 'agent') {
    iconColor = result.status === 'online' ? '#00c853' : '#3d5068'
  } else if (kind === 'page') {
    iconColor = '#7d92b0'
  } else if (kind === 'ioc') {
    iconColor = '#f59e0b'
  }

  return (
    <button
      onClick={onClick}
      onMouseEnter={onHover}
      className={`w-full flex items-center gap-3 px-4 py-3 text-left transition-colors
                  border-b border-[#1e2d42]/30 last:border-0 group ${
        isSelected ? 'bg-[#1d2f4a]' : 'hover:bg-[#19253d]'
      }`}
    >
      {/* Icon */}
      <GroupIcon className="w-4 h-4 shrink-0" style={{ color: iconColor }} />

      {/* Text */}
      <div className="flex-1 min-w-0">
        <p className="text-sm text-[#e2e8f4] truncate font-medium">{result.primary}</p>
        {result.secondary && (
          <p className="text-[11px] text-[#3d5068] truncate font-mono mt-0.5">
            {result.secondary}
          </p>
        )}
      </div>

      {/* Metadata badges */}
      <div className="flex items-center gap-2 shrink-0">
        {kind === 'alert' && result.severity !== undefined && (
          <span
            className="text-[10px] font-bold font-mono px-1.5 py-0.5 rounded-sm border"
            style={{
              color: getSeverityColor(result.severity),
              borderColor: `${getSeverityColor(result.severity)}40`,
              backgroundColor: `${getSeverityColor(result.severity)}15`,
            }}
          >
            {getSeverityLabel(result.severity)}
          </span>
        )}
        {result.status && kind !== 'alert' && (
          <span className="text-[10px] text-[#3d5068] bg-[#161f33] px-1.5 py-0.5 rounded-sm font-mono">
            {result.status}
          </span>
        )}
        {result.secondary && kind === 'rule' && (
          <span className="text-[10px] text-[#7c3aed] bg-[#7c3aed]/10 px-1.5 py-0.5 rounded-sm font-mono">
            {result.secondary}
          </span>
        )}
        {result.secondary && kind === 'ioc' && (
          <span className="text-[10px] text-[#f59e0b] bg-[#f59e0b]/10 px-1.5 py-0.5 rounded-sm font-mono uppercase">
            {result.secondary}
          </span>
        )}
        {/* Enter hint */}
        <span
          className={`text-[9px] font-mono text-[#3d5068] transition-opacity ${
            isSelected ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'
          }`}
        >
          Enter to open
        </span>
      </div>
    </button>
  )
}
