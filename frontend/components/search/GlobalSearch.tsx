'use client'

import { useState, useEffect, useRef, useCallback, useMemo } from 'react'
import { useRouter } from 'next/navigation'
import {
  Search, X, ShieldAlert, Monitor, Siren,
  AlertOctagon, BookOpen, Bug, Package, Loader2, ArrowRight,
  Crosshair, Workflow, Compass, Star,
  Terminal, Archive, Activity, Target, Rss, Network,
  HardDrive, ShieldCheck, BarChart3, Settings, Brain,
  LayoutDashboard, ShieldOff, Layers, Download, Tags,
  FileSearch, FileCode, Bell, FolderOpen,
} from 'lucide-react'
import { apiFetch } from '@/lib/api'
import { getSeverityColor } from '@/components/ui/badges'
import { useFavorites } from '@/lib/useFavorites'

interface NavItem {
  href: string
  label: string
  group: string
  keywords?: string[]
  icon: React.ElementType
}

const NAV_ITEMS: NavItem[] = [
  // 概要
  { href: '/dashboard',        label: 'ダッシュボード',     group: '概要',         keywords: ['dashboard', 'top', 'トップ'], icon: LayoutDashboard },
  { href: '/timeline',         label: 'タイムライン',       group: '概要',         keywords: ['timeline'], icon: Activity },
  // 検知
  { href: '/alerts',           label: 'アラート',           group: '検知',         keywords: ['alert', '警告', 'アラート一覧'], icon: ShieldAlert },
  { href: '/alerts/triage',    label: 'トリアージ',         group: '検知',         keywords: ['triage', '振り分け', '仕分け'], icon: Layers },
  { href: '/incidents',        label: 'インシデント',       group: '検知',         keywords: ['incident', '事案', '事故'], icon: Siren },
  { href: '/rules',            label: '検知ルール',         group: '検知',         keywords: ['rule', 'sigma', 'ルール'], icon: BookOpen },
  { href: '/suppressions',     label: 'アラート抑制',       group: '検知',         keywords: ['suppression', '抑制', '除外', 'ホワイトリスト'], icon: ShieldOff },
  // エンドポイント
  { href: '/endpoints',        label: 'エンドポイント',     group: 'エンドポイント', keywords: ['endpoint', 'agent', '端末', 'ホスト'], icon: Monitor },
  { href: '/live-response',    label: 'ライブレスポンス',   group: 'エンドポイント', keywords: ['live response', 'remote shell', 'リモート', '端末操作', 'ターミナル'], icon: Terminal },
  { href: '/forensics',        label: 'フォレンジクス',     group: 'エンドポイント', keywords: ['forensics', '証拠', '調査', 'メモリ'], icon: HardDrive },
  { href: '/quarantine',       label: '検疫ファイル',       group: 'エンドポイント', keywords: ['quarantine', '検疫', '隔離ファイル'], icon: Archive },
  { href: '/software',         label: 'ソフトウェア管理',   group: 'エンドポイント', keywords: ['software', 'package', 'インベントリ'], icon: Package },
  { href: '/agents/deploy',    label: 'エージェント配布',   group: 'エンドポイント', keywords: ['deploy', 'install', 'インストール', '配布'], icon: Download },
  { href: '/endpoints/bulk',   label: '一括操作',           group: 'エンドポイント', keywords: ['bulk', '一括', 'まとめて'], icon: Layers },
  { href: '/endpoints/tags',   label: 'エンドポイントタグ', group: 'エンドポイント', keywords: ['tag', 'タグ', 'ラベル'], icon: Tags },
  { href: '/events',           label: 'イベントログ',       group: 'エンドポイント', keywords: ['event', 'log', 'イベント', 'ログ'], icon: Activity },
  // インテリジェンス
  { href: '/ioc',              label: 'IOC管理',            group: 'インテリジェンス', keywords: ['ioc', 'indicator', '侵害指標', 'hash', 'ip'], icon: AlertOctagon },
  { href: '/mitre',            label: 'MITRE ATT&CK',       group: 'インテリジェンス', keywords: ['mitre', 'att&ck', 'attack', 'ミトレ', 'ttps'], icon: Target },
  { href: '/threat-intel',     label: '脅威インテリジェンス', group: 'インテリジェンス', keywords: ['threat intel', 'ti', 'feed', 'フィード'], icon: Rss },
  { href: '/threat-hunting',   label: 'スレットハンティング', group: 'インテリジェンス', keywords: ['hunt', 'hunting', 'ハンティング', '脅威探索'], icon: Crosshair },
  // 監視
  { href: '/network',          label: 'ネットワーク分析',   group: '監視',         keywords: ['network', 'ネットワーク', 'nta'], icon: Network },
  { href: '/ueba',             label: '行動分析 (UEBA)',    group: '監視',         keywords: ['ueba', '行動分析', '異常', '振る舞い'], icon: Activity },
  { href: '/fim',              label: 'ファイル変更監視',   group: '監視',         keywords: ['fim', 'file integrity', 'ファイル監視', '改ざん'], icon: FolderOpen },
  // 対応
  { href: '/playbooks',        label: 'プレイブック',       group: '対応',         keywords: ['playbook', 'soar', '自動対応', 'プレイ'], icon: Workflow },
  { href: '/vulnerabilities',  label: '脆弱性管理',         group: '対応',         keywords: ['vulnerability', 'cve', '脆弱性', 'パッチ'], icon: Bug },
  { href: '/compliance',       label: 'コンプライアンス',   group: '対応',         keywords: ['compliance', 'iso', 'pci', 'コンプラ', '準拠'], icon: ShieldCheck },
  // 分析
  { href: '/reports',          label: 'レポート',           group: '分析',         keywords: ['report', 'レポート', '帳票'], icon: BarChart3 },
  // 管理（admin）
  { href: '/admin/sigma-rules', label: 'Sigmaルール管理',   group: '管理',         keywords: ['sigma', 'rule', 'シグマ', '検知ルール管理'], icon: FileSearch },
  { href: '/admin/yara-rules',  label: 'YARAルール管理',    group: '管理',         keywords: ['yara', 'ヤラ', 'マルウェア検知'], icon: FileCode },
  { href: '/admin/alert-suppression', label: 'アラート抑制（管理）', group: '管理', keywords: ['suppression', '抑制', '除外'], icon: ShieldOff },
  { href: '/admin/live-response', label: 'ライブレスポンス（管理）', group: '管理', keywords: ['live response', 'ライブレスポンス', 'リモート'], icon: Terminal },
  { href: '/admin/custom-alert-rules', label: 'カスタムアラートルール', group: '管理', keywords: ['custom', 'カスタム', 'ルール'], icon: Bell },
  { href: '/settings',         label: '設定',               group: '管理',         keywords: ['settings', 'config', '設定', 'コンフィグ'], icon: Settings },
]

interface SearchResult {
  id: string
  type: 'favorite' | 'nav' | 'alert' | 'agent' | 'incident' | 'ioc' | 'rule' | 'vulnerability' | 'software' | 'hunt' | 'playbook'
  title: string
  subtitle?: string
  severity?: number
  status?: string
}

const TYPE_CONFIG: Record<string, {
  label: string
  icon: React.ElementType
  href: (id: string, title?: string) => string
  color: string
}> = {
  favorite:      { label: 'お気に入り',    icon: Star,         href: (id) => id,                  color: '#facc15' },
  nav:           { label: 'ページ',        icon: Compass,      href: (id) => id,                  color: '#14b8a6' },
  alert:         { label: 'アラート',      icon: ShieldAlert,  href: (id) => `/alerts/${id}`,    color: '#e8002d' },
  agent:         { label: 'エンドポイント', icon: Monitor,      href: (id) => `/endpoints/${id}`, color: '#1a6bff' },
  incident:      { label: 'インシデント',  icon: Siren,         href: (id) => `/incidents/${id}`, color: '#ff6b35' },
  ioc:           { label: 'IOC',          icon: AlertOctagon,  href: (_id, title) => `/ioc?q=${encodeURIComponent(title ?? '')}`, color: '#ff9800' },
  rule:          { label: '検知ルール',   icon: BookOpen,       href: (id) => `/rules/${id}`,     color: '#7c3aed' },
  vulnerability: { label: '脆弱性',       icon: Bug,            href: (id) => `/vulnerabilities/${id}`, color: '#ff4d6d' },
  software:      { label: 'ソフトウェア', icon: Package,        href: (_)   => `/software`,        color: '#14b8a6' },
  hunt:          { label: 'スレットハント', icon: Crosshair,    href: (_)   => `/threat-hunting`,  color: '#a78bfa' },
  playbook:      { label: 'プレイブック', icon: Workflow,        href: (_)  => `/playbooks`,        color: '#34d399' },
}

interface Props {
  open: boolean
  onClose: () => void
}

export function GlobalSearch({ open, onClose }: Props) {
  const router = useRouter()
  const [query, setQuery] = useState('')
  const [apiResults, setApiResults] = useState<SearchResult[]>([])
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const debounceRef = useRef<ReturnType<typeof setTimeout> | null>(null)
  const { favorites } = useFavorites()

  // お気に入りをクライアントサイドでフィルタリング
  const favoriteResults = useMemo<SearchResult[]>(() => {
    const q = query.trim().toLowerCase()
    if (q.length < 2) return []
    return favorites
      .filter(f => f.label.toLowerCase().includes(q) || f.href.toLowerCase().includes(q))
      .map(f => ({ id: f.href, type: 'favorite' as const, title: f.label, subtitle: 'お気に入り' }))
  }, [query, favorites])

  // ナビゲーション項目をクライアントサイドでフィルタリング
  const navResults = useMemo<SearchResult[]>(() => {
    const q = query.trim().toLowerCase()
    if (q.length < 2) return []
    return NAV_ITEMS
      .filter(item => {
        const label = item.label.toLowerCase()
        const group = item.group.toLowerCase()
        const href  = item.href.toLowerCase()
        return label.includes(q) || q.includes(label) ||
               group.includes(q) || href.includes(q) ||
               (item.keywords ?? []).some(k => k.toLowerCase().includes(q))
      })
      .slice(0, 5)
      .map(item => ({
        id: item.href,
        type: 'nav' as const,
        title: item.label,
        subtitle: item.group,
      }))
  }, [query])

  const results = useMemo(
    () => [...favoriteResults, ...navResults, ...apiResults],
    [favoriteResults, navResults, apiResults],
  )

  useEffect(() => {
    if (!open) return
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
  }, [open])

  useEffect(() => {
    if (open) {
      setQuery('')
      setApiResults([])
      setSelected(0)
      setTimeout(() => {
        if (inputRef.current) {
          inputRef.current.value = ''
          inputRef.current.focus()
        }
      }, 50)
    }
  }, [open])

  const doSearch = useCallback(async (q: string) => {
    if (q.length < 2) { setApiResults([]); return }
    setLoading(true)
    try {
      const data = await apiFetch(`/api/v1/search?q=${encodeURIComponent(q)}`) as { results?: SearchResult[] }
      setApiResults(data.results ?? [])
      setSelected(0)
    } catch {
      setApiResults([])
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => {
    if (debounceRef.current) clearTimeout(debounceRef.current)
    debounceRef.current = setTimeout(() => doSearch(query), 250)
    return () => { if (debounceRef.current) clearTimeout(debounceRef.current) }
  }, [query, doSearch])

  useEffect(() => {
    if (!open) return
    const handler = (e: KeyboardEvent) => {
      if (e.key === 'Escape') { onClose(); return }
      if (e.key === 'ArrowDown') { e.preventDefault(); setSelected(s => Math.min(s + 1, results.length - 1)) }
      else if (e.key === 'ArrowUp') { e.preventDefault(); setSelected(s => Math.max(s - 1, 0)) }
      else if (e.key === 'Enter' && results[selected]) navigate(results[selected])
    }
    window.addEventListener('keydown', handler)
    return () => window.removeEventListener('keydown', handler)
  }, [open, results, selected])

  const navigate = (r: SearchResult) => {
    const cfg = TYPE_CONFIG[r.type]
    if (!cfg) return
    let href: string
    if (r.type === 'software') {
      // Navigate to software page with the package name as search query
      const name = r.title.split(' ')[0]
      href = `/software?q=${encodeURIComponent(name)}`
    } else {
      href = cfg.href(r.id, r.title)
    }
    router.push(href)
    onClose()
  }

  if (!open) return null

  const navIconMap = Object.fromEntries(NAV_ITEMS.map(n => [n.href, n.icon]))

  const grouped = results.reduce<Record<string, SearchResult[]>>((acc, r) => {
    if (!acc[r.type]) acc[r.type] = []
    acc[r.type].push(r)
    return acc
  }, {})

  let flatIndex = 0

  return (
    <div
      className="fixed inset-0 z-50 flex items-start justify-center pt-20 px-4"
      onClick={onClose}
    >
      {/* Backdrop */}
      <div className="absolute inset-0 bg-falcon-bg/80 backdrop-blur-md" />

      {/* Modal */}
      <div
        className="relative w-full max-w-2xl bg-falcon-card border border-falcon-border
                   rounded-md shadow-falcon-modal overflow-hidden animate-slide-in"
        onClick={e => e.stopPropagation()}
      >
        {/* Header with input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-falcon-border">
          <div className="flex items-center gap-2 shrink-0">
            {loading
              ? <Loader2 className="w-4 h-4 text-falcon-red animate-spin" />
              : <Search className="w-4 h-4 text-falcon-subtle" />
            }
          </div>
          <input
            ref={inputRef}
            id="global-search-input"
            name="global-search"
            autoComplete="off"
            placeholder="アラート、エンドポイント、インシデントを検索..."
            className="flex-1 bg-transparent text-falcon-text placeholder-falcon-subtle
                       text-sm outline-hidden font-medium"
          />
          <div className="flex items-center gap-2 shrink-0">
            {query && (
              <button
                onClick={() => { if (inputRef.current) inputRef.current.value = ''; setQuery(''); setApiResults([]) }}
                className="text-falcon-subtle hover:text-falcon-muted transition-colors"
              >
                <X className="w-3.5 h-3.5" />
              </button>
            )}
            <kbd className="inline-flex items-center px-1.5 py-0.5 bg-falcon-raised border border-falcon-border
                            rounded text-[10px] text-falcon-subtle font-mono">
              ESC
            </kbd>
          </div>
        </div>

        {/* Results */}
        <div className="max-h-[440px] overflow-y-auto">
          {query.length >= 2 && !loading && results.length === 0 && (
            <div className="px-4 py-12 text-center">
              <Search className="w-8 h-8 text-falcon-border mx-auto mb-3" />
              <p className="text-falcon-subtle text-sm">「{query}」に一致する結果なし</p>
            </div>
          )}
          {query.length < 2 && (
            <div className="px-4 py-10">
              <p className="text-falcon-subtle text-xs text-center uppercase tracking-widest">
                2文字以上入力してください
              </p>
              {/* Quick navigation hints */}
              <div className="mt-6 grid grid-cols-3 gap-2">
                {Object.entries(TYPE_CONFIG).map(([type, cfg]) => {
                  const Icon = cfg.icon
                  return (
                    <div key={type} className="flex items-center gap-2 px-3 py-2 rounded bg-falcon-raised
                                               border border-falcon-border text-falcon-subtle">
                      <Icon className="w-3.5 h-3.5 shrink-0" style={{ color: cfg.color }} />
                      <span className="text-[11px]">{cfg.label}</span>
                    </div>
                  )
                })}
              </div>
            </div>
          )}

          {Object.entries(grouped).map(([type, items]) => {
            const cfg = TYPE_CONFIG[type]
            if (!cfg) return null
            const TypeIcon = cfg.icon
            return (
              <div key={type}>
                {/* Group header */}
                <div className="flex items-center gap-2 px-4 py-1.5 bg-falcon-raised/50
                                border-b border-falcon-border/50 sticky top-0">
                  <TypeIcon className="w-3 h-3 shrink-0" style={{ color: cfg.color }} />
                  <span className="text-[10px] font-bold text-falcon-muted uppercase tracking-widest">
                    {cfg.label}
                  </span>
                  <span className="text-[10px] text-falcon-subtle ml-auto font-mono">{items.length}</span>
                </div>
                {/* Items */}
                {items.map(r => {
                  const idx = flatIndex++
                  const isSelected = idx === selected
                  const sevColor = r.severity ? getSeverityColor(r.severity) : undefined
                  const ItemIcon = ((r.type === 'nav' || r.type === 'favorite') && navIconMap[r.id]) ? navIconMap[r.id] : TypeIcon
                  return (
                    <button
                      key={r.id}
                      onClick={() => navigate(r)}
                      onMouseEnter={() => setSelected(idx)}
                      className={`w-full flex items-center gap-3 px-4 py-3 text-left transition-colors
                                  border-b border-falcon-border/30 last:border-0 group ${
                        isSelected ? 'bg-falcon-active' : 'hover:bg-falcon-hover'
                      }`}
                    >
                      {/* Type icon */}
                      <ItemIcon className="w-4 h-4 shrink-0" style={{ color: cfg.color }} />

                      {/* Content */}
                      <div className="flex-1 min-w-0">
                        <p className="text-sm text-falcon-text truncate font-medium">{r.title}</p>
                        {r.subtitle && (
                          <p className="text-[11px] text-falcon-subtle truncate font-mono mt-0.5">{r.subtitle}</p>
                        )}
                      </div>

                      {/* Metadata */}
                      <div className="flex items-center gap-2 shrink-0">
                        {r.severity !== undefined && r.severity > 0 && sevColor && (
                          <span className="text-[10px] font-bold font-mono"
                                style={{ color: sevColor }}>
                            Lv{r.severity}
                          </span>
                        )}
                        {r.status && (
                          <span className="text-[10px] text-falcon-subtle bg-falcon-raised px-1.5 py-0.5 rounded-sm font-mono">
                            {r.status}
                          </span>
                        )}
                        <ArrowRight className={`w-3.5 h-3.5 transition-opacity text-falcon-subtle ${
                          isSelected ? 'opacity-100' : 'opacity-0 group-hover:opacity-100'
                        }`} />
                      </div>
                    </button>
                  )
                })}
              </div>
            )
          })}
        </div>

        {/* Footer */}
        {results.length > 0 && (
          <div className="flex items-center gap-4 px-4 py-2 border-t border-falcon-border
                          bg-falcon-raised/50 text-[10px] text-falcon-subtle">
            <span className="flex items-center gap-1">
              <kbd className="font-mono bg-falcon-border px-1 rounded-sm">↑↓</kbd> 移動
            </span>
            <span className="flex items-center gap-1">
              <kbd className="font-mono bg-falcon-border px-1 rounded-sm">↵</kbd> 開く
            </span>
            <span className="flex items-center gap-1">
              <kbd className="font-mono bg-falcon-border px-1 rounded-sm">Esc</kbd> 閉じる
            </span>
            <span className="ml-auto font-mono">{results.length} 件</span>
          </div>
        )}
      </div>
    </div>
  )
}
