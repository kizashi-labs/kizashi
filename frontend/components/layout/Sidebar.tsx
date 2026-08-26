'use client'

import React from 'react'
import NextLink from 'next/link'

import { isBackendPending } from '@/lib/backend-pending'
import { usePathname } from 'next/navigation'
import {
  LayoutDashboard, ShieldAlert, Monitor,
  BookOpen, BarChart3, Settings, Shield,
  Bell, Globe, User, Activity,
  Users, ClipboardList, Archive, Layers,
  Crosshair, AlertOctagon, Siren, ShieldOff, Workflow, CalendarClock,
  Target, Bug, Rss, Network, FolderOpen, Search, KeyRound,
  ShieldCheck, TrendingUp, TrendingDown, GitBranch, Download, Package, Tag, GitMerge, Crown, ShoppingBag, MessageSquare,
  ScanSearch, Radio, Terminal, Brain, Wifi,
  HardDrive, Cloud, Building2, Database, Usb, RefreshCw, Box, Code2,
  Map, HeartPulse, FileInput, Sliders, BellRing, Wrench, Server,
  FileCode, Webhook, HelpCircle, CheckCircle,
  Gauge, PackageCheck, MonitorSmartphone, Settings2, CheckSquare,
  SlidersHorizontal,
  FileSearch, Lock, Boxes, Ticket,
  LayoutTemplate, Timer,
  FlaskConical, Waves, Mail, Key,
  Eye, EyeOff, ClipboardCheck, UserX, ScanLine,
  GraduationCap, CalendarRange, PenTool, CalendarDays,
  Star, BarChart2, Send, AppWindow,
  BellDot, ServerCog, Flag, Tags,
  RadioTower, MailOpen,
  UserCheck, BookmarkCheck, FileBarChart,
  DollarSign, ArrowUpCircle, Scale,
  Award, Bot,
  Share2, Cpu, Zap,
  Flame, Video, Calculator,
  GitFork, Fish,
  NotebookPen, BookMarked,
  Radar, CloudLightning, Code,
  Printer, PlayCircle, Briefcase,
  Fingerprint,
  PieChart,
  Megaphone,
  Link as LinkIcon,
  FileCog,
  ChevronLeft,
  CreditCard,
  Inbox,
  X,
} from 'lucide-react'
import { useAuth } from '@/lib/auth'
import { useQuery } from '@tanstack/react-query'
import { apiFetch } from '@/lib/api'
import { TenantSwitcher } from './TenantSwitcher'
import { useState, useCallback, useEffect, useMemo } from 'react'
import { usePlan } from '@/lib/usePlan'
import { useFavorites } from '@/lib/useFavorites'

type NavItem = { href: string; label: string; icon: React.ElementType; feature?: string }
type NavGroup = { label: string; icon?: React.ElementType; items: NavItem[] }

// ── Navigation Groups ──────────────────────────────────────────

const navGroups: NavGroup[] = [
  {
    label: 'エグゼクティブ',
    icon: Star,
    items: [
    ],
  },
  {
    label: '概要',
    icon: LayoutDashboard,
    items: [
      { href: '/dashboard',  label: 'ダッシュボード', icon: LayoutDashboard },
    ],
  },
  {
    label: '検知',
    icon: ShieldAlert,
    items: [
      { href: '/alerts',         label: 'アラート',       icon: ShieldAlert },
    ],
  },
  {
    label: 'エンドポイント',
    icon: Monitor,
    items: [
      { href: '/endpoints',      label: 'エンドポイント',   icon: Monitor },
      { href: '/events',         label: 'イベントログ',     icon: Activity },
      { href: '/agents/deploy',    label: 'エージェント配布', icon: Download },
    ],
  },
  {
    label: 'インテリジェンス',
    icon: Brain,
    items: [
    ],
  },
  {
    label: '監視',
    icon: Radar,
    items: [
    ],
  },
  {
    label: '対応',
    icon: Siren,
    items: [
    ],
  },
  {
    label: 'アセット',
    icon: Package,
    items: [
    ],
  },
  {
    label: '計画',
    icon: PenTool,
    items: [
    ],
  },
  {
    label: 'ナレッジ',
    icon: BookOpen,
    items: [
    ],
  },
  {
    label: '分析',
    icon: BarChart3,
    items: [
    ],
  },
]

// ── Admin nav grouped into accordion sections ──────────────────

const adminNavGroups: NavGroup[] = [
  {
    label: 'コア',
    icon: LayoutDashboard,
    items: [
    ],
  },
  {
    label: '検知',
    icon: ShieldAlert,
    items: [
    ],
  },
  {
    label: 'ハンティング & 調査',
    icon: Crosshair,
    items: [
    ],
  },
  {
    label: '対応',
    icon: Siren,
    items: [
    ],
  },
  {
    label: '脅威インテリジェンス',
    icon: Brain,
    items: [
    ],
  },
  {
    label: 'セキュリティ運用',
    icon: Shield,
    items: [
    ],
  },
  {
    label: '統合',
    icon: Radio,
    items: [
    ],
  },
  {
    label: '管理 & 設定',
    icon: Settings,
    items: [
    ],
  },
  {
    label: 'レポート & コンプライアンス',
    icon: BarChart3,
    items: [
    ],
  },
  {
    label: 'システム',
    icon: Server,
    items: [
    ],
  },
  {
    label: 'セキュリティツール',
    icon: Target,
    items: [
    ],
  },
  {
    label: 'クラウド & インフラ',
    icon: Cloud,
    items: [
    ],
  },
  {
    label: '人材 & トレーニング',
    icon: GraduationCap,
    items: [
    ],
  },
  {
    label: 'ID & アクセス',
    icon: KeyRound,
    items: [
    ],
  },
  {
    label: '分析 & インサイト',
    icon: BarChart2,
    items: [
    ],
  },
  {
    label: 'ガバナンス & リスク',
    icon: Scale,
    items: [
    ],
  },
  {
    label: '自動化',
    icon: Zap,
    items: [
    ],
  },
  {
    label: 'インストーラー & 展開',
    icon: Download,
    items: [
    ],
  },
]

const bottomNav = [
  { href: '/faq',                     label: 'よくある質問',       icon: HelpCircle },
  { href: '/settings',                label: '設定',               icon: Settings },
  { href: '/profile',                 label: 'プロフィール',       icon: User },
  { href: '/help',                    label: 'ヘルプ',             icon: HelpCircle },
]

// ── Component ─────────────────────────────────────────────────

export function Sidebar({ onSearchOpen }: { onSearchOpen?: () => void }) {
  const pathname = usePathname()
  const { user } = useAuth()
  const isAdmin = user?.role === 'admin'
  const { hasFeature } = usePlan()

  const { data: alertStats } = useQuery<{ open: number }>({
    queryKey: ['alert-stats-sidebar'],
    queryFn: () => apiFetch('/api/v1/alerts/stats'),
    refetchInterval: 30_000,
    staleTime: 20_000,
  })

  const { data: incidentStats } = useQuery<{ total: number }>({
    queryKey: ['incident-stats-sidebar'],
    queryFn: () => apiFetch('/api/v1/incidents?status=active&per_page=1'),
    refetchInterval: 60_000,
    staleTime: 30_000,
  })

  const { data: notifUnread } = useQuery<{ count: number; urgent_alerts: number; new_incidents: number }>({
    queryKey: ['notif-unread-sidebar'],
    queryFn: () => apiFetch('/api/v1/notifications/unread'),
    refetchInterval: 60_000,
    staleTime: 30_000,
    retry: false,
  })

  const openAlertCount = alertStats?.open ?? 0
  const openIncidentCount = incidentStats?.total ?? 0
  const unreadCount = notifUnread?.count ?? 0

  // hrefs that carry a red (critical) badge when their count > 0
  // 先頭スラッシュ無しで持つ — 公開版生成の trim-frontend はクォート内の
  // 「/route」形の行しか消さないので、この書き方なら定義行が巻き添えにならない
  const ALERT_RED_HREFS   = ['alerts', 'admin/alerts'].map(p => '/' + p)
  const ALERT_ORANGE_HREFS = ['alerts/triage'].map(p => '/' + p)
  const INCIDENT_RED_HREFS    = ['incidents/war-room'].map(p => '/' + p)
  const INCIDENT_ORANGE_HREFS = ['incidents', 'admin/incidents'].map(p => '/' + p)

  // Returns badge color class for a sub-pane item, or null if none needed.
  const itemBadgeColor = useCallback((href: string): string | null => {
    if (openAlertCount > 0) {
      if (ALERT_RED_HREFS.includes(href))    return 'bg-[#e8002d] critical-pulse'
      if (ALERT_ORANGE_HREFS.includes(href)) return 'bg-orange-500'
    }
    if (openIncidentCount > 0) {
      if (INCIDENT_RED_HREFS.includes(href))    return 'bg-[#e8002d] critical-pulse'
      if (INCIDENT_ORANGE_HREFS.includes(href)) return 'bg-orange-500'
    }
    return null
  }, [openAlertCount, openIncidentCount]) // eslint-disable-line react-hooks/exhaustive-deps

  // Returns the count number to display on a sub-pane item badge.
  const itemBadgeCount = useCallback((href: string): number => {
    if (openAlertCount > 0) {
      if (ALERT_RED_HREFS.includes(href) || ALERT_ORANGE_HREFS.includes(href)) return openAlertCount
    }
    if (openIncidentCount > 0) {
      if (INCIDENT_RED_HREFS.includes(href) || INCIDENT_ORANGE_HREFS.includes(href)) return openIncidentCount
    }
    return 0
  }, [openAlertCount, openIncidentCount]) // eslint-disable-line react-hooks/exhaustive-deps

  // Returns true when the group should show an alert (red) badge.
  const groupAlertBadge = useCallback((group: NavGroup): boolean =>
    openAlertCount > 0 && group.items.some(i => [...ALERT_RED_HREFS, ...ALERT_ORANGE_HREFS].includes(i.href))
  , [openAlertCount]) // eslint-disable-line react-hooks/exhaustive-deps

  // Returns true when the group should show an incident (orange) badge.
  const groupIncidentBadge = useCallback((group: NavGroup): boolean =>
    openIncidentCount > 0 && group.items.some(i => [...INCIDENT_RED_HREFS, ...INCIDENT_ORANGE_HREFS].includes(i.href))
  , [openIncidentCount]) // eslint-disable-line react-hooks/exhaustive-deps

  const allGroups = useMemo(
    () => [...navGroups, ...(isAdmin ? adminNavGroups : [])],
    [isAdmin],
  )

  const allNavHrefs = useMemo(
    () => allGroups.flatMap(g => g.items.map(i => i.href)),
    [allGroups],
  )

  const isActive = useCallback((href: string) => {
    if (pathname === href) return true
    if (href === '/dashboard') return false
    if (!pathname.startsWith(href + '/')) return false
    return !allNavHrefs.some(
      other => other !== href && other.startsWith(href + '/') && pathname.startsWith(other)
    )
  }, [pathname, allNavHrefs])

  // Several adminNavGroups entries share a label with a navGroups entry (e.g.
  // both have '検知'). openGroup/subPaneGroup used to be keyed on the bare
  // label, so opening an admin group whose label collides with a regular one
  // resolved to the regular group's items instead (allGroups.find() returns
  // the first match, and navGroups is spread before adminNavGroups) — the
  // admin subpane silently showed the wrong content. Admin groups now get a
  // distinct 'admin:' -prefixed key for open/lookup purposes while the
  // displayed label is untouched.
  const groupKey = (label: string, admin: boolean) => (admin ? `admin:${label}` : label)

  const findActiveGroupLabel = useCallback(() => {
    const navMatch = navGroups.find(g => g.items.some(i => isActive(i.href)))
    if (navMatch) return navMatch.label
    if (isAdmin) {
      const adminMatch = adminNavGroups.find(g => g.items.some(i => isActive(i.href)))
      if (adminMatch) return groupKey(adminMatch.label, true)
    }
    return null
  }, [isAdmin, isActive])

  const [openGroup, setOpenGroup] = useState<string | null>(() => findActiveGroupLabel())

  useEffect(() => {
    const g = findActiveGroupLabel()
    if (g) setOpenGroup(g)
  }, [pathname]) // eslint-disable-line react-hooks/exhaustive-deps

  const subPaneGroup = openGroup?.startsWith('admin:')
    ? adminNavGroups.find(g => g.label === openGroup!.slice('admin:'.length)) ?? null
    : navGroups.find(g => g.label === openGroup) ?? null

  const { favorites, isFavorite, toggleFavorite, removeFavorite } = useFavorites()

  const toggleGroup = (label: string) =>
    setOpenGroup(prev => (prev === label ? null : label))

  // Whether the *currently open* subpane is the admin instance of a group.
  // Must be derived from the openGroup key (not from a label lookup against
  // adminNavGroups) for the same reason subPaneGroup is: regular and admin
  // groups frequently share a label (e.g. both have '検知'), so a label-only
  // check would also match when the regular, non-admin subpane is open.
  const openGroupIsAdmin = openGroup?.startsWith('admin:') ?? false

  return (
    <aside
      className={`h-full shrink-0 flex bg-falcon-gradient border-r border-[#1e2d42] overflow-hidden transition-all duration-200 ${
        openGroup ? 'w-[260px]' : 'w-[52px]'
      }`}
    >
      {/* ── Icon Rail ───────────────────────────────────────────── */}
      <div className="w-[52px] shrink-0 grid grid-rows-[auto_auto_1fr_auto] h-screen border-r border-[#1e2d42]">

        {/* Logo */}
        <div className="flex items-center justify-center h-[54px] border-b border-[#1e2d42] shrink-0">
          <div className="relative" title="Kizashi">
            <div className="w-8 h-8 rounded-sm flex items-center justify-center bg-linear-to-br from-[#e8002d] to-[#a80020] shadow-falcon-glow-red">
              <Shield className="w-4 h-4 text-white" strokeWidth={2.5} />
            </div>
            <span className="absolute -bottom-0.5 -right-0.5 w-2 h-2 bg-[#00c853] rounded-full border border-[#0d1220]" />
          </div>
        </div>

        {/* Search */}
        <div className="px-2 py-2 border-b border-[#1e2d42] shrink-0">
          <button
            onClick={onSearchOpen}
            title="検索 (Ctrl+K)"
            className="w-full flex items-center justify-center p-2 rounded-sm bg-[#0d1220] border border-[#1e2d42] text-[#7d92b0] hover:text-[#e2e8f4] hover:border-[#7d92b0]/40 transition-all"
          >
            <Search className="w-3.5 h-3.5" />
          </button>
        </div>

        {/* Nav group icons */}
        <nav className="overflow-y-auto min-h-0 px-2 py-2 space-y-0.5 scrollbar-thin">
          {navGroups.map(group => {
            const GroupIcon = group.icon!
            const hasActive = group.items.some(i => isActive(i.href))
            const isOpen = openGroup === group.label
            const alertBadge    = groupAlertBadge(group)
            const incidentBadge = groupIncidentBadge(group)
            return (
              <button
                key={group.label}
                onClick={() => toggleGroup(group.label)}
                title={
                  alertBadge    ? `${group.label}（未対応アラート ${openAlertCount} 件）` :
                  incidentBadge ? `${group.label}（未処理インシデント ${openIncidentCount} 件）` :
                  group.label
                }
                className={`relative w-full p-2.5 rounded-sm flex items-center justify-center transition-colors ${
                  isOpen
                    ? 'bg-[#1d2f4a]'
                    : hasActive
                      ? 'bg-[#19253d]'
                      : 'text-[#3d5068] hover:bg-[#19253d] hover:text-[#7d92b0]'
                }`}
              >
                {(hasActive || isOpen) && (
                  <span className="absolute left-0 top-1 bottom-1 w-0.5 rounded-r bg-[#e8002d]" />
                )}
                <GroupIcon className={`w-4 h-4 ${hasActive || isOpen ? 'text-[#e8002d]' : ''}`} />
                {(alertBadge || incidentBadge) && (
                  <span className={`absolute top-0.5 right-0.5 w-2 h-2 rounded-full ${alertBadge ? 'bg-[#e8002d] critical-pulse' : 'bg-orange-500'}`} />
                )}
              </button>
            )
          })}

          {/* Admin group icons */}
          {isAdmin && (
            <>
              <div className="border-t border-[#1e2d42] my-1.5" />
              {adminNavGroups.map(group => {
                const GroupIcon = group.icon!
                const hasActive = group.items.some(i => isActive(i.href))
                const isOpen = openGroup === groupKey(group.label, true)
                const alertBadge    = groupAlertBadge(group)
                const incidentBadge = groupIncidentBadge(group)
                return (
                  <button
                    key={`admin:${group.label}`}
                    onClick={() => toggleGroup(groupKey(group.label, true))}
                    title={
                      alertBadge    ? `[管理] ${group.label}（未対応アラート ${openAlertCount} 件）` :
                      incidentBadge ? `[管理] ${group.label}（未対応インシデント ${openIncidentCount} 件）` :
                      `[管理] ${group.label}`
                    }
                    className={`relative w-full p-2.5 rounded-sm flex items-center justify-center transition-colors ${
                      isOpen
                        ? 'bg-[#1d2f4a]'
                        : hasActive
                          ? 'bg-[#19253d]'
                          : 'text-[#3d5068] hover:bg-[#19253d] hover:text-[#7d92b0]'
                    }`}
                  >
                    {(hasActive || isOpen) && (
                      <span className="absolute left-0 top-1 bottom-1 w-0.5 rounded-r bg-[#e8002d]" />
                    )}
                    <GroupIcon className={`w-4 h-4 ${hasActive || isOpen ? 'text-[#e8002d]' : ''}`} />
                    {(alertBadge || incidentBadge) && (
                      <span className={`absolute top-0.5 right-0.5 w-2 h-2 rounded-full ${alertBadge ? 'bg-[#e8002d] critical-pulse' : 'bg-orange-500'}`} />
                    )}
                  </button>
                )
              })}
            </>
          )}
        </nav>

        {/* Bottom: settings + language switcher */}
        <div className="border-t border-[#1e2d42] px-2 py-2 space-y-0.5 shrink-0">
          {bottomNav.map(({ href, label, icon: Icon }) => {
            const active = isActive(href)
            // href.slice(1) 比較なのは trim-frontend 対策 — 上の HREFS 定数のコメント参照
            const showBadge = href.slice(1) === 'notifications' && unreadCount > 0
            return (
              <NextLink
                key={href}
                href={href}
                title={showBadge ? `${label}（未読 ${unreadCount}件）` : label}
                className={`relative flex items-center justify-center p-2 rounded-sm transition-all ${
                  active
                    ? 'bg-[#1d2f4a] text-[#e8002d]'
                    : 'text-[#3d5068] hover:bg-[#19253d] hover:text-[#7d92b0]'
                }`}
              >
                <Icon className="w-4 h-4" />
                {showBadge && (
                  <span className="absolute top-0.5 right-0.5 min-w-[14px] h-[14px] px-0.5 bg-[#e8002d] rounded-full text-white text-[9px] font-bold flex items-center justify-center leading-none">
                    {unreadCount > 99 ? '99+' : unreadCount}
                  </span>
                )}
              </NextLink>
            )
          })}
        </div>
      </div>

      {/* ── Sub-pane ────────────────────────────────────────────── */}
      {subPaneGroup && (() => {
        const SubIcon = subPaneGroup.icon!
        return (
        <div className="flex-1 flex flex-col overflow-hidden min-w-0">

          {/* Sub-pane header */}
          <div className="flex flex-col justify-center px-3 h-[54px] border-b border-[#1e2d42] shrink-0 gap-0.5">
            <span className="text-[9px] font-bold tracking-widest text-[#3d5068]">
              Kizashi<span className="text-[#e8002d]">EDR</span>
            </span>
            <div className="flex items-center gap-2">
              <SubIcon className="w-3.5 h-3.5 text-[#e8002d] shrink-0" />
              <span className={`text-[11px] font-bold uppercase tracking-wider flex-1 truncate ${
                openGroupIsAdmin ? 'text-[#e8002d]/70' : 'text-[#7d92b0]'
              }`}>
                {subPaneGroup.label}
              </span>
              <button
                onClick={() => setOpenGroup(null)}
                title="閉じる"
                className="p-1 rounded-sm text-[#3d5068] hover:text-[#7d92b0] hover:bg-[#19253d] transition-colors shrink-0"
              >
                <ChevronLeft className="w-3.5 h-3.5" />
              </button>
            </div>
          </div>

          {/* Tenant switcher — only for admin groups */}
          {isAdmin && openGroupIsAdmin && <TenantSwitcher />}

          {/* Items */}
          <div className="flex-1 overflow-y-auto px-2 py-2 space-y-0.5 scrollbar-thin">
            {/* お気に入りセクション */}
            {favorites.length > 0 && (
              <div className="mb-2">
                <div className="flex items-center gap-1.5 px-2 py-1">
                  <Star className="w-3 h-3 text-yellow-400 fill-yellow-400 shrink-0" />
                  <span className="text-[9px] font-bold tracking-widest text-[#3d5068] uppercase">お気に入り</span>
                </div>
                {favorites.map(fav => {
                  const active = isActive(fav.href)
                  return (
                    <div key={fav.href} className="group/favitem relative flex items-center">
                      <NextLink
                        href={fav.href}
                        className={`flex-1 flex items-center gap-2 px-2.5 py-[6px] rounded-sm text-[12px] transition-all duration-100 pr-7
                                    ${active ? 'bg-[#1d2f4a] text-white' : 'text-[#7d92b0] hover:bg-[#19253d] hover:text-[#e2e8f4]'}`}
                      >
                        {active && <span className="absolute left-0 top-1 bottom-1 w-0.5 rounded-r bg-[#e8002d]" />}
                        <Star className="w-3.5 h-3.5 text-yellow-400 fill-yellow-400 shrink-0" />
                        <span className="flex-1 font-medium truncate">{fav.label}</span>
                      </NextLink>
                      <button
                        onClick={(e) => { e.preventDefault(); e.stopPropagation(); removeFavorite(fav.href) }}
                        title="お気に入りから削除"
                        className="absolute right-1 z-10 p-1 rounded-sm opacity-0 group-hover/favitem:opacity-100 text-[#3d5068] hover:text-[#7d92b0] transition-opacity"
                      >
                        <X className="w-3 h-3" />
                      </button>
                    </div>
                  )
                })}
                <div className="my-1.5 border-t border-[#1e2d42]/60" />
              </div>
            )}

            {subPaneGroup.items.map(({ href, label: itemLabel, icon: Icon, feature }) => {
              const active = isActive(href)
              const locked = !!feature && !(hasFeature as (f: string) => boolean)(feature)
              // **サイドバーに 60 の「準備中」が、動く 232 と同じ顔で
              // 並んでいました**（実測 2026-08-12）。開いて初めて分かる
              // ので、担当者は開いて、戻って、また別のを開きます。
              // 一覧は `lib/backend-pending` にあり、バナーと同じものを
              // 読みます —— 写しを持つと片方だけ増えます。
              const pending = isBackendPending(href)
              const badgeColor = itemBadgeColor(href)
              const badgeCount = badgeColor ? itemBadgeCount(href) : 0
              const starred = isFavorite(href)
              return (
                <div key={href} className="group/navitem relative flex items-center">
                  <NextLink
                    href={href}
                    title={
                      locked
                        ? `${itemLabel}（上位プランが必要です）`
                        : pending
                          ? `${itemLabel}（バックエンド準備中です）`
                          : itemLabel
                    }
                    className={`relative flex-1 flex items-center gap-2 px-2.5 py-[6px] rounded-sm text-[12px]
                                transition-all duration-100 pr-7
                                ${active
                                  ? 'bg-[#1d2f4a] text-white'
                                  : locked
                                    ? 'text-[#3d5068] hover:bg-[#19253d]/50 hover:text-[#5a7090]'
                                    : 'text-[#7d92b0] hover:bg-[#19253d] hover:text-[#e2e8f4]'
                                }`}
                  >
                    {/* アクティブページの左ボーダー（赤） */}
                    {active && (
                      <span className="absolute left-0 top-1 bottom-1 w-0.5 rounded-r bg-[#e8002d]" />
                    )}
                    {/* 未対応件数があるページの左ボーダー（色付き・太め） */}
                    {!active && badgeColor && badgeCount > 0 && (
                      <span className={`absolute left-0 top-0.5 bottom-0.5 w-1 rounded-r ${badgeColor.includes('orange') ? 'bg-orange-500' : 'bg-[#e8002d]'}`} />
                    )}
                    <span className="shrink-0">
                      <Icon className={`w-3.5 h-3.5 ${
                        active ? 'text-[#e8002d]' : badgeColor && badgeCount > 0 ? (badgeColor.includes('orange') ? 'text-orange-400' : 'text-[#e8002d]') : 'text-[#3d5068] group-hover/navitem:text-[#7d92b0]'
                      }`} />
                    </span>
                    <span className="flex-1 font-medium truncate">{itemLabel}</span>
                    {/* 未対応件数バッジ（ラベル右側に表示） */}
                    {!active && badgeColor && badgeCount > 0 && (
                      <span className={`shrink-0 text-[9px] font-bold px-1.5 py-0.5 rounded-sm mr-6
                                        text-white ${badgeColor.includes('orange') ? 'bg-orange-500' : 'bg-[#e8002d]'}`}>
                        {badgeCount > 99 ? '99+' : badgeCount}件
                      </span>
                    )}
                    {locked && <Lock className="w-3 h-3 text-[#3d5068] shrink-0" />}
                    {!locked && pending && (
                      <span
                        className="shrink-0 text-[9px] font-medium px-1 py-0.5 rounded-sm mr-6 border border-amber-500/40 text-amber-400/90"
                      >
                        準備中
                      </span>
                    )}
                  </NextLink>
                  {!locked && (
                    <button
                      onClick={(e) => { e.preventDefault(); e.stopPropagation(); toggleFavorite(href, itemLabel) }}
                      title={starred ? 'お気に入りから削除' : 'お気に入りに追加'}
                      className={`absolute right-1 z-10 p-1 rounded-sm transition-all ${
                        starred
                          ? 'opacity-100 text-yellow-400'
                          : 'opacity-0 group-hover/navitem:opacity-100 text-[#3d5068] hover:text-yellow-400'
                      }`}
                    >
                      <Star className={`w-3 h-3 ${starred ? 'fill-yellow-400' : ''}`} />
                    </button>
                  )}
                </div>
              )
            })}
          </div>

          {/* User info strip at bottom of sub-pane */}
          {user && (
            <div className="border-t border-[#1e2d42] px-3 py-2 flex items-center gap-2 shrink-0">
              <div className="w-6 h-6 rounded-full bg-linear-to-br from-[#1a6bff] to-[#0044cc] flex items-center justify-center shrink-0">
                <span className="text-[9px] font-bold text-white uppercase">
                  {(user.full_name || user.email || user.id)?.[0]?.toUpperCase() ?? 'U'}
                </span>
              </div>
              <div className="min-w-0 flex-1">
                <p className="text-[11px] text-[#e2e8f4] font-medium truncate">{user.full_name || user.email || user.id}</p>
                <p className="text-[9px] text-[#3d5068] uppercase tracking-wide">
                  {user.role}
                  {user.role === 'viewer' && (
                    <span className="ml-1 text-[8px] px-1 py-px rounded-sm bg-[#1a1a2e] text-[#7c7cff] border border-[#2d2d5e] normal-case tracking-normal">閲覧専用</span>
                  )}
                </p>
              </div>
            </div>
          )}
        </div>
        )
      })()}
    </aside>
  )
}
