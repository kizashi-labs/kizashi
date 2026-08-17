'use client'

import React, { useEffect, useState, useCallback } from 'react'
import { usePathname, useRouter } from 'next/navigation'
import { useAuth } from '@/lib/auth'
import { Sidebar } from './Sidebar'
import { CommandPalette } from '@/components/search/CommandPalette'
import { AlertToastContainer } from '@/components/notifications/AlertToast'
import { CloudAlertToastContainer } from '@/components/notifications/CloudAlertToast'
import { RealtimeBanner } from '@/components/notifications/RealtimeBanner'
import { NotificationCenter } from '@/components/notifications/NotificationCenter'
import { UpgradeBanner } from '@/components/notifications/UpgradeBanner'
import { OnboardingWizard } from '@/components/onboarding/OnboardingWizard'
import { Shield, ChevronRight, Search, LogOut, Eye } from 'lucide-react'
import { MobileBottomNav } from './MobileNav'
import { useQuery } from '@tanstack/react-query'

// ── Breadcrumb map ─────────────────────────────────────────────
const BREADCRUMB: Record<string, string[]> = {
  '/dashboard':        ['Overview', 'ダッシュボード'],
  '/alerts':           ['Detection', 'アラート'],
  '/incidents':        ['Detection', 'インシデント'],
  '/incidents/':       ['Detection', 'インシデント詳細'],
  '/rules':            ['Detection', '検知ルール'],
  '/suppressions':     ['Detection', 'アラート抑制'],
  '/endpoints':        ['Endpoints', 'エンドポイント'],
  '/groups':           ['Endpoints', 'グループ管理'],
  '/groups/':          ['Endpoints', 'グループポリシー'],
  '/events':           ['Endpoints', 'イベントログ'],
  '/quarantine':       ['Endpoints', '検疫ファイル'],
  '/software':         ['Endpoints', 'ソフトウェア管理'],
  '/agents/deploy':    ['Endpoints', 'エージェント配布'],
  '/threat-intel':     ['Intelligence', '脅威インテリジェンス'],
  '/ioc':              ['Intelligence', 'IOC管理'],
  '/campaigns':        ['Intelligence', '脅威キャンペーン'],
  '/mitre':            ['Intelligence', 'MITRE ATT&CK'],
  '/threat-hunting':   ['Intelligence', 'スレットハンティング'],
  '/intel':            ['Intelligence', 'インテリジェンスハブ'],
  '/intel/vt':         ['Intelligence', 'VirusTotal検索'],
  '/settings/siem':    ['Administration', 'SIEM連携'],
  '/live-response':    ['Endpoints', 'ライブレスポンス'],
  '/network':          ['Monitoring', 'ネットワーク分析'],
  '/dns':              ['Monitoring', 'DNS監視'],
  '/dns-security':     ['Monitoring', 'DNSセキュリティ'],
  '/email-security':   ['Monitoring', 'メールセキュリティ'],
  '/cloud-security':   ['Monitoring', 'クラウドCSPM'],
  '/fim':              ['Monitoring', 'ファイル変更監視'],
  '/auth-events':      ['Monitoring', '認証イベント'],
  '/ueba':             ['Monitoring', '行動分析'],
  '/playbooks':        ['Response', 'プレイブック'],
  '/vulnerabilities':  ['Response', '脆弱性管理'],
  '/vulnerabilities/': ['Response', '脆弱性詳細'],
  '/compliance':       ['Response', 'コンプライアンス'],
  '/reports':          ['Analytics', 'レポート'],
  '/reports/schedules': ['Analytics', 'スケジュールレポート'],
  '/soc-metrics':      ['Analytics', 'SOCメトリクス'],
  '/notifications':    ['Settings', '通知設定'],
  '/settings':         ['Settings', '設定'],
  '/profile':          ['Account', 'プロフィール'],
  '/admin/users':      ['Administration', 'ユーザー管理'],
  '/admin/audit':      ['Administration', '監査ログ'],
  '/api-docs':              ['Administration', 'API ドキュメント'],
  '/admin/compliance':      ['Administration', 'コンプライアンス管理'],
}

// ── Top Bar ────────────────────────────────────────────────────
interface AuthUser { id: string; email: string; full_name: string; role: string }

function TopBar({ onSearchOpen, user, logout }: {
  onSearchOpen: () => void
  user: AuthUser | null
  logout: () => void
}) {
  const pathname = usePathname()
  const [now, setNow] = useState('')
  const [showUserMenu, setShowUserMenu] = useState(false)

  const { data: healthData } = useQuery<{ status: string; db?: string }>({
    queryKey: ['system-health'],
    queryFn: async () => {
      const res = await fetch('/health')
      return res.json()
    },
    refetchInterval: 60_000,
    staleTime: 30_000,
    retry: false,
  })
  const systemOk = !healthData || healthData.status === 'ok'

  // Live clock
  useEffect(() => {
    const tick = () => {
      setNow(new Date().toLocaleTimeString('ja-JP', {
        hour: '2-digit', minute: '2-digit', second: '2-digit',
        timeZoneName: 'short',
      }))
    }
    tick()
    const id = setInterval(tick, 1000)
    return () => clearInterval(id)
  }, [])

  // Find breadcrumb for current path
  const crumb = (() => {
    // Exact match first
    if (BREADCRUMB[pathname]) return BREADCRUMB[pathname]
    // Prefix match
    const key = Object.keys(BREADCRUMB)
      .filter(k => pathname.startsWith(k + '/'))
      .sort((a, b) => b.length - a.length)[0]
    return key ? BREADCRUMB[key] : ['', '']
  })()

  return (
    <header className="topbar-blur sticky top-0 z-40 flex items-center gap-4 px-5 h-11 border-b border-falcon-border">
      {/* Product name — always visible */}
      <div className="flex items-center gap-2 shrink-0 border-r border-falcon-border pr-4 mr-1">
        <div className="w-5 h-5 rounded-sm flex items-center justify-center bg-linear-to-br from-falcon-red to-falcon-red-dark">
          <Shield className="w-3 h-3 text-white" strokeWidth={2.5} />
        </div>
        <span className="text-[11px] font-bold tracking-widest text-[#c8d6e8] hidden sm:block">
          Kizashi<span className="text-falcon-red ml-0.5">EDR</span>
        </span>
      </div>

      {/* Breadcrumb */}
      <div className="flex items-center gap-1.5 text-xs flex-1 min-w-0">
        {crumb[0] && (
          <>
            <span className="text-falcon-subtle font-medium tracking-wide uppercase text-[10px]">{crumb[0]}</span>
            <ChevronRight className="w-3 h-3 text-falcon-subtle" />
          </>
        )}
        <span className="text-falcon-muted font-medium truncate">{crumb[1]}</span>
        {/* Dynamic sub-path (for detail pages) */}
        {pathname.split('/').length > 2 && pathname.split('/')[2] && !pathname.startsWith('/admin') && !pathname.startsWith('/reports/schedules') && !pathname.startsWith('/agents/deploy') && (
          <>
            <ChevronRight className="w-3 h-3 text-falcon-subtle" />
            <span className="text-falcon-text font-mono text-[10px]">
              {pathname.split('/')[2].slice(0, 8)}…
            </span>
          </>
        )}
      </div>

      {/* Right side controls */}
      <div className="flex items-center gap-3">
        {/* Live time */}
        <div className="hidden lg:flex items-center gap-2 px-3 py-1 rounded-md bg-falcon-surface border border-falcon-border">
          <span className="w-1.5 h-1.5 rounded-full bg-falcon-green animate-pulse shrink-0" />
          <span className="text-[#c8d6e8] font-mono text-xs tracking-wide tabular-nums">
            {now}
          </span>
        </div>

        {/* Search bar button */}
        <button
          onClick={onSearchOpen}
          className="hidden md:flex items-center gap-2 px-3 py-1 rounded
                     bg-falcon-surface border border-falcon-border text-falcon-subtle
                     hover:border-falcon-subtle hover:text-falcon-muted
                     transition-all duration-150 text-xs"
        >
          <Search className="w-3 h-3 shrink-0" />
          <span>Search...</span>
          <kbd className="ml-1 inline-flex items-center gap-0.5 px-1 py-0.5
                          bg-falcon-raised border border-falcon-border rounded text-[9px] font-mono">
            ⌘K
          </kbd>
        </button>

        {/* Notification Center */}
        <NotificationCenter />

        {/* Divider */}
        <div className="w-px h-4 bg-falcon-border" />

        {/* System status indicator */}
        <div className="hidden sm:flex items-center gap-1.5">
          <span className={`w-1.5 h-1.5 rounded-full ${systemOk ? 'bg-falcon-green' : 'bg-falcon-amber animate-pulse'}`} />
          <span className={`text-[10px] uppercase tracking-wider font-medium ${systemOk ? 'text-falcon-subtle' : 'text-falcon-amber'}`}>
            {systemOk ? 'SYSTEM OK' : 'DEGRADED'}
          </span>
        </div>

        {/* Divider */}
        <div className="w-px h-4 bg-falcon-border" />

        {/* User avatar + logout dropdown */}
        <div className="relative">
          <button
            onClick={() => setShowUserMenu(v => !v)}
            title={user?.full_name || user?.email || 'ユーザーメニュー'}
            className="w-7 h-7 rounded-full bg-linear-to-br from-falcon-blue to-[#0044cc] flex items-center justify-center hover:ring-2 hover:ring-falcon-blue/60 transition-all"
          >
            <span className="text-[10px] font-bold text-white uppercase">
              {(user?.full_name || user?.email || user?.id)?.[0]?.toUpperCase() ?? 'U'}
            </span>
          </button>
          {showUserMenu && (
            <>
              {/* Backdrop */}
              <div className="fixed inset-0 z-40" onClick={() => setShowUserMenu(false)} />
              <div className="absolute right-0 top-9 w-52 bg-[#111c2d] border border-falcon-border rounded-lg shadow-xl z-50 overflow-hidden">
                {user && (
                  <div className="px-3 py-2.5 border-b border-falcon-border">
                    <p className="text-[12px] font-semibold text-[#c8d6e8] truncate">{user.full_name || user.email}</p>
                    <p className="text-[10px] text-[#4a6080] truncate capitalize">{user.role}</p>
                  </div>
                )}
                <button
                  onClick={() => { setShowUserMenu(false); logout() }}
                  className="w-full flex items-center gap-2 px-3 py-2.5 text-[12px] text-falcon-red hover:bg-falcon-hover transition-colors"
                >
                  <LogOut className="w-3.5 h-3.5" />
                  ログアウト
                </button>
              </div>
            </>
          )}
        </div>
      </div>
    </header>
  )
}

// ── AppShell ───────────────────────────────────────────────────

export function AppShell({ children }: { children: React.ReactNode }) {
  const { token, isLoading, user, logout } = useAuth()
  const pathname = usePathname()
  const router = useRouter()
  const isLoginPage = pathname === '/login' || pathname === '/change-password' || pathname === '/landing' || pathname.startsWith('/auth/')
  const [searchOpen, setSearchOpen] = useState(false)

  const handleKeyDown = useCallback((e: KeyboardEvent) => {
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
      e.preventDefault()
      setSearchOpen(s => !s)
    }
  }, [])

  useEffect(() => {
    window.addEventListener('keydown', handleKeyDown)
    return () => window.removeEventListener('keydown', handleKeyDown)
  }, [handleKeyDown])

  useEffect(() => {
    if (!isLoading && !token && !isLoginPage) {
      router.replace('/login')
    }
  }, [isLoading, token, isLoginPage, router])

  // change-password page renders its own layout
  if (pathname === '/change-password') {
    return <>{children}</>
  }

  if (isLoginPage) {
    return <>{children}</>
  }

  if (isLoading || !token) {
    return (
      <div className="flex h-screen-safe items-center justify-center bg-falcon-bg">
        <div className="flex flex-col items-center gap-4">
          <div className="w-10 h-10 rounded-sm flex items-center justify-center bg-linear-to-br from-falcon-red to-falcon-red-dark">
            <Shield className="w-5 h-5 text-white" />
          </div>
          <div className="flex items-center gap-2">
            <div className="w-1.5 h-1.5 rounded-full bg-falcon-red animate-bounce" style={{ animationDelay: '0ms' }} />
            <div className="w-1.5 h-1.5 rounded-full bg-falcon-red animate-bounce" style={{ animationDelay: '150ms' }} />
            <div className="w-1.5 h-1.5 rounded-full bg-falcon-red animate-bounce" style={{ animationDelay: '300ms' }} />
          </div>
        </div>
      </div>
    )
  }

  return (
    <div className="flex h-screen-safe overflow-hidden bg-falcon-bg">
      {/* Sidebar — hidden on mobile */}
      <div className="hidden md:block h-full">
        <Sidebar onSearchOpen={() => setSearchOpen(true)} />
      </div>
      <div className="flex-1 flex flex-col overflow-hidden">
        <TopBar onSearchOpen={() => setSearchOpen(true)} user={user} logout={logout} />
        {/* pb-16 reserves space for mobile bottom nav */}
        {/* Freeプラン エージェント上限アップグレード誘導バナー */}
        <UpgradeBanner />
        {/* 初回ログイン時オンボーディングウィザード */}
        <OnboardingWizard />
        {user?.role === 'viewer' && (
          <div className="flex items-center gap-2 px-4 py-1.5 bg-[#1a1a2e] border-b border-[#2d2d5e] text-xs">
            <Eye className="w-3.5 h-3.5 text-[#7c7cff]" />
            <span className="text-[#9898d0] font-medium">閲覧専用モード</span>
            <span className="text-[#5a5a8a]">— データの閲覧のみ可能です。編集・作成・削除の操作はできません。</span>
          </div>
        )}
        <main className="flex-1 overflow-y-auto bg-falcon-bg pb-16 md:pb-0">
          {children}
        </main>
      </div>
      <CommandPalette isOpen={searchOpen} onClose={() => setSearchOpen(false)} />
      <AlertToastContainer />
      <CloudAlertToastContainer />
      <RealtimeBanner />
      {/* Mobile bottom navigation — visible only on small screens */}
      <MobileBottomNav onSearchOpen={() => setSearchOpen(true)} />
    </div>
  )
}
