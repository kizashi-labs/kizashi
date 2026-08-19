'use client'

import NextLink from 'next/link'
import { usePathname } from 'next/navigation'
import { useAuth } from '@/lib/auth'
import {
  LayoutDashboard, ShieldAlert, Monitor,
  Search, Settings, Menu, X, Shield,
  Activity, BookOpen, BarChart3,
} from 'lucide-react'
import { useState } from 'react'

// ── Bottom nav items (most-used shortcuts) ─────────────────────────────────
const BOTTOM_ITEMS = [
  { href: '/dashboard',     label: 'ダッシュボード', icon: LayoutDashboard },
  { href: '/alerts',        label: 'アラート',       icon: ShieldAlert      },
  { href: '/endpoints',     label: 'エンドポイント', icon: Monitor          },
  { href: '/incidents',     label: 'インシデント',   icon: Activity         },
  { href: '/reports',       label: 'レポート',       icon: BarChart3        },
]

// ── Mobile drawer menu items ───────────────────────────────────────────────
const DRAWER_SECTIONS = [
  {
    title: '検知・対応',
    items: [
      { href: '/alerts',        label: 'アラート',         icon: ShieldAlert   },
      { href: '/incidents',     label: 'インシデント',     icon: Activity      },
      { href: '/threat-hunting',label: '脅威ハンティング', icon: Search        },
      { href: '/playbooks',     label: 'プレイブック',     icon: BookOpen      },
    ],
  },
  {
    title: 'エンドポイント',
    items: [
      { href: '/endpoints',     label: 'エンドポイント',   icon: Monitor       },
      { href: '/events',        label: 'イベント',         icon: Activity      },
      { href: '/quarantine',    label: '隔離',             icon: Shield        },
    ],
  },
  {
    title: 'レポート・設定',
    items: [
      { href: '/reports',       label: 'レポート',         icon: BarChart3     },
      { href: '/settings',      label: '設定',             icon: Settings      },
    ],
  },
]

export function MobileBottomNav({ onSearchOpen }: { onSearchOpen: () => void }) {
  const pathname = usePathname()
  const { token } = useAuth()
  const [drawerOpen, setDrawerOpen] = useState(false)

  if (!token) return null

  const isActive = (href: string) =>
    pathname === href || (href !== '/dashboard' && pathname.startsWith(href))

  return (
    <>
      {/* ── Bottom tab bar ─────────────────────────────────── */}
      <nav className="md:hidden fixed bottom-0 inset-x-0 z-50 bg-[#0a1628] border-t border-[#1e2d42] flex items-stretch safe-bottom">

        {BOTTOM_ITEMS.map(({ href, label, icon: Icon }) => {
          const active = isActive(href)
          return (
            <NextLink
              key={href}
              href={href}
              className={`flex-1 flex flex-col items-center justify-center py-2 gap-0.5 text-[10px]
                          transition-colors
                          ${active
                            ? 'text-[#e8002d]'
                            : 'text-[#3d5068] hover:text-[#7d92b0]'
                          }`}
            >
              <Icon className={`w-5 h-5 ${active ? 'text-[#e8002d]' : ''}`} />
              <span className="leading-tight">{label}</span>
            </NextLink>
          )
        })}

        {/* More (hamburger) */}
        <button
          onClick={() => setDrawerOpen(true)}
          className="flex-1 flex flex-col items-center justify-center py-2 gap-0.5 text-[10px] text-[#3d5068] hover:text-[#7d92b0] transition-colors"
        >
          <Menu className="w-5 h-5" />
          <span className="leading-tight">メニュー</span>
        </button>
      </nav>

      {/* ── Drawer overlay ─────────────────────────────────── */}
      {drawerOpen && (
        <div className="md:hidden fixed inset-0 z-50 flex">
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/60"
            onClick={() => setDrawerOpen(false)}
          />

          {/* Drawer panel */}
          <div className="relative ml-auto w-72 h-full bg-[#0a1628] border-l border-[#1e2d42] flex flex-col overflow-y-auto">
            {/* Header */}
            <div className="flex items-center justify-between px-4 h-14 border-b border-[#1e2d42] shrink-0">
              <div className="flex items-center gap-2">
                <div className="w-6 h-6 rounded-sm bg-linear-to-br from-[#e8002d] to-[#a80020] flex items-center justify-center">
                  <Shield className="w-3.5 h-3.5 text-white" />
                </div>
                <span className="text-sm font-bold text-white">Kizashi</span>
              </div>
              <button
                onClick={() => setDrawerOpen(false)}
                className="p-1.5 rounded-sm text-[#3d5068] hover:text-white hover:bg-[#1e2d42] transition-colors"
              >
                <X className="w-5 h-5" />
              </button>
            </div>

            {/* Search */}
            <div className="px-3 py-3 border-b border-[#1e2d42]">
              <button
                onClick={() => { setDrawerOpen(false); onSearchOpen() }}
                className="w-full flex items-center gap-2 px-3 py-2 rounded-lg bg-[#0d1220] border border-[#1e2d42] text-[#3d5068] hover:border-[#3d5068] hover:text-[#7d92b0] transition-all text-sm"
              >
                <Search className="w-4 h-4" />
                <span>検索... (Ctrl+K)</span>
              </button>
            </div>

            {/* Nav sections */}
            <div className="flex-1 overflow-y-auto py-2">
              {DRAWER_SECTIONS.map(section => (
                <div key={section.title} className="mb-1">
                  <p className="px-4 py-2 text-[10px] uppercase tracking-wider font-medium text-[#3d5068]">
                    {section.title}
                  </p>
                  {section.items.map(({ href, label, icon: Icon }) => {
                    const active = isActive(href)
                    return (
                      <NextLink
                        key={href}
                        href={href}
                        onClick={() => setDrawerOpen(false)}
                        className={`flex items-center gap-3 px-4 py-2.5 text-sm transition-colors
                                    ${active
                                      ? 'text-white bg-[#1e2d42]'
                                      : 'text-[#7d92b0] hover:text-white hover:bg-[#0d1828]'
                                    }`}
                      >
                        <Icon className={`w-4 h-4 shrink-0 ${active ? 'text-[#e8002d]' : ''}`} />
                        {label}
                      </NextLink>
                    )
                  })}
                </div>
              ))}
            </div>
          </div>
        </div>
      )}
    </>
  )
}
