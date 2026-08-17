import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { MobileBottomNav } from '@/components/layout/MobileNav'

// next/link をモック
vi.mock('next/link', () => ({
  default: ({ children, href, className, onClick }: {
    children: React.ReactNode
    href: string
    className?: string
    onClick?: () => void
  }) => (
    <a
      href={href}
      className={className}
      onClick={(e) => { e.preventDefault(); onClick?.() }}
    >
      {children}
    </a>
  ),
}))

// next/navigation をモック
const mockUsePathname = vi.fn()
vi.mock('next/navigation', () => ({
  usePathname: () => mockUsePathname(),
}))

// @/lib/auth をモック
const mockUseAuth = vi.fn()
vi.mock('@/lib/auth', () => ({
  useAuth: () => mockUseAuth(),
}))

// lucide-react をモック
vi.mock('lucide-react', () => ({
  LayoutDashboard: () => <span data-testid="icon-dashboard" />,
  ShieldAlert: () => <span data-testid="icon-shieldalert" />,
  Monitor: () => <span data-testid="icon-monitor" />,
  Search: () => <span data-testid="icon-search" />,
  Settings: () => <span data-testid="icon-settings" />,
  Menu: () => <span data-testid="icon-menu" />,
  X: () => <span data-testid="icon-x" />,
  Shield: () => <span data-testid="icon-shield" />,
  Activity: () => <span data-testid="icon-activity" />,
  BookOpen: () => <span data-testid="icon-bookopen" />,
  BarChart3: () => <span data-testid="icon-barchart" />,
}))

describe('MobileBottomNav', () => {
  const onSearchOpen = vi.fn()

  beforeEach(() => {
    vi.clearAllMocks()
    mockUsePathname.mockReturnValue('/dashboard')
  })

  it('未ログイン (token なし) の場合は何も描画されないこと', () => {
    mockUseAuth.mockReturnValue({ token: null })
    const { container } = render(<MobileBottomNav onSearchOpen={onSearchOpen} />)
    expect(container.firstChild).toBeNull()
  })

  it('ログイン済みの場合はボトムナビが表示されること', () => {
    mockUseAuth.mockReturnValue({ token: 'tok' })
    render(<MobileBottomNav onSearchOpen={onSearchOpen} />)
    expect(screen.getByText('ダッシュボード')).toBeInTheDocument()
    expect(screen.getByText('アラート')).toBeInTheDocument()
    expect(screen.getByText('エンドポイント')).toBeInTheDocument()
    expect(screen.getByText('インシデント')).toBeInTheDocument()
    expect(screen.getByText('レポート')).toBeInTheDocument()
    expect(screen.getByText('メニュー')).toBeInTheDocument()
  })

  // text-falcon-red === #e8002d。Tailwind v4 移行で任意値クラスがテーマ
  // トークン名に正規化された（出力される CSS は同じ）。
  it('現在のパスに一致する項目がアクティブ表示 (赤色クラス) されること', () => {
    mockUseAuth.mockReturnValue({ token: 'tok' })
    mockUsePathname.mockReturnValue('/alerts')
    render(<MobileBottomNav onSearchOpen={onSearchOpen} />)
    const alertsLink = screen.getByText('アラート').closest('a')
    expect(alertsLink?.className).toContain('text-falcon-red')
  })

  it('サブパス (/alerts/123) でも該当項目がアクティブになること', () => {
    mockUseAuth.mockReturnValue({ token: 'tok' })
    mockUsePathname.mockReturnValue('/alerts/123')
    render(<MobileBottomNav onSearchOpen={onSearchOpen} />)
    const alertsLink = screen.getByText('アラート').closest('a')
    expect(alertsLink?.className).toContain('text-falcon-red')
  })

  it('メニューボタンをクリックするとドロワーが開くこと', async () => {
    const user = userEvent.setup()
    mockUseAuth.mockReturnValue({ token: 'tok' })
    render(<MobileBottomNav onSearchOpen={onSearchOpen} />)

    expect(screen.queryByText('検索... (Ctrl+K)')).toBeNull()
    await user.click(screen.getByText('メニュー'))
    expect(screen.getByText('検索... (Ctrl+K)')).toBeInTheDocument()
    expect(screen.getByText('Kizashi')).toBeInTheDocument()
  })

  it('ドロワー内の閉じるボタンでドロワーが閉じること', async () => {
    const user = userEvent.setup()
    mockUseAuth.mockReturnValue({ token: 'tok' })
    render(<MobileBottomNav onSearchOpen={onSearchOpen} />)

    await user.click(screen.getByText('メニュー'))
    expect(screen.getByText('Kizashi')).toBeInTheDocument()

    await user.click(screen.getByTestId('icon-x'))
    expect(screen.queryByText('Kizashi')).toBeNull()
  })

  it('ドロワー内の検索ボタンをクリックすると onSearchOpen が呼ばれ、ドロワーが閉じること', async () => {
    const user = userEvent.setup()
    mockUseAuth.mockReturnValue({ token: 'tok' })
    render(<MobileBottomNav onSearchOpen={onSearchOpen} />)

    await user.click(screen.getByText('メニュー'))
    await user.click(screen.getByText('検索... (Ctrl+K)'))

    expect(onSearchOpen).toHaveBeenCalledTimes(1)
    expect(screen.queryByText('Kizashi')).toBeNull()
  })

  it('ドロワー内のナビ項目がセクションごとに表示されること', async () => {
    const user = userEvent.setup()
    mockUseAuth.mockReturnValue({ token: 'tok' })
    render(<MobileBottomNav onSearchOpen={onSearchOpen} />)

    await user.click(screen.getByText('メニュー'))
    expect(screen.getByText('検知・対応')).toBeInTheDocument()
    expect(screen.getByText('脅威ハンティング')).toBeInTheDocument()
    expect(screen.getByText('プレイブック')).toBeInTheDocument()
    expect(screen.getByText('レポート・設定')).toBeInTheDocument()
    expect(screen.getByText('隔離')).toBeInTheDocument()
  })

  it('ドロワー内のナビリンクをクリックするとドロワーが閉じること', async () => {
    const user = userEvent.setup()
    mockUseAuth.mockReturnValue({ token: 'tok' })
    render(<MobileBottomNav onSearchOpen={onSearchOpen} />)

    await user.click(screen.getByText('メニュー'))
    expect(screen.getByText('Kizashi')).toBeInTheDocument()

    // ドロワー内の「プレイブック」リンクをクリック
    await user.click(screen.getByText('プレイブック'))
    expect(screen.queryByText('Kizashi')).toBeNull()
  })

  it('背景 (backdrop) をクリックするとドロワーが閉じること', async () => {
    const user = userEvent.setup()
    mockUseAuth.mockReturnValue({ token: 'tok' })
    const { container } = render(<MobileBottomNav onSearchOpen={onSearchOpen} />)

    await user.click(screen.getByText('メニュー'))
    expect(screen.getByText('Kizashi')).toBeInTheDocument()

    const backdrop = container.querySelector('.bg-black\\/60')
    expect(backdrop).not.toBeNull()
    await user.click(backdrop as Element)
    expect(screen.queryByText('Kizashi')).toBeNull()
  })
})
