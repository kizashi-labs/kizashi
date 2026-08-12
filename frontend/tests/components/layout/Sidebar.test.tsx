import { describe, it, expect, vi, beforeEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Sidebar } from '@/components/layout/Sidebar'

// next/link をモック
vi.mock('next/link', () => ({
  default: ({ children, href, className, title, onClick }: {
    children: React.ReactNode
    href: string
    className?: string
    title?: string
    onClick?: (e: React.MouseEvent) => void
  }) => (
    <a href={href} className={className} title={title} onClick={(e) => { e.preventDefault(); onClick?.(e) }}>
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

// @tanstack/react-query をモック（queryKey に応じてデータを返す）
let mockAlertStats: { open: number } | undefined
let mockIncidentStats: { total: number } | undefined
let mockNotifUnread: { count: number } | undefined
vi.mock('@tanstack/react-query', () => ({
  useQuery: (opts: { queryKey: unknown[] }) => {
    const key = String(opts.queryKey[0])
    if (key === 'alert-stats-sidebar') return { data: mockAlertStats, isLoading: false }
    if (key === 'incident-stats-sidebar') return { data: mockIncidentStats, isLoading: false }
    if (key === 'notif-unread-sidebar') return { data: mockNotifUnread, isLoading: false }
    return { data: undefined, isLoading: false }
  },
}))

vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

// @/lib/usePlan をモック — デフォルトは全機能アンロック
const mockHasFeature = vi.fn(() => true)
vi.mock('@/lib/usePlan', () => ({
  usePlan: () => ({ hasFeature: mockHasFeature }),
}))

// @/lib/useFavorites をモック
let mockFavorites: { href: string; label: string }[] = []
const mockToggleFavorite = vi.fn()
const mockRemoveFavorite = vi.fn()
vi.mock('@/lib/useFavorites', () => ({
  useFavorites: () => ({
    favorites: mockFavorites,
    isFavorite: (href: string) => mockFavorites.some(f => f.href === href),
    toggleFavorite: mockToggleFavorite,
    removeFavorite: mockRemoveFavorite,
  }),
}))

// TenantSwitcher は個別にテスト済みのためスタブ化
vi.mock('@/components/layout/TenantSwitcher', () => ({
  TenantSwitcher: () => <div data-testid="tenant-switcher" />,
}))

// lucide-react — アイコンの実描画は不要なので汎用スタブに差し替える。
// Proxy ベースのモック（get トラップのみ実装）は Vite の CJS 相互運用処理と
// 組み合わさって無期限にハングすることが判明したため（Sidebar が実際に
// import する 131 個のうち 1 個だけを import する最小再現でも再現した)、
// このファイル内の他のテスト（MobileNav 等）と同じ「明示的なオブジェクト」
// 方式に統一する。
vi.mock('lucide-react', () => ({
  LayoutDashboard: () => <span data-testid="icon-LayoutDashboard" />,
  ShieldAlert: () => <span data-testid="icon-ShieldAlert" />,
  Monitor: () => <span data-testid="icon-Monitor" />,
  BookOpen: () => <span data-testid="icon-BookOpen" />,
  BarChart3: () => <span data-testid="icon-BarChart3" />,
  Settings: () => <span data-testid="icon-Settings" />,
  Shield: () => <span data-testid="icon-Shield" />,
  Bell: () => <span data-testid="icon-Bell" />,
  Globe: () => <span data-testid="icon-Globe" />,
  User: () => <span data-testid="icon-User" />,
  Activity: () => <span data-testid="icon-Activity" />,
  Users: () => <span data-testid="icon-Users" />,
  ClipboardList: () => <span data-testid="icon-ClipboardList" />,
  Archive: () => <span data-testid="icon-Archive" />,
  Layers: () => <span data-testid="icon-Layers" />,
  Crosshair: () => <span data-testid="icon-Crosshair" />,
  AlertOctagon: () => <span data-testid="icon-AlertOctagon" />,
  Siren: () => <span data-testid="icon-Siren" />,
  ShieldOff: () => <span data-testid="icon-ShieldOff" />,
  Workflow: () => <span data-testid="icon-Workflow" />,
  CalendarClock: () => <span data-testid="icon-CalendarClock" />,
  Target: () => <span data-testid="icon-Target" />,
  Bug: () => <span data-testid="icon-Bug" />,
  Rss: () => <span data-testid="icon-Rss" />,
  Network: () => <span data-testid="icon-Network" />,
  FolderOpen: () => <span data-testid="icon-FolderOpen" />,
  Search: () => <span data-testid="icon-Search" />,
  KeyRound: () => <span data-testid="icon-KeyRound" />,
  ShieldCheck: () => <span data-testid="icon-ShieldCheck" />,
  TrendingUp: () => <span data-testid="icon-TrendingUp" />,
  TrendingDown: () => <span data-testid="icon-TrendingDown" />,
  GitBranch: () => <span data-testid="icon-GitBranch" />,
  Download: () => <span data-testid="icon-Download" />,
  Package: () => <span data-testid="icon-Package" />,
  Tag: () => <span data-testid="icon-Tag" />,
  GitMerge: () => <span data-testid="icon-GitMerge" />,
  Crown: () => <span data-testid="icon-Crown" />,
  ShoppingBag: () => <span data-testid="icon-ShoppingBag" />,
  MessageSquare: () => <span data-testid="icon-MessageSquare" />,
  ScanSearch: () => <span data-testid="icon-ScanSearch" />,
  Radio: () => <span data-testid="icon-Radio" />,
  Terminal: () => <span data-testid="icon-Terminal" />,
  Brain: () => <span data-testid="icon-Brain" />,
  Wifi: () => <span data-testid="icon-Wifi" />,
  HardDrive: () => <span data-testid="icon-HardDrive" />,
  Cloud: () => <span data-testid="icon-Cloud" />,
  Building2: () => <span data-testid="icon-Building2" />,
  Database: () => <span data-testid="icon-Database" />,
  Usb: () => <span data-testid="icon-Usb" />,
  RefreshCw: () => <span data-testid="icon-RefreshCw" />,
  Box: () => <span data-testid="icon-Box" />,
  Code2: () => <span data-testid="icon-Code2" />,
  Map: () => <span data-testid="icon-Map" />,
  HeartPulse: () => <span data-testid="icon-HeartPulse" />,
  FileInput: () => <span data-testid="icon-FileInput" />,
  Sliders: () => <span data-testid="icon-Sliders" />,
  BellRing: () => <span data-testid="icon-BellRing" />,
  Wrench: () => <span data-testid="icon-Wrench" />,
  Server: () => <span data-testid="icon-Server" />,
  FileCode: () => <span data-testid="icon-FileCode" />,
  Webhook: () => <span data-testid="icon-Webhook" />,
  HelpCircle: () => <span data-testid="icon-HelpCircle" />,
  CheckCircle: () => <span data-testid="icon-CheckCircle" />,
  Gauge: () => <span data-testid="icon-Gauge" />,
  PackageCheck: () => <span data-testid="icon-PackageCheck" />,
  MonitorSmartphone: () => <span data-testid="icon-MonitorSmartphone" />,
  Settings2: () => <span data-testid="icon-Settings2" />,
  CheckSquare: () => <span data-testid="icon-CheckSquare" />,
  SlidersHorizontal: () => <span data-testid="icon-SlidersHorizontal" />,
  FileSearch: () => <span data-testid="icon-FileSearch" />,
  Lock: () => <span data-testid="icon-Lock" />,
  Boxes: () => <span data-testid="icon-Boxes" />,
  Ticket: () => <span data-testid="icon-Ticket" />,
  LayoutTemplate: () => <span data-testid="icon-LayoutTemplate" />,
  Timer: () => <span data-testid="icon-Timer" />,
  FlaskConical: () => <span data-testid="icon-FlaskConical" />,
  Waves: () => <span data-testid="icon-Waves" />,
  Mail: () => <span data-testid="icon-Mail" />,
  Key: () => <span data-testid="icon-Key" />,
  Eye: () => <span data-testid="icon-Eye" />,
  EyeOff: () => <span data-testid="icon-EyeOff" />,
  ClipboardCheck: () => <span data-testid="icon-ClipboardCheck" />,
  UserX: () => <span data-testid="icon-UserX" />,
  ScanLine: () => <span data-testid="icon-ScanLine" />,
  GraduationCap: () => <span data-testid="icon-GraduationCap" />,
  CalendarRange: () => <span data-testid="icon-CalendarRange" />,
  PenTool: () => <span data-testid="icon-PenTool" />,
  CalendarDays: () => <span data-testid="icon-CalendarDays" />,
  Star: () => <span data-testid="icon-Star" />,
  BarChart2: () => <span data-testid="icon-BarChart2" />,
  Send: () => <span data-testid="icon-Send" />,
  AppWindow: () => <span data-testid="icon-AppWindow" />,
  BellDot: () => <span data-testid="icon-BellDot" />,
  ServerCog: () => <span data-testid="icon-ServerCog" />,
  Flag: () => <span data-testid="icon-Flag" />,
  Tags: () => <span data-testid="icon-Tags" />,
  RadioTower: () => <span data-testid="icon-RadioTower" />,
  MailOpen: () => <span data-testid="icon-MailOpen" />,
  UserCheck: () => <span data-testid="icon-UserCheck" />,
  BookmarkCheck: () => <span data-testid="icon-BookmarkCheck" />,
  FileBarChart: () => <span data-testid="icon-FileBarChart" />,
  DollarSign: () => <span data-testid="icon-DollarSign" />,
  ArrowUpCircle: () => <span data-testid="icon-ArrowUpCircle" />,
  Scale: () => <span data-testid="icon-Scale" />,
  Award: () => <span data-testid="icon-Award" />,
  Bot: () => <span data-testid="icon-Bot" />,
  Share2: () => <span data-testid="icon-Share2" />,
  Cpu: () => <span data-testid="icon-Cpu" />,
  Zap: () => <span data-testid="icon-Zap" />,
  Flame: () => <span data-testid="icon-Flame" />,
  Video: () => <span data-testid="icon-Video" />,
  Calculator: () => <span data-testid="icon-Calculator" />,
  GitFork: () => <span data-testid="icon-GitFork" />,
  Fish: () => <span data-testid="icon-Fish" />,
  NotebookPen: () => <span data-testid="icon-NotebookPen" />,
  BookMarked: () => <span data-testid="icon-BookMarked" />,
  Radar: () => <span data-testid="icon-Radar" />,
  CloudLightning: () => <span data-testid="icon-CloudLightning" />,
  Code: () => <span data-testid="icon-Code" />,
  Printer: () => <span data-testid="icon-Printer" />,
  PlayCircle: () => <span data-testid="icon-PlayCircle" />,
  Briefcase: () => <span data-testid="icon-Briefcase" />,
  Fingerprint: () => <span data-testid="icon-Fingerprint" />,
  PieChart: () => <span data-testid="icon-PieChart" />,
  Megaphone: () => <span data-testid="icon-Megaphone" />,
  Link: () => <span data-testid="icon-Link" />,
  FileCog: () => <span data-testid="icon-FileCog" />,
  ChevronLeft: () => <span data-testid="icon-ChevronLeft" />,
  CreditCard: () => <span data-testid="icon-CreditCard" />,
  Inbox: () => <span data-testid="icon-Inbox" />,
  X: () => <span data-testid="icon-X" />,
}))

const ADMIN_USER = { id: 'u1', email: 'admin@example.com', full_name: 'Admin User', role: 'admin' }
const ANALYST_USER = { id: 'u2', email: 'analyst@example.com', full_name: 'Analyst User', role: 'analyst' }

describe('Sidebar', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    mockAlertStats = undefined
    mockIncidentStats = undefined
    mockNotifUnread = undefined
    mockFavorites = []
    mockHasFeature.mockReturnValue(true)
    mockUsePathname.mockReturnValue('/dashboard')
    mockUseAuth.mockReturnValue({ user: ANALYST_USER })
  })

  it('非管理者ユーザーには管理者専用グループが表示されないこと', () => {
    render(<Sidebar />)
    expect(screen.queryByTitle('[管理] コア')).toBeNull()
  })

  it('管理者ユーザーには管理者専用グループアイコンが表示されること', () => {
    mockUseAuth.mockReturnValue({ user: ADMIN_USER })
    render(<Sidebar />)
    expect(screen.getByTitle('[管理] コア')).toBeInTheDocument()
  })

  it('通常グループのアイコンをクリックするとサブペインが開き、項目が表示されること', async () => {
    const user = userEvent.setup()
    // '/dashboard' belongs to the '概要' group itself, which would make it
    // auto-open on mount (see the next describe block) and defeat this test's
    // premise that the subpane starts closed. Use a pathname outside every
    // nav group so no group is open by default.
    mockUsePathname.mockReturnValue('/no-such-route')
    render(<Sidebar />)

    expect(screen.queryByText('グローバル検索')).toBeNull()
    await user.click(screen.getByTitle('概要'))
    expect(screen.getByText('グローバル検索')).toBeInTheDocument()
    expect(screen.getByText('保存済み検索')).toBeInTheDocument()
  })

  it('開いているグループを再度クリックするとサブペインが閉じること', async () => {
    const user = userEvent.setup()
    mockUsePathname.mockReturnValue('/no-such-route')
    render(<Sidebar />)

    await user.click(screen.getByTitle('概要'))
    expect(screen.getByText('グローバル検索')).toBeInTheDocument()

    await user.click(screen.getByTitle('概要'))
    expect(screen.queryByText('グローバル検索')).toBeNull()
  })

  it('現在のパスに一致するグループが初期状態で開いていること', () => {
    mockUsePathname.mockReturnValue('/alerts')
    render(<Sidebar />)
    expect(screen.getByText('トリアージ')).toBeInTheDocument()
  })

  it('未対応アラートがある場合、対象グループに赤バッジタイトルが表示されること', () => {
    mockAlertStats = { open: 5 }
    render(<Sidebar />)
    expect(screen.getByTitle('検知（未対応アラート 5 件）')).toBeInTheDocument()
  })

  it('サブペイン内のアイテムに未対応件数バッジが表示されること', async () => {
    const user = userEvent.setup()
    mockAlertStats = { open: 5 }
    mockUsePathname.mockReturnValue('/dashboard')
    render(<Sidebar />)

    await user.click(screen.getByTitle('検知（未対応アラート 5 件）'))
    // Both 'アラート' (/alerts) and 'トリアージ' (/alerts/triage) carry the same
    // open-alert count badge, so more than one '5件' is expected here.
    expect(screen.getAllByText('5件').length).toBeGreaterThan(0)
  })

  it('通知未読がある場合、下部ナビの通知アイコンにバッジが表示されること', () => {
    mockNotifUnread = { count: 3, urgent_alerts: 0, new_incidents: 0 } as any
    render(<Sidebar />)
    expect(screen.getByTitle('通知設定（未読 3件）')).toBeInTheDocument()
  })

  it('アクティブなページへのリンクにアクティブスタイルが付与されること', async () => {
    mockUsePathname.mockReturnValue('/alerts')
    render(<Sidebar />)

    // '/alerts' belongs to the '検知' group, which auto-opens on mount
    // (see '現在のパスに一致するグループが初期状態で開いていること' above) —
    // no click needed, and clicking '検知' again would toggle it closed.
    const link = screen.getByText('アラート').closest('a')
    expect(link?.className).toContain('bg-[#1d2f4a]')
  })

  it('機能ロックされた項目にロックアイコンが表示され、タイトルにその旨が示されること', async () => {
    const user = userEvent.setup()
    mockUseAuth.mockReturnValue({ user: ADMIN_USER })
    mockHasFeature.mockReturnValue(false)
    render(<Sidebar />)

    await user.click(screen.getByTitle('[管理] 検知'))
    const lockedLink = screen.getByTitle('YARAルール（上位プランが必要です）')
    expect(lockedLink).toBeInTheDocument()
  })

  it('お気に入りが登録されている場合、お気に入りセクションが表示されること', async () => {
    const user = userEvent.setup()
    mockFavorites = [{ href: '/alerts', label: 'アラート' }]
    mockUsePathname.mockReturnValue('/no-such-route')
    render(<Sidebar />)

    await user.click(screen.getByTitle('概要'))
    expect(screen.getByText('お気に入り')).toBeInTheDocument()
  })

  it('お気に入りに登録されていない項目のスターボタンをクリックすると toggleFavorite が呼ばれること', async () => {
    const user = userEvent.setup()
    mockUsePathname.mockReturnValue('/no-such-route')
    render(<Sidebar />)

    await user.click(screen.getByTitle('概要'))
    // Every un-favorited item in the group has its own star button.
    const [favButton] = screen.getAllByTitle('お気に入りに追加')
    await user.click(favButton)
    expect(mockToggleFavorite).toHaveBeenCalled()
  })

  it('管理者グループを開くと TenantSwitcher が表示されること', async () => {
    const user = userEvent.setup()
    mockUseAuth.mockReturnValue({ user: ADMIN_USER })
    render(<Sidebar />)

    await user.click(screen.getByTitle('[管理] コア'))
    expect(screen.getByTestId('tenant-switcher')).toBeInTheDocument()
  })

  it('通常グループを開いた場合は TenantSwitcher が表示されないこと', async () => {
    const user = userEvent.setup()
    mockUseAuth.mockReturnValue({ user: ADMIN_USER })
    render(<Sidebar />)

    await user.click(screen.getByTitle('概要'))
    expect(screen.queryByTestId('tenant-switcher')).toBeNull()
  })

  it('サブペインのユーザー情報欄にユーザー名とロールが表示されること', async () => {
    const user = userEvent.setup()
    mockUsePathname.mockReturnValue('/no-such-route')
    render(<Sidebar />)

    await user.click(screen.getByTitle('概要'))
    expect(screen.getByText('Analyst User')).toBeInTheDocument()
    expect(screen.getByText('analyst')).toBeInTheDocument()
  })

  it('サブペインを閉じるボタンをクリックするとサブペインが閉じること', async () => {
    const user = userEvent.setup()
    mockUsePathname.mockReturnValue('/no-such-route')
    render(<Sidebar />)

    await user.click(screen.getByTitle('概要'))
    expect(screen.getByText('グローバル検索')).toBeInTheDocument()

    await user.click(screen.getByTitle('閉じる'))
    expect(screen.queryByText('グローバル検索')).toBeNull()
  })
})
