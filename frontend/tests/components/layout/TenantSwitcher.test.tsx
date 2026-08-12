import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { TenantSwitcher } from '@/components/layout/TenantSwitcher'

// next/navigation をモック
const mockRefresh = vi.fn()
vi.mock('next/navigation', () => ({
  useRouter: () => ({ refresh: mockRefresh }),
}))

// @tanstack/react-query をモック
const mockInvalidateQueries = vi.fn()
let mockQueryData: { tenants: { id: string; name: string; slug: string }[] } | undefined
let mockIsLoading = false
vi.mock('@tanstack/react-query', () => ({
  useQuery: () => ({ data: mockQueryData, isLoading: mockIsLoading }),
  useQueryClient: () => ({ invalidateQueries: mockInvalidateQueries }),
}))

// lucide-react をモック
vi.mock('lucide-react', () => ({
  ChevronDown: () => <span data-testid="icon-chevron" />,
  Building2: () => <span data-testid="icon-building" />,
  Check: () => <span data-testid="icon-check" />,
}))

// @/lib/api をモック（useQuery をモック済みのため実際には呼ばれない）
vi.mock('@/lib/api', () => ({
  apiFetch: vi.fn(),
}))

const TENANTS = [
  { id: 't1', name: 'Acme Corp', slug: 'acme' },
  { id: 't2', name: 'Globex Inc', slug: 'globex' },
]

describe('TenantSwitcher', () => {
  beforeEach(() => {
    mockQueryData = undefined
    mockIsLoading = false
    localStorage.clear()
    vi.clearAllMocks()
  })

  afterEach(() => {
    localStorage.clear()
  })

  it('読み込み中は「読み込み中...」と表示されること', () => {
    mockIsLoading = true
    render(<TenantSwitcher />)
    expect(screen.getByText('読み込み中...')).toBeInTheDocument()
  })

  it('テナントが取得できていない場合は「テナント選択」と表示されること', () => {
    mockQueryData = { tenants: [] }
    render(<TenantSwitcher />)
    expect(screen.getByText('テナント選択')).toBeInTheDocument()
  })

  it('テナント一覧取得後、先頭テナント名が表示されること', () => {
    mockQueryData = { tenants: TENANTS }
    render(<TenantSwitcher />)
    expect(screen.getByText('Acme Corp')).toBeInTheDocument()
    expect(screen.getByText('acme')).toBeInTheDocument()
  })

  it('localStorage に保存済みの edr_tenant_id があればそのテナントを選択表示すること', () => {
    localStorage.setItem('edr_tenant_id', 't2')
    mockQueryData = { tenants: TENANTS }
    render(<TenantSwitcher />)
    expect(screen.getByText('Globex Inc')).toBeInTheDocument()
  })

  it('ボタンをクリックするとドロップダウンが開き、テナント一覧が表示されること', async () => {
    const user = userEvent.setup()
    mockQueryData = { tenants: TENANTS }
    render(<TenantSwitcher />)

    expect(screen.queryByText('Globex Inc')).toBeNull()
    await user.click(screen.getByTitle('テナントを切り替え'))

    expect(screen.getByText('Globex Inc')).toBeInTheDocument()
  })

  it('テナントを選択すると localStorage に保存され、invalidateQueries と router.refresh が呼ばれること', async () => {
    const user = userEvent.setup()
    mockQueryData = { tenants: TENANTS }
    render(<TenantSwitcher />)

    await user.click(screen.getByTitle('テナントを切り替え'))
    const dropdownItem = screen.getByText('Globex Inc')
    await user.click(dropdownItem)

    expect(localStorage.getItem('edr_tenant_id')).toBe('t2')
    expect(mockInvalidateQueries).toHaveBeenCalled()
    expect(mockRefresh).toHaveBeenCalled()
    // 選択後にドロップダウンが閉じる
    expect(screen.queryByText('Acme Corp')).toBeNull()
  })

  it('選択中のテナントに Check アイコンが表示されること', async () => {
    const user = userEvent.setup()
    localStorage.setItem('edr_tenant_id', 't1')
    mockQueryData = { tenants: TENANTS }
    render(<TenantSwitcher />)

    await user.click(screen.getByTitle('テナントを切り替え'))
    // 「Acme Corp」はヘッダーとドロップダウン項目の2箇所に表示される。
    // ドロップダウン内の項目（2つ目）を取得する。
    const acmeMatches = screen.getAllByText('Acme Corp')
    expect(acmeMatches).toHaveLength(2)
    const acmeRow = acmeMatches[1].closest('button')
    expect(acmeRow).not.toBeNull()
    expect(within(acmeRow as HTMLElement).getByTestId('icon-check')).toBeInTheDocument()
  })

  it('要素外をクリックするとドロップダウンが閉じること', async () => {
    const user = userEvent.setup()
    mockQueryData = { tenants: TENANTS }
    render(
      <div>
        <div data-testid="outside">outside</div>
        <TenantSwitcher />
      </div>
    )

    await user.click(screen.getByTitle('テナントを切り替え'))
    expect(screen.getByText('Globex Inc')).toBeInTheDocument()

    await user.click(screen.getByTestId('outside'))
    expect(screen.queryByText('Globex Inc')).toBeNull()
  })
})
