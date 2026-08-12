import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import BackendPendingBanner from '@/components/layout/BackendPendingBanner'

// next/navigation をモック
const mockUsePathname = vi.fn()
vi.mock('next/navigation', () => ({
  usePathname: () => mockUsePathname(),
}))

// lucide-react をモック
vi.mock('lucide-react', () => ({
  Construction: () => <span data-testid="icon-construction" />,
}))

describe('BackendPendingBanner', () => {
  it('pathname が null の場合は何も描画されないこと', () => {
    mockUsePathname.mockReturnValue(null)
    const { container } = render(<BackendPendingBanner />)
    expect(container.firstChild).toBeNull()
  })

  it('未対応ルート一覧にないパスでは何も描画されないこと', () => {
    mockUsePathname.mockReturnValue('/dashboard')
    const { container } = render(<BackendPendingBanner />)
    expect(container.firstChild).toBeNull()
  })

  it('完全未対応ルート (BACKEND_PENDING_ROUTES) で完全版メッセージが表示されること', () => {
    mockUsePathname.mockReturnValue('/admin/arch-review')
    render(<BackendPendingBanner />)
    expect(
      screen.getByText(/この画面のバックエンドは準備中です/)
    ).toBeInTheDocument()
    expect(screen.getByTestId('icon-construction')).toBeInTheDocument()
  })

  it('部分未対応ルート (PARTIAL_PENDING_ROUTES) で部分版メッセージが表示されること', () => {
    mockUsePathname.mockReturnValue('/profile/notifications')
    render(<BackendPendingBanner />)
    expect(
      screen.getByText(/この画面の一部機能はバックエンド準備中のため/)
    ).toBeInTheDocument()
  })

  it('完全未対応ルートが優先され、完全版メッセージのみ表示されること', () => {
    mockUsePathname.mockReturnValue('/admin/quarantine')
    render(<BackendPendingBanner />)
    expect(screen.getByText(/この画面のバックエンドは準備中です/)).toBeInTheDocument()
    expect(screen.queryByText(/一部機能はバックエンド準備中/)).toBeNull()
  })

  it('別の完全未対応ルート (/yara) でも表示されること', () => {
    mockUsePathname.mockReturnValue('/yara')
    render(<BackendPendingBanner />)
    expect(screen.getByText(/この画面のバックエンドは準備中です/)).toBeInTheDocument()
  })
})
