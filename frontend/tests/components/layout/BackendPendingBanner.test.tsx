import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import BackendPendingBanner from '@/components/layout/BackendPendingBanner'
// matchesRoute と一覧は lib/backend-pending.ts に移しました。サイドバーが
// 同じ一覧を読む必要があり、バナーの中に置いたままにできなかったためです。
import { matchesRoute } from '@/lib/backend-pending'

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

  it('別の完全未対応ルート (/admin/dark-web) でも表示されること', () => {
    mockUsePathname.mockReturnValue('/admin/dark-web')
    render(<BackendPendingBanner />)
    expect(screen.getByText(/この画面のバックエンドは準備中です/)).toBeInTheDocument()
  })

  // **ここは元は「完全未対応ルート (/yara)」でした (2026-08-17)。**
  // 8/10 が届く画面に「全部準備中」と出していたので、「一部準備中」へ
  // 移しました —— **告知が強すぎると、動く機能を利用者が避けます。**
  it('9割以上届く画面 (/yara) は一部準備中と出ること', () => {
    mockUsePathname.mockReturnValue('/yara')
    render(<BackendPendingBanner />)
    expect(
      screen.getByText(/この画面の一部機能はバックエンド準備中のため/)
    ).toBeInTheDocument()
    expect(screen.queryByText(/この画面のバックエンドは準備中です/)).toBeNull()
  })
})

// 動的セグメントの照合。usePathname() が返すのは /admin/users/abc/activity の
// ような実際のパスなので、[id] を含む経路は完全一致では一生当たりません。
// リストが長らく静的な経路だけだったので、当たらないことに気づく機会が
// ありませんでした。
describe('動的セグメントの照合', () => {
  it.each([
    { pattern: '/a/b', path: '/a/b', want: true },
    { pattern: '/a/b', path: '/a/c', want: false },
    { pattern: '/admin/users/[id]/activity', path: '/admin/users/abc/activity', want: true },
    { pattern: '/admin/users/[id]/activity', path: '/admin/users/activity', want: false },
    { pattern: '/admin/users/[id]/activity', path: '/admin/users/abc/roles', want: false },
    // パターンの方が短い場合。区間数を数えていないと、[id] で終わる経路が
    // その下の階層すべてに当たってしまいます。
    { pattern: '/a/[id]', path: '/a/b/c', want: false },
    { pattern: '/a/[id]', path: '/a/b', want: true },
    { pattern: '/a/[...rest]', path: '/a/b/c/d', want: true },
    { pattern: '/a/[...rest]', path: '/x/b', want: false },
  ])('$pattern vs $path', ({ pattern, path, want }) => {
    expect(matchesRoute(pattern, path)).toBe(want)
  })
})
