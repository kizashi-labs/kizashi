import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { ErrorBoundary, withErrorBoundary } from '@/components/ErrorBoundary'

// next/link をモック
vi.mock('next/link', () => ({
  default: ({ children, href, className }: {
    children: React.ReactNode
    href: string
    className?: string
  }) => <a href={href} className={className}>{children}</a>,
}))

// lucide-react をモック
vi.mock('lucide-react', () => ({
  AlertTriangle: () => <span data-testid="icon-alert-triangle" />,
  RefreshCw:     () => <span data-testid="icon-refresh" />,
  Home:          () => <span data-testid="icon-home" />,
}))

// エラーを投げる子コンポーネント
function ThrowError({ shouldThrow }: { shouldThrow: boolean }) {
  if (shouldThrow) throw new Error('テストエラーメッセージ')
  return <div>正常コンテンツ</div>
}

// コンソールエラー出力を抑制
const consoleError = console.error
beforeEach(() => {
  console.error = vi.fn()
})
afterEach(() => {
  console.error = consoleError
})

// ─── ErrorBoundary ────────────────────────────────────────────────────────────

describe('ErrorBoundary', () => {
  it('エラーが発生しない場合は子コンポーネントを描画すること', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={false} />
      </ErrorBoundary>
    )
    expect(screen.getByText('正常コンテンツ')).toBeInTheDocument()
  })

  it('エラー発生時にデフォルトのエラーUIを表示すること', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    )
    expect(screen.getByText('表示エラーが発生しました')).toBeInTheDocument()
  })

  it('エラーメッセージが表示されること', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    )
    expect(screen.getByText('テストエラーメッセージ')).toBeInTheDocument()
  })

  it('再試行ボタンが表示されること', () => {
    render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    )
    expect(screen.getByText('再試行')).toBeInTheDocument()
  })

  it('ダッシュボードへのリンクが表示されること', () => {
    const { container } = render(
      <ErrorBoundary>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    )
    const link = container.querySelector('a[href="/dashboard"]')
    expect(link).not.toBeNull()
  })

  it('再試行ボタンをクリックすると hasError がリセットされること', async () => {
    const user = userEvent.setup()
    // モジュールスコープの変数でスロー制御
    let shouldThrowNow = true
    function ControllableError() {
      if (shouldThrowNow) throw new Error('制御可能エラー')
      return <div>正常コンテンツ</div>
    }

    render(
      <ErrorBoundary>
        <ControllableError />
      </ErrorBoundary>
    )

    expect(screen.getByText('表示エラーが発生しました')).toBeInTheDocument()

    // スローを止めてから再試行ボタンをクリック
    shouldThrowNow = false
    const retryBtn = screen.getByText('再試行')
    await user.click(retryBtn)

    // hasError が false になり正常コンテンツが表示される
    expect(screen.getByText('正常コンテンツ')).toBeInTheDocument()
  })

  it('fallback props が指定された場合はカスタム fallback を表示すること', () => {
    render(
      <ErrorBoundary fallback={<div>カスタムエラー表示</div>}>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    )
    expect(screen.getByText('カスタムエラー表示')).toBeInTheDocument()
    expect(screen.queryByText('表示エラーが発生しました')).toBeNull()
  })

  it('fallback 使用時はデフォルト UI が表示されないこと', () => {
    render(
      <ErrorBoundary fallback={<span>fallback</span>}>
        <ThrowError shouldThrow={true} />
      </ErrorBoundary>
    )
    expect(screen.queryByText('再試行')).toBeNull()
  })
})

// ─── withErrorBoundary ────────────────────────────────────────────────────────

describe('withErrorBoundary HOC', () => {
  it('エラーなしで子コンポーネントが描画されること', () => {
    const WrappedComponent = withErrorBoundary(
      () => <div>HOC テスト</div>
    )
    render(<WrappedComponent />)
    expect(screen.getByText('HOC テスト')).toBeInTheDocument()
  })

  it('エラー時にデフォルトのエラーUIを表示すること', () => {
    const BrokenComponent = () => { throw new Error('HOC エラー') }
    const WrappedBroken = withErrorBoundary(BrokenComponent)
    render(<WrappedBroken />)
    expect(screen.getByText('表示エラーが発生しました')).toBeInTheDocument()
  })

  it('カスタム fallback を指定できること', () => {
    const BrokenComponent = () => { throw new Error('HOC エラー') }
    const WrappedBroken = withErrorBoundary(BrokenComponent, <div>カスタムHOCエラー</div>)
    render(<WrappedBroken />)
    expect(screen.getByText('カスタムHOCエラー')).toBeInTheDocument()
  })
})
