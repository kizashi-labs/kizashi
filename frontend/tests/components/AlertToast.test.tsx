import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act, fireEvent } from '@testing-library/react'
import { AlertToastContainer } from '@/components/notifications/AlertToast'

// next/link をモック
vi.mock('next/link', () => ({
  default: ({ children, href, onClick }: { children: React.ReactNode; href: string; onClick?: () => void }) => (
    <a href={href} onClick={onClick}>{children}</a>
  ),
}))

// lucide-react をモック
vi.mock('lucide-react', () => ({
  X: () => <span data-testid="icon-x">X</span>,
  ShieldAlert: () => <span data-testid="icon-shield-alert">ShieldAlert</span>,
  ShieldX: () => <span data-testid="icon-shield-x">ShieldX</span>,
  AlertTriangle: () => <span data-testid="icon-alert-triangle">AlertTriangle</span>,
  Info: () => <span data-testid="icon-info">Info</span>,
}))

// MockEventSource への参照
type MockEventSourceType = {
  instance: MockEventSourceInstance | null
}

type MockEventSourceInstance = {
  url: string
  onmessage: ((evt: MessageEvent) => void) | null
  close: () => void
  readyState: number
  simulateMessage: (data: unknown) => void
}

const getMockES = () =>
  (global as unknown as { MockEventSource: MockEventSourceType }).MockEventSource.instance as MockEventSourceInstance | null

function makeAlert(overrides: Partial<{
  ID: string
  Hostname: string
  RuleName: string
  Severity: number
  Title: string
  Status: string
  CreatedAt: string
}> = {}) {
  return {
    ID: 'alert-1',
    Hostname: 'host-a',
    RuleName: 'SuspiciousProcess',
    Severity: 3,
    Title: 'Test Alert',
    Status: 'open',
    CreatedAt: '2026-03-17T00:00:00Z',
    ...overrides,
  }
}

describe('AlertToastContainer', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    // MockEventSource のインスタンスをリセット
    ;(global as unknown as { MockEventSource: MockEventSourceType }).MockEventSource.instance = null
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.clearAllMocks()
  })

  it('SSE 接続が確立されること (EventSource コンストラクタが呼ばれること)', () => {
    render(<AlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()
    expect(es!.url).toBe('/ws/alerts')
  })

  it('type: "alert" のメッセージでトーストが表示されること', () => {
    render(<AlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({ type: 'alert', data: makeAlert() })
    })

    expect(screen.getByText('Test Alert')).toBeInTheDocument()
  })

  it('type が "alert" 以外のメッセージではトーストが表示されないこと', async () => {
    render(<AlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({ type: 'other', data: makeAlert() })
    })

    // トーストが表示されないことを確認
    expect(screen.queryByText('Test Alert')).toBeNull()
  })

  it('トーストが TTL 後に自動的に消えること (fake timers 使用)', () => {
    render(<AlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({ type: 'alert', data: makeAlert() })
    })

    expect(screen.getByText('Test Alert')).toBeInTheDocument()

    // TOAST_TTL_MS (8000ms) 経過後にトーストが消えること
    act(() => {
      vi.advanceTimersByTime(8000)
    })

    expect(screen.queryByText('Test Alert')).toBeNull()
  })

  it('同じ alert ID の重複トーストが表示されないこと', () => {
    render(<AlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({ type: 'alert', data: makeAlert({ ID: 'same-id', Title: 'First Alert' }) })
    })

    expect(screen.getByText('First Alert')).toBeInTheDocument()

    // 同じ ID で再度メッセージを送信
    act(() => {
      es!.simulateMessage({ type: 'alert', data: makeAlert({ ID: 'same-id', Title: 'First Alert' }) })
    })

    // トーストが1つだけ表示されること
    const toasts = screen.getAllByText('First Alert')
    expect(toasts).toHaveLength(1)
  })

  it('X ボタンでトーストが閉じられること', () => {
    render(<AlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({ type: 'alert', data: makeAlert({ Title: 'Closeable Alert' }) })
    })

    expect(screen.getByText('Closeable Alert')).toBeInTheDocument()

    // X ボタンをクリック
    const closeBtn = screen.getAllByTestId('icon-x')[0].closest('button') ?? screen.getAllByTestId('icon-x')[0]
    act(() => {
      fireEvent.click(closeBtn)
    })

    expect(screen.queryByText('Closeable Alert')).toBeNull()
  })

  it('MAX_TOASTS (5) を超えた場合に古いものが削除されること', () => {
    render(<AlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    // 6 件のアラートを送信
    act(() => {
      for (let i = 1; i <= 6; i++) {
        es!.simulateMessage({
          type: 'alert',
          data: makeAlert({ ID: `alert-${i}`, Title: `Alert ${i}` }),
        })
      }
    })

    // 最新の5件が表示され、最初のものは削除されていること
    expect(screen.queryByText('Alert 1')).toBeNull()
    expect(screen.getByText('Alert 2')).toBeInTheDocument()
    expect(screen.getByText('Alert 6')).toBeInTheDocument()

    // 表示されているトーストが最大 5 件であること
    const allAlertTexts = screen.queryAllByText(/^Alert \d+$/)
    expect(allAlertTexts.length).toBeLessThanOrEqual(5)
  })

  it('ID または Title がない不正なペイロードを無視すること', async () => {
    render(<AlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      // ID なし
      es!.simulateMessage({ type: 'alert', data: { Hostname: 'host', Title: 'No ID Alert' } })
      // Title なし
      es!.simulateMessage({ type: 'alert', data: { ID: 'some-id', Hostname: 'host' } })
      // 不正な JSON
      if (es!.onmessage) {
        const evt = new MessageEvent('message', { data: 'invalid json' })
        es!.onmessage(evt)
      }
    })

    // トーストが表示されないこと
    expect(screen.queryByText('No ID Alert')).toBeNull()
  })

  it('コンポーネントのアンマウント時に ES が閉じられること', () => {
    const { unmount } = render(<AlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    const closeSpy = vi.spyOn(es!, 'close')
    unmount()

    expect(closeSpy).toHaveBeenCalledOnce()
  })
})
