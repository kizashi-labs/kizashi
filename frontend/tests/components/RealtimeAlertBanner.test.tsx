import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { RealtimeAlertBanner } from '@/components/RealtimeAlertBanner'

// lucide-react をモック
vi.mock('lucide-react', () => ({
  X:             () => <button data-testid="btn-dismiss">X</button>,
  AlertTriangle: () => <span data-testid="icon-alert" />,
}))

// ─── WebSocket モック ──────────────────────────────────────────────────────────

type MockWSInstance = {
  url: string
  onopen: (() => void) | null
  onmessage: ((evt: MessageEvent) => void) | null
  onclose: (() => void) | null
  onerror: ((evt: Event) => void) | null
  send: ReturnType<typeof vi.fn>
  close: ReturnType<typeof vi.fn>
  readyState: number
}

let mockWSInstance: MockWSInstance | null = null

class MockWebSocket {
  url: string
  onopen: (() => void) | null = null
  onmessage: ((evt: MessageEvent) => void) | null = null
  onclose: (() => void) | null = null
  onerror: ((evt: Event) => void) | null = null
  send = vi.fn()
  close = vi.fn()
  readyState: number = WebSocket.CONNECTING

  static OPEN = WebSocket.OPEN

  constructor(url: string) {
    this.url = url
    mockWSInstance = this as unknown as MockWSInstance
    // 非同期で接続完了をシミュレート
    Promise.resolve().then(() => {
      this.readyState = WebSocket.OPEN
      this.onopen?.()
    })
  }
}

function simulateWSMessage(data: unknown) {
  if (!mockWSInstance?.onmessage) return
  const evt = new MessageEvent('message', {
    data: typeof data === 'string' ? data : JSON.stringify(data),
  })
  mockWSInstance.onmessage(evt)
}

// ─── セットアップ ──────────────────────────────────────────────────────────────

beforeEach(() => {
  mockWSInstance = null
  localStorage.setItem('token', 'dummy-jwt-token')
  ;(global as unknown as { WebSocket: typeof MockWebSocket }).WebSocket = MockWebSocket
})

afterEach(() => {
  localStorage.clear()
  vi.clearAllMocks()
})

// ─── テスト ────────────────────────────────────────────────────────────────────

describe('RealtimeAlertBanner', () => {
  it('初期状態ではアラート通知が表示されないこと', () => {
    render(<RealtimeAlertBanner />)
    // アラートタイトルが表示されない
    expect(screen.queryByText('New Alert')).toBeNull()
  })

  it('type="new_alert" のメッセージでバナーが表示されること', async () => {
    render(<RealtimeAlertBanner />)

    await act(async () => {
      simulateWSMessage({
        type: 'new_alert',
        timestamp: new Date().toISOString(),
        data: { id: 'a1', severity: 'critical', title: '緊急アラート' },
      })
    })

    await waitFor(() => {
      expect(screen.getByText('緊急アラート')).toBeInTheDocument()
    })
  })

  it('type が "new_alert" 以外のメッセージではバナーが表示されないこと', async () => {
    render(<RealtimeAlertBanner />)

    await act(async () => {
      simulateWSMessage({
        type: 'other_event',
        timestamp: new Date().toISOString(),
        data: { id: 'a2', severity: 'high', title: '別イベント' },
      })
    })

    expect(screen.queryByText('別イベント')).toBeNull()
  })

  it('severity が表示されること', async () => {
    render(<RealtimeAlertBanner />)

    await act(async () => {
      simulateWSMessage({
        type: 'new_alert',
        timestamp: new Date().toISOString(),
        data: { id: 'a3', severity: 'high', title: 'Severity Test' },
      })
    })

    await waitFor(() => {
      expect(screen.getByText('high')).toBeInTheDocument()
    })
  })

  it('最大5件までバナーが表示されること', async () => {
    render(<RealtimeAlertBanner />)

    await act(async () => {
      for (let i = 1; i <= 6; i++) {
        simulateWSMessage({
          type: 'new_alert',
          timestamp: new Date().toISOString(),
          data: { id: `alert-${i}`, severity: 'medium', title: `Alert ${i}` },
        })
      }
    })

    await waitFor(() => {
      // 最新の5件が表示
      expect(screen.getByText('Alert 6')).toBeInTheDocument()
      expect(screen.getByText('Alert 2')).toBeInTheDocument()
    })

    // 最初のアラート (Alert 1) は溢れて消えている
    expect(screen.queryByText('Alert 1')).toBeNull()
  })

  it('X ボタンをクリックするとバナーが閉じられること', async () => {
    const user = userEvent.setup()
    render(<RealtimeAlertBanner />)

    await act(async () => {
      simulateWSMessage({
        type: 'new_alert',
        timestamp: new Date().toISOString(),
        data: { id: 'dismiss-test', severity: 'low', title: '閉じるテスト' },
      })
    })

    await waitFor(() => {
      expect(screen.getByText('閉じるテスト')).toBeInTheDocument()
    })

    const dismissBtn = screen.getByTestId('btn-dismiss')
    await user.click(dismissBtn)

    await waitFor(() => {
      expect(screen.queryByText('閉じるテスト')).toBeNull()
    })
  })

  it('不正な JSON メッセージを無視すること', async () => {
    render(<RealtimeAlertBanner />)

    await act(async () => {
      if (mockWSInstance?.onmessage) {
        const evt = new MessageEvent('message', { data: 'invalid-json' })
        mockWSInstance.onmessage(evt)
      }
    })

    // エラーなし、バナー表示なし
    expect(screen.queryByTestId('icon-alert')).toBeNull()
  })
})
