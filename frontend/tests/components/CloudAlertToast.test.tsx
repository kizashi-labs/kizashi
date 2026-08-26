import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { render, screen, act, fireEvent } from '@testing-library/react'
import { CloudAlertToastContainer } from '@/components/notifications/CloudAlertToast'

// next/link をモック
vi.mock('next/link', () => ({
  default: ({ children, href, onClick }: { children: React.ReactNode; href: string; onClick?: () => void }) => (
    <a href={href} onClick={onClick}>{children}</a>
  ),
}))

// lucide-react をモック
vi.mock('lucide-react', () => ({
  X: () => <span data-testid="icon-x">X</span>,
  Cloud: () => <span data-testid="icon-cloud">Cloud</span>,
  AlertTriangle: () => <span data-testid="icon-alert-triangle">AlertTriangle</span>,
  ShieldAlert: () => <span data-testid="icon-shield-alert">ShieldAlert</span>,
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

function makeCloudEvent(overrides: Partial<{
  id: string
  provider: string
  event_type: string
  event_time: string
  source_ip: string
  region: string
  resource: string
}> = {}) {
  return {
    id: 'evt-1',
    provider: 'aws',
    event_type: 'ListBuckets',
    event_time: '2026-03-17T00:00:00Z',
    source_ip: '1.2.3.4',
    region: 'us-east-1',
    ...overrides,
  }
}

describe('CloudAlertToastContainer', () => {
  beforeEach(() => {
    vi.useFakeTimers()
    // MockEventSource のインスタンスをリセット
    ;(global as unknown as { MockEventSource: MockEventSourceType }).MockEventSource.instance = null
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.clearAllMocks()
  })

  it('/ws/cloud SSE エンドポイントへの接続確認', () => {
    render(<CloudAlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()
    expect(es!.url).toBe('/ws/cloud')
  })

  it('type: "cloud_event" メッセージでトーストが表示されること', () => {
    render(<CloudAlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({ type: 'cloud_event', data: makeCloudEvent({ event_type: 'ListBuckets' }) })
    })

    expect(screen.getByText('ListBuckets')).toBeInTheDocument()
  })

  it('type が "cloud_event" 以外のメッセージではトーストが表示されないこと', () => {
    render(<CloudAlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({ type: 'other', data: makeCloudEvent() })
    })

    expect(screen.queryByText('ListBuckets')).toBeNull()
  })

  it('DeleteTrail などの suspicious イベントで "⚠ SUSPICIOUS" バッジが表示されること', () => {
    render(<CloudAlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({
        type: 'cloud_event',
        data: makeCloudEvent({ id: 'susp-1', event_type: 'DeleteTrail' }),
      })
    })

    expect(screen.getByText('DeleteTrail')).toBeInTheDocument()
    expect(screen.getByText('⚠ SUSPICIOUS')).toBeInTheDocument()
  })

  it('StopLogging も suspicious イベントとして扱われること', () => {
    render(<CloudAlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({
        type: 'cloud_event',
        data: makeCloudEvent({ id: 'susp-2', event_type: 'StopLogging' }),
      })
    })

    expect(screen.getByText('⚠ SUSPICIOUS')).toBeInTheDocument()
  })

  it('non-suspicious イベントでは通常スタイルで表示されること ("⚠ SUSPICIOUS" バッジが表示されないこと)', () => {
    render(<CloudAlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({
        type: 'cloud_event',
        data: makeCloudEvent({ id: 'normal-1', event_type: 'ListBuckets' }),
      })
    })

    expect(screen.getByText('ListBuckets')).toBeInTheDocument()
    expect(screen.queryByText('⚠ SUSPICIOUS')).toBeNull()
  })

  it('接続切断時のクリーンアップ (es.close() が呼ばれること)', () => {
    const { unmount } = render(<CloudAlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    const closeSpy = vi.spyOn(es!, 'close')
    unmount()

    expect(closeSpy).toHaveBeenCalledOnce()
  })

  it('TTL 後にトーストが自動的に消えること', () => {
    render(<CloudAlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({
        type: 'cloud_event',
        data: makeCloudEvent({ id: 'ttl-1', event_type: 'GetObject' }),
      })
    })

    expect(screen.getByText('GetObject')).toBeInTheDocument()

    // TOAST_TTL_MS (10000ms) 経過後に消えること
    act(() => {
      vi.advanceTimersByTime(10000)
    })

    expect(screen.queryByText('GetObject')).toBeNull()
  })

  it('X ボタンでトーストが閉じられること', () => {
    render(<CloudAlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({
        type: 'cloud_event',
        data: makeCloudEvent({ id: 'close-1', event_type: 'PutObject' }),
      })
    })

    expect(screen.getByText('PutObject')).toBeInTheDocument()

    const closeBtn = screen.getAllByTestId('icon-x')[0].closest('button') ?? screen.getAllByTestId('icon-x')[0]
    act(() => {
      fireEvent.click(closeBtn)
    })

    expect(screen.queryByText('PutObject')).toBeNull()
  })

  it('同じイベント ID の重複トーストが表示されないこと', () => {
    render(<CloudAlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({
        type: 'cloud_event',
        data: makeCloudEvent({ id: 'dup-id', event_type: 'DescribeInstances' }),
      })
    })

    expect(screen.getByText('DescribeInstances')).toBeInTheDocument()

    act(() => {
      es!.simulateMessage({
        type: 'cloud_event',
        data: makeCloudEvent({ id: 'dup-id', event_type: 'DescribeInstances' }),
      })
    })

    const toasts = screen.queryAllByText('DescribeInstances')
    expect(toasts).toHaveLength(1)
  })

  it('Azure の suspicious イベントでも "⚠ SUSPICIOUS" バッジが表示されること', () => {
    render(<CloudAlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      es!.simulateMessage({
        type: 'cloud_event',
        data: makeCloudEvent({
          id: 'azure-1',
          provider: 'azure',
          event_type: 'Microsoft.Authorization/roleAssignments/write',
        }),
      })
    })

    expect(screen.getByText('⚠ SUSPICIOUS')).toBeInTheDocument()
  })

  it('MAX_TOASTS (4) を超えた場合に古いものが削除されること', () => {
    render(<CloudAlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    // 5 件のイベントを送信
    act(() => {
      for (let i = 1; i <= 5; i++) {
        es!.simulateMessage({
          type: 'cloud_event',
          data: makeCloudEvent({ id: `evt-${i}`, event_type: `Event${i}` }),
        })
      }
    })

    // 最古のイベントが削除されていること
    expect(screen.queryByText('Event1')).toBeNull()
    expect(screen.getByText('Event2')).toBeInTheDocument()
    expect(screen.getByText('Event5')).toBeInTheDocument()
  })

  it('不正なペイロードを無視すること', () => {
    render(<CloudAlertToastContainer />)
    const es = getMockES()
    expect(es).not.toBeNull()

    act(() => {
      // id なし
      es!.simulateMessage({ type: 'cloud_event', data: { event_type: 'NoIdEvent' } })
      // event_type なし
      es!.simulateMessage({ type: 'cloud_event', data: { id: 'some-id' } })
      // 不正な JSON
      if (es!.onmessage) {
        const evt = new MessageEvent('message', { data: 'bad json' })
        es!.onmessage(evt)
      }
    })

    expect(screen.queryByText('NoIdEvent')).toBeNull()
  })
})
