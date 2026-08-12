import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { renderHook, act, waitFor } from '@testing-library/react'
import { useWebSocket } from '@/lib/useWebSocket'

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
  readyState = WebSocket.CONNECTING

  static OPEN = 1

  constructor(url: string) {
    this.url = url
    mockWSInstance = this as unknown as MockWSInstance
  }

  simulateOpen() {
    this.readyState = WebSocket.OPEN
    this.onopen?.()
  }

  simulateMessage(data: unknown) {
    const evt = new MessageEvent('message', {
      data: typeof data === 'string' ? data : JSON.stringify(data),
    })
    this.onmessage?.(evt)
  }

  simulateClose() {
    this.readyState = WebSocket.CLOSED
    this.onclose?.()
  }

  simulateError() {
    this.onerror?.(new Event('error'))
  }
}

beforeEach(() => {
  mockWSInstance = null
  vi.useFakeTimers()
  localStorage.setItem('token', 'test-jwt-token')
  ;(global as unknown as { WebSocket: typeof MockWebSocket }).WebSocket = MockWebSocket
})

afterEach(() => {
  localStorage.clear()
  vi.useRealTimers()
  vi.clearAllMocks()
})

// ─── テスト ────────────────────────────────────────────────────────────────────

describe('useWebSocket', () => {
  it('localStorage に token がない場合は接続しないこと', () => {
    localStorage.clear()
    renderHook(() => useWebSocket())
    expect(mockWSInstance).toBeNull()
  })

  it('token がある場合に WebSocket が生成されること', () => {
    renderHook(() => useWebSocket())
    expect(mockWSInstance).not.toBeNull()
  })

  it('接続完了後に connected=true になること', () => {
    const { result } = renderHook(() => useWebSocket())

    expect(result.current.connected).toBe(false)

    act(() => {
      ;(mockWSInstance as unknown as MockWebSocket).simulateOpen()
    })

    expect(result.current.connected).toBe(true)
  })

  it('onConnect コールバックが呼ばれること', () => {
    const onConnect = vi.fn()
    renderHook(() => useWebSocket({ onConnect }))

    act(() => {
      ;(mockWSInstance as unknown as MockWebSocket).simulateOpen()
    })

    expect(onConnect).toHaveBeenCalledOnce()
  })

  it('接続後に auth token が送信されること', () => {
    renderHook(() => useWebSocket())

    act(() => {
      ;(mockWSInstance as unknown as MockWebSocket).simulateOpen()
    })

    expect(mockWSInstance!.send).toHaveBeenCalledWith(
      JSON.stringify({ token: 'test-jwt-token' })
    )
  })

  it('onMessage コールバックがメッセージ受信時に呼ばれること', () => {
    const onMessage = vi.fn()
    renderHook(() => useWebSocket({ onMessage }))

    act(() => {
      ;(mockWSInstance as unknown as MockWebSocket).simulateOpen()
      ;(mockWSInstance as unknown as MockWebSocket).simulateMessage({
        type: 'new_alert',
        timestamp: '2026-03-20T00:00:00Z',
        data: { id: 'a1', title: 'Test' },
      })
    })

    expect(onMessage).toHaveBeenCalledOnce()
    expect(onMessage.mock.calls[0][0]).toMatchObject({
      type: 'new_alert',
      data: { id: 'a1', title: 'Test' },
    })
  })

  it('lastMessage がメッセージ受信時に更新されること', () => {
    const { result } = renderHook(() => useWebSocket())

    act(() => {
      ;(mockWSInstance as unknown as MockWebSocket).simulateOpen()
      ;(mockWSInstance as unknown as MockWebSocket).simulateMessage({
        type: 'ping',
        timestamp: '2026-03-20T00:00:00Z',
        data: {},
      })
    })

    expect(result.current.lastMessage?.type).toBe('ping')
  })

  it('不正な JSON メッセージを無視してクラッシュしないこと', () => {
    renderHook(() => useWebSocket())

    expect(() => {
      act(() => {
        ;(mockWSInstance as unknown as MockWebSocket).simulateOpen()
        if (mockWSInstance?.onmessage) {
          mockWSInstance.onmessage(new MessageEvent('message', { data: 'bad json' }))
        }
      })
    }).not.toThrow()
  })

  it('切断時に connected=false になること', () => {
    const { result } = renderHook(() => useWebSocket({ reconnectInterval: 99999 }))

    act(() => {
      ;(mockWSInstance as unknown as MockWebSocket).simulateOpen()
    })
    expect(result.current.connected).toBe(true)

    act(() => {
      ;(mockWSInstance as unknown as MockWebSocket).simulateClose()
    })
    expect(result.current.connected).toBe(false)
  })

  it('onDisconnect コールバックが切断時に呼ばれること', () => {
    const onDisconnect = vi.fn()
    renderHook(() => useWebSocket({ onDisconnect, reconnectInterval: 99999 }))

    act(() => {
      ;(mockWSInstance as unknown as MockWebSocket).simulateOpen()
      ;(mockWSInstance as unknown as MockWebSocket).simulateClose()
    })

    expect(onDisconnect).toHaveBeenCalledOnce()
  })

  it('切断後に指定インターバルで再接続を試みること', () => {
    renderHook(() => useWebSocket({ reconnectInterval: 1000 }))

    // renderHook 後に生成された最初の WS インスタンスを保存
    const firstInstance = mockWSInstance
    expect(firstInstance).not.toBeNull()

    act(() => {
      ;(mockWSInstance as unknown as MockWebSocket).simulateOpen()
      ;(mockWSInstance as unknown as MockWebSocket).simulateClose()
    })

    // タイムアウト前はまだ同じインスタンス
    expect(mockWSInstance).toBe(firstInstance)

    // 1000ms 経過後に新しい WebSocket が生成される
    act(() => {
      vi.advanceTimersByTime(1000)
    })

    expect(mockWSInstance).not.toBe(firstInstance)
  })

  it('エラー発生時に ws.close() が呼ばれること', () => {
    renderHook(() => useWebSocket())

    const closeSpy = vi.spyOn(mockWSInstance!, 'close')

    act(() => {
      ;(mockWSInstance as unknown as MockWebSocket).simulateError()
    })

    expect(closeSpy).toHaveBeenCalledOnce()
  })

  it('アンマウント時に WebSocket が閉じられること', () => {
    const { unmount } = renderHook(() => useWebSocket())

    act(() => {
      ;(mockWSInstance as unknown as MockWebSocket).simulateOpen()
    })

    const closeSpy = vi.spyOn(mockWSInstance!, 'close')
    unmount()

    expect(closeSpy).toHaveBeenCalledOnce()
  })

  it('send() が OPEN 状態のときにデータを送信すること', () => {
    const { result } = renderHook(() => useWebSocket())

    act(() => {
      ;(mockWSInstance as unknown as MockWebSocket).simulateOpen()
    })

    act(() => {
      result.current.send({ action: 'subscribe', channel: 'alerts' })
    })

    expect(mockWSInstance!.send).toHaveBeenCalledWith(
      JSON.stringify({ action: 'subscribe', channel: 'alerts' })
    )
  })
})
