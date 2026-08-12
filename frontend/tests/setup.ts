import '@testing-library/jest-dom'

// グローバルな EventSource モック
class MockEventSource {
  static instance: MockEventSource | null = null
  url: string
  onmessage: ((evt: MessageEvent) => void) | null = null
  onerror: ((evt: Event) => void) | null = null
  onopen: ((evt: Event) => void) | null = null
  readyState: number = 0 // CONNECTING

  constructor(url: string) {
    this.url = url
    MockEventSource.instance = this
    this.readyState = 1 // OPEN
  }

  close() {
    this.readyState = 2 // CLOSED
  }

  // テストから呼び出すヘルパー
  simulateMessage(data: unknown) {
    if (this.onmessage) {
      const evt = new MessageEvent('message', {
        data: typeof data === 'string' ? data : JSON.stringify(data),
      })
      this.onmessage(evt)
    }
  }
}

// EventSource をグローバルに設定
;(global as unknown as { EventSource: typeof MockEventSource }).EventSource = MockEventSource
;(global as unknown as { MockEventSource: typeof MockEventSource }).MockEventSource = MockEventSource

// グローバルな fetch モック
global.fetch = vi.fn()
