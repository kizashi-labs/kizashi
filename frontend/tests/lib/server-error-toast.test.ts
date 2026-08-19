import { describe, it, expect, beforeEach, vi, afterEach } from 'vitest'
import { apiFetch, registerServerErrorHandler } from '@/lib/api'

// サーバは読み取りに失敗したとき 200 と空のリストを返すのをやめ、500 を
// 返すようになりました。ただし useQuery のエラー状態を見ている画面は
// 348 中 57 だけで、残りは data が undefined になったときに `?? []` /
// `?? 0` でそのまま 0件・0 を描画します。
//
// つまりサーバを正直にしただけでは、運用担当の画面は以前と同じ「該当なし」の
// ままです。この通知はその差を埋めるためのもので、ページ側のエラー表示が
// 揃うまでの下支えです。ここが黙ると、修正の効果は誰にも見えません。

function mockFetch(status: number, body: unknown = {}) {
  return vi.fn().mockResolvedValue({
    ok: status >= 200 && status < 300,
    status,
    headers: { get: () => null },
    json: async () => body,
  })
}

describe('サーバ障害の通知', () => {
  let messages: string[]
  // 静穏時間はモジュール内に持つので、テストごとに時計を先へ進めて
  // 前のテストの通知が次を抑え込まないようにする。
  let clock = Date.now()

  beforeEach(() => {
    messages = []
    registerServerErrorHandler(m => messages.push(m))
    clock += 60_000
    vi.useFakeTimers({ now: clock })
  })

  afterEach(() => {
    vi.useRealTimers()
    vi.unstubAllGlobals()
  })

  it('500 を受け取ったら通知する', async () => {
    vi.stubGlobal('fetch', mockFetch(500, { error: 'データベース操作に失敗しました' }))
    await expect(apiFetch('/api/v1/vulnerabilities')).rejects.toThrow()
    expect(messages).toHaveLength(1)
    expect(messages[0]).toContain('/api/v1/vulnerabilities')
    expect(messages[0]).toContain('実際の値ではありません')
  })

  it('503 も通知する', async () => {
    vi.stubGlobal('fetch', mockFetch(503))
    await expect(apiFetch('/api/v1/alerts')).rejects.toThrow()
    expect(messages).toHaveLength(1)
  })

  it('正常な応答では通知しない', async () => {
    vi.stubGlobal('fetch', mockFetch(200, { items: [] }))
    await apiFetch('/api/v1/alerts')
    expect(messages).toHaveLength(0)
  })

  it('404 では通知しない — サーバは答えている', async () => {
    vi.stubGlobal('fetch', mockFetch(404))
    await expect(apiFetch('/api/v1/alerts/missing')).rejects.toThrow()
    expect(messages).toHaveLength(0)
  })

  it('同じ画面から同時に失敗しても通知は1つ', async () => {
    vi.stubGlobal('fetch', mockFetch(500))
    await Promise.all([
      apiFetch('/api/v1/a').catch(() => {}),
      apiFetch('/api/v1/b').catch(() => {}),
      apiFetch('/api/v1/c').catch(() => {}),
    ])
    expect(messages).toHaveLength(1)
  })

  it('静穏時間を過ぎればまた通知する — 続く障害が黙るわけではない', async () => {
    vi.stubGlobal('fetch', mockFetch(500))
    await apiFetch('/api/v1/a').catch(() => {})
    expect(messages).toHaveLength(1)

    vi.advanceTimersByTime(6000)
    await apiFetch('/api/v1/b').catch(() => {})
    expect(messages).toHaveLength(2)
  })

  // 501 は「まだ実装されていません」であって障害ではありません。同じ通知を
  // 出すと、決して直らないものに再試行を促すことになります。
  it('501 では通知しない — 障害ではなく未実装', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue({
      ok: false, status: 501,
      headers: { get: () => null },
      json: async () => ({ error: '攻撃元の国別分布はまだ実装されていません', not_implemented: true }),
    }))
    const messages: string[] = []
    registerServerErrorHandler(m => messages.push(m))
    await expect(apiFetch('/api/v1/alerts/geo-stats')).rejects.toThrow()
    expect(messages).toHaveLength(0)
  })
})
