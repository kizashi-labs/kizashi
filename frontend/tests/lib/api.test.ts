import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest'
import { apiFetch } from '@/lib/api'

// window.location のモック（401 時のリダイレクト用）
const mockLocationAssign = vi.fn()
Object.defineProperty(window, 'location', {
  value: {
    href: '',
    assign: mockLocationAssign,
  },
  writable: true,
})

describe('apiFetch', () => {
  beforeEach(() => {
    vi.clearAllMocks()
    localStorage.clear()
    // fetch をリセット
    vi.mocked(global.fetch).mockReset()
  })

  afterEach(() => {
    localStorage.clear()
  })

  it('正常な JSON レスポンスを返すこと', async () => {
    const mockData = { id: 1, name: 'test' }
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify(mockData), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    )

    const result = await apiFetch<typeof mockData>('/api/v1/test')
    expect(result).toEqual(mockData)
  })

  it('401 で throw すること (Unauthorized)', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      })
    )

    await expect(apiFetch('/api/v1/protected')).rejects.toThrow('認証が必要です')
  })

  it('401 時に localStorage の edr_token と edr_user が削除されること', async () => {
    localStorage.setItem('edr_token', 'test-token')
    localStorage.setItem('edr_user', JSON.stringify({ id: '1', email: 'test@test.com' }))

    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'Unauthorized' }), {
        status: 401,
        headers: { 'Content-Type': 'application/json' },
      })
    )

    await expect(apiFetch('/api/v1/protected')).rejects.toThrow('認証が必要です')

    expect(localStorage.getItem('edr_token')).toBeNull()
    expect(localStorage.getItem('edr_user')).toBeNull()
  })

  it('Authorization ヘッダーが付与されること', async () => {
    const token = 'my-bearer-token'
    localStorage.setItem('edr_token', token)

    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    )

    await apiFetch('/api/v1/test')

    expect(vi.mocked(global.fetch)).toHaveBeenCalledOnce()
    const [, options] = vi.mocked(global.fetch).mock.calls[0]
    expect((options as RequestInit).headers).toMatchObject({
      Authorization: `Bearer ${token}`,
    })
  })

  it('トークンがない場合に Authorization ヘッダーが付与されないこと', async () => {
    // localStorage にトークンなし
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    )

    await apiFetch('/api/v1/test')

    const [, options] = vi.mocked(global.fetch).mock.calls[0]
    expect((options as RequestInit & { headers: Record<string, string> }).headers).not.toHaveProperty('Authorization')
  })

  it('エラーレスポンスの error フィールドをメッセージとして使用すること', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ error: 'Resource not found' }), {
        status: 404,
        headers: { 'Content-Type': 'application/json' },
      })
    )

    await expect(apiFetch('/api/v1/missing')).rejects.toThrow('Resource not found')
  })

  it('error フィールドがない場合は HTTP ステータスコードをメッセージとして使用すること', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({}), {
        status: 500,
        headers: { 'Content-Type': 'application/json' },
      })
    )

    await expect(apiFetch('/api/v1/error')).rejects.toThrow('HTTP 500')
  })

  it('Content-Type: application/json ヘッダーが常に付与されること', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    )

    await apiFetch('/api/v1/test')

    const [, options] = vi.mocked(global.fetch).mock.calls[0]
    expect((options as RequestInit).headers).toMatchObject({
      'Content-Type': 'application/json',
    })
  })

  it('呼び出し元から渡した options が fetch に引き渡されること', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response(JSON.stringify({ ok: true }), {
        status: 200,
        headers: { 'Content-Type': 'application/json' },
      })
    )

    await apiFetch('/api/v1/test', {
      method: 'POST',
      body: JSON.stringify({ key: 'value' }),
    })

    const [url, options] = vi.mocked(global.fetch).mock.calls[0]
    expect(url).toBe('/api/v1/test')
    expect((options as RequestInit).method).toBe('POST')
    expect((options as RequestInit).body).toBe(JSON.stringify({ key: 'value' }))
  })

  it('エラーレスポンスのボディが JSON でない場合に HTTP ステータスコードをメッセージとして使用すること', async () => {
    vi.mocked(global.fetch).mockResolvedValueOnce(
      new Response('Internal Server Error', {
        status: 503,
        headers: { 'Content-Type': 'text/plain' },
      })
    )

    await expect(apiFetch('/api/v1/error')).rejects.toThrow('HTTP 503')
  })
})
