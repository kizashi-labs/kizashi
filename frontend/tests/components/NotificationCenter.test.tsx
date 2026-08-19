import { describe, it, expect, afterEach, vi, beforeEach } from 'vitest'
import { render, screen, cleanup, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { NotificationCenter } from '@/components/notifications/NotificationCenter'

// ヘッダーの通知ベルは全画面に出ます。
//
// 以前ここは USE_MOCK を見ておらず、APIが落ちたときも、正常に0件を返した
// ときも作り物に切り替わっていました。出ていたのは
//
//   Critical: Mimikatz Detected — WORKSTATION-04 で認証情報の窃取をブロック
//   Agent Offline — agent-linux-02 が12分前からオフライン
//   New Incident Created — Lateral Movement Campaign, HIGH, 3端末
//
// の5件です。存在しない端末の、起きていない検知が、どのテナントのどの画面
// でも同じ内容で出ます。そして未読0件は「取得できなかった」でも
// 「デモを見せるべき」でもありません。
//
// テストでは NEXT_PUBLIC_USE_MOCK が未設定なので USE_MOCK は false です。
// つまりここで確かめているのは本番と同じ経路です。

vi.mock('next/navigation', () => ({ useRouter: () => ({ push: vi.fn() }) }))

const MOCK_TEXT = 'Mimikatz'

afterEach(cleanup)
beforeEach(() => vi.restoreAllMocks())

function wrap(fetchImpl: typeof fetch) {
  vi.stubGlobal('fetch', fetchImpl)
  const qc = new QueryClient({
    defaultOptions: { queries: { retry: false }, mutations: { retry: false } },
  })
  return render(
    <QueryClientProvider client={qc}>
      <NotificationCenter />
    </QueryClientProvider>
  )
}

const ok = (body: unknown) =>
  Promise.resolve({ ok: true, status: 200, json: () => Promise.resolve(body) } as Response)

describe('ヘッダーの通知ベル', () => {
  it('取得できなかったときに作り物を出さない', async () => {
    wrap((() => Promise.reject(new Error('down'))) as unknown as typeof fetch)
    await userEvent.click(screen.getByRole('button', { name: /通知|notification/i }))

    await waitFor(() => expect(screen.getByRole('alert')).toBeTruthy())
    expect(screen.getByRole('alert').textContent).toContain('通知を取得できませんでした')
    expect(screen.queryByText(new RegExp(MOCK_TEXT))).toBeNull()
  })

  it('取得できなかったことと、0件であることを言い分ける', async () => {
    wrap((() => Promise.reject(new Error('down'))) as unknown as typeof fetch)
    await userEvent.click(screen.getByRole('button', { name: /通知|notification/i }))

    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('未読が0件なのではありません')
    expect(screen.queryByText('通知はありません')).toBeNull()
  })

  it('本当に0件のときは0件と言う', async () => {
    wrap((() => ok([])) as unknown as typeof fetch)
    await userEvent.click(screen.getByRole('button', { name: /通知|notification/i }))

    await waitFor(() => expect(screen.getByText('通知はありません')).toBeTruthy())
    expect(screen.queryByText(new RegExp(MOCK_TEXT))).toBeNull()
    expect(screen.queryByText('通知を取得できませんでした')).toBeNull()
  })

  it('サーバが返した通知はそのまま出す', async () => {
    wrap((() =>
      ok([
        {
          id: 'n1',
          type: 'alert_critical',
          title: '本物のアラート',
          message: 'サーバから来ました',
          read: false,
          created_at: new Date().toISOString(),
          link: '/alerts',
        },
      ])) as unknown as typeof fetch)
    await userEvent.click(screen.getByRole('button', { name: /通知|notification/i }))

    await waitFor(() => expect(screen.getByText('本物のアラート')).toBeTruthy())
    expect(screen.queryByText(new RegExp(MOCK_TEXT))).toBeNull()
  })
})
