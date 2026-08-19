import { describe, it, expect, vi } from 'vitest'
import { render, screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider, useQuery } from '@tanstack/react-query'
import { PageDataUnavailable } from '@/components/PageDataUnavailable'

// 6ページを手で直したやり方（クエリごとに error / refetch を取り出す）は
// 残り341ページには向きません。この版はクエリの配線を要求せず、
// 「いま画面に出ているクエリのうち失敗しているもの」を自分で見ます。
//
// 肝は observer 数です。TanStack のキャッシュには前に見ていた画面のクエリも
// 失敗したまま残るので、単に status==='error' を集めると、いま見ていない
// 画面の失敗を今の画面の帯として出してしまいます。それは逆向きの嘘です。

function client() {
  return new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: Infinity } },
  })
}

function Screen({ qc, children }: { qc: QueryClient; children: React.ReactNode }) {
  return <QueryClientProvider client={qc}>{children}</QueryClientProvider>
}

function Widget({ id, fn }: { id: string; fn: () => Promise<unknown> }) {
  const { data } = useQuery({ queryKey: [id], queryFn: fn })
  return <div data-testid={id}>{JSON.stringify(data ?? null)}</div>
}

describe('PageDataUnavailable', () => {
  it('すべて成功していれば何も描画しない', async () => {
    const qc = client()
    const { container } = render(
      <Screen qc={qc}>
        <Widget id="a" fn={async () => ({ ok: true })} />
        <PageDataUnavailable what="アラート" />
      </Screen>
    )
    await screen.findByText('{"ok":true}')
    expect(container.querySelector('[role="alert"]')).toBeNull()
  })

  it('画面のクエリが1つ失敗すれば帯を出す', async () => {
    const qc = client()
    render(
      <Screen qc={qc}>
        <Widget id="a" fn={async () => ({ ok: true })} />
        <Widget id="b" fn={async () => { throw new Error('HTTP 500') }} />
        <PageDataUnavailable what="アラート" />
      </Screen>
    )
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    expect(screen.getByText(/アラートを取得できませんでした/)).toBeInTheDocument()
  })

  // ここが本体。これが効かないと、前の画面の失敗が今の画面の嘘になります。
  it('もう画面に出ていないクエリの失敗は無視する', async () => {
    const qc = client()
    const { unmount } = render(
      <Screen qc={qc}>
        <Widget id="gone" fn={async () => { throw new Error('HTTP 500') }} />
      </Screen>
    )
    await waitFor(() =>
      expect(qc.getQueryCache().find({ queryKey: ['gone'] })?.state.status).toBe('error')
    )
    unmount()

    // キャッシュには失敗したまま残っている。
    expect(qc.getQueryCache().find({ queryKey: ['gone'] })?.state.status).toBe('error')

    const { container } = render(
      <Screen qc={qc}>
        <Widget id="fresh" fn={async () => ({ ok: true })} />
        <PageDataUnavailable />
      </Screen>
    )
    await screen.findByText('{"ok":true}')
    expect(
      container.querySelector('[role="alert"]'),
      '前の画面のクエリの失敗を、今の画面の帯として出しています'
    ).toBeNull()
  })

  it('再試行で画面のクエリを取り直す', async () => {
    const qc = client()
    const refetchSpy = vi.spyOn(qc, 'refetchQueries')
    render(
      <Screen qc={qc}>
        <Widget id="b" fn={async () => { throw new Error('HTTP 500') }} />
        <PageDataUnavailable />
      </Screen>
    )
    await waitFor(() => expect(screen.getByRole('alert')).toBeInTheDocument())
    await userEvent.click(screen.getByRole('button', { name: /再試行/ }))
    expect(refetchSpy).toHaveBeenCalledWith({ type: 'active' })
  })

  it('複数失敗していれば件数を言う', async () => {
    const qc = client()
    render(
      <Screen qc={qc}>
        <Widget id="a" fn={async () => { throw new Error('x') }} />
        <Widget id="b" fn={async () => { throw new Error('y') }} />
        <PageDataUnavailable />
      </Screen>
    )
    await waitFor(() => expect(screen.getByText(/2件の取得が失敗しています/)).toBeInTheDocument())
  })
})
