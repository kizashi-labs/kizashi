import { describe, it, expect, afterEach, vi } from 'vitest'
import { render, screen, cleanup, waitFor, act } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { QueryClient, QueryClientProvider, useMutation } from '@tanstack/react-query'
import { PageSaveFailed } from '@/components/PageSaveFailed'

afterEach(cleanup)

function wrap(ui: React.ReactNode, qc = new QueryClient({ defaultOptions: { mutations: { retry: false } } })) {
  return render(<QueryClientProvider client={qc}>{ui}</QueryClientProvider>)
}

function Saver({
  fail,
  label = '保存',
  message = '502 Bad Gateway',
}: {
  fail: boolean
  label?: string
  message?: string
}) {
  const mut = useMutation({
    mutationFn: async () => {
      if (fail) throw new Error(message)
      return { ok: true }
    },
  })
  return <button onClick={() => mut.mutate()}>{label}</button>
}

describe('保存できなかったときの帯', () => {
  it('何も保存していなければ描かない', () => {
    const { container } = wrap(<PageSaveFailed />)
    expect(container.querySelector('[role="alert"]')).toBeNull()
  })

  it('保存が成功しても描かない', async () => {
    wrap(
      <>
        <PageSaveFailed />
        <Saver fail={false} />
      </>
    )
    await userEvent.click(screen.getByText('保存'))
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
  })

  it('保存が失敗したら、届いていないと言う', async () => {
    wrap(
      <>
        <PageSaveFailed />
        <Saver fail />
      </>
    )
    await userEvent.click(screen.getByText('保存'))
    const alert = await screen.findByRole('alert')
    expect(alert.textContent).toContain('保存できませんでした')
    expect(alert.textContent).toContain('サーバには反映されていません')
    expect(alert.textContent).toContain('502 Bad Gateway')
  })

  it('what を渡すと何の保存かを言う', async () => {
    wrap(
      <>
        <PageSaveFailed what="通知ルール" />
        <Saver fail />
      </>
    )
    await userEvent.click(screen.getByText('保存'))
    expect((await screen.findByRole('alert')).textContent).toContain('通知ルールを保存できませんでした')
  })

  it('閉じられる', async () => {
    wrap(
      <>
        <PageSaveFailed />
        <Saver fail />
      </>
    )
    await userEvent.click(screen.getByText('保存'))
    await screen.findByRole('alert')
    await userEvent.click(screen.getByLabelText('閉じる'))
    await waitFor(() => expect(screen.queryByRole('alert')).toBeNull())
  })

  // ここが肝心です。react-query は失敗した mutation を数分キャッシュに残すので、
  // 単に status === 'error' を集めると、前に見ていた画面の失敗が今の画面の帯に
  // なります。PageDataUnavailable が observer 数で同じ問題を避けているのと同じ話です。
  it('この画面を開く前の失敗は出さない', async () => {
    const qc = new QueryClient({ defaultOptions: { mutations: { retry: false } } })

    // 前の画面での失敗
    await act(async () => {
      await qc
        .getMutationCache()
        .build(qc, { mutationFn: async () => { throw new Error('前の画面') } })
        .execute(undefined)
        .catch(() => {})
    })

    // その後にこの画面を開く
    wrap(<PageSaveFailed />, qc)
    expect(screen.queryByRole('alert')).toBeNull()
  })

  // 上の検査は、前の画面の失敗と mount のあいだにミリ秒の境目が入れば
  // 通ってしまいます。**入るかどうかは機械の速さ次第で、通ったほうが
  // 正しく見えます。** 時計を止めて、必ず同じミリ秒に入れます。
  it('前の画面の失敗と同じミリ秒に開いても、出さない', async () => {
    const qc = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
    const frozen = vi.spyOn(Date, 'now').mockReturnValue(1_000_000)
    try {
      await act(async () => {
        await qc
          .getMutationCache()
          .build(qc, { mutationFn: async () => { throw new Error('前の画面') } })
          .execute(undefined)
          .catch(() => {})
      })

      wrap(<PageSaveFailed />, qc)
      expect(screen.queryByRole('alert')).toBeNull()
    } finally {
      frozen.mockRestore()
    }
  })

  it('開いたあとの失敗は出す', async () => {
    const qc = new QueryClient({ defaultOptions: { mutations: { retry: false } } })
    wrap(
      <>
        <PageSaveFailed />
        <Saver fail />
      </>,
      qc
    )
    await userEvent.click(screen.getByText('保存'))
    expect((await screen.findByRole('alert')).textContent).toContain('保存できませんでした')
  })

  // 直近の失敗を出します。1件しか失敗していない状態では「直近」も「最初」も
  // 同じものを指すので、2件で分けます。
  it('直近の失敗の理由を出す', async () => {
    wrap(
      <>
        <PageSaveFailed />
        <Saver fail label="A" message="古い失敗" />
        <Saver fail label="B" message="新しい失敗" />
      </>
    )
    await userEvent.click(screen.getByText('A'))
    await screen.findByRole('alert')
    await userEvent.click(screen.getByText('B'))
    await waitFor(() => expect(screen.getByRole('alert').textContent).toContain('新しい失敗'))
    expect(screen.getByRole('alert').textContent).not.toContain('古い失敗')
  })

  it('複数失敗したら件数を出す', async () => {
    wrap(
      <>
        <PageSaveFailed />
        <Saver fail label="A" />
        <Saver fail label="B" />
      </>
    )
    await userEvent.click(screen.getByText('A'))
    await userEvent.click(screen.getByText('B'))
    await waitFor(() =>
      expect(screen.getByRole('alert').textContent).toContain('2件の保存が失敗しています')
    )
  })
})
