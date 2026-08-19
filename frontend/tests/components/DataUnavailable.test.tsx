import { describe, it, expect, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { DataUnavailable } from '@/components/DataUnavailable'

// サーバは読み取りに失敗したとき 200 と空のリストを返すのをやめ、500 を
// 返すようになりました。しかし画面は data が undefined になったとき
// `?? []` / `?? 0` でそのまま 0件・0 を描画します。
//
// 「脆弱性0件」「未対応アラート0件」は SOC が行動を決める情報です。
// それが「取得できなかった」であることは、画面の中で言われなければ
// 伝わりません。この帯が黙ると、サーバを正直にした意味が消えます。

describe('DataUnavailable', () => {
  it('エラーが無ければ何も描画しない — 一覧の上に置きっぱなしにできる', () => {
    const { container } = render(<DataUnavailable error={undefined} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('errors がすべて undefined でも何も描画しない', () => {
    const { container } = render(<DataUnavailable errors={[undefined, null, undefined]} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('エラーがあれば「表示されている件数は実際の値ではない」と言う', () => {
    render(<DataUnavailable error={new Error('HTTP 500')} what="脆弱性" />)
    expect(screen.getByRole('alert')).toBeInTheDocument()
    expect(screen.getByText(/脆弱性を取得できませんでした/)).toBeInTheDocument()
    expect(screen.getByText(/実際の値ではありません/)).toBeInTheDocument()
  })

  it('what が無くても成立する', () => {
    render(<DataUnavailable error={new Error('x')} />)
    expect(screen.getByText(/データを取得できませんでした/)).toBeInTheDocument()
  })

  it('複数のクエリのうち1つでも失敗していれば表示する', () => {
    render(<DataUnavailable errors={[undefined, new Error('HTTP 500'), undefined]} what="脅威情報" />)
    expect(screen.getByRole('alert')).toBeInTheDocument()
  })

  it('複数失敗しているときはその件数を言う', () => {
    render(<DataUnavailable errors={[new Error('a'), new Error('b')]} />)
    expect(screen.getByText(/2件の取得が失敗しています/)).toBeInTheDocument()
  })

  it('サーバのメッセージを出す — 原因の切り分けに要る', () => {
    render(<DataUnavailable error={new Error('データベース操作に失敗しました')} />)
    expect(screen.getByText('データベース操作に失敗しました')).toBeInTheDocument()
  })

  it('onRetry が無ければ再試行ボタンを出さない', () => {
    render(<DataUnavailable error={new Error('x')} />)
    expect(screen.queryByRole('button', { name: /再試行/ })).not.toBeInTheDocument()
  })

  it('onRetry があれば押せる', async () => {
    const onRetry = vi.fn()
    render(<DataUnavailable error={new Error('x')} onRetry={onRetry} />)
    await userEvent.click(screen.getByRole('button', { name: /再試行/ }))
    expect(onRetry).toHaveBeenCalledTimes(1)
  })

  // 支援技術に届かないと、スクリーンリーダー利用者には 0件 のままです。
  it('role="alert" を付ける', () => {
    render(<DataUnavailable error={new Error('x')} />)
    expect(screen.getByRole('alert')).toBeInTheDocument()
  })
})
