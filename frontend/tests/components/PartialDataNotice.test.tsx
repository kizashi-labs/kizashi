import { describe, it, expect, afterEach } from 'vitest'
import { render, screen, cleanup } from '@testing-library/react'
import { PartialDataNotice } from '@/components/PartialDataNotice'

afterEach(cleanup)

describe('一部だけ取得できなかったときの帯', () => {
  it('欠けが無ければ何も描かない', () => {
    const { container } = render(<PartialDataNotice missing={[]} />)
    expect(container).toBeEmptyDOMElement()
  })

  it('missing を渡さなくても何も描かない', () => {
    const { container } = render(<PartialDataNotice />)
    expect(container).toBeEmptyDOMElement()
  })

  it('欠けたものの名前を並べる', () => {
    render(<PartialDataNotice missing={['脆弱性統計', '検知統計']} />)
    expect(screen.getByRole('alert').textContent).toContain('脆弱性統計、検知統計')
  })

  // 0 と書いてあるのに実際は取れていない、というのがこの帯の言うことです。
  it('0 が実際の値ではないと書く', () => {
    render(<PartialDataNotice missing={['脆弱性統計']} />)
    const text = screen.getByRole('alert').textContent ?? ''
    expect(text).toContain('一部を取得できませんでした')
    expect(text).toContain('実際の値ではありません')
  })

  // 画面全体が落ちたときの DataUnavailable と混ざらないこと。こちらは
  // 「一部」であって、残りの数字は本物です。
  it('画面全体が取得できなかったとは言わない', () => {
    render(<PartialDataNotice missing={['検知統計']} />)
    expect(screen.getByRole('alert').textContent).not.toContain('この画面に表示されている件数は実際の値ではありません')
  })
})
