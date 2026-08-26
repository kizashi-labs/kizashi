import { describe, it, expect } from 'vitest'
import { readInto } from '@/lib/partial'

// readInto は「届いたものは残す、届かなかったものは名前を残す」だけの関数で、
// 集約クエリの .catch を置き換えるためにあります。置き換える意味があるのは
// 2つ目の性質なので、そこを直接動かします。

describe('部分的に取得できたとき', () => {
  it('取得できたらそのまま返し、名前は残さない', async () => {
    const missing: string[] = []
    const v = await readInto(missing, '脆弱性統計', Promise.resolve({ total: 7 }), { total: 0 })
    expect(v).toEqual({ total: 7 })
    expect(missing).toEqual([])
  })

  it('取得できなければ fallback を返し、名前を残す', async () => {
    const missing: string[] = []
    const v = await readInto(missing, '脆弱性統計', Promise.reject(new Error('500')), { total: 0 })
    expect(v).toEqual({ total: 0 })
    expect(missing).toEqual(['脆弱性統計'])
  })

  it('落ちた分だけを、呼んだ順に集める', async () => {
    const missing: string[] = []
    await Promise.all([
      readInto(missing, '資産の稼働状況', Promise.resolve(1), 0),
      readInto(missing, '検知統計', Promise.reject(new Error('x')), 0),
      readInto(missing, '脆弱性統計', Promise.reject(new Error('y')), 0),
    ])
    expect(missing).toEqual(['検知統計', '脆弱性統計'])
  })

  // ここが要点です。以前の .catch は Promise.all を必ず解決させたので、
  // 集約クエリは「全部取れた」と見分けがつきませんでした。readInto も
  // Promise.all を解決させますが、何が欠けたかは残ります。
  it('1本落ちても、届いた分は消えない', async () => {
    const missing: string[] = []
    const [a, b] = await Promise.all([
      readInto(missing, '検知統計', Promise.resolve({ n: 42 }), { n: 0 }),
      readInto(missing, '脆弱性統計', Promise.reject(new Error('down')), { n: 0 }),
    ])
    expect(a).toEqual({ n: 42 })
    expect(b).toEqual({ n: 0 })
    expect(missing).toEqual(['脆弱性統計'])
  })

  it('falsy な値でも、取得できたことと取得できなかったことは別', async () => {
    const missing: string[] = []
    expect(await readInto(missing, '件数', Promise.resolve(0), -1)).toBe(0)
    expect(missing).toEqual([])
    expect(await readInto(missing, '件数', Promise.reject(new Error('x')), -1)).toBe(-1)
    expect(missing).toEqual(['件数'])
  })
})
