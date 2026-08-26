import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import { join } from 'path'

// サーバは読み取りに失敗したとき 200 と空のリストを返すのをやめました。
// しかしそれだけでは運用担当の画面は変わりません。data が undefined に
// なったとき `?? []` / `?? 0` でそのまま 0件・0 が描かれるからです。
//
// この差が埋まったかどうかは、ページを1つずつ直したかどうかでしか決まり
// ません。ここはその進み具合を固定します — 直した画面が黙って戻ることは
// なく、残りが何ページあるかが常に見えている状態にします。

const APP = join(process.cwd(), 'app')

function pageFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) {
      pageFiles(p, out)
    } else if (name === 'page.tsx') {
      out.push(p)
    }
  }
  return out
}

const rel = (p: string) => p.slice(APP.length + 1).replace(/\\/g, '/')

/**
 * 取得失敗を画面上で伝えるようにしたページ。
 *
 * これは待機リストではなく達成リストです。ここから外れることは、その画面が
 * 「0件」を事実として表示する状態に戻ることを意味します。
 */
const PAGES_WITH_HONEST_ERROR_STATE = [
  'alerts/page.tsx',
  'endpoints/page.tsx',
]

/**
 * データを取りに行くページのうち、まだ取得失敗を画面で伝えていない数。
 *
 * 0 です。347ページすべてが帯を持っているので、これは上限ではなく契約に
 * なりました。取りに行くページが新しくできて帯を持たなければ、ここで落ちます。
 */
const UNCONVERTED_PAGE_CEILING = 0

describe('取得失敗の画面表示', () => {
  const pages = pageFiles(APP)

  it('走査がページを見つけている', () => {
    expect(pages.length).toBeGreaterThan(20)
  })

  it.each(PAGES_WITH_HONEST_ERROR_STATE)('%s は取得失敗を画面で伝える', page => {
    const src = readFileSync(join(APP, page), 'utf8')
    expect(src, `${page} が帯を取り込んでいません`).toMatch(
      /from '@\/components\/(Page)?DataUnavailable'/
    )
    expect(src, `${page} が DataUnavailable を描画していません`).toMatch(/<(Page)?DataUnavailable\b/)
  })

  it('描画せずに import だけしているページが無い', () => {
    const importedButUnused = pages
      .map(p => ({ page: rel(p), src: readFileSync(p, 'utf8') }))
      .filter(({ src }) => /from '@\/components\/(Page)?DataUnavailable'/.test(src))
      .filter(({ src }) => !/<(Page)?DataUnavailable\b/.test(src))
      .map(({ page }) => page)
    expect(importedButUnused).toEqual([])
  })

  it('取りに行くページはすべて取得失敗を画面で伝える', () => {
    // 分母はデータを取りに行くページだけ。取得しないページに帯は要りません。
    const fetching = pages.filter(p => readFileSync(p, 'utf8').includes('useQuery'))
    const converted = fetching.filter(p => /<(Page)?DataUnavailable\b/.test(readFileSync(p, 'utf8')))
    const unconverted = fetching.length - converted.length

    expect(ratchetProblem(unconverted, UNCONVERTED_PAGE_CEILING)).toBeNull()
  })

  // ラチェットの判定そのもの。実測が上限とちょうど一致している通常状態では
  // どちらの分岐にも入らないので、外しても何も変わりません。ここで直接
  // 動かします。
  it.each([
    { actual: 0, ceiling: 0, expected: null },
    { actual: 1, ceiling: 0, expected: /増えています/ },
    { actual: 47, ceiling: 47, expected: null },
    { actual: 48, ceiling: 47, expected: /増えています/ },
    { actual: 46, ceiling: 47, expected: /下げてください/ },
  ])('ラチェット判定: $actual / $ceiling', ({ actual, ceiling, expected }) => {
    const got = ratchetProblem(actual, ceiling)
    if (expected === null) {
      expect(got).toBeNull()
    } else {
      expect(got).toMatch(expected)
    }
  })
})

/** 未対応ページ数と上限を突き合わせ、問題があればその内容を返す。 */
export function ratchetProblem(unconverted: number, ceiling: number): string | null {
  if (unconverted > ceiling) {
    return `未対応ページが ${ceiling} から ${unconverted} に増えています`
  }
  if (unconverted < ceiling) {
    // 上限を下げ忘れると、直したぶんだけ黙って戻せてしまいます。
    return (
      `未対応ページが ${unconverted} まで減りました。` +
      `UNCONVERTED_PAGE_CEILING を ${unconverted} に下げてください`
    )
  }
  return null
}
