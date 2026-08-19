import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'

// The compliance scorecard endpoints now answer with a null score and a
// coverage pair — assessed_controls / total_controls — when the evidence behind
// a framework could not be read. Before that, every evidence query in
// server/internal/scorecard discarded its error, and a dead database produced a
// NIST CSF score of 35.3 against a healthy 42.5, with twenty-three named
// findings like "No hardening baselines configured".
//
// Both consumers on this side turned that null straight back into a number:
//
//   dashboard/page.tsx
//     const score = data?.score ?? data?.nist_score ?? 78  // mock fallback
//
//   admin/security-scorecard/page.tsx
//     const EMPTY_SCORECARD = { overall_score: 0, ... }
//     catch { return EMPTY_SCORECARD }
//
// The first renders "78 / Good" in green for a framework nothing was measured
// for; the second renders 0 in red, which an auditor reads as total
// non-compliance. Opposite directions, same defect — a number where there is no
// measurement.
//
// The dashboard's 78 is also an unguarded literal of exactly the kind
// CLAUDE.md's mock-data convention exists to prevent. It was not named MOCK_*,
// so no codemod ever saw it.
//
// These are source-level gates. Both pages are heavily interactive and the
// property worth pinning is narrow: neither may substitute a number for an
// absent one.

const DASHBOARD = path.join(__dirname, '..', '..', 'app', 'dashboard', 'page.tsx')
const SCORECARD = path.join(__dirname, '..', '..', 'app', 'admin', 'security-scorecard', 'page.tsx')

// Comments are stripped before scanning. Every fix below is documented by a
// comment that quotes the code it replaced, so a gate that reads comments finds
// the defect it just removed. `//` is only a comment when not preceded by `:`,
// so URLs survive.
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/(^|[^:])\/\/.*$/gm, '$1')
}

const dashboardSrc = stripComments(readFileSync(DASHBOARD, 'utf-8'))
const scorecardSrc = stripComments(readFileSync(SCORECARD, 'utf-8'))

// nistWidget isolates the widget so a `?? 78` elsewhere on a 1000-line
// dashboard cannot fail this, and so the scan cannot silently stop matching.
function nistWidget(): string {
  const start = dashboardSrc.indexOf('function NistScoreWidget')
  expect(start, 'NistScoreWidget が dashboard/page.tsx にありません').toBeGreaterThan(-1)
  const next = dashboardSrc.indexOf('\nfunction ', start + 1)
  return dashboardSrc.slice(start, next === -1 ? undefined : next)
}

describe('NIST スコアウィジェット', () => {
  it('計測されていないスコアを数値で埋めない', () => {
    const src = nistWidget()

    // The exact shape that produced "78 / Good" out of an outage. Scoped to the
    // lines that read the API's score — a count defaulting to 0 elsewhere in the
    // widget is not this defect.
    const scoreLines = src.split('\n').filter(l => l.includes('nist_score'))
    expect(scoreLines.length, 'nist_score を読んでいる行がありません').toBeGreaterThan(0)
    for (const line of scoreLines) {
      expect(
        /\?\?\s*-?\d/.test(line),
        'nist_score のフォールバックに数値リテラルが使われています。' +
          `評価できなかった場合は数値ではなく未計測として描画してください: ${line.trim()}`,
      ).toBe(false)
    }

    expect(
      src.includes('mock fallback'),
      'ハードコードされたモック値が残っています',
    ).toBe(false)
  })

  it('未計測を明示的に扱う', () => {
    const src = nistWidget()
    expect(
      src.includes('score === null'),
      'スコアが null の場合の分岐がありません。' +
        'null は 0 でも 78 でもなく「計測できなかった」という意味です',
    ).toBe(true)
    expect(
      src.includes('未計測'),
      '未計測であることが画面に出ません',
    ).toBe(true)
  })

  it('評価できた項目数を表示する', () => {
    const src = nistWidget()
    expect(
      src.includes('nist_coverage'),
      'カバレッジ (assessed/total) を読んでいません。' +
        '26項目中3項目の90点と26項目中26項目の90点は別の主張です',
    ).toBe(true)
  })
})

describe('セキュリティスコアカード画面', () => {
  it('取得できなかったスコアカードを0点として描画しない', () => {
    expect(
      /overall_score:\s*0\b/.test(scorecardSrc),
      'overall_score: 0 のフォールバックが残っています。' +
        '0点はゲージ上で赤く「全面的な非準拠」として描画されます',
    ).toBe(false)
  })

  it('スコアの有無をカバレッジで判定する', () => {
    expect(
      scorecardSrc.includes('assessed_controls'),
      'assessed_controls を読んでいません。' +
        'Number(x) || 0 では本物の0点と欠損を区別できません',
    ).toBe(true)
    expect(
      scorecardSrc.includes('overall_score: number | null'),
      'overall_score が null を取れる型になっていません',
    ).toBe(true)
  })

  it('未計測時に専用の表示を出す', () => {
    expect(
      scorecardSrc.includes('評価できた項目がありません'),
      '評価できた項目が無いことが画面に出ません',
    ).toBe(true)
  })
})
