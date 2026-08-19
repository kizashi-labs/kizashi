import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import path from 'path'

// app/status is the public, unauthenticated status page. It used to draw its
// 30-day and 7-day availability history from Math.random():
//
//   function generateDailyBuckets(days: number, uptimePct: number): number[] {
//     const roll = Math.random()
//     if (roll < (1 - uptimePct / 100) * 0.5) buckets.push(94 + Math.random() * 4)
//     else buckets.push(99.5 + Math.random() * 0.5)
//     for (let i = days - 7; i < days; i++) buckets[i] = 100   // last 7 always 100
//   }
//   const BUCKETS_30 = generateDailyBuckets(30, 99.9)
//
// Thirty green bars, re-rolled on every page load, with the most recent week
// pinned to exactly 100%. The server's numbers were invented too, and the page
// coerced a missing figure to 0 with `?? 0`, so there was no path by which an
// honest "we do not measure this" could reach the screen.
//
// CLAUDE.md's mock-data convention — USE_MOCK / mockOr / m() — did not catch
// this because none of it was named MOCK_*. This is a source-level gate for
// the same rule on the one page where a fabricated number is a public claim.

const STATUS_PAGE = path.join(__dirname, '..', '..', 'app', 'status', 'page.tsx')

function statusSource(): string {
  return readFileSync(STATUS_PAGE, 'utf8')
}

// statusCode returns the page with comments removed. The gate is about what the
// page executes, not what it says: a comment recording that this file used to
// call Math.random() must not be mistaken for a call to it. `//` is only a
// comment when not preceded by `:`, so protocol-relative URLs survive.
function statusCode(): string {
  return statusSource()
    .replace(/\/\*[\s\S]*?\*\//g, '')
    .replace(/(^|[^:])\/\/.*$/gm, '$1')
}

describe('公開ステータスページ', () => {
  it('ソースが読めている（テストが空振りしていない）', () => {
    const src = statusSource()
    expect(src.length).toBeGreaterThan(1000)
    expect(src).toContain('/api/v1/health/uptime')
  })

  it('表示値を Math.random() で生成しない', () => {
    expect(statusCode()).not.toMatch(/Math\.random\(\)/)
  })

  it('稼働率のダミー生成関数を持たない', () => {
    const src = statusCode()
    expect(src).not.toContain('generateDailyBuckets')
    expect(src).not.toContain('BUCKETS_30')
    expect(src).not.toContain('BUCKETS_7')
  })

  it('欠測値を 0 に読み替えない', () => {
    // `data.uptime_30d ?? 0` rendered a green 0.00% for a figure the server
    // explicitly declined to provide. The state fields are spelled differently
    // from the API fields (uptime30d vs uptime_30d) and both are covered —
    // checking only the API spelling let a coerced render slip through.
    const src = statusCode()
    for (const field of ['uptime_30d', 'uptime_7d', 'uptime30d', 'uptime7d']) {
      expect(src, `${field} を 0 に読み替えています`).not.toMatch(
        new RegExp(`${field}\\s*(\\?\\?|\\|\\|)\\s*0`),
      )
    }
  })

  it('30日・7日の両方の表示が measured で分岐している', () => {
    // Both summary tiles must be guarded. Asserting only that the string
    // 未計測 appears somewhere let one tile be changed back to a number while
    // the other kept the label.
    const src = statusCode()
    const guarded = src.match(/sla\.measured\s*\?/g) ?? []
    expect(guarded.length, 'measured による分岐が足りません').toBeGreaterThanOrEqual(3)
    const unmeasured = src.match(/未計測/g) ?? []
    expect(unmeasured.length, '未計測ラベルが両方の指標に付いていません').toBeGreaterThanOrEqual(2)
  })

  it('サーバーの measured フラグを読む', () => {
    expect(statusCode()).toContain('data.measured')
  })

  it('未計測であることを画面に表示する', () => {
    const src = statusSource()
    expect(src).toContain('稼働率は計測されていません')
    expect(src).toContain('未計測')
  })

  it('空の障害履歴を「障害なし」と読ませない', () => {
    expect(statusSource()).toContain('障害履歴は記録されていません')
  })
})
