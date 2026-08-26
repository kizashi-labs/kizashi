import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import { join } from 'path'
import { blankNoise } from './blank-noise'
import { mockDeclSpans, guardedByUseMock } from './mock-scan'
import { toPosix } from './route-scan'

// The SOC dashboard had two widgets that had never shown real data.
//
// The threat map fell back to FALLBACK_GEO_THREATS — China 142 critical,
// Russia 89, North Korea 54 — whenever /api/v1/alerts/geo-stats failed, and it
// always failed, because alerts has no src_country column and nothing writes
// one. The alert heatmap generated a 7×24 grid from Math.random() with a
// weekday-and-business-hours shape whenever /api/v1/alerts/heatmap failed, and
// that endpoint has no route at all, so it failed every time.
//
// An empty state says "there is nothing yet". These said "54 attacks from North
// Korea" and "your quiet hour is 04:00". Specific, actionable, and untrue —
// on the screen a SOC opens first, about the thing it is there to watch.
//
// CLAUDE.md already states the rule for this codebase: mock data must be gated
// behind USE_MOCK and must never reach production. These predate that gate and
// were never wired into it.

const APP = join(process.cwd(), 'app')
const COMPONENTS = join(process.cwd(), 'components')

function tsxFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) tsxFiles(p, out)
    else if (name.endsWith('.tsx') || name.endsWith('.ts')) out.push(p)
  }
  return out
}

// パスは `/` 区切りに揃えてから相対化します。**Windows の `join` /
// `readdirSync` は `\` を返す**ので、素の `replace(cwd + '/', '')` は
// 空振りし、絶対パスが残ります。許可リストは相対パスを鍵にしている
// ので 1 件も当たらなくなり、**直っている木で全件が違反として並びます**
// —— 叫んでいるのは走査の壊れ方で、木の中身ではありません
// （route-scan.ts の toPosix に同じ注記があります）。
const rel = (p: string) =>
  toPosix(p).replace(toPosix(process.cwd()) + '/', '')

/**
 * Screens whose displayed values must not be invented.
 *
 * The dashboard is here because it is the one a SOC opens first and the one
 * whose numbers drive what gets looked at. The rest of the app still has
 * fabrications; they are counted, not ignored — see the ceiling below.
 */
const NO_FABRICATION = ['app/dashboard/page.tsx']

/**
 * Files elsewhere that still compute a displayed value from Math.random().
 *
 * Can only go down. Each is a screen showing a number nobody measured.
 *
 * 48 → 36 when the failure-handler fabrications went; see
 * fabricated-verdict.test.ts, which pins that class at zero outright.
 *
 * 36 → 34 when generateMockSecret went from /admin/oauth2-clients and
 * /admin/service-accounts. Those two built a 40-character client secret out of
 * Math.random() and showed it to the administrator as the one to distribute.
 *
 * 34 → 30 after reading all 43 remaining sites one at a time. Most turned out
 * to be inside builders only reached under USE_MOCK, or not displayed values
 * at all (a UUID, canvas coordinates, an animation's progress). What was left
 * was a small set of charts drawn from random numbers on screens whose whole
 * purpose is to show a trend:
 *
 *   /risk-score            30日のリスク推移 = 今のスコア − 30 + 経過日数 + 乱数
 *   /security-score        7日の推移、同じ作り
 *   /admin/ueba            7×24 の活動ヒートマップ（UEBA が探しているのは
 *                          まさに「いつもと違う時間帯」です）
 *   /dns-security          24時間のクエリ数と遮断数
 *   /vulnerabilities/trends 30日の新規/修正件数
 *   /network-anomalies     24時間の通信量。しかも i === 9 に山を決め打ち
 *   /rules/metrics         本物の合計を日数で割って ±30% の乱数
 *   /reports/benchmark     同業他社比較のパーセンタイル
 *
 * と、サーバを呼ばずに完了を演じていた3つの操作
 * （/admin/cloud-siem のルール試行、/admin/reports-engine の生成、
 * /admin/cloud-identity の同期）。
 */
//
// 30 → 29 (main 取り込み)。/cloud-security の進捗バーを消した分です ——
// サーバ側スキャンの進捗を返す経路は無く、バーはタイマーで動いていた
// だけなので、走っていないスキャンでも 100% まで進んで「完了」と
// 表示できました。いまは開始できたかどうかだけを出します。
const RANDOM_VALUE_CEILING = 1

/**
 * Files anywhere holding a FALLBACK_* constant. Zero, and it stays zero.
 *
 * This is a whole-tree count rather than a per-page one on purpose. The
 * per-page rule above can be deleted, and with healthy code nothing would
 * notice; the count here notices, because the number moves. Math.random()
 * already had that second observer — the ceiling — and FALLBACK_ did not.
 */
const FALLBACK_FILE_CEILING = 0

/** Lines that are code, not comments. A note describing a removed fabrication
 *  is not a fabrication, and the first version of this test failed on its own
 *  explanation of what it had deleted. */
function codeLines(src: string): string[] {
  return src.split('\n').filter(l => !/^\s*(\/\/|\*|\/\*)/.test(l))
}

/** Math.random() used for a value, rather than for a key or an id. */
function randomValueUses(src: string): number {
  return codeLines(src)
    .filter(line => line.includes('Math.random()'))
    .filter(line => !/\bkey=|\bid:\s*|\bid=/.test(line)).length
}

/** FALLBACK_* constants in code — the "if the API fails, show this instead" shape. */
function fallbackConstUses(src: string): number {
  return codeLines(src).filter(line => /FALLBACK_[A-Z_]+/.test(line)).length
}

describe('作り物のデータ', () => {
  const files = [...tsxFiles(APP), ...tsxFiles(COMPONENTS)]

  it('走査がファイルを見つけている', () => {
    expect(files.length).toBeGreaterThan(20)
  })

  // この1件だけを消しても、健全なコードでは何も落ちません（探す対象が無いので）。
  // 消した上で作り物を戻すと、下の2つの全体集計が件数の変化で落とします。
  it.each(NO_FABRICATION)('%s は表示する値を発明しない', page => {
    const code = codeLines(readFileSync(join(process.cwd(), page), 'utf8')).join('\n')
    expect(fabricationsIn(code), `${page} に作り物が残っています`).toEqual([])
  })

  // 2種類あり、片方を消しても正常なコードでは何も変わりません。両方を
  // 直接動かします。
  it.each([
    { src: 'const h = Math.random() * 100', want: ['random'] },
    { src: 'const F = FALLBACK_GEO_THREATS', want: ['fallback'] },
    { src: 'const a = FALLBACK_X\nconst b = Math.random()', want: ['fallback', 'random'] },
    { src: 'const a = 1', want: [] },
    { src: '<div key={Math.random()} />', want: [] },
  ])('作り物の検出: $src', ({ src, want }) => {
    expect(fabricationsIn(src)).toEqual(want)
  })

  it('作り物を表示に使うファイルが増えていない', () => {
    const offenders = files
      .map(f => ({ file: rel(f), n: randomValueUses(readFileSync(f, 'utf8')) }))
      .filter(x => x.n > 0)

    expect(ceilingProblem(offenders.length, RANDOM_VALUE_CEILING)).toBeNull()
  })

  it('API が落ちたとき用の固定データを持つファイルが無い', () => {
    const offenders = files
      .map(f => ({ file: rel(f), n: fallbackConstUses(readFileSync(f, 'utf8')) }))
      .filter(x => x.n > 0)

    expect(
      ceilingProblem(offenders.length, FALLBACK_FILE_CEILING),
      `固定データ: ${offenders.map(o => o.file).join(', ')}`
    ).toBeNull()
  })

  // 実測が上限とちょうど一致している通常状態では、どちらの分岐にも入りません。
  it.each([
    { actual: 30, ceiling: 30, expected: null },
    { actual: 31, ceiling: 30, expected: /増えています/ },
    { actual: 29, ceiling: 30, expected: /下げてください/ },
    { actual: 0, ceiling: 30, expected: /下げてください/ },
  ])('上限判定: $actual / $ceiling', ({ actual, ceiling, expected }) => {
    const got = ceilingProblem(actual, ceiling)
    if (expected === null) expect(got).toBeNull()
    else expect(got).toMatch(expected)
  })

  // 検出そのものが動いていること。動いていなければ「0件」で通ります。
  it('乱数の使用を見分けられる', () => {
    expect(randomValueUses('const h = Math.random() * 100')).toBe(1)
    expect(randomValueUses('<div key={Math.random()} />')).toBe(0)
    expect(randomValueUses('const id: Math.random().toString()')).toBe(0)
    expect(randomValueUses('const a = 1\nconst b = 2')).toBe(0)
    expect(randomValueUses('// 以前は Math.random() でした')).toBe(0)
  })

  it('固定データ定数を見分けられる', () => {
    expect(fallbackConstUses('const FALLBACK_GEO_THREATS = []')).toBe(1)
    expect(fallbackConstUses('// ここには FALLBACK_GEO_THREATS がありました')).toBe(0)
    expect(fallbackConstUses('const fallbackGeo = []')).toBe(0)
    expect(fallbackConstUses('const a = 1')).toBe(0)
  })
})

/**
 * どの種類の作り物が入っているか。
 *
 * 「API が落ちたら固定の配列を出す」形と、表示する数を乱数で作る形の2つ。
 */
export function fabricationsIn(code: string): string[] {
  const found: string[] = []
  if (fallbackConstUses(code) > 0) found.push('fallback')
  if (randomValueUses(code) > 0) found.push('random')
  return found
}

export function ceilingProblem(actual: number, ceiling: number): string | null {
  if (actual > ceiling) {
    return `作り物を表示に使うファイルが ${ceiling} から ${actual} に増えています`
  }
  if (actual < ceiling) {
    return (
      `作り物を表示に使うファイルが ${actual} まで減りました。` +
      `RANDOM_VALUE_CEILING を ${actual} に下げてください`
    )
  }
  return null
}

// ─── 乱数が「守られているか」 ────────────────────────────────────────────────
//
// 上のファイル数の上限は、直したことを測れません。`if (!USE_MOCK)` を1行
// 消しても、そのファイルに Math.random() があることは変わらないからです。
// 実際、8つの直しを元に戻す変異が、上限だけでは1つも落ちませんでした。
//
// 測るべきは到達可能性です —— 表示される値を作る Math.random() が、
// USE_MOCK の内側にあるかどうか。
//
// 「表示される値」から外すもの:
//   - id / トークン（toString(36) / toString(16)）
//   - タイマーの散らし（setTimeout）
//   - React の key
// これらは測定値を名乗りません。

/** 表示される値を作っていて、USE_MOCK の外にある Math.random()。 */
export function unguardedRandomValues(src: string): { line: number; text: string }[] {
  const clean = blankNoise(src)
  const spans = mockDeclSpans(clean)
  const out: { line: number; text: string }[] = []
  let i = clean.indexOf('Math.random()')
  while (i !== -1) {
    const line = clean.slice(0, i).split('\n').length
    const text = (src.split('\n')[line - 1] ?? '').trim()
    const notAValue = /toString\(36\)|toString\(16\)|setTimeout|key=|\bid[:=]/.test(text)
    const inMockDecl = spans.some(([a, b]) => i >= a && i < b)
    // 囲っているブロックの中に USE_MOCK があるか。最初は「直前の
    // トップレベル宣言から」で見ていましたが、コンポーネントの中の
    // `const x = useMemo(...)` は字下げされていてトップレベルに一致せず、
    // 無関係な行の USE_MOCK を拾っていました。守りは囲いの中にあります。
    // 8段まで見ます。守りは関数の入口の早期 return にあることが多く、
    // 乱数は Array.from の中のオブジェクトリテラルの中、のように深く
    // 入っています。4段だと入口まで届きません。
    const guarded = guardedByUseMock(clean, i, 8)
    if (!notAValue && !inMockDecl && !guarded) out.push({ line, text })
    i = clean.indexOf('Math.random()', i + 1)
  }
  return out
}

/**
 * 守られていないように見えるが、そうではないもの。ファイルごとに理由を書きます。
 *
 * 走査は関数をまたげないので、「呼び出し側が USE_MOCK で分けている」形は
 * ここに来ます。理由が本当かどうかは、1件ずつ読んで確かめました。
 */
interface RandomExcuse {
  why: string
  /**
   * 呼び出し側の守り。文字列としてファイルに残っていることを確かめます。
   *
   * 「呼び出し側が USE_MOCK で分けている」と書くだけでは、その分岐を
   * 1行消しても許可リストだけが残ります。守りそのものを書きます。
   * 守りが要らないもの（id、座標、演出）は null です。
   */
  guard: string | null
}

export function brokenRandomExcuses(
  sources: Record<string, string>,
  allow: Record<string, RandomExcuse>
): string[] {
  const problems: string[] = []
  for (const [file, e] of Object.entries(allow)) {
    if (e.guard === null) continue
    if (!(sources[file] ?? '').includes(e.guard)) {
      problems.push(`${file} の許可は「${e.why}」ですが、その守り (${e.guard}) が見当たりません`)
    }
  }
  return problems.sort()
}

const RANDOM_NOT_A_MEASUREMENT: Record<string, RandomExcuse> = {
}

/** 説明の無い箇所。0 で固定。 */
const UNGUARDED_RANDOM_CEILING = 0

export function randomGuardProblems(
  counts: Record<string, number>,
  allow: Record<string, string>
): string[] {
  const problems: string[] = []
  for (const [file, n] of Object.entries(counts)) {
    if (n > 0 && !(file in allow)) {
      problems.push(`${file}: ${n}箇所で、表示する値を USE_MOCK の外の Math.random() から作っています`)
    }
  }
  for (const [file, why] of Object.entries(allow)) {
    if (!counts[file]) {
      problems.push(`${file} はもう乱数を使っていません (${why})。リストから消してください`)
    }
  }
  return problems.sort()
}

describe('守られていない乱数', () => {
  const files = [...tsxFiles(APP), ...tsxFiles(COMPONENTS)]

  it('説明の無い箇所が残っていない', () => {
    const counts: Record<string, number> = {}
    for (const f of files) {
      const n = unguardedRandomValues(readFileSync(f, 'utf8')).length
      if (n > 0) counts[rel(f)] = n
    }
    for (const file of Object.keys(RANDOM_NOT_A_MEASUREMENT)) {
      counts[file] ??= unguardedRandomValues(readFileSync(join(process.cwd(), file), 'utf8')).length
    }

    const reasons: Record<string, string> = {}
    for (const [f, e] of Object.entries(RANDOM_NOT_A_MEASUREMENT)) reasons[f] = e.why
    const problems = randomGuardProblems(counts, reasons)
    expect(problems, problems.join('\n  ')).toEqual([])

    const total = Object.entries(counts)
      .filter(([f]) => !(f in RANDOM_NOT_A_MEASUREMENT))
      .reduce((a, [, n]) => a + n, 0)
    expect(total).toBe(UNGUARDED_RANDOM_CEILING)
  })

  // 許可の根拠が、まだコードに残っていること。
  it('許可の根拠が現存する', () => {
    const sources: Record<string, string> = {}
    for (const f of Object.keys(RANDOM_NOT_A_MEASUREMENT)) {
      sources[f] = readFileSync(join(process.cwd(), f), 'utf8')
    }
    expect(brokenRandomExcuses(sources, RANDOM_NOT_A_MEASUREMENT)).toEqual([])
  })

  it.each([
    { name: '守りが残っている', src: 'USE_MOCK ? build() : []', guard: 'USE_MOCK ? build()', want: 0 },
    { name: '守りが消えた', src: 'build()', guard: 'USE_MOCK ? build()', want: 1 },
    { name: '守りが要らない', src: 'anything', guard: null, want: 0 },
    { name: 'ファイルが読めない', src: undefined, guard: 'x', want: 1 },
  ])('許可の根拠: $name', ({ src, guard, want }) => {
    // 型を明示するのは、`{}` と `{ 'a.tsx': string }` の union が
    // `Record<string, string>` に代入できないためです（値は正しい）。
    const sources: Record<string, string> = src === undefined ? {} : { 'a.tsx': src }
    expect(brokenRandomExcuses(sources, { 'a.tsx': { why: '理由', guard } })).toHaveLength(want)
  })

  // 通常状態では上の判定はどちらの分岐にも入りません。
  //
  // 型引数を明示するのは、見本ごとに鍵の顔ぶれが違うと union に推論され、
  // `Record<string, number>` に渡せなくなるためです。
  it.each<{ name: string; counts: Record<string, number>; allow: Record<string, string>; want: number }>([
    { name: '違反なし', counts: {}, allow: {}, want: 0 },
    { name: '未許可の違反', counts: { 'a.tsx': 1 }, allow: {}, want: 1 },
    { name: '許可済み', counts: { 'a.tsx': 1 }, allow: { 'a.tsx': '理由' }, want: 0 },
    { name: '許可が古い', counts: { 'a.tsx': 0 }, allow: { 'a.tsx': '理由' }, want: 1 },
    { name: '2件', counts: { 'a.tsx': 1, 'b.tsx': 2 }, allow: {}, want: 2 },
  ])('判定: $name', ({ counts, allow, want }) => {
    expect(randomGuardProblems(counts, allow)).toHaveLength(want)
  })

  // 実測が0の通常状態では、検出そのものが一度も肯定側に入りません。
  it.each([
    { name: '素で表示に使う', src: 'const score = Math.random() * 100', want: 1 },
    { name: '同じ宣言の中で守られている', src: 'function f() {\n if (!USE_MOCK) return []\n return Math.random()\n}', want: 0 },
    { name: '三項で守られている', src: 'const d = USE_MOCK ? Math.random() : 0', want: 0 },
    { name: 'id は測定値ではない', src: 'const id = Math.random().toString(36)', want: 0 },
    { name: 'タイマーの散らし', src: 'setTimeout(f, 300 + Math.random() * 400)', want: 0 },
    { name: 'React の key', src: '<div key={Math.random()} />', want: 0 },
    { name: '作り物の宣言の中', src: 'const MOCK_ROWS = [{ n: Math.random() }]\n', want: 0 },
    { name: 'コメントの中', src: '// 以前は Math.random() でした\nconst a = 1', want: 0 },
    { name: '文字列の中', src: 'const s = "Math.random()"\nconst a = 1', want: 0 },
  ])('検出: $name', ({ src, want }) => {
    expect(unguardedRandomValues(src)).toHaveLength(want)
  })
})
