import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import { join } from 'path'
import { blankNoise } from './blank-noise'
import { toPosix } from './route-scan'

// 読み取りの失敗を、queryFn の中で答えにすり替えている箇所。
//
//   const { data: vulns } = useQuery({
//     queryFn: () => apiFetch('/api/v1/admin/vulnerabilities/stats')
//       .catch(() => ({ total: 0, critical: 0, high: 0, open: 0 })),
//   })
//
// The page-level band added to all 347 pages cannot see this one. `.catch`
// resolves the promise, so react-query reports status === 'success', the band
// finds no failing query, and the screen renders 重大な脆弱性 0件.
//
// That is the distinction this whole campaign started from, arriving one layer
// lower: 「まだ何も無い」 and 「取れていない」 are different sentences, and the
// second one had no way to be said. 161 reads across 81 files said the first.
//
// The sharpest were not the zeros. /executive — the board-facing dashboard —
// answered a failed /api/v1/security-posture with MOCK.posture: score 72,
// grade B, trend +3, last_updated 12分前. /reports/security-ops went further
// and had buildMockReport in initialData, so the report was fabricated before
// any request was made. /admin/compliance pre-filled NIST CSF with
// 'implemented' for 20 of 23 controls and stamped last_assessed with
// new Date(), so a tenant that had never run an assessment saw a fresh,
// mostly-compliant one.
//
// Two shapes are counted:
//   - `.catch(…)` chained onto the read whose handler ignores the error
//   - a read inside `try { … } catch {}`
//
// A handler that reads its error argument is not counted: it is doing
// something with the failure, and what it does is a separate question.
//
// The fix is not "delete the catch". Three集約クエリ (Promise.all in one
// queryFn) would have gone all-or-nothing, and a board dashboard blanking
// because one of four endpoints is down is not an improvement. Those use
// readInto/PartialDataNotice (lib/partial.ts), which keeps the parts that
// arrived and names the parts that did not.

const ROOTS = ['app', 'components', 'lib']

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) sourceFiles(p, out)
    else if (name.endsWith('.tsx') || name.endsWith('.ts')) out.push(p)
  }
  return out
}

// 素の fetch も見ます。以前は apiFetch だけで、素の fetch 40箇所は
// この判定に一度も映っていませんでした。握り潰しているものが今は無いと
// しても、無いことを確かめられる状態にしておきます。
const FETCH = /(?:\bapiFetch(?:List)?|(?<![.\w])fetch)\s*(?:<[^;{]*?>)?\s*\(/g

/** Index just past the matching close of the bracket opening at `open`. */
function balanced(src: string, open: number, o = '(', c = ')'): number {
  let depth = 0
  for (let i = open; i < src.length; i++) {
    if (src[i] === o) depth++
    else if (src[i] === c) {
      depth--
      if (depth === 0) return i + 1
    }
  }
  return -1
}

/**
 * The `.catch(handler)` chained directly onto a call ending at `end`.
 *
 * Returns the handler split into its parameter and body, or null when the
 * call is not followed by a catch. Only arrow handlers are recognised;
 * `.catch(console.error)` and `.catch(this.onFail)` are doing something with
 * the failure by definition, so they are not this rule's business.
 */
export function chainedCatch(clean: string, end: number): { param: string; body: string } | null {
  // 先頭に固定します。40文字先まで探してしまうと、この読み取りとは無関係な
  // 隣の `.catch` を「鎖でつながっている」と読み違えます。
  //
  // 固定してあるので m.index は必ず 0 ですが、足したままにしてあります。
  // 抜くと、固定を外す変更が「位置がずれて何も見つからない」という形で
  // 静かに通ってしまい、隣の catch を巻き込まない検査が効かなくなります。
  const m = /^\s*\.catch\(/.exec(clean.slice(end, end + 40))
  if (!m) return null
  const open = end + m.index + m[0].length - 1
  const close = balanced(clean, open)
  if (close < 0) return null
  const inner = clean.slice(open + 1, close - 1)
  const arrow = inner.indexOf('=>')
  if (arrow < 0) return null
  return { param: inner.slice(0, arrow).replace(/[()\s]/g, ''), body: inner.slice(arrow + 2).trim() }
}

/**
 * Does this handler throw the failure away?
 *
 * A handler that names its error and uses it is reporting; one that ignores
 * it and returns a value is answering. `_` counts as ignoring, and an empty
 * block counts as ignoring however the parameter is named — `catch (e) {}`
 * mentions the error and does nothing with it.
 */
export function discardsError(param: string, body: string): boolean {
  // 引数を名乗っていなければ、扱いようがありません。ここを外すと空の
  // 名前から `\b\b` という正規表現ができて、本文次第で当たったり当たら
  // なかったりします。
  if (!param) return true
  // `_` は「使わない」と書いた名前です。`.catch(_ => _)` のように本文に
  // 出てきても、失敗を扱ったことにはなりません。
  if (param === '_') return true
  return !new RegExp(`\\b${param.replace(/[^\w$]/g, '')}\\b`).test(body)
}

/**
 * Does this catch block answer instead of report?
 *
 * A block whose every statement is a `return` produces a value and does
 * nothing else — it cannot have told anyone. An empty block is that same
 * thing with the value left implicit.
 *
 * This started as "is the block empty", which missed the commoner shape:
 *
 *   queryFn: async () => {
 *     try { return await apiFetch(`/api/v1/agents/${id}/performance`) }
 *     catch { return { metrics: generateMockMetrics(range), processes: … } }
 *   }
 *
 * Not empty, so it did not count, and /endpoints/[id]/performance drew a CPU
 * and memory chart for an endpoint it had never reached.
 *
 * A block that calls something — setError, a toast, console — is doing
 * something with the failure, and what it does is a separate question.
 */
export function catchAnswers(body: string): boolean {
  // 波括弧も数えます。実際には、入れ子の `;` は丸括弧の中にも入っている
  // ことがほとんどで、波括弧を数えるのをやめても答えは変わりません
  // （変異させても落ちません）。それでも数えているのは、丸括弧を伴わない
  // 入れ子ブロック — オブジェクトリテラルの中の getter など — でだけ
  // 差が出るからです。落とせない検査を1つ残す代わりに、理由をここに
  // 書いておきます。
  const inner = body.replace(/^\{/, '').replace(/\}$/, '')
  let depth = 0
  const parts: string[] = []
  let cur = ''
  for (const c of inner) {
    if ('({['.includes(c)) depth++
    else if (')}]'.includes(c)) depth--
    if (c === ';' && depth === 0) {
      parts.push(cur)
      cur = ''
    } else cur += c
  }
  parts.push(cur)
  return parts.every(p => p.trim() === '' || /^return\b/.test(p.trim()))
}

/**
 * Is the block immediately containing this position a `try` whose `catch`
 * only returns?
 *
 * Same walk as silent-writes.test.ts: forward to the `}` that closes the
 * enclosing block, rather than a fixed window, which would match an unrelated
 * `try {} catch {}` further down the file.
 */
export function inEmptyCatchBlock(clean: string, from: number): boolean {
  let depth = 0
  for (let i = from; i < clean.length; i++) {
    const c = clean[i]
    if (c === '{') depth++
    else if (c === '}') {
      if (depth === 0) {
        const m = /^\}\s*catch\s*(?:\([^)]*\))?\s*\{/.exec(clean.slice(i))
        if (!m) return false
        const open = i + m[0].length - 1
        const close = balanced(clean, open, '{', '}')
        if (close < 0) return false
        return catchAnswers(clean.slice(open, close))
      }
      depth--
    }
  }
  return false
}

/**
 * Lines (1-based) where a read's failure is turned into data.
 *
 * Writes are excluded — silent-writes.test.ts pins those at zero with its own
 * named exceptions, and the two rules want different remedies. The method is
 * read off the original source rather than the blanked copy for the same
 * reason as there: `method: 'POST'` IS a string literal, so reading it from
 * the blanked copy finds nothing and every write looks like a read.
 */
export function swallowedReads(src: string): number[] {
  const clean = blankNoise(src)
  const found: number[] = []
  FETCH.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = FETCH.exec(clean)) !== null) {
    const open = m.index + m[0].length - 1
    const end = balanced(clean, open)
    if (end < 0) continue
    if (/method:\s*['"](POST|PUT|PATCH|DELETE)['"]/.test(src.slice(open, end))) continue

    const h = chainedCatch(clean, end)
    if ((h && discardsError(h.param, h.body)) || inEmptyCatchBlock(clean, end)) {
      found.push(clean.slice(0, open).split('\n').length)
    }
  }
  return found
}

/**
 * Reads that may still answer their own failure, each with the reason.
 *
 * Empty, and it stays empty unless something earns a line here. The bar is the
 * same as DELIBERATE_SILENT_WRITES: "there is nowhere to report to", not "the
 * failure does not matter". 集約クエリ do not belong here — readInto in
 * lib/partial.ts reports them without losing the parts that arrived.
 */
const DELIBERATE_SWALLOWED_READS: Record<string, string> = {
  'app/status/page.tsx':
    'サービス状態ページ。読めなかったこと自体がこの画面の出力です — ' +
    'health が返らなければ API を down、uptime が返らなければ「未測定」の' +
    'まま、エージェント数が返らなければ checking。catch が黙っているのでは' +
    'なく、catch の後の状態がそのまま画面に出ます。素の fetch も見るように' +
    '判定を広げたときに出てきました',
}

/**
 * 総数。許可した分も含みます。
 *
 * 「許可の無い違反」は上の readProblems が見ます。ここは総数を見るので、
 * 許可を1行足して黙らせても数字は動きます。素の fetch も数えるように
 * 広げたときに /status の3件が入り、0 から 3 になりました。増えたのは
 * 中身ではなく、見える範囲です。
 */
const SWALLOWED_READ_CEILING = 3

/**
 * Both halves of the rule, as one function over measurements.
 *
 * `counts` is file → how many swallowed reads it has. Returns a complaint for
 * every unlisted file that has one, and for every listed file that no longer
 * does.
 *
 * One function rather than two checks because with the tree clean and the
 * allowlist empty neither loop is ever reached from the scan, so each could be
 * deleted without anything noticing. The table below drives both directly.
 */
export function readProblems(
  counts: Record<string, number>,
  allow: Record<string, string>
): string[] {
  const problems: string[] = []
  for (const [file, n] of Object.entries(counts)) {
    if (n > 0 && !(file in allow)) {
      problems.push(
        `${file}: ${n}箇所で読み取りの失敗を答えにすり替えています。` +
          `queryFn の中で .catch すると status は success になるので、` +
          `画面の「取得できませんでした」の帯はこれを見つけられません`
      )
    }
  }
  for (const [file, why] of Object.entries(allow)) {
    if (!counts[file]) {
      problems.push(`${file} はもう読み取りの失敗を捨てていません (${why})。リストから消してください`)
    }
  }
  return problems.sort()
}

export function ceilingProblem(actual: number, ceiling: number): string | null {
  if (actual > ceiling) {
    return (
      `読み取りの失敗を答えにすり替えている箇所が ${ceiling} から ${actual} に増えています。` +
      `queryFn の中で .catch すると status は success になるので、` +
      `画面の「取得できませんでした」の帯はこれを見つけられません`
    )
  }
  if (actual < ceiling) {
    return (
      `読み取りの失敗を答えにすり替えている箇所が ${actual} まで減りました。` +
      `SWALLOWED_READ_CEILING を ${actual} に下げてください`
    )
  }
  return null
}

describe('読み取りの失敗を答えにすり替える', () => {
  const files = ROOTS.flatMap(r => sourceFiles(join(process.cwd(), r)))
  // パスは `/` 区切りに揃えてから相対化します。**Windows の `join` /
  // `readdirSync` は `\` を返す**ので、素の `replace(cwd + '/', '')` は
  // 空振りし、絶対パスが残ります。許可リストは相対パスを鍵にしている
  // ので 1 件も当たらなくなり、**直っている木で全件が違反として並びます**
  // —— 叫んでいるのは走査の壊れ方で、木の中身ではありません
  // （route-scan.ts の toPosix に同じ注記があります）。
  const rel = (p: string) =>
    toPosix(p).replace(toPosix(process.cwd()) + '/', '')

  it('走査がファイルを見つけている', () => {
    expect(files.length).toBeGreaterThan(20)
  })

  it('説明の無い箇所が残っていない', () => {
    const counts: Record<string, number> = {}
    for (const f of files) {
      const lines = swallowedReads(readFileSync(f, 'utf8'))
      if (lines.length > 0) counts[rel(f)] = lines.length
    }
    for (const file of Object.keys(DELIBERATE_SWALLOWED_READS)) {
      counts[file] ??= swallowedReads(readFileSync(join(process.cwd(), file), 'utf8')).length
    }

    const problems = readProblems(counts, DELIBERATE_SWALLOWED_READS)
    expect(problems, problems.join('\n  ')).toEqual([])

    // 件数のほうも見ます。上は「許可の無い違反」を見ますが、許可を1行
    // 足せば黙るので、総数が動いたこと自体は別に言わせます。
    const total = Object.values(counts).reduce((a, b) => a + b, 0)
    expect(ceilingProblem(total, SWALLOWED_READ_CEILING)).toBeNull()
  })

  // 違反も陳腐化した許可も無い通常状態では、上の判定はどちらの分岐にも
  // 入りません。判定そのものを直接動かします。
  //
  // 型を明記するのは、注釈が無いと各行の literal 型の union になり、
  // `{ 'a.tsx'?: undefined }` が `Record<string, number>` に渡らないためです。
  it.each<{ name: string; counts: Record<string, number>; allow: Record<string, string>; want: number }>([
    { name: '違反なし', counts: {}, allow: {}, want: 0 },
    { name: '未許可の違反', counts: { 'a.tsx': 1 }, allow: {}, want: 1 },
    { name: '許可済みの違反', counts: { 'a.tsx': 1 }, allow: { 'a.tsx': '理由' }, want: 0 },
    { name: '許可が古い（もう直っている）', counts: { 'a.tsx': 0 }, allow: { 'a.tsx': '理由' }, want: 1 },
    { name: '許可が古い（計測にも出ない）', counts: {}, allow: { 'a.tsx': '理由' }, want: 1 },
    { name: '2件', counts: { 'a.tsx': 1, 'b.tsx': 2 }, allow: {}, want: 2 },
  ])('判定: $name', ({ counts, allow, want }) => {
    expect(readProblems(counts, allow)).toHaveLength(want)
  })

  // 実測が 0 の通常状態では、検出そのものが一度も肯定側に入りません。
  // 「見つからない」と「探していない」は同じ 0 件なので、直接動かします。
  it.each([
    { name: '空配列にすり替える', src: "apiFetch('/x').catch(() => [])", want: 1 },
    { name: '0 の入った物にすり替える', src: "apiFetch('/x').catch(() => ({ total: 0 }))", want: 1 },
    { name: '定数にすり替える', src: "apiFetch('/x').catch(() => EMPTY_STATS)", want: 1 },
    { name: '作り物にすり替える', src: "apiFetch('/x').catch(() => MOCK.posture)", want: 1 },
    { name: 'null にする', src: "apiFetch('/x').catch(() => null)", want: 1 },
    { name: '型引数付きでも見つける', src: "apiFetch<Stats>('/x').catch(() => null)", want: 1 },
    { name: 'apiFetchList も同じ', src: "apiFetchList<A>('/x').catch(() => [])", want: 1 },
    { name: '空の catch で囲う', src: "try { await apiFetch('/x') } catch {}", want: 1 },
    { name: 'catch (e) {} も空', src: "try { await apiFetch('/x') } catch (e) {}", want: 1 },
    {
      name: 'catch が作り物を返す',
      src: "try { return await apiFetch('/x') } catch { return { metrics: [] } }",
      want: 1,
    },
    {
      name: 'catch が定数を返す',
      src: "try { return await apiFetch('/x') } catch { return MOCK_AGENTS }",
      want: 1,
    },
    {
      name: 'catch が投げ直す',
      src: "try { return await apiFetch('/x') } catch (e) { throw e }",
      want: 0,
    },
    {
      name: 'catch が報告してから返す',
      src: "try { return await apiFetch('/x') } catch { setError('だめ'); return [] }",
      want: 0,
    },
    { name: '_ は無視と同じ', src: "apiFetch('/x').catch(_ => [])", want: 1 },
    {
      name: '失敗を扱っていれば対象外',
      src: "apiFetch('/x').catch(e => setError(e.message))",
      want: 0,
    },
    {
      name: '投げ直しは対象外',
      src: "apiFetch('/x').catch(err => { throw err })",
      want: 0,
    },
    {
      name: 'catch の中身があれば対象外',
      src: "try { await apiFetch('/x') } catch { setError('だめ') }",
      want: 0,
    },
    { name: '素の読み取りは対象外', src: "await apiFetch('/x')", want: 0 },
    {
      name: '書き込みは silent-writes の担当',
      src: "apiFetch('/x', { method: 'POST' }).catch(() => null)",
      want: 0,
    },
    {
      name: 'コメントの中の例は数えない',
      src: "// apiFetch('/x').catch(() => [])\nconst a = 1",
      want: 0,
    },
    {
      name: '文字列の中の例も数えない',
      src: "const doc = \"apiFetch('/x').catch(() => [])\"\nconst a = 1",
      want: 0,
    },
    {
      // 鎖でつながっていない近くの .catch を巻き込まないこと。
      name: '隣の catch を鎖と読み違えない',
      src: "apiFetch('/x')\nregisterSW().catch(() => null)",
      want: 0,
    },
  ])('検出: $name', ({ src, want }) => {
    expect(swallowedReads(src)).toHaveLength(want)
  })

  // 引数を名乗るかどうかだけで判定が変わるので、そこも直接動かします。
  // catch ブロックの側も、通常状態では肯定側に入りません。
  it.each([
    { name: '空', body: '{}', want: true },
    { name: '返すだけ', body: '{ return [] }', want: true },
    { name: '作った物を返すだけ', body: '{ return { a: MOCK } }', want: true },
    { name: '中に ; を含む物を返す', body: '{ return f({ a: 1 }) }', want: true },
    // 入れ子の中の ; で文を切ってはいけません。切ると後半が return で
    // 始まらなくなり、答えているだけのブロックが「何かしている」に見えます。
    { name: '入れ子の関数の中に ; がある', body: '{ return f(() => { g(); h() }) }', want: true },
    { name: '報告する', body: "{ setError('x') }", want: false },
    { name: '投げ直す', body: '{ throw e }', want: false },
    { name: '報告してから返す', body: "{ setError('x'); return [] }", want: false },
  ])('catch が答えているか: $name', ({ body, want }) => {
    expect(catchAnswers(body)).toBe(want)
  })

  it.each([
    { param: '', body: '[]', want: true },
    { param: '_', body: '[]', want: true },
    { param: 'e', body: '[]', want: true },
    { param: 'e', body: 'setError(e)', want: false },
    { param: 'err', body: '{ throw err }', want: false },
    { param: 'e', body: '{}', want: true },
    { param: 'e', body: '{ }', want: true },
    // `_` は「使わない」と書いた名前なので、本文に出てきても扱いではない。
    { param: '_', body: '_', want: true },
    // 引数が無ければ本文が何であれ扱いようがない。空の名前から作った
    // 正規表現が本文に当たってしまう形を防ぎます。
    { param: '', body: 'null', want: true },
    { param: '', body: '[]', want: true },
    // 別物の中に部分一致しても、扱ったことにはなりません。
    { param: 'e', body: 'setError(errors)', want: true },
  ])('失敗を捨てたか: ($param) => $body', ({ param, body, want }) => {
    expect(discardsError(param, body)).toBe(want)
  })

  it.each([
    { actual: 0, ceiling: 0, expected: null },
    { actual: 1, ceiling: 0, expected: /増えています/ },
    { actual: 5, ceiling: 10, expected: /下げてください/ },
    { actual: 11, ceiling: 10, expected: /増えています/ },
  ])('上限判定: $actual / $ceiling', ({ actual, ceiling, expected }) => {
    const got = ceilingProblem(actual, ceiling)
    if (expected === null) expect(got).toBeNull()
    else expect(got).toMatch(expected)
  })
})
