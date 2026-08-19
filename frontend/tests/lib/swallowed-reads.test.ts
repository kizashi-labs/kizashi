import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import { join } from 'path'
import { blankNoise } from './blank-noise'
import {
  DELIBERATE_SWALLOWED_READS,
  ROOTS,
  SWALLOWED_READ_CEILING,
  catchAnswers,
  ceilingProblem,
  discardsError,
  readProblems,
  sourceFiles,
  swallowedReads,
} from './catch-scan'

describe('読み取りの失敗を答えにすり替える', () => {
  const files = ROOTS.flatMap(r => sourceFiles(join(process.cwd(), r)))
  const rel = (p: string) => p.replace(process.cwd() + '/', '')

  it('走査がファイルを見つけている', () => {
    expect(files.length).toBeGreaterThan(300)
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
