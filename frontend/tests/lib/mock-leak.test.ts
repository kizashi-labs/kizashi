import { describe, it, expect } from 'vitest'
import { readFileSync } from 'fs'
import { join } from 'path'
import { blankNoise } from './blank-noise'
import {
  GUARDED_ELSEWHERE,
  MOCK_LEAK_CEILING,
  ROOTS,
  brokenExcuses,
  ceilingProblem,
  mockLeakProblems,
  sourceFiles,
  unguardedMockUses,
} from './mock-scan'

describe('守られていない作り物', () => {
  const files = ROOTS.flatMap(r => sourceFiles(join(process.cwd(), r)))
  const rel = (p: string) => p.replace(process.cwd() + '/', '')

  it('走査がファイルを見つけている', () => {
    expect(files.length).toBeGreaterThan(300)
  })

  it('説明の無い箇所が残っていない', () => {
    const counts: Record<string, number> = {}
    for (const f of files) {
      const uses = unguardedMockUses(readFileSync(f, 'utf8'))
      if (uses.length > 0) counts[rel(f)] = uses.length
    }
    for (const file of Object.keys(GUARDED_ELSEWHERE)) {
      counts[file] ??= unguardedMockUses(readFileSync(join(process.cwd(), file), 'utf8')).length
    }

    const reasons: Record<string, string> = {}
    for (const [f, e] of Object.entries(GUARDED_ELSEWHERE)) reasons[f] = e.why
    const problems = mockLeakProblems(counts, reasons)
    expect(problems, problems.join('\n  ')).toEqual([])

    const total = Object.entries(counts)
      .filter(([f]) => !(f in GUARDED_ELSEWHERE))
      .reduce((a, [, n]) => a + n, 0)
    expect(ceilingProblem(total, MOCK_LEAK_CEILING)).toBeNull()
  })

  // 許可の理由が、まだコードに残っていること。
  it('許可の根拠が現存する', () => {
    const sources: Record<string, string> = {}
    for (const f of Object.keys(GUARDED_ELSEWHERE)) {
      sources[f] = readFileSync(join(process.cwd(), f), 'utf8')
    }
    expect(brokenExcuses(sources, GUARDED_ELSEWHERE)).toEqual([])
  })

  // 守りが全部残っている通常状態では、上は一度も肯定側に入りません。
  it.each([
    { name: '守りが残っている', src: 'if (!USE_MOCK) return null', guard: '!USE_MOCK', want: 0 },
    { name: '守りが消えた', src: 'return render()', guard: '!USE_MOCK', want: 1 },
    { name: '守りが要らない用例', src: 'anything', guard: null, want: 0 },
    { name: 'ファイルが読めない', src: undefined, guard: '!USE_MOCK', want: 1 },
  ])('許可の根拠: $name', ({ src, guard, want }) => {
    // 型を明示するのは、`{}` と `{ 'a.tsx': string }` の union が
    // `Record<string, string>` に代入できないためです（値は正しい）。
    const sources: Record<string, string> = src === undefined ? {} : { 'a.tsx': src }
    expect(brokenExcuses(sources, { 'a.tsx': { why: '理由', guard } })).toHaveLength(want)
  })

  // 条件と文言は別々に消せるので、別々に見ます。
  it.each([
    { name: '両方ある', src: 'if (!USE_MOCK) return <p>準備中</p>', want: 0 },
    { name: '条件だけ消えた', src: 'return <p>準備中</p>', want: 1 },
    { name: '文言だけ消えた', src: 'if (!USE_MOCK) return null', want: 1 },
    { name: '両方消えた', src: 'return render()', want: 2 },
  ])('許可の根拠（条件と文言）: $name', ({ src, want }) => {
    expect(
      brokenExcuses(
        { 'a.tsx': src },
        { 'a.tsx': { why: '理由', guard: '!USE_MOCK', guardText: '準備中' } }
      )
    ).toHaveLength(want)
  })

  // 通常状態では上の判定はどちらの分岐にも入りません。
  //
  // 型引数を明示するのは、見本ごとに鍵の顔ぶれが違うと union に推論され、
  // `Record<string, number>` に渡せなくなるためです。
  it.each<{ name: string; counts: Record<string, number>; allow: Record<string, string>; want: number }>([
    { name: '違反なし', counts: {}, allow: {}, want: 0 },
    { name: '未許可の違反', counts: { 'a.tsx': 1 }, allow: {}, want: 1 },
    { name: '許可済み', counts: { 'a.tsx': 1 }, allow: { 'a.tsx': '見本' }, want: 0 },
    { name: '許可が古い', counts: { 'a.tsx': 0 }, allow: { 'a.tsx': '見本' }, want: 1 },
    { name: '許可が計測に出ない', counts: {}, allow: { 'a.tsx': '見本' }, want: 1 },
    { name: '2件', counts: { 'a.tsx': 1, 'b.tsx': 3 }, allow: {}, want: 2 },
  ])('判定: $name', ({ counts, allow, want }) => {
    expect(mockLeakProblems(counts, allow)).toHaveLength(want)
  })

  // 実測が0の通常状態では、検出そのものが一度も肯定側に入りません。
  it.each([
    { name: '素で使う', src: 'const d = data ?? MOCK', want: 1 },
    { name: '入れ子で使う', src: 'const p = raw ?? MOCK.posture', want: 1 },
    { name: '初期状態に使う', src: 'const [x, setX] = useState(MOCK_PREFS)', want: 1 },
    { name: '生成関数も同じ', src: 'const rows = generateMockMetrics(range)', want: 1 },
    { name: 'buildMock も同じ', src: 'const r = buildMockReport(period)', want: 1 },
    { name: 'SAMPLE_ も名前としては拾う', src: 'setEvent(SAMPLE_EVENT)', want: 1 },
    { name: 'm() で守る', src: 'const d = data ?? m(MOCK_AGENTS)', want: 0 },
    { name: 'mockOr で守る', src: 'const d = data ?? mockOr(MOCK, EMPTY)', want: 0 },
    { name: '三項で守る', src: 'const d = USE_MOCK ? MOCK : EMPTY', want: 0 },
    {
      name: '入れ子の三項で守る',
      src: 'useQuery({ ...(USE_MOCK ? { initialData: MOCK_X } : {}) })',
      want: 0,
    },
    { name: '宣言は使用ではない', src: 'const MOCK_AGENTS = [{ id: 1 }]', want: 0 },
    {
      name: '作り物を組み立てる宣言も使用ではない',
      src: 'const MOCK: AssessmentData = { assessments: MOCK_ASSESSMENTS }',
      want: 0,
    },
    {
      name: '宣言が複数行でも中は使用ではない',
      src: 'const MOCK_DATA: CostData = {\n  year: 2026,\n  incidents: MOCK_INCIDENTS,\n}\n',
      want: 0,
    },
    {
      name: '宣言が終わったあとは使用',
      src: 'const MOCK_DATA = {\n  a: MOCK_A,\n}\n\nconst d = data ?? MOCK_DATA\n',
      want: 1,
    },
    { name: '型の位置は値ではない', src: 'useQuery<{ items: typeof MOCK_USERS }>({})', want: 0 },
    { name: 'import は数えない', src: "import { MOCK_X } from './m'", want: 0 },
    { name: 'コメントは数えない', src: '// 以前は MOCK を返していました\nconst a = 1', want: 0 },
    { name: '文字列も数えない', src: 'const s = "MOCK_AGENTS"\nconst a = 1', want: 0 },
    { name: '普通の定数は関係ない', src: 'const d = data ?? EMPTY_STATS', want: 0 },
  ])('検出: $name', ({ src, want }) => {
    expect(unguardedMockUses(src)).toHaveLength(want)
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
