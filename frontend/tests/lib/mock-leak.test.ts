import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import { join } from 'path'
import { blankNoise } from './blank-noise'

// CLAUDE.md の規則そのものを測ります。
//
//   Never reference a `MOCK_*` constant unguarded in a page — always gate it
//   through USE_MOCK / mockOr / m().
//
// fabricated-data.test.ts は FALLBACK_* という「名前」だけを見ていて、
// MOCK という名前は素通りしていました。そのため
//
//   const d = data ?? MOCK          // /admin/alert-routing, /admin/drp
//   const posture = postureRaw ?? MOCK.posture   // /executive
//
// が本番で作り物を描いていても、上限0のまま緑でした。名前を見る検査は、
// 見ている名前の分しか見ていません。
//
// ここは「作り物を指す名前が、USE_MOCK の外で使われている箇所」を数えます。
// 用例（SAMPLE_*）は別扱いです。利用者に「これは例です」と示すための
// 中身は作り物ではありません。下の許可リストに1件ずつ理由を書きます。

const ROOTS = ['app', 'components', 'lib']

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) sourceFiles(p, out)
    else if (name.endsWith('.tsx') || name.endsWith('.ts')) out.push(p)
  }
  return out
}

/** 作り物を指す名前。 */
export const MOCK_NAME =
  /\b(?:MOCK[A-Z_0-9]*|[A-Z][A-Z_0-9]*_MOCK[A-Z_0-9]*|SAMPLE_[A-Z_0-9]+|DEMO_[A-Z_0-9]+|DUMMY_[A-Z_0-9]+|(?:generate|build|get|save)Mock[A-Za-z]*)\b/g

/**
 * 作り物を組み立てている宣言の範囲。
 *
 *   const MOCK_DATA: CostData = {
 *     …
 *     incidents: MOCK_INCIDENTS,     ← ここは「使用」ではない
 *   }
 *
 * 中身を定義するだけでは画面に出ません。出るのは、この定数を使うところです。
 * 行だけを見ると宣言の2行目以降を取り逃がすので、初期化子の範囲を取ります。
 */
export function mockDeclSpans(clean: string): [number, number][] {
  const decl = /^(?:export\s+)?(?:const|let|var|function)\s+([A-Za-z_$][\w$]*)/gm
  const spans: [number, number][] = []
  let m: RegExpExecArray | null
  while ((m = decl.exec(clean)) !== null) {
    if (!new RegExp(`^(?:${MOCK_NAME.source.slice(2, -2)})$`).test(m[1])) continue
    // 次の行頭の非空白まで、が宣言の範囲。
    const rest = clean.slice(m.index)
    const nm = /\n(?=\S)/.exec(rest.slice(1))
    spans.push([m.index, nm ? m.index + 1 + nm.index : clean.length])
  }
  return spans
}

/** m(...) / mockOr(...) の引数の中か。 */
export function insideMockHelper(clean: string, at: number): boolean {
  let depth = 0
  for (let i = at; i >= 0; i--) {
    const c = clean[i]
    if (c === ')') depth++
    else if (c === '(') {
      if (depth === 0) {
        if (/(^|[^\w$.])(m|mockOr)$/.test(clean.slice(Math.max(0, i - 12), i))) return true
      } else depth--
    }
  }
  return false
}

/** 囲っている括弧・波括弧の開き位置。内側から。 */
function enclosers(clean: string, at: number, levels = 4): number[] {
  const out: number[] = []
  let depth = 0
  for (let i = at; i >= 0 && out.length < levels; i--) {
    const c = clean[i]
    if (c === ')' || c === '}' || c === ']') depth++
    else if (c === '(' || c === '{' || c === '[') {
      if (depth === 0) out.push(i)
      else depth--
    }
  }
  return out
}

/**
 * USE_MOCK の三項や条件の内側か。
 *
 * 行だけを見ると `...(USE_MOCK ? { initialData: MOCK_X } : {})` を取り逃がす
 * ので、内側から4段まで、開き括弧から当該位置までに USE_MOCK があるかを見ます。
 */
export function guardedByUseMock(clean: string, at: number, levels = 4): boolean {
  for (const o of enclosers(clean, at, levels)) {
    if (clean.slice(o, at).includes('USE_MOCK')) return true
  }
  let s = at
  while (s > 0 && clean[s - 1] !== ';' && clean[s - 1] !== '\n') s--
  return clean.slice(s, at).includes('USE_MOCK')
}

/**
 * 作り物が守られずに使われている行（1始まり）。
 *
 * 除外するもの:
 *   - import 行
 *   - 作り物自身の宣言（`const MOCK_X = …`）と、作り物を組み立てる宣言
 *     （`const MOCK: T = { assessments: MOCK_ASSESSMENTS }`）。中身を定義
 *     するだけでは画面に出ません。出るのは使うところです。
 *   - `typeof MOCK_X` — 型の位置で、値は取り出していません。
 */
export function unguardedMockUses(src: string): { line: number; id: string }[] {
  const clean = blankNoise(src)
  const spans = mockDeclSpans(clean)
  const out: { line: number; id: string }[] = []
  MOCK_NAME.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = MOCK_NAME.exec(clean)) !== null) {
    const id = m[0]
    if (id === 'USE_MOCK') continue
    const at = m.index
    const line = clean.slice(0, at).split('\n').length
    const text = src.split('\n')[line - 1] ?? ''
    if (/^\s*import\b/.test(text)) continue
    if (/\btypeof\s+$/.test(clean.slice(Math.max(0, at - 10), at))) continue
    // 作り物を組み立てる宣言の中。左辺も作り物の名前であることを要求します。
    if (spans.some(([a, b]) => at >= a && at < b)) continue
    const decl = /\b(?:const|let|var|function|type|interface)\s+([A-Za-z_$][\w$]*)/.exec(text)
    if (decl && (decl[1] === id || new RegExp(MOCK_NAME.source).test(decl[1]))) continue
    if (insideMockHelper(clean, at)) continue
    if (guardedByUseMock(clean, at)) continue
    out.push({ line, id })
  }
  return out
}

/**
 * 走査からは守られていないように見えるが、そうではないもの。
 *
 * 2種類あります。1つは用例 —— 利用者に「これは例です」と見せる中身で、
 * テナントのデータを名乗っていません。もう1つは、呼び出し側が USE_MOCK で
 * 分岐していて、この走査が関数をまたげないだけのものです。
 *
 * 1件ずつ、どちらでなぜかを書きます。「MOCK と付いているが実は違う」は
 * 理由になりません。「利用者が編集する入力欄の初期値」は理由になります。
 */
interface Excuse {
  why: string
  /**
   * 「呼び出し側で守っている」と言うときの、その守り。
   *
   * 文字列としてファイルに残っていることを確かめます。これが無いと、守りを
   * 1行消しても許可リストだけが残り、リストが嘘に変わります。用例のように
   * 守りが存在しないものは null です。
   *
   * 書くのは「守っている条件そのもの」です。守られたときに出る文言を書くと、
   * 条件を `if (false)` に変えても文言はファイルに残るので、通ってしまいます。
   */
  guard: string | null
  /** 守られたときに画面へ出る文言。あれば、これも残っていることを確かめます。 */
  guardText?: string
}

const GUARDED_ELSEWHERE: Record<string, Excuse> = {
  'app/admin/detection-studio/page.tsx': {
    why:
      'ルールを試すための入力イベント。利用者がその場で書き換えるものなので、' +
      'テナントのデータを名乗っていません',
    guard: null,
  },
  'app/admin/notification-templates/page.tsx': {
    why:
      'テンプレートのプレビューで {{alert_title}} などに入れる見本の値です。' +
      'プレビュー以外には出ません',
    guard: null,
  },
  'app/ioc/import/page.tsx': { why: 'ダウンロードできる CSV の記入例です', guard: null },
  'app/threat-intelligence/sharing/page.tsx': {
    why: '画面に載せている STIX の記述例です',
    guard: null,
  },
  'app/admin/data-viz/page.tsx': {
    why:
      'ウィジェットの中身を描く関数です。WidgetRenderer が USE_MOCK でない' +
      'ときに「データ源が接続されていません」を出して打ち切るので、' +
      'ここまで来るのはデモのときだけです',
    // 条件と、そのときに出る文言の両方。条件だけだと文言を消せてしまい、
    // 文言だけだと条件を `if (false)` にできてしまいます。
    guard:
      'function WidgetRenderer({ widget }: { widget: Widget }) {\n  if (!USE_MOCK) {',
    guardText: 'のデータ源が接続されていません',
  },
}

/**
 * 許可の理由が、まだコードに残っているか。
 *
 * `sources` はファイル→中身。守りの文字列が消えていれば、その許可は
 * もう成り立っていません。
 */
export function brokenExcuses(
  sources: Record<string, string>,
  allow: Record<string, Excuse>
): string[] {
  const problems: string[] = []
  for (const [file, e] of Object.entries(allow)) {
    if (e.guard === null) continue
    for (const needle of [e.guard, e.guardText]) {
      if (needle === undefined) continue
      if (!(sources[file] ?? '').includes(needle)) {
        problems.push(
          `${file} の許可は「${e.why}」ですが、その守り (${needle}) が` +
            `ファイルに見当たりません。許可が成り立っていません`
        )
      }
    }
  }
  return problems.sort()
}

/** 説明の無い箇所。0 で固定。 */
const MOCK_LEAK_CEILING = 0

/**
 * 違反と、陳腐化した許可を、1つの判定にまとめたもの。
 *
 * 分けて書くと、木が綺麗で許可が全部生きている通常状態ではどちらのループも
 * 回らず、片方を消しても何も落ちません。
 */
export function mockLeakProblems(
  counts: Record<string, number>,
  allow: Record<string, string>
): string[] {
  const problems: string[] = []
  for (const [file, n] of Object.entries(counts)) {
    if (n > 0 && !(file in allow)) {
      problems.push(
        `${file}: ${n}箇所で作り物を USE_MOCK の外から使っています。` +
          `本番でテナントのデータとして表示されます`
      )
    }
  }
  for (const [file, why] of Object.entries(allow)) {
    if (!counts[file]) {
      problems.push(`${file} はもう作り物を使っていません (${why})。リストから消してください`)
    }
  }
  return problems.sort()
}

export function ceilingProblem(actual: number, ceiling: number): string | null {
  if (actual > ceiling) {
    return `USE_MOCK の外から作り物を使っている箇所が ${ceiling} から ${actual} に増えています`
  }
  if (actual < ceiling) {
    return (
      `USE_MOCK の外から作り物を使っている箇所が ${actual} まで減りました。` +
      `MOCK_LEAK_CEILING を ${actual} に下げてください`
    )
  }
  return null
}

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
