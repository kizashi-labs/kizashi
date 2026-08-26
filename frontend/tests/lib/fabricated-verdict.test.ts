import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import { join } from 'path'
import { blankNoise, regexCanStartHere } from './blank-noise'
import { toPosix } from './route-scan'

// A `catch` that invents the answer.
//
// The previous gate stopped the dashboard from inventing ambient numbers. This
// is the sharper version of the same defect: the operator asks a question, the
// request fails, and the UI answers anyway.
//
//   admin/sigma-rules       matched: Math.random() > 0.4, and
//                           matched_fields: ['CommandLine', 'Image'] as evidence
//   admin/yara-rules        matched, with '$s1 at 0x10' as the offset it hit
//   admin/detection-studio  70% "マッチ!", with an encoded-PowerShell command
//                           line presented as the matching field
//   admin/threat-intelligence  60% "脅威インジケーター検出", confidence 60-99,
//                           severity picked from four, source 'MISP Community'
//   admin/siem-integration  a failed connection test toasting 接続成功 with a
//                           latency in ms
//   admin/log-forwarding    the same, for the SIEM forwarding destination
//   admin/observability     the same, returning { success: true }
//   admin/log-sources       a 404 on "create source" answered with a browser-
//                           generated ingest token, and "regenerate" the same
//   admin/saved-searches    "3,412件マッチ・210ms" for a search that never ran
//
// Five of those pages already render BackendPendingBanner, which says この画面の
// バックエンドは準備中です at the top. The page admitted the backend was missing
// in the header and reported a confident result in the body.
//
// The consequence is not a wrong number on a chart. A detection engineer ships
// a rule because the test said MATCHED. An analyst opens an incident because
// the lookup said the hash is known-malicious. An operator finishes configuring
// log forwarding because the test said 接続成功, and the logs go nowhere.

const ROOTS = ['app', 'components']

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) sourceFiles(p, out)
    else if (name.endsWith('.tsx') || name.endsWith('.ts')) out.push(p)
  }
  return out
}

// blankNoise と regexCanStartHere は tests/lib/blank-noise.ts に移しました。
// 7本のゲートがここから import していたので、どれを走らせてもこのファイルの
// テストが丸ごと一緒に走っていました（65秒かかるものを含めて）。
// 道具としての import が、テストの実行を連れてきていました。


// catch (e) { … }, onError: (e) => { … }, onError: e => { … }
const HANDLER =
  /\bcatch\s*(?:\([^)]*\))?\s*\{|\bonError\s*:\s*(?:async\s+)?(?:\([^)]*\)|[A-Za-z_$][\w$]*)\s*=>\s*\{/g

/**
 * Line numbers (1-based) where Math.random() sits inside a failure handler.
 *
 * Separated out and driven directly below: with the tree clean the loop never
 * pushes, and a scan that finds nothing reads exactly like one that looks
 * nowhere.
 */
export function randomInHandlers(src: string): number[] {
  const clean = blankNoise(src)
  const found: number[] = []
  HANDLER.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = HANDLER.exec(clean)) !== null) {
    const start = m.index + m[0].length - 1 // the opening brace
    let depth = 0
    let i = start
    for (; i < clean.length; i++) {
      if (clean[i] === '{') depth++
      else if (clean[i] === '}' && --depth === 0) break
    }
    const body = clean.slice(start, i)
    for (const hit of body.matchAll(/Math\.random\(\)/g)) {
      found.push(clean.slice(0, start + (hit.index ?? 0)).split('\n').length)
    }
  }
  return found
}

/**
 * Handlers still allowed to invent an answer.
 *
 * Empty, and it stays empty. An entry here is a screen that answers a question
 * it could not answer — not a style preference.
 */
const KNOWN_FABRICATING_HANDLERS: Record<string, string> = {}

/**
 * Both halves of the rule, as one function over measurements.
 *
 * `counts` is file → how many fabricating handlers it has. Returns a complaint
 * for every unlisted file that has one, and for every listed file that no
 * longer does.
 *
 * Extracted because with the tree clean and the allowlist empty neither branch
 * is ever reached, and a rule that never fires reads exactly like one that was
 * deleted — deleting the staleness check outright changed nothing until this
 * existed.
 */
export function handlerProblems(
  counts: Record<string, number>,
  allow: Record<string, string>
): string[] {
  const problems: string[] = []
  for (const [file, n] of Object.entries(counts)) {
    if (n > 0 && !(file in allow)) {
      problems.push(`${file}: 失敗したときに乱数で答えを作っています`)
    }
  }
  for (const [file, why] of Object.entries(allow)) {
    if (!counts[file]) {
      problems.push(`${file} はもう作り物を返していません (${why})。許可リストから消してください`)
    }
  }
  return problems.sort()
}

describe('blankNoise の下ごしらえ', () => {
  // 正規表現リテラルを文字列として読むと、そこから引用符の対応がずれます。
  // app/ioc/page.tsx の1行がそれで、9ファイル・1,668行が blankNoise を使う
  // すべての判定から見えなくなっていました。空白になった範囲は「そこに
  // 何も無い」と同じ形なので、どの判定も違反0件として通ります。
  it('正規表現の中の引用符で対応がずれない', () => {
    const src = [
      "const m = s.match(/\\[[\\w-]+:[\\w.]+\\s*=\\s*'([^']+)'\\]/)",
      'const found = <PageSaveFailed />',
    ].join('\n')
    expect(blankNoise(src)).toContain('PageSaveFailed')
  })

  // 逆方向。TSX の閉じタグ `</div>` の `/` を正規表現の開始と読むと、
  // 同じ行にもう1つ `/` があればその間が空白になります。JSX だらけの
  // ファイルでは走査そのものが崩れます。
  it('JSX の閉じタグを正規表現として読まない', () => {
    const src = '<div><span>x</span></div>\nconst y = useMutation({})'
    const clean = blankNoise(src)
    expect(clean).toContain('span')
    expect(clean).toContain('useMutation')
  })

  it.each([
    { name: '行頭', before: '', want: true },
    { name: '代入の後', before: 'const r = ', want: true },
    { name: '開き括弧の後', before: 'foo(', want: true },
    { name: 'return の後', before: 'return ', want: true },
    { name: '値の後（除算）', before: 'const x = a ', want: false },
    { name: '閉じ括弧の後（除算）', before: 'f(a) ', want: false },
    { name: 'JSX の閉じタグ', before: '<div>x<', want: false },
    { name: '識別子の後', before: 'width', want: false },
  ])('regexCanStartHere: $name', ({ before, want }) => {
    expect(regexCanStartHere(before)).toBe(want)
  })

  // 1行で閉じない `/` は正規表現ではありません。ここを外すと、
  // 閉じタグ1つでファイルの残り全部が空白になります。
  it('閉じない正規表現がファイルの残りを飲み込まない', () => {
    const src = 'const a = (/unterminated\nconst b = useMutation({})'
    expect(blankNoise(src)).toContain('useMutation')
  })
})

describe('失敗したときに答えを作る', () => {
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

  it('catch / onError の中に Math.random() が無い', () => {
    const counts: Record<string, number> = {}
    for (const f of files) {
      const lines = randomInHandlers(readFileSync(f, 'utf8'))
      if (lines.length > 0) counts[rel(f)] = lines.length
    }
    for (const file of Object.keys(KNOWN_FABRICATING_HANDLERS)) {
      counts[file] ??= randomInHandlers(readFileSync(join(process.cwd(), file), 'utf8')).length
    }

    const problems = handlerProblems(counts, KNOWN_FABRICATING_HANDLERS)
    expect(
      problems,
      '利用者は、これを自分が投げた質問の答えとして読みます:\n  ' + problems.join('\n  ')
    ).toEqual([])
  })

  // 通常状態では違反も陳腐化した許可も無いので、上のテストはどちらの分岐にも
  // 入りません。判定そのものを直接動かします。
  it.each<{ name: string; counts: Record<string, number>; allow: Record<string, string>; want: number }>([
    { name: '違反なし', counts: {}, allow: {}, want: 0 },
    { name: '未許可の違反', counts: { 'a.tsx': 1 }, allow: {}, want: 1 },
    { name: '許可済みの違反', counts: { 'a.tsx': 1 }, allow: { 'a.tsx': '理由' }, want: 0 },
    { name: '許可が古い（もう直っている）', counts: { 'a.tsx': 0 }, allow: { 'a.tsx': '理由' }, want: 1 },
    { name: '許可が古い（計測にも出ない）', counts: {}, allow: { 'a.tsx': '理由' }, want: 1 },
    { name: '2件', counts: { 'a.tsx': 1, 'b.tsx': 2 }, allow: {}, want: 2 },
  ])('判定: $name', ({ counts, allow, want }) => {
    expect(handlerProblems(counts, allow)).toHaveLength(want)
  })

  // 検出そのもの。正常なコードでは1件も見つからないので、
  // 「見つからない」と「探していない」が区別できません。
  it.each([
    {
      name: 'catch ブロック',
      src: 'try { f() } catch { const x = Math.random() }',
      want: 1,
    },
    {
      name: 'catch (e) ブロック',
      src: 'try { f() } catch (e) {\n  return Math.random()\n}',
      want: 1,
    },
    {
      name: 'onError の矢印関数',
      src: 'useMutation({ onError: (e) => { setR(Math.random()) } })',
      want: 1,
    },
    {
      name: 'onError の引数1つ省略形',
      src: 'useMutation({ onError: e => { setR(Math.random()) } })',
      want: 1,
    },
    {
      name: 'try の中は対象外',
      src: 'try { const x = Math.random() } catch { g() }',
      want: 0,
    },
    {
      name: 'catch の外は対象外',
      src: 'try { f() } catch { g() }\nconst x = Math.random()',
      want: 0,
    },
    {
      name: '入れ子のブロックも catch の内側',
      src: 'try { f() } catch {\n  if (a) { const x = Math.random() }\n}',
      want: 1,
    },
    {
      name: 'コメントの中の言及は数えない',
      src: 'try { f() } catch {\n  // ここは Math.random() でした\n  throw e\n}',
      want: 0,
    },
    {
      name: '文字列の中の言及も数えない',
      src: 'try { f() } catch {\n  throw new Error("Math.random() は使いません")\n}',
      want: 0,
    },
    {
      name: 'テンプレートリテラルの ${} の中は数える',
      src: 'try{f()}catch{ toast(`接続成功 — ${Math.floor(Math.random()*150)}ms`) }',
      want: 1,
    },
    {
      name: 'テンプレートリテラルの地の文は数えない',
      src: 'try{f()}catch{ toast(`以前は Math.random() でした`) }',
      want: 0,
    },
    {
      name: '入れ子のテンプレートリテラル',
      src: 'try{f()}catch{ toast(`a${`b${Math.random()}`}c`) }',
      want: 1,
    },
    {
      name: '2件',
      src: 'try{f()}catch{ a(Math.random()); b(Math.random()) }',
      want: 2,
    },
  ])('検出: $name', ({ src, want }) => {
    expect(randomInHandlers(src)).toHaveLength(want)
  })

  // blankNoise が消しすぎると、上の「数えない」ケースが全部通ってしまい、
  // 同時に本物も見えなくなります。位置を保つことがこの関数の仕事です。
  it('コメントと文字列を消しても位置がずれない', () => {
    const src = 'const a = 1 // Math.random()\nconst b = Math.random()'
    const blanked = blankNoise(src)
    expect(blanked).toHaveLength(src.length)
    expect(blanked.split('\n')).toHaveLength(2)
    expect(blanked).not.toContain('// Math.random()')
    expect(blanked.split('\n')[1]).toContain('Math.random()')
  })

  // 長さが1文字でもずれると、以降の位置がすべてずれます。落ちるのではなく、
  // 別の場所を見て「見つからない」と答えるので、静かに効かなくなります。
  it.each([
    "const c = { flag: '🇨🇳' }\nconst d = Math.random()",
    "const s = 'サロゲートペア: 𝕏 と 👨‍👩‍👧‍👦'\nconst d = Math.random()",
    'const t = `絵文字 ${"🎉"} つき`\nconst d = Math.random()',
    'const u = "改行なし"\nconst d = Math.random()',
  ])('長さが変わらない: %s', src => {
    const blanked = blankNoise(src)
    expect(blanked).toHaveLength(src.length)
    expect(blanked.indexOf('Math.random()')).toBe(src.indexOf('Math.random()'))
  })
})
