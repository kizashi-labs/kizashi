import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import { join } from 'path'
import { blankNoise } from './blank-noise'

// 素の fetch() で API を叩いている箇所。
//
// これまでの3つの判定 — server-routes / swallowed-reads / silent-writes —
// はどれも apiFetch と persist しか見ていませんでした。素の fetch は
// 40箇所あり、そのどれもが、宛先が実在するかも、失敗を握り潰していないかも、
// 一度も確かめられていませんでした。
//
// サーバ側で「1つの綴りしか見ていない判定」を3回見つけた直後に、同じものを
// こちら側で探して出てきた分です。判定が報告するのは「私はこの形しか見て
// いません」ではなく、数です。
//
// 素の fetch に固有の欠陥がひとつあります。**fetch は 4xx / 5xx で reject
// しません。** res.ok を見なければ、サーバが返したエラーがそのまま成功として
// 扱われます。apiFetch はこれを中で処理しているので、その外に出た瞬間だけ
// 起きます。
//
// 実測で11箇所。中でも書き出し系が重く、
//
//   /admin/audit-logs   500 の本文がそのまま audit-export.csv になり、
//                       catch 側では画面に見えている行から CSV を組み立てて
//                       同じ名前で保存していました。監査に出すファイルが、
//                       いま絞り込んで表示している分にすり替わります
//   /admin/sigma-rules  同じ形。取り込み直すと表示外のルールが消えます
//   /alerts             catch すら無く、エラー本文が alerts_YYYY-MM-DD.csv に
//   webhooks/stripe     Go 側が 500 を返しても catch に入らないので、課金の
//                       更新をしないまま Stripe には 200 を返します。Stripe は
//                       200 のイベントを再送しません
//
// 「fetch を使うな」という規則ではありません。認証前の画面、Blob の
// ダウンロード、Next の route handler など、apiFetch を通せない場所は
// あります。ここが求めるのは、応答が失敗だったかどうかを見ることだけです。

const ROOTS = ['app', 'components', 'lib']

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) sourceFiles(p, out)
    else if (name.endsWith('.tsx') || name.endsWith('.ts')) out.push(p)
  }
  return out
}

/** `fetch(` not preceded by a dot or word char — so `refetch(` is not one. */
const RAW = /(?<![.\w])fetch\s*\(/g

export function balanced(src: string, open: number, o = '(', c = ')'): number {
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
 * Is there a branch that runs when the response is a failure?
 *
 * 「res.ok を見ているか」ではなく「失敗したときに通る道があるか」を見ます。
 * この二つは違います。
 *
 *   if (r.ok) setIntegrations(await r.json())    ← 見ているが、道が無い
 *
 * これは最初 checksTheResponse という名前で「.ok が出てくるか」を見て
 * いました。上の形は通ってしまい、実際に /settings/cloud と /threat-intel が
 * これでした。失敗しても一覧は前のまま、画面は「まだ登録がありません」と
 * 同じ見た目になります。判定を「.ok に触れたか」で書くと、触れて何もして
 * いない箇所が正しいことになります。
 *
 * 失敗側の道と数えるもの:
 *
 *   if (!r.ok) …            否定形
 *   r.ok ? … : …            三項
 *   if (r.ok) { … } else …  else がある
 *   r.status                値そのものを使っている（/status の分類など）
 */
export function respondsToFailure(clean: string, start: number, end: number): boolean {
  const before = clean.slice(Math.max(0, start - 80), start)
  const named = /(?:const|let|var)\s+(\w+)\s*=\s*(?:await\s+)?$/.exec(before)?.[1]
  // 次の fetch の手前で切ります。切らないと、同じファイルの隣の呼び出しが
  // 書いている `if (!r.ok)` をこちらの確認として数えます。応答の変数名は
  // どのブロックでも res や r なので、必ず当たります。
  //
  // これは実際に起きました。/settings/cloud の一覧取得を
  // `if (r.ok) setIntegrations(…)` に戻す変異が生き残り、理由は
  // 30行下の handleCreate が持つ `if (!r.ok)` でした。
  const nextFetch = clean.slice(end).search(/(?<![.\w])fetch\s*\(/)
  const window = nextFetch < 0 ? 700 : Math.min(700, nextFetch)
  const after = clean.slice(end, end + window)

  const hasFailurePath = (v: string, text: string): boolean => {
    const V = v.replace(/[^\w$]/g, '')
    if (new RegExp(`!\\s*${V}\\.ok\\b`).test(text)) return true
    if (new RegExp(`\\b${V}\\.ok\\s*\\?`).test(text)) return true
    if (new RegExp(`\\b${V}\\.ok\\s*===\\s*false`).test(text)) return true
    if (new RegExp(`\\b${V}\\.status\\b`).test(text)) return true
    // if (v.ok) { … } else …
    const m = new RegExp(`if\\s*\\(\\s*${V}\\.ok\\s*\\)`).exec(text)
    if (m) {
      const rest = text.slice(m.index + m[0].length)
      if (/^\s*\{/.test(rest)) {
        const close = balanced(rest, rest.indexOf('{'), '{', '}')
        if (close > 0 && /^\s*else\b/.test(rest.slice(close))) return true
      }
    }
    return false
  }

  if (named && hasFailurePath(named, after)) return true
  // .then(r => … ) — 引数名は何でもよく、async も付きます。
  //
  // 最初に書いたときは async を許していませんでした。res.ok を
  // ちゃんと見ている2箇所が「見ていない」に分類され、この判定は
  // 違反として報告しました。書いている最中に、同じ狭さを自分でやって
  // います。
  const th = /\.then\s*\(\s*(?:async\s+)?\(?\s*(\w+)\s*\)?\s*=>/.exec(after)
  if (th && hasFailurePath(th[1], after.slice(th.index, th.index + 400))) return true
  return false
}

/** Every raw fetch in the tree, with whether its response is checked. */
export function rawFetches(files: Array<{ file: string; src: string }>) {
  const out: Array<{ file: string; line: number; checked: boolean }> = []
  for (const { file, src } of files) {
    const clean = blankNoise(src)
    RAW.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = RAW.exec(clean)) !== null) {
      const open = m.index + m[0].length - 1
      const end = balanced(clean, open)
      if (end < 0) continue
      out.push({
        file,
        line: clean.slice(0, m.index).split('\n').length,
        checked: respondsToFailure(clean, m.index, end),
      })
    }
  }
  return out
}

/**
 * Raw fetches that never look at the response, minus the ones with a reason.
 *
 * キーは file:line ではなく file です。行は編集で動きます。
 */
export const UNCHECKED_ON_PURPOSE: Record<string, string> = {
  'lib/auth.tsx':
    'ログアウトの投げっぱなし。サーバ側のセッション失効が失敗しても、' +
    '手元のトークンは消します。逆にすると、サーバが落ちている間は' +
    'ログアウトできません',
  'app/status/page.tsx':
    'サービス状態ページの遅延測定。応答が返ってきたこと自体が測定対象で、' +
    '内容は見ません。到達できなければ catch が down にします',
}

export function uncheckedProblems(
  sites: Array<{ file: string; line: number; checked: boolean }>,
  excused: Record<string, string>
): string[] {
  return sites
    .filter(s => !s.checked && !excused[s.file])
    .map(s => `${s.file}:${s.line}: fetch の応答を確かめていません。` +
      'fetch は 4xx/5xx で reject しないので、エラーが成功として扱われます')
    .sort()
}

export function staleExcuses(
  sites: Array<{ file: string; line: number; checked: boolean }>,
  excused: Record<string, string>
): string[] {
  const unchecked = new Set(sites.filter(s => !s.checked).map(s => s.file))
  return Object.keys(excused)
    .filter(f => !unchecked.has(f))
    .map(f => `${f}: 例外として残していますが、応答を確かめない fetch がもうありません`)
    .sort()
}

describe('素の fetch', () => {
  const files = ROOTS.flatMap(r =>
    sourceFiles(r).map(file => ({ file, src: readFileSync(file, 'utf8') }))
  )
  const sites = rawFetches(files)

  it('走査が届いている', () => {
    expect(sites.length, '素の fetch が1つも見つかりません').toBeGreaterThan(20)
    expect(sites.some(s => s.file === 'lib/api.ts')).toBe(true)
    // refetch() を拾っていないこと。この木には refetch() が30箇所以上
    // あるので、拾い始めれば件数がはっきり変わります。上限を緩く置くと
    // 「refetch も数えている」判定が通ってしまいます。
    expect(sites.length).toBeLessThan(50)
  })

  it('応答を確かめない fetch が残っていない', () => {
    const problems = uncheckedProblems(sites, UNCHECKED_ON_PURPOSE)
    expect(problems, problems.join('\n  ')).toEqual([])
  })

  it('直した箇所の理由が残っていない', () => {
    const stale = staleExcuses(sites, UNCHECKED_ON_PURPOSE)
    expect(stale, stale.join('\n  ')).toEqual([])
  })

  // 通常状態では上の2本とも肯定側の分岐に入りません。判定を直接動かします。
  it.each([
    { name: '確かめている', sites: [{ file: 'a', line: 1, checked: true }], want: 0 },
    { name: '確かめていない', sites: [{ file: 'a', line: 1, checked: false }], want: 1 },
    { name: '理由がある', sites: [{ file: 'lib/auth.tsx', line: 1, checked: false }], want: 0 },
    { name: '2件', sites: [{ file: 'a', line: 1, checked: false }, { file: 'b', line: 2, checked: false }], want: 2 },
  ])('判定: $name', ({ sites, want }) => {
    expect(uncheckedProblems(sites, UNCHECKED_ON_PURPOSE)).toHaveLength(want)
  })

  it.each([
    { name: 'res.ok を見ている', src: 'const res = await fetch(url)\nif (!res.ok) throw new Error()', want: true },
    { name: 'res.status を見ている', src: 'const res = await fetch(url)\nif (res.status === 404) return null', want: true },
    { name: 'then の中で見ている', src: 'fetch(url).then(r => { if (!r.ok) throw new Error() })', want: true },
    { name: '三項で見ている', src: 'fetch(url).then(r => r.ok ? r.json() : null)', want: true },
    { name: 'async の then で見ている', src: 'fetch(url).then(async res => { if (!res.ok) throw new Error() })', want: true },
    { name: '見ていない', src: 'const res = await fetch(url)\nconst body = await res.json()', want: false },
    { name: '投げっぱなし', src: 'await fetch(url, { method: "DELETE" })', want: false },
    { name: '別の変数の ok を見ている', src: 'const res = await fetch(url)\nif (!other.ok) throw new Error()', want: false },
    { name: 'ok を見ているが失敗側の道が無い', src: 'const r = await fetch(url)\nif (r.ok) setData(await r.json())', want: false },
    { name: 'ok を見て else がある', src: 'const r = await fetch(url)\nif (r.ok) { setData(1) } else { setErr(1) }', want: true },
    { name: 'then が中身を見ていない', src: 'fetch(url).then(r => r.json())', want: false },
    // 窓を次の fetch の手前で切っていること。切らないと、下の save() が
    // 書いている `!r.ok` が load() の確認として数えられます。応答の変数名は
    // どのブロックでも res や r なので、必ず当たります。
    //
    // /settings/cloud で実際に起きました。一覧取得を無防備に戻す変異が
    // 生き残り、理由は30行下の handleCreate が持つ `if (!r.ok)` でした。
    // 判定は直しましたが、**それを守るものがありませんでした** — 変異
    // させたら、窓を切る行を消しても誰も気づきませんでした。
    {
      name: '隣の fetch が書いた ok を自分のものにしない',
      src: 'async function load() {\n  const r = await fetch(a)\n  setData(await r.json())\n}\n' +
        'async function save() {\n  const r = await fetch(b)\n  if (!r.ok) throw new Error()\n}',
      want: false,
    },
  ])('応答の確認: $name', ({ src, want }) => {
    const clean = blankNoise(src)
    RAW.lastIndex = 0
    const m = RAW.exec(clean)!
    const open = m.index + m[0].length - 1
    expect(respondsToFailure(clean, m.index, balanced(clean, open))).toBe(want)
  })

  // 経路の判定（server-routes）が素の fetch を見ていること。
  // 見ていなくても件数は動かない（40件とも実在する宛先）ので、
  // 上限だけでは戻されたことに気づけません。
  it('経路の判定が素の fetch を見ている', async () => {
    const { frontendCalls } = await import('./server-routes.test')
    const calls = frontendCalls(readFileSync('app/settings/cloud/page.tsx', 'utf8'))
    expect(
      calls.some(c => c.path.includes('/cloud/integrations')),
      'server-routes.test.ts の CALL_SITES が素の fetch を含んでいません'
    ).toBe(true)
  })

  it('refetch() を fetch として数えていない', () => {
    const clean = 'const onClick = () => refetch()\nconst r = await fetch(u)\nif (!r.ok) {}'
    expect(rawFetches([{ file: 'x', src: clean }])).toHaveLength(1)
  })
})
