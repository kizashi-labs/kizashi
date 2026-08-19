// サーバに無い宛先の走査そのもの。**検査は入っていません。**
//
// もとは server-routes.test.ts の中にありました。ほかの検査ファイルが
// 道具を借りるために `import … from './server-routes.test'` と書いており、
// **test ファイルを import すると、その describe の中身が import した側の
// 収集時にもう一度走ります。** ここは describe の直下で server/internal/api
// の Go を全部と frontend の .ts/.tsx を全部読むので、借りた側 3 本ぶん、
// 同じ走査が計 4 回起きていました（server-routes.test.ts 単体で 197 秒、
// うち import 66 秒）。
//
// 道具だけを describe の無いファイルに出せば、借りても走りません。
// **数値の上限と、それを読む検査は server-routes.test.ts に残しています** ——
// 上限は「この木の実測」で、道具の性質ではないからです。
//
// この形が崩れないように、no-test-imports.test.ts が
// 「test ファイルから test ファイルを import していないこと」を見ています。

import { readFileSync, readdirSync, statSync, existsSync } from 'fs'
import { join } from 'path'
import { blankNoise } from './blank-noise'

// Endpoints the frontend calls that the server does not serve.
//
// Nothing reports this. apiFetch gets a 404, the page's `.catch` turns it into
// an empty list or a resolved promise, and the screen looks like a feature with
// no data yet. It is measurable, though: gin registers every route in
// server/internal/api, so the set of paths the server answers is right there
// in the source, and so is the set of paths the frontend asks for.
//
// Both sets together leave 269 calls with no matching route: 119 reads and
// 150 writes. (117 と数えていた時期があります。同じ group 変数が別の
// 場所で別の path に束ねられているのが 19 個あり、union が作る**幻の
// 経路**に当たった呼び出しが数から消えていました。下の
// UNROUTED_READ_CEILING に内訳があります。)
//
// The write figure was recorded as 131 for one commit. That was an undercount,
// and the cause is worth keeping: twenty pages had moved their writes to
// persist() from lib/persist, which wraps apiFetch, and this scan only looked
// for apiFetch. Nineteen calls vanished from the measurement without a single
// endpoint being fixed — the number fell and read as progress. CALL_SITES below
// now lists both spellings. docs/サーバに無い宛先の内訳.md and
// docs/サーバに無い宛先の内訳-読み取り.md list every one of them, grouped by
// prefix, with the verb and path mistakes already fixed and the rest left as
// product decisions.
//
// The number that matters is in the reads doc: 72 of the 117 unrouted reads
// sit under a prefix where the writes have no route either. Those 45 prefixes
// are not drift between the two sides — the feature exists as a screen and
// nowhere else. Where a write with no route also discarded its failure, the
// operator clicked, the UI confirmed, and nothing changed — 33 such calls
// across 20 pages, since fixed (see silent-writes.test.ts). /admin/geo-blocking
// had no backend at all: no route, no handler, nothing under internal/, behind
// a page that let an admin enable country-level blocking and watch the toggle
// turn on.
//
// This file does not decide which side is wrong. A missing route can mean the
// endpoint was never built, or that the frontend has a typo, or that a feature
// was removed from one side only. It pins the number so it stops growing while
// nobody is looking, which is how it got here.
//
// One blind spot, found by mutation-testing this file and worth stating rather
// than pretending away: a param route swallows its siblings. Delete
// `alerts.GET("/geo-stats")` and /api/v1/alerts/geo-stats still matches
// `alerts/:id`, so the count does not move. That is what the server does too —
// the request is routed to GetAlert with id="geo-stats" and answers a bad-UUID
// error rather than a 404 — so this is the same shape of wrong, not a
// miscount. It does mean a deleted static route under a `:id` sibling passes
// unnoticed here.

export const API_DIR = join(process.cwd(), '..', 'server', 'internal', 'api')
export const REPO = join(process.cwd(), '..')

/**
 * ファイルの経路を `/` 区切りに揃えます。
 *
 * **この走査は「リポジトリからの相対パス」を文字列の切り貼りで作ります**
 * （`f.replace(repo + '/', '')`）。Windows の `join`/`readdirSync` は `\`
 * を返すので、切り落としが空振りして絶対パスがそのまま残り、
 * `callsByClient` の `startsWith('sdk/python')` が **1本も当たりません。**
 *
 * 床（python 25 / typescript 24）は、そのとき初めて「走査から消えた」と
 * 正しく叫びます —— **叫んでいるのは走査の壊れ方で、SDK の中身では
 * ありません。** CI は Linux なので緑のまま、手元でだけ落ちます。
 *
 * Linux では何も変えません（`\` は現れないので恒等写像です）。
 */
export function toPosix(p: string): string {
  return p.split('\\').join('/')
}
export const FRONTEND_ROOTS = ['app', 'components', 'lib']
export const API_PREFIX = '/api/v1'

export type Method = 'GET' | 'POST' | 'PUT' | 'PATCH' | 'DELETE'
export const METHODS: Method[] = ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']

export function filesUnder(dir: string, exts: string[], out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) filesUnder(p, exts, out)
    else if (exts.some(e => name.endsWith(e))) out.push(p)
  }
  return out
}

// ── the server side ─────────────────────────────────────────────────────────

/**
 * `x := y.Group("/path")` — the variable, its parent, and the segment.
 *
 * The parent may be a selector (`s.router.Group("/api/v1")`), so it is
 * captured with dots and reduced to its last identifier. Requiring a bare
 * identifier silently failed on exactly that line, which left `api`
 * unresolved and every route recorded without its /api/v1 prefix.
 */
const GROUP = /(\w+)\s*:?=\s*([\w.]+)\.Group\(\s*"([^"]*)"/g
/** `x.GET("/path", handler)` — including Any, which answers every method. */
const REGISTER = /(\w+)\.(GET|POST|PUT|PATCH|DELETE|Any)\(\s*"([^"]*)"/g

/**
 * Every route the server registers, as "METHOD /path".
 *
 * Group variables are resolved transitively: a route registered on `tiAdmin`
 * where `tiAdmin := protected.Group("/admin/threat-intel")` and
 * `protected := api.Group("/")` is /admin/threat-intel/… . A variable can be
 * assigned more than once in the tree (`agents := protected.Group("/agents")`
 * appears five times), so every base it could have is kept.
 */
export function serverRoutes(sources: string[]): Set<string> {
  type Decl = { parent: string; path: string; at: number }
  // すべての file をまたいだ表（宣言が別 file にある変数のため）。
  const bases = new Map<string, Decl[]>()
  // file ごとの表。**同じ名前が別の場所で別の path に束ねられるため**、
  // どの宣言かを登録の位置で選びます（下の resolve を参照）。
  const perSource: Array<Map<string, Decl[]>> = sources.map(() => new Map())

  sources.forEach((src, i) => {
    const clean = blankNoiseGo(src)
    GROUP.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = GROUP.exec(clean)) !== null) {
      const [, name, parentExpr, path] = m
      const parent = parentExpr.split('.').pop()!
      if (name === parent) continue // `x = x.Group(...)` would not terminate
      const decl: Decl = { parent, path, at: m.index }
      if (!bases.has(name)) bases.set(name, [])
      bases.get(name)!.push(decl)
      if (!perSource[i].has(name)) perSource[i].set(name, [])
      perSource[i].get(name)!.push(decl)
    }
  })

  /**
   * The prefixes a group variable can stand for at a given point in a file.
   *
   * **同じ名前が二度束ねられていました。** router.go の `ep` は 1711 行で
   * `/endpoints`、2767 行で `/admin/edr-policies` です。両方を union すると、
   * `ep.GET("/:id")`（後者）から **`GET /api/v1/endpoints/:id` という
   * 存在しない経路**が生まれます。そして `:id` は1 segment に何でも当たる
   * ので、`GET /api/v1/endpoints/criticality` が「サーバにある」と判定され、
   * **無い経路が数から消えていました。**
   *
   * いまは登録より上にある、いちばん近い宣言を選びます。同じ file に
   * 宣言が無ければ（引数で渡された `protected` など）、今まで通り
   * file をまたいだ表を使います。
   */
  const resolve = (name: string, at: number, i: number, depth = 0): string[] => {
    if (depth > 8) return ['']
    const local = (perSource[i].get(name) ?? []).filter(d => d.at < at)
    if (local.length) {
      const d = local[local.length - 1]
      return resolve(d.parent, d.at, i, depth + 1).map(pp => pp + d.path)
    }
    const global = bases.get(name)
    if (!global) return ['']
    const out: string[] = []
    for (const d of global) {
      for (const pp of resolveGlobal(d.parent, depth + 1)) out.push(pp + d.path)
    }
    return out.length ? out : ['']
  }

  const resolveGlobal = (name: string, depth = 0): string[] => {
    if (depth > 8 || !bases.has(name)) return ['']
    const out: string[] = []
    for (const d of bases.get(name)!) {
      for (const pp of resolveGlobal(d.parent, depth + 1)) out.push(pp + d.path)
    }
    return out.length ? out : ['']
  }

  const routes = new Set<string>()
  const add = (method: string, path: string) => {
    const p = normalisePath(path)
    const methods = method === 'Any' ? METHODS : [method]
    for (const meth of methods) {
      routes.add(`${meth} ${p}`)
      // Some routes are registered straight on the router with the version
      // prefix spelled out (`s.router.GET("/api/v1/health/detailed", …)`).
      if (p.startsWith(API_PREFIX)) routes.add(`${meth} ${p.slice(API_PREFIX.length) || '/'}`)
    }
  }
  sources.forEach((src, i) => {
    const clean = blankNoiseGo(src)
    REGISTER.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = REGISTER.exec(clean)) !== null) {
      const [, name, method, path] = m
      for (const base of resolve(name, m.index, i)) add(method, base + path)
    }
  })
  return routes
}

/**
 * Go's comments and string literals blanked, offsets preserved.
 *
 * The route regexes read the path out of a string literal, so this cannot use
 * blankNoise as-is — it keeps double-quoted contents and only blanks comments
 * and raw backtick strings, which is where the SQL and the doc comments live.
 */
function blankNoiseGo(src: string): string {
  const keep = (s: string) => s.replace(/[^\n]/g, ' ')
  const out: string[] = []
  let i = 0
  while (i < src.length) {
    if (src[i] === '/' && src[i + 1] === '/') {
      let j = src.indexOf('\n', i)
      if (j < 0) j = src.length
      out.push(keep(src.slice(i, j)))
      i = j
      continue
    }
    if (src[i] === '/' && src[i + 1] === '*') {
      let j = src.indexOf('*/', i + 2)
      j = j < 0 ? src.length : j + 2
      out.push(keep(src.slice(i, j)))
      i = j
      continue
    }
    if (src[i] === '`') {
      let j = src.indexOf('`', i + 1)
      j = j < 0 ? src.length : j + 1
      out.push(keep(src.slice(i, j)))
      i = j
      continue
    }
    out.push(src[i])
    i += 1
  }
  return out.join('')
}

export function normalisePath(p: string): string {
  const collapsed = p.replace(/\/+/g, '/')
  return collapsed.length > 1 ? collapsed.replace(/\/$/, '') : collapsed
}

/** Does a gin route pattern answer this concrete path? */
export function matchesRoute(pattern: string, path: string): boolean {
  const a = pattern.split('/').filter(Boolean)
  const b = path.split('/').filter(Boolean)
  const star = a.findIndex(s => s.startsWith('*'))
  if (star >= 0) {
    return b.length >= star && a.slice(0, star).every((s, k) => s === b[k] || s.startsWith(':'))
  }
  if (a.length !== b.length) return false
  return a.every((s, k) => s === b[k] || s.startsWith(':'))
}

// ── the frontend side ───────────────────────────────────────────────────────

/**
 * Calls that name an endpoint.
 *
 * `persist(what, path, init)` from lib/persist wraps apiFetch, so a page
 * converted to it disappears from this scan unless it is listed here. That
 * happened: the unrouted-write count dropped from 131 to 124 when twenty pages
 * adopted the helper, and not one endpoint had been fixed. A measurement that
 * falls when code moves is worse than no measurement — it reads as progress.
 */
// 三つの綴り。二つでは足りませんでした。
//
// persist を足したときは、19件が「宛先が消えた」のではなく「見えていな
// かった」ものとして出てきました。素の fetch も同じで、40件がどの判定
// にも映っていませんでした。数え漏らした分は、直ったのと同じ形で数字に
// 現れます。tests/lib/raw-fetch.test.ts が素の fetch そのものを見ています。
//
// **4つ目の綴りは、型引数でした (2026-08-12)。** `<[^;{]*?>` は `{` を
// 除いていたので、**`apiFetch<{ rules: Rule[] }>(…)` の形が1件も
// 見えていませんでした** —— `apiFetch<Agent[]>` は見えるのに、
// object の型を直接書いた瞬間に消えます。実測 **154 件 / 90 file**、
// 見えていた 1310 件に対して約1割です。
//
// `;` を除くのも駄目でした: `<{ token?: string; enrollment_token?: string }>`
// のように、object の型は中に `;` を持ちます。括弧だけを境にします ——
// 非貪欲なので、次の `(` を越えることはありません。
const CALL_SITES = [
  { re: /\bapiFetch(?:List)?\s*(?:<[^()]*?>)?\s*\(/g, pathArg: 0 },
  { re: /\bpersist\s*\(/g, pathArg: 1 },
  { re: /(?<![.\w])fetch\s*\(/g, pathArg: 0 },
]

export interface Call {
  method: Method
  /** Representative path, for reporting. */
  path: string
  /** Every concrete path the literal can produce. */
  paths: string[]
  line: number
}

/**
 * Every /api/v1 endpoint a file asks for.
 *
 * The method is read from the call's own argument list, bounded by paren
 * matching. An early version scanned a fixed window past the path and picked
 * up the *next* call's `method:`, which reported 31 writes to /api/v1/agents —
 * an endpoint whose GET has existed all along.
 */
export function frontendCalls(src: string): Call[] {
  // The call sites are found in the blanked copy, so a commented-out example
  // is not a call. The path literal has to be read from the original — that is
  // the one thing blankNoise erases. Offsets are identical between the two.
  const clean = blankNoise(src)
  const calls: Call[] = []
  for (const { re, pathArg } of CALL_SITES) {
    re.lastIndex = 0
    let m: RegExpExecArray | null
    while ((m = re.exec(clean)) !== null) {
      const open = m.index + m[0].length - 1
      const q = literalStart(src, clean, open, pathArg)
      if (q < 0) continue
      const quote = src[q]

      const litEnd = findLiteralEnd(src, q + 1, quote)
      const literal = src.slice(q + 1, litEnd)
      if (!literal.startsWith('/')) continue

      const argsEnd = closingParen(clean, open)
      const args = src.slice(open, argsEnd)
      const meth = /method:\s*['"](GET|POST|PUT|PATCH|DELETE)['"]/.exec(args)
      const paths = candidatePaths(literal)
      calls.push({
        method: (meth?.[1] as Method) ?? 'GET',
        path: paths[0],
        paths,
        line: src.slice(0, m.index).split('\n').length,
      })
    }
  }
  return calls
}

/**
 * Index in `src` of the opening quote of argument number `pathArg`.
 *
 * Commas are counted in the blanked copy so a comma inside a string or a
 * comment does not advance the argument, and depth is tracked so a comma
 * inside a nested call or object literal does not either. Returns -1 when that
 * argument is not a string literal — `persist(label, url, …)` where the url is
 * a variable cannot be resolved statically and is skipped rather than guessed.
 */
export function literalStart(src: string, clean: string, open: number, pathArg: number): number {
  let depth = 0
  let arg = 0
  for (let i = open; i < clean.length && i < open + 8000; i++) {
    const c = clean[i]
    if (c === '(' || c === '[' || c === '{') depth++
    else if (c === ')' || c === ']' || c === '}') {
      depth--
      if (depth === 0) return -1
    } else if (c === ',' && depth === 1) {
      arg++
      if (arg > pathArg) return -1
      continue
    }
    if (arg === pathArg && depth === 1) {
      const q = src[i]
      if (q === "'" || q === '"' || q === '`') return i
    }
  }
  return -1
}

function findLiteralEnd(src: string, from: number, quote: string): number {
  // **入れ子のテンプレートで切れていました。**
  //
  //   `/api/v1/admin/access-review/items${c ? `?campaign_id=${c.id}` : \'\'}`
  //                                            ^ ここで終わりだと読む
  //
  // 内側の ` で止まるので、取り出した literal は補間の途中で切れ、
  // **`…/items:p` という存在しない経路**になっていました。補間の中は
  // 深さを数えて飛ばします。
  let interp = 0
  for (let i = from; i < src.length; i++) {
    if (src[i] === '\\') { i++; continue }
    if (quote === '`' && src[i] === '$' && src[i + 1] === '{') { interp++; i++; continue }
    if (interp > 0) {
      if (src[i] === '{') interp++
      else if (src[i] === '}') interp--
      continue
    }
    if (src[i] === quote) return i
  }
  return src.length
}

export function closingParen(src: string, open: number): number {
  let depth = 0
  for (let i = open; i < src.length && i < open + 8000; i++) {
    if (src[i] === '(') depth++
    else if (src[i] === ')' && --depth === 0) return i + 1
  }
  return Math.min(src.length, open + 800)
}

/**
 * The concrete paths a template literal can produce.
 *
 * `${id}` becomes :p, but an interpolation made only of string literals is
 * expanded instead: `/auth/mfa/email/${enable ? 'enable' : 'disable'}` is two
 * real paths, both of which the server registers. Collapsing it to
 * /auth/mfa/email/:p reported a working call as unrouted — the same mistake
 * as reading a segment that is not a parameter as though it were one.
 *
 * Brace-matched, so a ternary or an object inside does not end it early.
 */
export function candidatePaths(lit: string): string[] {
  lit = withoutTrailingQueryBuilder(lit)
  let variants = ['']
  let i = 0
  while (i < lit.length) {
    if (lit[i] === '$' && lit[i + 1] === '{') {
      let depth = 0
      let j = i + 1
      for (; j < lit.length; j++) {
        if (lit[j] === '{') depth++
        else if (lit[j] === '}' && --depth === 0) break
      }
      const expr = lit.slice(i + 2, j)
      const pieces = literalAlternatives(expr)
      variants = variants.flatMap(v => pieces.map(p => v + p))
      i = j + 1
      continue
    }
    const ch = lit[i]
    variants = variants.map(v => v + ch)
    i += 1
  }
  const seen = new Set<string>()
  for (const v of variants) seen.add(normalisePath(v.split('?')[0].split('#')[0]))
  return [...seen]
}

/**
 * Drops a trailing interpolation that is building a query string.
 *
 *   `/api/v1/admin/access-review/items${c ? `?campaign_id=${c.id}` : ''}`
 *   `/api/v1/admin/api-security/events${params}`
 *   `/api/v1/device-events${buildQuery({ … })}`
 *
 * All three are the bare path at runtime, but read literally the tail became
 * a segment (`items:p`) and the call was reported as unrouted. Five calls sat
 * in that state, every one of them working.
 *
 * The tell is that the interpolation is glued to the end with no `/` in front
 * of it: a path segment is always preceded by a slash. A suffix inside the
 * last segment would be caught by this too — that is the accepted cost, and it
 * is much smaller than a systematic false positive.
 */
export function withoutTrailingQueryBuilder(lit: string): string {
  // **いちばん外側の補間を探します。** `lastIndexOf('${')` だと、
  // クエリを組み立てる入れ子の内側に当たります:
  //
  //   `…/items${c ? `?campaign_id=${c.id}` : ''}`
  //                                ^^^^^^ ここが「最後の ${」
  //
  // 外側が末尾まで届いているのに、内側で見ているので届いていないと
  // 判断し、補間はそのまま展開されて `…/items:p` という**存在しない
  // 経路**になります。実測 2 件（access-review・MDM プロファイル）が、
  // **動いているのに「宛先が無い」と報告されていました。**
  let at = -1
  for (let i = 0; i < lit.length; i++) {
    if (lit[i] !== '$' || lit[i + 1] !== '{') continue
    at = i
    // この補間の終わりまで飛ばします（入れ子は数えません）。
    let depth = 0
    for (let j = i + 1; j < lit.length; j++) {
      if (lit[j] === '{') depth++
      else if (lit[j] === '}' && --depth === 0) {
        i = j
        break
      }
    }
  }
  if (at < 0) return lit
  // The interpolation must run to the end of the literal.
  let depth = 0
  let j = at + 1
  for (; j < lit.length; j++) {
    if (lit[j] === '{') depth++
    else if (lit[j] === '}' && --depth === 0) break
  }
  if (j !== lit.length - 1) return lit
  if (at === 0 || lit[at - 1] === '/') return lit
  return lit.slice(0, at)
}

/**
 * The values an interpolation can take, or [':p'] when it is not a choice
 * between string literals.
 *
 * Only expressions built purely of quoted strings, a ternary and `||`/`??`
 * qualify; anything containing an identifier that is used as a value could be
 * any string at runtime and stays a parameter.
 */
export function literalAlternatives(expr: string): string[] {
  const strings = [...expr.matchAll(/'([^']*)'|"([^"]*)"|`([^`$]*)`/g)].map(
    m => m[1] ?? m[2] ?? m[3]
  )
  if (strings.length === 0) return [':p']
  // Remove the literals and the operators that can only select between them.
  const rest = expr
    .replace(/'[^']*'|"[^"]*"|`[^`$]*`/g, '')
    .replace(/[?:|&()\s]|\?\?/g, '')
  // What is left must be an identifier or two doing the selecting, not a value.
  if (/[.[\]+`$]/.test(rest)) return [':p']
  return strings
}

/** One representative path, for reporting. */
export function normaliseLiteral(lit: string): string {
  return candidatePaths(lit)[0]
}

// ── the rule ────────────────────────────────────────────────────────────────

/**
 * True when *no* path this call can produce has a route.
 *
 * A call whose interpolation selects between literals is only a problem if
 * every branch is unrouted; one working branch means the endpoint exists and
 * the parameter is doing its job.
 */
export function isUnrouted(call: Call, routes: Set<string>): boolean {
  return call.paths.every(p => !hasRoute(call.method, p, routes))
}

export function hasRoute(method: Method, path: string, routes: Set<string>): boolean {
  const bare = path.startsWith(API_PREFIX) ? path.slice(API_PREFIX.length) || '/' : path
  if (routes.has(`${method} ${bare}`)) return true
  for (const entry of routes) {
    const sp = entry.indexOf(' ')
    if (entry.slice(0, sp) !== method) continue
    if (matchesRoute(entry.slice(sp + 1), bare)) return true
  }
  return false
}

export function ceilingProblem(what: string, actual: number, ceiling: number): string | null {
  if (actual > ceiling) {
    return `${what}が ${ceiling} から ${actual} に増えています`
  }
  if (actual < ceiling) {
    return `${what}が ${actual} まで減りました。上限を ${actual} に下げてください`
  }
  return null
}
