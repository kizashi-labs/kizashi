import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync, existsSync } from 'fs'
import { join } from 'path'
import { blankNoise } from './blank-noise'
import {
  API_DIR, API_PREFIX, FRONTEND_ROOTS, METHODS, REPO,
  ceilingProblem, closingParen, filesUnder, frontendCalls, hasRoute,
  isUnrouted, literalStart, matchesRoute, normalisePath, serverRoutes, toPosix,
  type Method,
} from './route-scan'

// サーバに無い宛先の**数**と、それを読む検査。
//
// 走査そのものは route-scan.ts に出しました。**describe を持たないファイル
// なので、ほかの検査が道具を借りても走りません。** 借りるために
// `./server-routes.test` を import していた 3 本は、同じ走査を収集のたびに
// もう一度動かしていました。
//
// ここに残しているのは上限と検査です。上限は「この木の実測」であって
// 道具の性質ではないので、道具と一緒に動かすものではありません。

/**
 * Calls whose endpoint the server does not register. Only go down.
 *
 * Writes are counted separately because they are the ones with a consequence
 * beyond an empty screen: the operator believes something changed.
 */
// 実測 (2026-08-12): 読み取り 117 → **119**。
//
// **117 は少なく数えていました。** 同じ group 変数が別の場所で別の path に
// 束ねられているのが 19 個あり（`ep` は `/endpoints` と
// `/admin/edr-policies`、`cr` に至っては4つ）、union すると**存在しない
// 経路**が生まれます。`:id` は1 segment に何でも当たるので、
// `GET /api/v1/endpoints/criticality` は `GET /api/v1/endpoints/:id`
// （`ep.GET("/:id")` × `/endpoints`、gin には無い組み合わせ）に当たって
// 「サーバにある」と判定されていました。
//
// 内訳: 幻の経路に隠れていた 3 件が出て 120、`GET /endpoints/criticality`
// に本物の経路を足して 119。**上がったのは、増えたからではなく
// 見えるようになったからです。**
//
// **同じことがもう一度あります (2026-08-12): 119 → 126、書き込み
// 150 → 153。** 呼び出しを見つける正規表現が `apiFetch<{ … }>(…)` の
// 形を1件も拾っていませんでした（型引数から `{` を除いていたため）。
// **154 件 / 90 file** が判定の外にあり、そのうち 10 件は宛先が
// ありませんでした。
//
// **そしてもう一度 (2026-08-12): 126 → 137 → 134、書き込み 153 → 159。**
// 判定が `/api/v1` で始まる宛先しか見ていませんでした。サーバは
// `/taxii2` も出しているので、**版のついていない宛先は、間違っていても
// 数に出ません**でした。絶対パスなら全部見るようにして 17 件出ました
// —— TAXII の4件は当たっている（見えていなかっただけ）、残る 13 件は
// 本当に宛先がありません。
//
// 出たうち ITDR の読み取り3本は**宛先の書き間違い**でした
// （`/api/itdr/incidents` に対し、サーバは
// `/api/v1/admin/itdr/incidents`）。直したので読み取りは 134 です。
//
// **数が4度続けて上がりました。4度とも、走査が見ていなかった分です。**
//
// **5度目は下がりました (2026-08-12): 134 → 130。** literal の終わりを
// 探すのに、入れ子のテンプレートを数えていませんでした ——
// `…/items${c ? \`?campaign_id=${c.id}\` : ''}` は内側の ` で切れ、
// **補間の途中で終わる literal**になります。4件が、動いているのに
// 「宛先が無い」と報告されていました。**上がるのと同じくらい、
// 下がるのも走査の間違いでした。**
//
// **6度目も下がりました (main 取り込み): 130 → 129 / 159 → 158。**
// 今回は走査の間違いではなく、宛先が実在するようになった分です ——
// incidents 画面が /api/v1/admin/correlation/rules と
// PUT /api/v1/admin/incidents/:id/status（どちらも router に無い）を
// 呼んでいたのを、実在する /api/v1/correlation-engine と
// PATCH /api/v1/incidents/:id/status に付け替えました (#673)。
// **7度目 (全体同期の取り込み): 129 → 133 / 158 → 163。**
// 今回は上がっている。理由は走査の劣化でも新しい死んだ呼び出しでもなく、
// **公開版のサーバが商用版より提供する経路が少ない**こと。同期は上流の
// frontend を持ち込むが、その画面が叩く宛先の一部はこのリポジトリの
// router に存在しない（ai-triage / ai-usage / agent-update / billing /
// cspm-enhanced 等、docs/openapi.yaml の再生成でも 102 パスが落ちた）。
//
// **上げるのはこの一度だけにすること。** ここから先に増えたぶんは、
// 上流との差ではなく新しく死んだ呼び出しである。下げる方向には自由に
// 動かしてよい（宛先を実装した／画面を BackendPendingBanner に登録した）。
//
// **8度目 (#70 の取り込み): 132 → 133。** 「一度だけ」と書いた直後に
// もう一度上げている。理由を書く:
//
//   #70 が /login の SSO 提供者取得 (`GET /api/v1/auth/sso/providers`) を
//   戻した。この版のサーバに SSO のルートは無い (router.go に sso が 0 件)。
//   overlay に login ページを丸ごとフォークすると、本流が直っても写しが
//   追従しない構図になるため、フォークせず 404 を受けて degrade させる、
//   という判断。画面は壊れない（一覧が空のまま、SSO ボタンが描かれない）。
//
// **この 1 件は backend-pending-coverage.test.ts の DEAD_BUT_GRACEFUL に
// 理由つきで登録してある。** 宛先が実装されればあちらが「もう死んで
// いません」と落ちるので、この +1 も一緒に見直される。
const UNROUTED_READ_CEILING = 133
const UNROUTED_WRITE_CEILING = 163

describe('サーバに無い宛先', () => {
  const goFiles = existsSync(API_DIR) ? filesUnder(API_DIR, ['.go']) : []
  const goSources = goFiles
    .filter(f => !f.endsWith('_test.go'))
    .map(f => readFileSync(f, 'utf8'))
  const routes = serverRoutes(goSources)

  const feFiles = FRONTEND_ROOTS.flatMap(r => filesUnder(join(process.cwd(), r), ['.ts', '.tsx']))
  const rel = (p: string) => p.replace(process.cwd() + '/', '')

  const unrouted = feFiles.flatMap(f =>
    frontendCalls(readFileSync(f, 'utf8'))
      .filter(c => isUnrouted(c, routes))
      .map(c => ({ ...c, file: rel(f) }))
  )

  // ルーティング表を読めていなければ「全部無い」か「全部ある」になり、
  // どちらでも上限判定は通ってしまいます。両側の走査をまず確かめます。
  it('サーバのルーティング表を読めている', () => {
    expect(goFiles.length, 'server/internal/api が見つかりません').toBeGreaterThan(10)
    expect(routes.size, '登録ルートが少なすぎます').toBeGreaterThan(1000)
    // 実在することが確実な数本。走査が壊れたらここが落ちます。
    for (const known of ['GET /agents', 'GET /alerts', 'GET /agents/:id', 'POST /auth/login']) {
      expect(routes.has(known), `${known} を見つけられていません`).toBe(true)
    }
  })

  it('フロントエンドの呼び出しを読めている', () => {
    const all = feFiles.flatMap(f => frontendCalls(readFileSync(f, 'utf8')))
    expect(all.length, 'apiFetch の呼び出しが見つかりません').toBeGreaterThan(500)
    expect(all.filter(c => c.method !== 'GET').length).toBeGreaterThan(100)
  })

  it('ルートの無い読み取りが増えていない', () => {
    const n = unrouted.filter(c => c.method === 'GET').length
    expect(ceilingProblem('ルートの無い読み取り', n, UNROUTED_READ_CEILING)).toBeNull()
  })

  it('ルートの無い書き込みが増えていない', () => {
    const writes = unrouted.filter(c => c.method !== 'GET')
    expect(
      ceilingProblem('ルートの無い書き込み', writes.length, UNROUTED_WRITE_CEILING),
      '押した人には成功に見えます:\n  ' +
        writes.slice(0, 20).map(c => `${c.method} ${c.path}  ${c.file}:${c.line}`).join('\n  ')
    ).toBeNull()
  })

  // ── 判定そのもの ─────────────────────────────────────────────────────────
  // 実測が上限と一致している通常状態では、上の4本はどれも肯定側の分岐に
  // 入りません。ここから下は判定を直接動かします。

  it.each([
    { pattern: '/agents', path: '/agents', want: true },
    { pattern: '/agents/:id', path: '/agents/abc', want: true },
    { pattern: '/agents/:id', path: '/agents', want: false },
    { pattern: '/agents/:id', path: '/agents/abc/tags', want: false },
    { pattern: '/agents/:id/tags/:tag', path: '/agents/a/tags/b', want: true },
    { pattern: '/files/*path', path: '/files/a/b/c', want: true },
    { pattern: '/files/*path', path: '/other/a', want: false },
    { pattern: '/agents', path: '/alerts', want: false },
  ])('経路照合: $pattern vs $path', ({ pattern, path, want }) => {
    expect(matchesRoute(pattern, path)).toBe(want)
  })

  it('グループを辿って完全な経路を組み立てられる', () => {
    const r = serverRoutes([
      `func x() {
         api := s.router.Group("/api/v1")
         protected := api.Group("/")
         ti := protected.Group("/admin/threat-intel")
         ti.POST("/lookup", h.LookupIOC)
         protected.GET("/agents/:id", h.GetAgent)
         s.router.GET("/api/v1/health/detailed", h.Health)
       }`,
    ])
    expect(r.has('POST /api/v1/admin/threat-intel/lookup')).toBe(true)
    expect(r.has('GET /api/v1/agents/:id')).toBe(true)
    // 版のプレフィックスを直接書いたものは、両方の綴りで登録されます。
    expect(r.has('GET /health/detailed')).toBe(true)
    expect(r.has('GET /api/v1/health/detailed')).toBe(true)
  })

  it('コメントの中のルートは登録として数えない', () => {
    const r = serverRoutes([
      `func x() {
         // protected.GET("/ghost", h.Ghost)
         /* protected.POST("/phantom", h.Phantom) */
         protected := api.Group("")
         protected.GET("/real", h.Real)
       }`,
    ])
    expect(r.has('GET /ghost')).toBe(false)
    expect(r.has('POST /phantom')).toBe(false)
    expect(r.has('GET /real')).toBe(true)
  })

  // **同じ名前が別の場所で別の path に束ねられている**とき、登録より上に
  // ある宣言を使うこと。union すると幻の経路が生まれ、**その幻に当たった
  // 呼び出しは「サーバにある」として数から消えます。**
  it('同じ名前の group は、登録の直前の宣言で解決する', () => {
    const r = serverRoutes([
      `func x() {
         api := s.router.Group("/api/v1")
         protected := api.Group("/")
         ep := protected.Group("/endpoints")
         ep.GET("/criticality", h.List)
       }
       func y(protected *gin.RouterGroup) {
         ep := protected.Group("/admin/edr-policies")
         ep.GET("/:id", h.Get)
       }`,
    ])
    expect(r.has('GET /api/v1/endpoints/criticality')).toBe(true)
    expect(r.has('GET /api/v1/admin/edr-policies/:id')).toBe(true)
    // **幻**: `ep.GET("/:id")` は `/endpoints` の側では登録されていません。
    expect(r.has('GET /api/v1/endpoints/:id')).toBe(false)
    expect(r.has('GET /api/v1/admin/edr-policies/criticality')).toBe(false)
  })

  it('Any は全メソッドを答える', () => {
    const r = serverRoutes([`func x() { g := api.Group("/g"); g.Any("/p", h.P) }`])
    for (const m of METHODS) expect(r.has(`${m} /g/p`)).toBe(true)
  })

  it.each([
    // 末尾の補間はクエリ文字列の組み立てで、経路の一部ではありません。
    {
      src: "apiFetch(`/api/v1/admin/api-security/events${params}`)",
      method: 'GET',
      path: '/api/v1/admin/api-security/events',
    },
    {
      src: 'apiFetch(`/api/v1/device-events${buildQuery({ a: 1 })}`)',
      method: 'GET',
      path: '/api/v1/device-events',
    },
    // **入れ子のクエリ組み立て。** 「最後の `${`」で探すと、内側の
    // `${c.id}` に当たって外側が末尾まで届いていないと判断し、
    // **`…/items:p` という存在しない経路**として報告されていました。
    // 実測2件（access-review・MDM プロファイル）——
    // 宛先が無いのは同じでも、**報告される経路が実在しないと、探しに
    // 行った人が何も見つけられません。**
    {
      src: "apiFetch(`/api/v1/admin/access-review/items${c ? `?campaign_id=${c.id}` : ''}`)",
      method: 'GET',
      path: '/api/v1/admin/access-review/items',
    },
    {
      src: "apiFetch(`/api/v1/admin/mdm/profiles${f !== 'all' ? `?platform=${f}` : ''}`)",
      method: 'GET',
      path: '/api/v1/admin/mdm/profiles',
    },
    // 直前が / なら経路の一部なので、そのまま :p にします。
    {
      src: 'apiFetch(`/api/v1/agents/${id}`)',
      method: 'GET',
      path: '/api/v1/agents/:p',
    },
    { src: `apiFetch('/api/v1/agents')`, method: 'GET', path: '/api/v1/agents' },
    {
      src: `apiFetch('/api/v1/agents/x', { method: 'DELETE' })`,
      method: 'DELETE',
      path: '/api/v1/agents/x',
    },
    {
      src: 'apiFetch(`/api/v1/agents/${id}/isolate`, { method: `POST`.length ? { method: "POST" } : {} })',
      method: 'POST',
      path: '/api/v1/agents/:p/isolate',
    },
    {
      src: `apiFetch('/api/v1/agents?per_page=500')`,
      method: 'GET',
      path: '/api/v1/agents',
    },
    {
      src: 'apiFetchList<Agent>(`/api/v1/groups/${g.id}/agents`)',
      method: 'GET',
      path: '/api/v1/groups/:p/agents',
    },
  ])('呼び出しの読み取り: $src', ({ src, method, path }) => {
    const [c] = frontendCalls(src)
    expect(c.method).toBe(method)
    expect(c.path).toBe(path)
  })

  // persist() は書き込み専用で、init に method が無いと読み取りとして
  // 数えられ、違う上限に入ります。呼び出し側の規約として固定します。
  it('persist の呼び出しは必ず method を渡している', () => {
    const offenders: string[] = []
    for (const f of feFiles) {
      const src = readFileSync(f, 'utf8')
      const clean = blankNoise(src)
      for (const m of [...clean.matchAll(/\bpersist\s*\(/g)]) {
        const open = m.index + m[0].length - 1
        const args = src.slice(open, closingParen(clean, open))
        if (!/method:\s*['"](GET|POST|PUT|PATCH|DELETE)['"]/.test(args)) {
          offenders.push(`${rel(f)}:${src.slice(0, m.index).split('\n').length}`)
        }
      }
    }
    expect(offenders, 'method の無い persist は読み取りとして数えられます').toEqual([])
  })

  // 引数の位置決め。入れ子の中のカンマで引数が進むと、別の文字列を経路と
  // して読みます。通常のコードには入れ子のカンマが無く、消しても何も
  // 変わらないので、直接動かします。
  it.each([
    { src: `f('/a', {})`, arg: 0, want: '/a' },
    { src: `f('x', '/b', {})`, arg: 1, want: '/b' },
    { src: `f(t('a', 'b'), '/c', {})`, arg: 1, want: '/c' },
    { src: `f({ a: 1, b: 2 }, '/d')`, arg: 1, want: '/d' },
    { src: `f('/a')`, arg: 1, want: null },
    { src: `f(url, {})`, arg: 0, want: null },
  ])('引数の位置決め: $src → $arg', ({ src, arg, want }) => {
    const clean = blankNoise(src)
    const at = literalStart(src, clean, src.indexOf('('), arg)
    if (want === null) {
      expect(at).toBe(-1)
    } else {
      const quote = src[at]
      expect(src.slice(at + 1, src.indexOf(quote, at + 1))).toBe(want)
    }
  })

  it('直後の呼び出しのメソッドを取り違えない', () => {
    const calls = frontendCalls(
      `const a = apiFetch('/api/v1/read')\n` +
        `const b = apiFetch('/api/v1/write', { method: 'POST' })`
    )
    expect(calls.map(c => c.method)).toEqual(['GET', 'POST'])
  })

  it('コメントの中の呼び出しは数えない', () => {
    expect(frontendCalls(`// apiFetch('/api/v1/ghost')\nconst a = 1`)).toHaveLength(0)
  })

  it.each([
    { name: '一致するルートがある', call: 'GET /agents', want: false },
    { name: 'メソッドだけ違う', call: 'POST /agents', want: true },
    { name: '経路が無い', call: 'GET /nowhere', want: true },
  ])('未登録の判定: $name', ({ call, want }) => {
    const routes = new Set(['GET /agents', 'GET /agents/:id'])
    const [method, path] = call.split(' ')
    expect(
      isUnrouted(
        { method: method as Method, path: API_PREFIX + path, paths: [API_PREFIX + path], line: 1 },
        routes
      )
    ).toBe(want)
  })

  it.each([
    { actual: 10, ceiling: 10, expected: null },
    { actual: 11, ceiling: 10, expected: /増えています/ },
    { actual: 9, ceiling: 10, expected: /下げてください/ },
    { actual: 0, ceiling: 10, expected: /下げてください/ },
  ])('上限判定: $actual / $ceiling', ({ actual, ceiling, expected }) => {
    const got = ceilingProblem('x', actual, ceiling)
    if (expected === null) expect(got).toBeNull()
    else expect(got).toMatch(expected)
  })
})

// ── SDK と mobile ───────────────────────────────────────────────────────────

/**
 * The endpoints the shipped clients call.
 *
 * **照合していたのは `frontend/` だけでした。** SDK も mobile も同じ
 * サーバを叩きますが、どちらも一度も突き合わせていません。実測
 * (2026-08-12): **59 本のうち 16 本に経路がありませんでした** ——
 * Python と TypeScript が同じ 8 つを間違えています（両者は写しなので、
 * 片方の間違いはもう片方にもあります）。
 *
 *	PATCH /alerts/:id 他2つ          サーバは PUT です
 *	GET/POST /threat-intel/ioc       サーバは /ioc です
 *	live-response/sessions ×3        **セッションは端末ごと**で、
 *	                                 `/agents/:id/live-response/sessions` です
 *
 * SDK の検査はクライアントの実装から書かれていて、**間違った宛先を
 * そのまま留めていました** —— 緑のまま、呼べば必ず 404 です。
 */
export function clientCalls(repo: string): Array<{ method: Method; path: string; where: string }> {
  const out: Array<{ method: Method; path: string; where: string }> = []
  const add = (method: string, path: string, where: string) => {
    out.push({ method: method.toUpperCase() as Method, path, where })
  }
  const walk = (dir: string, exts: string[]): string[] => {
    if (!existsSync(dir)) return []
    const acc: string[] = []
    for (const n of readdirSync(dir)) {
      if (n === 'node_modules') continue
      const p = join(dir, n)
      if (statSync(p).isDirectory()) acc.push(...walk(p, exts))
      else if (exts.some(e => p.endsWith(e))) acc.push(p)
    }
    return acc
  }

  // Python / TypeScript SDK: request("GET", "/api/v1/…")
  for (const f of [...walk(join(repo, 'sdk', 'python'), ['.py']),
                   ...walk(join(repo, 'sdk', 'typescript', 'src'), ['.ts'])]) {
    if (toPosix(f).includes('/tests/')) continue
    const src = readFileSync(f, 'utf8')
    for (const m of src.matchAll(/["'`](GET|POST|PUT|PATCH|DELETE)["'`]\s*,\s*f?[`'"]([^`'"]+)[`'"]/g)) {
      add(m[1], m[2], toPosix(f).replace(toPosix(repo) + '/', ''))
    }
  }
  // mobile: axios の baseURL が /api/v1 なので、呼び出しは相対です。
  for (const f of walk(join(repo, 'mobile'), ['.ts', '.tsx'])) {
    const src = readFileSync(f, 'utf8')
    for (const m of src.matchAll(/\bapi\.(get|post|put|patch|delete)(?:<[^>]*>)?\(\s*[`'"]([^`'"]+)[`'"]/g)) {
      add(m[1], '/api/v1' + m[2], toPosix(f).replace(toPosix(repo) + '/', ''))
    }
  }
  return out
}

/** `{id}` も `${id}` も、経路のパラメータとして扱います。 */
export function clientPath(raw: string): string {
  return normalisePath(
    raw.split('?')[0].replace(/\$\{[^}]*\}/g, ':p').replace(/\{[^}]*\}/g, ':p')
  )
}

/**
 * どの配布物から何本見えているか。
 *
 * **合計だけの床では、いちばん小さい配布物が丸ごと抜けても通ります。**
 * 実測 (2026-08-13) は python 25 / typescript 24 / mobile 5 の 54 本で、床は
 * 40 —— mobile を走査から外しても 49 本残るので、検査は緑のままでした。
 * mobile の 5 本はいま全部サーバに当たっているので、もう一方の規則
 * （無い宛先を叩いていない）も何も言いません。**見ているつもりで見て
 * いなくても分からない**、が 40 変異の通しで出た唯一の生き残りです。
 */
export function callsByClient(calls: Array<{ where: string }>): Record<string, number> {
  const out: Record<string, number> = { 'sdk/python': 0, 'sdk/typescript': 0, mobile: 0 }
  for (const c of calls) {
    for (const k of Object.keys(out)) if (c.where.startsWith(k)) out[k]++
  }
  return out
}

// 実測 (2026-08-13)。**増えるのは構いませんが、黙って減るのは走査が壊れた
// 合図です。**
// mobile はこのリポジトリに含まれません（公開版は frontend / sdk まで）。
// **床を 0 にはせず、項目ごと外します。** 0 の床は「走査が壊れても気づけない」
// を意味し、この検査が防ごうとしているものそのものです。mobile を同梱する
// 版では、この行を戻してください。
const CLIENT_FLOORS: Record<string, number> = {
  'sdk/python': 25,
  'sdk/typescript': 24,
}

describe('SDK と mobile の宛先', () => {
  const goSources = existsSync(API_DIR)
    ? filesUnder(API_DIR, ['.go']).filter(f => !f.endsWith('_test.go')).map(f => readFileSync(f, 'utf8'))
    : []
  const routes = serverRoutes(goSources)
  const calls = clientCalls(REPO)

  it('走査が両側に届いている', () => {
    expect(routes.size, 'ルーティング表が読めていません').toBeGreaterThan(1000)
    expect(calls.length, 'SDK/mobile の呼び出しが見つかりません').toBeGreaterThan(40)

    // **配布物ごとに見ます。** 合計だけでは mobile の 5 本が消えても
    // 分かりません。
    const seen = callsByClient(calls)
    expect(Object.keys(CLIENT_FLOORS).length, '床そのものが消えています').toBeGreaterThan(0)
    for (const [client, floor] of Object.entries(CLIENT_FLOORS)) {
      expect(floor, `${client} の床が 0 になっています`).toBeGreaterThan(0)
      expect(
        seen[client],
        `${client} の呼び出しが走査から消えています（実測 ${seen[client]}、床 ${floor}）`
      ).toBeGreaterThanOrEqual(floor)
    }
  })

  // 緑の木では上の判定に届かないので、合成入力で直接見ます。
  it('配布物ごとに数え分けている', () => {
    expect(
      callsByClient([
        { where: 'sdk/python/kizashi_edr/__init__.py' },
        { where: 'sdk/typescript/src/client.ts' },
        { where: 'mobile/app/(tabs)/alerts.tsx' },
        { where: 'mobile/lib/notifications.ts' },
        { where: 'frontend/lib/api.ts' },
      ])
    ).toEqual({ 'sdk/python': 1, 'sdk/typescript': 1, mobile: 2 })
  })

  // **0 が規則です。** SDK は配布物なので、宛先が違えば利用者の呼び出しが
  // そのまま 404 になります。画面と違って、こちらは直せるのが私たちだけです。
  it('サーバに無い宛先を叩いていない', () => {
    const bad = calls
      .filter(c => !hasRoute(c.method, clientPath(c.path), routes))
      .map(c => `${c.method} ${clientPath(c.path)}  ${c.where}`)
      .sort()
    expect(bad, bad.join('\n  ')).toEqual([])
  })

  it.each([
    { raw: '/api/v1/alerts/{alert_id}', want: '/api/v1/alerts/:p' },
    { raw: '/api/v1/alerts/${id}', want: '/api/v1/alerts/:p' },
    { raw: '/api/v1/alerts?limit=50', want: '/api/v1/alerts' },
  ])('経路の正規化: $raw', ({ raw, want }) => {
    expect(clientPath(raw)).toBe(want)
  })
})
