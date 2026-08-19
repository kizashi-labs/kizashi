import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync, existsSync } from 'fs'
import { join } from 'path'
import { serverRoutes, frontendCalls, isUnrouted, ceilingProblem } from './route-scan'

// A screen every one of whose API calls has no route must say so.
//
// BackendPendingBanner already carries 67 routes and renders
// 「この画面のバックエンドは準備中です」at the top of each. Eight screens in
// the same state were missing from it — reachable from the sidebar, no notice,
// and 100% of their apiFetch calls naming endpoints with no route anywhere in
// server/internal/api:
//
//   /admin/custom-fields     8/8   カスタム項目の作成・並べ替え・削除
//   /admin/security-budget   5/5
//   /admin/mfa-management    3/3   MFAのリセット・無効化
//   /admin/agent-performance 1/1
//   /admin/dark-web          1/1
//   /admin/maturity-model    1/1
//   /admin/webhook-tester    1/1
//   /reports/builder         1/1
//
// Not partly broken — nothing on any of them reaches the server. To a user
// they were finished features.
//
// This is not the decision about whether those features should exist; that is
// in docs/判断待ちの一覧.md and belongs to the owner. This is the part that
// holds under every possible answer: a screen that cannot do anything must not
// look like it can.

const APP = join(process.cwd(), 'app')
const API_DIR = join(process.cwd(), '..', 'server', 'internal', 'api')
// **一覧はここ1つです。** 元は `BackendPendingBanner.tsx` の中にあり、
// 画面を開いて初めて「準備中」と分かる形でした。サイドバーからも読める
// ように `lib/backend-pending.ts` に移してあります —— 写しを持つと、
// 片方だけ増えて「バナーは出るのにサイドバーは普通の顔をしている」画面が
// できます。下の検査が、写しが生まれていないことを留めます。
const BANNER = join(process.cwd(), 'lib/backend-pending.ts')
const SIDEBAR = join(process.cwd(), 'components/layout/Sidebar.tsx')

function filesUnder(dir: string, exts: string[], out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) filesUnder(p, exts, out)
    else if (exts.some(e => name.endsWith(e))) out.push(p)
  }
  return out
}

/** The route a page.tsx serves, as the app router sees it.
 *
 * **区切りを `/` に揃えます。** `join` は Windows で `\` を返すので、
 * 揃えないと経路が `\admin\group-policies` になり、告知リストの
 * `'/admin/group-policies'` と**一件も当たりません** —— 判定は
 * 「全部が未告知」に見え、CI（Linux）と手元で違う数が出ます。
 */
export function routeOf(pageFile: string): string {
  const rel = pageFile.replace(APP, '').replace(/\\/g, '/').replace(/\/page\.tsx$/, '')
  // Route groups — (marketing)/foo — are not part of the URL.
  return rel.replace(/\/\([^)]*\)/g, '') || '/'
}

/**
 * Which routes the banner announces, both the full and the partial list.
 *
 * Read out of the source rather than imported: the component is a client
 * component that calls usePathname, and the lists are the contract here, not
 * the rendering.
 */
export function announcedRoutes(src: string): { full: Set<string>; partial: Set<string> } {
  const listOf = (name: string) => {
    const at = src.indexOf(`${name} = new Set`)
    if (at < 0) return new Set<string>()
    const end = src.indexOf('])', at)
    return new Set(
      [...src.slice(at, end).matchAll(/'([^']+)'/g)].map(m => m[1])
    )
  }
  return { full: listOf('BACKEND_PENDING_ROUTES'), partial: listOf('PARTIAL_PENDING_ROUTES') }
}

/**
 * Screens that must be announced, and stale announcements.
 *
 * Separated out because on the passing path both loops fall through: no screen
 * is silently dead and no entry is stale, so neither branch is ever reached and
 * a rule that never fires reads the same as one that was deleted.
 */
export function bannerProblems(
  deadScreens: string[],
  announced: { full: Set<string>; partial: Set<string> }
): string[] {
  const problems: string[] = []
  for (const route of deadScreens) {
    if (!announced.full.has(route) && !announced.partial.has(route)) {
      problems.push(
        `${route}: この画面の API 呼び出しはすべてサーバにルートがありません。` +
          'BackendPendingBanner に登録していないと、完成した機能に見えます'
      )
    }
  }
  return problems.sort()
}

/**
 * Announced-as-pending pages that have at least one call the server answers.
 *
 * **「まだ無い」の告知は、無いあいだだけ正しい**ものです。実装された
 * あとも出し続けると、動いている機能を利用者が避けます —— 空の画面と
 * 同じくらい、使われないという結果は同じです。
 */
export function aliveAnnouncedScreens(full: Set<string>, routes: Set<string>): string[] {
  const out: string[] = []
  for (const f of filesUnder(APP, ['page.tsx'])) {
    const route = routeOf(f)
    if (!full.has(route)) continue
    const calls = frontendCalls(readFileSync(f, 'utf8'))
    const routed = calls.filter(c => !isUnrouted(c, routes))
    if (routed.length > 0) {
      out.push(`${route}: ${routed.length}/${calls.length} 本が届きます (${routed[0].method} ${routed[0].path})`)
    }
  }
  return out.sort()
}

/**
 * How much of a screen reaches the server.
 *
 * **切り出してあるのは、`全部死んでいる` を数から外す条件が「通る木では
 * 何も変えない」からです。** 全部死んでいる画面はどれも告知済みなので、
 * その条件を外しても 43 のままでした —— 見本を食わせて直接殺します。
 *
 * 3つを分けるのは、**読まれ方が違う**からです:
 *
 *	clean   全部届く
 *	partly  動く区画と動かない区画が混ざる（いちばん見分けにくい）
 *	dead    全部届かない（`BackendPendingBanner` が出ます）
 */
export function screenVerdict(total: number, bad: number): 'clean' | 'partly' | 'dead' {
  if (bad === 0) return 'clean'
  if (bad === total) return 'dead'
  return 'partly'
}

describe('バックエンドの無い画面の告知', () => {
  const goFiles = existsSync(API_DIR)
    ? filesUnder(API_DIR, ['.go']).filter(f => !f.endsWith('_test.go'))
    : []
  const routes = serverRoutes(goFiles.map(f => readFileSync(f, 'utf8')))
  const announced = announcedRoutes(readFileSync(BANNER, 'utf8'))

  /** Pages where every apiFetch call is unrouted. One call is enough to count. */
  const deadScreens = filesUnder(APP, ['page.tsx'])
    .filter(f => {
      const calls = frontendCalls(readFileSync(f, 'utf8'))
      return calls.length > 0 && calls.every(c => isUnrouted(c, routes))
    })
    .map(routeOf)

  it('走査が両側に届いている', () => {
    expect(goFiles.length, 'server/internal/api が見つかりません').toBeGreaterThan(10)
    expect(routes.size).toBeGreaterThan(1000)
    expect(announced.full.size, '告知リストが読めていません').toBeGreaterThan(50)
    expect(deadScreens.length, '判定が1画面も見つけていません').toBeGreaterThan(0)
  })

  it('API がすべて届かない画面は「準備中」と告知している', () => {
    const problems = bannerProblems(deadScreens, announced)
    expect(problems, problems.join('\n  ')).toEqual([])
  })

  // **逆向きの嘘は、これまで誰も見ていませんでした。**
  //
  // 上の検査は「届かない画面が告知されているか」しか見ません。
  // 告知したまま backend が実装された画面は、**動いているのに
  // 「準備中」と言い続けます** —— 利用者はその機能を使いません。
  //
  // 実測 (2026-08-12): **15 画面**。`/admin/group-policies` は 10 本中
  // 9 本、`/yara` は 8/10、`/admin/oncall` は 7/8 が届きます。
  // `/admin/asset-criticality` は 3/3 届くようになったので外しました。
  //
  // **14 と数えていた時期があります。** 呼び出しの判定が
  // `apiFetch<{ … }>(…)` の形を見ていなかったためで、`/alerts/rules` を
  // 「1/1 届く」と読んでいました（実際は 4/5）。**全部届く画面は
  // 1つもありません** —— 外せるものが在るように見えていただけです。
  //
  // 上限で留めているのは、**どれを消して、どれを「一部準備中」に
  // 移すかが product の判断**だからです（`docs/判断待ちの一覧.md`）。
  // 増えないこと・減ったら下げることだけを見ます。
  //
  // **16 件目は意図したものです (2026-08-12)。** `/admin/itdr` は経路が
  // ありますが、サーバは 501（未実装）を返します —— この判定が見るのは
  // 「経路が在るか」だけなので、**501 を返す経路も「届く」に数えます。**
  // 告知は正しく、経路も正しく、それでもここに出ます。
  // 17 件目も同じです: `/admin/drp` も経路はあり、501 を返します。
  // 18・19 件目も同じ（`/admin/alert-routing`・`/admin/security-assessment`）。
  //
  // **この5つは「経路が在って 501」です。** 判定が見るのは経路の有無
  // だけなので「届く」に数えられますが、告知は正しく、経路も正しい。
  //
  // **19 → 17 (2026-08-17)。** 9割以上届く2画面
  // （group-policies 9/10・yara 8/10）を「一部準備中」へ移しました ——
  // 「全部無い」と「ほぼ在る」を同じ告知で出していたのが元の形です。
  // 残る 17 は「使えるとは言えない」ままなので、告知も上限も据え置きです。
  const ANNOUNCED_BUT_ALIVE_CEILING = 17

  it('「準備中」と告知した画面に、届く呼び出しが増えていない', () => {
    const alive = aliveAnnouncedScreens(announced.full, routes)
    expect(
      ceilingProblem('告知したまま届く画面', alive.length, ANNOUNCED_BUT_ALIVE_CEILING),
      alive.join('\n  ')
    ).toBeNull()
  })

  // 通常状態では上の判定は肯定側の分岐に入りません。直接動かします。
  it.each([
    { name: '告知済み', dead: ['/a'], full: ['/a'], partial: [], want: 0 },
    { name: '一部準備中として告知済み', dead: ['/a'], full: [], partial: ['/a'], want: 0 },
    { name: '未告知', dead: ['/a'], full: [], partial: [], want: 1 },
    { name: '別の画面が告知済み', dead: ['/a'], full: ['/b'], partial: [], want: 1 },
    { name: '死んだ画面が無い', dead: [], full: [], partial: [], want: 0 },
    { name: '2件未告知', dead: ['/a', '/b'], full: [], partial: [], want: 2 },
  ])('判定: $name', ({ dead, full, partial, want }) => {
    expect(
      bannerProblems(dead, { full: new Set(full), partial: new Set(partial) })
    ).toHaveLength(want)
  })

  it.each([
    { file: join(APP, 'admin/custom-fields/page.tsx'), want: '/admin/custom-fields' },
    { file: join(APP, 'agents/[id]/config/page.tsx'), want: '/agents/[id]/config' },
    { file: join(APP, 'page.tsx'), want: '/' },
  ])('経路の導出: $want', ({ file, want }) => {
    expect(routeOf(file)).toBe(want)
  })

  /**
   * Screens where some calls work and some go nowhere, announced as neither.
   *
   * **これまで見ていたのは「全部死んでいる画面」だけでした。**
   * 一部だけ死んでいる画面は、動く区画があるぶん**見分けにくい**形です
   * —— 押しても何も起きないボタンが1つ混ざっていても、画面全体は
   * 動いて見えます。
   *
   * 実測 (2026-08-12): **43 画面 / 61 本**。告知は
   * `PARTIAL_PENDING_ROUTES` に4件しかありません。
   */
  function partlyDeadScreens(): string[] {
    const out: string[] = []
    for (const f of filesUnder(APP, ['page.tsx'])) {
      const route = routeOf(f)
      if (announced.full.has(route) || announced.partial.has(route)) continue
      const calls = frontendCalls(readFileSync(f, 'utf8'))
      if (calls.length === 0) continue
      const bad = calls.filter(c => isUnrouted(c, routes))
      if (screenVerdict(calls.length, bad.length) !== 'partly') continue
      out.push(`${route}: ${bad.length}/${calls.length} 本が届きません (${bad[0].method} ${bad[0].path})`)
    }
    return out.sort()
  }

  // 実測 (2026-08-12): 43 画面 → **入れ子のテンプレートで切れていた
  // literal を直して 39**（4件は動いていました）。
  // → `/incidents/[id]` を告知して **38**。
  //
  // **2026-08-17: 残る 38 画面すべてを告知して 0。上限ではなく規則です。**
  // 告知しない選択肢は「押しても何も起きないボタンを黙って置く」ことと
  // 同じでした。宛先を作ったら、その画面を `PARTIAL_PENDING_ROUTES`
  // から外してください —— **0 なので、外し忘れも足し忘れも落ちます。**
  const PARTLY_DEAD_CEILING = 0

  it('一部だけ届かない画面が、告知されずに残っていない', () => {
    const partly = partlyDeadScreens()
    expect(
      ceilingProblem('一部だけ届かない画面', partly.length, PARTLY_DEAD_CEILING),
      partly.slice(0, 20).join('\n  ')
    ).toBeNull()
  })

  // **サイドバーが、同じ一覧を読んでいること。**
  //
  // 実測 (2026-08-12): サイドバーの 292 項目のうち **60 が準備中**です。
  // 印が無ければ、動く 232 と見分けがつきません —— 開いて、戻って、
  // また別のを開くことになります。
  //
  // **60 → 59 (2026-08-17)。** `/admin/group-policies` を「一部準備中」
  // へ移したぶんです（`/yara` はサイドバーに導線がありません）。数えて
  // いるのは**全部準備中の印**だけなので、一部準備中に移した画面は
  // ここから外れます。
  //
  // **59 → 60 (全体同期の取り込み)。** 増えたのは告知が増えたからで、
  // 壊れたからではない。この取り込みで判定が捕まえた「全 API が届かない
  // のに告知が無い画面」を 2 つ登録した:
  //
  //   /admin/integrations/ldap        隣の elastic / sentinel / soar は登録済み
  //   /admin/uninstall-protection
  //
  // （/auth/sso も登録したが、サイドバーに導線が無いのでここには出ない。
  //   /rules は「一部準備中」なので、この数は全部準備中の印だけを数える。）
  const NAV_PENDING = 60

  it('サイドバーの「準備中」が、同じ一覧から来ている', () => {
    const nav = readFileSync(SIDEBAR, 'utf8')
    expect(
      nav.includes("from '@/lib/backend-pending'"),
      '**サイドバーが一覧を読んでいません。**'
    ).toBe(true)
    expect(
      nav.includes('isBackendPending(href)'),
      '**項目ごとに判定していません。**'
    ).toBe(true)
    // 写しを持っていないこと。
    expect(
      nav.includes('BACKEND_PENDING_ROUTES = new Set'),
      '**サイドバーが一覧の写しを持っています。** 片方だけ増えます'
    ).toBe(false)

    const hrefs = new Set([...nav.matchAll(/href:\s*'([^']+)'/g)].map(m => m[1]))
    const pending = [...hrefs].filter(h => announced.full.has(h))
    expect(
      ceilingProblem('サイドバーに出ている準備中', pending.length, NAV_PENDING),
      pending.slice(0, 20).join('\n  ')
    ).toBeNull()
  })

  it.each([
    { total: 5, bad: 0, want: 'clean' },
    { total: 5, bad: 1, want: 'partly' },
    { total: 5, bad: 4, want: 'partly' },
    { total: 5, bad: 5, want: 'dead' },
    { total: 1, bad: 1, want: 'dead' },
  ])('画面の見立て: $total 本中 $bad 本が届かない → $want', ({ total, bad, want }) => {
    expect(screenVerdict(total, bad)).toBe(want)
  })

  it('告知リストを両方とも読めている', () => {
    const src = readFileSync(BANNER, 'utf8')
    const { full, partial } = announcedRoutes(src)
    expect(full.has('/admin/custom-fields')).toBe(true)
    expect(full.has('/admin/geo-blocking')).toBe(true)
    expect(partial.has('/profile/notifications')).toBe(true)
    // 片方のリストをもう片方として読んでいないこと。
    expect(full.has('/profile/notifications')).toBe(false)
  })
})
