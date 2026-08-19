import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import { join } from 'path'
import { blankNoise } from './blank-noise'
import { chainedCatch, discardsError, inEmptyCatchBlock } from './swallowed-reads.test'

// A write whose failure is thrown away.
//
//   setConfig(prev => ({ ...prev, enabled: !prev.enabled }))
//   apiFetch('/api/v1/admin/geo-blocking/config', { method: 'PUT', … })
//     .catch(() => {})
//
// The local state moves first and the save's failure is discarded, so the
// toggle looks applied whether or not anything was saved. The react-query
// variant is the same defect wearing different clothes:
//
//   useMutation({
//     mutationFn: (id) => apiFetch(`…/${id}/toggle`, { method: 'POST' })
//       .catch(() => null),
//     onSuccess: () => qc.invalidateQueries(…),   // always runs
//   })
//
// `.catch(() => null)` turns a failure into a resolved promise, so isError
// never becomes true and onError never fires. One page went further and wrote
// `onError: () => setComputeStatus('success')` outright.
//
// This was measured against the server's own routing table. 294 of the
// frontend's apiFetch calls name an endpoint that has no matching route in
// server/internal/api at all — 164 of them writes. Where those two sets
// overlap, the operator clicks, the UI confirms, and nothing anywhere has
// changed. That overlap was 33 calls across 20 pages, including:
//
//   POST   /admin/encryption/enforce             ディスク暗号化の強制
//   POST   /admin/identity-risk/users/:id/enforce-mfa
//   POST   /admin/ztna/policies/:id/toggle       ゼロトラストの到達制御
//   PUT    /admin/geo-blocking/config            国単位の遮断
//   PUT    /admin/deception/traps/:id/toggle     おとりの有効/無効
//   PUT    /admin/siem/configs/:id/toggle        SIEM転送の有効/無効
//   DELETE /admin/edr-policies/assignments/:id   EDRポリシーの割り当て解除
//   POST   /admin/controls-monitoring/assess     統制評価の実施
//
// There is no geo-blocking backend at all — no route, no handler, nothing in
// internal/. An admin could enable it, watch the toggle turn on, and be
// protected by nothing.
//
// Whether those features should exist is a product decision. Whether the UI
// may report that they took effect is not.
//
// The rest followed: 110 sites, then 66 after the unrouted pages, then 0
// unexplained. The remaining three are named below with what each leaves
// undone, because a count of three says nothing and a list of three does.
//
// The sharpest of the later batch was not an unrouted endpoint at all.
// /soc/shifts saved the handover notes with `.catch(() => {})` and set the
// saved indicator on the next line — the notes the outgoing analyst writes and
// the incoming one reads. Both sides would believe the handover happened.

const ROOTS = ['app', 'components', 'lib']

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) sourceFiles(p, out)
    else if (name.endsWith('.tsx') || name.endsWith('.ts')) out.push(p)
  }
  return out
}

/** apiFetch(…) / apiFetchList(…) — the opening paren of each call. */
// 素の fetch も見ます。以前は apiFetch だけで、素の fetch 40箇所は
// この判定に一度も映っていませんでした。握り潰しているものが今は無いと
// しても、無いことを確かめられる状態にしておきます。
const FETCH = /(?:\bapiFetch(?:List)?|(?<![.\w])fetch)\s*(?:<[^;{]*?>)?\s*\(/g

/** The call's own argument list, by paren matching from its opening paren. */
function callArgs(src: string, open: number): { text: string; end: number } {
  let depth = 0
  for (let i = open; i < src.length && i < open + 6000; i++) {
    if (src[i] === '(') depth++
    else if (src[i] === ')') {
      depth--
      if (depth === 0) return { text: src.slice(open, i + 1), end: i + 1 }
    }
  }
  return { text: src.slice(open, open + 600), end: open + 600 }
}

// この判定は swallowed-reads.test.ts と同じものを使います。以前はここに
// 独自の SWALLOW 正規表現があり、握りつぶしの形を
// `{}` / null / undefined / [] / false / 0 の6つに限っていました。
// そのため
//
//   apiFetch('/api/v1/admin/oauth2', { method: 'POST' })
//     .catch(() => ({ success: true }))
//
// は「握りつぶし」に数えられず、SILENT_WRITE_CEILING = 0 が緑のまま
// 65箇所が残っていました。うち13箇所は success: true / ok: true を
// そのまま返しており、失敗を成功として報告していたことになります。
//
// 規則の写しを持つと、写しのほうだけが正しくなります。判定は1つです。

/**
 * Lines (1-based) where a write's failure is discarded.
 *
 * Two shapes, both counted: a `.catch(…)` chained directly onto the call that
 * yields a benign value, and a `try { … } catch {}` with an empty body around
 * it. The method is read from the call's own argument list — scanning a fixed
 * window ahead attributes the *next* call's method to this one, which is how
 * an early version of this measurement reported 31 phantom writes to
 * /api/v1/agents, an endpoint whose GET has existed all along.
 */
export function silentWrites(src: string): number[] {
  const clean = blankNoise(src)
  const found: number[] = []
  FETCH.lastIndex = 0
  let m: RegExpExecArray | null
  while ((m = FETCH.exec(clean)) !== null) {
    const open = m.index + m[0].length - 1
    const { end } = callArgs(clean, open)

    // Structure comes from the blanked copy, the method from the original.
    // blankNoise empties string literals, and `method: 'POST'` IS a string
    // literal — reading it off the blanked copy finds nothing and every write
    // looks like a read. blankNoise preserves offsets exactly, so the same
    // slice of the original is the same call.
    if (!/method:\s*['"](POST|PUT|PATCH|DELETE)['"]/.test(src.slice(open, end))) continue

    const h = chainedCatch(clean, end)
    if ((h && discardsError(h.param, h.body)) || inEmptyCatchBlock(clean, end)) {
      found.push(clean.slice(0, open).split('\n').length)
    }
  }
  return found
}

/**
 * Pages whose writes must not discard their failure. Absolute — no ceiling.
 *
 * This started as the pages whose save had no server route to reach, so the
 * discarded failure was not a rare case but every single click. It is now
 * every page: the ceiling below reached zero, and what is left is the named
 * list of deliberate exceptions rather than an anonymous count.
 */
const NO_SILENT_WRITES = [
  'app/admin/ai-triage/page.tsx',
  'app/admin/bas/page.tsx',
  'app/admin/controls-monitoring/page.tsx',
  'app/admin/custom-fields/page.tsx',
  'app/admin/dark-web/page.tsx',
  'app/admin/data-viz/page.tsx',
  'app/admin/deception/page.tsx',
  'app/admin/edr-policies/page.tsx',
  'app/admin/encryption-mgmt/page.tsx',
  'app/admin/geo-blocking/page.tsx',
  'app/admin/identity-risk/page.tsx',
  'app/admin/marketplace/page.tsx',
  'app/admin/saved-searches/page.tsx',
  'app/admin/security-dw/page.tsx',
  'app/admin/siem-integration/page.tsx',
  'app/admin/training-analytics/page.tsx',
  'app/admin/training-mgmt/page.tsx',
  'app/admin/ztna/page.tsx',
  'app/profile/notifications/page.tsx',
  'app/software/diff/page.tsx',
]

/**
 * The three writes that may still discard their failure, each with the reason.
 *
 * 110 → 66 → 0 unexplained. An entry here is a claim that there is nowhere to
 * report to, not a claim that the failure does not matter — each one still
 * leaves something undone on the server, and each says what.
 *
 * The bar is deliberately high: "the user would find a banner annoying" is not
 * a reason. "The component is unmounting and has no render left" is.
 */
const DELIBERATE_SILENT_WRITES: Record<string, string> = {
  'lib/auth.tsx':
    'ログアウトの投げっぱなし。サーバ側のセッション失効が失敗しても、' +
    '手元のトークンは消します。逆にすると、サーバが落ちている間は' +
    'ログアウトできません。素の fetch も見るように判定を広げたときに' +
    '出てきました',
  'app/live-response/page.tsx':
    'useEffect の後始末で、コンポーネントが消える瞬間にセッションを閉じます。' +
    '描画先がもう無いので出せません。伝わらなかった場合サーバ側にセッションが残ります',
  'app/live-response/[id]/page.tsx':
    '画面を閉じる操作の一部で、直後に router.back() します。同上',
  'app/admin/mobile-device-management/commands/page.tsx':
    '30秒ごとの自動ポーリングです。背景の再取得が失敗するたびに帯を出すと、' +
    '本当の失敗が埋もれます。手動の更新ボタンが同じ経路を叩き、そちらは報告します',
}

/** 説明の無い箇所。0 で固定。 */
const SILENT_WRITE_CEILING = 0

/**
 * Entries in the allowlist that no longer describe the code.
 *
 * Separated out because with all three still silent the loop never pushes, so
 * deleting the check outright changed nothing — the list would quietly become
 * a record of how things used to be.
 */
export function staleExceptions(
  counts: Record<string, number>,
  allow: Record<string, string>
): string[] {
  const problems: string[] = []
  for (const [file, why] of Object.entries(allow)) {
    if (!counts[file]) {
      problems.push(`${file} はもう失敗を捨てていません (${why})。リストから消してください`)
    }
  }
  return problems.sort()
}

export function ceilingProblem(actual: number, ceiling: number): string | null {
  if (actual > ceiling) {
    return `保存の失敗を捨てている書き込みが ${ceiling} から ${actual} に増えています`
  }
  if (actual < ceiling) {
    return (
      `保存の失敗を捨てている書き込みが ${actual} まで減りました。` +
      `SILENT_WRITE_CEILING を ${actual} に下げてください`
    )
  }
  return null
}

describe('保存の失敗を捨てる書き込み', () => {
  const files = ROOTS.flatMap(r => sourceFiles(join(process.cwd(), r)))
  const rel = (p: string) => p.replace(process.cwd() + '/', '')

  it('走査がファイルを見つけている', () => {
    expect(files.length).toBeGreaterThan(300)
  })

  it.each(NO_SILENT_WRITES)('%s は保存の失敗を捨てない', page => {
    const lines = silentWrites(readFileSync(join(process.cwd(), page), 'utf8'))
    expect(
      lines,
      `${page}: 保存に失敗しても画面だけが変わります。` +
        'この宛先にはサーバ側のルートがありません'
    ).toEqual([])
  })

  it('説明の無い箇所が残っていない', () => {
    const total = files
      .filter(f => !(rel(f) in DELIBERATE_SILENT_WRITES))
      .map(f => silentWrites(readFileSync(f, 'utf8')).length)
      .reduce((a, b) => a + b, 0)
    expect(ceilingProblem(total, SILENT_WRITE_CEILING)).toBeNull()
  })

  // 許可した3件が本当にその状態であること。直したのに残っていると、
  // リストが「昔そうだった」の記録に変わります。
  it('意図した例外がすべて現存する', () => {
    const counts: Record<string, number> = {}
    for (const file of Object.keys(DELIBERATE_SILENT_WRITES)) {
      counts[file] = silentWrites(readFileSync(join(process.cwd(), file), 'utf8')).length
    }
    expect(staleExceptions(counts, DELIBERATE_SILENT_WRITES)).toEqual([])
  })

  // 3件とも本当に例外のままの通常状態では、上の判定は肯定側に入りません。
  it.each<{ name: string; counts: Record<string, number>; allow: Record<string, string>; want: number }>([
    { name: 'すべて現存', counts: { a: 1 }, allow: { a: '理由' }, want: 0 },
    { name: '1件は直っている', counts: { a: 0 }, allow: { a: '理由' }, want: 1 },
    { name: '計測にも出ない', counts: {}, allow: { a: '理由' }, want: 1 },
    { name: '2件とも直っている', counts: { a: 0, b: 0 }, allow: { a: '理', b: '由' }, want: 2 },
    { name: '許可が空', counts: {}, allow: {}, want: 0 },
  ])('陳腐化の判定: $name', ({ counts, allow, want }) => {
    expect(staleExceptions(counts, allow)).toHaveLength(want)
  })

  // 正常なコードでは上のどちらも肯定側の分岐に入りません。判定を直接動かします。
  it.each([
    {
      name: 'catch(() => {}) を鎖でつないだ書き込み',
      src: "apiFetch('/x', { method: 'PUT' }).catch(() => {})",
      want: 1,
    },
    {
      name: 'catch(() => null)',
      src: "apiFetch('/x', { method: 'DELETE' }).catch(() => null)",
      want: 1,
    },
    {
      name: '空の catch で囲った書き込み',
      src: "try { await apiFetch('/x', { method: 'POST' }) } catch {}",
      want: 1,
    },
    {
      name: 'catch (e) {} も空',
      src: "try { await apiFetch('/x', { method: 'POST' }) } catch (e) {}",
      want: 1,
    },
    {
      name: '読み取りは対象外',
      src: "apiFetch('/x').catch(() => null)",
      want: 0,
    },
    {
      name: '失敗を扱っている書き込みは対象外',
      src: "apiFetch('/x', { method: 'PUT' }).catch(e => setError(e))",
      want: 0,
    },
    {
      name: 'catch の中身があれば対象外',
      src: "try { await apiFetch('/x', { method: 'POST' }) } catch { setError('だめ') }",
      want: 0,
    },
    {
      name: '素の書き込みは対象外',
      src: "await apiFetch('/x', { method: 'POST' })",
      want: 0,
    },
    {
      name: 'コメントの中の例は数えない',
      src: "// apiFetch('/x', { method: 'PUT' }).catch(() => {})\nconst a = 1",
      want: 0,
    },
    {
      name: '成功を作って返す',
      src: "apiFetch('/x', { method: 'POST' }).catch(() => ({ success: true }))",
      want: 1,
    },
    {
      name: '作った行を返す',
      src: "apiFetch('/x', { method: 'POST' }).catch(() => ({ id: '1', ...data }))",
      want: 1,
    },
    {
      name: '引数をそのまま返す',
      src: "apiFetch('/x', { method: 'PUT' }).catch(() => body)",
      want: 1,
    },
    {
      name: '直後の読み取りのメソッドを取り違えない',
      src:
        "apiFetch('/read')\nconst m = useMutation({ mutationFn: () => " +
        "apiFetch('/write', { method: 'POST' }) })",
      want: 0,
    },
  ])('検出: $name', ({ src, want }) => {
    expect(silentWrites(src)).toHaveLength(want)
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
