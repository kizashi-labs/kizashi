import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import { join } from 'path'
import { blankNoise } from './blank-noise'
import { ceilingProblem } from './route-scan'

// 保存の失敗を出す手段を1つも持たない画面。
//
// silent-writes.test.ts は「失敗を捨てている書き込み」を見ます。ここが見る
// のは、その一歩手前です — 捨ててはいないが、受け取ったものを出す先が
// 画面に無い状態。
//
//   const addMutation = useMutation({
//     mutationFn: body => apiFetch('/api/v1/ioc/ip-block', { method: 'POST', … }),
//     onSuccess: () => { … setShowAddModal(false) … },
//   })
//
// onError がありません。isError も読んでいません。失敗すると、モーダルは
// 開いたまま、入力もそのまま、何も出ません。押した人に見えるのは「反応が
// 無い」だけなので、もう一度押します。
//
// PageSaveFailed はこのために作った帯で、react-query の失敗した mutation を
// 拾って「保存できませんでした / 画面の表示は変わっていません」と出します。
// 作ったあと、34画面にしか置かれていませんでした。useMutation を持つ画面は
// 217あり、そのうち54画面は失敗を出す手段を1つも持っていませんでした。
//
// 帯が唯一の答えではありません。onError で個別に出すのも、usePersist の
// SaveFailed も、mutateAsync を try/catch で包むのも同じだけ有効です。
// この判定が求めるのは、**どれか1つはあること**です。

const ROOTS = ['app', 'components']

function sourceFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) sourceFiles(p, out)
    else if (name.endsWith('.tsx') || name.endsWith('.ts')) out.push(p)
  }
  return out
}

/** Does this file create mutations at all? */
export function hasMutations(clean: string): boolean {
  return /\buseMutation\s*[<(]/.test(clean)
}

/**
 * Any way at all for a failed save to reach the person who pressed the button.
 *
 * 網羅ではなく「1つでもあるか」です。どれが正しいかは画面ごとに違います。
 */
export function showsSaveFailures(clean: string): boolean {
  return (
    /\bonError\s*:/.test(clean) ||        // その mutation で個別に出す
    /\bisError\b/.test(clean) ||          // 呼び出し側が状態を読む
    /<PageSaveFailed/.test(clean) ||      // 画面上の帯
    /<SaveFailed/.test(clean) ||          // usePersist の相方
    /\busePersist\s*\(/.test(clean) ||
    /\bmutateAsync\b[\s\S]{0,400}?catch/.test(clean)
  )
}

export function nakedMutationPages(
  files: Array<{ file: string; src: string }>
): string[] {
  return files
    .filter(f => {
      const clean = blankNoise(f.src)
      return hasMutations(clean) && !showsSaveFailures(clean)
    })
    .map(f => `${f.file}: 保存に失敗しても画面に何も出ません。` +
      'onError を書くか、<PageSaveFailed /> を置いてください')
    .sort()
}

/**
 * Mutations on a page beyond what that page can report a failure for.
 *
 * **上の判定は画面ごとです。** 1つでも出す手段があれば通るので、
 * `isError` が1箇所ある画面は、**残り12の mutation が何も出さなくても**
 * 通ります。実際にそうでした:
 *
 *	/incidents/[id]   13 のうち 11 が裸（連絡記録・エスカレーション・
 *	                  対応者・事後検証のタブ。宛先そのものもありません）
 *	/admin/users      8 のうち 6
 *	/settings         7 のうち 6
 *
 * 実測 (2026-08-12): mutation 534 のうち **114** が裸です。
 *
 * 画面全体の帯（`PageSaveFailed` / `usePersist`）は全部を覆うので、
 * 覆えていない数だけを数えます。
 */
export function nakedMutationCount(clean: string): number {
  const mutations = (clean.match(/\buseMutation\s*[<(]/g) ?? []).length
  if (mutations === 0) return 0
  if (/<PageSaveFailed/.test(clean) || /<SaveFailed/.test(clean) || /\busePersist\s*\(/.test(clean)) {
    return 0
  }
  const perMutation =
    (clean.match(/\bonError\s*:/g) ?? []).length +
    (clean.match(/\.isError\b/g) ?? []).length +
    (clean.match(/\bmutateAsync\b/g) ?? []).length
  return Math.max(0, mutations - perMutation)
}

describe('保存の失敗を出す手段', () => {
  const files = ROOTS.flatMap(r =>
    sourceFiles(r).map(file => ({ file, src: readFileSync(file, 'utf8') }))
  )

  it('走査が届いている', () => {
    const withMutations = files.filter(f => hasMutations(blankNoise(f.src)))
    expect(withMutations.length, 'useMutation を使う画面が見つかりません').toBeGreaterThan(5)
  })

  it('保存の失敗を出せない画面が残っていない', () => {
    const problems = nakedMutationPages(files)
    expect(problems, problems.join('\n  ')).toEqual([])
  })

  // 実測 (2026-08-12): 114（`app` と `components`）→ 48 画面に
  // `<PageSaveFailed />` を置いて **0**。
  //
  // **0 が規則です。** 上限のままだと、上限を上げる変異が「増えて
  // いない」を素通りします（実測 0 に対して上限 10 は、上限として見れば
  // 真です）。規則そのものを下で留めます。
  const NAKED_MUTATION_CEILING = 0

  it('失敗を出せない mutation が増えていない', () => {
    expect(
      NAKED_MUTATION_CEILING,
      '**0 が規則です。** 1本でも許すなら、押した人に何も出ない保存が' +
        'あるという意味です'
    ).toBe(0)

    let total = 0
    const worst: string[] = []
    for (const f of files) {
      const n = nakedMutationCount(blankNoise(f.src))
      if (n > 0) worst.push(`${f.file}: ${n} 本`)
      total += n
    }
    worst.sort((a, b) => parseInt(b.split(': ')[1]) - parseInt(a.split(': ')[1]))
    expect(
      ceilingProblem('失敗を出せない mutation', total, NAKED_MUTATION_CEILING,
        'NAKED_MUTATION_CEILING'),
      worst.slice(0, 15).join('\n  ')
    ).toBeNull()
  })

  it.each([
    { name: '帯が全部を覆う', src: 'useMutation(a)\nuseMutation(b)\n<PageSaveFailed />', want: 0 },
    { name: '1つずつ覆う', src: 'useMutation(a)\nuseMutation(b)\nx.isError\ny.isError', want: 0 },
    { name: '**1つだけ覆う**', src: 'useMutation(a)\nuseMutation(b)\nx.isError', want: 1 },
    { name: '何も覆わない', src: 'useMutation(a)\nuseMutation(b)', want: 2 },
    { name: 'mutation が無い', src: 'const x = 1', want: 0 },
  ])('裸の数: $name', ({ src, want }) => {
    expect(nakedMutationCount(src)).toBe(want)
  })

  // 通常状態では上の判定は肯定側の分岐に入りません。直接動かします。
  it.each([
    { name: 'onError がある', src: 'useMutation({ mutationFn: f, onError: e => x })', want: 0 },
    { name: 'isError を読む', src: 'const m = useMutation({ mutationFn: f })\nif (m.isError) x', want: 0 },
    { name: '帯がある', src: 'useMutation({ mutationFn: f })\n<PageSaveFailed />', want: 0 },
    { name: 'usePersist', src: 'useMutation({ mutationFn: f })\nconst p = usePersist(x)', want: 0 },
    { name: 'mutateAsync を包んでいる', src: 'useMutation({ mutationFn: f })\ntry { await m.mutateAsync(x) } catch (e) { show(e) }', want: 0 },
    { name: '何も無い', src: 'useMutation({ mutationFn: f, onSuccess: () => close() })', want: 1 },
    { name: 'mutation が無い', src: 'const x = 1', want: 0 },
  ])('判定: $name', ({ src, want }) => {
    expect(nakedMutationPages([{ file: 'x.tsx', src }])).toHaveLength(want)
  })

  // コメントや文字列の中の onError を数えていないこと。
  it('コメントの中の onError は数えない', () => {
    const src = 'useMutation({ mutationFn: f })\n// onError: ここに書くべきです\n'
    expect(nakedMutationPages([{ file: 'x.tsx', src }])).toHaveLength(1)
  })
})
