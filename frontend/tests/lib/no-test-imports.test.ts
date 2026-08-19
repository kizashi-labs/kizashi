import { describe, it, expect } from 'vitest'
import { readFileSync, readdirSync, statSync } from 'fs'
import { join } from 'path'

// 検査ファイルが、ほかの検査ファイルを import していないこと。
//
// **import すると、相手の describe の中身が自分の収集時にもう一度走ります。**
// 落ちるわけでも、二重に数えるわけでもありません。ただ、同じ走査が黙って
// 何度も動きます。
//
// 実際に起きていました。server-routes.test.ts は describe の直下で
// server/internal/api の Go を全部と frontend の .ts/.tsx を全部読みます
// （単体で 197 秒、うち import 66 秒）。道具を借りるために 3 本が
// `from './server-routes.test'` と書いていたので、**同じ走査が計 4 回**
// 動いていました。frontend 全体 572 秒のうち import が 392 秒を占めていた
// 主因です。
//
// 直し方は「借りない」ではなく「道具を describe の無いファイルに出す」です
// （route-scan.ts）。この検査は、それが元に戻らないようにするためのものです。
//
// **速さの問題としてだけ読まないでください。** 相手の describe が
// 収集時に何かを書き込む種類のものだった場合、import した側の収集で
// それがもう一度起きます。順番にも回数にも保証がありません。

const TESTS_DIR = join(process.cwd(), 'tests')

function testFiles(dir: string, out: string[] = []): string[] {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) testFiles(p, out)
    else if (name.endsWith('.test.ts') || name.endsWith('.test.tsx')) out.push(p)
  }
  return out
}

// `import … from '…'` / `require('…')` / `import('…')` の相対指定を拾います。
const SPECIFIER =
  /(?:from\s*|import\s*\(\s*|require\s*\(\s*)['"](\.[^'"]*)['"]/g

describe('検査ファイル同士の import', () => {
  const files = testFiles(TESTS_DIR)

  it('走査が壊れていない（検査ファイルを見つけている）', () => {
    expect(files.length, 'tests/ の下に検査ファイルが見つかりません').toBeGreaterThan(20)
  })

  it('検査ファイルは、ほかの検査ファイルを import しない', () => {
    const bad: string[] = []
    for (const f of files) {
      const src = readFileSync(f, 'utf8')
      for (const raw of src.split('\n')) {
        // **注釈は見ません。** この落とし穴を説明している文章まで拾うと、
        // 直した場所ほど怒られることになります（このファイルの上の説明が、
        // まさにその形をしています）。
        //
        // blank-noise.ts の blankNoise は使えません —— あちらは文字列も
        // 潰しますが、ここで探しているものが文字列そのものです。
        // import は行をまたがない形でしか書かれないので、行頭の判定で足ります。
        const t = raw.trimStart()
        if (t.startsWith('//') || t.startsWith('*') || t.startsWith('/*')) continue
        for (const m of raw.matchAll(SPECIFIER)) {
          const spec = m[1]
          if (!/\.test(\.tsx?)?$/.test(spec)) continue
          bad.push(`${f.replace(process.cwd() + '/', '')} → ${spec}`)
        }
      }
    }
    expect(
      bad.length === 0
        ? null
        : '検査ファイルがほかの検査ファイルを import しています。' +
          '**相手の describe が、こちらの収集時にもう一度走ります。**' +
          '共有したいものは describe の無いファイルに出してください' +
          `（route-scan.ts がその例です）:\n  ${bad.join('\n  ')}`,
    ).toBeNull()
  })
})
