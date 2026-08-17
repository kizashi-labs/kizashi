#!/usr/bin/env node
/**
 * MOCK_* の未ガード参照を検出する。
 *
 * 背景: 画面のほとんどが「API が空/失敗ならモックを出す」形で書かれていた。
 * NEXT_PUBLIC_USE_MOCK=false の本番ビルドでも、モック定数を **素で** 参照して
 * いる箇所はそのまま描画される。実在しない担当者名・架空の CVE・作り物の
 * 経営指標が、本物の画面に混ざって出る。しかも「データが少ないだけ」に見えるので
 * 気づかれない。lib/mock.ts の m()/mockOr() を通していれば本番では空に落ちる。
 *
 * 許可する参照:
 *   - m(MOCK_X) / mockOr(MOCK_X, ...) 経由
 *   - 同じ行に USE_MOCK があるもの（三項で明示的に分岐している）
 *   - const/let MOCK_X = ... の宣言（宣言そのものと、その中で組み立てる参照）
 *   - typeof MOCK_X（型としての参照。値は取り出さない）
 *   - import / export 行
 *
 * 使い方: node scripts/check-mock-guards.mjs
 */
import { readdirSync, readFileSync, statSync } from 'node:fs'
import { join, relative } from 'node:path'

const ROOT = new URL('..', import.meta.url).pathname
const SCAN_DIRS = ['app', 'components', 'lib', 'hooks']
const EXTS = ['.ts', '.tsx']

// 値としてのモックではないもの。localStorage のキー名など。
const ALLOWLIST = new Set(['MOCK_STORAGE_KEY'])

function walk(dir, out = []) {
  for (const name of readdirSync(dir)) {
    const p = join(dir, name)
    if (statSync(p).isDirectory()) {
      if (name === 'node_modules' || name === '.next') continue
      walk(p, out)
    } else if (EXTS.some(e => name.endsWith(e))) {
      out.push(p)
    }
  }
  return out
}

const MOCK_REF = /\bMOCK_[A-Za-z0-9_]*/g
const DECL_START = /^\s*(?:export\s+)?(?:const|let|var)\s+MOCK_[A-Za-z0-9_]*\b/

// m(...) / mockOr(...) の呼び出しを、引数まるごと取り除く。
// 引数の途中に MOCK_X が出る形（`mockOr({ items: MOCK_X }, EMPTY)`）や
// 型引数つきの形（`mockOr<T | null>(MOCK_X, null)`）もガード済みとして扱う。
const GUARD_CALL = /\b(?:m|mockOr)\s*(?:<[^()<>]*>)?\(/
function stripGuardedCalls(line) {
  let out = line
  for (;;) {
    const hit = GUARD_CALL.exec(out)
    if (!hit) return out
    let depth = 0
    let end = -1
    for (let i = hit.index + hit[0].length - 1; i < out.length; i++) {
      if (out[i] === '(') depth++
      else if (out[i] === ')') {
        depth--
        if (depth === 0) { end = i; break }
      }
    }
    // 閉じ括弧が同じ行に無い（複数行にまたがる呼び出し）。
    // 行末まで消して打ち切る — 続きの行は次のループで個別に判定される。
    out = end === -1 ? out.slice(0, hit.index) : out.slice(0, hit.index) + out.slice(end + 1)
  }
}

/** 行から「ガード済み」の参照を消し、残ったものを返す。 */
function unguardedRefs(line) {
  const rest = stripGuardedCalls(line).replace(/\btypeof\s+MOCK_[A-Za-z0-9_]*/g, '')
  if (rest.includes('USE_MOCK')) return []
  return (rest.match(MOCK_REF) ?? []).filter(n => !ALLOWLIST.has(n))
}

const problems = []

for (const dir of SCAN_DIRS) {
  let files
  try {
    files = walk(join(ROOT, dir))
  } catch {
    continue // 存在しないディレクトリは黙って飛ばす
  }
  for (const file of files) {
    const lines = readFileSync(file, 'utf8').split('\n')
    // MOCK_X の宣言ブロックの中は「モックを組み立てている」 so 参照を許す。
    // ブレース/角括弧の収支で宣言の終わりを判定する。
    let declDepth = 0
    let inDecl = false

    lines.forEach((line, i) => {
      const code = line.replace(/\/\/.*$/, '')

      if (!inDecl && DECL_START.test(code)) {
        inDecl = true
        declDepth = 0
      }

      if (!inDecl && !/^\s*(import|export)\b/.test(code)) {
        for (const name of unguardedRefs(code)) {
          problems.push(`${relative(ROOT, file)}:${i + 1}: ${name} — ${line.trim()}`)
        }
      }

      if (inDecl) {
        for (const ch of code) {
          if (ch === '{' || ch === '[' || ch === '(') declDepth++
          else if (ch === '}' || ch === ']' || ch === ')') declDepth--
        }
        if (declDepth <= 0) inDecl = false
      }
    })
  }
}

if (problems.length > 0) {
  console.error(
    `\nガードされていない MOCK_* 参照が ${problems.length} 件あります。\n` +
    `本番ビルド (NEXT_PUBLIC_USE_MOCK != 'true') でモックが描画されます。\n` +
    `lib/mock.ts の m() / mockOr() を通すか、USE_MOCK で明示的に分岐してください。\n\n` +
    problems.map(p => '  ' + p).join('\n') + '\n'
  )
  process.exit(1)
}

console.log('MOCK_* はすべてガードされています')
