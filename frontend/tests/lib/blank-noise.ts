/**
 * Blanks out comments and string literals, preserving offsets and newlines.
 *
 * すべてのゲートが最初に通す下ごしらえです。**ここが見落とすものは、
 * どのゲートからも見えません。** 正規表現リテラルを知らなかったあいだ、
 * 9ファイル・1,668行がどの判定にも映っていませんでした。空白になった
 * コードは、無いコードと同じ形をしています。
 *
 * これは fabricated-verdict.test.ts の中にありました。7本のゲートが
 * そこから import していたので、**どのゲートを走らせても、あちらの
 * テストが丸ごと一緒に走ります** — 65秒かかるものを含めて。
 * テストファイルを道具として import すると、その副作用が付いてきます。
 */
/**
 * Blanks out comments and string literals, preserving offsets and newlines.
 *
 * Without this the scan trips over its own explanations: the comments left
 * behind at each of the sites above name Math.random() precisely so the next
 * reader knows what used to be there.
 */
/**
 * Can a `/` at the end of `before` begin a regex literal rather than divide?
 *
 * 直前の意味のあるトークンで決まります。値の後ろなら除算、演算子・開き括弧・
 * キーワードの後ろなら正規表現です。
 */
export function regexCanStartHere(before: string): boolean {
  const t = before.replace(/\s+$/, '')
  if (t === '') return true
  const last = t[t.length - 1]
  // `<` は入れません。TSX の閉じタグ `</div>` が正規表現の開始に見え、
  // 同じ行にもう1つ `/` があると、その間が空白になります。JSX だらけの
  // ファイルでは、これで走査そのものが崩れます — useMutation を持つ画面が
  // 217から75に減りました。
  if ('(,=:[!&|?{};+-*~%^'.includes(last)) return true
  return /\b(return|typeof|instanceof|in|of|case|do|else|yield|await|void|delete|new)$/.test(t)
}

export function blankNoise(src: string): string {
  const out: string[] = []
  // Replace per UTF-16 code unit, not per code point. `[...s]` iterates code
  // points, so '🇨🇳' (four units, two code points) came back as two spaces and
  // every offset after it shifted — silently, because the scan still ran and
  // just looked at the wrong bytes. A page whose country list starts with a
  // flag emoji reported zero findings.
  const keepNewlines = (s: string) => s.replace(/[^\n]/g, ' ')
  let i = 0
  while (i < src.length) {
    const c = src[i]
    if (c === '/' && src[i + 1] === '/') {
      let j = src.indexOf('\n', i)
      if (j < 0) j = src.length
      out.push(keepNewlines(src.slice(i, j)))
      i = j
      continue
    }
    if (c === '/' && src[i + 1] === '*') {
      let j = src.indexOf('*/', i + 2)
      j = j < 0 ? src.length : j + 2
      out.push(keepNewlines(src.slice(i, j)))
      i = j
      continue
    }
    // 正規表現リテラル。中の ' や " を文字列の開始として読むと、そこから
    // 引用符の対応がずれて、後ろの大きな範囲が丸ごと空白になります。
    //
    //   const m = ind.pattern?.match(/\[[\w-]+:[\w.]+\s*=\s*'([^']+)'\]/)
    //
    // app/ioc/page.tsx の1行です。この行から下、<PageSaveFailed /> を含む
    // 60行ほどが、blankNoise を使うすべての判定から見えなくなっていました。
    // 空白になった範囲は「そこに何も無い」と同じ形をしているので、
    // どの判定も違反0件として通ります。
    //
    // `/` が除算か正規表現かは、直前の意味のあるトークンで決まります。
    if (c === '/' && regexCanStartHere(out.join(''))) {
      let j = i + 1
      let inClass = false
      while (j < src.length) {
        if (src[j] === '\\') { j += 2; continue }
        if (src[j] === '[') inClass = true
        else if (src[j] === ']') inClass = false
        else if (src[j] === '/' && !inClass) { j += 1; break }
        else if (src[j] === '\n') break // 1行で閉じない = 正規表現ではなかった
        j += 1
      }
      // フラグ
      while (j < src.length && /[gimsuyvd]/.test(src[j])) j += 1
      out.push(keepNewlines(src.slice(i, j)))
      i = j
      continue
    }
    if (c === '"' || c === "'") {
      let j = i + 1
      while (j < src.length) {
        if (src[j] === '\\') { j += 2; continue }
        if (src[j] === c) { j += 1; break }
        j += 1
      }
      out.push(keepNewlines(src.slice(i, j)))
      i = j
      continue
    }
    // Template literals: blank the literal text, KEEP the ${…} expressions.
    //
    // Treating a template as one opaque string was a real blind spot. The
    // failed SIEM connection test toasted
    //   `接続成功 — レイテンシ ${Math.floor(Math.random() * 150) + 20}ms`
    // and a scanner that blanks the whole template cannot see that at all —
    // the fabrication is in the interpolation, which is code.
    if (c === '`') {
      out.push(' ')
      let j = i + 1
      while (j < src.length) {
        if (src[j] === '\\') { out.push('  '); j += 2; continue }
        if (src[j] === '`') { out.push(' '); j += 1; break }
        if (src[j] === '$' && src[j + 1] === '{') {
          let depth = 0
          let k = j + 1
          for (; k < src.length; k++) {
            if (src[k] === '{') depth++
            else if (src[k] === '}' && --depth === 0) break
          }
          // `${` and `}` blanked, the expression between them recursed into.
          out.push('  ', blankNoise(src.slice(j + 2, k)), ' ')
          j = k + 1
          continue
        }
        out.push(src[j] === '\n' ? '\n' : ' ')
        j += 1
      }
      i = j
      continue
    }
    out.push(c)
    i += 1
  }
  return out.join('')
}
