#!/usr/bin/env node
/**
 * Add ?? 0 guard to all unguarded prop.toLocaleString() calls.
 * Transforms:  foo.bar.toLocaleString()  →  (foo.bar ?? 0).toLocaleString()
 * Skips already-guarded:  (foo.bar ?? 0).toLocaleString()
 */
const fs = require('fs')
const path = require('path')

function getFiles(dir, results = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory() && !['node_modules', '.next'].includes(entry.name)) {
      getFiles(full, results)
    } else if (entry.isFile() && entry.name.endsWith('.tsx')) {
      results.push(full)
    }
  }
  return results
}

const APP_DIR = path.join(process.cwd(), 'frontend/app')
const files = getFiles(APP_DIR)
let modified = 0

for (const file of files) {
  let src = fs.readFileSync(file, 'utf8')
  const original = src

  // Match: word.word.toLocaleString() NOT already preceded by ?? 0)
  // Negative lookbehind: not preceded by ?? 0)
  src = src.replace(/(?<!\?+\s*0\s*\))(\b\w+\.\w+)\.toLocaleString\(\)/g, (match, expr) => {
    return `(${expr} ?? 0).toLocaleString()`
  })

  if (src === original) continue
  fs.writeFileSync(file, src, 'utf8')
  modified++
  console.log(`✓ ${path.relative(APP_DIR, file)}`)
}

console.log(`\nModified ${modified} files`)
