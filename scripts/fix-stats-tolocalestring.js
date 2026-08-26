#!/usr/bin/env node
/**
 * Fix potential runtime crash: property.toLocaleString() where property may be
 * undefined when USE_MOCK=false and m() returns {}.
 *
 * Transforms:
 *   displayStats.foo.toLocaleString()  → (displayStats.foo ?? 0).toLocaleString()
 *   s.foo.toLocaleString()             → (s.foo ?? 0).toLocaleString()
 * where the variable is a stats-like object from ?? m(MOCK_STATS)
 */

const fs = require('fs')
const path = require('path')

function getFiles(dir, ext, results = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory() && !['node_modules', '.next'].includes(entry.name)) {
      getFiles(full, ext, results)
    } else if (entry.isFile() && entry.name.endsWith(ext)) {
      results.push(full)
    }
  }
  return results
}

const APP_DIR = path.join(process.cwd(), 'frontend/app')
const files = getFiles(APP_DIR, '.tsx')
let modified = 0

for (const file of files) {
  let src = fs.readFileSync(file, 'utf8')
  const original = src

  // Only process files that have stats ?? m(MOCK_STATS) pattern
  if (!src.includes('?? m(MOCK_STATS)') && !src.includes('|| m(MOCK_STATS)')) continue

  // Fix: statsVar.prop.toLocaleString() → (statsVar.prop ?? 0).toLocaleString()
  // where prop is not already guarded with ?? 0
  // Match: word.word.toLocaleString() but NOT (word.word ?? 0).toLocaleString()
  src = src.replace(/(?<!\??\s*0\s*\))\b(\w+\.\w+)\.toLocaleString\(\)/g, (match, expr) => {
    // Don't re-wrap already guarded patterns
    if (match.startsWith('(')) return match
    return `(${expr} ?? 0).toLocaleString()`
  })

  if (src === original) continue
  fs.writeFileSync(file, src, 'utf8')
  modified++
  console.log(`✓ ${path.relative(APP_DIR, file)}`)
}

console.log(`\nModified ${modified} files`)
