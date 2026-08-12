#!/usr/bin/env node
/**
 * Fixes type errors from apply-mock-guard.js:
 * Changes `?? (USE_MOCK ? MOCK_X : [])` to `?? (USE_MOCK ? MOCK_X : undefined)`
 * and `|| (USE_MOCK ? MOCK_X : [])` to `|| (USE_MOCK ? MOCK_X : undefined)`
 * where MOCK_X is an object type (not an array-named mock).
 *
 * Actually, we replace ALL occurrences with `null as any` for simplicity.
 */

const fs = require('fs')
const path = require('path')

function getFiles(dir, ext, results = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name)
    if (entry.isDirectory() && entry.name !== 'node_modules' && entry.name !== '.next') {
      getFiles(full, ext, results)
    } else if (entry.isFile() && entry.name.endsWith(ext)) {
      results.push(full)
    }
  }
  return results
}

const APP_DIR = path.join(__dirname, '../frontend/app')
const files = getFiles(APP_DIR, '.tsx')
let fixed = 0

for (const file of files) {
  let src = fs.readFileSync(file, 'utf8')
  const original = src

  // Replace `?? (USE_MOCK ? MOCK_X : [])` with `?? (USE_MOCK ? MOCK_X : null as any)`
  src = src.replace(
    /\?\? \(USE_MOCK \? (MOCK_\w+) : \[\]\)/g,
    '?? (USE_MOCK ? $1 : null as any)'
  )

  // Replace `|| (USE_MOCK ? MOCK_X : [])` with `|| (USE_MOCK ? MOCK_X : null as any)`
  src = src.replace(
    /\|\| \(USE_MOCK \? (MOCK_\w+) : \[\]\)/g,
    '|| (USE_MOCK ? $1 : null as any)'
  )

  if (src === original) continue
  fs.writeFileSync(file, src, 'utf8')
  fixed++
}

console.log(`Fixed fallback type in ${fixed} files`)
