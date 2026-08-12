#!/usr/bin/env node
/**
 * Reverts unsafe ?? and || mock transformations while keeping
 * the safe initialData/placeholderData transformations.
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

  // Revert: ?? (USE_MOCK ? MOCK_X : null as any) → ?? MOCK_X
  src = src.replace(
    /\?\? \(USE_MOCK \? (MOCK_\w+) : null as any\)/g,
    '?? $1'
  )

  // Revert: || (USE_MOCK ? MOCK_X : null as any) → || MOCK_X
  src = src.replace(
    /\|\| \(USE_MOCK \? (MOCK_\w+) : null as any\)/g,
    '|| $1'
  )

  // Remove USE_MOCK import if no longer needed (i.e., only initialData/placeholderData uses remain)
  // Actually keep it - it may be used by initialData/placeholderData transforms

  if (src === original) continue
  fs.writeFileSync(file, src, 'utf8')
  fixed++
}

console.log(`Reverted unsafe transforms in ${fixed} files`)
