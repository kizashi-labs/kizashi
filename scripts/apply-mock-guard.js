#!/usr/bin/env node
/**
 * Wraps mock data fallbacks with USE_MOCK guard so production (AWS) shows
 * real/empty data, and local dev keeps mock fallbacks.
 *
 * Safe transformations only:
 *   1. initialData: MOCK_X,     → ...(USE_MOCK ? { initialData: MOCK_X } : {}),
 *   2. placeholderData: MOCK_X, → ...(USE_MOCK ? { placeholderData: MOCK_X } : {}),
 *   3. ?? MOCK_X                → ?? (USE_MOCK ? MOCK_X : [])
 *   4. || MOCK_X                → || (USE_MOCK ? MOCK_X : [])
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
const IMPORT_LINE = "import { USE_MOCK } from '@/lib/mock'"
const files = getFiles(APP_DIR, '.tsx')

let modifiedFiles = 0

for (const file of files) {
  let src = fs.readFileSync(file, 'utf8')
  const original = src

  if (!src.includes('MOCK_')) continue

  // 1. initialData: MOCK_X,  (not already guarded)
  src = src.replace(
    /^(\s+)initialData:\s*(MOCK_\w+),?(\s*)$/gm,
    (m, indent, mockVar, trail) => {
      if (m.includes('USE_MOCK')) return m
      return `${indent}...(USE_MOCK ? { initialData: ${mockVar} } : {}),${trail}`
    }
  )

  // 2. placeholderData: MOCK_X,  (not already guarded)
  //    Also handles placeholderData: MOCK_X.something or MOCK_X.map(...)
  src = src.replace(
    /^(\s+)placeholderData:\s*(MOCK_\w+[^,\n]*),?(\s*)$/gm,
    (m, indent, mockExpr, trail) => {
      if (m.includes('USE_MOCK')) return m
      return `${indent}...(USE_MOCK ? { placeholderData: ${mockExpr} } : {}),${trail}`
    }
  )

  // 3. ?? MOCK_X  (not already wrapped)
  src = src.replace(
    /\?\? (MOCK_\w+)/g,
    (m, mockVar) => {
      if (m.includes('USE_MOCK')) return m
      return `?? (USE_MOCK ? ${mockVar} : [])`
    }
  )

  // 4. || MOCK_X  (not already wrapped)
  src = src.replace(
    /\|\| (MOCK_\w+)/g,
    (m, mockVar) => {
      if (m.includes('USE_MOCK')) return m
      return `|| (USE_MOCK ? ${mockVar} : [])`
    }
  )

  if (src === original) continue

  // Add import after last import block if not already present
  if (!src.includes(IMPORT_LINE) && !src.includes("from '@/lib/mock'")) {
    const importBlockEnd = src.lastIndexOf('\nimport ')
    if (importBlockEnd !== -1) {
      const lineEnd = src.indexOf('\n', importBlockEnd + 1)
      src = src.slice(0, lineEnd + 1) + IMPORT_LINE + '\n' + src.slice(lineEnd + 1)
    }
  }

  fs.writeFileSync(file, src, 'utf8')
  modifiedFiles++
  console.log(`✓ ${path.relative(APP_DIR, file)}`)
}

console.log(`\nDone: modified ${modifiedFiles} files`)
