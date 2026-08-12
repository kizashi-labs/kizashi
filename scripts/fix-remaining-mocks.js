#!/usr/bin/env node
/**
 * Fixes remaining inline mock patterns:
 * 1. `staleTime: N, placeholderData: MOCK_X,` → `staleTime: N, ...(USE_MOCK ? { placeholderData: MOCK_X } : {}),`
 * 2. `placeholderData: MOCK_X.something` → conditional spread
 * 3. `catch(() => MOCK_X)` → `catch(() => null)`  (queryFn error fallback)
 * 4. `data = MOCK_X` default in destructure → remove default
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

  if (!src.includes('MOCK_')) continue

  // 1. Inline placeholderData on same line as staleTime
  //    `staleTime: N, placeholderData: MOCK_X,`
  src = src.replace(
    /(staleTime:[^,]+), placeholderData: (MOCK_\w+[^,\n]*),?/g,
    (m, before, mockExpr) => {
      if (m.includes('USE_MOCK')) return m
      return `${before}, ...(USE_MOCK ? { placeholderData: ${mockExpr} } : {}),`
    }
  )

  // 2. placeholderData: MOCK_X.map(...) or MOCK_X.something
  src = src.replace(
    /^(\s+)placeholderData: (MOCK_\w+\.[^,\n]+),?(\s*)$/gm,
    (m, indent, mockExpr, trail) => {
      if (m.includes('USE_MOCK')) return m
      return `${indent}...(USE_MOCK ? { placeholderData: ${mockExpr} } : {}),${trail}`
    }
  )

  // 3. catch(() => MOCK_X) → catch(() => null as any)
  //    These are in queryFn where API errors fall back to mock
  src = src.replace(
    /\.catch\(\(\) => (MOCK_\w+)\)/g,
    (m, mockVar) => {
      if (m.includes('USE_MOCK')) return m
      return `.catch(() => USE_MOCK ? ${mockVar} : null as any)`
    }
  )

  if (src === original) continue
  fs.writeFileSync(file, src, 'utf8')
  fixed++
  console.log(`✓ ${path.relative(APP_DIR, file)}`)
}

console.log(`\nFixed ${fixed} files`)
