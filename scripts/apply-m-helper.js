#!/usr/bin/env node
/**
 * Wraps all unguarded MOCK_ usages with the m() helper from '@/lib/mock'.
 *
 * Patterns handled:
 *  ?? MOCK_X            → ?? m(MOCK_X)
 *  || MOCK_X            → || m(MOCK_X)
 *  : MOCK_X (ternary)   → : m(MOCK_X)
 *  useState<T>(MOCK_X)  → useState<T>(m(MOCK_X))
 *  = MOCK_X (catch/etc) → = m(MOCK_X)
 *  {MOCK_X.map(         → {m(MOCK_X).map(
 *  (MOCK_X as           → (m(MOCK_X) as   -- skip (already handled)
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
const IMPORT_M = "import { USE_MOCK, m } from '@/lib/mock'"
const IMPORT_USE_MOCK = "import { USE_MOCK } from '@/lib/mock'"
const files = getFiles(APP_DIR, '.tsx')
let modified = 0

for (const file of files) {
  let src = fs.readFileSync(file, 'utf8')
  const original = src

  // Skip if no MOCK_ references
  if (!src.includes('MOCK_')) continue

  // Skip MOCK_ that are only definitions (const MOCK_X = ...) with no usage
  // We need to find usages outside of const definitions

  // Patterns to transform (only when not already wrapped in m() or USE_MOCK)
  // We use negative lookbehind to avoid double-wrapping

  // 1. ?? MOCK_X  (not already m(...) or USE_MOCK)
  src = src.replace(/\?\? (MOCK_\w+)(?!\s*[\?:,\)]?\s*\))/g, (match, mockVar) => {
    if (match.startsWith('?? m(') || match.startsWith('?? (USE_MOCK')) return match
    return `?? m(${mockVar})`
  })

  // 2. || MOCK_X
  src = src.replace(/\|\| (MOCK_\w+)(?!\s*[\?:,\)]?\s*\))/g, (match, mockVar) => {
    if (match.startsWith('|| m(') || match.startsWith('|| (USE_MOCK')) return match
    return `|| m(${mockVar})`
  })

  // 3. useState<...>(MOCK_X) and useState(MOCK_X)
  src = src.replace(/useState(<[^>]+>)?\((MOCK_\w+)\)/g, (match, generic, mockVar) => {
    if (match.includes('m(') || match.includes('USE_MOCK')) return match
    return `useState${generic || ''}(m(${mockVar}))`
  })

  // 4. return MOCK_X  (in catch/queryFn)
  src = src.replace(/return (MOCK_\w+)([\s\n;,}])/g, (match, mockVar, suffix) => {
    if (match.includes('m(') || match.includes('USE_MOCK') || match.includes('//')) return match
    return `return m(${mockVar})${suffix}`
  })

  // 5. = MOCK_X  (assignment — but NOT const MOCK_X = or let MOCK_X =)
  src = src.replace(/(?<![A-Z_]) = (MOCK_\w+)([\s\n;,)])/g, (match, mockVar, suffix) => {
    if (match.includes('m(') || match.includes('USE_MOCK') || match.includes('const ') || match.includes('let ')) return match
    return ` = m(${mockVar})${suffix}`
  })

  // 6. {MOCK_X.map(  →  {m(MOCK_X).map(
  src = src.replace(/\{(MOCK_\w+)\.map\(/g, (match, mockVar) => {
    if (match.includes('m(') || match.includes('USE_MOCK')) return match
    return `{m(${mockVar}).map(`
  })

  // 7. (MOCK_X).map(  →  m(MOCK_X).map(
  src = src.replace(/\((MOCK_\w+)\)\.map\(/g, (match, mockVar) => {
    if (match.includes('m(') || match.includes('USE_MOCK')) return match
    return `m(${mockVar}).map(`
  })

  // 8. ternary: ? MOCK_X :  and  : MOCK_X  at end of ternary
  //    Only when MOCK_X is at the very end before newline/comma/paren
  src = src.replace(/\? (MOCK_\w+)([\n,;)])/g, (match, mockVar, suffix) => {
    if (match.includes('m(') || match.includes('USE_MOCK')) return match
    // Don't transform MOCK_X that is a type reference after ?
    return `? m(${mockVar})${suffix}`
  })

  // 9. : MOCK_X  at end of ternary/assignment
  //    Be careful not to match object property syntax
  src = src.replace(/((?:isError|isLoading|!data|error)\s*\?\s*[^:]+:\s*)(MOCK_\w+)/g, (match, before, mockVar) => {
    if (match.includes('m(') || match.includes('USE_MOCK')) return match
    return `${before}m(${mockVar})`
  })

  if (src === original) continue

  // Update import to include m
  if (src.includes(IMPORT_USE_MOCK)) {
    src = src.replace(IMPORT_USE_MOCK, IMPORT_M)
  } else if (!src.includes("from '@/lib/mock'")) {
    // Add import after last import line
    const lines = src.split('\n')
    let lastImport = -1, inMulti = false
    for (let i = 0; i < lines.length; i++) {
      const t = lines[i].trim()
      if (inMulti) { if (t.includes("from '") || t.includes('from "')) { lastImport = i; inMulti = false } continue }
      if (t.startsWith('import ')) { if (t.includes("from '") || t.includes('from "')) lastImport = i; else inMulti = true }
    }
    lines.splice(lastImport + 1, 0, IMPORT_M)
    src = lines.join('\n')
  } else if (src.includes("from '@/lib/mock'") && !src.includes('{ m }') && !src.includes(', m }') && !src.includes('m,')) {
    // Add m to existing import
    src = src.replace(/import \{ ([^}]+) \} from '@\/lib\/mock'/, (match, imports) => {
      if (imports.includes(' m,') || imports.includes(', m') || imports === 'm') return match
      return `import { ${imports}, m } from '@/lib/mock'`
    })
  }

  fs.writeFileSync(file, src, 'utf8')
  modified++
  console.log(`✓ ${path.relative(APP_DIR, file)}`)
}

console.log(`\nModified ${modified} files`)
