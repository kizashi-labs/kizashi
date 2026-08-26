#!/usr/bin/env node
/**
 * Fix remaining direct MOCK_ usages (not wrapped in m()) that appear
 * in function/render context (not in const MOCK_X = ... definitions).
 *
 * Patterns fixed:
 *   MOCK_X.filter(   → m(MOCK_X).filter(
 *   MOCK_X.find(     → m(MOCK_X).find(
 *   MOCK_X.reduce(   → m(MOCK_X).reduce(
 *   MOCK_X.map(      → m(MOCK_X).map(  (if not already handled)
 *   MOCK_X.length    → m(MOCK_X).length
 *   MOCK_X[          → m(MOCK_X)[
 *   return MOCK_X    → return m(MOCK_X)  (in function context)
 *   : MOCK_X         → : m(MOCK_X)      (ternary/object value)
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

  // Skip if no MOCK_ at all
  if (!src.includes('MOCK_')) continue

  // Fix MOCK_X.filter/find/reduce/map/forEach/length/slice/sort/includes
  // but NOT when preceded by m( (already wrapped) or const MOCK_X = (definition)
  const methods = ['filter', 'find', 'reduce', 'map', 'forEach', 'slice', 'sort', 'includes', 'length', 'some', 'every']
  for (const method of methods) {
    const sep = method === 'length' ? '' : '('
    const re = new RegExp(`(?<!m\\()(MOCK_\\w+)\\.${method}${sep === '(' ? '\\(' : ''}`, 'g')
    src = src.replace(re, (match, mockVar) => {
      // Don't transform const MOCK_X = ... definitions
      if (match.includes('const ') || match.includes('let ')) return match
      return `m(${mockVar}).${method}${sep}`
    })
  }

  // Fix MOCK_X[ array index access
  src = src.replace(/(?<!m\()(MOCK_\w+)\[/g, (match, mockVar) => {
    return `m(${mockVar})[`
  })

  if (src === original) continue
  fs.writeFileSync(file, src, 'utf8')
  modified++
  console.log(`✓ ${path.relative(APP_DIR, file)}`)
}

console.log(`\nModified ${modified} files`)
