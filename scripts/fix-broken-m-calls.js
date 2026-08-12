#!/usr/bin/env node
/**
 * Fix broken m(MOCK_FOO)BAR patterns created by apply-m-helper.js
 * where the negative lookahead caused partial MOCK_ variable name matching.
 * e.g.  m(MOCK_WORKFLOW)S  → m(MOCK_WORKFLOWS)
 *        m(MOCK_STAT)S      → m(MOCK_STATS)
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

  // Fix: m(MOCK_FOO)BAR → m(MOCK_FOOBAR)
  // Where BAR is one or more uppercase letters/underscores/digits
  src = src.replace(/m\((MOCK_[A-Z0-9_]+)\)([A-Z][A-Z0-9_]*)/g, (match, mockVar, suffix) => {
    return `m(${mockVar}${suffix})`
  })

  if (src === original) continue

  fs.writeFileSync(file, src, 'utf8')
  modified++
  console.log(`✓ ${path.relative(APP_DIR, file)}`)
}

console.log(`\nModified ${modified} files`)
