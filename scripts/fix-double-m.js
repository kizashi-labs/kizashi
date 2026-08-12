#!/usr/bin/env node
/**
 * Fix double-wrapped mm(MOCK_X) patterns back to m(MOCK_X)
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

  // Fix mm(MOCK_X) → m(MOCK_X)
  src = src.replace(/\bmm\((MOCK_\w+)\)/g, 'm($1)')

  if (src === original) continue
  fs.writeFileSync(file, src, 'utf8')
  modified++
  console.log(`✓ ${path.relative(APP_DIR, file)}`)
}

console.log(`\nModified ${modified} files`)
