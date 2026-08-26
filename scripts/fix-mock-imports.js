#!/usr/bin/env node
/**
 * Fixes incorrectly placed `import { USE_MOCK }` lines.
 * Removes any misplaced ones and re-inserts after the full import block.
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

let fixed = 0

for (const file of files) {
  let src = fs.readFileSync(file, 'utf8')
  const original = src

  if (!src.includes(IMPORT_LINE)) continue

  // Remove all existing occurrences of the import line (may be misplaced)
  src = src.split('\n').filter(l => l.trim() !== IMPORT_LINE).join('\n')

  // Find the end of the import block:
  // Split into lines, find the last line that starts with 'import ' (accounting for multi-line imports)
  const lines = src.split('\n')
  let lastImportEnd = -1
  let inMultilineImport = false

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]
    const trimmed = line.trim()

    if (inMultilineImport) {
      if (trimmed.includes("from '") || trimmed.includes('from "')) {
        lastImportEnd = i
        inMultilineImport = false
      }
      continue
    }

    if (trimmed.startsWith('import ')) {
      if (trimmed.includes("from '") || trimmed.includes('from "')) {
        // Single-line import
        lastImportEnd = i
      } else {
        // Multi-line import (e.g., import { ... } from '...' spanning multiple lines)
        inMultilineImport = true
        lastImportEnd = i
      }
    }
  }

  if (lastImportEnd === -1) {
    // No imports found, add at top
    src = IMPORT_LINE + '\n' + src
  } else {
    lines.splice(lastImportEnd + 1, 0, IMPORT_LINE)
    src = lines.join('\n')
  }

  if (src === original) continue

  fs.writeFileSync(file, src, 'utf8')
  fixed++
  console.log(`✓ ${path.relative(APP_DIR, file)}`)
}

console.log(`\nFixed imports in ${fixed} files`)
