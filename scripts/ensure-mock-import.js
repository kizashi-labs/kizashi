#!/usr/bin/env node
/**
 * Ensures all files using USE_MOCK have the import.
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

  // Skip if doesn't use USE_MOCK or already has import
  if (!src.includes('USE_MOCK')) continue
  if (src.includes(IMPORT_LINE) || src.includes("from '@/lib/mock'")) continue

  // Find end of import block
  const lines = src.split('\n')
  let lastImportEnd = -1
  let inMultilineImport = false

  for (let i = 0; i < lines.length; i++) {
    const trimmed = lines[i].trim()
    if (inMultilineImport) {
      if (trimmed.includes("from '") || trimmed.includes('from "')) {
        lastImportEnd = i
        inMultilineImport = false
      }
      continue
    }
    if (trimmed.startsWith('import ')) {
      if (trimmed.includes("from '") || trimmed.includes('from "')) {
        lastImportEnd = i
      } else {
        inMultilineImport = true
        lastImportEnd = i
      }
    }
  }

  if (lastImportEnd === -1) {
    src = IMPORT_LINE + '\n' + src
  } else {
    lines.splice(lastImportEnd + 1, 0, IMPORT_LINE)
    src = lines.join('\n')
  }

  fs.writeFileSync(file, src, 'utf8')
  fixed++
  console.log(`✓ ${path.relative(APP_DIR, file)}`)
}

console.log(`\nAdded import to ${fixed} files`)
