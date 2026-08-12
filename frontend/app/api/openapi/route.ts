import { NextResponse } from 'next/server'
import { readFileSync, existsSync } from 'fs'
import { join } from 'path'

// Minimal YAML → object parser for the subset used in openapi.yaml.
// Handles nested mappings, sequences, and string values well enough for display.
function parseYamlPaths(yaml: string): Record<string, unknown> {
  // Use a simple line-based parser to extract paths and operations for display.
  // For full fidelity, install js-yaml. This is sufficient for the docs UI.
  const lines = yaml.split('\n')
  const result: Record<string, unknown> = {
    openapi: '',
    info: { title: 'Kizashi API', version: '1.0.0' },
    paths: {},
    tags: [],
  }

  // Extract top-level fields
  for (const line of lines) {
    const m = line.match(/^openapi:\s*['"]?(.+?)['"]?\s*$/)
    if (m) result.openapi = m[1]
    const im = line.match(/^  title:\s*(.+)$/)
    if (im) (result.info as Record<string, unknown>).title = im[1].replace(/['"]/g, '').trim()
    const vm = line.match(/^  version:\s*['"]?(.+?)['"]?\s*$/)
    if (vm) (result.info as Record<string, unknown>).version = vm[1].trim()
  }

  // Extract paths block
  let inPaths = false
  let currentPath = ''
  let currentMethod = ''
  let currentSummary = ''
  let currentTags: string[] = []
  let indent = 0
  const paths: Record<string, Record<string, { summary: string; tags: string[] }>> = {}

  for (let i = 0; i < lines.length; i++) {
    const raw = lines[i]
    const trimmed = raw.trimStart()
    const lineIndent = raw.length - trimmed.length

    if (raw === 'paths:') { inPaths = true; indent = 0; continue }
    if (inPaths && lineIndent === 0 && trimmed && !trimmed.startsWith('#') && raw !== 'paths:') {
      inPaths = false
    }
    if (!inPaths) continue

    if (lineIndent === 2 && trimmed.startsWith('/')) {
      currentPath = trimmed.replace(/:$/, '')
      paths[currentPath] = {}
    } else if (lineIndent === 4 && /^(get|post|put|patch|delete|head|options):/.test(trimmed)) {
      currentMethod = trimmed.replace(/:.*$/, '')
      currentSummary = ''
      currentTags = []
      paths[currentPath] = paths[currentPath] ?? {}
      paths[currentPath][currentMethod] = { summary: '', tags: [] }
    } else if (lineIndent === 6 && trimmed.startsWith('summary:')) {
      currentSummary = trimmed.replace(/^summary:\s*/, '').replace(/['"]/g, '')
      if (paths[currentPath]?.[currentMethod]) {
        paths[currentPath][currentMethod].summary = currentSummary
      }
    } else if (lineIndent === 6 && trimmed.startsWith('tags:')) {
      currentTags = []
    } else if (lineIndent === 8 && trimmed.startsWith('- ') && currentMethod) {
      const tag = trimmed.slice(2).trim()
      if (paths[currentPath]?.[currentMethod]) {
        paths[currentPath][currentMethod].tags.push(tag)
      }
    }
  }

  result.paths = paths

  // Extract tags
  const tagMatches = yaml.matchAll(/^- name:\s*(.+)$/mg)
  const tags: Array<{ name: string }> = []
  for (const m of tagMatches) {
    tags.push({ name: m[1].trim() })
  }
  result.tags = tags

  return result
}

export async function GET() {
  try {
    const candidates = [
      join(process.cwd(), '..', 'docs', 'openapi.yaml'),
      join(process.cwd(), 'docs', 'openapi.yaml'),
    ]
    const yamlPath = candidates.find(p => existsSync(p))
    if (!yamlPath) {
      return NextResponse.json({ error: 'OpenAPI spec not found' }, { status: 404 })
    }
    const content = readFileSync(yamlPath, 'utf-8')
    const parsed = parseYamlPaths(content)
    return NextResponse.json(parsed)
  } catch (err) {
    return NextResponse.json({ error: String(err) }, { status: 500 })
  }
}
