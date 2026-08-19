'use client'

import { useState, useEffect } from 'react'
import { FileText, ChevronDown, ChevronRight, Search, ExternalLink, Copy, Check } from 'lucide-react'

// ── Types ──────────────────────────────────────────────────────────────────────

interface OpenAPISpec {
  openapi: string
  info: { title: string; version: string; description?: string }
  paths: Record<string, Record<string, OpenAPIOperation>>
  components?: {
    schemas?: Record<string, unknown>
    securitySchemes?: Record<string, unknown>
  }
  tags?: Array<{ name: string; description?: string }>
}

interface OpenAPIOperation {
  summary?: string
  description?: string
  tags?: string[]
  operationId?: string
  parameters?: OpenAPIParameter[]
  requestBody?: {
    required?: boolean
    content?: Record<string, { schema?: unknown }>
  }
  responses?: Record<string, { description: string; content?: unknown }>
  security?: unknown[]
}

interface OpenAPIParameter {
  name: string
  in: 'path' | 'query' | 'header' | 'cookie'
  required?: boolean
  description?: string
  schema?: { type?: string; example?: unknown }
}

// ── Helpers ────────────────────────────────────────────────────────────────────

const METHOD_COLORS: Record<string, string> = {
  get:    'bg-blue-900/50 text-blue-300 border-blue-700/60',
  post:   'bg-green-900/50 text-green-300 border-green-700/60',
  put:    'bg-yellow-900/50 text-yellow-300 border-yellow-700/60',
  patch:  'bg-orange-900/50 text-orange-300 border-orange-700/60',
  delete: 'bg-red-900/50 text-red-300 border-red-700/60',
}

function MethodBadge({ method }: { method: string }) {
  const cls = METHOD_COLORS[method.toLowerCase()] ?? 'bg-zinc-800 text-zinc-300 border-zinc-700'
  return (
    <span className={`inline-flex items-center px-2 py-0.5 rounded-sm border text-[10px] font-bold uppercase tracking-wider shrink-0 ${cls}`}>
      {method.toUpperCase()}
    </span>
  )
}

function StatusBadge({ code }: { code: string }) {
  const n = parseInt(code)
  const cls =
    n < 300 ? 'text-green-400' :
    n < 400 ? 'text-yellow-400' :
    n < 500 ? 'text-orange-400' :
    'text-red-400'
  return <span className={`font-mono text-xs font-bold ${cls}`}>{code}</span>
}

// ── Operation Row ──────────────────────────────────────────────────────────────

function OperationRow({
  path,
  method,
  op,
}: {
  path: string
  method: string
  op: OpenAPIOperation
}) {
  const [open, setOpen] = useState(false)
  const [copied, setCopied] = useState(false)

  function copyPath() {
    navigator.clipboard.writeText(path).then(() => {
      setCopied(true)
      setTimeout(() => setCopied(false), 1500)
    })
  }

  return (
    <div className="border border-[#1e2d42] rounded-lg overflow-hidden mb-2">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-3 px-4 py-3 bg-[#0d1828] hover:bg-[#111f35] transition-colors text-left"
      >
        <MethodBadge method={method} />
        <span className="font-mono text-sm text-[#a0bcd8] flex-1 truncate">{path}</span>
        {op.summary && (
          <span className="text-xs text-[#5a6a7a] hidden md:block truncate max-w-xs">{op.summary}</span>
        )}
        {open ? <ChevronDown className="w-4 h-4 text-[#3d5068] shrink-0" /> : <ChevronRight className="w-4 h-4 text-[#3d5068] shrink-0" />}
      </button>

      {open && (
        <div className="px-4 py-4 border-t border-[#1e2d42] bg-[#080c14] space-y-4">
          {/* Path + copy */}
          <div className="flex items-center gap-2">
            <code className="flex-1 text-xs font-mono text-[#7d92b0] bg-[#0d1220] px-3 py-1.5 rounded-sm border border-[#1e2d42]">
              {method.toUpperCase()} {path}
            </code>
            <button
              onClick={copyPath}
              className="p-1.5 rounded-sm text-[#3d5068] hover:text-white hover:bg-[#1e2d42] transition-colors"
            >
              {copied ? <Check className="w-3.5 h-3.5 text-green-400" /> : <Copy className="w-3.5 h-3.5" />}
            </button>
          </div>

          {/* Description */}
          {(op.description || op.summary) && (
            <p className="text-sm text-[#7d92b0]">{op.description ?? op.summary}</p>
          )}

          {/* Parameters */}
          {op.parameters && op.parameters.length > 0 && (
            <div>
              <h4 className="text-xs font-semibold text-[#3d5068] uppercase tracking-wider mb-2">Parameters</h4>
              <div className="space-y-1.5">
                {op.parameters.map(p => (
                  <div key={`${p.in}-${p.name}`} className="flex items-start gap-3 text-xs">
                    <span className="font-mono text-[#a0bcd8] w-32 shrink-0">{p.name}</span>
                    <span className="text-[#3d5068] w-16 shrink-0">{p.in}</span>
                    <span className="text-[#3d5068] w-12 shrink-0">{(p.schema as { type?: string })?.type ?? ''}</span>
                    {p.required && <span className="text-red-400 text-[10px] font-bold">required</span>}
                    {p.description && <span className="text-[#5a6a7a] flex-1">{p.description}</span>}
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Request body */}
          {op.requestBody && (
            <div>
              <h4 className="text-xs font-semibold text-[#3d5068] uppercase tracking-wider mb-2">
                Request Body {op.requestBody.required && <span className="text-red-400 normal-case">(required)</span>}
              </h4>
              <div className="text-xs text-[#5a6a7a] font-mono">
                {Object.keys(op.requestBody.content ?? {}).join(', ')}
              </div>
            </div>
          )}

          {/* Responses */}
          {op.responses && (
            <div>
              <h4 className="text-xs font-semibold text-[#3d5068] uppercase tracking-wider mb-2">Responses</h4>
              <div className="space-y-1">
                {Object.entries(op.responses).map(([code, resp]) => (
                  <div key={code} className="flex items-center gap-3 text-xs">
                    <StatusBadge code={code} />
                    <span className="text-[#5a6a7a]">{(resp as { description: string }).description}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}
    </div>
  )
}

// ── Tag Section ────────────────────────────────────────────────────────────────

function TagSection({
  tag,
  operations,
}: {
  tag: string
  operations: Array<{ path: string; method: string; op: OpenAPIOperation }>
}) {
  const [open, setOpen] = useState(true)

  return (
    <div className="mb-6">
      <button
        onClick={() => setOpen(o => !o)}
        className="w-full flex items-center gap-2 mb-3 group"
      >
        <div className="flex items-center gap-2 flex-1">
          {open
            ? <ChevronDown className="w-4 h-4 text-[#e8002d]" />
            : <ChevronRight className="w-4 h-4 text-[#e8002d]" />
          }
          <h2 className="text-sm font-bold text-white uppercase tracking-wider">{tag}</h2>
          <span className="text-xs text-[#3d5068] bg-[#0d1220] px-2 py-0.5 rounded-full border border-[#1e2d42]">
            {operations.length}
          </span>
        </div>
      </button>
      {open && (
        <div className="ml-6">
          {operations.map(({ path, method, op }) => (
            <OperationRow key={`${method}-${path}`} path={path} method={method} op={op} />
          ))}
        </div>
      )}
    </div>
  )
}

// ── Page ───────────────────────────────────────────────────────────────────────

export default function ApiDocsPage() {
  const [spec, setSpec] = useState<OpenAPISpec | null>(null)
  const [error, setError] = useState<string | null>(null)
  const [search, setSearch] = useState('')

  useEffect(() => {
    fetch('/api/openapi')
      .then(async res => {
        if (!res.ok) throw new Error(`HTTP ${res.status}`)
        return res.json() as Promise<OpenAPISpec>
      })
      .then(setSpec)
      .catch(err => setError(err.message))
  }, [])

  // Build tag → operations index
  const taggedOps: Record<string, Array<{ path: string; method: string; op: OpenAPIOperation }>> = {}
  const untagged: Array<{ path: string; method: string; op: OpenAPIOperation }> = []

  if (spec) {
    for (const [path, methods] of Object.entries(spec.paths ?? {})) {
      for (const [method, op] of Object.entries(methods)) {
        const tags = (op as OpenAPIOperation).tags ?? []
        if (tags.length === 0) {
          untagged.push({ path, method, op: op as OpenAPIOperation })
        } else {
          for (const tag of tags) {
            if (!taggedOps[tag]) taggedOps[tag] = []
            taggedOps[tag].push({ path, method, op: op as OpenAPIOperation })
          }
        }
      }
    }
  }

  // Filter by search
  const filterOps = (ops: Array<{ path: string; method: string; op: OpenAPIOperation }>) => {
    if (!search) return ops
    const q = search.toLowerCase()
    return ops.filter(({ path, method, op }) =>
      path.toLowerCase().includes(q) ||
      method.toLowerCase().includes(q) ||
      (op.summary ?? '').toLowerCase().includes(q) ||
      (op.description ?? '').toLowerCase().includes(q),
    )
  }

  type OpList = Array<{ path: string; method: string; op: OpenAPIOperation }>
  const filteredTaggedOps: Record<string, OpList> = {}
  for (const [tag, ops] of Object.entries(taggedOps)) {
    const filtered = filterOps(ops)
    if (filtered.length > 0) filteredTaggedOps[tag] = filtered
  }

  const totalEndpoints = Object.values(taggedOps).flat().length + untagged.length

  return (
    <div className="min-h-screen bg-[#070d19] p-6">
      {/* Header */}
      <div className="max-w-5xl mx-auto">
        <div className="mb-6">
          <h1 className="text-2xl font-bold text-white flex items-center gap-2">
            <FileText className="w-6 h-6 text-blue-400" />
            API ドキュメント
          </h1>
          {spec && (
            <div className="flex items-center gap-4 mt-2">
              <p className="text-[#7d92b0] text-sm">
                {spec.info.title} <span className="text-[#3d5068]">v{spec.info.version}</span>
              </p>
              <span className="text-[#3d5068] text-xs bg-[#0d1220] px-2 py-0.5 rounded-sm border border-[#1e2d42]">
                OpenAPI {spec.openapi}
              </span>
              <span className="text-[#3d5068] text-xs">
                {totalEndpoints} エンドポイント
              </span>
            </div>
          )}
        </div>

        {/* Search */}
        <div className="relative mb-6">
          <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-[#3d5068]" />
          <input
            type="text"
            value={search}
            onChange={e => setSearch(e.target.value)}
            placeholder="エンドポイントを検索... (パス、メソッド、概要)"
            className="w-full pl-9 pr-4 py-2.5 bg-[#0d1220] border border-[#1e2d42] rounded-lg text-sm text-white placeholder-[#3d5068] focus:outline-hidden focus:border-[#3d5068] transition-colors"
          />
        </div>

        {/* Auth info */}
        {spec && (
          <div className="mb-6 bg-blue-900/20 border border-blue-700/40 rounded-xl px-4 py-3 flex items-start gap-3">
            <ExternalLink className="w-4 h-4 text-blue-400 shrink-0 mt-0.5" />
            <div>
              <p className="text-blue-300 text-sm font-medium">認証</p>
              <p className="text-blue-200/70 text-xs mt-0.5">
                すべての保護されたエンドポイントには <code className="text-blue-300">Authorization: Bearer &lt;token&gt;</code> ヘッダーが必要です。
                <code className="text-blue-300 ml-1">POST /api/v1/auth/login</code> でトークンを取得してください。
              </p>
            </div>
          </div>
        )}

        {/* Error state */}
        {error && (
          <div className="bg-yellow-900/20 border border-yellow-700/40 rounded-xl px-4 py-4 mb-6">
            <p className="text-yellow-300 text-sm font-medium mb-1">OpenAPI仕様の読み込みに失敗しました</p>
            <p className="text-yellow-200/70 text-xs">{error}</p>
            <p className="text-yellow-200/70 text-xs mt-2">
              ファイルは <code className="text-yellow-300">docs/openapi.yaml</code> にあります。
              開発サーバーが起動しているか確認してください。
            </p>
          </div>
        )}

        {/* Loading */}
        {!spec && !error && (
          <div className="flex items-center justify-center h-40">
            <div className="w-8 h-8 border-2 border-blue-500 border-t-transparent rounded-full animate-spin" />
          </div>
        )}

        {/* Operations */}
        {spec && (
          <>
            {Object.entries(filteredTaggedOps).map(([tag, ops]) => (
              <TagSection key={tag} tag={tag} operations={ops} />
            ))}
            {filterOps(untagged).length > 0 && (
              <TagSection tag="その他" operations={filterOps(untagged)} />
            )}
            {search && Object.keys(filteredTaggedOps).length === 0 && filterOps(untagged).length === 0 && (
              <div className="text-center text-[#3d5068] py-12">
                <Search className="w-8 h-8 mx-auto mb-2 opacity-40" />
                <p className="text-sm">「{search}」に一致するエンドポイントが見つかりません</p>
              </div>
            )}
          </>
        )}
      </div>
    </div>
  )
}
